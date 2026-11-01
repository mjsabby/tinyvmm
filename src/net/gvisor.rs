//! gVisor backend (`--net-backend gvisor`): gVisor's netstack, Go code built
//! into `tinyvmm_gvisor.dll` from `gvisor/` and loaded at run time (see
//! `winsys::gvisor`). It terminates the guest's TCP and UDP itself and
//! relays them through Go's host sockets.
//!
//! The guest network is the NAT's (172.29.255.0/29, gateway .1 whose TCP
//! ports are the host's loopback, the guest .2) and so is its DHCP server,
//! answered here before frames reach gVisor. Pings to the gateway are
//! gVisor's; pings to other hosts are dropped, as gVisor, which accepts
//! every destination address, would otherwise answer them itself.
//!
//! gVisor builds TCP segments for the guest up to ~64 KiB with a partial
//! checksum (host GSO), which reach the guest as GSO frames, or are finished
//! in software for a guest that didn't negotiate the offloads. Guest TSO
//! super-segments go to gVisor whole. Frames gVisor builds while the guest's
//! RX backlog is deep wait here until the guest drains it.

use crate::net::dhcp;
use crate::net::nat::PortForward;
use crate::net::wire::*;
use crate::virtio::net::{
    HDR_F_NEEDS_CSUM, HDR_GSO_NONE, HDR_GSO_TCPV4, NetBackend, NetDevice, RxHeader, TxHeader,
    tx_offload_software,
};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread::JoinHandle;
use winsys::gvisor::{Gvisor, GvisorHost, Offload};

/// The gateway's MAC, as the NAT's.
const GATEWAY_MAC: [u8; 6] = [0x02, 0x53, 0x54, 0x00, 0x00, 0x01];
/// Frames to the guest held while its RX backlog is deep, beyond which more
/// are dropped (gVisor's TCP then retransmits them).
const RX_HOLD_MAX: usize = 8192;

pub struct GvisorOptions {
    pub port_forwards: Vec<PortForward>,
    /// DNS servers DHCP offers (those the guest can reach; see the NAT's).
    pub dns_servers: Vec<[u8; 4]>,
}

/// Where gVisor's frames for the guest go.
struct Host {
    net: Weak<NetDevice>,
    held: Mutex<VecDeque<(Vec<u8>, RxHeader)>>,
    /// Set (and the condvar signalled) when the flusher should look again.
    poke: Mutex<bool>,
    poked: Condvar,
    stop: AtomicBool,
    rx_drops: AtomicU64,
    held_max: AtomicU64,
    soft_offload: AtomicU64,
}

impl Host {
    /// Deliver `frame`, or hold it while the guest's RX backlog is deep.
    fn deliver(&self, dev: &NetDevice, frame: &[u8], hdr: RxHeader) {
        let mut held = self.held.lock().unwrap();
        if held.is_empty() && !dev.rx_congested() {
            drop(held);
            dev.inject_rx_gso_batched(frame, hdr);
            return;
        }
        if held.len() >= RX_HOLD_MAX {
            self.rx_drops.fetch_add(1, Ordering::Relaxed);
            return;
        }
        held.push_back((frame.to_vec(), hdr));
        self.held_max
            .fetch_max(held.len() as u64, Ordering::Relaxed);
    }

    /// Deliver held frames while the guest has room.
    fn flush(&self) {
        let Some(dev) = self.net.upgrade() else {
            return;
        };
        loop {
            let mut held = self.held.lock().unwrap();
            if held.is_empty() || dev.rx_congested() {
                break;
            }
            let Some((f, hdr)) = held.pop_front() else {
                break;
            };
            drop(held);
            dev.inject_rx_gso_batched(&f, hdr);
        }
        dev.notify_rx();
    }

    fn poke(&self) {
        *self.poke.lock().unwrap() = true;
        self.poked.notify_one();
    }
}

/// The virtio-net header describing a frame gVisor offloaded.
fn rx_header(frame: &[u8], off: Offload) -> RxHeader {
    if !off.needs_csum {
        return RxHeader::default();
    }
    let csum_start = ETH_HDR + usize::from(off.l3_len);
    let mut hdr = RxHeader {
        flags: HDR_F_NEEDS_CSUM,
        csum_start: csum_start as u16,
        csum_offset: 16,
        ..Default::default()
    };
    if off.gso_mss > 0
        && let Some(&doff) = frame.get(csum_start + 12)
    {
        hdr.gso_type = HDR_GSO_TCPV4;
        hdr.gso_size = off.gso_mss;
        hdr.hdr_len = (csum_start + usize::from(doff >> 4) * 4) as u16;
    }
    hdr
}

impl GvisorHost for Host {
    fn send(&self, frame: &[u8], off: Offload, more: bool) {
        let Some(dev) = self.net.upgrade() else {
            return;
        };
        let hdr = rx_header(frame, off);
        let takes = dev.rx_csum_ok() && (hdr.gso_type == HDR_GSO_NONE || dev.rx_gso_ok());
        if hdr.has_offload() && !takes {
            // The guest didn't negotiate the offload: finish it here.
            self.soft_offload.fetch_add(1, Ordering::Relaxed);
            let mut f = frame.to_vec();
            let tx: TxHeader = hdr;
            tx_offload_software(&mut f, &tx, &mut |seg| {
                self.deliver(&dev, seg, RxHeader::default())
            });
        } else {
            self.deliver(&dev, frame, hdr);
        }
        if !more {
            dev.notify_rx();
        }
    }
}

pub struct GvisorBackend {
    stack: Gvisor<Host>,
    host: Arc<Host>,
    lease: dhcp::Lease,
    flusher: Mutex<Option<JoinHandle<()>>>,
    icmp_drops: AtomicU64,
    stopped: AtomicBool,
    /// The stack's counters as it stopped, for the exit summary.
    last_stats: Mutex<Option<winsys::gvisor::Stats>>,
}

impl GvisorBackend {
    /// Start gVisor's stack for `net`; returns the backend and gVisor's
    /// version. Fails if the DLL can't be loaded or the stack set up.
    pub fn new(net: &Arc<NetDevice>, opts: GvisorOptions) -> Result<(Arc<Self>, String), String> {
        let version = winsys::gvisor::version()?;
        let host = Arc::new(Host {
            net: Arc::downgrade(net),
            held: Mutex::new(VecDeque::new()),
            poke: Mutex::new(false),
            poked: Condvar::new(),
            stop: AtomicBool::new(false),
            rx_drops: AtomicU64::new(0),
            held_max: AtomicU64::new(0),
            soft_offload: AtomicU64::new(0),
        });
        let stack = Gvisor::new(
            crate::net::GATEWAY_IP,
            crate::net::PREFIX_LEN,
            GATEWAY_MAC,
            1500,
            host.clone(),
        )
        .map_err(|e| format!("gvisor: {e}"))?;
        for pf in &opts.port_forwards {
            if let Err(e) =
                stack.add_port_forward(pf.host_addr, pf.host_port, pf.guest_ip, pf.guest_port)
            {
                eprintln!(
                    "[gvisor] port-forward {:?}:{} -> {:?}:{} failed: {e}",
                    pf.host_addr, pf.host_port, pf.guest_ip, pf.guest_port
                );
            }
        }
        let netmask = crate::net::NETMASK;
        let lease = dhcp::Lease {
            server: crate::net::GATEWAY_IP,
            client: crate::net::GUEST_IP,
            netmask,
            dns: dhcp::usable_dns(&opts.dns_servers, crate::net::GATEWAY_IP, netmask),
            lease_secs: 24 * 60 * 60,
        };
        let h = host.clone();
        let flusher = std::thread::Builder::new()
            .name("gvisor-rx".into())
            .spawn(move || {
                while !h.stop.load(Ordering::Acquire) {
                    {
                        let mut p = h.poke.lock().unwrap();
                        while !*p && !h.stop.load(Ordering::Acquire) {
                            p = h.poked.wait(p).unwrap();
                        }
                        *p = false;
                    }
                    h.flush();
                }
            })
            .map_err(|e| format!("gvisor: flusher thread: {e}"))?;
        Ok((
            Arc::new(GvisorBackend {
                stack,
                host,
                lease,
                flusher: Mutex::new(Some(flusher)),
                icmp_drops: AtomicU64::new(0),
                stopped: AtomicBool::new(false),
                last_stats: Mutex::new(None),
            }),
            version,
        ))
    }

    /// Handle what the gateway answers here rather than in gVisor: DHCP, and
    /// pings to other hosts (dropped). True if `frame` was consumed.
    fn intercept(&self, frame: &[u8]) -> bool {
        let Some(eth) = parse_eth(frame) else {
            return false;
        };
        if eth.ethertype != ETHERTYPE_IPV4 {
            return false;
        }
        let Some(ip) = parse_ipv4(eth.payload) else {
            return false;
        };
        match ip.proto {
            IP_PROTO_ICMP if ip.dst != crate::net::GATEWAY_IP => {
                self.icmp_drops.fetch_add(1, Ordering::Relaxed);
                true
            }
            IP_PROTO_UDP => {
                let Some(udp) = parse_udp(ip.payload) else {
                    return false;
                };
                if udp.dst_port != dhcp::SERVER_PORT
                    || (ip.dst != dhcp::BROADCAST_IP && ip.dst != crate::net::GATEWAY_IP)
                {
                    return false;
                }
                self.answer_dhcp(udp.payload);
                true
            }
            _ => false,
        }
    }

    fn answer_dhcp(&self, msg: &[u8]) {
        let mut payload = Vec::new();
        let Some(to) = dhcp::reply(msg, &self.lease, &mut payload) else {
            return;
        };
        let gw = crate::net::GATEWAY_IP;
        let udp = build_udp(gw, to.ip, dhcp::SERVER_PORT, dhcp::CLIENT_PORT, &payload);
        let ip = build_ipv4(gw, to.ip, IP_PROTO_UDP, &udp);
        let frame = build_eth(to.mac, GATEWAY_MAC, ETHERTYPE_IPV4, &ip);
        if let Some(dev) = self.host.net.upgrade() {
            self.host.deliver(&dev, &frame, RxHeader::default());
            dev.notify_rx();
        }
    }
}

impl NetBackend for GvisorBackend {
    fn on_guest_frame(&self, frame: &[u8]) {
        if !self.intercept(frame) {
            self.stack.input(frame);
        }
    }

    /// gVisor takes TSO super-segments and unfinished checksums as they are.
    fn on_guest_frame_offload(&self, frame: &mut [u8], _hdr: &TxHeader) {
        if !self.intercept(frame) {
            self.stack.input(frame);
        }
    }

    fn on_rx_space(&self) {
        self.host.poke();
    }

    fn diag_summary(&self) -> Option<String> {
        let s = self
            .last_stats
            .lock()
            .unwrap()
            .unwrap_or_else(|| self.stack.stats());
        let ld = |a: &AtomicU64| a.load(Ordering::Relaxed);
        Some(format!(
            "gvisor: tcp_flows={} refused={} udp_flows={} segs_out={} segs_in={} retransmits={} \
             fast_retransmits={} rto={} dsacked={} input_drops={} rx_drops={} rx_held_max={} \
             soft_offload={} icmp_drops={}",
            s.tcp_flows,
            s.tcp_refused,
            s.udp_flows,
            s.segs_sent,
            s.segs_received,
            s.retransmits,
            s.fast_retransmits,
            s.rtos,
            s.dsacked,
            s.input_drops,
            ld(&self.host.rx_drops),
            ld(&self.host.held_max),
            ld(&self.host.soft_offload),
            ld(&self.icmp_drops),
        ))
    }

    fn stop(&self) {
        if self.stopped.swap(true, Ordering::AcqRel) {
            return;
        }
        *self.last_stats.lock().unwrap() = Some(self.stack.stats());
        self.stack.close();
        self.host.stop.store(true, Ordering::Release);
        self.host.poke();
        if let Some(h) = self.flusher.lock().unwrap().take() {
            let _ = h.join();
        }
    }
}
