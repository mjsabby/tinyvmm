//! smoltcp as the NAT's guest-facing TCP engine (`--net-backend smoltcp`).
//!
//! The NAT (`nat.rs`) terminates each guest TCP connection in a per-flow TCB
//! it drives through [`TcbDyn`]; by default that's a `tcp-sans-io` `Tcb`. This
//! puts a smoltcp socket behind the same trait instead, so everything else —
//! the IOCP host sockets, flow table, GSO coalescing, RX backpressure, DHCP,
//! UDP and ICMP — is the very same code, and a comparison between the two
//! isolates the TCP engine.
//!
//! Each flow owns a smoltcp `Interface` on the IP medium (no ARP) with one
//! TCP socket in it. A guest datagram is lent to the interface as the single
//! packet of a polled device, and what the interface builds queues here until
//! the NAT extracts it. smoltcp leaves TCP checksums to us (the device
//! claims checksum offload): guest segments are verified here unless the
//! guest left their checksum to us, and outgoing ones are filled in (or left
//! partial for the guest) as they are extracted.

use super::nat::TcbDyn;
use crate::net::wire::{IP_PROTO_TCP, checksum16};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Checksum, ChecksumCapabilities, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address,
};
use std::collections::VecDeque;
use std::sync::OnceLock;
use tcp_sans_io::{State, TcbConfig, TcbStats, TcpError};

/// The guest link's IP MTU: smoltcp sizes its MSS (and its segments) from it.
const MTU: usize = 1500;
/// Most datagrams a TCB holds built but not yet extracted, as tcp-sans-io's
/// egress ring does (32 slots there). A poll that fills it stops building,
/// and the NAT's next tick picks up where it stopped.
const TX_QUEUE_MAX: usize = 64;
/// Most of the send ring one host receive may fill (`send_reserve`): the
/// NAT's `TCP_RECV_MAX`.
const STAGE_MAX: usize = 256 * 1024;

/// Millisecond TCP timestamps (smoltcp takes a context-free `fn() -> u32`).
fn tsval() -> u32 {
    static START: OnceLock<std::time::Instant> = OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis() as u32
}

fn ipv4(a: [u8; 4]) -> IpAddress {
    IpAddress::Ipv4(Ipv4Address::from(a))
}

/// Datagrams the interface built, oldest first, and spent buffers to reuse.
#[derive(Default)]
struct TxQueue {
    pkts: VecDeque<Vec<u8>>,
    spare: Vec<Vec<u8>>,
    /// The NAT asked for no new segments (`set_egress_paused`); replies to
    /// what the guest sends still go out.
    paused: bool,
}

/// The device an interface is polled with: at most one guest datagram,
/// borrowed for the poll, and the queue the interface's output goes to.
struct Dev<'a> {
    rx: Option<&'a [u8]>,
    q: &'a mut TxQueue,
}

struct RxTok<'a>(&'a [u8]);
struct TxTok<'a>(&'a mut TxQueue);

impl phy::RxToken for RxTok<'_> {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(self.0)
    }
}

impl phy::TxToken for TxTok<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut b = self.0.spare.pop().unwrap_or_default();
        b.clear();
        b.resize(len, 0);
        let r = f(&mut b);
        self.0.pkts.push_back(b);
        r
    }
}

fn caps() -> DeviceCapabilities {
    let mut checksum = ChecksumCapabilities::default();
    checksum.tcp = Checksum::None;
    let mut caps = DeviceCapabilities::default();
    caps.medium = Medium::Ip;
    caps.max_transmission_unit = MTU;
    caps.checksum = checksum;
    caps
}

impl phy::Device for Dev<'_> {
    type RxToken<'b>
        = RxTok<'b>
    where
        Self: 'b;
    type TxToken<'b>
        = TxTok<'b>
    where
        Self: 'b;

    fn receive(&mut self, _: Instant) -> Option<(RxTok<'_>, TxTok<'_>)> {
        let pkt = self.rx.take()?;
        Some((RxTok(pkt), TxTok(self.q)))
    }

    fn transmit(&mut self, _: Instant) -> Option<TxTok<'_>> {
        (!self.q.paused && self.q.pkts.len() < TX_QUEUE_MAX).then_some(TxTok(self.q))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        caps()
    }
}

/// Heap memory a socket buffer borrows. A smoltcp socket can't hand its
/// buffers back, so each connection's socket borrows this allocation afresh
/// and the pooled TCB never reallocates its rings.
struct Ring(*mut [u8]);

impl Ring {
    fn new(n: usize) -> Self {
        Ring(Box::into_raw(vec![0u8; n].into_boxed_slice()))
    }

    /// The memory, for a new socket.
    ///
    /// # Safety
    /// No other borrow from this ring may be live: the socket built on the
    /// previous one must have been dropped.
    unsafe fn lend(&mut self) -> &'static mut [u8] {
        // SAFETY: the allocation lives until `drop`, which runs after the
        // socket set that borrows it (field order in `SmolTcb`), and the
        // caller guarantees this is the only live borrow.
        unsafe { &mut *self.0 }
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        // SAFETY: from `Box::into_raw` in `new`, freed only here.
        drop(unsafe { Box::from_raw(self.0) });
    }
}

/// One guest-facing TCP connection on smoltcp, as [`TcbDyn`].
pub(super) struct SmolTcb {
    // Dropped before the rings it borrows (fields drop in order).
    sockets: SocketSet<'static>,
    handle: SocketHandle,
    iface: Interface,
    rx_ring: Ring,
    tx_ring: Ring,
    q: TxQueue,
    cfg: TcbConfig,
    now: Instant,
    /// Free space of the send ring lent to the host (`send_reserve`): host
    /// receives complete asynchronously, so they can't write into smoltcp's
    /// ring, whose free space moves as it drains.
    stage: Box<[u8]>,
    lent: Option<usize>,
    csum_offload: bool,
    /// The connection got past LISTEN: a socket back in LISTEN (a RST during
    /// the handshake) has ended, like one that closed.
    began: bool,
    /// The connection ended in a reset (the peer's RST, `abort`, or a
    /// timeout) rather than the close handshake.
    reset: bool,
    stats: TcbStats,
}

/// A pooled TCB with `BUF`-byte send and receive rings, for `cfg` (which
/// `reinit` replaces when the pool hands it out).
pub(super) fn make<const BUF: usize>(cfg: TcbConfig) -> Box<dyn TcbDyn> {
    let mut sockets = SocketSet::new(Vec::with_capacity(1));
    let mut rx_ring = Ring::new(BUF);
    let mut tx_ring = Ring::new(BUF);
    // SAFETY: fresh rings, borrowed once.
    let handle = sockets.add(unsafe { new_socket(&mut rx_ring, &mut tx_ring) });
    let mut q = TxQueue::default();
    Box::new(SmolTcb {
        sockets,
        handle,
        iface: new_iface(&mut q, cfg.local.ip, iface_seed(cfg.iss)),
        rx_ring,
        tx_ring,
        q,
        cfg,
        now: Instant::ZERO,
        stage: vec![0; BUF.min(STAGE_MAX)].into_boxed_slice(),
        lent: None,
        csum_offload: false,
        began: false,
        reset: false,
        stats: TcbStats::default(),
    })
}

/// A socket on the rings, set up as the NAT wants: no Nagle (host bytes go
/// to the guest as they come), Reno like tcp-sans-io, and timestamps.
///
/// # Safety
/// No socket built on these rings may still be live.
unsafe fn new_socket(rx: &mut Ring, tx: &mut Ring) -> tcp::Socket<'static> {
    // SAFETY: per the caller.
    let (rx, tx) = unsafe { (rx.lend(), tx.lend()) };
    let mut s = tcp::Socket::new(tcp::SocketBuffer::new(rx), tcp::SocketBuffer::new(tx));
    s.set_nagle_enabled(false);
    s.set_congestion_control(tcp::CongestionControl::Reno);
    s.set_tsval_generator(Some(tsval));
    s
}

/// The interface's random seed, from which smoltcp draws the connection's
/// initial sequence number: the NAT's per-connection ISS.
fn iface_seed(iss: u32) -> u64 {
    u64::from(iss) << 32 | u64::from(iss.rotate_left(13)) | 1
}

/// An interface owning `local` (and, by prefix 0, on-link with any peer).
fn new_iface(q: &mut TxQueue, local: [u8; 4], seed: u64) -> Interface {
    let mut cfg = Config::new(HardwareAddress::Ip);
    cfg.random_seed = seed;
    let mut iface = Interface::new(cfg, &mut Dev { rx: None, q }, Instant::ZERO);
    iface.update_ip_addrs(|a| {
        let _ = a.push(IpCidr::new(ipv4(local), 0));
    });
    iface
}

impl SmolTcb {
    fn sock(&self) -> &tcp::Socket<'static> {
        self.sockets.get::<tcp::Socket>(self.handle)
    }

    fn sock_mut(&mut self) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut::<tcp::Socket>(self.handle)
    }

    /// Poll the interface: process `pkt` (if any), run timers, and build what
    /// is due.
    fn run(&mut self, pkt: Option<&[u8]>) {
        let before = self.sock().state();
        let mut dev = Dev {
            rx: pkt,
            q: &mut self.q,
        };
        self.iface.poll(self.now, &mut dev, &mut self.sockets);
        let after = self.sock().state();
        if !matches!(after, tcp::State::Closed | tcp::State::Listen) {
            self.began = true;
        } else if self.began
            && before != after
            && !matches!(
                before,
                tcp::State::LastAck | tcp::State::Closing | tcp::State::TimeWait
            )
        {
            // Ended before the peer's FIN (or before ours was acknowledged
            // in the handshake's last step): a reset, as in tcp-sans-io.
            self.reset = true;
        }
    }
}

/// Whether the TCP segment in IPv4 datagram `ip` carries a valid checksum.
fn tcp_csum_ok(ip: &[u8]) -> bool {
    let Some(&vihl) = ip.first() else {
        return false;
    };
    let ihl = usize::from(vihl & 0x0F) * 4;
    let total = ip
        .get(2..4)
        .map_or(0, |b| usize::from(u16::from_be_bytes([b[0], b[1]])));
    let Some(tcp) = ip.get(ihl..total.min(ip.len())) else {
        return false;
    };
    if ip.len() < 20 {
        return false;
    }
    let mut pseudo = [0u8; 12];
    pseudo[..8].copy_from_slice(&ip[12..20]);
    pseudo[9] = IP_PROTO_TCP;
    pseudo[10..].copy_from_slice(&(tcp.len() as u16).to_be_bytes());
    checksum16(&[&pseudo, tcp]) == 0
}

/// Fill in the TCP checksum of IPv4 datagram `ip`: complete, or only its
/// pseudo-header part for a guest that finishes it (`partial`).
fn fill_tcp_csum(ip: &mut [u8], partial: bool) {
    let ihl = usize::from(ip[0] & 0x0F) * 4;
    if ip.len() < ihl + 20 {
        return;
    }
    let mut pseudo = [0u8; 12];
    pseudo[..8].copy_from_slice(&ip[12..20]);
    pseudo[9] = IP_PROTO_TCP;
    pseudo[10..].copy_from_slice(&((ip.len() - ihl) as u16).to_be_bytes());
    let tcp = &mut ip[ihl..];
    tcp[16..18].fill(0);
    let csum = if partial {
        !checksum16(&[&pseudo])
    } else {
        checksum16(&[&pseudo, tcp])
    };
    tcp[16..18].copy_from_slice(&csum.to_be_bytes());
}

impl TcbDyn for SmolTcb {
    fn set_now(&mut self, now: u64) {
        self.now = Instant::from_millis(now as i64);
    }

    fn listen(&mut self) -> Result<(), TcpError> {
        let local = IpListenEndpoint {
            addr: Some(ipv4(self.cfg.local.ip)),
            port: self.cfg.local.port,
        };
        self.sock_mut()
            .listen(local)
            .map_err(|_| TcpError::InvalidState)
    }

    fn connect(&mut self) -> Result<(), TcpError> {
        let remote = IpEndpoint::new(ipv4(self.cfg.remote.ip), self.cfg.remote.port);
        let local = IpListenEndpoint {
            addr: Some(ipv4(self.cfg.local.ip)),
            port: self.cfg.local.port,
        };
        let SmolTcb {
            sockets,
            handle,
            iface,
            ..
        } = self;
        sockets
            .get_mut::<tcp::Socket>(*handle)
            .connect(iface.context(), remote, local)
            .map_err(|_| TcpError::InvalidState)?;
        self.began = true;
        Ok(())
    }

    fn inject_packet(&mut self, pkt: &[u8]) -> Result<(), TcpError> {
        if !tcp_csum_ok(pkt) {
            return Err(TcpError::MalformedPacket);
        }
        self.inject_packet_l4_csum_trusted(pkt)
    }

    fn inject_packet_l4_csum_trusted(&mut self, pkt: &[u8]) -> Result<(), TcpError> {
        self.stats.segs_in += 1;
        self.run(Some(pkt));
        Ok(())
    }

    fn extract_packet_with(&mut self, f: &mut dyn FnMut(&[u8])) -> bool {
        let Some(mut pkt) = self.q.pkts.pop_front() else {
            return false;
        };
        fill_tcp_csum(&mut pkt, self.csum_offload);
        self.stats.segs_out += 1;
        f(&pkt);
        self.q.spare.push(pkt);
        true
    }

    fn set_tx_csum_offload(&mut self, on: bool) {
        self.csum_offload = on;
    }

    fn poll(&self) -> u32 {
        const READABLE: u32 = 1 << 0;
        const PEER_CLOSED: u32 = 1 << 3;
        const CLOSED: u32 = 1 << 4;
        const ERROR: u32 = 1 << 6;
        let mut ev = 0;
        if self.sock().can_recv() {
            ev |= READABLE;
        }
        match self.state() {
            State::CloseWait | State::LastAck | State::Closing | State::TimeWait => {
                ev |= PEER_CLOSED;
            }
            State::Closed => ev |= CLOSED,
            _ => {}
        }
        if self.reset {
            ev |= ERROR;
        }
        ev
    }

    fn recv(&mut self, dst: &mut [u8]) -> Result<usize, TcpError> {
        self.sock_mut().recv_slice(dst).map_err(|e| match e {
            tcp::RecvError::Finished => TcpError::ConnectionClosed,
            _ => TcpError::InvalidState,
        })
    }

    fn send_reserve(&mut self, max: usize) -> Result<(&mut [u8], &mut [u8]), TcpError> {
        let s = self.sock();
        if self.lent.is_some() || !s.may_send() {
            return Err(TcpError::InvalidState);
        }
        let n = (s.send_capacity() - s.send_queue())
            .min(max)
            .min(self.stage.len());
        if n == 0 {
            return Err(TcpError::WouldBlock);
        }
        self.lent = Some(n);
        Ok((&mut self.stage[..n], &mut []))
    }

    fn send_commit(&mut self, n: usize) -> Result<usize, TcpError> {
        let lent = self.lent.take().ok_or(TcpError::InvalidState)?;
        let n = n.min(lent);
        if n == 0 {
            return Ok(0);
        }
        // The ring's free space only grew since the loan, so all `n` fit.
        let SmolTcb {
            sockets,
            handle,
            stage,
            ..
        } = self;
        sockets
            .get_mut::<tcp::Socket>(*handle)
            .send_slice(&stage[..n])
            .map_err(|_| TcpError::InvalidState)
    }

    fn state(&self) -> State {
        match self.sock().state() {
            tcp::State::Closed => State::Closed,
            tcp::State::Listen if self.began => State::Closed,
            tcp::State::Listen => State::Listen,
            tcp::State::SynSent => State::SynSent,
            tcp::State::SynReceived => State::SynRcvd,
            tcp::State::Established => State::Established,
            tcp::State::FinWait1 => State::FinWait1,
            tcp::State::FinWait2 => State::FinWait2,
            tcp::State::CloseWait => State::CloseWait,
            tcp::State::Closing => State::Closing,
            tcp::State::LastAck => State::LastAck,
            tcp::State::TimeWait => State::TimeWait,
        }
    }

    fn tick(&mut self) -> Result<(), TcpError> {
        self.run(None);
        Ok(())
    }

    fn set_egress_paused(&mut self, paused: bool) {
        self.q.paused = paused;
    }

    fn abort(&mut self) -> Result<(), TcpError> {
        // smoltcp sends the RST from the next poll.
        self.sock_mut().abort();
        self.reset = true;
        Ok(())
    }

    fn close(&mut self) -> Result<(), TcpError> {
        self.sock_mut().close();
        Ok(())
    }

    fn reinit(&mut self, cfg: TcbConfig) {
        // A fresh socket (smoltcp's own reset keeps some per-connection
        // state, such as whether the last peer used timestamps) and a fresh
        // interface, seeded for this connection's ISN.
        drop(self.sockets.remove(self.handle));
        // SAFETY: the socket that borrowed the rings is gone.
        self.handle = self
            .sockets
            .add(unsafe { new_socket(&mut self.rx_ring, &mut self.tx_ring) });
        self.iface = new_iface(&mut self.q, cfg.local.ip, iface_seed(cfg.iss));
        let q = &mut self.q;
        q.spare.extend(q.pkts.drain(..));
        q.paused = false;
        self.cfg = cfg;
        self.lent = None;
        self.began = false;
        self.reset = false;
        self.stats = TcbStats::default();
    }

    fn set_secret(&mut self, _secret: &[u8; 16]) {}

    // smoltcp reaps neither half-closed nor stalled connections by default.
    fn set_fin_wait2_timeout(&mut self, _ms: u32) {}
    fn set_user_timeout(&mut self, _ms: u32) {}

    fn stats(&self) -> TcbStats {
        TcbStats {
            segs_in: self.stats.segs_in,
            segs_out: self.stats.segs_out,
            ..TcbStats::default()
        }
    }
}
