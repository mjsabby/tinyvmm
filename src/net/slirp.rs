//! libslirp backend (`--net-backend slirp`): QEMU's user-mode network stack,
//! loaded at run time (see `winsys::slirp` and `tools/fetch_libslirp.py`).
//!
//! One worker thread owns the libslirp instance. The vCPU side queues guest
//! frames and pokes a loopback UDP socket; the worker sleeps in `WSAPoll` on
//! that socket and libslirp's own, feeds it the queued frames, and lets it
//! service its host sockets and timers.
//!
//! The guest network is the NAT's: 172.29.255.0/29, gateway .1 (whose TCP
//! ports are the host's loopback, as with the NAT), the guest .2 by DHCP.
//! libslirp's own DNS forwarder is .3. As in QEMU, libslirp takes and builds
//! MTU-sized frames with complete checksums: guest TSO super-segments are
//! segmented in software first (the `NetBackend` default), and frames to the
//! guest carry no offload metadata. Like QEMU's net queue, frames libslirp
//! builds while the guest's RX backlog is deep wait here for it to drain
//! rather than being dropped.

use crate::net::nat::PortForward;
use crate::virtio::net::{NetBackend, NetDevice, RxHeader};
use std::collections::VecDeque;
use std::net::UdpSocket;
use std::os::windows::io::AsRawSocket;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak, mpsc};
use std::thread::JoinHandle;
use winsys::slirp::{Slirp, SlirpConfig, SlirpHost};

/// libslirp's DNS forwarder, offered by its DHCP server.
pub const NAMESERVER_IP: [u8; 4] = [172, 29, 255, 3];
/// Guest frames queued for the worker beyond which more are dropped.
const TX_QUEUE_MAX: usize = 4096;
/// Frames to the guest held while its RX backlog is deep, beyond which more
/// are dropped (libslirp's TCP then retransmits them).
const RX_HOLD_MAX: usize = 8192;
/// Longest the worker sleeps when neither libslirp nor the guest has work.
const IDLE_MS: u32 = 1000;

pub struct SlirpOptions {
    pub port_forwards: Vec<PortForward>,
}

#[derive(Default)]
struct FrameQueue {
    frames: VecDeque<Vec<u8>>,
    spare: Vec<Vec<u8>>,
}

struct Shared {
    queue: Mutex<FrameQueue>,
    /// A wake datagram is on its way, or the worker has yet to look at the
    /// queue: no need to send another.
    wake_armed: AtomicBool,
    /// Connected to the socket the worker polls.
    waker: UdpSocket,
    stop: AtomicBool,
    tx_drops: AtomicU64,
    rx_drops: AtomicU64,
    rx_held_max: AtomicU64,
}

impl Shared {
    fn wake(&self) {
        if !self.wake_armed.swap(true, Ordering::AcqRel) {
            let _ = self.waker.send(&[0]);
        }
    }
}

pub struct SlirpBackend {
    shared: Arc<Shared>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

/// libslirp's view of the guest: frames it sends go to the NIC, or wait in
/// `held` while the guest's RX backlog is deep.
struct Host {
    net: Weak<NetDevice>,
    held: VecDeque<Vec<u8>>,
    spare: Vec<Vec<u8>>,
    shared: Arc<Shared>,
}

impl SlirpHost for Host {
    fn send_packet(&mut self, frame: &[u8]) {
        let Some(dev) = self.net.upgrade() else {
            return;
        };
        if self.held.is_empty() && !dev.rx_congested() {
            dev.inject_rx_gso_batched(frame, RxHeader::default());
            return;
        }
        if self.held.len() >= RX_HOLD_MAX {
            self.shared.rx_drops.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let mut b = self.spare.pop().unwrap_or_default();
        b.clear();
        b.extend_from_slice(frame);
        self.held.push_back(b);
        self.shared
            .rx_held_max
            .fetch_max(self.held.len() as u64, Ordering::Relaxed);
    }

    fn guest_error(&mut self, msg: &str) {
        eprintln!("[slirp] guest error: {msg}");
    }
}

impl Host {
    /// Deliver held frames while the guest has room for them.
    fn flush(&mut self) {
        let Some(dev) = self.net.upgrade() else {
            return;
        };
        while !self.held.is_empty() && !dev.rx_congested() {
            if let Some(b) = self.held.pop_front() {
                dev.inject_rx_gso_batched(&b, RxHeader::default());
                self.spare.push(b);
            }
        }
        dev.notify_rx();
    }
}

impl SlirpBackend {
    /// Start libslirp for `net`. Fails if libslirp can't be loaded or
    /// started; returns the backend and libslirp's version.
    pub fn new(net: &Arc<NetDevice>, opts: SlirpOptions) -> Result<(Arc<Self>, String), String> {
        let version = winsys::slirp::version()?;
        let sock = |what: &str, e: std::io::Error| format!("slirp: {what}: {e}");
        let wake_rx = UdpSocket::bind("127.0.0.1:0").map_err(|e| sock("wake socket", e))?;
        wake_rx
            .set_nonblocking(true)
            .map_err(|e| sock("wake socket", e))?;
        let waker = UdpSocket::bind("127.0.0.1:0").map_err(|e| sock("waker", e))?;
        waker
            .connect(wake_rx.local_addr().map_err(|e| sock("wake socket", e))?)
            .map_err(|e| sock("waker", e))?;
        waker.set_nonblocking(true).map_err(|e| sock("waker", e))?;
        let shared = Arc::new(Shared {
            queue: Mutex::new(FrameQueue::default()),
            wake_armed: AtomicBool::new(false),
            waker,
            stop: AtomicBool::new(false),
            tx_drops: AtomicU64::new(0),
            rx_drops: AtomicU64::new(0),
            rx_held_max: AtomicU64::new(0),
        });
        let (ready_tx, ready_rx) = mpsc::channel();
        let host = Host {
            net: Arc::downgrade(net),
            held: VecDeque::new(),
            spare: Vec::new(),
            shared: shared.clone(),
        };
        let s = shared.clone();
        let worker = std::thread::Builder::new()
            .name("slirp".into())
            .spawn(move || run(s, host, opts, wake_rx, ready_tx))
            .map_err(|e| format!("slirp: worker thread: {e}"))?;
        match ready_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = worker.join();
                return Err(e);
            }
            Err(_) => return Err("slirp: worker died during start-up".into()),
        }
        Ok((
            Arc::new(SlirpBackend {
                shared,
                worker: Mutex::new(Some(worker)),
            }),
            version,
        ))
    }
}

/// The worker: start libslirp, then loop.
fn run(
    shared: Arc<Shared>,
    host: Host,
    opts: SlirpOptions,
    wake_rx: UdpSocket,
    ready: mpsc::Sender<Result<(), String>>,
) {
    let gw = crate::net::GATEWAY_IP;
    let mask = crate::net::NETMASK;
    let cfg = SlirpConfig {
        network: std::array::from_fn(|i| gw[i] & mask[i]),
        netmask: mask,
        host: gw,
        dhcp_start: crate::net::GUEST_IP,
        nameserver: NAMESERVER_IP,
        mtu: 1500,
    };
    let mut slirp = match Slirp::new(&cfg, host) {
        Ok(s) => s,
        Err(e) => {
            let _ = ready.send(Err(format!("slirp: {e}")));
            return;
        }
    };
    for pf in &opts.port_forwards {
        if !slirp.add_hostfwd(
            false,
            pf.host_addr,
            pf.host_port,
            pf.guest_ip,
            pf.guest_port,
        ) {
            eprintln!(
                "[slirp] port-forward {:?}:{} -> {:?}:{} failed",
                pf.host_addr, pf.host_port, pf.guest_ip, pf.guest_port
            );
        }
    }
    let _ = ready.send(Ok(()));
    let wake = [wake_rx.as_raw_socket() as usize];
    let mut batch: VecDeque<Vec<u8>> = VecDeque::new();
    let mut drain = [0u8; 64];
    while !shared.stop.load(Ordering::Acquire) {
        // Don't sleep on frames the guest may already have room for.
        let max = if slirp.host().held.is_empty() {
            IDLE_MS
        } else {
            1
        };
        let polled = slirp.poll(max, &wake);
        if polled.readable & 1 != 0 {
            while wake_rx.recv(&mut drain).is_ok() {}
        }
        // Disarm before taking the queue: a frame queued after this pokes
        // the socket again, so it is never left waiting for the idle timeout.
        shared.wake_armed.store(false, Ordering::Release);
        std::mem::swap(&mut batch, &mut shared.queue.lock().unwrap().frames);
        for f in &batch {
            slirp.input(f);
        }
        if !batch.is_empty() {
            let mut q = shared.queue.lock().unwrap();
            let room = TX_QUEUE_MAX.saturating_sub(q.spare.len());
            q.spare.extend(batch.drain(..).take(room));
            batch.clear();
        }
        slirp.host().flush();
    }
}

impl NetBackend for SlirpBackend {
    fn on_guest_frame(&self, frame: &[u8]) {
        {
            let mut q = self.shared.queue.lock().unwrap();
            if q.frames.len() >= TX_QUEUE_MAX {
                self.shared.tx_drops.fetch_add(1, Ordering::Relaxed);
                return;
            }
            let mut b = q.spare.pop().unwrap_or_default();
            b.clear();
            b.extend_from_slice(frame);
            q.frames.push_back(b);
        }
        self.shared.wake();
    }

    /// The guest drained its RX backlog: deliver the frames held for it.
    fn on_rx_space(&self) {
        self.shared.wake();
    }

    fn diag_summary(&self) -> Option<String> {
        let ld = |a: &AtomicU64| a.load(Ordering::Relaxed);
        Some(format!(
            "slirp: tx_drops={} rx_drops={} rx_held_max={}",
            ld(&self.shared.tx_drops),
            ld(&self.shared.rx_drops),
            ld(&self.shared.rx_held_max),
        ))
    }

    fn stop(&self) {
        self.shared.stop.store(true, Ordering::Release);
        let _ = self.shared.waker.send(&[0]);
        if let Some(h) = self.worker.lock().unwrap().take() {
            let _ = h.join();
        }
    }
}
