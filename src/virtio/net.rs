//! virtio-net device (spec §5.1) with a pluggable backend. The device owns the
//! two virtqueues and the RX-injection path; a `NetBackend` decides what to do
//! with guest TX frames and may inject RX frames back. Port of
//! src/virtio/virtio_net.cpp + the backend split from net_backend.h.

use crate::diag::etw;
use crate::virtio::device::{
    DEVICE_ID_NET, FEATURE_RING_EVENT_IDX, FEATURE_VERSION_1, VirtioDevice,
};
use crate::virtio::queue::{PoppedChain, Virtqueue};
use crate::whp::GuestMemory;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

const NET_F_CSUM: u64 = 1 << 0;
const NET_F_GUEST_CSUM: u64 = 1 << 1;
const NET_FEATURE_MAC: u64 = 1 << 5;
const NET_F_GUEST_TSO4: u64 = 1 << 7;
const NET_F_HOST_TSO4: u64 = 1 << 11;
const NET_F_MRG_RXBUF: u64 = 1 << 15;
const NET_FEATURE_STATUS: u64 = 1 << 16;

const NET_STATUS_LINK_UP: u16 = 1;
const VIRTIO_NET_HDR_SIZE: usize = 12;

// virtio_net_hdr.flags / .gso_type values (spec §5.1.6).
pub const HDR_F_NEEDS_CSUM: u8 = 1;
pub const HDR_F_DATA_VALID: u8 = 2;
pub const HDR_GSO_NONE: u8 = 0;
pub const HDR_GSO_TCPV4: u8 = 1;

/// The 10 driver-visible bytes of `struct virtio_net_hdr` for an RX frame
/// (`num_buffers` is appended by `deliver_rx`). Backends pass this with
/// [`NetDevice::inject_rx_gso`] to deliver a coalesced (>MTU) TCP super-frame.
#[derive(Clone, Copy, Default)]
pub struct RxHeader {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

/// The same 10 bytes on a guest TX frame. `csum_start` is relative to the
/// start of the Ethernet frame (header already stripped).
pub type TxHeader = RxHeader;

impl RxHeader {
    fn parse(h: &[u8; VIRTIO_NET_HDR_SIZE]) -> Self {
        let le = |i: usize| u16::from_le_bytes([h[i], h[i + 1]]);
        RxHeader {
            flags: h[0],
            gso_type: h[1],
            hdr_len: le(2),
            gso_size: le(4),
            csum_start: le(6),
            csum_offset: le(8),
        }
    }

    /// True when the frame carries offload work (partial checksum or GSO).
    pub fn has_offload(&self) -> bool {
        self.flags & HDR_F_NEEDS_CSUM != 0 || self.gso_type != HDR_GSO_NONE
    }
}

/// Per-slot capacity + slot count of the preallocated RX delivery pool, so
/// `inject_rx` copies into a pooled buffer instead of allocating a `Vec` per
/// inbound frame. With `GUEST_TSO4` a single delivered frame may carry up to
/// ~64 KiB of TCP payload, so the slot must hold a full GSO super-frame.
const RX_FRAME_CAP: usize = 65600;
const RX_POOL_SLOTS: usize = 64;
/// Backlog depth at which [`NetDevice::rx_congested`] tells a backend to stop
/// sending, and the depth it must drain back to before the backend is woken
/// ([`NetBackend::on_rx_space`]). The gap below [`RX_POOL_SLOTS`] absorbs
/// frames already being built and traffic that isn't throttled (ARP, ICMP,
/// UDP); the hysteresis batches the wakes.
const RX_BACKLOG_HIGH: usize = 32;
const RX_BACKLOG_LOW: usize = 8;
/// Most frames `inject_rx_gso_batched` publishes before checking whether the
/// guest wants an interrupt, if the backend hasn't called `notify_rx` yet.
/// Eight 64 KiB GSO frames take about half a 256-entry ring of 4 KiB
/// mergeable buffers, so a sleeping guest wakes with buffers to spare.
pub const RX_NOTIFY_BATCH: u32 = 8;

pub const NET_RX_QUEUE: u32 = 0;
pub const NET_TX_QUEUE: u32 = 1;
pub const NET_QUEUE_MAX: u32 = 256;

pub type IrqFn = Box<dyn Fn(u32) + Send + Sync>;

/// Data-plane peer of a `NetDevice`. `on_guest_frame` runs on the vCPU thread
/// for each transmitted Ethernet frame (virtio_net_hdr already stripped); it
/// must not block. Backends inject inbound frames via `NetDevice::inject_rx`.
pub trait NetBackend: Send + Sync {
    /// A complete, MTU-sized frame with valid checksums.
    fn on_guest_frame(&self, frame: &[u8]);
    /// A frame with TX offload work pending (`CSUM` / `HOST_TSO4`): a partial
    /// L4 checksum and/or a TCPv4 super-segment of up to ~64 KiB. `frame` is
    /// scratch and may be modified. The default finishes the work in software
    /// (checksum completion + segmentation) and feeds `on_guest_frame`.
    fn on_guest_frame_offload(&self, frame: &mut [u8], hdr: &TxHeader) {
        tx_offload_software(frame, hdr, &mut |f| self.on_guest_frame(f));
    }
    fn stop(&self) {}
    /// The RX backlog drained after [`NetDevice::rx_congested`] reported it
    /// full: resume sending. Runs on whichever thread drained it (doorbell,
    /// vCPU, or the backend's own via `inject_rx`), so it must not block.
    fn on_rx_space(&self) {}
    /// Backend counters to append to the NIC's exit summary, if any.
    fn diag_summary(&self) -> Option<String> {
        None
    }
}

const ETH_HDR_LEN: usize = 14;
const TCP_FIN: u8 = 0x01;
const TCP_PSH: u8 = 0x08;
const TCP_CWR: u8 = 0x80;

thread_local! {
    static TSO_SCRATCH: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Software fallback for TX offloads: emits finished, MTU-sized frames.
/// Malformed or unsupported requests are dropped.
pub fn tx_offload_software(frame: &mut [u8], hdr: &TxHeader, emit: &mut dyn FnMut(&[u8])) {
    match hdr.gso_type {
        HDR_GSO_NONE
            if (hdr.flags & HDR_F_NEEDS_CSUM == 0
                || complete_csum(frame, hdr.csum_start, hdr.csum_offset)) =>
        {
            emit(frame);
        }
        HDR_GSO_TCPV4 => {
            TSO_SCRATCH.with(|s| tso4_segment(frame, hdr.gso_size, &mut s.borrow_mut(), emit))
        }
        _ => {}
    }
}

/// Finish a partial checksum (spec §5.1.6.2): the field at
/// `csum_start + csum_offset` holds the pseudo-header sum; fold everything from
/// `csum_start` to the end and store the complement there.
fn complete_csum(frame: &mut [u8], csum_start: u16, csum_offset: u16) -> bool {
    let s = csum_start as usize;
    let o = s + csum_offset as usize;
    if s >= frame.len() || o + 2 > frame.len() {
        return false;
    }
    let c = crate::net::wire::checksum16(&[&frame[s..]]);
    frame[o..o + 2].copy_from_slice(&c.to_be_bytes());
    true
}

/// Split a TCPv4 super-segment into `mss`-payload frames with fresh IPv4
/// lengths/IDs/checksums, per-segment sequence numbers, FIN/PSH only on the
/// last segment, CWR only on the first, and full TCP checksums.
fn tso4_segment(frame: &[u8], mss: u16, seg: &mut Vec<u8>, emit: &mut dyn FnMut(&[u8])) {
    let be16 = |b: &[u8], i: usize| u16::from_be_bytes([b[i], b[i + 1]]);
    let ip = ETH_HDR_LEN;
    if frame.len() < ip + 40
        || be16(frame, 12) != 0x0800
        || frame[ip] >> 4 != 4
        || frame[ip + 9] != 6
    {
        return;
    }
    let ihl = (frame[ip] & 0x0F) as usize * 4;
    let tcp = ip + ihl;
    if ihl < 20 || frame.len() < tcp + 20 {
        return;
    }
    let thl = (frame[tcp + 12] >> 4) as usize * 4;
    let hl = tcp + thl;
    let mss = mss as usize;
    if thl < 20 || frame.len() < hl || mss == 0 {
        return;
    }
    let tot = be16(frame, ip + 2) as usize;
    let end = if tot >= ihl + thl && ip + tot <= frame.len() {
        ip + tot
    } else {
        frame.len()
    };
    let seq0 = u32::from_be_bytes(frame[tcp + 4..tcp + 8].try_into().unwrap());
    let id0 = be16(frame, ip + 4);
    let mut off = hl;
    let mut i: u16 = 0;
    loop {
        let n = mss.min(end - off);
        let last = off + n >= end;
        seg.clear();
        seg.extend_from_slice(&frame[..hl]);
        seg.extend_from_slice(&frame[off..off + n]);
        let s = &mut seg[..];
        s[ip + 2..ip + 4].copy_from_slice(&((ihl + thl + n) as u16).to_be_bytes());
        s[ip + 4..ip + 6].copy_from_slice(&id0.wrapping_add(i).to_be_bytes());
        s[ip + 10] = 0;
        s[ip + 11] = 0;
        let c = crate::net::wire::checksum16(&[&s[ip..tcp]]);
        s[ip + 10..ip + 12].copy_from_slice(&c.to_be_bytes());
        let seq = seq0.wrapping_add((off - hl) as u32);
        s[tcp + 4..tcp + 8].copy_from_slice(&seq.to_be_bytes());
        if !last {
            s[tcp + 13] &= !(TCP_FIN | TCP_PSH);
        }
        if i > 0 {
            s[tcp + 13] &= !TCP_CWR;
        }
        s[tcp + 16] = 0;
        s[tcp + 17] = 0;
        let mut pseudo = [0u8; 12];
        pseudo[..8].copy_from_slice(&s[ip + 12..ip + 20]);
        pseudo[9] = 6;
        pseudo[10..12].copy_from_slice(&((thl + n) as u16).to_be_bytes());
        let c = crate::net::wire::checksum16(&[&pseudo, &s[tcp..]]);
        s[tcp + 16..tcp + 18].copy_from_slice(&c.to_be_bytes());
        emit(s);
        if last {
            break;
        }
        off += n;
        i = i.wrapping_add(1);
    }
}

/// Preallocated RX delivery pool: fixed slot storage + a free list + the queue
/// of (slot, len, hdr) awaiting delivery to the guest. No per-frame allocation.
struct RxPool {
    slots: Vec<Box<[u8; RX_FRAME_CAP]>>,
    free: Vec<u32>,
    pending: VecDeque<(u32, u32, RxHeader)>,
    chain: PoppedChain,
}

impl RxPool {
    fn new() -> Self {
        RxPool {
            // Boxed slots: 64 × 64 KiB on the heap (a flat Vec<[u8; 65600]>
            // would be one 4 MiB contiguous allocation; per-slot Box keeps each
            // page-granular and avoids a large stack temporary in vec![..]).
            slots: (0..RX_POOL_SLOTS)
                .map(|_| Box::new([0u8; RX_FRAME_CAP]))
                .collect(),
            free: (0..RX_POOL_SLOTS as u32).collect(),
            pending: VecDeque::new(),
            chain: PoppedChain::default(),
        }
    }
    fn clear(&mut self) {
        self.pending.clear();
        self.free.clear();
        self.free.extend(0..self.slots.len() as u32);
    }
}

/// Reusable TX assembly buffers (frame bytes + popped-chain descriptors) so the
/// TX drain path is allocation-free.
struct TxScratch {
    frame: Vec<u8>,
    chain: PoppedChain,
}

// RxPool/TxScratch hold a reused PoppedChain whose ChainBufs are raw pointers
// into guest RAM. Like Virtqueue, they're only dereferenced under the queue
// lock during a drain (and cleared/refilled each pop_into), so sending the
// owning device between threads is safe.
unsafe impl Send for RxPool {}
unsafe impl Send for TxScratch {}

/// RX slow-path counters. Bumped only when the guest's RX ring can't take a
/// frame right away, so they cost nothing while the ring stays stocked.
#[derive(Default)]
pub struct RxCounters {
    /// Frames that had to wait in the backlog for guest RX buffers.
    backlogged: AtomicU64,
    /// Times the ring ran dry mid-frame and the popped buffers were given back.
    rewinds: AtomicU64,
    /// Frames published truncated because even a whole ring couldn't hold them.
    truncated: AtomicU64,
    /// Frames dropped because the backlog was full.
    backlog_drops: AtomicU64,
    /// Deepest the backlog got.
    backlog_max: AtomicU64,
    /// Times a backend was told to stop sending because the backlog was deep.
    throttles: AtomicU64,
}

pub struct NetDevice {
    rxq: Mutex<Virtqueue>,
    txq: Mutex<Virtqueue>,
    rx: Mutex<RxPool>,
    tx_scratch: Mutex<TxScratch>,
    mac: [u8; 6],
    link_status: AtomicU16,
    driver_ok: AtomicBool,
    acked_features: AtomicU64,
    irq: OnceLock<IrqFn>,
    // Set once at setup; read lock-free (no Arc clone) on every TX kick.
    // `backend_detached` is the OnceLock-compatible equivalent of taking the
    // Option to None at snapshot quiesce (a OnceLock can't be cleared).
    backend: OnceLock<Arc<dyn NetBackend>>,
    backend_detached: AtomicBool,
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    /// Interrupts this device asked its transport to raise, per queue.
    rx_irqs: AtomicU64,
    tx_irqs: AtomicU64,
    /// Frames `inject_rx_gso_batched` published whose interrupt check waits
    /// for `notify_rx`.
    rx_unsignaled: AtomicU32,
    rx_ctr: RxCounters,
    /// `rx.pending.len()`, readable without the lock.
    rx_backlog: AtomicUsize,
    /// A backend was told the backlog is congested and wants a wake-up.
    rx_wake: AtomicBool,
}

impl NetDevice {
    pub fn new(mem: Arc<GuestMemory>, mac: [u8; 6]) -> Arc<Self> {
        Arc::new(NetDevice {
            rxq: Mutex::new(Virtqueue::new(mem.clone(), NET_QUEUE_MAX)),
            txq: Mutex::new(Virtqueue::new(mem, NET_QUEUE_MAX)),
            rx: Mutex::new(RxPool::new()),
            tx_scratch: Mutex::new(TxScratch {
                frame: Vec::with_capacity(RX_FRAME_CAP),
                chain: PoppedChain::default(),
            }),
            mac,
            link_status: AtomicU16::new(NET_STATUS_LINK_UP),
            driver_ok: AtomicBool::new(false),
            acked_features: AtomicU64::new(0),
            irq: OnceLock::new(),
            backend: OnceLock::new(),
            backend_detached: AtomicBool::new(false),
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            rx_irqs: AtomicU64::new(0),
            tx_irqs: AtomicU64::new(0),
            rx_unsignaled: AtomicU32::new(0),
            rx_ctr: RxCounters::default(),
            rx_backlog: AtomicUsize::new(0),
            rx_wake: AtomicBool::new(false),
        })
    }

    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }
    pub fn set_irq_callback(&self, f: IrqFn) {
        let _ = self.irq.set(f);
    }
    pub fn set_backend(&self, b: Arc<dyn NetBackend>) {
        let _ = self.backend.set(b);
    }
    /// Stop + detach the host backend (drains its worker threads). Used to
    /// quiesce the data plane before a snapshot capture so no inbound frame
    /// mutates the RX queue / guest RAM mid-capture.
    pub fn quiesce_backend(&self) {
        self.backend_detached.store(true, Ordering::Release);
        if let Some(b) = self.backend.get() {
            b.stop();
        }
        if etw::enabled(etw::INFO, etw::kw::LIFECYCLE) {
            let m = self.mac();
            let mac = m.iter().fold(0u64, |a, &b| (a << 8) | b as u64);
            etw::Event::new("NetBackendStop", etw::INFO, etw::kw::LIFECYCLE)
                .hex64("mac", mac)
                .write();
        }
    }
    pub fn tx_packets(&self) -> u64 {
        self.tx_packets.load(Ordering::Relaxed)
    }
    pub fn rx_packets(&self) -> u64 {
        self.rx_packets.load(Ordering::Relaxed)
    }

    /// One-line data-path summary for the exit report: frame counts, interrupt
    /// counts (`msix`: what the transport's MSI-X actually injected, from the
    /// caller), the RX slow-path counters, and whatever the backend adds.
    pub fn diag_summary(&self, msix: u64) -> String {
        let c = &self.rx_ctr;
        let ld = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let mut s = format!(
            "rx_frames={} tx_frames={} msix={msix} rx_irqs={} tx_irqs={} rx_backlogged={} \
             rx_rewinds={} rx_truncated={} rx_backlog_drops={} rx_backlog_max={} \
             rx_throttles={}",
            self.rx_packets(),
            self.tx_packets(),
            ld(&self.rx_irqs),
            ld(&self.tx_irqs),
            ld(&c.backlogged),
            ld(&c.rewinds),
            ld(&c.truncated),
            ld(&c.backlog_drops),
            ld(&c.backlog_max),
            ld(&c.throttles),
        );
        if let Some(extra) = self.backend.get().and_then(|b| b.diag_summary()) {
            s.push_str(" | ");
            s.push_str(&extra);
        }
        s
    }

    /// Whether the RX backlog is too deep for a backend to keep sending. When
    /// true, stop producing guest-bound frames until [`NetBackend::on_rx_space`]
    /// is called, which happens once the guest has taken most of the backlog.
    /// One atomic load while uncongested.
    pub fn rx_congested(&self) -> bool {
        if self.rx_backlog.load(Ordering::Relaxed) < RX_BACKLOG_HIGH {
            return false;
        }
        let armed = !self.rx_wake.swap(true, Ordering::SeqCst);
        // Re-check after arming: a drain racing the arm either sees the flag
        // (and wakes us) or has already stored the lower depth read here.
        let congested = self.rx_backlog.load(Ordering::SeqCst) >= RX_BACKLOG_HIGH;
        if congested && armed {
            self.rx_ctr.throttles.fetch_add(1, Ordering::Relaxed);
        }
        congested
    }

    /// Wake a backend that [`Self::rx_congested`] paused, once the backlog has
    /// drained to `left` frames (or was discarded). Read-only unless armed.
    fn maybe_wake_backend(&self, left: usize) {
        if left > RX_BACKLOG_LOW
            || !self.rx_wake.load(Ordering::SeqCst)
            || !self.rx_wake.swap(false, Ordering::SeqCst)
        {
            return;
        }
        if !self.backend_detached.load(Ordering::Acquire)
            && let Some(b) = self.backend.get()
        {
            b.on_rx_space();
        }
    }

    fn raise(&self, qidx: u32) {
        let n = if qidx == NET_RX_QUEUE {
            &self.rx_irqs
        } else {
            &self.tx_irqs
        };
        n.fetch_add(1, Ordering::Relaxed);
        if let Some(cb) = self.irq.get() {
            cb(qidx);
        }
    }

    /// Drain TX: strip the virtio_net_hdr, complete the chain, hand the frame
    /// to the backend. Assembles each frame into a reused scratch buffer (no
    /// per-frame allocation) and posts inline.
    fn pump_tx(&self) {
        // Lock-free borrow of the set-once backend: no Mutex and no Arc clone
        // on the TX-kick path. `detached` mirrors the pre-snapshot take()->None.
        let backend = if self.backend_detached.load(Ordering::Acquire) {
            None
        } else {
            self.backend.get()
        };
        let mut s = self.tx_scratch.lock().unwrap();
        let TxScratch { frame, chain } = &mut *s;
        let mut tx_interrupt = false;
        let mut count = 0u64;
        {
            let mut tx = self.txq.lock().unwrap();
            if tx.ready() {
                while tx.pop_into(chain) {
                    let hdr = read_tx_hdr(chain);
                    frame_into(frame, chain, VIRTIO_NET_HDR_SIZE);
                    tx.push(chain.head_index, 0);
                    if !frame.is_empty() {
                        if etw::enabled(etw::VERBOSE, etw::kw::NET) {
                            etw::Event::new("NetTx", etw::VERBOSE, etw::kw::NET)
                                .u32("len", frame.len() as u32)
                                .write();
                        }
                        if let Some(b) = backend {
                            // on_guest_frame only posts to the NAT IOCP (or
                            // loopback inject) — it never re-enters the device's
                            // TX path, so holding txq here is safe.
                            if hdr.has_offload() {
                                b.on_guest_frame_offload(frame, &hdr);
                            } else {
                                b.on_guest_frame(frame);
                            }
                        }
                        count += 1;
                    }
                }
                if count > 0 {
                    tx_interrupt = tx.should_interrupt_driver();
                }
            }
        }
        if tx_interrupt {
            self.raise(NET_TX_QUEUE);
        }
        if count > 0 {
            self.tx_packets.fetch_add(count, Ordering::Relaxed);
        }
    }

    /// Inject an inbound Ethernet frame toward the guest with a zeroed
    /// virtio_net_hdr (no GSO/csum metadata). See [`Self::inject_rx_gso`].
    pub fn inject_rx(&self, frame: &[u8]) {
        self.inject_rx_gso(frame, RxHeader::default());
    }

    /// Inject an inbound Ethernet frame with an explicit `virtio_net_hdr`. With
    /// `gso_type != GSO_NONE` the frame may exceed MTU (a coalesced TCP super-
    /// segment) and `gso_size` carries the original MSS; the guest's GRO path
    /// processes it as one skb instead of `payload/MSS` separate segments —
    /// the lever for the ~207 MB/s vCPU-bound RX ceiling. Thread-safe.
    ///
    /// Steady-state fast path: when nothing is queued ahead and the guest has
    /// posted an RX buffer, write straight from `frame` into the descriptor
    /// chain — skipping the ~64 KiB RxPool slot copy. The pool is only used
    /// when the guest hasn't replenished (backpressure).
    pub fn inject_rx_gso(&self, frame: &[u8], hdr: RxHeader) {
        self.inject_rx_frame(frame, hdr, true);
    }

    /// Like [`Self::inject_rx_gso`], but the guest's interrupt waits for
    /// [`Self::notify_rx`], so a backend delivering a burst interrupts the
    /// guest once for all of it. The frame is published at once (a guest
    /// that is polling takes it right away); only the interrupt waits, and
    /// for at most [`RX_NOTIFY_BATCH`] frames, so a sleeping guest wakes
    /// while its ring still has buffers.
    pub fn inject_rx_gso_batched(&self, frame: &[u8], hdr: RxHeader) {
        self.inject_rx_frame(frame, hdr, false);
    }

    /// Interrupt the guest for frames [`Self::inject_rx_gso_batched`]
    /// published, if it asked for one (EVENT_IDX). One atomic swap when
    /// nothing is waiting.
    pub fn notify_rx(&self) {
        // Swap before checking: a frame published after the swap is counted
        // again, so it is never left without a later check.
        if self.rx_unsignaled.swap(0, Ordering::AcqRel) == 0 {
            return;
        }
        let irq = self.rxq.lock().unwrap().should_interrupt_driver();
        if irq {
            self.raise(NET_RX_QUEUE);
        }
    }

    fn inject_rx_frame(&self, frame: &[u8], hdr: RxHeader, notify: bool) {
        let n = frame.len();
        if n == 0 || n > RX_FRAME_CAP {
            return;
        }
        if etw::enabled(etw::VERBOSE, etw::kw::NET) {
            etw::Event::new("NetRx", etw::VERBOSE, etw::kw::NET)
                .u32("len", n as u32)
                .u32("gso", hdr.gso_type as u32)
                .write();
        }
        let mrg = self.mrg_rxbuf();
        {
            let mut rx = self.rx.lock().unwrap();
            let mut rxq = self.rxq.lock().unwrap();
            if rxq.ready() && rx.pending.is_empty() {
                let rxp = &mut *rx;
                if deliver_frame(&mut rxq, &mut rxp.chain, frame, &hdr, mrg, &self.rx_ctr).is_some()
                {
                    self.rx_packets.fetch_add(1, Ordering::Relaxed);
                    let irq = notify && rxq.should_interrupt_driver();
                    drop(rxq);
                    drop(rx);
                    if irq {
                        self.raise(NET_RX_QUEUE);
                    } else if !notify
                        && self.rx_unsignaled.fetch_add(1, Ordering::AcqRel) + 1 >= RX_NOTIFY_BATCH
                    {
                        self.notify_rx();
                    }
                    return;
                }
            }
            drop(rxq);
            let Some(idx) = rx.free.pop() else {
                self.rx_ctr.backlog_drops.fetch_add(1, Ordering::Relaxed);
                if crate::diag::net_enabled() {
                    eprintln!("[net] rx backlog full: dropped a {n}-byte frame");
                }
                if etw::enabled(etw::VERBOSE, etw::kw::NET) {
                    etw::Event::new("NetRxDrop", etw::VERBOSE, etw::kw::NET)
                        .u32("len", n as u32)
                        .write();
                }
                return;
            };
            rx.slots[idx as usize][..n].copy_from_slice(frame);
            rx.pending.push_back((idx, n as u32, hdr));
            self.rx_backlog.store(rx.pending.len(), Ordering::SeqCst);
            self.rx_ctr.backlogged.fetch_add(1, Ordering::Relaxed);
            self.rx_ctr
                .backlog_max
                .fetch_max(rx.pending.len() as u64, Ordering::Relaxed);
        }
        self.deliver_rx();
    }

    /// Whether `MRG_RXBUF` was negotiated (multi-buffer RX delivery is allowed).
    fn mrg_rxbuf(&self) -> bool {
        self.acked_features.load(Ordering::Relaxed) & NET_F_MRG_RXBUF != 0
    }

    /// Whether the guest negotiated everything a backend needs to deliver
    /// coalesced (>MTU) TCPv4 super-frames via [`Self::inject_rx_gso`].
    pub fn rx_gso_ok(&self) -> bool {
        const NEED: u64 = NET_F_GUEST_CSUM | NET_F_GUEST_TSO4 | NET_F_MRG_RXBUF;
        self.acked_features.load(Ordering::Relaxed) & NEED == NEED
    }

    /// Whether the guest accepts partial checksums: a backend may then
    /// deliver frames with `HDR_F_NEEDS_CSUM` instead of summing payloads.
    pub fn rx_csum_ok(&self) -> bool {
        self.acked_features.load(Ordering::Relaxed) & NET_F_GUEST_CSUM != 0
    }

    /// Move queued frames into the guest's RX buffers (the RxPool fallback path
    /// — the steady-state direct delivery happens inline in `inject_rx_gso`).
    fn deliver_rx(&self) {
        let mut rx_interrupt = false;
        let mrg = self.mrg_rxbuf();
        let left;
        {
            let mut rx = self.rx.lock().unwrap();
            let mut rxq = self.rxq.lock().unwrap();
            if rxq.ready() {
                let mut any = false;
                let rxp = &mut *rx;
                while let Some(&(idx, len, hdr)) = rxp.pending.front() {
                    let frame = &rxp.slots[idx as usize][..len as usize];
                    if deliver_frame(&mut rxq, &mut rxp.chain, frame, &hdr, mrg, &self.rx_ctr)
                        .is_none()
                    {
                        break;
                    }
                    rxp.pending.pop_front();
                    rxp.free.push(idx);
                    any = true;
                    self.rx_packets.fetch_add(1, Ordering::Relaxed);
                }
                if any {
                    rx_interrupt = rxq.should_interrupt_driver();
                }
            }
            left = rx.pending.len();
            self.rx_backlog.store(left, Ordering::SeqCst);
        }
        if rx_interrupt {
            self.raise(NET_RX_QUEUE);
        }
        self.maybe_wake_backend(left);
    }
}

/// Deliver one frame into guest RX chain(s). With MRG_RXBUF a frame may span
/// several chains: the first carries the 12-byte header (with `num_buffers`
/// patched once the count is known), the rest carry raw payload. Each consumed
/// chain is pushed to the used ring with its bytes-written. Returns `None` if
/// no RX buffer is available (frame NOT delivered — caller queues it).
fn deliver_frame(
    rxq: &mut Virtqueue,
    chain: &mut PoppedChain,
    frame: &[u8],
    hdr: &RxHeader,
    mrg: bool,
    ctr: &RxCounters,
) -> Option<u16> {
    // Bounded: a refill racing `rewind_avail` may not kick, so retry rather
    // than wait for it, but never spin on a ring a guest keeps poking.
    for _ in 0..4 {
        let cursor = rxq.avail_cursor();
        if !rxq.pop_into(chain) {
            return None;
        }
        let (mut written, hdr_ptr) = write_first_rx(chain, hdr, frame);
        let head0 = chain.head_index;
        let used0 = written + VIRTIO_NET_HDR_SIZE as u32;
        let mut nbufs: u16 = 1;
        // 64 spill chains covers a 64 KiB frame across the driver's initial
        // ~1.5 KiB mergeable buffers (which adapt upward toward PAGE_SIZE).
        let mut extra: [(u16, u32); 64] = [(0, 0); 64];
        let mut ran_dry = false;
        while mrg && (written as usize) < frame.len() && (nbufs as usize) <= extra.len() {
            if !rxq.pop_into(chain) {
                ran_dry = true;
                break;
            }
            let w = write_more_rx(chain, &frame[written as usize..]);
            extra[nbufs as usize - 1] = (chain.head_index, w);
            written += w;
            nbufs += 1;
            if w == 0 {
                break;
            }
        }
        // Out of guest RX buffers mid-frame. Publishing the prefix would hand
        // the guest a truncated packet that it drops: for a coalesced TCP
        // super-frame that is ~64 KB of loss. Give the chains back so the
        // caller queues the frame until the driver refills the ring. Only if
        // even a whole ring can't hold it, publish what fits rather than wedge
        // every later frame behind it.
        if ran_dry && u32::from(nbufs) < rxq.size() {
            ctr.rewinds.fetch_add(1, Ordering::Relaxed);
            if rxq.rewind_avail(cursor) {
                continue;
            }
            return None;
        }
        if (written as usize) < frame.len() {
            ctr.truncated.fetch_add(1, Ordering::Relaxed);
            if crate::diag::net_enabled() {
                eprintln!(
                    "[net] rx frame truncated: {written} of {} bytes in {nbufs} buffers",
                    frame.len()
                );
            }
        }
        if let Some(p) = hdr_ptr {
            unsafe {
                *p.add(10) = nbufs as u8;
                *p.add(11) = (nbufs >> 8) as u8;
            }
        }
        // All of the frame's buffers become visible together (one used.idx
        // update): see `Virtqueue::add_used`.
        rxq.add_used(head0, used0);
        for &(h, u) in &extra[..nbufs as usize - 1] {
            rxq.add_used(h, u);
        }
        rxq.publish_used();
        return Some(nbufs);
    }
    None
}

/// Hard cap on an assembled guest TX frame: a `HOST_TSO4` super-segment is at
/// most a 64 KiB IPv4 datagram plus the Ethernet (and a VLAN) header. A hostile
/// chain (overlapping indirect descriptors summing to ~guest-RAM-size) must not
/// balloon `out` to OOM/abort.
pub const TX_FRAME_CAP: usize = ETH_HDR_LEN + 4 + 65535;

/// Copy the leading virtio_net_hdr out of a TX chain (it may span buffers).
/// A chain too short to hold it yields an all-zero (no-offload) header.
fn read_tx_hdr(chain: &PoppedChain) -> TxHeader {
    let mut h = [0u8; VIRTIO_NET_HDR_SIZE];
    let mut n = 0;
    for b in &chain.bufs {
        if b.write {
            continue;
        }
        let s = b.as_slice();
        let take = s.len().min(VIRTIO_NET_HDR_SIZE - n);
        h[n..n + take].copy_from_slice(&s[..take]);
        n += take;
        if n == VIRTIO_NET_HDR_SIZE {
            return TxHeader::parse(&h);
        }
    }
    TxHeader::default()
}

/// Concatenate a chain's device-readable buffers, skipping `skip` leading
/// (virtio_net_hdr) bytes, into `out` (cleared first). No allocation when `out`
/// already has capacity. Truncates at [`TX_FRAME_CAP`].
fn frame_into(out: &mut Vec<u8>, chain: &PoppedChain, skip: usize) {
    out.clear();
    let mut remaining_skip = skip;
    for b in &chain.bufs {
        if b.write {
            continue;
        }
        let s = b.as_slice();
        if remaining_skip >= s.len() {
            remaining_skip -= s.len();
            continue;
        }
        let src = &s[remaining_skip..];
        let take = src.len().min(TX_FRAME_CAP - out.len());
        out.extend_from_slice(&src[..take]);
        if out.len() >= TX_FRAME_CAP {
            break;
        }
        remaining_skip = 0;
    }
}

/// Write the 12-byte virtio_net_hdr (from `hdr`, `num_buffers` left as 0 for
/// later patching) followed by as much of `frame` as fits into the chain's
/// writable buffers. Returns (frame bytes written, pointer to byte 0 of the
/// header if at least 12 contiguous writable bytes were available — used to
/// patch `num_buffers` once the MRG_RXBUF chain count is known). One memcpy on
/// the common single-buffer path.
fn write_first_rx(chain: &mut PoppedChain, hdr: &RxHeader, frame: &[u8]) -> (u32, Option<*mut u8>) {
    let mut h = [0u8; VIRTIO_NET_HDR_SIZE];
    h[0] = hdr.flags;
    h[1] = hdr.gso_type;
    h[2..4].copy_from_slice(&hdr.hdr_len.to_le_bytes());
    h[4..6].copy_from_slice(&hdr.gso_size.to_le_bytes());
    h[6..8].copy_from_slice(&hdr.csum_start.to_le_bytes());
    h[8..10].copy_from_slice(&hdr.csum_offset.to_le_bytes());
    // num_buffers: default to 1 so a header that (theoretically) splits across
    // buffers — leaving no patch pointer — is still valid for the guest's
    // `receive_mergeable` (num_buffers=0 would underflow its `while --n` loop).
    // The caller patches the real count via `hdr_ptr` in the normal case.
    h[10] = 1;

    let mut hdr_left = VIRTIO_NET_HDR_SIZE;
    let mut hdr_ptr: Option<*mut u8> = None;
    let mut frame_off = 0usize;
    for b in chain.bufs.iter_mut() {
        if !b.write {
            continue;
        }
        let dst = b.as_mut_slice();
        let mut di = 0usize;
        if hdr_left > 0 {
            let n = hdr_left.min(dst.len());
            let start = VIRTIO_NET_HDR_SIZE - hdr_left;
            dst[..n].copy_from_slice(&h[start..start + n]);
            // Only expose a patch pointer when the whole header lands in one
            // buffer (the Linux driver always posts ≥1536-byte RX bufs, so this
            // holds in practice; otherwise num_buffers stays 0 ⇒ guest treats
            // it as 1, which is correct only for the non-MRG single-buffer case
            // — and we never inject >MTU frames without MRG negotiated).
            if start == 0 && n == VIRTIO_NET_HDR_SIZE {
                hdr_ptr = Some(dst.as_mut_ptr());
            }
            di = n;
            hdr_left -= n;
        }
        if hdr_left == 0 && frame_off < frame.len() && di < dst.len() {
            let n = (dst.len() - di).min(frame.len() - frame_off);
            dst[di..di + n].copy_from_slice(&frame[frame_off..frame_off + n]);
            frame_off += n;
        }
        if hdr_left == 0 && frame_off >= frame.len() {
            break;
        }
    }
    (frame_off as u32, hdr_ptr)
}

/// Write `frame` into a continuation chain's writable buffers (no header).
/// Returns bytes written.
fn write_more_rx(chain: &mut PoppedChain, frame: &[u8]) -> u32 {
    let mut off = 0usize;
    for b in chain.bufs.iter_mut() {
        if !b.write || off >= frame.len() {
            continue;
        }
        let dst = b.as_mut_slice();
        let n = dst.len().min(frame.len() - off);
        dst[..n].copy_from_slice(&frame[off..off + n]);
        off += n;
    }
    off as u32
}

impl VirtioDevice for NetDevice {
    fn device_id(&self) -> u32 {
        DEVICE_ID_NET
    }

    fn device_features(&self) -> u64 {
        FEATURE_VERSION_1
            | FEATURE_RING_EVENT_IDX
            | NET_FEATURE_MAC
            | NET_FEATURE_STATUS
            // RX-side offloads: let backends deliver coalesced (>MTU) TCP
            // segments so the guest processes one skb per super-frame instead of
            // one per MSS (the ~207 MB/s ceiling was the guest TCP stack at
            // ~148 K segments/s). MRG_RXBUF lets one packet span multiple RX
            // descriptors; GUEST_TSO4 requires GUEST_CSUM (spec §5.1.3.1).
            | NET_F_GUEST_CSUM
            | NET_F_GUEST_TSO4
            | NET_F_MRG_RXBUF
            // TX-side offloads: the guest hands us partially-checksummed TCP
            // super-segments (up to 64 KiB) instead of checksumming and
            // segmenting every MSS itself. Backends consume them natively (NAT
            // terminates TCP) or finish them in software; HOST_TSO4 requires
            // CSUM (spec §5.1.3.1).
            | NET_F_CSUM
            | NET_F_HOST_TSO4
    }

    fn set_driver_features(&self, acked: u64) -> bool {
        if acked & FEATURE_VERSION_1 == 0 {
            return false;
        }
        if acked & !self.device_features() != 0 {
            return false;
        }
        self.acked_features.store(acked, Ordering::Relaxed);
        true
    }

    fn queue_count(&self) -> u32 {
        2
    }

    fn queue_max(&self, idx: u32) -> u32 {
        if idx == NET_RX_QUEUE || idx == NET_TX_QUEUE {
            NET_QUEUE_MAX
        } else {
            0
        }
    }

    fn enable_queue(&self, idx: u32, desc: u64, avail: u64, used: u64, size: u16, event_idx: bool) {
        let q = match idx {
            NET_RX_QUEUE => &self.rxq,
            NET_TX_QUEUE => &self.txq,
            _ => return,
        };
        let mut q = q.lock().unwrap();
        q.set_desc_gpa(desc);
        q.set_avail_gpa(avail);
        q.set_used_gpa(used);
        q.set_size(size as u32);
        q.set_event_idx_enabled(event_idx);
        q.set_ready(true);
    }

    fn disable_queue(&self, idx: u32) {
        let q = match idx {
            NET_RX_QUEUE => &self.rxq,
            NET_TX_QUEUE => &self.txq,
            _ => return,
        };
        q.lock().unwrap().set_ready(false);
    }

    fn notify_queue(&self, idx: u32) {
        if idx == NET_TX_QUEUE {
            self.pump_tx();
        } else if idx == NET_RX_QUEUE {
            self.deliver_rx();
        }
    }

    fn driver_ok(&self) {
        self.driver_ok.store(true, Ordering::Relaxed);
    }

    fn reset(&self) {
        self.driver_ok.store(false, Ordering::Relaxed);
        self.acked_features.store(0, Ordering::Relaxed);
        self.rx.lock().unwrap().clear();
        self.rx_backlog.store(0, Ordering::SeqCst);
        self.maybe_wake_backend(0);
        self.rxq.lock().unwrap().reset();
        self.txq.lock().unwrap().reset();
    }

    fn read_config(&self, offset: u32, size: u32) -> u32 {
        let mut buf = [0u8; 12];
        buf[0..6].copy_from_slice(&self.mac);
        let st = self.link_status.load(Ordering::Relaxed);
        buf[6] = (st & 0xFF) as u8;
        buf[7] = (st >> 8) as u8;
        if offset as usize >= buf.len() {
            return 0;
        }
        let mut take = size as usize;
        if offset as usize + take > buf.len() {
            take = buf.len() - offset as usize;
        }
        let mut v = [0u8; 4];
        v[..take].copy_from_slice(&buf[offset as usize..offset as usize + take]);
        u32::from_le_bytes(v)
    }

    // ---- save/restore hooks (mirror console: rx/tx queues + driver_ok/feats).
    // The host-side backend (NAT socket table / loopback) is NOT snapshotted; a
    // fresh backend is wired in on restore, so live external flows reset but the
    // device model + new flows work. ----
    fn capture_queue(&self, idx: u32) -> Option<crate::virtio::queue::QueueState> {
        match idx {
            NET_RX_QUEUE => Some(self.rxq.lock().unwrap().capture()),
            NET_TX_QUEUE => Some(self.txq.lock().unwrap().capture()),
            _ => None,
        }
    }

    fn apply_queue(&self, idx: u32, st: &crate::virtio::queue::QueueState) {
        match idx {
            NET_RX_QUEUE => self.rxq.lock().unwrap().apply(st),
            NET_TX_QUEUE => self.txq.lock().unwrap().apply(st),
            _ => {}
        }
    }

    fn capture_device_state(&self) -> Vec<u8> {
        let mut b = vec![0u8; 16];
        b[0] = self.driver_ok.load(Ordering::Relaxed) as u8;
        b[8..16].copy_from_slice(&self.acked_features.load(Ordering::Relaxed).to_le_bytes());
        b
    }

    fn apply_device_state(&self, bytes: &[u8]) {
        if bytes.len() >= 16 {
            self.driver_ok.store(bytes[0] != 0, Ordering::Relaxed);
            self.acked_features.store(
                u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
                Ordering::Relaxed,
            );
        }
    }
}

/// Echoes guest TX frames straight back as RX. No host networking.
pub struct LoopbackBackend {
    net: Weak<NetDevice>,
}

impl LoopbackBackend {
    pub fn new(net: &Arc<NetDevice>) -> Arc<Self> {
        Arc::new(LoopbackBackend {
            net: Arc::downgrade(net),
        })
    }
}

impl NetBackend for LoopbackBackend {
    fn on_guest_frame(&self, frame: &[u8]) {
        if let Some(net) = self.net.upgrade() {
            net.inject_rx(frame);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::wire::{build_eth, build_ipv4, build_tcp, checksum16};

    const SRC: [u8; 4] = [10, 0, 0, 2];
    const DST: [u8; 4] = [1, 2, 3, 4];

    /// A guest-style offloaded TCP frame: the TCP checksum field holds only
    /// the (un-complemented) pseudo-header sum, as Linux leaves it for
    /// CHECKSUM_PARTIAL.
    fn offloaded_frame(payload: &[u8], flags: u8) -> Vec<u8> {
        let mut tcp = build_tcp(SRC, DST, 40000, 80, 1000, 7, flags, 512);
        tcp.extend_from_slice(payload);
        let mut pseudo = [0u8; 12];
        pseudo[..4].copy_from_slice(&SRC);
        pseudo[4..8].copy_from_slice(&DST);
        pseudo[9] = 6;
        pseudo[10..12].copy_from_slice(&(tcp.len() as u16).to_be_bytes());
        tcp[16..18].copy_from_slice(&(!checksum16(&[&pseudo])).to_be_bytes());
        build_eth([2; 6], [4; 6], 0x0800, &build_ipv4(SRC, DST, 6, &tcp))
    }

    fn tcp_csum_ok(f: &[u8]) -> bool {
        let ip = &f[ETH_HDR_LEN..];
        let tcp = &ip[20..];
        let mut pseudo = [0u8; 12];
        pseudo[..8].copy_from_slice(&ip[12..20]);
        pseudo[9] = 6;
        pseudo[10..12].copy_from_slice(&(tcp.len() as u16).to_be_bytes());
        checksum16(&[&ip[..20]]) == 0 && checksum16(&[&pseudo, tcp]) == 0
    }

    fn csum_hdr() -> TxHeader {
        TxHeader {
            flags: HDR_F_NEEDS_CSUM,
            csum_start: (ETH_HDR_LEN + 20) as u16,
            csum_offset: 16,
            ..Default::default()
        }
    }

    #[test]
    fn software_csum_completion() {
        let mut f = offloaded_frame(b"hello, offload", 0x18);
        assert!(!tcp_csum_ok(&f));
        let mut out = Vec::new();
        tx_offload_software(&mut f, &csum_hdr(), &mut |s| out.push(s.to_vec()));
        assert_eq!(out.len(), 1);
        assert!(tcp_csum_ok(&out[0]));

        // csum_start/offset past the end of the frame: dropped, not panicking.
        let hdr = TxHeader {
            csum_offset: 0xFFF0,
            ..csum_hdr()
        };
        out.clear();
        tx_offload_software(&mut f, &hdr, &mut |s| out.push(s.to_vec()));
        assert!(out.is_empty());
    }

    #[test]
    fn software_tso4_segmentation() {
        let payload: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
        let mut f = offloaded_frame(&payload, 0x18 | TCP_FIN | TCP_CWR); // ACK|PSH|FIN|CWR
        let hdr = TxHeader {
            gso_type: HDR_GSO_TCPV4,
            gso_size: 1448,
            hdr_len: (ETH_HDR_LEN + 40) as u16,
            ..csum_hdr()
        };
        let mut segs = Vec::new();
        tx_offload_software(&mut f, &hdr, &mut |s| segs.push(s.to_vec()));
        assert_eq!(segs.len(), 10_000usize.div_ceil(1448));
        let mut got = Vec::new();
        for (i, s) in segs.iter().enumerate() {
            assert!(tcp_csum_ok(s), "segment {i} checksum");
            let tcp = &s[ETH_HDR_LEN + 20..];
            let seq = u32::from_be_bytes(tcp[4..8].try_into().unwrap());
            assert_eq!(seq, 1000 + got.len() as u32);
            let last = i == segs.len() - 1;
            assert_eq!(tcp[13] & (TCP_FIN | TCP_PSH) != 0, last);
            assert_eq!(tcp[13] & TCP_CWR != 0, i == 0);
            assert!(tcp.len() - 20 <= 1448);
            got.extend_from_slice(&tcp[20..]);
        }
        assert_eq!(got, payload);
    }

    /// A frame needing more RX buffers than the guest has posted must not be
    /// published truncated: nothing reaches the used ring until the driver adds
    /// enough buffers, and then the whole frame arrives.
    #[test]
    fn rx_frame_waits_for_buffers_instead_of_truncating() {
        use crate::virtio::queue::VRING_DESC_F_WRITE;
        const DESC: u64 = 0x1000;
        const AVAIL: u64 = 0x2000;
        const USED: u64 = 0x3000;
        const BUF: u64 = 0x10000;
        const BUF_LEN: u32 = 2048;
        let mem = Arc::new(GuestMemory::new_host_only(256 * 1024).unwrap());
        let mut q = Virtqueue::new(mem.clone(), 8);
        q.set_size(8);
        q.set_desc_gpa(DESC);
        q.set_avail_gpa(AVAIL);
        q.set_used_gpa(USED);
        q.set_event_idx_enabled(true);
        q.set_ready(true);
        // Post `n` single-descriptor writable buffers (descriptor i in slot i).
        let post = |n: u16| {
            for i in 0..n {
                let mut d = [0u8; 16];
                d[0..8].copy_from_slice(&(BUF + u64::from(i) * u64::from(BUF_LEN)).to_le_bytes());
                d[8..12].copy_from_slice(&BUF_LEN.to_le_bytes());
                d[12..14].copy_from_slice(&VRING_DESC_F_WRITE.to_le_bytes());
                mem.write_at(DESC + 16 * u64::from(i), &d).unwrap();
                mem.write_at(AVAIL + 4 + 2 * u64::from(i), &i.to_le_bytes())
                    .unwrap();
            }
            mem.write_at(AVAIL + 2, &n.to_le_bytes()).unwrap();
        };
        let used_idx = || mem.read_u16(USED + 2).unwrap();
        // The 12-byte header plus 6000 bytes needs three 2 KiB buffers.
        let frame: Vec<u8> = (0..6000u32).map(|i| i as u8).collect();
        let mut chain = PoppedChain::default();
        let ctr = RxCounters::default();

        post(2);
        let r = deliver_frame(&mut q, &mut chain, &frame, &RxHeader::default(), true, &ctr);
        assert_eq!(r, None);
        assert_eq!(ctr.rewinds.load(Ordering::Relaxed), 1);
        assert_eq!(used_idx(), 0, "no truncated frame published");
        assert_eq!(q.avail_cursor(), 0, "popped buffers given back");

        post(3);
        let r = deliver_frame(&mut q, &mut chain, &frame, &RxHeader::default(), true, &ctr);
        assert_eq!(r, Some(3));
        assert_eq!(used_idx(), 3);
        assert_eq!(mem.read_u16(BUF + 10), Some(3), "num_buffers");
    }

    /// With no guest RX buffers, frames back up in the backlog: a backend that
    /// honours `rx_congested` is told to stop at the high mark, and is woken
    /// exactly once when the guest posts buffers and the backlog drains.
    #[test]
    fn rx_backlog_throttles_and_wakes_backend() {
        use crate::virtio::queue::VRING_DESC_F_WRITE;
        struct Wakes(AtomicUsize);
        impl NetBackend for Wakes {
            fn on_guest_frame(&self, _: &[u8]) {}
            fn on_rx_space(&self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        const DESC: u64 = 0x1000;
        const AVAIL: u64 = 0x2000;
        const USED: u64 = 0x3000;
        const BUF: u64 = 0x10000;
        const BUF_LEN: u32 = 2048;
        const QSIZE: u16 = 64;
        let mem = Arc::new(GuestMemory::new_host_only(512 * 1024).unwrap());
        let dev = NetDevice::new(mem.clone(), [2, 0, 0, 0, 0, 1]);
        let wakes = Arc::new(Wakes(AtomicUsize::new(0)));
        dev.set_backend(wakes.clone());
        {
            let mut q = dev.rxq.lock().unwrap();
            q.set_size(QSIZE.into());
            q.set_desc_gpa(DESC);
            q.set_avail_gpa(AVAIL);
            q.set_used_gpa(USED);
            q.set_event_idx_enabled(true);
            q.set_ready(true);
        }
        let frame = [0xab_u8; 100];
        for i in 0..RX_BACKLOG_HIGH {
            assert!(!dev.rx_congested(), "frame {i}: below the high mark");
            dev.inject_rx(&frame);
        }
        assert!(dev.rx_congested(), "backlog at the high mark");
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);

        // The guest posts a buffer per ring slot and kicks the RX queue.
        for i in 0..QSIZE {
            let mut d = [0u8; 16];
            d[0..8].copy_from_slice(&(BUF + u64::from(i) * u64::from(BUF_LEN)).to_le_bytes());
            d[8..12].copy_from_slice(&BUF_LEN.to_le_bytes());
            d[12..14].copy_from_slice(&VRING_DESC_F_WRITE.to_le_bytes());
            mem.write_at(DESC + 16 * u64::from(i), &d).unwrap();
            mem.write_at(AVAIL + 4 + 2 * u64::from(i), &i.to_le_bytes())
                .unwrap();
        }
        mem.write_at(AVAIL + 2, &QSIZE.to_le_bytes()).unwrap();
        dev.notify_queue(NET_RX_QUEUE);

        assert_eq!(
            dev.rx_packets(),
            RX_BACKLOG_HIGH as u64,
            "backlog delivered"
        );
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1, "woken once");
        assert!(!dev.rx_congested());
    }

    /// Batched RX frames are published at once but interrupt the guest once:
    /// at `notify_rx`, or at the `RX_NOTIFY_BATCH`-th frame if the backend
    /// keeps going, and only if the guest asked (EVENT_IDX `used_event`).
    #[test]
    fn batched_rx_interrupts_once_per_burst() {
        use crate::virtio::queue::VRING_DESC_F_WRITE;
        const DESC: u64 = 0x1000;
        const AVAIL: u64 = 0x2000;
        const USED: u64 = 0x3000;
        const BUF: u64 = 0x10000;
        const BUF_LEN: u32 = 2048;
        const QSIZE: u16 = 64;
        let mem = Arc::new(GuestMemory::new_host_only(512 * 1024).unwrap());
        let dev = NetDevice::new(mem.clone(), [2, 0, 0, 0, 0, 1]);
        let irqs = Arc::new(AtomicUsize::new(0));
        let seen = irqs.clone();
        dev.set_irq_callback(Box::new(move |q| {
            assert_eq!(q, NET_RX_QUEUE);
            seen.fetch_add(1, Ordering::SeqCst);
        }));
        {
            let mut q = dev.rxq.lock().unwrap();
            q.set_size(QSIZE.into());
            q.set_desc_gpa(DESC);
            q.set_avail_gpa(AVAIL);
            q.set_used_gpa(USED);
            q.set_event_idx_enabled(true);
            q.set_ready(true);
        }
        for i in 0..QSIZE {
            let mut d = [0u8; 16];
            d[0..8].copy_from_slice(&(BUF + u64::from(i) * u64::from(BUF_LEN)).to_le_bytes());
            d[8..12].copy_from_slice(&BUF_LEN.to_le_bytes());
            d[12..14].copy_from_slice(&VRING_DESC_F_WRITE.to_le_bytes());
            mem.write_at(DESC + 16 * u64::from(i), &d).unwrap();
            mem.write_at(AVAIL + 4 + 2 * u64::from(i), &i.to_le_bytes())
                .unwrap();
        }
        mem.write_at(AVAIL + 2, &QSIZE.to_le_bytes()).unwrap();
        let used_idx = || mem.read_u16(USED + 2).unwrap();
        // An idle guest re-arms: interrupt me when the next entry is used.
        let rearm = || {
            let next = used_idx();
            mem.write_at(AVAIL + 4 + 2 * u64::from(QSIZE), &next.to_le_bytes())
                .unwrap();
        };
        let irq_count = || irqs.load(Ordering::SeqCst);
        let frame = [0xab_u8; 100];

        rearm();
        for _ in 0..3 {
            dev.inject_rx_gso_batched(&frame, RxHeader::default());
        }
        assert_eq!(used_idx(), 3, "published at once");
        assert_eq!(irq_count(), 0, "the interrupt waits for notify_rx");
        dev.notify_rx();
        assert_eq!(irq_count(), 1, "one interrupt for the burst");
        dev.notify_rx();
        assert_eq!(irq_count(), 1, "nothing new since");

        rearm();
        for _ in 0..RX_NOTIFY_BATCH {
            dev.inject_rx_gso_batched(&frame, RxHeader::default());
        }
        assert_eq!(irq_count(), 2, "a long burst interrupts without notify_rx");
        dev.notify_rx();
        assert_eq!(irq_count(), 2);

        // The guest is still processing (no re-arm): no interrupt is owed.
        dev.inject_rx_gso_batched(&frame, RxHeader::default());
        dev.notify_rx();
        assert_eq!(irq_count(), 2, "the guest did not ask");

        rearm();
        dev.inject_rx(&frame);
        assert_eq!(irq_count(), 3, "unbatched frames interrupt right away");
    }
}
