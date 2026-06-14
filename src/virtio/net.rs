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
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

const NET_F_GUEST_CSUM: u64 = 1 << 1;
const NET_FEATURE_MAC: u64 = 1 << 5;
const NET_F_GUEST_TSO4: u64 = 1 << 7;
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

/// Per-slot capacity + slot count of the preallocated RX delivery pool, so
/// `inject_rx` copies into a pooled buffer instead of allocating a `Vec` per
/// inbound frame. With `GUEST_TSO4` a single delivered frame may carry up to
/// ~64 KiB of TCP payload, so the slot must hold a full GSO super-frame.
const RX_FRAME_CAP: usize = 65600;
const RX_POOL_SLOTS: usize = 64;

pub const NET_RX_QUEUE: u32 = 0;
pub const NET_TX_QUEUE: u32 = 1;
pub const NET_QUEUE_MAX: u32 = 256;

pub type IrqFn = Box<dyn Fn(u32) + Send + Sync>;

/// Data-plane peer of a `NetDevice`. `on_guest_frame` runs on the vCPU thread
/// for each transmitted Ethernet frame (virtio_net_hdr already stripped); it
/// must not block. Backends inject inbound frames via `NetDevice::inject_rx`.
pub trait NetBackend: Send + Sync {
    fn on_guest_frame(&self, frame: &[u8]);
    fn stop(&self) {}
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

    fn raise(&self, qidx: u32) {
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
                            b.on_guest_frame(frame);
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
                if deliver_frame(&mut rxq, &mut rxp.chain, frame, &hdr, mrg).is_some() {
                    self.rx_packets.fetch_add(1, Ordering::Relaxed);
                    let irq = rxq.should_interrupt_driver();
                    drop(rxq);
                    drop(rx);
                    if irq {
                        self.raise(NET_RX_QUEUE);
                    }
                    return;
                }
            }
            drop(rxq);
            let Some(idx) = rx.free.pop() else {
                if etw::enabled(etw::VERBOSE, etw::kw::NET) {
                    etw::Event::new("NetRxDrop", etw::VERBOSE, etw::kw::NET)
                        .u32("len", n as u32)
                        .write();
                }
                return;
            };
            rx.slots[idx as usize][..n].copy_from_slice(frame);
            rx.pending.push_back((idx, n as u32, hdr));
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

    /// Move queued frames into the guest's RX buffers (the RxPool fallback path
    /// — the steady-state direct delivery happens inline in `inject_rx_gso`).
    fn deliver_rx(&self) {
        let mut rx_interrupt = false;
        let mrg = self.mrg_rxbuf();
        {
            let mut rx = self.rx.lock().unwrap();
            let mut rxq = self.rxq.lock().unwrap();
            if rxq.ready() {
                let mut any = false;
                let rxp = &mut *rx;
                while let Some(&(idx, len, hdr)) = rxp.pending.front() {
                    let frame = &rxp.slots[idx as usize][..len as usize];
                    if deliver_frame(&mut rxq, &mut rxp.chain, frame, &hdr, mrg).is_none() {
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
        }
        if rx_interrupt {
            self.raise(NET_RX_QUEUE);
        }
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
) -> Option<u16> {
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
    while mrg && (written as usize) < frame.len() && (nbufs as usize) <= extra.len() {
        if !rxq.pop_into(chain) {
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
    if let Some(p) = hdr_ptr {
        unsafe {
            *p.add(10) = nbufs as u8;
            *p.add(11) = (nbufs >> 8) as u8;
        }
    }
    rxq.push(head0, used0);
    for &(h, u) in &extra[..nbufs as usize - 1] {
        rxq.push(h, u);
    }
    Some(nbufs)
}

/// Hard cap on an assembled guest TX frame. We advertise no GSO/TSO, so a
/// well-behaved driver never exceeds MTU; a hostile chain (overlapping indirect
/// descriptors summing to ~guest-RAM-size) must not balloon `out` to OOM/abort.
const TX_FRAME_CAP: usize = 65536;

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
