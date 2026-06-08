//! virtio-net device (spec §5.1) with a pluggable backend. The device owns the
//! two virtqueues and the RX-injection path; a `NetBackend` decides what to do
//! with guest TX frames and may inject RX frames back. Port of
//! src/virtio/virtio_net.cpp + the backend split from net_backend.h.

use crate::diag::etw;
use crate::virtio::device::{
    VirtioDevice, DEVICE_ID_NET, FEATURE_RING_EVENT_IDX, FEATURE_VERSION_1,
};
use crate::virtio::queue::{PoppedChain, Virtqueue};
use crate::whp::GuestMemory;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

const NET_FEATURE_MAC: u64 = 1 << 5;
const NET_FEATURE_STATUS: u64 = 1 << 16;

const NET_STATUS_LINK_UP: u16 = 1;
const VIRTIO_NET_HDR_SIZE: usize = 12;

/// Per-slot capacity + slot count of the preallocated RX delivery pool, so
/// `inject_rx` copies into a pooled buffer instead of allocating a `Vec` per
/// inbound frame.
const RX_FRAME_CAP: usize = 2048;
const RX_POOL_SLOTS: usize = 512;

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
/// of (slot, len) awaiting delivery to the guest. No per-frame allocation.
struct RxPool {
    slots: Vec<[u8; RX_FRAME_CAP]>,
    free: Vec<u32>,
    pending: VecDeque<(u32, u16)>,
    chain: PoppedChain,
}

impl RxPool {
    fn new() -> Self {
        RxPool {
            slots: vec![[0u8; RX_FRAME_CAP]; RX_POOL_SLOTS],
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

    /// Inject an inbound Ethernet frame toward the guest (prepending a zero
    /// virtio_net_hdr). Thread-safe; callable from backend worker threads.
    /// Copies into a preallocated pool slot — no allocation. If the pool is
    /// exhausted (guest not consuming), the frame is dropped (backpressure).
    pub fn inject_rx(&self, frame: &[u8]) {
        let n = frame.len();
        if n == 0 || n > RX_FRAME_CAP {
            return;
        }
        if etw::enabled(etw::VERBOSE, etw::kw::NET) {
            etw::Event::new("NetRx", etw::VERBOSE, etw::kw::NET)
                .u32("len", n as u32)
                .write();
        }
        {
            let mut rx = self.rx.lock().unwrap();
            let Some(idx) = rx.free.pop() else {
                if etw::enabled(etw::VERBOSE, etw::kw::NET) {
                    etw::Event::new("NetRxDrop", etw::VERBOSE, etw::kw::NET)
                        .u32("len", n as u32)
                        .write();
                }
                return;
            };
            rx.slots[idx as usize][..n].copy_from_slice(frame);
            rx.pending.push_back((idx, n as u16));
        }
        self.deliver_rx();
    }

    /// Move queued frames into the guest's RX buffers, releasing each pool slot
    /// once written.
    fn deliver_rx(&self) {
        let mut rx_interrupt = false;
        {
            let mut rx = self.rx.lock().unwrap();
            let mut rxq = self.rxq.lock().unwrap();
            if rxq.ready() {
                let mut any = false;
                // Reborrow the guard as a plain &mut so the borrow checker can
                // split disjoint field borrows (chain vs slots) in one call.
                let rxp = &mut *rx;
                while let Some(&(idx, len)) = rxp.pending.front() {
                    if !rxq.pop_into(&mut rxp.chain) {
                        break;
                    }
                    let total = write_frame_to_rx(
                        &mut rxp.chain,
                        &rxp.slots[idx as usize][..len as usize],
                    );
                    rxq.push(rxp.chain.head_index, total);
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

/// Concatenate a chain's device-readable buffers, skipping `skip` leading
/// (virtio_net_hdr) bytes, into `out` (cleared first). No allocation when `out`
/// already has capacity.
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
        out.extend_from_slice(&s[remaining_skip..]);
        remaining_skip = 0;
    }
}

/// Write a zero virtio_net_hdr followed by `frame` into a chain's
/// device-writable buffers. Returns bytes written.
fn write_frame_to_rx(chain: &mut PoppedChain, frame: &[u8]) -> u32 {
    let total_logical = VIRTIO_NET_HDR_SIZE + frame.len();
    let mut produced = 0usize;
    let mut written = 0u32;
    for b in chain.bufs.iter_mut() {
        if !b.write {
            continue;
        }
        let dst = b.as_mut_slice();
        let mut i = 0;
        while i < dst.len() && produced < total_logical {
            dst[i] = if produced < VIRTIO_NET_HDR_SIZE {
                0
            } else {
                frame[produced - VIRTIO_NET_HDR_SIZE]
            };
            i += 1;
            produced += 1;
        }
        written += i as u32;
        if produced >= total_logical {
            break;
        }
    }
    written
}

impl VirtioDevice for NetDevice {
    fn device_id(&self) -> u32 {
        DEVICE_ID_NET
    }

    fn device_features(&self) -> u64 {
        FEATURE_VERSION_1 | FEATURE_RING_EVENT_IDX | NET_FEATURE_MAC | NET_FEATURE_STATUS
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
            self.acked_features
                .store(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), Ordering::Relaxed);
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
