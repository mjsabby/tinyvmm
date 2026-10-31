//! virtio-blk device (spec §5.2). Port of src/virtio/virtio_blk.cpp.
//!
//! Single requestq (queue 0). Backed by an async [`BlockFile`] (one IOCP
//! worker thread per disk). `notify_queue` (on the doorbell pump thread) drains
//! the avail ring, decodes each `virtio_blk_req` header, and submits the data
//! segments to the backend as independent, concurrent ops. Each segment's
//! completion (`on_seg_complete`) runs on the IOCP worker, or inline on the
//! pump when the host page cache served it synchronously; the completion that
//! retires a request's last segment pushes the used ring and raises the queue
//! interrupt via the transport.
//!
//! Implements READ / WRITE / FLUSH plus the RO, DISCARD, and WRITE_ZEROES
//! feature bits. DISCARD is a synchronous SCSI UNMAP from `notify_queue`;
//! WRITE_ZEROES is an ordinary WRITE sourced from a shared zero buffer.
//!
//! The device tracks every request from the moment it leaves the avail ring
//! until it settles (`active`). A reset cannot wait for in-flight requests (it
//! runs under the transport lock their completions take), so it completes
//! asynchronously: it starts a new epoch, requests from an earlier epoch settle
//! without touching the guest, and `reset_pending` keeps the device status
//! non-zero until they have. `quiesce` stops the device for teardown and
//! snapshots once every request it took has completed.

use crate::diag::etw;
use crate::host::block_file::{BlockFile, Op, Request};
use crate::virtio::device::{
    DEVICE_ID_BLOCK, FEATURE_RING_EVENT_IDX, FEATURE_VERSION_1, VirtioDevice,
};
use crate::virtio::queue::{ChainBuf, ChainScratch, Virtqueue};
use crate::whp::GuestMemory;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

// virtio-blk feature bits (spec §5.2.3).
const BLK_F_SIZE_MAX: u64 = 1 << 1;
const BLK_F_SEG_MAX: u64 = 1 << 2;
const BLK_F_RO: u64 = 1 << 5;
const BLK_F_BLK_SIZE: u64 = 1 << 6;
const BLK_F_FLUSH: u64 = 1 << 9;
const BLK_F_DISCARD: u64 = 1 << 13;
const BLK_F_WRITE_ZEROES: u64 = 1 << 14;

// virtio_blk_req::type values we handle.
const BLK_T_IN: u32 = 0;
const BLK_T_OUT: u32 = 1;
const BLK_T_FLUSH: u32 = 4;
const BLK_T_DISCARD: u32 = 11;
const BLK_T_WRITE_ZEROES: u32 = 13;

// Status byte values.
const BLK_S_OK: u8 = 0;
const BLK_S_IOERR: u8 = 1;
const BLK_S_UNSUPP: u8 = 2;

const SECTOR_SIZE: u32 = 512;

// blk config-space offsets (spec §5.2.4). NOTE: the DISCARD/WRITE_ZEROES block
// lives AFTER writeback(32)/unused0(33)/num_queues(34), i.e. starting at 36 —
// not 32. (The C++ reference has these 4 bytes too low, a latent bug that the
// blk-test never tripped because mkfs doesn't issue large discards.)
const CFG_CAPACITY: usize = 0; // le64 sectors
const CFG_SIZE_MAX: usize = 8; // le32
const CFG_SEG_MAX: usize = 12; // le32
const CFG_BLK_SIZE: usize = 20; // le32 (after geometry[4])
// DISCARD / WRITE_ZEROES sub-config.
const CFG_MAX_DISCARD_SECTORS: usize = 36; // le32
const CFG_MAX_DISCARD_SEG: usize = 40; // le32
const CFG_DISCARD_SECTOR_ALIGN: usize = 44; // le32
const CFG_MAX_WRITE_ZEROES_SECTORS: usize = 48; // le32
const CFG_MAX_WRITE_ZEROES_SEG: usize = 52; // le32
const CFG_WRITE_ZEROES_MAY_UNMAP: usize = 56; // u8

// We advertise a single range per request: a DISCARD of up to 2 GiB (4 Mi
// sectors), a WRITE_ZEROES of up to one zero buffer.
const BLK_MAX_DISCARD_SECTORS: u64 = 4 * 1024 * 1024;
const BLK_MAX_WRITE_ZEROES_SECTORS: u64 = (ZERO_BYTES / SECTOR_SIZE as usize) as u64;
const BLK_MAX_RANGE_SEG: usize = 1;
/// Size of the shared buffer every WRITE_ZEROES is written from.
const ZERO_BYTES: usize = 4 * 1024 * 1024;

/// The source of every WRITE_ZEROES. Leaked, so it outlives any write still
/// reading it; nothing writes to it.
fn zeroes() -> &'static [u8] {
    static ZEROES: OnceLock<&'static [u8]> = OnceLock::new();
    ZEROES.get_or_init(|| Box::leak(vec![0; ZERO_BYTES].into_boxed_slice()))
}

// ---- Bounce-buffer coalescing -------------------------------------------------
//
// Guest page-cache I/O arrives as ~150 non-contiguous 4–8 KiB segments per
// request (see the BlkSubmit.segs histogram in out\nested-blk-baseline.etl).
// Issuing one ReadFile/WriteFile per segment is ~55 K syscalls/s and dominates
// host CPU under nested virt. When a request has >1 data segment and totals
// ≤ BOUNCE_CAP, we instead issue ONE I/O against a host bounce buffer and
// scatter/gather to/from the guest segments. Single-segment requests (and
// anything that overflows the cap or finds the pool empty) stay on the
// existing zero-copy per-segment path.
//
// Cost: one extra memcpy of the request payload (≤ 2 MiB). Benefit: ~150×
// fewer syscalls + IOCP completions per request. The bounce buffers are host-
// allocated and fixed-size; the guest cannot influence their size or address.
// Linux's observed max request on this device is 4 MiB exactly (max_sectors);
// the cap must cover that or those requests fall back to per-segment. 8 slots
// covers the in-flight depth (sequential readahead keeps ~1–2 in flight; the
// 49 % miss at 8×2 MiB was size-gated, not pool-gated). 8 × 4 MiB = 32 MiB/disk.
const BOUNCE_CAP: usize = 4 * 1024 * 1024;
const BOUNCE_SLOTS: usize = 8;
const NO_BOUNCE: u16 = u16::MAX;

pub type IrqFn = Box<dyn Fn(u32) + Send + Sync>;

/// Parent of one virtio-blk request. Its data segments are issued as independent
/// [`SegOp`]s that run concurrently; `segs_outstanding` counts how many are still
/// in flight (plus one submission guard), and whichever decrement drives it to 0
/// finishes the request. It is shared between the submit thread and the IOCP
/// worker, so the cross-thread fields are atomic (the refcount idiom: the plain
/// fields are written before submission and read only at refcount 0, after the
/// `segs_outstanding` release/acquire edge).
struct BlkReq {
    /// Index of this request's slot in the `ReqPool` (O(1) release).
    slot: u16,
    head_idx: u16,
    /// `BouncePool` slot owning this request's coalesced buffer + scatter list,
    /// or `NO_BOUNCE` if the request took the zero-copy per-segment path.
    bounce_slot: u16,
    rtype: u32,
    /// The device epoch the request was taken in (see `BlockDevice::epoch`).
    epoch: u32,
    status_ptr: *mut u8,
    /// Outstanding segment I/Os + 1 submission guard; reaching 0 finishes.
    segs_outstanding: AtomicU32,
    /// Bytes read so far (the read used_len); only segment completions write it.
    total_done: AtomicU32,
    failed: AtomicBool,
}

impl BlkReq {
    fn empty(slot: u16) -> BlkReq {
        BlkReq {
            slot,
            head_idx: 0,
            bounce_slot: NO_BOUNCE,
            rtype: 0,
            epoch: 0,
            status_ptr: std::ptr::null_mut(),
            segs_outstanding: AtomicU32::new(0),
            total_done: AtomicU32::new(0),
            failed: AtomicBool::new(false),
        }
    }
}

/// One in-flight segment I/O. `req` MUST be the first field so the backend's
/// completion `*mut Request` is recovered as a `*mut SegOp`. `parent` points at
/// the owning [`BlkReq`] whose `segs_outstanding` this op decrements on
/// completion. Ownership is linear (one submit -> one completion).
#[repr(C)]
struct SegOp {
    req: Request,
    parent: *mut BlkReq,
    slot: u16,
}

impl SegOp {
    fn empty(slot: u16) -> SegOp {
        SegOp {
            req: Request::zeroed(),
            parent: std::ptr::null_mut(),
            slot,
        }
    }
}

// SegOp holds raw pointers (req.buf into guest RAM, parent into the ReqPool); it
// is handed to the IOCP and recovered on completion, with ownership passed
// linearly between the submit and worker threads -- so it is Send.
unsafe impl Send for SegOp {}

/// Preallocated pool of parent request slots. Each slot is a heap-stable
/// `Box<BlkReq>` whose address is stored as the `parent` back-pointer in every
/// in-flight `SegOp`, so it must not move; slots are reused via a free-list, so
/// submit/complete allocate nothing on the hot path. Sized to the virtqueue
/// depth (the maximum possible in-flight requests).
struct ReqPool {
    // Box (not inline) is REQUIRED: each slot's address is handed to in-flight
    // SegOps as their `parent` and must stay stable for the slab's lifetime;
    // `Vec<BlkReq>` would move slots on realloc.
    #[allow(clippy::vec_box)]
    slab: Vec<Box<BlkReq>>,
    free: Vec<u16>,
}

impl ReqPool {
    fn new(n: usize) -> ReqPool {
        let n = n.clamp(1, u16::MAX as usize);
        let mut slab = Vec::with_capacity(n);
        for i in 0..n {
            slab.push(Box::new(BlkReq::empty(i as u16)));
        }
        let free: Vec<u16> = (0..n as u16).rev().collect();
        ReqPool { slab, free }
    }
    fn acquire(&mut self) -> Option<u16> {
        self.free.pop()
    }
    fn release(&mut self, slot: u16) {
        self.free.push(slot);
    }
    fn inflight(&self) -> usize {
        self.slab.len() - self.free.len()
    }
}

// BlkReq's only raw field is `status_ptr` (into guest RAM, kept alive by
// GuestMemory). It is shared between the submit and worker threads, but every
// cross-thread field is atomic, so it is Send.
unsafe impl Send for BlkReq {}

/// One reusable bounce buffer + the guest scatter list it serves. Ownership is
/// linear (acquire on submit → release in `finish_request`), so the same slot
/// is never touched by two threads at once; the IOCP post/completion is the
/// synchronizing edge (mirroring `SegOp`).
struct BounceSlot {
    buf: Box<[u8]>,
    /// (guest ptr, len) for each original segment, in request order. Pointers
    /// are `host_range`-validated guest-RAM addresses captured at submit time.
    segs: Vec<(*mut u8, u32)>,
}

// SAFETY: `segs` raw pointers are into guest RAM (kept alive by `GuestMemory`)
// and are only dereferenced under the linear acquire→release ownership above.
unsafe impl Send for BounceSlot {}

struct BouncePool {
    // Boxed for stable addresses (a `*mut BounceSlot` is held across the lock).
    #[allow(clippy::vec_box)]
    slab: Vec<Box<BounceSlot>>,
    free: Vec<u16>,
}

impl BouncePool {
    fn new(n: usize) -> BouncePool {
        let n = n.clamp(1, u16::MAX as usize);
        let mut slab = Vec::with_capacity(n);
        for _ in 0..n {
            slab.push(Box::new(BounceSlot {
                buf: vec![0u8; BOUNCE_CAP].into_boxed_slice(),
                segs: Vec::new(),
            }));
        }
        let free: Vec<u16> = (0..n as u16).rev().collect();
        BouncePool { slab, free }
    }
    fn acquire(&mut self) -> Option<u16> {
        self.free.pop()
    }
    fn release(&mut self, slot: u16) {
        self.free.push(slot);
    }
    /// Stable pointer to slot `i`; valid while the caller owns the slot.
    fn slot_ptr(&mut self, i: u16) -> *mut BounceSlot {
        &mut *self.slab[i as usize] as *mut BounceSlot
    }
}

/// Preallocated pool of in-flight segment-op slots. Each is a heap-stable
/// `Box<SegOp>` whose address is the IOCP completion context, reused via a
/// free-list. Total in-flight segments are bounded by the descriptor-table size,
/// so this is sized to the virtqueue depth.
struct SegPool {
    #[allow(clippy::vec_box)]
    slab: Vec<Box<SegOp>>,
    free: Vec<u16>,
}

impl SegPool {
    fn new(n: usize) -> SegPool {
        let n = n.clamp(1, u16::MAX as usize);
        let mut slab = Vec::with_capacity(n);
        for i in 0..n {
            slab.push(Box::new(SegOp::empty(i as u16)));
        }
        let free: Vec<u16> = (0..n as u16).rev().collect();
        SegPool { slab, free }
    }
    fn acquire(&mut self) -> Option<u16> {
        self.free.pop()
    }
    fn release(&mut self, slot: u16) {
        self.free.push(slot);
    }
}

pub struct BlockDevice {
    backend: Arc<BlockFile>,
    queue: Mutex<Virtqueue>,
    irq: OnceLock<IrqFn>,
    blk_cfg: [u8; 64],
    queue_max: u32,
    readonly: bool,
    driver_features: AtomicU64,
    /// Preallocated in-flight parent-request pool (no per-request heap alloc).
    pool: Mutex<ReqPool>,
    /// Preallocated in-flight segment-op pool (one slot per concurrent segment).
    seg_pool: Mutex<SegPool>,
    /// Reusable bounce buffers for multi-segment coalescing (see BOUNCE_CAP).
    bounce_pool: Mutex<BouncePool>,
    /// Reused across drain calls so submit allocates nothing (see `drain`).
    drain_chain: Mutex<ChainScratch>,

    ops_in: AtomicU64,
    ops_out: AtomicU64,
    ops_flush: AtomicU64,
    ops_discard: AtomicU64,
    ops_write_zeroes: AtomicU64,
    ops_err: AtomicU64,
    ops_done: AtomicU64,
    /// Requests taken off the avail ring that have not yet settled (been
    /// retired on the used ring, or dropped). Incremented under the queue
    /// lock, so a reset either precedes a pop or sees its request here.
    active: AtomicU64,
    /// Bumped by each reset, under the queue lock. A request remembers the
    /// epoch it was taken in; one from an earlier epoch is stale: it settles
    /// without writing its status byte or read data, pushing a used element,
    /// or raising an interrupt, as its buffers and ring belong to the driver
    /// again (and the queue may since have been re-enabled).
    epoch: AtomicU32,
    /// Set by `quiesce`: the device takes no more requests.
    stopped: AtomicBool,
    /// Most requests the guest had outstanding at once (in flight here plus
    /// still waiting in the avail ring), sampled at each pop.
    max_depth: AtomicU64,
}

fn put_le(dst: &mut [u8], v: u64) {
    for (i, b) in dst.iter_mut().enumerate() {
        *b = (v >> (8 * i)) as u8;
    }
}

impl BlockDevice {
    pub fn new(mem: Arc<GuestMemory>, backend: Arc<BlockFile>, queue_max: u32) -> Arc<Self> {
        let mut cfg = [0u8; 64];
        let capacity_sectors = backend.size() / SECTOR_SIZE as u64;
        put_le(&mut cfg[CFG_CAPACITY..CFG_CAPACITY + 8], capacity_sectors);
        // SIZE_MAX: max bytes per data segment. 1 GiB ⇒ "don't split": the host
        // side is zero-copy (ReadFile/WriteFile straight into guest RAM via
        // host_range), so segment size has no allocation/security cost. NOTE:
        // for page-cache-backed I/O the segment count is bound by guest *page
        // fragmentation* (each non-contiguous 4 KiB page is its own descriptor),
        // not by this cap — measured ~150 segs/request regardless. This value
        // only helps the GPA-contiguous case (O_DIRECT, hugepage folios).
        put_le(&mut cfg[CFG_SIZE_MAX..CFG_SIZE_MAX + 4], 0x4000_0000);
        // SEG_MAX: reserve 2 entries (header + status) from queue_max.
        let seg_max = queue_max.saturating_sub(2);
        put_le(&mut cfg[CFG_SEG_MAX..CFG_SEG_MAX + 4], seg_max as u64);
        put_le(&mut cfg[CFG_BLK_SIZE..CFG_BLK_SIZE + 4], SECTOR_SIZE as u64);
        // DISCARD / WRITE_ZEROES sub-config. Always populated; the guest only
        // reads it if it accepts the matching feature bit (gated on a writable
        // backend in device_features).
        put_le(
            &mut cfg[CFG_MAX_DISCARD_SECTORS..CFG_MAX_DISCARD_SECTORS + 4],
            BLK_MAX_DISCARD_SECTORS,
        );
        put_le(
            &mut cfg[CFG_MAX_DISCARD_SEG..CFG_MAX_DISCARD_SEG + 4],
            BLK_MAX_RANGE_SEG as u64,
        );
        put_le(
            &mut cfg[CFG_DISCARD_SECTOR_ALIGN..CFG_DISCARD_SECTOR_ALIGN + 4],
            1,
        );
        put_le(
            &mut cfg[CFG_MAX_WRITE_ZEROES_SECTORS..CFG_MAX_WRITE_ZEROES_SECTORS + 4],
            BLK_MAX_WRITE_ZEROES_SECTORS,
        );
        put_le(
            &mut cfg[CFG_MAX_WRITE_ZEROES_SEG..CFG_MAX_WRITE_ZEROES_SEG + 4],
            BLK_MAX_RANGE_SEG as u64,
        );
        // WRITE_ZEROES writes zeros; it never unmaps.
        cfg[CFG_WRITE_ZEROES_MAY_UNMAP] = 0;

        let dev = Arc::new(BlockDevice {
            backend: backend.clone(),
            queue: Mutex::new(Virtqueue::new(mem, queue_max)),
            irq: OnceLock::new(),
            blk_cfg: cfg,
            queue_max,
            readonly: backend.readonly(),
            driver_features: AtomicU64::new(0),
            pool: Mutex::new(ReqPool::new(queue_max as usize)),
            seg_pool: Mutex::new(SegPool::new(queue_max as usize)),
            bounce_pool: Mutex::new(BouncePool::new(BOUNCE_SLOTS)),
            drain_chain: Mutex::new(ChainScratch::default()),
            ops_in: AtomicU64::new(0),
            ops_out: AtomicU64::new(0),
            ops_flush: AtomicU64::new(0),
            ops_discard: AtomicU64::new(0),
            ops_write_zeroes: AtomicU64::new(0),
            ops_err: AtomicU64::new(0),
            ops_done: AtomicU64::new(0),
            active: AtomicU64::new(0),
            epoch: AtomicU32::new(0),
            stopped: AtomicBool::new(false),
            max_depth: AtomicU64::new(0),
        });

        // The IOCP worker invokes this on completion. Weak so the backend's
        // callback doesn't keep the device alive (no Arc cycle).
        let weak = Arc::downgrade(&dev);
        backend.set_completion_callback(Box::new(move |req: *mut Request| {
            if let Some(d) = weak.upgrade() {
                d.on_seg_complete(req);
            }
        }));
        dev
    }

    pub fn set_irq_callback(&self, f: IrqFn) {
        let _ = self.irq.set(f);
    }

    pub fn ops_in(&self) -> u64 {
        self.ops_in.load(Ordering::Relaxed)
    }
    pub fn ops_out(&self) -> u64 {
        self.ops_out.load(Ordering::Relaxed)
    }
    pub fn ops_flush(&self) -> u64 {
        self.ops_flush.load(Ordering::Relaxed)
    }
    pub fn ops_discard(&self) -> u64 {
        self.ops_discard.load(Ordering::Relaxed)
    }
    pub fn ops_write_zeroes(&self) -> u64 {
        self.ops_write_zeroes.load(Ordering::Relaxed)
    }
    pub fn ops_err(&self) -> u64 {
        self.ops_err.load(Ordering::Relaxed)
    }
    pub fn ops_done(&self) -> u64 {
        self.ops_done.load(Ordering::Relaxed)
    }
    /// Deepest queue the guest drove (see `max_depth`). Unlike the backend's
    /// `max_inflight`, it counts requests the host served synchronously.
    pub fn max_depth(&self) -> u64 {
        self.max_depth.load(Ordering::Relaxed)
    }
    pub fn pending_count(&self) -> usize {
        self.pool.lock().unwrap().inflight()
    }

    /// Take whatever the guest left in the avail ring, stop taking requests,
    /// and wait until every request taken has settled: completed, with its
    /// status byte and used element written and its interrupt raised. Called
    /// with the vCPUs stopped, so the ring and guest RAM then stay still: a
    /// snapshot never captures a request taken off the avail ring but not yet
    /// completed, and the backend can stop with nothing in flight. Doorbells
    /// that arrive afterwards are ignored.
    pub fn quiesce(&self) {
        {
            let mut scratch = self.drain_chain.lock().unwrap();
            if !self.stopped.load(Ordering::Relaxed) {
                self.drain_ring(&mut scratch);
                self.stopped.store(true, Ordering::Relaxed);
            }
        }
        let start = Instant::now();
        let mut warned = false;
        while self.active.load(Ordering::Acquire) != 0 {
            if !warned && start.elapsed() >= Duration::from_secs(5) {
                warned = true;
                eprintln!(
                    "[blk] quiesce: still waiting for {} request(s) in flight",
                    self.active.load(Ordering::Relaxed)
                );
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn raise(&self, qidx: u32) {
        if let Some(cb) = self.irq.get() {
            cb(qidx);
        }
    }

    /// Retire `head` on the used ring, unless its epoch has ended.
    fn push_used(&self, epoch: u32, head: u16, used_len: u32) {
        let mut q = self.queue.lock().unwrap();
        if self.epoch.load(Ordering::Relaxed) == epoch {
            q.push(head, used_len);
        }
    }

    fn raise_irq_if_needed(&self, epoch: u32) {
        let fire = {
            let mut q = self.queue.lock().unwrap();
            self.epoch.load(Ordering::Relaxed) == epoch && q.should_interrupt_driver()
        };
        if fire {
            self.raise(0);
        }
    }

    /// Fail a request before it ever reaches the backend.
    fn reject(&self, epoch: u32, head: u16, status_ptr: *mut u8, status: u8) {
        self.ops_err.fetch_add(1, Ordering::Relaxed);
        self.finish_inline(epoch, head, Some(status_ptr), status);
    }

    /// Finish a request that never reached the backend: write its status byte
    /// (if it has a writable one), retire the chain, signal the driver, and
    /// settle it.
    fn finish_inline(&self, epoch: u32, head: u16, status_ptr: Option<*mut u8>, status: u8) {
        if let Some(p) = status_ptr
            && self.epoch.load(Ordering::Relaxed) == epoch
        {
            unsafe {
                *p = status;
            }
        }
        self.push_used(epoch, head, 1);
        self.raise_irq_if_needed(epoch);
        self.settle();
    }

    /// A request taken off the ring has settled: the device will not touch its
    /// guest buffers or the used ring for it again. Must come last.
    fn settle(&self) {
        self.active.fetch_sub(1, Ordering::Release);
    }

    /// Acquire a parent slot and submit every data segment of a request
    /// concurrently, each as its own `SegOp`. FLUSH is issued as one Flush
    /// segment. A submission guard (`segs_outstanding` starts at 1) keeps the
    /// request from finishing until all segments have been submitted, even if
    /// some complete immediately; the decrement that drives the count to 0
    /// finishes the request. `sync` runs the segments to completion on this
    /// thread instead (`BlockFile::submit_sync`).
    #[allow(clippy::too_many_arguments)]
    fn submit_request(
        &self,
        epoch: u32,
        head: u16,
        rtype: u32,
        base_offset: u64,
        status_ptr: *mut u8,
        data: &[ChainBuf],
        sync: bool,
    ) {
        let parent = {
            let mut pool = self.pool.lock().unwrap();
            pool.acquire().map(|slot| {
                let p = &mut *pool.slab[slot as usize];
                p.slot = slot;
                p.head_idx = head;
                p.bounce_slot = NO_BOUNCE;
                p.rtype = rtype;
                p.epoch = epoch;
                p.status_ptr = status_ptr;
                p.segs_outstanding.store(1, Ordering::Relaxed); // submission guard
                p.total_done.store(0, Ordering::Relaxed);
                p.failed.store(false, Ordering::Relaxed);
                p as *mut BlkReq
            })
        };
        let Some(parent) = parent else {
            self.reject(epoch, head, status_ptr, BLK_S_IOERR);
            return;
        };

        // Total payload + file-bounds (subtraction form so it can't wrap).
        let backend_size = self.backend.size();
        let total_len: u64 = data.iter().map(|s| s.len as u64).sum();
        let in_bounds = base_offset <= backend_size && total_len <= backend_size - base_offset;

        // Coalesce: when a multi-segment request fits the bounce cap and a slot
        // is free, issue ONE I/O against a host buffer instead of one per
        // segment. Single-segment / oversize / pool-empty fall through to the
        // zero-copy per-segment path unchanged.
        let bounce: Option<*mut BounceSlot> = if rtype != BLK_T_FLUSH
            && in_bounds
            && data.len() > 1
            && total_len <= BOUNCE_CAP as u64
        {
            let mut bp = self.bounce_pool.lock().unwrap();
            bp.acquire().map(|idx| {
                unsafe { (*parent).bounce_slot = idx };
                bp.slot_ptr(idx)
            })
        } else {
            None
        };

        if etw::enabled(etw::VERBOSE, etw::kw::BLOCK) {
            let segs = if rtype == BLK_T_FLUSH {
                1
            } else {
                data.len() as u32
            };
            etw::Event::new("BlkSubmit", etw::VERBOSE, etw::kw::BLOCK)
                .u32("type", rtype)
                .u64("sector", base_offset / SECTOR_SIZE as u64)
                .u32("segs", segs)
                .u32("bytes", total_len.min(u32::MAX as u64) as u32)
                .u32("bounced", bounce.is_some() as u32)
                .u32("head", head as u32)
                .write();
        }

        if rtype == BLK_T_FLUSH {
            self.submit_seg(parent, std::ptr::null_mut(), 0, 0, Op::Flush, false);
        } else if let Some(bs) = bounce {
            // SAFETY: we own this slot from acquire() until finish_request()
            // releases it; no other thread touches it concurrently.
            let bs = unsafe { &mut *bs };
            bs.segs.clear();
            let op = if rtype == BLK_T_IN {
                Op::Read
            } else {
                Op::Write
            };
            let mut off = 0usize;
            for seg in data {
                bs.segs.push((seg.ptr, seg.len as u32));
                if op == Op::Write {
                    // Gather guest → bounce now (the guest pages are quiescent
                    // until completion). `seg.ptr/len` were host_range-validated.
                    let dst = &mut bs.buf[off..off + seg.len];
                    dst.copy_from_slice(unsafe { std::slice::from_raw_parts(seg.ptr, seg.len) });
                }
                off += seg.len;
            }
            self.submit_seg(
                parent,
                bs.buf.as_mut_ptr(),
                total_len as u32,
                base_offset,
                op,
                sync,
            );
        } else {
            let op = if rtype == BLK_T_IN {
                Op::Read
            } else {
                Op::Write
            };
            let mut file_off = base_offset;
            for seg in data {
                // Bounds-check each segment against the backing file (subtraction
                // form so a 32-bit length + 64-bit offset can't wrap the check).
                if file_off > backend_size || seg.len as u64 > backend_size - file_off {
                    unsafe { (*parent).failed.store(true, Ordering::Relaxed) };
                    break;
                }
                self.submit_seg(parent, seg.ptr, seg.len as u32, file_off, op, sync);
                file_off += seg.len as u64;
            }
        }

        // Drop the submission guard; if every segment already completed (or none
        // was submitted) this finishes the request now.
        if unsafe { (*parent).segs_outstanding.fetch_sub(1, Ordering::AcqRel) } == 1 {
            self.finish_request(parent);
        }
    }

    /// Acquire a `SegOp`, fill its `Request`, count it on the parent, and submit
    /// it. On synchronous submit failure it undoes the count and fails the
    /// parent; the submission guard keeps the count from reaching 0 here, so the
    /// request is finished exactly once -- by `submit_request`'s guard drop or by
    /// the last real completion.
    fn submit_seg(
        &self,
        parent: *mut BlkReq,
        buf: *mut u8,
        bytes: u32,
        file_offset: u64,
        op: Op,
        sync: bool,
    ) {
        let seg: *mut SegOp = {
            let mut sp = self.seg_pool.lock().unwrap();
            let Some(slot) = sp.acquire() else {
                // SegOp pool exhausted (not expected: in-flight segments are
                // bounded by the descriptor-table size). Fail the request.
                unsafe { (*parent).failed.store(true, Ordering::Relaxed) };
                return;
            };
            let s = &mut *sp.slab[slot as usize];
            s.req = Request::zeroed();
            s.req.buf = buf;
            s.req.bytes = bytes;
            s.req.file_offset = file_offset;
            s.req.op = op;
            s.parent = parent;
            s.slot = slot;
            s as *mut SegOp
        };
        unsafe { (*parent).segs_outstanding.fetch_add(1, Ordering::AcqRel) };
        let req = unsafe { &mut (*seg).req as *mut Request };
        let started = if sync {
            unsafe { self.backend.submit_sync(req) }
        } else {
            unsafe { self.backend.submit(req) }
        };
        if !started {
            unsafe { (*parent).failed.store(true, Ordering::Relaxed) };
            unsafe { (*parent).segs_outstanding.fetch_sub(1, Ordering::AcqRel) };
            self.release_seg(seg);
        }
    }

    fn release_seg(&self, seg: *mut SegOp) {
        let slot = unsafe { (*seg).slot };
        self.seg_pool.lock().unwrap().release(slot);
    }

    fn drain(&self) {
        // One reused chain scratch across the whole drain AND across drain calls
        // so submit never allocates: each request's data segments are copied into
        // preallocated SegOp slots (submit_request) before the next pop_into,
        // and holding `drain_chain` serialises the rare concurrent drain without
        // extending the contended queue-lock hold time.
        let mut scratch = self.drain_chain.lock().unwrap();
        if self.stopped.load(Ordering::Relaxed) {
            return;
        }
        self.drain_ring(&mut scratch);
    }

    /// Take every request the guest has published and start or finish each.
    /// The caller holds `drain_chain`, whose scratch is `scratch`.
    fn drain_ring(&self, scratch: &mut ChainScratch) {
        // On the doorbell pump, a request the guest is waiting on alone is done
        // synchronously right here (see `BlockFile::submit_sync`); concurrent
        // ones stay async so a host cache miss never stalls the others.
        let inline_ok = crate::virtio::transport::on_doorbell_pump();
        loop {
            let (taken, waiting, epoch) = {
                let mut q = self.queue.lock().unwrap();
                if !q.pop_into(scratch) {
                    break;
                }
                let taken = self.active.fetch_add(1, Ordering::Relaxed) + 1;
                (taken, q.avail_pending(), self.epoch.load(Ordering::Relaxed))
            };
            let depth = taken + waiting as u64;
            self.max_depth.fetch_max(depth, Ordering::Relaxed);
            let lone = inline_ok && depth == 1;
            let bufs = &scratch.bufs;
            let head = scratch.head_index;
            if bufs.len() < 2 {
                // Malformed (need at least header + status). Mirror the C++:
                // drop without retiring the descriptor.
                self.ops_err.fetch_add(1, Ordering::Relaxed);
                self.settle();
                continue;
            }

            let last = bufs.len() - 1;
            let hdr_ok = !bufs[0].write && bufs[0].len >= 16;
            let status_ptr = bufs[last].ptr;
            let sta_ok = bufs[last].write && bufs[last].len >= 1;
            if !hdr_ok || !sta_ok {
                self.ops_err.fetch_add(1, Ordering::Relaxed);
                self.finish_inline(epoch, head, sta_ok.then_some(status_ptr), BLK_S_UNSUPP);
                continue;
            }

            let (rtype, sector) = {
                let h = bufs[0].as_slice();
                (
                    u32::from_le_bytes(h[0..4].try_into().unwrap()),
                    u64::from_le_bytes(h[8..16].try_into().unwrap()),
                )
            };

            // The middle buffers (between header and status) are the data.
            let data: &[ChainBuf] = &bufs[1..last];

            // Reject ridiculous sector values before multiplying.
            let sector_ok = sector <= u64::MAX / SECTOR_SIZE as u64;
            if !sector_ok && rtype != BLK_T_FLUSH {
                self.reject(epoch, head, status_ptr, BLK_S_IOERR);
                continue;
            }
            let cur_file_offset = if sector_ok {
                sector * SECTOR_SIZE as u64
            } else {
                0
            };

            // DISCARD (a SCSI UNMAP) is rare and runs inline. WRITE_ZEROES goes
            // down the WRITE path, sourced from the shared zero buffer.
            if rtype == BLK_T_DISCARD || rtype == BLK_T_WRITE_ZEROES {
                let is_wz = rtype == BLK_T_WRITE_ZEROES;
                let total: usize = data.iter().map(|s| s.len).sum();
                let segs_readable = data.iter().all(|s| !s.write);
                if total == 0 || !total.is_multiple_of(16) || !segs_readable {
                    self.reject(epoch, head, status_ptr, BLK_S_UNSUPP);
                    continue;
                }
                if self.readonly {
                    self.reject(epoch, head, status_ptr, BLK_S_IOERR);
                    continue;
                }
                let nranges = total / 16;
                if nranges > BLK_MAX_RANGE_SEG {
                    self.reject(epoch, head, status_ptr, BLK_S_UNSUPP);
                    continue;
                }
                // Single range under our cap (<= 16 bytes): a stack buffer, no
                // heap allocation even on this cold path.
                let mut range_buf = [0u8; 16 * BLK_MAX_RANGE_SEG];
                let mut filled = 0usize;
                for s in data {
                    let sl = s.as_slice();
                    let n = sl.len().min(range_buf.len() - filled);
                    range_buf[filled..filled + n].copy_from_slice(&sl[..n]);
                    filled += n;
                }
                let cap_sectors = if is_wz {
                    BLK_MAX_WRITE_ZEROES_SECTORS
                } else {
                    BLK_MAX_DISCARD_SECTORS
                };
                let backend_size = self.backend.size();
                let mut all_ok = true;
                let mut write_zeroes = None;
                for k in 0..nranges {
                    let base = k * 16;
                    let r_sector =
                        u64::from_le_bytes(range_buf[base..base + 8].try_into().unwrap());
                    let num_sectors =
                        u32::from_le_bytes(range_buf[base + 8..base + 12].try_into().unwrap());
                    let flags =
                        u32::from_le_bytes(range_buf[base + 12..base + 16].try_into().unwrap());
                    if num_sectors == 0 {
                        continue;
                    }
                    if num_sectors as u64 > cap_sectors {
                        all_ok = false;
                        break;
                    }
                    if r_sector > u64::MAX / SECTOR_SIZE as u64 {
                        all_ok = false;
                        break;
                    }
                    let byte_off = r_sector * SECTOR_SIZE as u64;
                    let byte_len = num_sectors as u64 * SECTOR_SIZE as u64;
                    if byte_off > backend_size || byte_len > backend_size - byte_off {
                        all_ok = false;
                        break;
                    }
                    // DISCARD flags must be 0; the WRITE_ZEROES unmap bit is
                    // advisory (we always write zeros).
                    if !is_wz && flags != 0 {
                        all_ok = false;
                        break;
                    }
                    if is_wz {
                        write_zeroes = Some((byte_off, byte_len));
                    } else if !self.backend.discard_range(byte_off, byte_len) {
                        all_ok = false;
                        break;
                    }
                }
                if all_ok && let Some((byte_off, byte_len)) = write_zeroes {
                    self.ops_write_zeroes.fetch_add(1, Ordering::Relaxed);
                    // `byte_len` is within BLK_MAX_WRITE_ZEROES_SECTORS, so
                    // within the buffer.
                    let zeros = ChainBuf {
                        ptr: zeroes().as_ptr().cast_mut(),
                        len: byte_len as usize,
                        write: false,
                    };
                    self.submit_request(epoch, head, rtype, byte_off, status_ptr, &[zeros], lone);
                    continue;
                }
                if all_ok {
                    if is_wz {
                        self.ops_write_zeroes.fetch_add(1, Ordering::Relaxed);
                    } else {
                        self.ops_discard.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    self.ops_err.fetch_add(1, Ordering::Relaxed);
                }
                let status = if all_ok { BLK_S_OK } else { BLK_S_IOERR };
                self.finish_inline(epoch, head, Some(status_ptr), status);
                continue;
            }

            // FLUSH: no data segments expected; ignore any present.
            if rtype == BLK_T_FLUSH {
                self.ops_flush.fetch_add(1, Ordering::Relaxed);
                self.submit_request(epoch, head, rtype, cur_file_offset, status_ptr, &[], false);
                continue;
            }

            if rtype != BLK_T_IN && rtype != BLK_T_OUT {
                self.reject(epoch, head, status_ptr, BLK_S_UNSUPP);
                continue;
            }

            // For reads, data segs must be device-writable; for writes,
            // device-readable.
            let want_write = rtype == BLK_T_IN;
            if data.iter().any(|s| s.write != want_write) {
                self.reject(epoch, head, status_ptr, BLK_S_UNSUPP);
                continue;
            }
            if rtype == BLK_T_OUT && self.readonly {
                self.reject(epoch, head, status_ptr, BLK_S_IOERR);
                continue;
            }
            // Empty data: ack immediately.
            if data.is_empty() {
                self.finish_inline(epoch, head, Some(status_ptr), BLK_S_OK);
                continue;
            }

            if rtype == BLK_T_IN {
                self.ops_in.fetch_add(1, Ordering::Relaxed);
            } else {
                self.ops_out.fetch_add(1, Ordering::Relaxed);
            }

            self.submit_request(epoch, head, rtype, cur_file_offset, status_ptr, data, lone);
        }
    }

    /// Segment completion: on the IOCP worker, or on the submitting thread when
    /// the host served the op synchronously. Records failure / bytes-read on
    /// the parent, releases the SegOp slot, then decrements the parent's
    /// outstanding count; the decrement that drives it to 0 finishes the request.
    /// Two segments of one request can complete on different threads at once,
    /// so the parent's running byte count is updated atomically; the AcqRel on
    /// `segs_outstanding` publishes it to whoever observes the count reach 0.
    fn on_seg_complete(&self, req: *mut Request) {
        let seg = req as *mut SegOp;
        let (parent, ok, op, bytes) = unsafe {
            let s = &*seg;
            (s.parent, s.req.ok, s.req.op, s.req.bytes)
        };
        if !ok {
            unsafe { (*parent).failed.store(true, Ordering::Relaxed) };
        } else if op == Op::Read {
            // Bounced read: scatter the host buffer back to the guest segments
            // before publishing completion. We own the bounce slot (acquired at
            // submit) until finish_request releases it; the segment pointers
            // were host_range-validated at pop time and the guest-RAM slab
            // outlives the device. A stale read's data stays in the bounce
            // buffer: since the reset, its guest buffers are the driver's.
            let bidx = unsafe { (*parent).bounce_slot };
            let stale = self.epoch.load(Ordering::Relaxed) != unsafe { (*parent).epoch };
            if bidx != NO_BOUNCE && !stale {
                let bs = {
                    let mut bp = self.bounce_pool.lock().unwrap();
                    bp.slot_ptr(bidx)
                };
                let bs = unsafe { &*bs };
                let mut off = 0usize;
                for &(p, l) in &bs.segs {
                    let n = (l as usize).min(bytes as usize - off);
                    if n == 0 {
                        break;
                    }
                    unsafe {
                        std::ptr::copy_nonoverlapping(bs.buf.as_ptr().add(off), p, n);
                    }
                    off += n;
                }
            }
            // used_len is u32, so saturate the running total of bytes read.
            let p = unsafe { &*parent };
            let _ = p
                .total_done
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |t| {
                    Some(t.saturating_add(bytes))
                });
        }
        self.release_seg(seg);
        if unsafe { (*parent).segs_outstanding.fetch_sub(1, Ordering::AcqRel) } == 1 {
            self.finish_request(parent);
        }
    }

    /// Finish a request: write its status byte, retire it on the used ring,
    /// release the parent slot, signal the driver, and settle it. Runs exactly
    /// once per request -- driven by `segs_outstanding` reaching 0 -- on
    /// whichever thread observes that (the guard drop in `submit_request`, or
    /// the last completion). A stale request (see `epoch`) only releases its
    /// slots and settles.
    fn finish_request(&self, parent: *mut BlkReq) {
        let (head, rtype, epoch, failed, total_done, status_ptr, slot) = unsafe {
            let p = &*parent;
            (
                p.head_idx,
                p.rtype,
                p.epoch,
                p.failed.load(Ordering::Acquire),
                p.total_done.load(Ordering::Relaxed),
                p.status_ptr,
                p.slot,
            )
        };
        if self.epoch.load(Ordering::Relaxed) == epoch {
            unsafe { *status_ptr = if failed { BLK_S_IOERR } else { BLK_S_OK } };
        }
        // used_len = data the device wrote (reads only) + the status byte.
        let used_len = if failed {
            1u32
        } else if rtype == BLK_T_IN {
            total_done.wrapping_add(1)
        } else {
            1
        };
        self.push_used(epoch, head, used_len);
        self.ops_done.fetch_add(1, Ordering::Relaxed);

        if etw::enabled(etw::VERBOSE, etw::kw::BLOCK) {
            etw::Event::new("BlkComplete", etw::VERBOSE, etw::kw::BLOCK)
                .u32("type", rtype)
                .u32("used_len", used_len)
                .u32("failed", failed as u32)
                .u32("head", head as u32)
                .write();
        }

        // Return the bounce + parent slots to their pools (O(1)).
        let bidx = unsafe { (*parent).bounce_slot };
        if bidx != NO_BOUNCE {
            self.bounce_pool.lock().unwrap().release(bidx);
        }
        self.pool.lock().unwrap().release(slot);
        self.raise_irq_if_needed(epoch);
        self.settle();
    }
}

impl VirtioDevice for BlockDevice {
    fn device_id(&self) -> u32 {
        DEVICE_ID_BLOCK
    }

    fn device_features(&self) -> u64 {
        let mut f = FEATURE_VERSION_1
            | FEATURE_RING_EVENT_IDX
            | BLK_F_BLK_SIZE
            | BLK_F_FLUSH
            | BLK_F_SEG_MAX
            | BLK_F_SIZE_MAX;
        if self.readonly {
            f |= BLK_F_RO;
        } else {
            // DISCARD / WRITE_ZEROES are only valid on writable backends.
            f |= BLK_F_DISCARD | BLK_F_WRITE_ZEROES;
        }
        f
    }

    fn set_driver_features(&self, acked: u64) -> bool {
        if acked & !self.device_features() != 0 {
            return false;
        }
        self.driver_features.store(acked, Ordering::Relaxed);
        true
    }

    fn queue_count(&self) -> u32 {
        1
    }

    fn queue_max(&self, idx: u32) -> u32 {
        if idx == 0 { self.queue_max } else { 0 }
    }

    fn enable_queue(&self, idx: u32, desc: u64, avail: u64, used: u64, size: u16, event_idx: bool) {
        if idx != 0 {
            return;
        }
        let mut q = self.queue.lock().unwrap();
        q.set_desc_gpa(desc);
        q.set_avail_gpa(avail);
        q.set_used_gpa(used);
        q.set_size(size as u32);
        q.set_event_idx_enabled(event_idx);
        q.set_ready(true);
    }

    fn disable_queue(&self, idx: u32) {
        if idx == 0 {
            self.queue.lock().unwrap().set_ready(false);
        }
    }

    fn notify_queue(&self, idx: u32) {
        if idx == 0 {
            self.drain();
        }
    }

    fn queue_has_work(&self, idx: u32) -> Option<bool> {
        if idx != 0 {
            return None;
        }
        if self.stopped.load(Ordering::Relaxed) {
            return Some(false);
        }
        // A held lock is a completion pushing the used ring: let the drain look.
        Some(self.queue.try_lock().map_or(true, |q| q.has_avail()))
    }

    fn driver_ok(&self) {}

    fn reset(&self) {
        // A guest-triggered reset (status write of 0) can race with requests
        // still in flight. It must not wait for them: it runs under the
        // transport `common` lock, which a completion's IRQ path re-takes.
        // Instead the reset completes asynchronously (see `reset_pending`):
        //  1. Under the queue lock, end the epoch and reset the virtqueue. A
        //     request taken before this is stale: it still runs to completion,
        //     but writes no status byte or bounced read data, pushes nothing to
        //     the used ring (which may belong to a re-enabled queue by then),
        //     and raises no interrupt. A zero-copy read still lands in its
        //     buffers before the request settles, but the driver does not reuse
        //     them until the reset has completed.
        //  2. Do NOT rebuild the pool free-lists. A parent or segment slot whose
        //     ReadFile/WriteFile is still outstanding must never be reissued to a
        //     new request: that would alias a live BlkReq/SegOp across the pump
        //     and worker threads (a data race + double free). The free-lists
        //     self-heal as completions land — every acquired slot is released
        //     exactly once.
        {
            let mut q = self.queue.lock().unwrap();
            self.epoch.fetch_add(1, Ordering::Relaxed);
            q.reset();
        }
        self.driver_features.store(0, Ordering::Relaxed);
    }

    fn reset_pending(&self) -> bool {
        self.active.load(Ordering::Acquire) != 0
    }

    fn read_config(&self, off: u32, size: u32) -> u32 {
        let off = off as usize;
        let size = size as usize;
        if size == 0 || off >= self.blk_cfg.len() || size > self.blk_cfg.len() - off {
            return 0;
        }
        let n = core::cmp::min(size, 4);
        let mut v = [0u8; 4];
        v[..n].copy_from_slice(&self.blk_cfg[off..off + n]);
        u32::from_le_bytes(v)
    }

    fn capture_queue(&self, idx: u32) -> Option<crate::virtio::queue::QueueState> {
        if idx == 0 {
            Some(self.queue.lock().unwrap().capture())
        } else {
            None
        }
    }
    fn apply_queue(&self, idx: u32, st: &crate::virtio::queue::QueueState) {
        if idx == 0 {
            self.queue.lock().unwrap().apply(st);
        }
    }
    fn capture_device_state(&self) -> Vec<u8> {
        // The durable mutable state is the negotiated driver features; blk_cfg
        // is recomputed identically from the backing file's size on restore.
        self.driver_features
            .load(Ordering::Relaxed)
            .to_le_bytes()
            .to_vec()
    }
    fn apply_device_state(&self, bytes: &[u8]) {
        if bytes.len() >= 8 {
            self.driver_features.store(
                u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
                Ordering::Relaxed,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::mpsc;

    const NEXT: u16 = 1;
    const WRITE: u16 = 2;
    const DATA: [(u64, u32, bool); 2] = [(0x10_0000, 4096, true), (0x10_2000, 4096, true)];

    /// A 64 MiB VHDX whose first 4 MiB hold 0x5a.
    struct Image(PathBuf);

    impl Image {
        fn new() -> Self {
            static NEXT_IMAGE: AtomicU64 = AtomicU64::new(0);
            let image = Self(std::env::temp_dir().join(format!(
                "tinyvmm-blk-{}-{}.vhdx",
                std::process::id(),
                NEXT_IMAGE.fetch_add(1, Ordering::Relaxed)
            )));
            winsys::host::vhdx::create(image.path(), 64 << 20).unwrap();
            let backend = BlockFile::new(image.path(), false);
            let (tx, rx) = mpsc::channel();
            backend
                .set_completion_callback(Box::new(move |r| tx.send(unsafe { (*r).ok }).unwrap()));
            backend.start();
            let mut bytes = vec![0x5a; 4 << 20];
            let mut request = Request::zeroed();
            request.op = Op::Write;
            request.buf = bytes.as_mut_ptr();
            request.bytes = bytes.len() as u32;
            assert!(unsafe { backend.submit_sync(&mut request) });
            assert!(rx.recv_timeout(Duration::from_secs(10)).unwrap());
            image
        }

        fn path(&self) -> &str {
            self.0.to_str().unwrap()
        }
    }

    impl Drop for Image {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn device(image: &Image) -> (Arc<GuestMemory>, Arc<BlockFile>, Arc<BlockDevice>) {
        let backend = Arc::new(BlockFile::new(image.path(), false));
        assert!(backend.open(), "error {}", backend.open_err());
        let mem = Arc::new(GuestMemory::new_host_only(8 << 20).unwrap());
        let dev = BlockDevice::new(mem.clone(), backend.clone(), 32);
        backend.start();
        (mem, backend, dev)
    }

    /// A 32-entry split virtqueue in guest RAM: descriptors at `base`, then the
    /// avail ring, the used ring, request headers and status bytes, a page
    /// apart.
    #[derive(Clone, Copy)]
    struct Ring(u64);

    impl Ring {
        fn avail(self) -> u64 {
            self.0 + 0x1000
        }
        fn used(self) -> u64 {
            self.0 + 0x2000
        }
        fn enable(self, dev: &BlockDevice) {
            dev.enable_queue(0, self.0, self.avail(), self.used(), 32, false);
        }
        fn used_idx(self, mem: &GuestMemory) -> u16 {
            u16::from_le_bytes(mem.read_array::<2>(self.used() + 2).unwrap())
        }
        fn desc(self, mem: &GuestMemory, i: u16, addr: u64, len: u32, flags: u16) {
            let mut d = [0u8; 16];
            d[0..8].copy_from_slice(&addr.to_le_bytes());
            d[8..12].copy_from_slice(&len.to_le_bytes());
            d[12..14].copy_from_slice(&flags.to_le_bytes());
            d[14..16].copy_from_slice(&(i + 1).to_le_bytes());
            mem.write_at(self.0 + u64::from(i) * 16, &d).unwrap();
        }
        /// Make chain `head` the ring's `slot`-th request and publish it.
        fn publish(self, mem: &GuestMemory, slot: u16, head: u16) {
            mem.write_at(self.avail() + 4 + u64::from(slot) * 2, &head.to_le_bytes())
                .unwrap();
            mem.write_at(self.avail() + 2, &(slot + 1).to_le_bytes())
                .unwrap();
        }
        /// Publish request `slot` (header for sector 0, `data`, status byte)
        /// at descriptor `head`, without a kick. Returns the status byte's GPA,
        /// preset to 0xaa.
        fn request(
            self,
            mem: &GuestMemory,
            slot: u16,
            head: u16,
            rtype: u32,
            data: &[(u64, u32, bool)],
        ) -> u64 {
            let header = self.0 + 0x3000 + u64::from(slot) * 16;
            let status = self.0 + 0x3800 + u64::from(slot);
            let mut h = [0u8; 16];
            h[0..4].copy_from_slice(&rtype.to_le_bytes());
            mem.write_at(header, &h).unwrap();
            mem.write_at(status, &[0xaa]).unwrap();
            self.desc(mem, head, header, 16, NEXT);
            let mut i = head + 1;
            for &(addr, len, writable) in data {
                self.desc(mem, i, addr, len, NEXT | if writable { WRITE } else { 0 });
                i += 1;
            }
            self.desc(mem, i, status, 1, WRITE);
            self.publish(mem, slot, head);
            status
        }
    }

    fn byte(mem: &GuestMemory, gpa: u64) -> u8 {
        mem.read_array::<1>(gpa).unwrap()[0]
    }

    fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Reset with a request in flight, then reuse its buffers and re-enable a
    /// fresh queue at once (as a driver that doesn't wait for the reset
    /// might). The request must settle without touching the guest.
    fn reset_with_request_in_flight(rtype: u32) {
        let image = Image::new();
        let (mem, backend, dev) = device(&image);
        let (old, fresh) = (Ring(0x1_0000), Ring(0x2_0000));
        old.enable(&dev);
        // Hold the IOCP worker in the first interrupt (a FLUSH's), so the next
        // request's completion queues up behind it.
        let (entered_tx, entered) = mpsc::sync_channel(1);
        let (release, release_rx) = mpsc::sync_channel::<()>(1);
        let release_rx = Mutex::new(release_rx);
        let first = AtomicBool::new(true);
        dev.set_irq_callback(Box::new(move |_| {
            if first.swap(false, Ordering::SeqCst) {
                entered_tx.send(()).unwrap();
                let _ = release_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(30));
            }
        }));
        old.request(&mem, 0, 0, BLK_T_FLUSH, &[]);
        dev.notify_queue(0);
        entered.recv_timeout(Duration::from_secs(10)).unwrap();
        let status = if rtype == BLK_T_IN {
            old.request(&mem, 1, 4, rtype, &DATA)
        } else {
            let mut range = [0u8; 16];
            range[8..12].copy_from_slice(&(BLK_MAX_WRITE_ZEROES_SECTORS as u32).to_le_bytes());
            mem.write_at(0x3_0000, &range).unwrap();
            old.request(&mem, 1, 4, rtype, &[(0x3_0000, 16, false)])
        };
        dev.notify_queue(0);
        assert_eq!(
            dev.pending_count(),
            1,
            "the request must still be in flight"
        );

        dev.reset();
        assert!(dev.reset_pending());
        mem.write_at(status, &[0xdd]).unwrap();
        for &(addr, len, _) in &DATA {
            mem.write_at(addr, &vec![0x77; len as usize]).unwrap();
        }
        fresh.enable(&dev);
        release.send(()).unwrap();
        wait_until("the reset to settle", || !dev.reset_pending());

        assert_eq!(fresh.used_idx(&mem), 0, "stale completion in the new queue");
        assert_eq!(old.used_idx(&mem), 1, "stale completion in the old queue");
        assert_eq!(byte(&mem, status), 0xdd, "stale status write");
        for &(addr, _, _) in &DATA {
            assert_eq!(mem.read_array::<4096>(addr).unwrap(), [0x77; 4096]);
        }
        // The new queue works.
        let status = fresh.request(&mem, 0, 0, BLK_T_FLUSH, &[]);
        dev.notify_queue(0);
        wait_until("a FLUSH on the new queue", || fresh.used_idx(&mem) == 1);
        assert_eq!(byte(&mem, status), BLK_S_OK);
        dev.quiesce();
        backend.stop();
    }

    #[test]
    fn reset_drops_a_stale_bounced_read() {
        reset_with_request_in_flight(BLK_T_IN);
    }

    #[test]
    fn reset_drops_a_stale_write_zeroes() {
        reset_with_request_in_flight(BLK_T_WRITE_ZEROES);
    }

    #[test]
    fn quiesce_completes_published_requests_then_stops() {
        let image = Image::new();
        let (mem, backend, dev) = device(&image);
        let ring = Ring(0x1_0000);
        ring.enable(&dev);
        // Requests finished without the backend settle at once: a chain too
        // short to be a request (dropped) and an unsupported type (rejected).
        ring.desc(&mem, 0, 0x1_3000, 16, 0);
        ring.publish(&mem, 0, 0);
        let unsupported = ring.request(&mem, 1, 2, 99, &[]);
        dev.notify_queue(0);
        assert!(!dev.reset_pending());
        assert_eq!(byte(&mem, unsupported), BLK_S_UNSUPP);

        // Published after the last drain: the doorbell pump never got to it.
        let status = ring.request(&mem, 2, 4, BLK_T_IN, &DATA);
        dev.quiesce();
        let q = dev.capture_queue(0).unwrap();
        assert_eq!((q.last_avail, q.last_used_idx), (3, 2));
        assert_eq!(ring.used_idx(&mem), 2);
        assert_eq!(byte(&mem, status), BLK_S_OK);
        for &(addr, _, _) in &DATA {
            assert_eq!(mem.read_array::<4096>(addr).unwrap(), [0x5a; 4096]);
        }

        // Stopped: a later doorbell takes nothing.
        ring.request(&mem, 3, 8, BLK_T_FLUSH, &[]);
        assert_eq!(dev.queue_has_work(0), Some(false));
        dev.notify_queue(0);
        assert_eq!(dev.capture_queue(0).unwrap().last_avail, 3);
        backend.stop();
        assert_eq!(backend.inflight(), 0);
    }
}
