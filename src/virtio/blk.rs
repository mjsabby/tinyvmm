//! virtio-blk device (spec §5.2). Port of src/virtio/virtio_blk.cpp.
//!
//! Single requestq (queue 0). Backed by an async [`BlockFile`] (one IOCP
//! worker thread per disk). `notify_queue` (on the vCPU thread) drains the
//! avail ring, decodes each `virtio_blk_req` header, and submits the data
//! segments to the backend as independent, concurrent ops. The IOCP worker
//! runs `on_seg_complete` per segment; the completion that retires a request's
//! last segment pushes the used ring and raises the queue interrupt via the
//! transport.
//!
//! Implements READ / WRITE / FLUSH plus the RO, DISCARD, and WRITE_ZEROES
//! feature bits. DISCARD / WRITE_ZEROES are served synchronously on the host
//! file via `FSCTL_SET_ZERO_DATA` (sparse-unmap) from `notify_queue`.

use crate::diag::etw;
use crate::host::block_file::{BlockFile, Op, Request};
use crate::virtio::device::{
    DEVICE_ID_BLOCK, FEATURE_RING_EVENT_IDX, FEATURE_VERSION_1, VirtioDevice,
};
use crate::virtio::queue::{ChainBuf, ChainScratch, Virtqueue};
use crate::whp::GuestMemory;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

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

// We advertise a single range per request, up to 2 GiB (4 Mi sectors).
const BLK_MAX_DISCARD_SECTORS: u64 = 4 * 1024 * 1024;
const BLK_MAX_WRITE_ZEROES_SECTORS: u64 = 4 * 1024 * 1024;
const BLK_MAX_RANGE_SEG: usize = 1;

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
        // write_zeroes_may_unmap = 1: SET_ZERO_DATA on a sparse file unmaps.
        cfg[CFG_WRITE_ZEROES_MAY_UNMAP] = 1;

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
    pub fn pending_count(&self) -> usize {
        self.pool.lock().unwrap().inflight()
    }

    fn raise(&self, qidx: u32) {
        if let Some(cb) = self.irq.get() {
            cb(qidx);
        }
    }

    fn push_used(&self, head: u16, used_len: u32) {
        self.queue.lock().unwrap().push(head, used_len);
    }

    fn raise_irq_if_needed(&self) {
        let fire = self.queue.lock().unwrap().should_interrupt_driver();
        if fire {
            self.raise(0);
        }
    }

    /// Fail a request before it ever reaches the backend: set the status byte,
    /// retire the chain, bump the error counter, and signal the driver.
    fn reject(&self, head: u16, status_ptr: *mut u8, status: u8) {
        unsafe {
            *status_ptr = status;
        }
        self.push_used(head, 1);
        self.ops_err.fetch_add(1, Ordering::Relaxed);
        self.raise_irq_if_needed();
    }

    /// Acquire a parent slot and submit every data segment of a request
    /// concurrently, each as its own `SegOp`. FLUSH is issued as one Flush
    /// segment. A submission guard (`segs_outstanding` starts at 1) keeps the
    /// request from finishing until all segments have been submitted, even if
    /// some complete immediately; the decrement that drives the count to 0
    /// finishes the request.
    fn submit_request(
        &self,
        head: u16,
        rtype: u32,
        base_offset: u64,
        status_ptr: *mut u8,
        data: &[ChainBuf],
    ) {
        let parent: *mut BlkReq = {
            let mut pool = self.pool.lock().unwrap();
            let Some(slot) = pool.acquire() else {
                self.reject(head, status_ptr, BLK_S_IOERR);
                return;
            };
            let p = &mut *pool.slab[slot as usize];
            p.slot = slot;
            p.head_idx = head;
            p.bounce_slot = NO_BOUNCE;
            p.rtype = rtype;
            p.status_ptr = status_ptr;
            p.segs_outstanding.store(1, Ordering::Relaxed); // submission guard
            p.total_done.store(0, Ordering::Relaxed);
            p.failed.store(false, Ordering::Relaxed);
            p as *mut BlkReq
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
            self.submit_seg(parent, std::ptr::null_mut(), 0, 0, Op::Flush);
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
                self.submit_seg(parent, seg.ptr, seg.len as u32, file_off, op);
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
    fn submit_seg(&self, parent: *mut BlkReq, buf: *mut u8, bytes: u32, file_offset: u64, op: Op) {
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
        if !unsafe { self.backend.submit(&mut (*seg).req) } {
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
        loop {
            let got = {
                let mut q = self.queue.lock().unwrap();
                q.pop_into(&mut scratch)
            };
            if !got {
                break;
            }
            let bufs = &scratch.bufs;
            let head = scratch.head_index;
            if bufs.len() < 2 {
                // Malformed (need at least header + status). Mirror the C++:
                // drop without retiring the descriptor.
                self.ops_err.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            let last = bufs.len() - 1;
            let hdr_ok = !bufs[0].write && bufs[0].len >= 16;
            let status_ptr = bufs[last].ptr;
            let sta_ok = bufs[last].write && bufs[last].len >= 1;
            if !hdr_ok || !sta_ok {
                if sta_ok {
                    unsafe {
                        *status_ptr = BLK_S_UNSUPP;
                    }
                }
                self.push_used(head, 1);
                self.ops_err.fetch_add(1, Ordering::Relaxed);
                self.raise_irq_if_needed();
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
                self.reject(head, status_ptr, BLK_S_IOERR);
                continue;
            }
            let cur_file_offset = if sector_ok {
                sector * SECTOR_SIZE as u64
            } else {
                0
            };

            // DISCARD / WRITE_ZEROES: synchronous ZeroRange (FSCTL_SET_ZERO_DATA),
            // which on a sparse NTFS file both zeroes the bytes and deallocates
            // clusters. Rare, so it runs inline rather than through the IOCP.
            if rtype == BLK_T_DISCARD || rtype == BLK_T_WRITE_ZEROES {
                let is_wz = rtype == BLK_T_WRITE_ZEROES;
                let total: usize = data.iter().map(|s| s.len).sum();
                let segs_readable = data.iter().all(|s| !s.write);
                if total == 0 || !total.is_multiple_of(16) || !segs_readable {
                    self.reject(head, status_ptr, BLK_S_UNSUPP);
                    continue;
                }
                if self.readonly {
                    self.reject(head, status_ptr, BLK_S_IOERR);
                    continue;
                }
                let nranges = total / 16;
                if nranges > BLK_MAX_RANGE_SEG {
                    self.reject(head, status_ptr, BLK_S_UNSUPP);
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
                    // DISCARD flags must be 0; WRITE_ZEROES unmap bit is advisory
                    // (we always unmap via SET_ZERO_DATA on a sparse file).
                    if !is_wz && flags != 0 {
                        all_ok = false;
                        break;
                    }
                    if !self.backend.zero_range(byte_off, byte_len) {
                        all_ok = false;
                        break;
                    }
                }
                unsafe {
                    *status_ptr = if all_ok { BLK_S_OK } else { BLK_S_IOERR };
                }
                self.push_used(head, 1);
                if all_ok {
                    if is_wz {
                        self.ops_write_zeroes.fetch_add(1, Ordering::Relaxed);
                    } else {
                        self.ops_discard.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    self.ops_err.fetch_add(1, Ordering::Relaxed);
                }
                self.raise_irq_if_needed();
                continue;
            }

            // FLUSH: no data segments expected; ignore any present.
            if rtype == BLK_T_FLUSH {
                self.ops_flush.fetch_add(1, Ordering::Relaxed);
                self.submit_request(head, rtype, cur_file_offset, status_ptr, &[]);
                continue;
            }

            if rtype != BLK_T_IN && rtype != BLK_T_OUT {
                self.reject(head, status_ptr, BLK_S_UNSUPP);
                continue;
            }

            // For reads, data segs must be device-writable; for writes,
            // device-readable.
            let want_write = rtype == BLK_T_IN;
            if data.iter().any(|s| s.write != want_write) {
                self.reject(head, status_ptr, BLK_S_UNSUPP);
                continue;
            }
            if rtype == BLK_T_OUT && self.readonly {
                self.reject(head, status_ptr, BLK_S_IOERR);
                continue;
            }
            // Empty data: ack immediately.
            if data.is_empty() {
                unsafe {
                    *status_ptr = BLK_S_OK;
                }
                self.push_used(head, 1);
                self.raise_irq_if_needed();
                continue;
            }

            if rtype == BLK_T_IN {
                self.ops_in.fetch_add(1, Ordering::Relaxed);
            } else {
                self.ops_out.fetch_add(1, Ordering::Relaxed);
            }

            self.submit_request(head, rtype, cur_file_offset, status_ptr, data);
        }
    }

    /// IOCP-worker completion for one segment. Records failure / bytes-read on
    /// the parent, releases the SegOp slot, then decrements the parent's
    /// outstanding count; the decrement that drives it to 0 finishes the request.
    /// All completions for a disk run on its single IOCP worker thread, so the
    /// per-segment updates to the parent are serialized; the AcqRel on
    /// `segs_outstanding` publishes them to whoever observes the count reach 0.
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
            // outlives the device.
            let bidx = unsafe { (*parent).bounce_slot };
            if bidx != NO_BOUNCE {
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
            // Single-writer (this worker thread), so load+store is race-free.
            let p = unsafe { &*parent };
            let prev = p.total_done.load(Ordering::Relaxed);
            p.total_done
                .store(prev.saturating_add(bytes), Ordering::Relaxed);
        }
        self.release_seg(seg);
        if unsafe { (*parent).segs_outstanding.fetch_sub(1, Ordering::AcqRel) } == 1 {
            self.finish_request(parent);
        }
    }

    /// Finish a request: write its status byte, retire it on the used ring,
    /// release the parent slot, and signal the driver. Runs exactly once per
    /// request -- driven by `segs_outstanding` reaching 0 -- on whichever thread
    /// observes that (the guard drop in `submit_request`, or the last completion).
    fn finish_request(&self, parent: *mut BlkReq) {
        let (head, rtype, failed, total_done, status_ptr, slot) = unsafe {
            let p = &*parent;
            (
                p.head_idx,
                p.rtype,
                p.failed.load(Ordering::Acquire),
                p.total_done.load(Ordering::Relaxed),
                p.status_ptr,
                p.slot,
            )
        };
        unsafe { *status_ptr = if failed { BLK_S_IOERR } else { BLK_S_OK } };
        // used_len = data the device wrote (reads only) + the status byte.
        let used_len = if failed {
            1u32
        } else if rtype == BLK_T_IN {
            total_done.wrapping_add(1)
        } else {
            1
        };
        self.push_used(head, used_len);
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
        self.raise_irq_if_needed();
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

    fn driver_ok(&self) {}

    fn reset(&self) {
        // A guest-triggered reset (status write of 0) can race with reads/writes
        // still outstanding on the IOCP worker — the worker is NOT stopped here.
        // Two rules keep that memory-safe without draining (which would deadlock:
        // reset runs under the transport `common` lock, and a completion's IRQ
        // path re-takes `common`):
        //  1. Reset the virtqueue. With `ready == false`, an in-flight completion
        //     finds `push` / `should_interrupt_driver` early-returning, so it
        //     retires through the normal path — releasing its parent + segment
        //     slots — without touching the guest ring or raising an interrupt.
        //  2. Do NOT rebuild the pool free-lists. A parent or segment slot whose
        //     ReadFile/WriteFile is still outstanding must never be reissued to a
        //     new request: that would alias a live BlkReq/SegOp across the pump
        //     and worker threads (a data race + double free). The free-lists
        //     self-heal as completions land — every acquired slot is released
        //     exactly once.
        self.queue.lock().unwrap().reset();
        self.driver_features.store(0, Ordering::Relaxed);
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
