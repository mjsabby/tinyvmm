//! virtio-blk device (spec §5.2). Port of src/virtio/virtio_blk.cpp.
//!
//! Single requestq (queue 0). Backed by an async [`BlockFile`] (one IOCP
//! worker thread per disk). `notify_queue` (on the vCPU thread) drains the
//! avail ring, decodes each `virtio_blk_req` header, and submits the data
//! segments to the backend. The IOCP worker runs `on_complete`, which advances
//! a per-request state machine; after the last segment + the status byte it
//! pushes the used ring and raises the queue interrupt via the transport.
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
use std::sync::atomic::{AtomicU64, Ordering};
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

pub type IrqFn = Box<dyn Fn(u32) + Send + Sync>;

/// Per virtio-blk request. `req` MUST be the first field so a `*mut Request`
/// handed back by the backend can be recovered as a `*mut BlkReq`.
#[repr(C)]
struct BlkReq {
    req: Request,
    /// Index of this request's slot in the `ReqPool`, so completion can release
    /// it in O(1) instead of searching the in-flight list.
    slot: u16,
    head_idx: u16,
    rtype: u32,
    data_segs: Vec<ChainBuf>,
    cur_seg: usize,
    cur_file_offset: u64,
    total_done: u32,
    status_ptr: *mut u8,
    failed: bool,
}

impl BlkReq {
    fn empty(slot: u16) -> BlkReq {
        BlkReq {
            req: Request::zeroed(),
            slot,
            head_idx: 0,
            rtype: 0,
            data_segs: Vec::new(),
            cur_seg: 0,
            cur_file_offset: 0,
            total_done: 0,
            status_ptr: std::ptr::null_mut(),
            failed: false,
        }
    }
}

/// Preallocated pool of in-flight request slots. Each slot is a heap-stable
/// `Box<BlkReq>` whose address is the IOCP completion context; slots are reused
/// via a free-list, so submit/complete allocate nothing on the hot path. Sized
/// to the virtqueue depth (the maximum possible in-flight). Each slot keeps its
/// `data_segs` Vec and reuses its capacity across requests.
struct ReqPool {
    // Box (not inline) is REQUIRED: each slot's address is handed to the IOCP
    // backend as the completion context and must stay stable for the slab's
    // lifetime; `Vec<BlkReq>` would move slots on realloc.
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
    fn reset(&mut self) {
        self.free = (0..self.slab.len() as u16).rev().collect();
    }
}

// BlkReq holds raw pointers into guest RAM (kept alive by GuestMemory) and the
// embedded Request buffer pointer. Ownership of a request is handed off
// linearly (submitting thread -> IOCP worker), so no two threads touch the
// same BlkReq concurrently.
unsafe impl Send for BlkReq {}

pub struct BlockDevice {
    backend: Arc<BlockFile>,
    queue: Mutex<Virtqueue>,
    irq: OnceLock<IrqFn>,
    blk_cfg: [u8; 64],
    queue_max: u32,
    readonly: bool,
    driver_features: AtomicU64,
    /// Preallocated in-flight request pool (no per-request heap allocation).
    pool: Mutex<ReqPool>,
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
        // SIZE_MAX: max bytes per data segment (generous 64 KiB).
        put_le(&mut cfg[CFG_SIZE_MAX..CFG_SIZE_MAX + 4], 64 * 1024);
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
                d.on_complete(req);
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

    /// Acquire a pool slot for an async request, copy its data segments into the
    /// slot's reused Vec, and return the stable raw pointer (the IOCP completion
    /// context). Returns None only if the pool is exhausted (in-flight == depth).
    fn begin_request(
        &self,
        head: u16,
        rtype: u32,
        cur_file_offset: u64,
        status_ptr: *mut u8,
        data: &[ChainBuf],
    ) -> Option<*mut BlkReq> {
        let mut pool = self.pool.lock().unwrap();
        let slot = pool.acquire()?;
        let r = &mut *pool.slab[slot as usize];
        r.req = Request::zeroed();
        r.slot = slot;
        r.head_idx = head;
        r.rtype = rtype;
        r.data_segs.clear();
        r.data_segs.extend_from_slice(data);
        r.cur_seg = 0;
        r.cur_file_offset = cur_file_offset;
        r.total_done = 0;
        r.status_ptr = status_ptr;
        r.failed = false;
        Some(r as *mut BlkReq)
    }

    fn drain(&self) {
        // One reused chain scratch across the whole drain AND across drain calls
        // so submit never allocates: each request's data segments are copied into
        // the preallocated ReqPool slot (begin_request) before the next pop_into,
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
                let Some(raw) = self.begin_request(head, rtype, cur_file_offset, status_ptr, data)
                else {
                    self.reject(head, status_ptr, BLK_S_IOERR);
                    continue;
                };
                unsafe {
                    (*raw).req.op = Op::Flush;
                }
                if !unsafe { self.backend.submit(&mut (*raw).req) } {
                    unsafe {
                        (*raw).failed = true;
                    }
                    self.finish_request(raw);
                }
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

            let Some(raw) = self.begin_request(head, rtype, cur_file_offset, status_ptr, data)
            else {
                self.reject(head, status_ptr, BLK_S_IOERR);
                continue;
            };

            if etw::enabled(etw::VERBOSE, etw::kw::BLOCK) {
                let r = unsafe { &*raw };
                etw::Event::new("BlkSubmit", etw::VERBOSE, etw::kw::BLOCK)
                    .u32("type", r.rtype)
                    .u64("sector", r.cur_file_offset / SECTOR_SIZE as u64)
                    .u32("segs", r.data_segs.len() as u32)
                    .u32("head", r.head_idx as u32)
                    .write();
            }
            self.submit_next(raw);
        }
    }

    /// Submit the next pending data segment, or finish if all are done.
    fn submit_next(&self, r: *mut BlkReq) {
        enum Act {
            Finish,
            BoundsFail,
            Submit,
        }
        let act = unsafe {
            let rr = &mut *r;
            if rr.cur_seg >= rr.data_segs.len() {
                Act::Finish
            } else {
                let seg_ptr = rr.data_segs[rr.cur_seg].ptr;
                let seg_len = rr.data_segs[rr.cur_seg].len;
                // Bounds-check the segment against the backing file. Subtraction
                // form so a 32-bit length + 64-bit offset can't wrap the check.
                let backend_size = self.backend.size();
                if rr.cur_file_offset > backend_size
                    || seg_len as u64 > backend_size - rr.cur_file_offset
                {
                    Act::BoundsFail
                } else {
                    rr.req.buf = seg_ptr;
                    rr.req.bytes = seg_len as u32;
                    rr.req.file_offset = rr.cur_file_offset;
                    rr.req.op = if rr.rtype == BLK_T_IN {
                        Op::Read
                    } else {
                        Op::Write
                    };
                    Act::Submit
                }
            }
        };
        match act {
            Act::Finish => self.finish_request(r),
            Act::BoundsFail => {
                unsafe {
                    (*r).failed = true;
                }
                self.finish_request(r);
            }
            Act::Submit => {
                if !unsafe { self.backend.submit(&mut (*r).req) } {
                    unsafe {
                        (*r).failed = true;
                    }
                    self.finish_request(r);
                }
            }
        }
    }

    /// IOCP-worker completion entry point. `req` is the embedded Request, which
    /// is the first field of a `BlkReq`.
    fn on_complete(&self, req: *mut Request) {
        let r = req as *mut BlkReq;
        let finish = unsafe {
            let rr = &mut *r;
            if !rr.req.ok {
                rr.failed = true;
                true
            } else if rr.req.op == Op::Flush {
                true
            } else {
                // used_len is u32, so saturate the running total.
                let n = rr.req.bytes;
                rr.total_done = rr.total_done.saturating_add(n);
                rr.cur_file_offset += n as u64;
                rr.cur_seg += 1;
                false
            }
        };
        if finish {
            self.finish_request(r);
        } else {
            self.submit_next(r);
        }
    }

    fn finish_request(&self, r: *mut BlkReq) {
        let (head, used_len) = unsafe {
            *(*r).status_ptr = if (*r).failed { BLK_S_IOERR } else { BLK_S_OK };
            // used_len = data the device wrote (reads only) + the status byte.
            let used_len = if (*r).failed {
                1u32
            } else {
                (if (*r).rtype == BLK_T_IN {
                    (*r).total_done
                } else {
                    0
                })
                .wrapping_add(1)
            };
            ((*r).head_idx, used_len)
        };
        self.push_used(head, used_len);
        self.ops_done.fetch_add(1, Ordering::Relaxed);

        if etw::enabled(etw::VERBOSE, etw::kw::BLOCK) {
            let (rtype, failed) = unsafe { ((*r).rtype, (*r).failed) };
            etw::Event::new("BlkComplete", etw::VERBOSE, etw::kw::BLOCK)
                .u32("type", rtype)
                .u32("used_len", used_len)
                .u32("failed", failed as u32)
                .u32("head", head as u32)
                .write();
        }

        // Return the slot to the pool (O(1)); its data_segs Vec stays allocated
        // for reuse by a future request.
        let slot = unsafe { (*r).slot };
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
        // Best-effort. The caller is expected to have quiesced the backend
        // (stopped the IOCP worker) before reset.
        self.pool.lock().unwrap().reset();
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
