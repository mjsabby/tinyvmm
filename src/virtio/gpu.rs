//! virtio-gpu device, basic 2D / CPU-rendered subset (spec §5.7).
//!
//! Implements a single-scanout 2D GPU: the guest creates host resources
//! (`RESOURCE_CREATE_2D`), attaches guest-memory backing pages
//! (`RESOURCE_ATTACH_BACKING`), copies pixels guest->host
//! (`TRANSFER_TO_HOST_2D`), binds a resource to scanout 0 (`SET_SCANOUT`) and
//! asks the host to display it (`RESOURCE_FLUSH`). On flush we swizzle the bound
//! resource into BGRA and hand it to a present callback (a Win32 window; see
//! [`crate::display`]). No 3D/virgl, blob resources, EDID, multi-scanout, or
//! hardware cursor — the cursor queue is drained and acked so the guest's
//! software cursor path works.
//!
//! Threading mirrors the other virtio devices: the queues are serviced inline on
//! whichever thread wrote the queue-notify MMIO (no doorbell — the GPU command
//! rate is low and bounded by display refresh). The present callback only copies
//! into the window's shared buffer and posts a repaint, so it is cheap to run
//! under the device lock.
//!
//! Save/restore: the full device state (driver flags, every resource's geometry,
//! backing scatter-gather list, and host pixel shadow, plus the scanout binding)
//! is serialized through [`VirtioDevice::capture_device_state`] /
//! `apply_device_state`. On restore the bound scanout is re-presented so the
//! window comes back showing the same image without replaying guest commands.

use crate::diag::etw;
use crate::virtio::device::{
    DEVICE_ID_GPU, FEATURE_RING_EVENT_IDX, FEATURE_VERSION_1, VirtioDevice,
};
use crate::virtio::queue::{ChainScratch, PoppedChain, Virtqueue};
use crate::whp::GuestMemory;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

pub const GPU_CONTROL_QUEUE: u32 = 0;
pub const GPU_CURSOR_QUEUE: u32 = 1;
pub const GPU_QUEUE_MAX: u32 = 64;

const NUM_SCANOUTS: u32 = 1;
const MAX_SCANOUTS: usize = 16; // sizeof display-info response is fixed at 16
const MAX_DIM: u32 = 8192;
const MAX_BACKING_ENTRIES: u32 = 1 << 16;
const BPP: u32 = 4;

// virtio_gpu_ctrl_type — 2D control commands.
const CMD_GET_DISPLAY_INFO: u32 = 0x0100;
const CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
const CMD_RESOURCE_UNREF: u32 = 0x0102;
const CMD_SET_SCANOUT: u32 = 0x0103;
const CMD_RESOURCE_FLUSH: u32 = 0x0104;
const CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
const CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
const CMD_RESOURCE_DETACH_BACKING: u32 = 0x0107;
// cursor commands.
const CMD_UPDATE_CURSOR: u32 = 0x0300;
const CMD_MOVE_CURSOR: u32 = 0x0301;
// responses.
const RESP_OK_NODATA: u32 = 0x1100;
const RESP_OK_DISPLAY_INFO: u32 = 0x1101;
const RESP_ERR_UNSPEC: u32 = 0x1200;
const RESP_ERR_INVALID_SCANOUT_ID: u32 = 0x1202;
const RESP_ERR_INVALID_RESOURCE_ID: u32 = 0x1203;
const RESP_ERR_INVALID_PARAMETER: u32 = 0x1205;

const FLAG_FENCE: u32 = 1 << 0;
const CTRL_HDR_LEN: usize = 24;
const DISPLAY_ONE_LEN: usize = 24; // rect(16) + enabled(4) + flags(4)

// Device-state snapshot blob header (see capture_device_state).
const GPU_SNAP_MAGIC: &[u8; 4] = b"GPU1";
const GPU_SNAP_VERSION: u8 = 1;

pub type IrqFn = Box<dyn Fn(u32) + Send + Sync>;
/// Present a BGRA (top-down, `stride == width*4`) frame of `width`x`height`.
pub type PresentFn = Box<dyn Fn(&[u8], u32, u32) + Send + Sync>;

#[derive(Clone, PartialEq, Eq, Debug)]
struct Resource2d {
    width: u32,
    height: u32,
    format: u32,
    /// Host shadow copy in the resource's native format, populated by
    /// TRANSFER_TO_HOST_2D. `len == width*height*BPP`.
    host: Vec<u8>,
    /// Guest-memory backing as `(gpa, len)` scatter-gather segments.
    backing: Vec<(u64, u64)>,
}

struct GpuState {
    resources: HashMap<u32, Resource2d>,
    /// Resource bound to scanout 0 (0 == none / disabled).
    scanout_resource: u32,
    /// Reusable BGRA scratch handed to the present callback.
    present_buf: Vec<u8>,
    /// Reusable gather buffer for the current control request (alloc-free hot
    /// path: cleared + refilled per command, capacity persists across kicks).
    req: Vec<u8>,
    /// Reusable build buffer for the current control response.
    resp: Vec<u8>,
}

pub struct GpuDevice {
    mem: Arc<GuestMemory>,
    controlq: Mutex<Virtqueue>,
    cursorq: Mutex<Virtqueue>,
    ctrl_scratch: Mutex<ChainScratch>,
    cursor_scratch: Mutex<ChainScratch>,
    state: Mutex<GpuState>,
    driver_ok: AtomicBool,
    acked_features: AtomicU64,
    irq: OnceLock<IrqFn>,
    present: OnceLock<PresentFn>,
    /// Advertised preferred display size (reported by GET_DISPLAY_INFO and used
    /// as the initial window size).
    width: u32,
    height: u32,
    frames: AtomicU64,
    ctrl_cmds: AtomicU64,
}

impl GpuDevice {
    pub fn new(mem: Arc<GuestMemory>, width: u32, height: u32) -> Arc<Self> {
        let width = width.clamp(64, MAX_DIM);
        let height = height.clamp(64, MAX_DIM);
        Arc::new(GpuDevice {
            controlq: Mutex::new(Virtqueue::new(mem.clone(), GPU_QUEUE_MAX)),
            cursorq: Mutex::new(Virtqueue::new(mem.clone(), GPU_QUEUE_MAX)),
            mem,
            ctrl_scratch: Mutex::new(ChainScratch::default()),
            cursor_scratch: Mutex::new(ChainScratch::default()),
            state: Mutex::new(GpuState {
                resources: HashMap::new(),
                scanout_resource: 0,
                present_buf: Vec::new(),
                req: Vec::new(),
                resp: Vec::new(),
            }),
            driver_ok: AtomicBool::new(false),
            acked_features: AtomicU64::new(0),
            irq: OnceLock::new(),
            present: OnceLock::new(),
            width,
            height,
            frames: AtomicU64::new(0),
            ctrl_cmds: AtomicU64::new(0),
        })
    }

    pub fn set_irq_callback(&self, f: IrqFn) {
        let _ = self.irq.set(f);
    }
    pub fn set_present_callback(&self, f: PresentFn) {
        let _ = self.present.set(f);
    }
    pub fn frames(&self) -> u64 {
        self.frames.load(Ordering::Relaxed)
    }
    pub fn ctrl_cmds(&self) -> u64 {
        self.ctrl_cmds.load(Ordering::Relaxed)
    }

    fn raise(&self, qidx: u32) {
        if let Some(cb) = self.irq.get() {
            cb(qidx);
        }
    }

    fn drain_control(&self) {
        let mut interrupt = false;
        let mut cmds = 0u64;
        {
            let mut q = self.controlq.lock().unwrap();
            if !q.ready() {
                return;
            }
            let mut chain = self.ctrl_scratch.lock().unwrap();
            let mut st = self.state.lock().unwrap();
            while q.pop_into(&mut chain) {
                let used = self.process_ctrl(&mut st, &chain);
                q.push(chain.head_index, used);
                cmds += 1;
            }
            if cmds > 0 {
                interrupt = q.should_interrupt_driver();
            }
        }
        if cmds > 0 {
            self.ctrl_cmds.fetch_add(cmds, Ordering::Relaxed);
        }
        if interrupt {
            self.raise(GPU_CONTROL_QUEUE);
        }
    }

    fn drain_cursor(&self) {
        let mut interrupt = false;
        let mut any = false;
        {
            let mut q = self.cursorq.lock().unwrap();
            if !q.ready() {
                return;
            }
            let mut chain = self.cursor_scratch.lock().unwrap();
            // Cursor commands carry no response payload; just ack each chain.
            while q.pop_into(&mut chain) {
                q.push(chain.head_index, 0);
                any = true;
            }
            if any {
                interrupt = q.should_interrupt_driver();
            }
        }
        if interrupt {
            self.raise(GPU_CURSOR_QUEUE);
        }
    }

    /// Process one control chain: gather the request into the reusable `req`
    /// buffer, dispatch (building the response into the reusable `resp` buffer),
    /// then scatter `resp` into the chain's writable buffers. Allocation-free on
    /// the steady-state hot path (the scratch buffers keep their capacity).
    fn process_ctrl(&self, st: &mut GpuState, chain: &PoppedChain) -> u32 {
        st.req.clear();
        for buf in &chain.bufs {
            if !buf.write && buf.len != 0 {
                st.req.extend_from_slice(buf.as_slice());
            }
        }
        self.dispatch(st);
        write_response(chain, &st.resp)
    }

    /// Decode the command in `st.req` and build the response into `st.resp`.
    /// Every command but GET_DISPLAY_INFO returns just a status header, so those
    /// return a status code and the header is written once here.
    fn dispatch(&self, st: &mut GpuState) {
        if st.req.len() < CTRL_HDR_LEN {
            put_header(&st.req, RESP_ERR_UNSPEC, &mut st.resp);
            return;
        }
        let cmd = rd_u32(&st.req, 0);
        let status = match cmd {
            CMD_GET_DISPLAY_INFO => {
                self.cmd_display_info(st);
                return;
            }
            CMD_RESOURCE_CREATE_2D => self.cmd_create_2d(st),
            CMD_RESOURCE_UNREF => self.cmd_unref(st),
            CMD_SET_SCANOUT => self.cmd_set_scanout(st),
            CMD_RESOURCE_FLUSH => self.cmd_flush(st),
            CMD_TRANSFER_TO_HOST_2D => self.cmd_transfer_2d(st),
            CMD_RESOURCE_ATTACH_BACKING => self.cmd_attach_backing(st),
            CMD_RESOURCE_DETACH_BACKING => self.cmd_detach_backing(st),
            other => {
                if etw::enabled(etw::VERBOSE, etw::kw::VIRTIO) {
                    etw::Event::new("GpuUnknownCmd", etw::VERBOSE, etw::kw::VIRTIO)
                        .u32("cmd", other)
                        .write();
                }
                RESP_ERR_UNSPEC
            }
        };
        put_header(&st.req, status, &mut st.resp);
    }

    fn cmd_display_info(&self, st: &mut GpuState) {
        put_header(&st.req, RESP_OK_DISPLAY_INFO, &mut st.resp);
        st.resp
            .resize(CTRL_HDR_LEN + MAX_SCANOUTS * DISPLAY_ONE_LEN, 0);
        // pmodes[0]: full-size, enabled. The rest stay zeroed (disabled).
        let p = CTRL_HDR_LEN;
        wr_u32(&mut st.resp, p + 8, self.width);
        wr_u32(&mut st.resp, p + 12, self.height);
        wr_u32(&mut st.resp, p + 16, 1); // enabled
    }

    fn cmd_create_2d(&self, st: &mut GpuState) -> u32 {
        let id = rd_u32(&st.req, 24);
        let format = rd_u32(&st.req, 28);
        let w = rd_u32(&st.req, 32);
        let h = rd_u32(&st.req, 36);
        if id == 0 || st.resources.contains_key(&id) {
            return RESP_ERR_INVALID_RESOURCE_ID;
        }
        if channel_indices(format).is_none() {
            return RESP_ERR_INVALID_PARAMETER;
        }
        if w == 0 || h == 0 || w > MAX_DIM || h > MAX_DIM {
            return RESP_ERR_INVALID_PARAMETER;
        }
        let size = (w as usize) * (h as usize) * BPP as usize;
        st.resources.insert(
            id,
            Resource2d {
                width: w,
                height: h,
                format,
                host: vec![0u8; size],
                backing: Vec::new(),
            },
        );
        RESP_OK_NODATA
    }

    fn cmd_unref(&self, st: &mut GpuState) -> u32 {
        let id = rd_u32(&st.req, 24);
        if st.resources.remove(&id).is_none() {
            return RESP_ERR_INVALID_RESOURCE_ID;
        }
        if st.scanout_resource == id {
            st.scanout_resource = 0;
        }
        RESP_OK_NODATA
    }

    fn cmd_set_scanout(&self, st: &mut GpuState) -> u32 {
        let scanout = rd_u32(&st.req, 40);
        let res_id = rd_u32(&st.req, 44);
        if scanout >= NUM_SCANOUTS {
            return RESP_ERR_INVALID_SCANOUT_ID;
        }
        if res_id == 0 {
            st.scanout_resource = 0; // detach / blank
            return RESP_OK_NODATA;
        }
        if !st.resources.contains_key(&res_id) {
            return RESP_ERR_INVALID_RESOURCE_ID;
        }
        st.scanout_resource = res_id;
        RESP_OK_NODATA
    }

    fn cmd_flush(&self, st: &mut GpuState) -> u32 {
        let id = rd_u32(&st.req, 40);
        if !st.resources.contains_key(&id) {
            return RESP_ERR_INVALID_RESOURCE_ID;
        }
        if st.scanout_resource == id {
            self.present_resource(st, id);
        }
        RESP_OK_NODATA
    }

    fn cmd_transfer_2d(&self, st: &mut GpuState) -> u32 {
        let rx = rd_u32(&st.req, 24);
        let ry = rd_u32(&st.req, 28);
        let rw = rd_u32(&st.req, 32);
        let rh = rd_u32(&st.req, 36);
        let offset = rd_u64(&st.req, 40);
        let id = rd_u32(&st.req, 48);
        let Some(res) = st.resources.get_mut(&id) else {
            return RESP_ERR_INVALID_RESOURCE_ID;
        };
        let x_end = rx as u64 + rw as u64;
        let y_end = ry as u64 + rh as u64;
        if x_end > res.width as u64 || y_end > res.height as u64 {
            return RESP_ERR_INVALID_PARAMETER;
        }
        if rw == 0 || rh == 0 {
            return RESP_OK_NODATA;
        }
        let stride = (res.width * BPP) as u64;
        let ok = if rx == 0 && ry == 0 && rw == res.width && rh == res.height {
            // Whole-resource fast path: one contiguous backing read.
            let len = (stride * rh as u64) as usize;
            read_backing(&self.mem, &res.backing, offset, &mut res.host[..len])
        } else {
            let row_bytes = (rw * BPP) as usize;
            let mut ok = true;
            for row in 0..rh as u64 {
                let src = offset + stride * row;
                let dst = ((ry as u64 + row) * stride + (rx * BPP) as u64) as usize;
                if !read_backing(
                    &self.mem,
                    &res.backing,
                    src,
                    &mut res.host[dst..dst + row_bytes],
                ) {
                    ok = false;
                    break;
                }
            }
            ok
        };
        if ok { RESP_OK_NODATA } else { RESP_ERR_UNSPEC }
    }

    fn cmd_attach_backing(&self, st: &mut GpuState) -> u32 {
        let id = rd_u32(&st.req, 24);
        let nr = rd_u32(&st.req, 28);
        if nr > MAX_BACKING_ENTRIES {
            return RESP_ERR_UNSPEC;
        }
        let need = 32 + (nr as usize) * 16;
        if st.req.len() < need {
            return RESP_ERR_UNSPEC;
        }
        // Read entries before taking the &mut resource borrow so `st.req` and
        // `st.resources` aren't borrowed at once.
        let Some(res) = st.resources.get_mut(&id) else {
            return RESP_ERR_INVALID_RESOURCE_ID;
        };
        res.backing.clear();
        res.backing.reserve(nr as usize);
        for i in 0..nr as usize {
            let base = 32 + i * 16;
            let addr = rd_u64(&st.req, base);
            let len = rd_u32(&st.req, base + 8) as u64;
            res.backing.push((addr, len));
        }
        RESP_OK_NODATA
    }

    fn cmd_detach_backing(&self, st: &mut GpuState) -> u32 {
        let id = rd_u32(&st.req, 24);
        let Some(res) = st.resources.get_mut(&id) else {
            return RESP_ERR_INVALID_RESOURCE_ID;
        };
        res.backing.clear();
        RESP_OK_NODATA
    }

    /// Swizzle the bound resource to BGRA and hand it to the present callback.
    fn present_resource(&self, st: &mut GpuState, id: u32) {
        let (w, h, fmt) = match st.resources.get(&id) {
            Some(r) => (r.width, r.height, r.format),
            None => return,
        };
        let need = (w as usize) * (h as usize) * BPP as usize;
        if need == 0 {
            return;
        }
        if st.present_buf.len() != need {
            st.present_buf.resize(need, 0);
        }
        // Disjoint field borrows: read `host`, write `present_buf`.
        let res = st.resources.get(&id).unwrap();
        swizzle_to_bgra(fmt, &res.host, &mut st.present_buf);
        if let Some(p) = self.present.get() {
            p(&st.present_buf, w, h);
        }
        self.frames.fetch_add(1, Ordering::Relaxed);
        if etw::enabled(etw::VERBOSE, etw::kw::VIRTIO) {
            etw::Event::new("GpuFlush", etw::VERBOSE, etw::kw::VIRTIO)
                .u32("res", id)
                .u32("w", w)
                .u32("h", h)
                .write();
        }
    }
}

impl VirtioDevice for GpuDevice {
    fn device_id(&self) -> u32 {
        DEVICE_ID_GPU
    }

    fn device_features(&self) -> u64 {
        // No GPU-specific feature bits (no VIRGL/EDID/blob): a plain 2D device.
        FEATURE_VERSION_1 | FEATURE_RING_EVENT_IDX
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
        if idx == GPU_CONTROL_QUEUE || idx == GPU_CURSOR_QUEUE {
            GPU_QUEUE_MAX
        } else {
            0
        }
    }

    fn enable_queue(&self, idx: u32, desc: u64, avail: u64, used: u64, size: u16, event_idx: bool) {
        let q = match idx {
            GPU_CONTROL_QUEUE => &self.controlq,
            GPU_CURSOR_QUEUE => &self.cursorq,
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
            GPU_CONTROL_QUEUE => &self.controlq,
            GPU_CURSOR_QUEUE => &self.cursorq,
            _ => return,
        };
        q.lock().unwrap().set_ready(false);
    }

    fn notify_queue(&self, idx: u32) {
        match idx {
            GPU_CONTROL_QUEUE => self.drain_control(),
            GPU_CURSOR_QUEUE => self.drain_cursor(),
            _ => {}
        }
    }

    fn driver_ok(&self) {
        self.driver_ok.store(true, Ordering::Relaxed);
    }

    fn reset(&self) {
        self.driver_ok.store(false, Ordering::Relaxed);
        self.acked_features.store(0, Ordering::Relaxed);
        self.controlq.lock().unwrap().reset();
        self.cursorq.lock().unwrap().reset();
        let mut st = self.state.lock().unwrap();
        st.resources.clear();
        st.scanout_resource = 0;
    }

    fn read_config(&self, offset: u32, size: u32) -> u32 {
        // struct virtio_gpu_config { events_read; events_clear; num_scanouts;
        // num_capsets; } — all le32. events_* are 0 (no display hotplug events).
        let mut img = [0u8; 16];
        img[8..12].copy_from_slice(&NUM_SCANOUTS.to_le_bytes());
        let mut v = [0u8; 4];
        let n = size.min(4) as usize;
        for (i, slot) in v.iter_mut().enumerate().take(n) {
            *slot = img.get(offset as usize + i).copied().unwrap_or(0);
        }
        u32::from_le_bytes(v)
    }

    fn write_config(&self, _offset: u32, _size: u32, _value: u32) {
        // events_clear is the only writable field; we never raise events.
    }

    fn capture_queue(&self, idx: u32) -> Option<crate::virtio::queue::QueueState> {
        match idx {
            GPU_CONTROL_QUEUE => Some(self.controlq.lock().unwrap().capture()),
            GPU_CURSOR_QUEUE => Some(self.cursorq.lock().unwrap().capture()),
            _ => None,
        }
    }
    fn apply_queue(&self, idx: u32, s: &crate::virtio::queue::QueueState) {
        match idx {
            GPU_CONTROL_QUEUE => self.controlq.lock().unwrap().apply(s),
            GPU_CURSOR_QUEUE => self.cursorq.lock().unwrap().apply(s),
            _ => {}
        }
    }
    fn capture_device_state(&self) -> Vec<u8> {
        // Full durable GPU state: driver flags + every resource (geometry,
        // backing scatter-gather list, and the host pixel shadow) + the scanout
        // binding. The host shadow carries the actual displayed image, so a
        // restore reproduces the same UI without replaying guest commands. Safe
        // to read unsynchronized w.r.t. the guest: capture runs only after every
        // vCPU is stopped (the GPU queues are serviced inline on vCPU threads).
        let st = self.state.lock().unwrap();
        encode_state(
            self.driver_ok.load(Ordering::Relaxed),
            self.acked_features.load(Ordering::Relaxed),
            st.scanout_resource,
            &st.resources,
        )
    }

    fn apply_device_state(&self, bytes: &[u8]) {
        let Some((driver_ok, acked, scanout, resources)) = decode_state(bytes) else {
            return; // unknown/truncated/legacy blob: nothing to restore
        };
        self.driver_ok.store(driver_ok, Ordering::Relaxed);
        self.acked_features.store(acked, Ordering::Relaxed);
        {
            let mut st = self.state.lock().unwrap();
            st.resources = resources;
            st.scanout_resource = scanout;
        }
        // Re-present the bound scanout so the restored window shows the saved
        // image immediately (before the guest issues any new commands).
        if scanout != 0 {
            let mut st = self.state.lock().unwrap();
            self.present_resource(&mut st, scanout);
        }
    }
}

// ---- helpers ---------------------------------------------------------------

fn rd_u32(b: &[u8], off: usize) -> u32 {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}
fn rd_u64(b: &[u8], off: usize) -> u64 {
    b.get(off..off + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}
fn wr_u32(b: &mut [u8], off: usize, v: u32) {
    if let Some(s) = b.get_mut(off..off + 4) {
        s.copy_from_slice(&v.to_le_bytes());
    }
}

/// Minimal bounds-checked little-endian cursor reader for the device-state blob.
/// Every accessor returns `None` past the end so a truncated/corrupt blob aborts
/// the restore cleanly instead of panicking or reading out of bounds.
struct Rdr<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Rdr<'a> {
    fn new(b: &'a [u8]) -> Self {
        Rdr { b, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.pos..self.pos + n)?;
        self.pos += n;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
    }
}

/// Serialize the durable GPU device state (see [`GpuDevice::capture_device_state`]).
fn encode_state(
    driver_ok: bool,
    acked: u64,
    scanout: u32,
    resources: &HashMap<u32, Resource2d>,
) -> Vec<u8> {
    let mut w = Vec::new();
    w.extend_from_slice(GPU_SNAP_MAGIC);
    w.push(GPU_SNAP_VERSION);
    w.push(driver_ok as u8);
    w.extend_from_slice(&acked.to_le_bytes());
    w.extend_from_slice(&scanout.to_le_bytes());
    w.extend_from_slice(&(resources.len() as u32).to_le_bytes());
    for (&id, res) in resources {
        w.extend_from_slice(&id.to_le_bytes());
        w.extend_from_slice(&res.width.to_le_bytes());
        w.extend_from_slice(&res.height.to_le_bytes());
        w.extend_from_slice(&res.format.to_le_bytes());
        w.extend_from_slice(&(res.backing.len() as u32).to_le_bytes());
        for &(gpa, len) in &res.backing {
            w.extend_from_slice(&gpa.to_le_bytes());
            w.extend_from_slice(&len.to_le_bytes());
        }
        w.extend_from_slice(&(res.host.len() as u32).to_le_bytes());
        w.extend_from_slice(&res.host);
    }
    w
}

/// Inverse of [`encode_state`]. Returns `None` on a foreign magic, version
/// mismatch, or any truncation (leaving the caller's state untouched).
#[allow(clippy::type_complexity)]
fn decode_state(bytes: &[u8]) -> Option<(bool, u64, u32, HashMap<u32, Resource2d>)> {
    let mut r = Rdr::new(bytes);
    if r.take(4)? != GPU_SNAP_MAGIC {
        return None;
    }
    let version = r.u8()?;
    if version != GPU_SNAP_VERSION {
        return None;
    }
    let driver_ok = r.u8()? != 0;
    let acked = r.u64()?;
    let scanout = r.u32()?;
    let count = r.u32()?;
    let mut resources = HashMap::new();
    for _ in 0..count {
        let id = r.u32()?;
        let width = r.u32()?;
        let height = r.u32()?;
        let format = r.u32()?;
        let bcount = r.u32()?;
        // Don't pre-reserve from an untrusted count; each push validates length.
        let mut backing = Vec::new();
        for _ in 0..bcount {
            backing.push((r.u64()?, r.u64()?));
        }
        let hlen = r.u32()? as usize;
        let host = r.take(hlen)?.to_vec();
        resources.insert(
            id,
            Resource2d {
                width,
                height,
                format,
                host,
                backing,
            },
        );
    }
    Some((driver_ok, acked, scanout, resources))
}

/// Write a 24-byte virtio_gpu_ctrl_hdr response (echoing the request's fence)
/// into `out`, replacing its contents. Reuses `out`'s capacity (no allocation
/// once it has grown once).
fn put_header(req: &[u8], rtype: u32, out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(&rtype.to_le_bytes());
    out.extend_from_slice(&(rd_u32(req, 4) & FLAG_FENCE).to_le_bytes());
    out.extend_from_slice(&rd_u64(req, 8).to_le_bytes()); // fence_id (echoed)
    out.extend_from_slice(&rd_u32(req, 16).to_le_bytes()); // ctx_id
    out.push(req.get(20).copied().unwrap_or(0)); // ring_idx
    out.extend_from_slice(&[0u8; 3]); // padding -> 24 bytes
}

/// Scatter `resp` across the chain's writable buffers; returns bytes written.
fn write_response(chain: &PoppedChain, resp: &[u8]) -> u32 {
    let mut off = 0usize;
    for buf in &chain.bufs {
        if !buf.write || buf.len == 0 {
            continue;
        }
        if off >= resp.len() {
            break;
        }
        let n = (resp.len() - off).min(buf.len);
        // ChainBuf is Copy; its as_mut_slice gives the already-bounds-checked
        // guest view. The audited raw-pointer deref lives in ChainBuf, not here.
        let mut b = *buf;
        b.as_mut_slice()[..n].copy_from_slice(&resp[off..off + n]);
        off += n;
    }
    off as u32
}

/// Read `dst.len()` bytes from a scatter-gather backing starting at linear
/// `offset`. Returns false if the backing doesn't fully cover the range.
fn read_backing(mem: &GuestMemory, backing: &[(u64, u64)], offset: u64, dst: &mut [u8]) -> bool {
    let mut di = 0usize;
    let mut skip = offset;
    for &(gpa, len) in backing {
        if di >= dst.len() {
            break;
        }
        if skip >= len {
            skip -= len;
            continue;
        }
        let seg_off = skip;
        let avail = (len - seg_off) as usize;
        let want = (dst.len() - di).min(avail);
        if !mem.read_into(gpa + seg_off, &mut dst[di..di + want]) {
            return false;
        }
        di += want;
        skip = 0;
    }
    di == dst.len()
}

/// Indices into a source 4-byte pixel that yield (blue, green, red) for the GDI
/// BGRA target, per the virtio-gpu 32bpp formats. `None` => unsupported format.
/// Byte orders derived from QEMU's virtio_gpu_get_pixman_format mapping.
fn channel_indices(format: u32) -> Option<(usize, usize, usize)> {
    match format {
        1 | 2 => Some((0, 1, 2)),    // B8G8R8A8 / B8G8R8X8: mem [B,G,R,_]
        3 | 4 => Some((3, 2, 1)),    // A8R8G8B8 / X8R8G8B8: mem [_,R,G,B]
        67 | 134 => Some((2, 1, 0)), // R8G8B8A8 / R8G8B8X8: mem [R,G,B,_]
        68 | 121 => Some((1, 2, 3)), // X8B8G8R8 / A8B8G8R8: mem [_,B,G,R]
        _ => None,
    }
}

/// Convert a native-format resource buffer to GDI BGRA (alpha forced opaque).
fn swizzle_to_bgra(format: u32, src: &[u8], dst: &mut [u8]) {
    let (bi, gi, ri) = channel_indices(format).unwrap_or((0, 1, 2));
    if (bi, gi, ri) == (0, 1, 2) {
        let n = src.len().min(dst.len());
        dst[..n].copy_from_slice(&src[..n]);
        return;
    }
    let pixels = dst.len() / 4;
    for i in 0..pixels {
        let s = i * 4;
        if s + 4 > src.len() {
            break;
        }
        let p = &src[s..s + 4];
        let d = &mut dst[s..s + 4];
        d[0] = p[bi];
        d[1] = p[gi];
        d[2] = p[ri];
        d[3] = 0xFF;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::queue::ChainBuf;

    #[test]
    fn channel_indices_cover_all_2d_formats() {
        // Byte order verified against QEMU's virtio_gpu_get_pixman_format and
        // the Linux virtio_gpu_translate_format DRM mapping.
        assert_eq!(channel_indices(1), Some((0, 1, 2))); // B8G8R8A8
        assert_eq!(channel_indices(2), Some((0, 1, 2))); // B8G8R8X8
        assert_eq!(channel_indices(3), Some((3, 2, 1))); // A8R8G8B8
        assert_eq!(channel_indices(4), Some((3, 2, 1))); // X8R8G8B8
        assert_eq!(channel_indices(67), Some((2, 1, 0))); // R8G8B8A8
        assert_eq!(channel_indices(134), Some((2, 1, 0))); // R8G8B8X8
        assert_eq!(channel_indices(68), Some((1, 2, 3))); // X8B8G8R8
        assert_eq!(channel_indices(121), Some((1, 2, 3))); // A8B8G8R8
        assert_eq!(channel_indices(0), None);
        assert_eq!(channel_indices(999), None);
    }

    #[test]
    fn swizzle_identity_is_a_straight_copy() {
        // B8G8R8X8 (mem [B,G,R,X]) maps straight onto GDI BGRA.
        let src = [40u8, 30, 20, 10, 4, 3, 2, 1];
        let mut dst = [0u8; 8];
        swizzle_to_bgra(2, &src, &mut dst);
        assert_eq!(dst, src);
    }

    #[test]
    fn swizzle_xrgb_reorders_to_bgra() {
        // X8R8G8B8: memory bytes are [X, R, G, B]; expect BGRA [B, G, R, 0xFF].
        let src = [10u8, 20, 30, 40]; // X=10 R=20 G=30 B=40
        let mut dst = [0u8; 4];
        swizzle_to_bgra(4, &src, &mut dst);
        assert_eq!(dst, [40, 30, 20, 0xFF]);
    }

    #[test]
    fn swizzle_rgba_reorders_to_bgra() {
        // R8G8B8A8: memory bytes are [R, G, B, A]; expect BGRA [B, G, R, 0xFF].
        let src = [20u8, 30, 40, 99]; // R=20 G=30 B=40 A=99
        let mut dst = [0u8; 4];
        swizzle_to_bgra(67, &src, &mut dst);
        assert_eq!(dst, [40, 30, 20, 0xFF]);
    }

    #[test]
    fn put_header_echoes_fence_when_requested() {
        let mut req = vec![0u8; 24];
        wr_u32(&mut req, 0, CMD_RESOURCE_FLUSH);
        wr_u32(&mut req, 4, FLAG_FENCE);
        req[8..16].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        wr_u32(&mut req, 16, 7); // ctx_id
        req[20] = 3; // ring_idx
        let mut h = vec![0xEEu8; 8]; // pre-filled: put_header must clear it
        put_header(&req, RESP_OK_NODATA, &mut h);
        assert_eq!(h.len(), 24);
        assert_eq!(rd_u32(&h, 0), RESP_OK_NODATA);
        assert_eq!(rd_u32(&h, 4), FLAG_FENCE);
        assert_eq!(rd_u64(&h, 8), 0x1122_3344_5566_7788);
        assert_eq!(rd_u32(&h, 16), 7);
        assert_eq!(h[20], 3);
    }

    #[test]
    fn put_header_clears_fence_when_not_requested() {
        let mut req = vec![0u8; 24];
        req[8..16].copy_from_slice(&0xDEADu64.to_le_bytes());
        let mut h = Vec::new();
        put_header(&req, RESP_ERR_INVALID_RESOURCE_ID, &mut h);
        assert_eq!(rd_u32(&h, 0), RESP_ERR_INVALID_RESOURCE_ID);
        assert_eq!(rd_u32(&h, 4), 0); // FLAG_FENCE not set
        assert_eq!(rd_u64(&h, 8), 0xDEAD); // fence id still echoed
    }

    #[test]
    fn write_response_scatters_and_skips_readable() {
        let mut a = [0u8; 3];
        let mut r = [0xAAu8; 4];
        let mut b = [0u8; 5];
        let chain = PoppedChain {
            head_index: 0,
            bufs: vec![
                ChainBuf {
                    ptr: a.as_mut_ptr(),
                    len: a.len(),
                    write: true,
                },
                ChainBuf {
                    ptr: r.as_mut_ptr(),
                    len: r.len(),
                    write: false,
                },
                ChainBuf {
                    ptr: b.as_mut_ptr(),
                    len: b.len(),
                    write: true,
                },
            ],
        };
        let resp = [1u8, 2, 3, 4, 5, 6];
        let n = write_response(&chain, &resp);
        assert_eq!(n, 6);
        assert_eq!(a, [1, 2, 3]);
        assert_eq!(b, [4, 5, 6, 0, 0]);
        assert_eq!(r, [0xAA; 4]); // readable buffer untouched
    }

    #[test]
    fn read_helpers_are_bounds_checked() {
        let b = [1u8, 0, 0, 0];
        assert_eq!(rd_u32(&b, 0), 1);
        assert_eq!(rd_u32(&b, 2), 0); // out of range -> 0
        assert_eq!(rd_u64(&b, 0), 0); // not enough bytes -> 0
    }

    fn sample_resources() -> HashMap<u32, Resource2d> {
        let mut m = HashMap::new();
        m.insert(
            7,
            Resource2d {
                width: 4,
                height: 2,
                format: 2,
                host: (0..32).collect(), // 4*2*4 bytes
                backing: vec![(0x1000, 0x2000), (0x8000, 0x1000)],
            },
        );
        m.insert(
            42,
            Resource2d {
                width: 1,
                height: 1,
                format: 67,
                host: vec![9, 8, 7, 6],
                backing: vec![],
            },
        );
        m
    }

    #[test]
    fn device_state_roundtrips() {
        let res = sample_resources();
        let blob = encode_state(true, 0x1_0000_0001, 7, &res);
        let (driver_ok, acked, scanout, decoded) = decode_state(&blob).expect("decode");
        assert!(driver_ok);
        assert_eq!(acked, 0x1_0000_0001);
        assert_eq!(scanout, 7);
        assert_eq!(decoded, res); // resources (incl. host pixels + backing) preserved
    }

    #[test]
    fn device_state_rejects_truncation_and_bad_magic() {
        let blob = encode_state(false, 0, 0, &sample_resources());
        // Truncations at every length must fail cleanly (None), never panic.
        for n in 0..blob.len() {
            assert!(decode_state(&blob[..n]).is_none(), "len {n} should fail");
        }
        // Foreign magic is ignored.
        let mut bad = blob.clone();
        bad[0] = b'X';
        assert!(decode_state(&bad).is_none());
    }

    #[test]
    fn device_state_empty_resources_roundtrips() {
        let empty = HashMap::new();
        let blob = encode_state(false, 0, 0, &empty);
        let (driver_ok, acked, scanout, decoded) = decode_state(&blob).expect("decode");
        assert!(!driver_ok);
        assert_eq!(acked, 0);
        assert_eq!(scanout, 0);
        assert!(decoded.is_empty());
    }
}
