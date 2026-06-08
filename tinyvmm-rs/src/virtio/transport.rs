//! virtio-PCI "modern" transport (spec §4.1). Exposes a `VirtioDevice` over a
//! PCI Type-0 function with the standard capability chain + MSI-X. Port of
//! src/virtio/virtio_pci.cpp (doorbells/save-restore omitted; notify is
//! serviced synchronously on the vCPU thread).

use crate::devices::mmio_bus::{MmioAccess, MmioBus};
use crate::pci::config::{BarEvent, BarKind, PciConfigSpace};
use crate::pci::msix::MsiX;
use crate::pci::{PciFunction, CAP_ID_VENDOR};
use crate::virtio::device::{
    VirtioDevice, FEATURE_RING_EVENT_IDX, STATUS_DRIVER_OK, STATUS_FEATURES_OK, STATUS_NEEDS_RESET,
};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::thread::JoinHandle;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Hypervisor::WHV_PARTITION_HANDLE;
use windows_sys::Win32::System::Threading::{
    CreateEventW, ResetEvent, SetEvent, WaitForMultipleObjects,
};
use whpsys::doorbell::Doorbell;

// BAR0 layout.
const BAR_SIZE: u32 = 0x4000;
const OFF_COMMON: u64 = 0x0000;
const LEN_COMMON: u64 = 0x0040;
const OFF_ISR: u64 = 0x0040;
const LEN_ISR: u64 = 0x0004;
const OFF_NOTIFY: u64 = 0x1000;
const LEN_NOTIFY: u64 = 0x1000;
const NOTIFY_MULT: u32 = 4;
const OFF_DEVICE: u64 = 0x2000;
const LEN_DEVICE: u64 = 0x0100;
const OFF_MSIX_TABLE: u32 = 0x3000;
const OFF_MSIX_PBA: u32 = 0x3800;

// virtio-pci capability config types.
const CAP_COMMON: u8 = 1;
const CAP_NOTIFY: u8 = 2;
const CAP_ISR: u8 = 3;
const CAP_DEVICE: u8 = 4;

// common_cfg field offsets.
const CC_DEVICE_FEATURE_SELECT: u32 = 0x00;
const CC_DEVICE_FEATURE: u32 = 0x04;
const CC_DRIVER_FEATURE_SELECT: u32 = 0x08;
const CC_DRIVER_FEATURE: u32 = 0x0C;
const CC_MSIX_CONFIG: u32 = 0x10;
const CC_DEVICE_STATUS: u32 = 0x14;
const CC_QUEUE_SIZE: u32 = 0x18;
const CC_QUEUE_ENABLE: u32 = 0x1C;
const CC_QUEUE_DESC: u32 = 0x20;
const CC_QUEUE_DRIVER: u32 = 0x28;
const CC_QUEUE_DEVICE: u32 = 0x30;

const ISR_QUEUE_BIT: u32 = 1 << 0;
const ISR_CONFIG_BIT: u32 = 1 << 1;

pub struct Options {
    pub vendor_id: u16,
    pub sub_vendor_id: u16,
    pub sub_id: u16,
    pub num_msix_vectors: u16,
    pub pci_class: u8,
    pub pci_subclass: u8,
    /// Install WHP MMIO doorbells on the queue-notify registers so guest kicks
    /// don't take a VM exit; a pump thread services the queues instead. Worth
    /// it only for devices with a hot notify path + a downstream worker
    /// (virtio-net). Leave false for low-rate devices (console/rng).
    pub doorbells: bool,
}

#[derive(Clone, Copy)]
struct QueueState {
    msix_vector: u16,
    enable: u16,
    desc: u64,
    driver: u64,
    device: u64,
    size: u16,
}

impl Default for QueueState {
    fn default() -> Self {
        QueueState {
            msix_vector: 0xFFFF,
            enable: 0,
            desc: 0,
            driver: 0,
            device: 0,
            size: 0,
        }
    }
}

struct Common {
    device_feature_select: u32,
    driver_feature_select: u32,
    driver_features: u64,
    msix_config: u16,
    status: u8,
    config_generation: u8,
    queue_select: u16,
    queues: Vec<QueueState>,
}

pub struct PciTransport {
    me: Weak<PciTransport>,
    name: String,
    device: Arc<dyn VirtioDevice>,
    mmio_bus: Arc<MmioBus>,
    msix: Arc<MsiX>,
    msix_cap_off: u32,
    cfg: Mutex<PciConfigSpace>,
    common: Mutex<Common>,
    isr_status: AtomicU32,
    bar_gpa: AtomicU64,
    bar_mapped: AtomicBool,
    notify_count: AtomicU64,
    part: WHV_PARTITION_HANDLE,
    use_doorbells: bool,
    doorbell_state: Mutex<Option<DoorbellState>>,
}

/// Active doorbell set + the pump thread servicing them. Dropped on BAR unmap.
struct DoorbellState {
    stop_event: HANDLE,
    doorbells: Vec<Doorbell>,
    pump: Option<JoinHandle<()>>,
}

// SAFETY: the raw fields are OS event HANDLEs (stop_event + the per-doorbell
// events) used only for cross-thread signalling/waiting, which is thread-safe.
unsafe impl Send for DoorbellState {}

/// Send wrapper so the wait-handle array can move into the pump thread.
struct SendHandles(Vec<HANDLE>);
// SAFETY: the wrapped HANDLEs are OS event handles passed to the pump thread for
// WaitForMultipleObjects only; OS handle waits are thread-safe.
unsafe impl Send for SendHandles {}

/// Pump thread: wait on {stop, per-queue doorbells} and drive the existing
/// `notify_queue` path off the event instead of a VM exit. A short timeout
/// sweeps all queues as a safety net for any notification that the doorbell
/// didn't catch (e.g. EVENT_IDX corner cases) — mirrors the C++ 5 ms sweep.
/// Pump thread: block until a per-queue doorbell (or stop) fires and drive the
/// existing `notify_queue` path — no VM exit, and no periodic wakeup. The
/// doorbell is sufficient on its own: the virtqueue re-reads avail.idx
/// (Acquire) every drain and publishes avail_event (Release) requesting the
/// next kick, so the EVENT_IDX notification race is closed (verified: a 20 MB
/// transfer ran at line rate with the periodic sweep disabled). Any write that
/// somehow doesn't match the doorbell still falls through to the MMIO handler,
/// so no periodic safety sweep is needed (unlike the C++, whose 5 ms timeout is
/// really its WSAPoll socket-poll cadence — we use IOCP for sockets instead).
/// The pump holds a strong `Arc<dyn VirtioDevice>` (not `Weak<PciTransport>`):
/// it only needs `notify_queue`, the device merely *weak*-refs the transport
/// back (via the irq closure) so there's no strong cycle, and teardown drives
/// the exit via `stop_event` + join — so no per-fire `upgrade()` is needed.
fn doorbell_pump(device: Arc<dyn VirtioDevice>, handles: SendHandles, qcount: u32) {
    // INFINITE: wake only on a doorbell/stop. Set to a finite value to also run
    // a periodic all-queue safety sweep (not needed; see above).
    const SWEEP_MS: u32 = u32::MAX;
    let handles = handles.0;
    loop {
        let r = unsafe {
            WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, SWEEP_MS)
        };
        if r == WAIT_OBJECT_0 {
            break; // stop_event
        }
        if r == WAIT_TIMEOUT {
            for q in 0..qcount {
                device.notify_queue(q);
            }
        } else {
            let i = r.wrapping_sub(WAIT_OBJECT_0) as usize;
            if i >= 1 && i < handles.len() {
                unsafe {
                    ResetEvent(handles[i]);
                }
                if crate::diag::etw::enabled(
                    crate::diag::etw::VERBOSE,
                    crate::diag::etw::kw::DOORBELL,
                ) {
                    crate::diag::etw::Event::new(
                        "Doorbell",
                        crate::diag::etw::VERBOSE,
                        crate::diag::etw::kw::DOORBELL,
                    )
                    .u32("queue", (i - 1) as u32)
                    .write();
                }
                device.notify_queue((i - 1) as u32);
            } else {
                break; // WAIT_FAILED or unexpected
            }
        }
    }
}

impl Drop for PciTransport {
    fn drop(&mut self) {
        self.teardown_doorbells();
    }
}


fn append_virtio_cap(
    cfg: &mut PciConfigSpace,
    cfg_type: u8,
    bar: u8,
    offset: u32,
    length: u32,
    multiplier: u32,
) {
    let cap_len: u32 = if multiplier != 0 { 20 } else { 16 };
    let off = cfg.append_capability(CAP_ID_VENDOR, cap_len);
    let p = cfg.cfg_bytes_mut(off, cap_len as usize);
    p[2] = cap_len as u8;
    p[3] = cfg_type;
    p[4] = bar;
    p[5] = 0;
    p[6] = 0;
    p[7] = 0;
    p[8..12].copy_from_slice(&offset.to_le_bytes());
    p[12..16].copy_from_slice(&length.to_le_bytes());
    if multiplier != 0 {
        p[16..20].copy_from_slice(&multiplier.to_le_bytes());
    }
}

impl PciTransport {
    pub fn new(
        name: &str,
        device: Arc<dyn VirtioDevice>,
        opts: Options,
        mmio_bus: Arc<MmioBus>,
        part: WHV_PARTITION_HANDLE,
    ) -> Arc<Self> {
        assert!(opts.num_msix_vectors >= 1);
        let qcount = device.queue_count();
        let did = 0x1040u16 + device.device_id() as u16;
        let sub_id = if opts.sub_id != 0 {
            opts.sub_id
        } else {
            device.device_id() as u16
        };

        let mut cfg = PciConfigSpace::new();
        cfg.set_ids(opts.vendor_id, did, opts.sub_vendor_id, sub_id);
        cfg.set_class(opts.pci_class, opts.pci_subclass, 0, 0);
        cfg.set_interrupt_pin(0);
        cfg.declare_mmio64_bar(0, BAR_SIZE, true);

        append_virtio_cap(&mut cfg, CAP_COMMON, 0, OFF_COMMON as u32, LEN_COMMON as u32, 0);
        append_virtio_cap(&mut cfg, CAP_NOTIFY, 0, OFF_NOTIFY as u32, LEN_NOTIFY as u32, NOTIFY_MULT);
        append_virtio_cap(&mut cfg, CAP_ISR, 0, OFF_ISR as u32, LEN_ISR as u32, 0);
        append_virtio_cap(&mut cfg, CAP_DEVICE, 0, OFF_DEVICE as u32, LEN_DEVICE as u32, 0);

        let msix = MsiX::new(opts.num_msix_vectors as u32, part, 0, OFF_MSIX_TABLE, OFF_MSIX_PBA);
        let msix_cap_off = msix.add_capability(&mut cfg);

        let queues = vec![QueueState::default(); qcount as usize];

        Arc::new_cyclic(|weak| PciTransport {
            me: weak.clone(),
            name: name.to_string(),
            device,
            mmio_bus,
            msix,
            msix_cap_off,
            cfg: Mutex::new(cfg),
            common: Mutex::new(Common {
                device_feature_select: 0,
                driver_feature_select: 0,
                driver_features: 0,
                msix_config: 0xFFFF,
                status: 0,
                config_generation: 0,
                queue_select: 0,
                queues,
            }),
            isr_status: AtomicU32::new(0),
            bar_gpa: AtomicU64::new(0),
            bar_mapped: AtomicBool::new(false),
            notify_count: AtomicU64::new(0),
            part,
            use_doorbells: opts.doorbells,
            doorbell_state: Mutex::new(None),
        })
    }

    // ---- Device -> transport interrupt signals.

    pub fn raise_queue_interrupt(&self, qidx: u32) {
        self.isr_status.fetch_or(ISR_QUEUE_BIT, Ordering::Relaxed);
        let v = {
            let c = self.common.lock().unwrap();
            c.queues.get(qidx as usize).map(|q| q.msix_vector).unwrap_or(0xFFFF)
        };
        if v != 0xFFFF {
            self.msix.trigger(v as u32);
        }
    }

    pub fn raise_config_change_interrupt(&self) {
        self.isr_status.fetch_or(ISR_CONFIG_BIT, Ordering::Relaxed);
        let v = {
            let mut c = self.common.lock().unwrap();
            c.config_generation = c.config_generation.wrapping_add(1);
            c.msix_config
        };
        if v != 0xFFFF {
            self.msix.trigger(v as u32);
        }
    }

    fn on_bar_mapped(&self, gpa: u64) {
        self.bar_gpa.store(gpa, Ordering::Relaxed);
        self.bar_mapped.store(true, Ordering::Relaxed);
        self.install_bar_handlers(gpa);
        if self.use_doorbells {
            self.install_doorbells(gpa);
        }
    }

    fn on_bar_unmapped(&self) {
        if !self.bar_mapped.swap(false, Ordering::Relaxed) {
            return;
        }
        self.teardown_doorbells();
        let gpa = self.bar_gpa.load(Ordering::Relaxed);
        self.mmio_bus.unregister(gpa + OFF_COMMON);
        self.mmio_bus.unregister(gpa + OFF_ISR);
        self.mmio_bus.unregister(gpa + OFF_NOTIFY);
        self.mmio_bus.unregister(gpa + OFF_DEVICE);
        self.msix.uninstall(&self.mmio_bus);
    }

    /// Register a WHP doorbell on each queue's notify register and start the
    /// pump thread. Matching guest kicks then signal an event with no VM exit.
    fn install_doorbells(&self, gpa: u64) {
        let mut guard = self.doorbell_state.lock().unwrap();
        if guard.is_some() {
            return;
        }
        let qcount = self.device.queue_count();
        let stop_event =
            unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if stop_event.is_null() {
            return;
        }
        let mut doorbells = Vec::with_capacity(qcount as usize);
        let mut handles: Vec<HANDLE> = Vec::with_capacity(qcount as usize + 1);
        handles.push(stop_event);
        for q in 0..qcount {
            let notify_gpa = gpa + OFF_NOTIFY + (q as u64) * (NOTIFY_MULT as u64);
            // The driver writes the 16-bit queue index to the notify register.
            match Doorbell::new(self.part, notify_gpa, q as u64, 2) {
                Some(db) => {
                    handles.push(db.event());
                    doorbells.push(db);
                }
                None => {
                    // Partial failure: tear down what we registered and bail
                    // (the MMIO fallback still services notifies).
                    unsafe {
                        CloseHandle(stop_event);
                    }
                    return;
                }
            }
        }
        let device = self.device.clone();
        let send = SendHandles(handles);
        let pump = std::thread::Builder::new()
            .name(format!("{}-doorbell", self.name))
            .spawn(move || doorbell_pump(device, send, qcount))
            .ok();
        *guard = Some(DoorbellState {
            stop_event,
            doorbells,
            pump,
        });
    }

    fn teardown_doorbells(&self) {
        let state = self.doorbell_state.lock().unwrap().take();
        if let Some(mut state) = state {
            unsafe {
                SetEvent(state.stop_event);
            }
            if let Some(h) = state.pump.take() {
                let _ = h.join();
            }
            // Doorbells unregister + close on drop now that the pump has exited.
            drop(state.doorbells);
            unsafe {
                CloseHandle(state.stop_event);
            }
        }
    }

    fn install_bar_handlers(&self, gpa: u64) {
        let w = self.me.clone();
        self.mmio_bus.register(
            gpa + OFF_COMMON,
            LEN_COMMON,
            "virtio:common",
            Box::new(move |a| {
                if let Some(t) = w.upgrade() {
                    t.handle_common_cfg(a);
                }
            }),
        );
        let w = self.me.clone();
        self.mmio_bus.register(
            gpa + OFF_ISR,
            LEN_ISR,
            "virtio:isr",
            Box::new(move |a| {
                if let Some(t) = w.upgrade() {
                    t.handle_isr(a);
                }
            }),
        );
        let w = self.me.clone();
        self.mmio_bus.register(
            gpa + OFF_NOTIFY,
            LEN_NOTIFY,
            "virtio:notify",
            Box::new(move |a| {
                if let Some(t) = w.upgrade() {
                    t.handle_notify(a);
                }
            }),
        );
        let w = self.me.clone();
        self.mmio_bus.register(
            gpa + OFF_DEVICE,
            LEN_DEVICE,
            "virtio:device-cfg",
            Box::new(move |a| {
                if let Some(t) = w.upgrade() {
                    t.handle_device_cfg(a);
                }
            }),
        );
        self.msix.install(&self.mmio_bus, gpa);
    }

    fn handle_common_cfg(&self, access: &mut MmioAccess) {
        let mut c = self.common.lock().unwrap();
        let base = self.bar_gpa.load(Ordering::Relaxed) + OFF_COMMON;
        let off = (access.gpa - base) as u32;
        let sz = access.access_size as u32;

        if access.is_write {
            if sz == 8 && (off & 0x7) == 0 {
                let v = u64::from_le_bytes(access.data);
                self.write_cc32(&mut c, off, v as u32);
                self.write_cc32(&mut c, off + 4, (v >> 32) as u32);
                return;
            }
            let n = sz.min(4) as usize;
            let mut buf = [0u8; 4];
            buf[..n].copy_from_slice(&access.data[..n]);
            let v = u32::from_le_bytes(buf);
            let aligned = off & !0x3;
            let shift = (off & 0x3) * 8;
            if sz < 4 {
                let mask = match sz {
                    1 => 0xFFu32,
                    2 => 0xFFFF,
                    _ => 0xFFFF_FFFF,
                };
                let mut cur = self.read_cc32(&c, aligned);
                cur &= !(mask << shift);
                cur |= (v & mask) << shift;
                self.write_cc32(&mut c, aligned, cur);
            } else {
                self.write_cc32(&mut c, aligned, v);
            }
            return;
        }

        if sz == 8 && (off & 0x7) == 0 {
            let lo = self.read_cc32(&c, off) as u64;
            let hi = self.read_cc32(&c, off + 4) as u64;
            access.data = (lo | (hi << 32)).to_le_bytes();
            return;
        }
        let aligned = off & !0x3;
        let shift = (off & 0x3) * 8;
        let v = self.read_cc32(&c, aligned) >> shift;
        access.data = [0; 8];
        let n = sz.min(4) as usize;
        access.data[..n].copy_from_slice(&v.to_le_bytes()[..n]);
    }

    fn read_cc32(&self, c: &Common, off: u32) -> u32 {
        match off {
            CC_DEVICE_FEATURE_SELECT => c.device_feature_select,
            CC_DEVICE_FEATURE => {
                let f = self.device.device_features();
                match c.device_feature_select {
                    0 => f as u32,
                    1 => (f >> 32) as u32,
                    _ => 0,
                }
            }
            CC_DRIVER_FEATURE_SELECT => c.driver_feature_select,
            CC_DRIVER_FEATURE => match c.driver_feature_select {
                0 => c.driver_features as u32,
                1 => (c.driver_features >> 32) as u32,
                _ => 0,
            },
            CC_MSIX_CONFIG => c.msix_config as u32 | ((self.device.queue_count()) << 16),
            CC_DEVICE_STATUS => {
                c.status as u32
                    | ((c.config_generation as u32) << 8)
                    | ((c.queue_select as u32) << 16)
            }
            CC_QUEUE_SIZE => {
                let mut sz = 0u16;
                let mut vec = 0xFFFFu16;
                if (c.queue_select as usize) < c.queues.len() {
                    let q = &c.queues[c.queue_select as usize];
                    sz = if q.size != 0 {
                        q.size
                    } else {
                        self.device.queue_max(c.queue_select as u32) as u16
                    };
                    vec = q.msix_vector;
                }
                sz as u32 | ((vec as u32) << 16)
            }
            CC_QUEUE_ENABLE => {
                let en = c
                    .queues
                    .get(c.queue_select as usize)
                    .map(|q| q.enable)
                    .unwrap_or(0);
                en as u32 | ((c.queue_select as u32) << 16)
            }
            o if o == CC_QUEUE_DESC
                || o == CC_QUEUE_DESC + 4
                || o == CC_QUEUE_DRIVER
                || o == CC_QUEUE_DRIVER + 4
                || o == CC_QUEUE_DEVICE
                || o == CC_QUEUE_DEVICE + 4 =>
            {
                let Some(q) = c.queues.get(c.queue_select as usize) else {
                    return 0;
                };
                let v: u64 = if o == CC_QUEUE_DESC {
                    q.desc
                } else if o == CC_QUEUE_DESC + 4 {
                    q.desc >> 32
                } else if o == CC_QUEUE_DRIVER {
                    q.driver
                } else if o == CC_QUEUE_DRIVER + 4 {
                    q.driver >> 32
                } else if o == CC_QUEUE_DEVICE {
                    q.device
                } else {
                    q.device >> 32
                };
                v as u32
            }
            _ => 0,
        }
    }

    fn write_cc32(&self, c: &mut Common, off: u32, value: u32) {
        match off {
            CC_DEVICE_FEATURE_SELECT => c.device_feature_select = value,
            CC_DEVICE_FEATURE => {}
            CC_DRIVER_FEATURE_SELECT => c.driver_feature_select = value,
            CC_DRIVER_FEATURE => {
                if c.driver_feature_select > 1 {
                    return;
                }
                if c.driver_feature_select == 0 {
                    c.driver_features = (c.driver_features & 0xFFFF_FFFF_0000_0000) | value as u64;
                } else {
                    c.driver_features =
                        (c.driver_features & 0x0000_0000_FFFF_FFFF) | ((value as u64) << 32);
                }
            }
            CC_MSIX_CONFIG => c.msix_config = (value & 0xFFFF) as u16,
            CC_DEVICE_STATUS => {
                let new_status = (value & 0xFF) as u8;
                if new_status != c.status {
                    self.apply_status_write(c, new_status);
                }
                c.queue_select = ((value >> 16) & 0xFFFF) as u16;
            }
            CC_QUEUE_SIZE => {
                let sel = c.queue_select as usize;
                if sel < c.queues.len() {
                    let qs = (value & 0xFFFF) as u16;
                    let max = self.device.queue_max(c.queue_select as u32) as u16;
                    if qs <= max {
                        c.queues[sel].size = qs;
                    }
                    c.queues[sel].msix_vector = ((value >> 16) & 0xFFFF) as u16;
                }
            }
            CC_QUEUE_ENABLE => {
                let en = (value & 0xFFFF) as u16;
                let sel = c.queue_select as usize;
                if sel < c.queues.len() {
                    c.queues[sel].enable = en;
                    let q = c.queues[sel];
                    if en != 0 && q.size != 0 {
                        let event_idx = c.driver_features & FEATURE_RING_EVENT_IDX != 0;
                        self.device.enable_queue(
                            c.queue_select as u32,
                            q.desc,
                            q.driver,
                            q.device,
                            q.size,
                            event_idx,
                        );
                    } else if en == 0 {
                        self.device.disable_queue(c.queue_select as u32);
                    }
                }
            }
            o if o == CC_QUEUE_DESC || o == CC_QUEUE_DRIVER || o == CC_QUEUE_DEVICE => {
                let sel = c.queue_select as usize;
                if sel < c.queues.len() {
                    let q = &mut c.queues[sel];
                    let lo = value as u64;
                    if o == CC_QUEUE_DESC {
                        q.desc = (q.desc & 0xFFFF_FFFF_0000_0000) | lo;
                    } else if o == CC_QUEUE_DRIVER {
                        q.driver = (q.driver & 0xFFFF_FFFF_0000_0000) | lo;
                    } else {
                        q.device = (q.device & 0xFFFF_FFFF_0000_0000) | lo;
                    }
                }
            }
            o if o == CC_QUEUE_DESC + 4 || o == CC_QUEUE_DRIVER + 4 || o == CC_QUEUE_DEVICE + 4 => {
                let sel = c.queue_select as usize;
                if sel < c.queues.len() {
                    let q = &mut c.queues[sel];
                    let hi = (value as u64) << 32;
                    if o == CC_QUEUE_DESC + 4 {
                        q.desc = (q.desc & 0x0000_0000_FFFF_FFFF) | hi;
                    } else if o == CC_QUEUE_DRIVER + 4 {
                        q.driver = (q.driver & 0x0000_0000_FFFF_FFFF) | hi;
                    } else {
                        q.device = (q.device & 0x0000_0000_FFFF_FFFF) | hi;
                    }
                }
            }
            _ => {}
        }
    }

    fn apply_status_write(&self, c: &mut Common, new_status: u8) {
        if new_status == 0 {
            c.status = 0;
            self.isr_status.store(0, Ordering::Relaxed);
            c.device_feature_select = 0;
            c.driver_feature_select = 0;
            c.driver_features = 0;
            c.msix_config = 0xFFFF;
            c.queue_select = 0;
            for q in c.queues.iter_mut() {
                *q = QueueState::default();
            }
            self.device.reset();
            return;
        }
        let prev = c.status;
        let adding = new_status & !prev;
        let mut effective = new_status;
        if adding & STATUS_FEATURES_OK != 0
            && !self.device.set_driver_features(c.driver_features) {
                effective &= !STATUS_FEATURES_OK;
                effective |= STATUS_NEEDS_RESET;
            }
        c.status = effective;
        if adding & STATUS_DRIVER_OK != 0 {
            self.device.driver_ok();
        }
    }

    fn handle_isr(&self, access: &mut MmioAccess) {
        if access.is_write {
            return;
        }
        let snap = self.isr_status.swap(0, Ordering::AcqRel);
        access.data = [0; 8];
        let n = (access.access_size as usize).min(4);
        access.data[..n].copy_from_slice(&snap.to_le_bytes()[..n]);
    }

    fn handle_notify(&self, access: &mut MmioAccess) {
        if !access.is_write {
            access.data = [0; 8];
            return;
        }
        self.notify_count.fetch_add(1, Ordering::Relaxed);
        let off = (access.gpa - (self.bar_gpa.load(Ordering::Relaxed) + OFF_NOTIFY)) as u32;
        let mut qidx = off / NOTIFY_MULT;
        if access.access_size == 2 {
            qidx = u16::from_le_bytes(access.data[0..2].try_into().unwrap()) as u32;
        } else if access.access_size == 4 {
            qidx = u32::from_le_bytes(access.data[0..4].try_into().unwrap());
        }
        // Do NOT hold the common lock: the device's drain path may call back
        // into raise_queue_interrupt (which locks common).
        self.device.notify_queue(qidx);
    }

    fn handle_device_cfg(&self, access: &mut MmioAccess) {
        let off = (access.gpa - (self.bar_gpa.load(Ordering::Relaxed) + OFF_DEVICE)) as u32;
        if access.is_write {
            let n = (access.access_size as usize).min(4);
            let mut buf = [0u8; 4];
            buf[..n].copy_from_slice(&access.data[..n]);
            self.device
                .write_config(off, access.access_size as u32, u32::from_le_bytes(buf));
            return;
        }
        let v = self.device.read_config(off, access.access_size as u32);
        access.data = [0; 8];
        let n = (access.access_size as usize).min(4);
        access.data[..n].copy_from_slice(&v.to_le_bytes()[..n]);
    }
}

impl PciFunction for PciTransport {
    fn name(&self) -> &str {
        &self.name
    }

    fn config_read(&self, offset: u32, size: u32) -> u32 {
        self.cfg.lock().unwrap().read(offset, size)
    }

    fn config_write(&self, offset: u32, size: u32, value: u32) {
        let events = self.cfg.lock().unwrap().write(offset, size, value);
        // Keep the MSI-X helper's enable/funcmask in sync with config space.
        let mc = self.cfg.lock().unwrap().read16(self.msix_cap_off + 2);
        self.msix.set_control(mc);
        for e in events {
            match e {
                BarEvent::Mapped { idx: 0, gpa, .. } => self.on_bar_mapped(gpa),
                BarEvent::Unmapped { idx: 0 } => self.on_bar_unmapped(),
                _ => {}
            }
        }
    }

    fn bar_layout(&self) -> [(BarKind, u32); 6] {
        self.cfg.lock().unwrap().bar_layout()
    }

    fn assign_bar_base(&self, idx: usize, gpa: u64) {
        self.cfg.lock().unwrap().set_bar_base(idx, gpa);
    }
}

// ======================= Snapshot (save/restore) =======================
//
// One `DeviceSnapshot` captures everything needed to restore a virtio-PCI
// function: PCI config (BARs/command), MSI-X routing table, virtio common-cfg
// (incl. the per-queue MSI-X vector mapping, which is the unique routing info
// not stored in the virtqueues), per-queue programming, and device-specific
// bytes. Rust-self-consistent only -- NOT cross-compatible with the C++ format.

use crate::virtio::queue::{QueueState as VqState, QUEUE_STATE_ENCODED};

pub struct DeviceSnapshot {
    cfg: [u8; 256],
    bar_vals: [(u32, u32); 6],
    device_feature_select: u32,
    driver_feature_select: u32,
    driver_features: u64,
    msix_config: u16,
    status: u8,
    config_generation: u8,
    queue_select: u16,
    common_queues: Vec<QueueState>,
    isr: u32,
    msix_control: u16,
    msix_table: Vec<[u32; 4]>,
    msix_pba: Vec<u64>,
    /// (queue index, durable virtqueue programming + ring position).
    queues: Vec<(u32, VqState)>,
    device_state: Vec<u8>,
}

struct LeW {
    b: Vec<u8>,
}
impl LeW {
    fn new() -> Self {
        LeW { b: Vec::new() }
    }
    fn u8(&mut self, v: u8) {
        self.b.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, s: &[u8]) {
        self.b.extend_from_slice(s);
    }
}

struct LeR<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> LeR<'a> {
    fn new(b: &'a [u8]) -> Self {
        LeR { b, p: 0 }
    }
    fn need(&self, n: usize) -> bool {
        self.p + n <= self.b.len()
    }
    fn u8(&mut self) -> u8 {
        let v = self.b[self.p];
        self.p += 1;
        v
    }
    fn u16(&mut self) -> u16 {
        let v = u16::from_le_bytes([self.b[self.p], self.b[self.p + 1]]);
        self.p += 2;
        v
    }
    fn u32(&mut self) -> u32 {
        let mut a = [0u8; 4];
        a.copy_from_slice(&self.b[self.p..self.p + 4]);
        self.p += 4;
        u32::from_le_bytes(a)
    }
    fn u64(&mut self) -> u64 {
        let mut a = [0u8; 8];
        a.copy_from_slice(&self.b[self.p..self.p + 8]);
        self.p += 8;
        u64::from_le_bytes(a)
    }
    fn take(&mut self, n: usize) -> &'a [u8] {
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        s
    }
}

impl DeviceSnapshot {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = LeW::new();
        w.bytes(&self.cfg);
        for (lo, hi) in self.bar_vals.iter() {
            w.u32(*lo);
            w.u32(*hi);
        }
        w.u32(self.device_feature_select);
        w.u32(self.driver_feature_select);
        w.u64(self.driver_features);
        w.u16(self.msix_config);
        w.u8(self.status);
        w.u8(self.config_generation);
        w.u16(self.queue_select);
        w.u32(self.isr);
        w.u16(self.common_queues.len() as u16);
        for q in &self.common_queues {
            w.u16(q.msix_vector);
            w.u16(q.enable);
            w.u16(q.size);
            w.u64(q.desc);
            w.u64(q.driver);
            w.u64(q.device);
        }
        w.u16(self.msix_control);
        w.u16(self.msix_table.len() as u16);
        for e in &self.msix_table {
            w.u32(e[0]);
            w.u32(e[1]);
            w.u32(e[2]);
            w.u32(e[3]);
        }
        w.u16(self.msix_pba.len() as u16);
        for p in &self.msix_pba {
            w.u64(*p);
        }
        w.u16(self.queues.len() as u16);
        for (qidx, st) in &self.queues {
            w.u32(*qidx);
            w.bytes(&st.encode());
        }
        w.u32(self.device_state.len() as u32);
        w.bytes(&self.device_state);
        w.b
    }

    pub fn decode(buf: &[u8]) -> Option<DeviceSnapshot> {
        let mut r = LeR::new(buf);
        if !r.need(256 + 48 + 4 + 4 + 8 + 2 + 1 + 1 + 2 + 4 + 2) {
            return None;
        }
        let mut cfg = [0u8; 256];
        cfg.copy_from_slice(r.take(256));
        let mut bar_vals = [(0u32, 0u32); 6];
        for slot in bar_vals.iter_mut() {
            let lo = r.u32();
            let hi = r.u32();
            *slot = (lo, hi);
        }
        let device_feature_select = r.u32();
        let driver_feature_select = r.u32();
        let driver_features = r.u64();
        let msix_config = r.u16();
        let status = r.u8();
        let config_generation = r.u8();
        let queue_select = r.u16();
        let isr = r.u32();
        let cq_count = r.u16() as usize;
        if !r.need(cq_count * (2 + 2 + 2 + 8 + 8 + 8)) {
            return None;
        }
        let mut common_queues = Vec::with_capacity(cq_count);
        for _ in 0..cq_count {
            let msix_vector = r.u16();
            let enable = r.u16();
            let size = r.u16();
            let desc = r.u64();
            let driver = r.u64();
            let device = r.u64();
            common_queues.push(QueueState {
                msix_vector,
                enable,
                desc,
                driver,
                device,
                size,
            });
        }
        if !r.need(2) {
            return None;
        }
        let msix_control = r.u16();
        if !r.need(2) {
            return None;
        }
        let t_count = r.u16() as usize;
        if !r.need(t_count * 16) {
            return None;
        }
        let mut msix_table = Vec::with_capacity(t_count);
        for _ in 0..t_count {
            msix_table.push([r.u32(), r.u32(), r.u32(), r.u32()]);
        }
        if !r.need(2) {
            return None;
        }
        let p_count = r.u16() as usize;
        if !r.need(p_count * 8) {
            return None;
        }
        let mut msix_pba = Vec::with_capacity(p_count);
        for _ in 0..p_count {
            msix_pba.push(r.u64());
        }
        if !r.need(2) {
            return None;
        }
        let q_count = r.u16() as usize;
        let mut queues = Vec::with_capacity(q_count);
        for _ in 0..q_count {
            if !r.need(4 + QUEUE_STATE_ENCODED) {
                return None;
            }
            let qidx = r.u32();
            let st = VqState::decode(r.take(QUEUE_STATE_ENCODED))?;
            queues.push((qidx, st));
        }
        if !r.need(4) {
            return None;
        }
        let ds_len = r.u32() as usize;
        if !r.need(ds_len) {
            return None;
        }
        let device_state = r.take(ds_len).to_vec();
        Some(DeviceSnapshot {
            cfg,
            bar_vals,
            device_feature_select,
            driver_feature_select,
            driver_features,
            msix_config,
            status,
            config_generation,
            queue_select,
            common_queues,
            isr,
            msix_control,
            msix_table,
            msix_pba,
            queues,
            device_state,
        })
    }
}

impl PciTransport {
    /// Capture the full device state for a snapshot.
    pub fn snapshot_capture(&self) -> DeviceSnapshot {
        let (cfg, bar_vals) = self.cfg.lock().unwrap().snapshot_capture();
        let (msix_control, msix_table, msix_pba) = self.msix.snapshot_capture();
        let (
            device_feature_select,
            driver_feature_select,
            driver_features,
            msix_config,
            status,
            config_generation,
            queue_select,
            common_queues,
        ) = {
            let c = self.common.lock().unwrap();
            (
                c.device_feature_select,
                c.driver_feature_select,
                c.driver_features,
                c.msix_config,
                c.status,
                c.config_generation,
                c.queue_select,
                c.queues.clone(),
            )
        };
        let qcount = self.device.queue_count();
        let mut queues = Vec::with_capacity(qcount as usize);
        for q in 0..qcount {
            if let Some(st) = self.device.capture_queue(q) {
                queues.push((q, st));
            }
        }
        DeviceSnapshot {
            cfg,
            bar_vals,
            device_feature_select,
            driver_feature_select,
            driver_features,
            msix_config,
            status,
            config_generation,
            queue_select,
            common_queues,
            isr: self.isr_status.load(Ordering::Relaxed),
            msix_control,
            msix_table,
            msix_pba,
            queues,
            device_state: self.device.capture_device_state(),
        }
    }

    /// Restore the full device state from a snapshot. The guest must NOT be
    /// running. Order is significant: (1) PCI config first so the BAR re-maps
    /// and the MMIO + MSI-X handlers re-register; (2) virtio common-cfg so the
    /// per-queue MSI-X vector mapping is in place for IRQ routing; (3) MSI-X
    /// table so completions route; (4) device virtqueue programming; (5)
    /// device-specific state (driver_ok, etc.). The status state machine is
    /// NOT re-run -- fields are set directly.
    pub fn snapshot_apply(&self, snap: &DeviceSnapshot) {
        let events = self
            .cfg
            .lock()
            .unwrap()
            .snapshot_apply(&snap.cfg, &snap.bar_vals);
        for e in events {
            match e {
                BarEvent::Mapped { idx: 0, gpa, .. } => self.on_bar_mapped(gpa),
                BarEvent::Unmapped { idx: 0 } => self.on_bar_unmapped(),
                _ => {}
            }
        }
        {
            let mut c = self.common.lock().unwrap();
            c.device_feature_select = snap.device_feature_select;
            c.driver_feature_select = snap.driver_feature_select;
            c.driver_features = snap.driver_features;
            c.msix_config = snap.msix_config;
            c.status = snap.status;
            c.config_generation = snap.config_generation;
            c.queue_select = snap.queue_select;
            if snap.common_queues.len() == c.queues.len() {
                c.queues.copy_from_slice(&snap.common_queues);
            } else {
                c.queues = snap.common_queues.clone();
            }
        }
        self.isr_status.store(snap.isr, Ordering::Relaxed);
        self.msix
            .snapshot_apply(snap.msix_control, &snap.msix_table, &snap.msix_pba);
        for (qidx, st) in &snap.queues {
            self.device.apply_queue(*qidx, st);
        }
        self.device.apply_device_state(&snap.device_state);
    }
}
