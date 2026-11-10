//! virtio-PCI "modern" transport (spec §4.1). Exposes a `VirtioDevice` over a
//! PCI Type-0 function with the standard capability chain + MSI-X. Port of
//! src/virtio/virtio_pci.cpp (doorbells/save-restore omitted; notify is
//! serviced synchronously on the vCPU thread).

use crate::devices::mmio_bus::{MmioAccess, MmioBus};
use crate::mem_layout::{MMIO_WINDOW_BASE, MMIO_WINDOW_END};
use crate::pci::config::{BarEvent, BarKind, PciConfigSpace};
use crate::pci::msix::MsiX;
use crate::pci::{CAP_ID_VENDOR, PciFunction};
use crate::virtio::device::{
    FEATURE_RING_EVENT_IDX, STATUS_DRIVER_OK, STATUS_FEATURES_OK, STATUS_NEEDS_RESET, VirtioDevice,
};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::thread::JoinHandle;
use whpsys::doorbell::Doorbell;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Hypervisor::WHV_PARTITION_HANDLE;
use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent, WaitForMultipleObjects};

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
    /// The status a reset (status write of 0) started from. Reads report it
    /// instead of 0 while the device is still settling that reset.
    reset_from: u8,
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
    /// The MSI-X vector of each queue and of config changes, as `common` has
    /// them (`sync_vectors`), and the config generation. Kept outside
    /// `common` so that raising an interrupt takes no lock: devices raise from
    /// their own threads, sometimes under a device lock, while `common` is
    /// held across the device callbacks (reset, enable, disable) that take
    /// those same locks.
    queue_vectors: Vec<AtomicU16>,
    config_vector: AtomicU16,
    config_generation: AtomicU8,
    bar_gpa: AtomicU64,
    bar_mapped: AtomicBool,
    notify_count: AtomicU64,
    part: WHV_PARTITION_HANDLE,
    use_doorbells: bool,
    doorbell_state: Mutex<Option<DoorbellState>>,
}

/// The doorbells of a transport and the pump thread serving them. Registered
/// the first time the BAR is mapped and kept until the transport drops:
/// unregistering one can block forever in vid.sys (see `whpsys::doorbell`),
/// and the guest decides when a BAR is unmapped, so nothing it does may reach
/// an unregistration.
struct DoorbellState {
    stop_event: HANDLE,
    doorbells: Vec<Doorbell>,
    pump: Option<JoinHandle<()>>,
    route: Arc<DoorbellRoute>,
}

/// What a doorbell pump needs to know about its transport's BAR.
struct DoorbellRoute {
    /// The BAR base the doorbells were registered at.
    gpa: u64,
    /// The BAR is mapped at `gpa` now, so a doorbell is a kick of this
    /// device's queue. Otherwise the guest has unmapped or moved the BAR and
    /// the write belongs to whatever sits at that address (see
    /// [`doorbell_pump`]).
    live: AtomicBool,
    mmio_bus: Arc<MmioBus>,
}

impl DoorbellRoute {
    /// Hand the write that fired queue `q`'s doorbell to the MMIO bus: the
    /// 2-byte store of `q` to that queue's notify address, which is all a
    /// doorbell matches.
    fn forward(&self, q: u32) {
        let mut write = MmioAccess {
            gpa: self.gpa + OFF_NOTIFY + u64::from(q) * u64::from(NOTIFY_MULT),
            access_size: 2,
            is_write: true,
            data: [0; 8],
        };
        write.data[..2].copy_from_slice(&(q as u16).to_le_bytes());
        self.mmio_bus.dispatch(&mut write);
    }
}

// SAFETY: the raw fields are OS event HANDLEs (stop_event + the per-doorbell
// events) used only for cross-thread signalling/waiting, which is thread-safe.
unsafe impl Send for DoorbellState {}

/// Send wrapper so the wait-handle array can move into the pump thread.
struct SendHandles(Vec<HANDLE>);
// SAFETY: the wrapped HANDLEs are OS event handles passed to the pump thread for
// WaitForMultipleObjects only; OS handle waits are thread-safe.
unsafe impl Send for SendHandles {}

thread_local! {
    static ON_DOORBELL_PUMP: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// True on a doorbell pump thread. A device may run a request inline there
/// (the pump has nothing else to do) but must not on a vCPU thread, where
/// `notify_queue` arrives through the MMIO fallback.
pub fn on_doorbell_pump() -> bool {
    ON_DOORBELL_PUMP.with(|c| c.get())
}

/// Default ceiling of a pump's busy-poll window (`--poll-us`), KVM's default
/// `halt_poll_ns`. Nested, the gap a pump sees between finishing a request
/// and the doorbell for the guest's next one (the completion interrupt, the
/// guest's turnaround and the doorbell's own wake-up) is often over 50 us, so
/// a 50 us ceiling let the window collapse and every request paid the wake-up.
pub const DEFAULT_POLL_US: u64 = 200;
static POLL_MAX_NS: AtomicU64 = AtomicU64::new(DEFAULT_POLL_US * 1000);

/// Set the busy-poll ceiling for pumps started from now on; 0 disables polling.
pub fn set_poll_max_us(us: u64) {
    POLL_MAX_NS.store(us.saturating_mul(1000), Ordering::Relaxed);
}

/// Adaptive busy-poll window of one pump, after KVM's halt polling. A
/// doorbell's trip to the pump (hypervisor signal, DPC, thread wake-up, often
/// from a sleeping core) costs tens of microseconds, about as much as a whole
/// cached 4 KiB request. When the guest issues requests back to back, the pump
/// therefore spins on the ring for a while after each one and picks the next
/// request up from guest memory. The window grows while requests keep arriving
/// within the ceiling and decays to zero when they don't, so an idle or
/// sparsely used device never spins.
struct PollWindow {
    ns: u64,
    max: u64,
    last_done: std::time::Instant,
}

impl PollWindow {
    const MIN_NS: u64 = 2_000;

    fn new() -> Self {
        PollWindow {
            ns: 0,
            max: POLL_MAX_NS.load(Ordering::Relaxed),
            last_done: std::time::Instant::now(),
        }
    }

    /// Woken by a doorbell: a poll as long as the idle gap since the last
    /// work would have caught this request.
    fn on_doorbell(&mut self) {
        if self.max == 0 {
            return;
        }
        let gap = self.last_done.elapsed().as_nanos() as u64;
        if gap <= self.max {
            self.ns = (self.ns * 2)
                .max(gap + gap / 4)
                .clamp(Self::MIN_NS, self.max);
        } else {
            self.shrink();
        }
    }

    fn shrink(&mut self) {
        self.ns /= 2;
        if self.ns < Self::MIN_NS {
            self.ns = 0;
        }
    }

    /// Spin until queue `q` has work (true) or the window expires (false).
    fn poll(&mut self, device: &dyn VirtioDevice, q: u32) -> bool {
        let start = std::time::Instant::now();
        loop {
            match device.queue_has_work(q) {
                Some(true) => return true,
                Some(false) => {}
                None => {
                    // Not pollable: never try again on this pump.
                    self.max = 0;
                    self.ns = 0;
                    return false;
                }
            }
            if start.elapsed().as_nanos() as u64 >= self.ns {
                self.shrink();
                return false;
            }
            for _ in 0..16 {
                std::hint::spin_loop();
            }
        }
    }
}

/// Pump thread: block until a per-queue doorbell (or stop) fires and drive the
/// existing `notify_queue` path — no VM exit, and no periodic wakeup. The
/// doorbell is sufficient on its own: when a drain finds the ring empty, the
/// virtqueue publishes `avail_event` requesting the next kick, issues a full
/// fence, and re-reads `avail.idx` (`Virtqueue::arm_kick_and_recheck`, pairing
/// with the barrier in the driver's `virtqueue_kick_prepare`), so the EVENT_IDX
/// notification race is closed. Any write that somehow doesn't match the
/// doorbell still falls through to the MMIO handler, so no periodic safety
/// sweep is needed (unlike the C++, whose 5 ms timeout is really its WSAPoll
/// socket-poll cadence — we use IOCP for sockets instead).
/// The pump holds a strong `Arc<dyn VirtioDevice>` (not `Weak<PciTransport>`):
/// it only needs `notify_queue`, the device merely *weak*-refs the transport
/// back (via the irq closure) so there's no strong cycle, and teardown drives
/// the exit via `stop_event` + join — so no per-fire `upgrade()` is needed.
///
/// `handles[i + 1]` is the doorbell of queue `queues[i]`. The doorbells stay
/// registered at `route.gpa` for the transport's whole life, wherever the
/// guest moves the BAR. While the BAR isn't there, a doorbell is still the
/// 2-byte write of the queue index that matched it, at an address this device
/// no longer answers: the pump hands that write to the MMIO bus, as the VM
/// exit it replaced would have, so it reaches whichever device the guest put
/// there (or nothing).
fn doorbell_pump(
    device: Arc<dyn VirtioDevice>,
    route: Arc<DoorbellRoute>,
    handles: SendHandles,
    queues: Vec<u32>,
) {
    ON_DOORBELL_PUMP.with(|c| c.set(true));
    // INFINITE: wake only on a doorbell/stop. Set to a finite value to also run
    // a periodic all-queue safety sweep (not needed; see above).
    const SWEEP_MS: u32 = u32::MAX;
    let handles = handles.0;
    let mut window = PollWindow::new();
    loop {
        let r =
            unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, SWEEP_MS) };
        if r == WAIT_OBJECT_0 {
            break; // stop_event
        }
        if r == WAIT_TIMEOUT {
            if route.live.load(Ordering::Acquire) {
                for &q in &queues {
                    device.notify_queue(q);
                }
            }
        } else {
            let i = r.wrapping_sub(WAIT_OBJECT_0) as usize;
            if i >= 1 && i < handles.len() {
                let q = queues[i - 1];
                if !route.live.load(Ordering::Acquire) {
                    route.forward(q);
                    continue;
                }
                // Doorbell events are auto-reset (see whpsys::doorbell): WFMO
                // already consumed the signal, no ResetEvent needed.
                if crate::diag::etw::enabled(
                    crate::diag::etw::VERBOSE,
                    crate::diag::etw::kw::DOORBELL,
                ) {
                    crate::diag::etw::Event::new(
                        "Doorbell",
                        crate::diag::etw::VERBOSE,
                        crate::diag::etw::kw::DOORBELL,
                    )
                    .u32("queue", q)
                    .write();
                }
                window.on_doorbell();
                device.notify_queue(q);
                // Requests the poll catches are drained like a doorbell's. If
                // the guest kicked for one anyway, the event stays set and the
                // next wait returns at once into a drain that finds nothing.
                while window.ns > 0 && window.poll(device.as_ref(), q) {
                    device.notify_queue(q);
                }
                window.last_done = std::time::Instant::now();
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

        append_virtio_cap(
            &mut cfg,
            CAP_COMMON,
            0,
            OFF_COMMON as u32,
            LEN_COMMON as u32,
            0,
        );
        append_virtio_cap(
            &mut cfg,
            CAP_NOTIFY,
            0,
            OFF_NOTIFY as u32,
            LEN_NOTIFY as u32,
            NOTIFY_MULT,
        );
        append_virtio_cap(&mut cfg, CAP_ISR, 0, OFF_ISR as u32, LEN_ISR as u32, 0);
        append_virtio_cap(
            &mut cfg,
            CAP_DEVICE,
            0,
            OFF_DEVICE as u32,
            LEN_DEVICE as u32,
            0,
        );

        let msix = MsiX::new(
            opts.num_msix_vectors as u32,
            part,
            0,
            OFF_MSIX_TABLE,
            OFF_MSIX_PBA,
        );
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
                reset_from: 0,
                queue_select: 0,
                queues,
            }),
            isr_status: AtomicU32::new(0),
            queue_vectors: (0..qcount).map(|_| AtomicU16::new(0xFFFF)).collect(),
            config_vector: AtomicU16::new(0xFFFF),
            config_generation: AtomicU8::new(0),
            bar_gpa: AtomicU64::new(0),
            bar_mapped: AtomicBool::new(false),
            notify_count: AtomicU64::new(0),
            part,
            use_doorbells: opts.doorbells,
            doorbell_state: Mutex::new(None),
        })
    }

    // ---- Device -> transport interrupt signals.

    /// MSI-X interrupts this function has injected into the guest.
    pub fn msix_injected_count(&self) -> u64 {
        self.msix.injected_count()
    }

    /// Raise queue `qidx`'s interrupt. Takes no transport lock (see
    /// `queue_vectors`), so a device may call it from any thread, whatever
    /// device lock it holds.
    pub fn raise_queue_interrupt(&self, qidx: u32) {
        self.isr_status.fetch_or(ISR_QUEUE_BIT, Ordering::Relaxed);
        let v = self
            .queue_vectors
            .get(qidx as usize)
            .map_or(0xFFFF, |v| v.load(Ordering::Acquire));
        if v != 0xFFFF {
            self.msix.trigger(v as u32);
        }
    }

    pub fn raise_config_change_interrupt(&self) {
        self.isr_status.fetch_or(ISR_CONFIG_BIT, Ordering::Relaxed);
        self.config_generation.fetch_add(1, Ordering::AcqRel);
        let v = self.config_vector.load(Ordering::Acquire);
        if v != 0xFFFF {
            self.msix.trigger(v as u32);
        }
    }

    /// Publish the MSI-X vectors `c` holds to the lock-free copies the raise
    /// paths read. Call with `common` held, after anything that changes them.
    fn sync_vectors(&self, c: &Common) {
        self.config_vector.store(c.msix_config, Ordering::Release);
        for (i, v) in self.queue_vectors.iter().enumerate() {
            let vector = c.queues.get(i).map_or(0xFFFF, |q| q.msix_vector);
            v.store(vector, Ordering::Release);
        }
    }

    fn on_bar_mapped(&self, gpa: u64) {
        // The guest fully controls the BAR base. Refuse to wire a BAR that falls
        // outside the PCI MMIO window or overlaps another device's mapped BAR:
        // registering an overlapping range would otherwise abort the VMM. A
        // mis-programmed BAR just leaves this device's MMIO unwired (the guest's
        // own problem), never a host crash. `is_range_free` + the non-panicking
        // `MmioBus::register` are the backstop for a concurrent reprogram race.
        let end = gpa.checked_add(BAR_SIZE as u64);
        let placement_ok = gpa >= MMIO_WINDOW_BASE
            && end.is_some_and(|e| e <= MMIO_WINDOW_END)
            && self.mmio_bus.is_range_free(gpa, BAR_SIZE as u64);
        if !placement_ok {
            return;
        }
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
        // The doorbells stay registered (see `DoorbellState`); from now on
        // their pump treats a write there as one to an address this device
        // doesn't answer.
        if let Some(state) = self.doorbell_state.lock().unwrap().as_ref() {
            state.route.live.store(false, Ordering::Release);
        }
        let gpa = self.bar_gpa.load(Ordering::Relaxed);
        self.mmio_bus.unregister(gpa + OFF_COMMON);
        self.mmio_bus.unregister(gpa + OFF_ISR);
        self.mmio_bus.unregister(gpa + OFF_NOTIFY);
        self.mmio_bus.unregister(gpa + OFF_DEVICE);
        self.msix.uninstall(&self.mmio_bus);
    }

    /// Register a WHP doorbell on each queue's notify register and start the
    /// pump thread. Matching guest kicks then signal an event with no VM exit.
    ///
    /// Done once, where the BAR is first mapped. If the guest later maps it
    /// somewhere else, the registration stays where it is and kicks at the new
    /// address take the MMIO exit: following the BAR would mean unregistering
    /// (see `DoorbellState`), or registering without bound.
    fn install_doorbells(&self, gpa: u64) {
        let mut guard = self.doorbell_state.lock().unwrap();
        if let Some(state) = guard.as_ref() {
            state
                .route
                .live
                .store(state.route.gpa == gpa, Ordering::Release);
            return;
        }
        let qcount = self.device.queue_count();
        let stop_event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if stop_event.is_null() {
            return;
        }
        let mut doorbells = Vec::with_capacity(qcount as usize);
        let mut queues = Vec::with_capacity(qcount as usize);
        let mut handles: Vec<HANDLE> = Vec::with_capacity(qcount as usize + 1);
        handles.push(stop_event);
        for q in 0..qcount {
            let notify_gpa = gpa + OFF_NOTIFY + (q as u64) * (NOTIFY_MULT as u64);
            // The driver writes the 16-bit queue index to the notify register.
            // A queue whose doorbell can't be registered keeps the MMIO exit;
            // the ones registered so far are kept, never unregistered.
            if let Some(db) = Doorbell::new(self.part, notify_gpa, q as u64, 2) {
                handles.push(db.event());
                queues.push(q);
                doorbells.push(db);
            }
        }
        if doorbells.is_empty() {
            unsafe {
                CloseHandle(stop_event);
            }
            return;
        }
        let route = Arc::new(DoorbellRoute {
            gpa,
            live: AtomicBool::new(true),
            mmio_bus: self.mmio_bus.clone(),
        });
        let device = self.device.clone();
        let send = SendHandles(handles);
        let pump_route = route.clone();
        let pump = std::thread::Builder::new()
            .name(format!("{}-doorbell", self.name))
            .spawn(move || doorbell_pump(device, pump_route, send, queues))
            .ok();
        *guard = Some(DoorbellState {
            stop_event,
            doorbells,
            pump,
            route,
        });
    }

    /// Unregister the doorbells. Only as the transport drops: this can block
    /// forever (see `DoorbellState`), so VM teardown has freed guest RAM by
    /// then, and nothing the guest does while it runs gets here.
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

    /// Stop serving the guest, for VM teardown: join the doorbell pump and mark
    /// every queue not ready, so neither the pump nor a device path that checks
    /// a queue's readiness under its lock (console input, sound, input) touches
    /// guest RAM afterwards. The doorbells stay registered until the transport
    /// drops: unregistering one can block forever (see `whpsys::doorbell`), so
    /// teardown frees guest RAM first. Devices with work in flight on their own
    /// threads (blk, net, 9p) need their own quiesce as well.
    pub fn stop(&self) {
        self.stop_pump();
        for q in 0..self.device.queue_count() {
            self.device.disable_queue(q);
        }
    }

    /// Join the doorbell pump and leave the queues as they are. Call once the
    /// vCPUs have stopped: from then on nothing takes requests off this
    /// device's queues behind the caller's back, so a snapshot can capture
    /// them, and teardown isn't racing a drain. A kick the pump hadn't got to
    /// stays in the ring (see [`Self::sweep_queues`]).
    pub fn stop_pump(&self) {
        let pump = self.doorbell_state.lock().unwrap().as_mut().map(|s| {
            unsafe {
                SetEvent(s.stop_event);
            }
            s.pump.take()
        });
        if let Some(Some(h)) = pump {
            let _ = h.join();
        }
    }

    /// [`Self::stop_pump`], but no later than `deadline`: false if the pump
    /// is still serving a request then. A device may run a request on its
    /// pump (a lone disk read, a 9p request), which then takes as long as the
    /// host's disk or share does, and one that has stopped answering takes
    /// for ever. The pump is left as it is in that case, and so must
    /// everything it uses be: the caller can't go on tearing the VM down.
    pub fn stop_pump_by(&self, deadline: std::time::Instant) -> bool {
        let pump = self.doorbell_state.lock().unwrap().as_mut().map(|s| {
            unsafe {
                SetEvent(s.stop_event);
            }
            s.pump.take()
        });
        let Some(Some(h)) = pump else {
            return true;
        };
        while !h.is_finished() {
            if std::time::Instant::now() >= deadline {
                if let Some(s) = self.doorbell_state.lock().unwrap().as_mut() {
                    s.pump = Some(h);
                }
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let _ = h.join();
        true
    }

    /// Take whatever the driver left in each queue, on the calling thread, as
    /// a kick would. For a snapshot, after [`Self::stop_pump`]: a request the
    /// guest had already kicked for is then served before the capture rather
    /// than left in a ring whose doorbell the restored guest won't ring again.
    pub fn sweep_queues(&self) {
        for q in 0..self.device.queue_count() {
            self.device.notify_queue(q);
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
            } else {
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
            }
            // A write may have set a vector, or reset them all.
            self.sync_vectors(&c);
            return;
        }

        if sz == 8 && (off & 0x7) == 0 {
            let lo = self.guest_read_cc32(&c, off) as u64;
            let hi = self.guest_read_cc32(&c, off + 4) as u64;
            access.data = (lo | (hi << 32)).to_le_bytes();
            return;
        }
        let aligned = off & !0x3;
        let shift = (off & 0x3) * 8;
        let v = self.guest_read_cc32(&c, aligned) >> shift;
        access.data = [0; 8];
        let n = sz.min(4) as usize;
        access.data[..n].copy_from_slice(&v.to_le_bytes()[..n]);
    }

    /// A common-cfg dword as the driver reads it. Until the device has settled
    /// a reset, the status still reads as before it, so the driver keeps
    /// polling for 0 (`VirtioDevice::reset_pending`). Sub-dword writes merge
    /// into the true state (`read_cc32`) instead.
    fn guest_read_cc32(&self, c: &Common, off: u32) -> u32 {
        let v = self.read_cc32(c, off);
        if off == CC_DEVICE_STATUS && c.status == 0 && self.device.reset_pending() {
            (v & !0xFF) | c.reset_from as u32
        } else {
            v
        }
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
                    | ((self.config_generation.load(Ordering::Acquire) as u32) << 8)
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
                    // virtio requires a power-of-two queue size; the ring index
                    // and EVENT_IDX wrap math assume it. Reject anything else
                    // (size keeps its previous value; the driver re-reads it).
                    if qs <= max && qs.is_power_of_two() {
                        c.queues[sel].size = qs;
                    }
                    c.queues[sel].msix_vector = ((value >> 16) & 0xFFFF) as u16;
                }
            }
            CC_QUEUE_ENABLE => {
                let en = (value & 0xFFFF) as u16;
                let sel = c.queue_select as usize;
                if sel < c.queues.len() {
                    let q = c.queues[sel];
                    // A driver that never wrote queue_size keeps the size it
                    // read there: the device's maximum (spec §4.1.4.3).
                    let size = match q.size {
                        0 => self.device.queue_max(c.queue_select as u32) as u16,
                        n => n,
                    };
                    // Spec §2.7: desc 16-byte, avail 2-byte, used 4-byte aligned.
                    // The queue's atomic ring-index accesses (`AtomicU16::from_ptr`)
                    // require natural alignment; an odd guest GPA would be Rust UB
                    // (and a fault on non-x86). Refuse the enable instead.
                    let aligned = q.desc & 0xF == 0 && q.driver & 1 == 0 && q.device & 3 == 0;
                    if en != 0 && size != 0 && aligned {
                        let event_idx = c.driver_features & FEATURE_RING_EVENT_IDX != 0;
                        self.device.enable_queue(
                            c.queue_select as u32,
                            q.desc,
                            q.driver,
                            q.device,
                            size,
                            event_idx,
                        );
                        c.queues[sel].size = size;
                        c.queues[sel].enable = en;
                    } else if en == 0 {
                        self.device.disable_queue(c.queue_select as u32);
                        c.queues[sel].enable = 0;
                    }
                    // A refused enable changes nothing, so queue_enable keeps
                    // reading what is true of the queue.
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
            // The device may finish the reset later (`guest_read_cc32`).
            c.reset_from = c.status;
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
        if adding & STATUS_FEATURES_OK != 0 && !self.device.set_driver_features(c.driver_features) {
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

    /// Device-specific config, which devices serve a dword at most at a time:
    /// an 8-byte access (`mov rax, [bar+0x2000]`) is two dword accesses, as
    /// the transport does for common config.
    fn handle_device_cfg(&self, access: &mut MmioAccess) {
        let off = (access.gpa - (self.bar_gpa.load(Ordering::Relaxed) + OFF_DEVICE)) as u32;
        let size = access.access_size as usize;
        let dword = |d: &[u8; 8], at: usize| u32::from_le_bytes(d[at..at + 4].try_into().unwrap());
        if access.is_write {
            if size == 8 {
                self.device.write_config(off, 4, dword(&access.data, 0));
                self.device.write_config(off + 4, 4, dword(&access.data, 4));
                return;
            }
            let n = size.min(4);
            let mut buf = [0u8; 4];
            buf[..n].copy_from_slice(&access.data[..n]);
            self.device
                .write_config(off, n as u32, u32::from_le_bytes(buf));
            return;
        }
        if size == 8 {
            let lo = self.device.read_config(off, 4);
            let hi = self.device.read_config(off + 4, 4);
            access.data = ((lo as u64) | ((hi as u64) << 32)).to_le_bytes();
            return;
        }
        let n = size.min(4);
        let v = self.device.read_config(off, n as u32);
        access.data = [0; 8];
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

use crate::virtio::queue::{QUEUE_STATE_ENCODED, QueueState as VqState};

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
                self.config_generation.load(Ordering::Acquire),
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
            self.config_generation
                .store(snap.config_generation, Ordering::Release);
            c.queue_select = snap.queue_select;
            if snap.common_queues.len() == c.queues.len() {
                c.queues.copy_from_slice(&snap.common_queues);
            } else {
                c.queues = snap.common_queues.clone();
            }
            self.sync_vectors(&c);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A device whose reset leaves requests in flight until `pending` clears.
    #[derive(Default)]
    struct SlowReset {
        pending: AtomicBool,
        resets: AtomicU32,
    }

    impl VirtioDevice for SlowReset {
        fn device_id(&self) -> u32 {
            2
        }
        fn device_features(&self) -> u64 {
            0
        }
        fn set_driver_features(&self, _: u64) -> bool {
            true
        }
        fn queue_count(&self) -> u32 {
            1
        }
        fn queue_max(&self, _: u32) -> u32 {
            8
        }
        fn enable_queue(&self, _: u32, _: u64, _: u64, _: u64, _: u16, _: bool) {}
        fn disable_queue(&self, _: u32) {}
        fn notify_queue(&self, _: u32) {}
        fn driver_ok(&self) {}
        fn reset(&self) {
            self.resets.fetch_add(1, Ordering::Relaxed);
            self.pending.store(true, Ordering::Relaxed);
        }
        fn reset_pending(&self) -> bool {
            self.pending.load(Ordering::Relaxed)
        }
    }

    /// A common-cfg access at `off` (the BAR sits at GPA 0); returns what a
    /// read saw.
    fn common(t: &PciTransport, off: u32, size: u8, write: Option<u32>) -> u32 {
        let mut a = MmioAccess {
            gpa: off as u64,
            access_size: size,
            is_write: write.is_some(),
            data: [0; 8],
        };
        a.data[..4].copy_from_slice(&write.unwrap_or(0).to_le_bytes());
        t.handle_common_cfg(&mut a);
        u32::from_le_bytes(a.data[..4].try_into().unwrap())
    }

    #[test]
    fn status_reads_nonzero_until_the_device_settles_a_reset() {
        let dev = Arc::new(SlowReset::default());
        let opts = Options {
            vendor_id: 0x1AF4,
            sub_vendor_id: 0x1AF4,
            sub_id: 0,
            num_msix_vectors: 2,
            pci_class: 0x01,
            pci_subclass: 0,
            doorbells: false,
        };
        let mmio = Arc::new(MmioBus::new());
        let t = PciTransport::new("test", dev.clone(), opts, mmio, 0);
        common(&t, CC_DEVICE_STATUS, 1, Some(0x0F));
        common(&t, CC_DEVICE_STATUS, 1, Some(0));
        assert_eq!(dev.resets.load(Ordering::Relaxed), 1);
        assert_eq!(common(&t, CC_DEVICE_STATUS, 1, None), 0x0F);
        // A queue_select write merges into the real status (0), not the 0x0F
        // reported meanwhile.
        common(&t, CC_DEVICE_STATUS + 2, 2, Some(0));
        dev.pending.store(false, Ordering::Relaxed);
        assert_eq!(common(&t, CC_DEVICE_STATUS, 1, None), 0);
        assert_eq!(dev.resets.load(Ordering::Relaxed), 1);
    }

    /// Records device-config accesses; config byte `i` reads as `0x10 + i`.
    #[derive(Default)]
    struct Cfg {
        writes: Mutex<Vec<(u32, u32, u32)>>,
    }

    impl VirtioDevice for Cfg {
        fn device_id(&self) -> u32 {
            1
        }
        fn device_features(&self) -> u64 {
            0
        }
        fn set_driver_features(&self, _: u64) -> bool {
            true
        }
        fn queue_count(&self) -> u32 {
            1
        }
        fn queue_max(&self, _: u32) -> u32 {
            8
        }
        fn enable_queue(&self, _: u32, _: u64, _: u64, _: u64, _: u16, _: bool) {}
        fn disable_queue(&self, _: u32) {}
        fn notify_queue(&self, _: u32) {}
        fn driver_ok(&self) {}
        fn reset(&self) {}
        fn read_config(&self, offset: u32, size: u32) -> u32 {
            assert!(size <= 4, "a {size}-byte config read reached the device");
            let b = |i: u32| if i < size { 0x10 + offset + i } else { 0 };
            u32::from_le_bytes([b(0) as u8, b(1) as u8, b(2) as u8, b(3) as u8])
        }
        fn write_config(&self, offset: u32, size: u32, value: u32) {
            assert!(size <= 4, "a {size}-byte config write reached the device");
            self.writes.lock().unwrap().push((offset, size, value));
        }
    }

    /// A guest can access device config 8 bytes at a time (`mov rax, [bar +
    /// 0x2000]`); devices serve at most a dword, so the transport splits it.
    /// Passing the size on made virtio-net slice past a 4-byte buffer and
    /// abort the VMM.
    #[test]
    fn eight_byte_device_config_accesses_are_two_dwords() {
        let dev = Arc::new(Cfg::default());
        let opts = Options {
            vendor_id: 0x1AF4,
            sub_vendor_id: 0x1AF4,
            sub_id: 0,
            num_msix_vectors: 2,
            pci_class: 0x02,
            pci_subclass: 0,
            doorbells: false,
        };
        let t = PciTransport::new("test", dev.clone(), opts, Arc::new(MmioBus::new()), 0);
        let mut a = MmioAccess {
            gpa: OFF_DEVICE + 2,
            access_size: 8,
            is_write: false,
            data: [0; 8],
        };
        t.handle_device_cfg(&mut a);
        assert_eq!(a.data, [0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19]);
        a.access_size = 2;
        t.handle_device_cfg(&mut a);
        assert_eq!(a.data, [0x12, 0x13, 0, 0, 0, 0, 0, 0]);
        a.is_write = true;
        a.access_size = 8;
        a.data = 0x8877_6655_4433_2211u64.to_le_bytes();
        t.handle_device_cfg(&mut a);
        assert_eq!(
            *dev.writes.lock().unwrap(),
            [(2, 4, 0x4433_2211), (6, 4, 0x8877_6655)]
        );
    }

    fn opts(num_msix_vectors: u16) -> Options {
        Options {
            vendor_id: 0x1AF4,
            sub_vendor_id: 0x1AF4,
            sub_id: 0,
            num_msix_vectors,
            pci_class: 0x02,
            pci_subclass: 0,
            doorbells: false,
        }
    }

    /// Program queue `q` (size 8) through the common config, as a driver does.
    fn program_queue(t: &PciTransport, q: u32, vector: u16, desc: u64, avail: u64, used: u64) {
        common(t, CC_DEVICE_STATUS + 2, 2, Some(q)); // queue_select
        common(t, CC_QUEUE_SIZE, 4, Some(8 | (vector as u32) << 16));
        common(t, CC_QUEUE_DESC, 4, Some(desc as u32));
        common(t, CC_QUEUE_DRIVER, 4, Some(avail as u32));
        common(t, CC_QUEUE_DEVICE, 4, Some(used as u32));
        common(t, CC_QUEUE_ENABLE, 2, Some(1));
    }

    /// Raising an interrupt takes no transport lock. It used to take
    /// `common`, which is held across `reset`, `enable_queue` and
    /// `disable_queue`: a device raising from under a lock those take
    /// deadlocked against a guest's status write.
    #[test]
    fn raising_an_interrupt_takes_no_transport_lock() {
        let dev = Arc::new(SlowReset::default());
        let t = PciTransport::new("test", dev, opts(2), Arc::new(MmioBus::new()), 0);
        let _held = t.common.lock().unwrap();
        t.raise_queue_interrupt(0);
        t.raise_config_change_interrupt();
    }

    /// The vectors the raise paths read follow what the driver programs, and
    /// a reset clears them.
    #[test]
    fn interrupt_vectors_follow_the_common_config() {
        let dev = Arc::new(SlowReset::default());
        let t = PciTransport::new("test", dev, opts(2), Arc::new(MmioBus::new()), 0);
        let vectors = |t: &PciTransport| {
            (
                t.config_vector.load(Ordering::Acquire),
                t.queue_vectors[0].load(Ordering::Acquire),
            )
        };
        assert_eq!(vectors(&t), (0xFFFF, 0xFFFF));
        common(&t, CC_DEVICE_STATUS, 1, Some(0x03));
        common(&t, CC_MSIX_CONFIG, 2, Some(1));
        program_queue(&t, 0, 0, 0x1000, 0x2000, 0x3000);
        assert_eq!(vectors(&t), (1, 0));
        common(&t, CC_DEVICE_STATUS, 1, Some(0));
        assert_eq!(vectors(&t), (0xFFFF, 0xFFFF));
    }

    /// virtio-net's TX drain holds its TX queue lock while a backend that
    /// answers inline (loopback, WinTun's ARP responder, gVisor's DHCP)
    /// delivers a frame and raises the RX interrupt; a device reset holds
    /// `common` and then takes the TX queue lock. With the raise taking
    /// `common` too, the two threads waited on each other for good. Wired as
    /// `main.rs` wires a NIC, with the two sides made to meet.
    #[test]
    fn a_tx_drain_and_a_device_reset_do_not_deadlock() {
        use crate::virtio::net::{LoopbackBackend, NET_RX_QUEUE, NET_TX_QUEUE, NetDevice};
        use crate::virtio::queue::VRING_DESC_F_WRITE;
        use crate::whp::GuestMemory;
        use std::sync::mpsc;
        use std::time::Duration;

        let mem = Arc::new(GuestMemory::new_host_only(1 << 20).unwrap());
        let dev = NetDevice::new(mem.clone(), [2, 0, 0, 0, 0, 1]);
        dev.set_backend(LoopbackBackend::new(&dev));
        let net_dev: Arc<dyn VirtioDevice> = dev.clone();
        let t = PciTransport::new("net", net_dev, opts(3), Arc::new(MmioBus::new()), 0);
        // When the drain raises the RX interrupt (TX queue lock held), let
        // the reset get as far as it can first.
        let (at_raise, reset_go) = mpsc::channel::<()>();
        let wt = Arc::downgrade(&t);
        dev.set_irq_callback(Box::new(move |q| {
            if q == NET_RX_QUEUE {
                let _ = at_raise.send(());
                std::thread::sleep(Duration::from_millis(200));
            }
            if let Some(t) = wt.upgrade() {
                t.raise_queue_interrupt(q);
            }
        }));

        // RX: eight writable 2 KiB buffers. TX: one 76-byte chain, a zeroed
        // virtio_net_hdr and a 64-byte frame.
        const RX: (u64, u64, u64) = (0x1000, 0x2000, 0x3000);
        const TX: (u64, u64, u64) = (0x4000, 0x5000, 0x6000);
        for i in 0..8u16 {
            let mut d = [0u8; 16];
            d[0..8].copy_from_slice(&(0x10000 + u64::from(i) * 2048).to_le_bytes());
            d[8..12].copy_from_slice(&2048u32.to_le_bytes());
            d[12..14].copy_from_slice(&VRING_DESC_F_WRITE.to_le_bytes());
            mem.write_at(RX.0 + 16 * u64::from(i), &d).unwrap();
            mem.write_at(RX.1 + 4 + 2 * u64::from(i), &i.to_le_bytes())
                .unwrap();
        }
        mem.write_at(RX.1 + 2, &8u16.to_le_bytes()).unwrap();
        let mut d = [0u8; 16];
        d[0..8].copy_from_slice(&0x20000u64.to_le_bytes());
        d[8..12].copy_from_slice(&76u32.to_le_bytes());
        mem.write_at(TX.0, &d).unwrap();
        mem.write_at(0x20000 + 12, &[0xAB; 64]).unwrap();
        mem.write_at(TX.1 + 2, &1u16.to_le_bytes()).unwrap();

        common(&t, CC_DEVICE_STATUS, 1, Some(0x03));
        program_queue(&t, NET_RX_QUEUE, 0xFFFF, RX.0, RX.1, RX.2);
        program_queue(&t, NET_TX_QUEUE, 0xFFFF, TX.0, TX.1, TX.2);

        let (done, finished) = mpsc::channel::<&'static str>();
        let pump = {
            let (dev, done) = (dev.clone(), done.clone());
            std::thread::spawn(move || {
                dev.notify_queue(NET_TX_QUEUE);
                let _ = done.send("the TX drain");
            })
        };
        let vcpu = {
            let t = t.clone();
            std::thread::spawn(move || {
                reset_go.recv().unwrap();
                common(&t, CC_DEVICE_STATUS, 1, Some(0));
                let _ = done.send("the reset");
            })
        };
        for _ in 0..2 {
            finished
                .recv_timeout(Duration::from_secs(20))
                .expect("the TX drain and the device reset are waiting on each other");
        }
        pump.join().unwrap();
        vcpu.join().unwrap();
        assert_eq!(mem.read_u16(RX.2 + 2), Some(1), "the frame came back");
    }

    /// A doorbell that fires while the BAR isn't where it was registered is
    /// the guest's write to that address, and goes to whatever is there now.
    #[test]
    fn a_stale_doorbell_is_a_write_on_the_bus() {
        let bus = Arc::new(MmioBus::new());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        assert!(bus.register(
            0xE000_1000,
            0x1000,
            "other-device-notify",
            Box::new(move |a| {
                let value = u16::from_le_bytes([a.data[0], a.data[1]]);
                log.lock()
                    .unwrap()
                    .push((a.gpa, a.access_size, a.is_write, value));
            }),
        ));
        let route = DoorbellRoute {
            gpa: 0xE000_0000,
            live: AtomicBool::new(false),
            mmio_bus: bus,
        };
        route.forward(0);
        route.forward(3);
        assert_eq!(
            *seen.lock().unwrap(),
            [(0xE000_1000, 2, true, 0), (0xE000_100C, 2, true, 3)]
        );
    }

    /// Records the queues the transport enables.
    #[derive(Default)]
    struct Enables(Mutex<Vec<(u32, u64, u16)>>);

    impl VirtioDevice for Enables {
        fn device_id(&self) -> u32 {
            4
        }
        fn device_features(&self) -> u64 {
            0
        }
        fn set_driver_features(&self, _: u64) -> bool {
            true
        }
        fn queue_count(&self) -> u32 {
            1
        }
        fn queue_max(&self, _: u32) -> u32 {
            8
        }
        fn enable_queue(&self, idx: u32, desc: u64, _: u64, _: u64, size: u16, _: bool) {
            self.0.lock().unwrap().push((idx, desc, size));
        }
        fn disable_queue(&self, _: u32) {}
        fn notify_queue(&self, _: u32) {}
        fn driver_ok(&self) {}
        fn reset(&self) {}
    }

    /// A driver that never writes queue_size gets the size it read there, the
    /// device's maximum; and an enable the transport refuses (a misaligned
    /// ring) doesn't read back as enabled.
    #[test]
    fn queue_enable_defaults_the_size_and_reports_refusals() {
        let dev = Arc::new(Enables::default());
        let t = PciTransport::new("test", dev.clone(), opts(2), Arc::new(MmioBus::new()), 0);
        let enabled = |t: &PciTransport| common(t, CC_QUEUE_ENABLE, 2, None) & 0xFFFF;
        assert_eq!(common(&t, CC_QUEUE_SIZE, 2, None), 8, "the maximum");

        // Misaligned descriptor table: refused.
        common(&t, CC_QUEUE_DESC, 4, Some(0x1001));
        common(&t, CC_QUEUE_ENABLE, 2, Some(1));
        assert_eq!(enabled(&t), 0);
        assert!(dev.0.lock().unwrap().is_empty());

        common(&t, CC_QUEUE_DESC, 4, Some(0x1000));
        common(&t, CC_QUEUE_ENABLE, 2, Some(1));
        assert_eq!(enabled(&t), 1);
        assert_eq!(*dev.0.lock().unwrap(), [(0, 0x1000, 8)]);
    }
}
