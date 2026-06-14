//! Software-emulated local APIC (x2APIC) for a single boot vCPU.
//!
//! # Why this exists
//!
//! tinyvmm normally lets WHP emulate the LAPIC (`LocalApicEmulationMode =
//! X2Apic`). That works on bare metal because WHP delivers interrupts using
//! hardware APIC virtualization (APICv / posted interrupts). Under *nested*
//! virtualization (this Windows host is itself a Hyper-V VM) the L1 hypervisor
//! does not expose APICv to WHP's L2 partition, so WHP can only deliver a
//! pending LAPIC interrupt at the *next* VM exit -- it cannot preempt a running
//! vCPU. A guest that goes idle waiting for a device completion (e.g. a
//! virtio-blk read) spins in `poll_idle`/halts with no further exits, and the
//! completion interrupt is never delivered: the guest hangs.
//!
//! The fix, mirroring OpenVMM's `user_mode_apic` path, is to turn WHP's LAPIC
//! off (`LocalApicEmulationMode = None`) and emulate it here. We then inject
//! interrupts ourselves via VM-entry event injection
//! (`WHvRegisterPendingInterruption`), which does not depend on APICv, and kick
//! the vCPU out of its run with `WHvCancelRunVirtualProcessor` so the injection
//! lands promptly. See `vcpu::try_inject_interrupt` and the run loop.
//!
//! # Scope
//!
//! Single vCPU (BSP only) in x2APIC mode: no IPIs to other processors, no
//! SIPI/AP startup. The guest accesses the APIC through MSRs (0x800-0x83F) plus
//! `IA32_APIC_BASE` (0x1B), all of which trap to [`read_msr`]/[`write_msr`].
//! TSC-deadline mode is hidden from CPUID, so only the count-based timer is
//! emulated.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::Duration;
use windows_sys::Win32::System::Hypervisor::{WHV_PARTITION_HANDLE, WHvCancelRunVirtualProcessor};

// --- x2APIC MSR indices (MSR = 0x800 + (xAPIC register offset >> 4)) ---------
const MSR_APIC_BASE: u32 = 0x1B;
const X2_BASE: u32 = 0x800;
const X2_END: u32 = 0x83F;
const X2_ID: u32 = 0x800;
const X2_VERSION: u32 = 0x801;
const X2_TPR: u32 = 0x808;
const X2_PPR: u32 = 0x80A;
const X2_EOI: u32 = 0x80B;
const X2_LDR: u32 = 0x80D;
const X2_SVR: u32 = 0x80F;
const X2_ISR0: u32 = 0x810;
const X2_TMR0: u32 = 0x818;
const X2_IRR0: u32 = 0x820;
const X2_ESR: u32 = 0x828;
const X2_LVT_CMCI: u32 = 0x82F;
const X2_ICR: u32 = 0x830;
const X2_LVT_TIMER: u32 = 0x832;
const X2_LVT_THERMAL: u32 = 0x833;
const X2_LVT_PMC: u32 = 0x834;
const X2_LVT_LINT0: u32 = 0x835;
const X2_LVT_LINT1: u32 = 0x836;
const X2_LVT_ERROR: u32 = 0x837;
const X2_TIMER_ICT: u32 = 0x838; // initial count
const X2_TIMER_CCT: u32 = 0x839; // current count
const X2_TIMER_DCR: u32 = 0x83E; // divide configuration
const X2_SELF_IPI: u32 = 0x83F;

const LVT_MASKED: u32 = 1 << 16;
const LVT_TIMER_PERIODIC: u32 = 1 << 17;
const SVR_ENABLE: u32 = 1 << 8;

/// Reset value for an LVT entry: masked.
const LVT_RESET: u32 = LVT_MASKED;

struct Inner {
    /// `IA32_APIC_BASE` (0x1B). Holds the BSP/global-enable/x2apic-enable bits.
    apic_base: u64,
    /// Spurious-interrupt vector register; bit 8 is the software enable.
    svr: u32,
    /// 256-bit in-service / interrupt-request bitmaps, 8 x u32 each.
    isr: [u32; 8],
    irr: [u32; 8],
    esr: u32,
    // Local vector table entries (stored; only the timer fires for a single vCPU).
    lvt_timer: u32,
    lvt_thermal: u32,
    lvt_pmc: u32,
    lvt_lint0: u32,
    lvt_lint1: u32,
    lvt_error: u32,
    lvt_cmci: u32,
    // Count-based timer.
    divide_cfg: u32,
    initial_count: u32,
    /// Host TSC at which the current count started.
    timer_start_tsc: u64,
    /// Host TSC at which the timer next fires; 0 means disarmed.
    timer_deadline_tsc: u64,
    stop: bool,
}

impl Inner {
    fn new() -> Self {
        Inner {
            // x2APIC is pre-enabled (bit 10): this LAPIC only services the
            // x2APIC MSR range, so the guest MUST come up in x2APIC mode.
            // Linux's `check_x2apic()` reads IA32_APIC_BASE early — without
            // bit 10 set (and no interrupt-remapping unit) it stays in xAPIC,
            // sends every LAPIC access to MMIO 0xFEE00000 (which we don't
            // handle), and the timer is never armed → jiffies freeze → first
            // `msleep()` parks the guest forever.
            apic_base: 0xFEE0_0000 | (1 << 8) /*BSP*/ | (1 << 10) /*x2APIC*/ | (1 << 11), /*EN*/
            svr: 0xFF, // vector 0xFF, software-disabled until the guest sets bit 8
            isr: [0; 8],
            irr: [0; 8],
            esr: 0,
            lvt_timer: LVT_RESET,
            lvt_thermal: LVT_RESET,
            lvt_pmc: LVT_RESET,
            lvt_lint0: LVT_RESET,
            lvt_lint1: LVT_RESET,
            lvt_error: LVT_RESET,
            lvt_cmci: LVT_RESET,
            divide_cfg: 0,
            initial_count: 0,
            timer_start_tsc: 0,
            timer_deadline_tsc: 0,
            stop: false,
        }
    }

    fn enabled(&self) -> bool {
        self.svr & SVR_ENABLE != 0
    }

    fn set_irr(&mut self, vector: u8) {
        self.irr[(vector >> 5) as usize] |= 1 << (vector & 31);
    }

    /// Highest set bit in a 256-bit bitmap, or `None`.
    fn top(bitmap: &[u32; 8]) -> Option<u8> {
        for w in (0..8).rev() {
            if bitmap[w] != 0 {
                return Some(((w as u32) << 5 | (31 - bitmap[w].leading_zeros())) as u8);
            }
        }
        None
    }
}

/// Divide-configuration register value -> TSC ticks per APIC timer count.
/// The APIC bus frequency is defined as the host TSC frequency, so one count is
/// exactly `divisor` host-TSC ticks; the guest calibrates against this and the
/// scaling cancels out (see module docs / the timer thread).
fn divisor(dcr: u32) -> u64 {
    // The divisor field is bits [1:0] and bit [3] (bit 2 reserved).
    let sel = (dcr & 0b11) | ((dcr & 0b1000) >> 1);
    match sel {
        0 => 2,
        1 => 4,
        2 => 8,
        3 => 16,
        4 => 32,
        5 => 64,
        6 => 128,
        _ => 1,
    }
}

pub struct LocalApic {
    inner: Mutex<Inner>,
    timer_cv: Condvar,
    /// Signalled when a vector is queued (or shutdown is requested) to wake a
    /// run loop parked on a halted guest. See [`LocalApic::park_while_idle`].
    wake_cv: Condvar,
    /// Target (partition, vp) for the wake kick; `(0, 0)` until bound.
    target: Mutex<(WHV_PARTITION_HANDLE, u32)>,
    tsc_hz: Mutex<u64>,
    thread_started: AtomicBool,
}

static LAPIC: OnceLock<LocalApic> = OnceLock::new();

/// Whether the software LAPIC is driving interrupt delivery (set by [`init`]).
/// When false, WHP's hardware LAPIC is in charge and MSIs go through
/// `WHvRequestInterrupt` instead -- the efficient path on bare metal, where
/// APIC virtualization is available. Only nested guests need the emulation.
static ACTIVE: AtomicBool = AtomicBool::new(false);

/// True when the software LAPIC owns interrupt delivery (nested guests).
pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

/// The process-wide software LAPIC for the (single) boot vCPU.
pub fn global() -> &'static LocalApic {
    LAPIC.get_or_init(|| LocalApic {
        inner: Mutex::new(Inner::new()),
        timer_cv: Condvar::new(),
        wake_cv: Condvar::new(),
        target: Mutex::new((0, 0)),
        tsc_hz: Mutex::new(0),
        thread_started: AtomicBool::new(false),
    })
}

/// Bind the LAPIC to a partition/vCPU, reset its state, and start its timer
/// thread. Idempotent: a second call (e.g. a fresh guest in the same process)
/// resets and rebinds. `tsc_hz` is the host TSC frequency, used to convert
/// APIC-timer counts to wall-clock deadlines.
pub fn init(part: WHV_PARTITION_HANDLE, vp_index: u32, tsc_hz: u64) {
    let a = global();
    ACTIVE.store(true, Ordering::Relaxed);
    *a.target.lock().unwrap() = (part, vp_index);
    *a.tsc_hz.lock().unwrap() = tsc_hz;
    {
        let mut g = a.inner.lock().unwrap();
        *g = Inner::new();
    }
    a.timer_cv.notify_all();
    if !a.thread_started.swap(true, Ordering::SeqCst) {
        std::thread::Builder::new()
            .name("lapic-timer".into())
            .spawn(move || a.timer_loop())
            .expect("spawn lapic-timer");
    }
}

fn rdtsc() -> u64 {
    // SAFETY: RDTSC is always available on x86-64 and has no preconditions.
    unsafe { core::arch::x86_64::_rdtsc() }
}

impl LocalApic {
    /// Kick the bound vCPU out of `WHvRunVirtualProcessor` so the run loop
    /// re-enters and injects a freshly-queued vector promptly (rather than
    /// waiting for the guest's next natural exit).
    fn kick(&self) {
        let (part, vp) = *self.target.lock().unwrap();
        if part != 0 {
            // SAFETY: `part` is a live partition handle; cancelling the vCPU run
            // from another thread is the documented WHP wake mechanism.
            unsafe { WHvCancelRunVirtualProcessor(part, vp, 0) };
        }
    }

    /// Queue `vector` for delivery (sets its IRR bit) and wake the vCPU so the
    /// run loop injects it: notify a run loop parked on a halted guest, and kick
    /// one currently inside `WHvRunVirtualProcessor`. Called from device MSI
    /// delivery and the timer thread.
    pub fn request_interrupt(&self, vector: u8) {
        {
            let mut g = self.inner.lock().unwrap();
            g.set_irr(vector);
        }
        // Wake a parked run loop. Safe against lost wakeups: `set_irr` ran under
        // `inner`, and `park_while_idle` re-checks the IRR under `inner` after a
        // notify, so a parker either already saw the bit or will be notified.
        self.wake_cv.notify_all();
        self.kick();
    }

    /// Block the calling run loop while the guest is idle: wait until a vector is
    /// queued in the IRR, shutdown is requested (`stop`), or `timeout` elapses,
    /// instead of spinning on `WHvRunVirtualProcessor`. This is the nested
    /// counterpart to WHP's hardware HLT wait. `timeout` bounds any missed
    /// wakeup (the timer/device path normally wakes us in microseconds).
    pub fn park_while_idle(&self, stop: &AtomicBool, timeout: Duration) {
        let g = self.inner.lock().unwrap();
        let _ = self.wake_cv.wait_timeout_while(g, timeout, |inner| {
            inner.irr.iter().all(|&w| w == 0) && !stop.load(Ordering::Acquire)
        });
    }

    /// Wake a parked run loop without queuing an interrupt (used on shutdown).
    pub fn wake(&self) {
        let _g = self.inner.lock().unwrap();
        self.wake_cv.notify_all();
    }

    /// Fast IRR-non-empty check so the run loop can skip the per-exit
    /// `WHvGetVirtualProcessorRegisters(CR8)` syscall when nothing is pending.
    pub fn irr_nonempty(&self) -> bool {
        let g = self.inner.lock().unwrap();
        g.enabled() && g.irr.iter().any(|&w| w != 0)
    }

    /// Highest-priority deliverable vector given the live TPR class `cr8`
    /// (CR8 = TPR[7:4]). Pure peek -- does not change APIC state. Returns `None`
    /// if the APIC is software-disabled, nothing is pending, or the pending
    /// vector's priority does not exceed the processor priority (PPR).
    pub fn next_vector(&self, cr8: u32) -> Option<u8> {
        let g = self.inner.lock().unwrap();
        if !g.enabled() {
            return None;
        }
        let irr_top = Inner::top(&g.irr)?;
        let isr_top = Inner::top(&g.isr).map(|v| v >> 4).unwrap_or(0) as u32;
        let ppr = cr8.max(isr_top);
        if (irr_top >> 4) as u32 > ppr {
            Some(irr_top)
        } else {
            None
        }
    }

    /// Accept `vector` into service: clear it from the IRR and set it in the
    /// ISR. Call after the vector has actually been injected at VM entry.
    pub fn take_vector(&self, vector: u8) {
        let mut g = self.inner.lock().unwrap();
        g.irr[(vector >> 5) as usize] &= !(1 << (vector & 31));
        g.isr[(vector >> 5) as usize] |= 1 << (vector & 31);
    }

    /// End-of-interrupt: clear the highest in-service vector.
    fn eoi(&self, g: &mut Inner) {
        if let Some(v) = Inner::top(&g.isr) {
            g.isr[(v >> 5) as usize] &= !(1 << (v & 31));
        }
    }

    /// Processor priority register value (PPR), TPR class taken from `cr8`.
    fn ppr(&self, cr8: u32) -> u32 {
        let g = self.inner.lock().unwrap();
        let isr_top = Inner::top(&g.isr).map(|v| v >> 4).unwrap_or(0) as u32;
        (cr8.max(isr_top)) << 4
    }

    /// Handle an RDMSR of an APIC register. Returns `true` if `msr` belongs to
    /// the APIC (and `*out` was set), `false` to let other handlers run.
    pub fn read_msr(&self, msr: u32, cr8: u32, out: &mut u64) -> bool {
        if msr == MSR_APIC_BASE {
            *out = self.inner.lock().unwrap().apic_base;
            return true;
        }
        if !(X2_BASE..=X2_END).contains(&msr) {
            return false;
        }
        if msr == X2_PPR {
            *out = self.ppr(cr8) as u64;
            return true;
        }
        let g = self.inner.lock().unwrap();
        let v: u32 = match msr {
            X2_ID => 0,                // x2APIC ID of the BSP
            X2_VERSION => 0x0005_0014, // version 0x14, max LVT entry = 5
            X2_TPR => cr8 << 4,
            X2_LDR => 1, // x2APIC LDR for ID 0: (0<<16)|(1<<0)
            X2_SVR => g.svr,
            X2_ESR => g.esr,
            X2_ISR0..=0x817 => g.isr[(msr - X2_ISR0) as usize],
            X2_TMR0..=0x81F => 0, // all interrupts are edge-triggered (MSI)
            X2_IRR0..=0x827 => g.irr[(msr - X2_IRR0) as usize],
            X2_LVT_CMCI => g.lvt_cmci,
            X2_LVT_TIMER => g.lvt_timer,
            X2_LVT_THERMAL => g.lvt_thermal,
            X2_LVT_PMC => g.lvt_pmc,
            X2_LVT_LINT0 => g.lvt_lint0,
            X2_LVT_LINT1 => g.lvt_lint1,
            X2_LVT_ERROR => g.lvt_error,
            X2_TIMER_ICT => g.initial_count,
            X2_TIMER_CCT => current_count(&g),
            X2_TIMER_DCR => g.divide_cfg,
            _ => 0,
        };
        *out = v as u64;
        true
    }

    /// Handle a WRMSR of an APIC register. Returns `true` if handled. `set_cr8`
    /// is set to `Some(tpr_class)` when the guest wrote the TPR via MSR and CR8
    /// must be synced by the caller.
    pub fn write_msr(&self, msr: u32, val: u64, set_cr8: &mut Option<u32>) -> bool {
        if msr == MSR_APIC_BASE {
            self.inner.lock().unwrap().apic_base = val;
            return true;
        }
        if !(X2_BASE..=X2_END).contains(&msr) {
            return false;
        }
        let lo = val as u32;
        let mut kick = false;
        {
            let mut g = self.inner.lock().unwrap();
            match msr {
                X2_TPR => *set_cr8 = Some((lo >> 4) & 0xF),
                X2_EOI => self.eoi(&mut g),
                X2_SVR => g.svr = lo,
                X2_ESR => g.esr = 0,
                X2_LVT_CMCI => g.lvt_cmci = lo,
                X2_LVT_TIMER => g.lvt_timer = lo,
                X2_LVT_THERMAL => g.lvt_thermal = lo,
                X2_LVT_PMC => g.lvt_pmc = lo,
                X2_LVT_LINT0 => g.lvt_lint0 = lo,
                X2_LVT_LINT1 => g.lvt_lint1 = lo,
                X2_LVT_ERROR => g.lvt_error = lo,
                X2_TIMER_DCR => g.divide_cfg = lo,
                X2_TIMER_ICT => {
                    arm_timer(&mut g, lo);
                    kick = true; // wake the timer thread to honor the new deadline
                }
                X2_ICR => {
                    // Single vCPU: only a self-directed fixed IPI matters.
                    // Shorthand bits [19:18]: 1 = self, 2 = all-incl-self.
                    let shorthand = (val >> 18) & 0x3;
                    let deliv = (val >> 8) & 0x7;
                    if (shorthand == 1 || shorthand == 2) && deliv == 0 {
                        let v = lo as u8;
                        g.set_irr(v);
                        kick = true;
                    }
                }
                X2_SELF_IPI => {
                    g.set_irr(lo as u8);
                    kick = true;
                }
                _ => {}
            }
        }
        if kick {
            self.timer_cv.notify_all();
        }
        true
    }

    fn timer_loop(&'static self) {
        let tsc_hz = (*self.tsc_hz.lock().unwrap()).max(1);
        loop {
            let mut fire_vec: Option<u8> = None;
            {
                let mut g = self.inner.lock().unwrap();
                loop {
                    if g.stop {
                        return;
                    }
                    let now = rdtsc();
                    if g.timer_deadline_tsc != 0 && now >= g.timer_deadline_tsc {
                        let masked = g.lvt_timer & LVT_MASKED != 0;
                        let periodic = g.lvt_timer & LVT_TIMER_PERIODIC != 0;
                        if !masked && g.enabled() {
                            fire_vec = Some((g.lvt_timer & 0xFF) as u8);
                        }
                        if periodic && g.initial_count != 0 {
                            let period = g.initial_count as u64 * divisor(g.divide_cfg);
                            g.timer_deadline_tsc = g.timer_deadline_tsc.wrapping_add(period.max(1));
                            g.timer_start_tsc = now;
                        } else {
                            g.timer_deadline_tsc = 0;
                        }
                        break;
                    }
                    // Sleep until the deadline (or indefinitely if disarmed). A
                    // re-arm notifies `timer_cv`, waking us early to recompute
                    // against the new deadline.
                    if g.timer_deadline_tsc == 0 {
                        g = self.timer_cv.wait(g).unwrap();
                    } else {
                        let ticks = g.timer_deadline_tsc - now;
                        let nanos = (ticks as u128 * 1_000_000_000u128 / tsc_hz as u128)
                            .min(60_000_000_000u128) as u64;
                        let (ng, _) = self
                            .timer_cv
                            .wait_timeout(g, Duration::from_nanos(nanos))
                            .unwrap();
                        g = ng;
                    }
                }
            }
            if let Some(v) = fire_vec {
                self.request_interrupt(v);
            }
        }
    }
}

/// Arm or disarm the count-based timer from an initial-count write.
fn arm_timer(g: &mut Inner, initial: u32) {
    g.initial_count = initial;
    if initial == 0 {
        g.timer_deadline_tsc = 0;
        return;
    }
    let now = rdtsc();
    g.timer_start_tsc = now;
    g.timer_deadline_tsc = now + initial as u64 * divisor(g.divide_cfg);
}

/// Current-count register value, computed from elapsed host TSC.
fn current_count(g: &Inner) -> u32 {
    if g.timer_deadline_tsc == 0 || g.initial_count == 0 {
        return 0;
    }
    let now = rdtsc();
    if now >= g.timer_deadline_tsc {
        return 0;
    }
    let remaining_ticks = g.timer_deadline_tsc - now;
    (remaining_ticks / divisor(g.divide_cfg)) as u32
}
