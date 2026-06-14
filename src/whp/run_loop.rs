//! Drives a single vCPU's exit loop. Routes IO/MMIO accesses through the IO and
//! MMIO buses via the WHP emulator (`whpsys::emulator`), and handles CPUID/MSR/
//! HLT exits. Port of src/whp/run_loop.cpp.

use crate::devices::io_bus::{IoAccess, IoBus};
use crate::devices::mmio_bus::{MmioAccess, MmioBus};
use crate::whp::cpuid::{CpuidContext, resolve_cpuid};
use crate::whp::emulator::{EmuError, Emulator, EmulatorBus};
use crate::whp::hv::{HvEnlightenment, MsrHandled};
use crate::whp::regs::reg64;
use crate::whp::vcpu::{Exit, ExitReason, Vcpu, exit_reason_name};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use windows_sys::Win32::System::Hypervisor::{
    WHvRegisterPendingInterruption, WHvX64RegisterCr8, WHvX64RegisterRax, WHvX64RegisterRbx,
    WHvX64RegisterRcx, WHvX64RegisterRdx, WHvX64RegisterRip,
};

const RFLAGS_IF: u64 = 1 << 9;

/// Safety-net cap on how long a halted guest parks waiting for an interrupt.
/// The timer/device path normally wakes it in microseconds; this only bounds a
/// missed wakeup and keeps shutdown responsive.
const HALT_PARK: std::time::Duration = std::time::Duration::from_millis(50);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    GuestHalted,
    Cancelled,
    UnhandledExit,
    EmulationFailure,
    SnapshotRequested,
}

#[derive(Default)]
pub struct Counters {
    pub io: AtomicU64,
    pub mmio: AtomicU64,
    pub halt: AtomicU64,
    pub cpuid: AtomicU64,
    pub msr: AtomicU64,
    pub other: AtomicU64,
}

/// Bridges the WHP emulator's neutral IO/MMIO accesses to the device buses.
/// Built per `run()` call; borrowed by the emulator during each `try_*`.
struct RunBus<'a> {
    io_bus: &'a IoBus,
    mmio_bus: &'a MmioBus,
    verbose_io: bool,
}

impl EmulatorBus for RunBus<'_> {
    fn io(&self, acc: &mut crate::whp::emulator::IoAccess) {
        let mut a = IoAccess {
            port: acc.port,
            access_size: acc.access_size,
            is_write: acc.is_write,
            value: acc.value,
        };
        let claimed = self.io_bus.dispatch(&mut a);
        if self.verbose_io {
            eprintln!(
                "[loop] io {} port=0x{:04x} size={} value=0x{:08x} {}",
                if a.is_write { "OUT" } else { "IN " },
                a.port,
                a.access_size,
                a.value,
                if claimed { "(claimed)" } else { "(unclaimed)" }
            );
        }
        if !a.is_write {
            acc.value = a.value;
        }
    }

    fn mmio(&self, acc: &mut crate::whp::emulator::MmioAccess) {
        let mut a = MmioAccess {
            gpa: acc.gpa,
            access_size: acc.access_size,
            is_write: acc.is_write,
            data: acc.data,
        };
        self.mmio_bus.dispatch(&mut a);
        if !a.is_write {
            acc.data = a.data;
        }
    }
}

pub struct RunLoop {
    vcpu: Arc<Vcpu>,
    io_bus: Arc<IoBus>,
    mmio_bus: Arc<MmioBus>,
    emulator: Emulator,
    vcpu_count: u32,
    hv: Option<Arc<HvEnlightenment>>,
    stop: Arc<AtomicBool>,
    counters: Arc<Counters>,
    verbose_io: bool,
}

// `RunLoop` AUTO-derives Send: the only non-trivial field is the `Emulator`
// (which is itself Send via its audited SharedPtr handle); everything else is
// Arc/scalar, compiler-checked.

impl RunLoop {
    pub fn new(
        vcpu: Arc<Vcpu>,
        io_bus: Arc<IoBus>,
        mmio_bus: Arc<MmioBus>,
        vcpu_count: u32,
    ) -> crate::error::Result<Self> {
        let emulator = Emulator::new()?;
        Ok(RunLoop {
            vcpu,
            io_bus,
            mmio_bus,
            emulator,
            vcpu_count: vcpu_count.max(1),
            hv: None,
            stop: Arc::new(AtomicBool::new(false)),
            counters: Arc::new(Counters::default()),
            verbose_io: false,
        })
    }

    pub fn set_hv(&mut self, hv: Arc<HvEnlightenment>) {
        self.hv = Some(hv);
    }
    pub fn set_verbose_io(&mut self, v: bool) {
        self.verbose_io = v;
    }
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        self.stop.clone()
    }
    pub fn counters(&self) -> Arc<Counters> {
        self.counters.clone()
    }
    pub fn vcpu(&self) -> Arc<Vcpu> {
        self.vcpu.clone()
    }

    /// May be called from any thread: set the stop flag and poke the vCPU out
    /// of `WHvRunVirtualProcessor`.
    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Release);
        let _ = self.vcpu.cancel();
        // Also wake the loop if it's parked on a halted guest (not in `run`).
        whpsys::lapic::global().wake();
    }

    pub fn run(&self) -> StopReason {
        let bus = RunBus {
            io_bus: &self.io_bus,
            mmio_bus: &self.mmio_bus,
            verbose_io: self.verbose_io,
        };
        let part = self.vcpu.part();
        let vp = self.vcpu.index();

        loop {
            if self.stop.load(Ordering::Acquire) {
                return StopReason::Cancelled;
            }

            // Deliver any interrupt the software LAPIC has queued before
            // re-entering the guest. Done on every iteration -- including those
            // reached via `continue` (e.g. the HLT path) and after an
            // interrupt-window exit -- so a queued vector is never stranded.
            self.deliver_interrupts();

            let exit = match self.vcpu.run_exit() {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("[loop] WHvRunVirtualProcessor failed: {e}");
                    return StopReason::EmulationFailure;
                }
            };

            if crate::diag::etw::enabled(crate::diag::etw::VERBOSE, crate::diag::etw::kw::VMEXIT) {
                crate::diag::etw::Event::new(
                    "VmExit",
                    crate::diag::etw::VERBOSE,
                    crate::diag::etw::kw::VMEXIT,
                )
                .u32("reason", exit.raw_reason())
                .u32("vp", vp)
                .hex64("rip", exit.rip())
                .write();
            }

            match exit.reason() {
                ExitReason::Halt => {
                    self.counters.halt.fetch_add(1, Ordering::Relaxed);
                    if (exit.rflags() & RFLAGS_IF) != 0 {
                        // Idle guest with interrupts enabled. When the software
                        // LAPIC is driving, WHP doesn't know about our pending
                        // interrupts, so re-running would just busy-cycle through
                        // HLT exits. Instead park the thread until a device/timer
                        // queues a vector (à la OpenVMM's poll-when-halted), then
                        // loop so `deliver_interrupts` injects it. With WHP's
                        // hardware LAPIC, WHP itself waits on HLT, so just re-run.
                        if whpsys::lapic::active() {
                            whpsys::lapic::global().park_while_idle(&self.stop, HALT_PARK);
                        }
                        continue;
                    }
                    println!(
                        "[loop] HLT at RIP=0x{:x} (IF=0) -- treating as terminal",
                        exit.rip()
                    );
                    return StopReason::GuestHalted;
                }
                ExitReason::IoPort => {
                    self.counters.io.fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = self.emulator.try_io(&exit, part, vp, &bus) {
                        Self::report_emu_err("IoEmulation", e, exit.rip());
                        return StopReason::EmulationFailure;
                    }
                }
                ExitReason::Memory => {
                    self.counters.mmio.fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = self.emulator.try_mmio(&exit, part, vp, &bus) {
                        Self::report_emu_err("MmioEmulation", e, exit.rip());
                        return StopReason::EmulationFailure;
                    }
                }
                ExitReason::Cpuid => {
                    self.counters.cpuid.fetch_add(1, Ordering::Relaxed);
                    if let Some(stop) = self.handle_cpuid(&exit) {
                        return stop;
                    }
                }
                ExitReason::Msr => {
                    self.counters.msr.fetch_add(1, Ordering::Relaxed);
                    if let Some(stop) = self.handle_msr(&exit) {
                        return stop;
                    }
                }
                // EOI now arrives as an x2APIC MSR write (LAPIC = None), handled
                // in the software LAPIC; WHP's EOI-exit no longer fires. The
                // interrupt-window and cancel exits just re-run the delivery pass
                // at the top of the loop.
                ExitReason::ApicEoi | ExitReason::InterruptWindow | ExitReason::Canceled => {}
                ExitReason::Other(other) => {
                    self.counters.other.fetch_add(1, Ordering::Relaxed);
                    eprintln!(
                        "[loop] unhandled exit reason {} (0x{:x}) at RIP=0x{:x}",
                        exit_reason_name(other),
                        other,
                        exit.rip()
                    );
                    return StopReason::UnhandledExit;
                }
            }
        }
    }

    /// Log an emulator failure with the same wording the C++ loop used.
    fn report_emu_err(which: &str, e: EmuError, rip: u64) {
        match e {
            EmuError::Hresult(hr) => {
                eprintln!("[loop] WHvEmulatorTry{which} HRESULT=0x{:08X}", hr as u32)
            }
            EmuError::Incomplete(s) => eprintln!(
                "[loop] {} emulation failed (status=0x{:08x}) at RIP=0x{:x}",
                if which == "IoEmulation" { "IO" } else { "MMIO" },
                s,
                rip
            ),
        }
    }

    fn handle_cpuid(&self, exit: &Exit) -> Option<StopReason> {
        let c = exit.cpuid();
        let leaf = c.leaf;
        let subleaf = c.subleaf;
        let next_rip = exit.rip() + exit.instruction_length() as u64;

        // Snapshot-trigger magic leaf: always return the signature (so the guest
        // can detect support); if armed (`--save`), record the request and stop.
        // RIP is advanced first so the guest resumes past the CPUID on restore.
        if leaf == crate::whp::snapshot::MAGIC_LEAF {
            use crate::whp::snapshot as snap;
            let names = [
                WHvX64RegisterRax,
                WHvX64RegisterRbx,
                WHvX64RegisterRcx,
                WHvX64RegisterRdx,
                WHvX64RegisterRip,
            ];
            let vals = [
                reg64(snap::SIG_EAX as u64),
                reg64(snap::SIG_EBX as u64),
                reg64(snap::SIG_ECX as u64),
                reg64(snap::SIG_EDX as u64),
                reg64(next_rip),
            ];
            if let Err(e) = self.vcpu.set_registers(&names, &vals) {
                eprintln!("[loop] snapshot-leaf set-regs failed: {e}");
                return Some(StopReason::EmulationFailure);
            }
            if snap::on_magic_leaf(self.vcpu.index()) {
                println!("[snapshot] trigger fired from vp={}", self.vcpu.index());
                return Some(StopReason::SnapshotRequested);
            }
            return None;
        }

        let ctx = CpuidContext {
            vcpu_index: self.vcpu.index(),
            vcpu_count: self.vcpu_count,
        };
        let r = resolve_cpuid(
            leaf,
            subleaf,
            c.default_eax,
            c.default_ebx,
            c.default_ecx,
            c.default_edx,
            &ctx,
        );
        let names = [
            WHvX64RegisterRax,
            WHvX64RegisterRbx,
            WHvX64RegisterRcx,
            WHvX64RegisterRdx,
            WHvX64RegisterRip,
        ];
        let vals = [
            reg64(r.eax as u64),
            reg64(r.ebx as u64),
            reg64(r.ecx as u64),
            reg64(r.edx as u64),
            reg64(next_rip),
        ];
        if let Err(e) = self.vcpu.set_registers(&names, &vals) {
            eprintln!("[loop] CPUID set-regs failed: {e}");
            return Some(StopReason::EmulationFailure);
        }
        None
    }

    /// Inject the highest-priority interrupt the software LAPIC has queued, if
    /// the guest can accept it now. Called before every guest re-entry. No-op on
    /// bare metal, where WHP's hardware LAPIC delivers interrupts itself.
    fn deliver_interrupts(&self) {
        if !whpsys::lapic::active() {
            return;
        }
        // Skip the per-exit `WHvGetVirtualProcessorRegisters(CR8)` syscall when
        // nothing is pending (the common case): a Mutex + 8-word OR is ~50 ns
        // vs ~2 µs for the WHP register read under nested virt. At ~17 K exits/s
        // (net RX flood) this is the difference between ~3.5 % and ~0 % CPU.
        let lapic = whpsys::lapic::global();
        if !lapic.irr_nonempty() {
            return;
        }
        // Live TPR class (CR8 = TPR[7:4]); the software LAPIC owns the priority
        // decision, we just feed it the current processor priority.
        let cr8 = self
            .vcpu
            .get_register(WHvX64RegisterCr8)
            .map(|v| (unsafe { v.Reg64 } & 0xF) as u32)
            .unwrap_or(0);
        let Some(vector) = lapic.next_vector(cr8) else {
            return;
        };
        match self.vcpu.try_inject_interrupt(vector) {
            // Accepted into service; clear it from the IRR.
            Ok(true) => whpsys::lapic::global().take_vector(vector),
            // Guest not interruptible right now (IF=0 / shadow / pending). Leave
            // the vector in the IRR; we retry on the next exit. The periodic
            // timer, EOI MSR writes, and the cancel issued on every new MSI all
            // force frequent exits, so the wait is short.
            Ok(false) => {}
            Err(e) => eprintln!("[loop] interrupt injection failed: {e}"),
        }
    }

    fn handle_msr(&self, exit: &Exit) -> Option<StopReason> {
        let m = exit.msr();
        let msr = m.msr;
        let is_write = m.is_write;
        let wr_val = ((m.rdx & 0xFFFF_FFFF) << 32) | (m.rax & 0xFFFF_FFFF);

        // x2APIC / APIC_BASE MSRs are served by the software LAPIC (when active,
        // i.e. LAPIC = None); everything else by the Hyper-V enlightenment. With
        // the hardware LAPIC the APIC MSRs don't trap at all, so this is skipped.
        let mut rd_val: u64 = 0;
        let handled = if !whpsys::lapic::active() {
            false
        } else if is_write {
            let mut set_cr8 = None;
            let h = whpsys::lapic::global().write_msr(msr, wr_val, &mut set_cr8);
            if let Some(tpr_class) = set_cr8 {
                // Guest set TPR via the APIC MSR; keep CR8 in sync.
                let _ = self
                    .vcpu
                    .set_registers(&[WHvX64RegisterCr8], &[reg64(tpr_class as u64)]);
            }
            h
        } else {
            let cr8 = self
                .vcpu
                .get_register(WHvX64RegisterCr8)
                .map(|v| (unsafe { v.Reg64 } & 0xF) as u32)
                .unwrap_or(0);
            whpsys::lapic::global().read_msr(msr, cr8, &mut rd_val)
        };

        if !handled {
            let Some(hv) = self.hv.as_ref() else {
                eprintln!(
                    "[loop] MSR exit with no enlightenment wired: {} msr=0x{:08x} at RIP=0x{:x}",
                    if is_write { "WRMSR" } else { "RDMSR" },
                    msr,
                    exit.rip()
                );
                return Some(StopReason::UnhandledExit);
            };
            let result = if is_write {
                hv.handle_wrmsr(self.vcpu.index(), msr, wr_val)
            } else {
                hv.handle_rdmsr(self.vcpu.index(), msr, &mut rd_val)
            };
            if result == MsrHandled::NoInjectGp {
                return self.inject_gp();
            }
        }

        let next_rip = exit.rip() + exit.instruction_length() as u64;
        let res = if is_write {
            self.vcpu
                .set_registers(&[WHvX64RegisterRip], &[reg64(next_rip)])
        } else {
            self.vcpu.set_registers(
                &[WHvX64RegisterRax, WHvX64RegisterRdx, WHvX64RegisterRip],
                &[
                    reg64(rd_val & 0xFFFF_FFFF),
                    reg64((rd_val >> 32) & 0xFFFF_FFFF),
                    reg64(next_rip),
                ],
            )
        };
        if let Err(e) = res {
            eprintln!("[loop] MSR set-regs failed: {e}");
            return Some(StopReason::EmulationFailure);
        }
        None
    }

    /// Inject #GP(0) at the faulting instruction without advancing RIP.
    /// The 64-bit register value packs the bitfield in the low dword and the
    /// error code (0) in the high dword.
    fn inject_gp(&self) -> Option<StopReason> {
        // InterruptionPending=1 | InterruptionType=3 (<<1) | DeliverErrorCode=1 (<<4)
        //   | InterruptionVector=13 (<<16)  -> 0xD0017; ErrorCode = 0.
        let pi: u64 = 0x000D_0017;
        if let Err(e) = self
            .vcpu
            .set_registers(&[WHvRegisterPendingInterruption], &[reg64(pi)])
        {
            eprintln!("[loop] #GP injection failed: {e}");
            return Some(StopReason::EmulationFailure);
        }
        None
    }
}
