//! Drives a single vCPU's exit loop. Routes IO/MMIO accesses through the IO and
//! MMIO buses via the WHP emulator (`whpsys::emulator`), and handles CPUID/MSR/
//! HLT exits. Port of src/whp/run_loop.cpp.

use crate::devices::io_bus::{IoAccess, IoBus};
use crate::devices::mmio_bus::{MmioAccess, MmioBus};
use crate::whp::cpuid::{resolve_cpuid, CpuidContext};
use crate::whp::emulator::{EmuError, Emulator, EmulatorBus};
use crate::whp::hv::{HvEnlightenment, MsrHandled};
use crate::whp::regs::reg64;
use crate::whp::vcpu::{exit_reason_name, Exit, ExitReason, Vcpu};

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use windows_sys::Win32::System::Hypervisor::{
    WHvRegisterPendingInterruption, WHvX64RegisterRax, WHvX64RegisterRbx, WHvX64RegisterRcx,
    WHvX64RegisterRdx, WHvX64RegisterRip,
};

const RFLAGS_IF: u64 = 1 << 9;

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
                ExitReason::InterruptWindow | ExitReason::ApicEoi | ExitReason::Canceled => {}
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

    fn handle_msr(&self, exit: &Exit) -> Option<StopReason> {
        let m = exit.msr();
        let msr = m.msr;
        let is_write = m.is_write;
        let wr_val = ((m.rdx & 0xFFFF_FFFF) << 32) | (m.rax & 0xFFFF_FFFF);

        let Some(hv) = self.hv.as_ref() else {
            eprintln!(
                "[loop] MSR exit with no enlightenment wired: {} msr=0x{:08x} at RIP=0x{:x}",
                if is_write { "WRMSR" } else { "RDMSR" },
                msr,
                exit.rip()
            );
            return Some(StopReason::UnhandledExit);
        };

        let mut rd_val: u64 = 0;
        let result = if is_write {
            hv.handle_wrmsr(self.vcpu.index(), msr, wr_val)
        } else {
            hv.handle_rdmsr(self.vcpu.index(), msr, &mut rd_val)
        };

        if result == MsrHandled::NoInjectGp {
            return self.inject_gp();
        }

        let next_rip = exit.rip() + exit.instruction_length() as u64;
        let res = if is_write {
            self.vcpu.set_registers(&[WHvX64RegisterRip], &[reg64(next_rip)])
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
