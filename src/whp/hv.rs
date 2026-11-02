//! Hyper-V enlightenments, implemented by WHP's hypervisor as in OpenVMM.
//! Before setup tinyvmm names the set it wants ([`OFFLOADED`]); the hypervisor
//! then serves their MSRs, hypercalls and overlay pages itself, with no exit to
//! tinyvmm, and describes them in the Hyper-V CPUID leaves, which `cpuid.rs`
//! passes through. Linux then flushes remote TLBs and sends IPIs with one
//! hypercall, skips most EOIs (lazy EOI, through the VP assist page), lets
//! spinlock waiters idle (PV spinlocks), and uses synthetic timer 0 as its
//! clock event device.
//!
//! WHP has no invariant-TSC enlightenment, so Linux marks the TSC unstable and
//! keeps time with the reference TSC page. The hypervisor maintains that page
//! from the host's TSC rate, so a restore on a host whose TSC runs at another
//! rate keeps the guest clock right.
//!
//! What stays in tinyvmm: the guest crash MSRs, which WHP passes through
//! ([`CrashMsrs`]), and saving and restoring the enlightenment state the
//! hypervisor keeps: [`PartitionState`] here, the per-vCPU SynIC state in
//! `vcpu_state`.

use crate::error::{Error, Result};
use crate::whp::partition::synthetic_processor_features_supported;
use crate::whp::regs::reg64;
use crate::whp::{GuestMemory, Partition, Vcpu};
use core::ffi::c_void;
use std::sync::{Arc, Mutex};
use windows_sys::Win32::System::Hypervisor::{
    WHV_REGISTER_NAME, WHvCapabilityCodeProcessorClockFrequency, WHvGetCapability,
    WHvRegisterGuestOsId, WHvRegisterReferenceTsc, WHvX64RegisterHypercall,
};

/// `WHV_SYNTHETIC_PROCESSOR_FEATURES` bits.
pub mod feature {
    pub const HYPERVISOR_PRESENT: u64 = 1 << 0;
    pub const HV1: u64 = 1 << 1;
    pub const ACCESS_VP_RUN_TIME_REG: u64 = 1 << 2;
    pub const ACCESS_PARTITION_REFERENCE_COUNTER: u64 = 1 << 3;
    pub const ACCESS_SYNIC_REGS: u64 = 1 << 4;
    pub const ACCESS_SYNTHETIC_TIMER_REGS: u64 = 1 << 5;
    /// The APIC MSRs and the VP assist page, which carries lazy EOI.
    pub const ACCESS_INTR_CTRL_REGS: u64 = 1 << 6;
    pub const ACCESS_HYPERCALL_REGS: u64 = 1 << 7;
    pub const ACCESS_VP_INDEX: u64 = 1 << 8;
    pub const ACCESS_PARTITION_REFERENCE_TSC: u64 = 1 << 9;
    pub const ACCESS_GUEST_IDLE_REG: u64 = 1 << 10;
    pub const ACCESS_FREQUENCY_REGS: u64 = 1 << 11;
    pub const EXTENDED_GVA_RANGES_FOR_FLUSH: u64 = 1 << 15;
    pub const FAST_HYPERCALL_OUTPUT: u64 = 1 << 18;
    pub const DIRECT_SYNTHETIC_TIMERS: u64 = 1 << 22;
    pub const EXTENDED_PROCESSOR_MASKS: u64 = 1 << 24;
    pub const TB_FLUSH_HYPERCALLS: u64 = 1 << 25;
    pub const SYNTHETIC_CLUSTER_IPI: u64 = 1 << 26;
    pub const NOTIFY_LONG_SPIN_WAIT: u64 = 1 << 27;
    pub const QUERY_NUMA_DISTANCE: u64 = 1 << 28;
    pub const SIGNAL_EVENTS: u64 = 1 << 29;
    pub const RETARGET_DEVICE_INTERRUPT: u64 = 1 << 30;
}

/// The enlightenments tinyvmm asks for: OpenVMM's set for an x86 guest with
/// no VTL2 and no nested virtualization (`virt_whp`'s partition setup).
pub const OFFLOADED: u64 = feature::HYPERVISOR_PRESENT
    | feature::HV1
    | feature::ACCESS_VP_RUN_TIME_REG
    | feature::ACCESS_PARTITION_REFERENCE_COUNTER
    | feature::ACCESS_HYPERCALL_REGS
    | feature::ACCESS_VP_INDEX
    | feature::ACCESS_PARTITION_REFERENCE_TSC
    | feature::ACCESS_SYNIC_REGS
    | feature::ACCESS_SYNTHETIC_TIMER_REGS
    | feature::FAST_HYPERCALL_OUTPUT
    | feature::EXTENDED_PROCESSOR_MASKS
    | feature::SYNTHETIC_CLUSTER_IPI
    | feature::NOTIFY_LONG_SPIN_WAIT
    | feature::QUERY_NUMA_DISTANCE
    | feature::SIGNAL_EVENTS
    | feature::RETARGET_DEVICE_INTERRUPT
    | feature::TB_FLUSH_HYPERCALLS
    | feature::ACCESS_GUEST_IDLE_REG
    | feature::ACCESS_FREQUENCY_REGS
    | feature::EXTENDED_GVA_RANGES_FOR_FLUSH
    | feature::ACCESS_INTR_CTRL_REGS
    | feature::DIRECT_SYNTHETIC_TIMERS;

/// Have the hypervisor implement the enlightenments; call before
/// [`Partition::setup`]. A boot asks for [`OFFLOADED`] and gets what of it the
/// host supports. A restore asks for the set its guest booted with, all of
/// which the host must support: the guest chose its code paths from it.
/// Returns the set enabled.
pub fn offload(part: &Partition, restore: Option<u64>) -> Result<u64> {
    const BASE: u64 = feature::HYPERVISOR_PRESENT | feature::HV1;
    let supported = synthetic_processor_features_supported().unwrap_or(0);
    if supported & BASE != BASE {
        return Err(Error::msg(format!(
            "this host's Windows Hypervisor Platform can't implement Hyper-V \
             enlightenments for a guest (supported synthetic processor features: \
             0x{supported:x}); tinyvmm needs a newer Windows"
        )));
    }
    let features = match restore {
        Some(saved) if saved & !supported != 0 => {
            return Err(Error::msg(format!(
                "this host can't implement Hyper-V enlightenments 0x{:x}, which the \
                 snapshot's guest booted with",
                saved & !supported
            )));
        }
        Some(saved) => saved,
        None => OFFLOADED & supported,
    };
    part.set_synthetic_processor_features(features)?;
    Ok(features)
}

/// The partition-wide enlightenment state the hypervisor keeps: the guest OS
/// ID, the hypercall and reference TSC page MSRs (the hypervisor rebuilds both
/// pages from them: they overlay guest RAM rather than live in it), and the
/// reference time. Taken and put back with partition time suspended, so the
/// reference time and every vCPU's TSC are one instant.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PartitionState {
    pub guest_os_id: u64,
    pub hypercall: u64,
    pub reference_tsc: u64,
    pub reference_time: u64,
}

impl PartitionState {
    const ENCODED_LEN: usize = 32;

    /// The MSRs are partition-wide; like OpenVMM, go through the BSP.
    pub fn capture(part: &Partition, bsp: &Vcpu) -> Result<Self> {
        let names: [WHV_REGISTER_NAME; 3] = [
            WHvRegisterGuestOsId,
            WHvX64RegisterHypercall,
            WHvRegisterReferenceTsc,
        ];
        let v = bsp.get_registers_bytes(&names)?;
        let u64_of = |b: &[u8; 16]| u64::from_le_bytes(b[..8].try_into().unwrap());
        Ok(PartitionState {
            guest_os_id: u64_of(&v[0]),
            hypercall: u64_of(&v[1]),
            reference_tsc: u64_of(&v[2]),
            reference_time: part.reference_time()?,
        })
    }

    /// The guest OS ID goes in before the hypercall MSR, as a guest writes
    /// them, and the reference time before the reference TSC page, which maps
    /// the TSC onto it. Partition time must be suspended.
    pub fn apply(&self, part: &Partition, bsp: &Vcpu) -> Result<()> {
        bsp.set_registers(
            &[WHvRegisterGuestOsId, WHvX64RegisterHypercall],
            &[reg64(self.guest_os_id), reg64(self.hypercall)],
        )?;
        part.set_reference_time(self.reference_time)?;
        bsp.set_registers(&[WHvRegisterReferenceTsc], &[reg64(self.reference_tsc)])
    }

    pub fn encode(&self) -> Vec<u8> {
        [
            self.guest_os_id,
            self.hypercall,
            self.reference_tsc,
            self.reference_time,
        ]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(Error::msg(format!(
                "snapshot: HvPartition section is {} bytes, not {}",
                bytes.len(),
                Self::ENCODED_LEN
            )));
        }
        let u64_at = |i: usize| u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
        Ok(PartitionState {
            guest_os_id: u64_at(0),
            hypercall: u64_at(1),
            reference_tsc: u64_at(2),
            reference_time: u64_at(3),
        })
    }
}

/// Rate the guest TSC counts at, as the hypervisor reports it (its
/// "processor clock"), or None if WHP can't say. This is the rate the
/// hypervisor itself keeps time by; OpenVMM reads the same value.
pub fn processor_clock_hz() -> Option<u64> {
    let mut hz: u64 = 0;
    let mut written: u32 = 0;
    // SAFETY: WHvGetCapability writes at most 8 bytes into `hz`.
    let hr = unsafe {
        WHvGetCapability(
            WHvCapabilityCodeProcessorClockFrequency,
            &mut hz as *mut u64 as *mut c_void,
            std::mem::size_of::<u64>() as u32,
            &mut written,
        )
    };
    (hr >= 0 && hz != 0).then_some(hz)
}

/// Guest crash registers: P0..P4 carry the report, a write of CRASH_CTL with
/// `CRASH_CTL_NOTIFY` posts it. A read of CRASH_CTL says which report kinds
/// are taken.
pub const MSR_CRASH_P0: u32 = 0x4000_0100;
pub const MSR_CRASH_P4: u32 = 0x4000_0104;
pub const MSR_CRASH_CTL: u32 = 0x4000_0105;
const CRASH_CTL_NOTIFY: u64 = 1 << 63;
/// The report is a page of kernel log: P3 = its GPA, P4 = its length.
const CRASH_CTL_NOTIFY_MSG: u64 = 1 << 62;
const PAGE_SIZE: usize = 4096;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MsrHandled {
    Yes,
    NoInjectGp,
    /// The guest reported a crash (a kernel panic) through the crash MSRs;
    /// [`CrashMsrs::crash_report`] describes it.
    GuestCrashed,
}

/// The guest crash MSRs (`0x40000100`-`0x40000105`), which `cpuid.rs`
/// advertises in CPUID `0x40000003` EDX[10]. WHP's hypervisor leaves them to
/// the VMM, so they still exit. Linux reports a panic through them, and the
/// run loop stops the VM with the report instead of leaving a vCPU spinning in
/// `panic()` forever.
pub struct CrashMsrs {
    ram: Arc<GuestMemory>,
    regs: Mutex<CrashRegs>,
}

#[derive(Default)]
struct CrashRegs {
    p: [u64; 5],
    ctl: u64,
}

impl CrashMsrs {
    pub fn new(ram: Arc<GuestMemory>) -> Self {
        CrashMsrs {
            ram,
            regs: Mutex::new(CrashRegs::default()),
        }
    }

    pub fn handle_wrmsr(&self, msr: u32, value: u64) -> MsrHandled {
        let mut c = self.regs.lock().unwrap();
        match msr {
            MSR_CRASH_P0..=MSR_CRASH_P4 => {
                c.p[(msr - MSR_CRASH_P0) as usize] = value;
                MsrHandled::Yes
            }
            MSR_CRASH_CTL if value & CRASH_CTL_NOTIFY != 0 => {
                c.ctl = value;
                MsrHandled::GuestCrashed
            }
            MSR_CRASH_CTL => MsrHandled::Yes,
            _ => MsrHandled::NoInjectGp,
        }
    }

    pub fn handle_rdmsr(&self, msr: u32, out: &mut u64) -> MsrHandled {
        let c = self.regs.lock().unwrap();
        match msr {
            MSR_CRASH_P0..=MSR_CRASH_P4 => {
                *out = c.p[(msr - MSR_CRASH_P0) as usize];
                MsrHandled::Yes
            }
            // Both report kinds are taken, so Linux registers its kernel-log
            // dumper as well as the panic notifier (`hv_common_init`).
            MSR_CRASH_CTL => {
                *out = CRASH_CTL_NOTIFY | CRASH_CTL_NOTIFY_MSG;
                MsrHandled::Yes
            }
            _ => {
                *out = 0;
                MsrHandled::NoInjectGp
            }
        }
    }

    /// The crash the guest last reported (see [`MsrHandled::GuestCrashed`]):
    /// the tail of its kernel log, or failing that the registers it posted.
    /// Guest text is reduced to printable ASCII so it can't drive the host's
    /// terminal.
    pub fn crash_report(&self) -> String {
        let (p, ctl) = {
            let c = self.regs.lock().unwrap();
            (c.p, c.ctl)
        };
        if ctl & CRASH_CTL_NOTIFY_MSG != 0 {
            let mut msg = vec![0u8; (p[4] as usize).min(PAGE_SIZE)];
            if !msg.is_empty() && self.ram.read_into(p[3], &mut msg) {
                return msg
                    .iter()
                    .map(|&b| match b {
                        b'\n' | b'\t' | 0x20..=0x7e => b as char,
                        _ => '.',
                    })
                    .collect();
            }
        }
        format!(
            "code 0x{:x}, guest OS id 0x{:x}, RIP 0x{:x}, RAX 0x{:x}, RSP 0x{:x}",
            p[0], p[1], p[2], p[3], p[4]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Linux's panic path (`hv_kmsg_dump`): it reads CRASH_CTL at boot for the
    /// report kinds taken, then posts P3 = GPA and P4 = length of a page of
    /// kernel log and writes CRASH_CTL = NOTIFY | NOTIFY_MSG. That write
    /// reports the crash; the log comes back with control bytes neutralized.
    #[test]
    fn a_guest_panic_reports_its_kernel_log() {
        let ram = Arc::new(GuestMemory::new_host_only(0x4000).unwrap());
        let crash = CrashMsrs::new(ram.clone());
        let mut ctl = 0;
        let _ = crash.handle_rdmsr(MSR_CRASH_CTL, &mut ctl);
        assert_eq!(ctl, CRASH_CTL_NOTIFY | CRASH_CTL_NOTIFY_MSG);

        let log = b"Kernel panic - not syncing: VFS\x1b]0;x\x07\n";
        assert!(ram.write_bytes(0x3000, log));
        for (msr, value) in [(0, 0), (1, 0), (2, 0), (3, 0x3000), (4, log.len() as u64)] {
            assert!(crash.handle_wrmsr(MSR_CRASH_P0 + msr, value) == MsrHandled::Yes);
        }
        assert!(
            crash.handle_wrmsr(MSR_CRASH_CTL, 0) == MsrHandled::Yes,
            "no notify bit"
        );
        assert!(
            crash.handle_wrmsr(MSR_CRASH_CTL, CRASH_CTL_NOTIFY | CRASH_CTL_NOTIFY_MSG)
                == MsrHandled::GuestCrashed
        );
        assert_eq!(
            crash.crash_report(),
            "Kernel panic - not syncing: VFS.]0;x.\n"
        );

        // Without a message, the report is the registers the guest posted.
        assert!(crash.handle_wrmsr(MSR_CRASH_P0 + 2, 0xffff_ffff_8100_0000) == MsrHandled::Yes);
        assert!(crash.handle_wrmsr(MSR_CRASH_CTL, CRASH_CTL_NOTIFY) == MsrHandled::GuestCrashed);
        assert!(crash.crash_report().contains("RIP 0xffffffff81000000"));
    }
}
