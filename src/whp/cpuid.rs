//! CPUID exit policy. Layers tinyvmm overrides (invariant TSC, ARAT, TSC
//! frequency via leaf 0x15/0x16, per-vCPU x2APIC topology, the guest crash
//! MSRs, and hiding MONITOR/MWAIT) on top of the default result WHP reports
//! with each CPUID exit. Port of src/whp/cpuid.cpp.
//!
//! Every CPUID exits (`X64CpuidExit` without a CPUID exit list), so the
//! partition sets no static CPUID result list: an entry there would replace
//! that default, which tracks guest state (CPUID.1 OSXSAVE follows CR4) and
//! hides host-only features, with fixed host values.
//!
//! The Hyper-V leaves (`0x40000000`-`0x400000FF`) are the hypervisor's: it
//! implements the enlightenments (`hv.rs`), and its default result describes
//! exactly those, so they pass through.

use core::arch::x86_64::{__cpuid, _rdtsc};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy, Default)]
pub struct CpuidResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

pub struct CpuidContext {
    pub vcpu_index: u32,
    pub vcpu_count: u32,
}

// MONITOR/MWAIT #UD in a WHP guest, yet a bare-metal root partition sees
// MONITOR: left visible, Linux idles in
// mwait_idle and panics on its first idle; hidden, it falls back to HLT. AMD's
// MONITORX/MWAITX (leaf 0x80000001), which Linux uses for udelay, is hidden too.
const ECX_MONITOR: u32 = 1 << 3;
const ECX_X2APIC: u32 = 1 << 21;
const ECX_TSC_DEADLINE: u32 = 1 << 24;
const ECX_HYPERVISOR: u32 = 1 << 31;
const ECX_EXT_MWAITX: u32 = 1 << 29;
const EAX_ARAT: u32 = 1 << 2;
const EDX_INVARIANT_TSC: u32 = 1 << 8;

// CPUID.40000003H:EDX[10]: the guest crash MSRs, which tinyvmm implements
// (`hv::CrashMsrs`) and the hypervisor doesn't report. Linux then reports a
// panic (its kernel log tail) through them (`hv_common_init`), and tinyvmm
// stops the VM with that report instead of leaving a vCPU spinning in
// `panic()` forever.
const HV_MISC_GUEST_CRASH_MSRS_AVAILABLE: u32 = 1 << 10;

static HIDE_TSC_DEADLINE: AtomicBool = AtomicBool::new(false);

pub fn set_hide_tsc_deadline(hide: bool) {
    HIDE_TSC_DEADLINE.store(hide, Ordering::Relaxed);
}

/// The guest TSC rate. WHP's processor clock is what the hypervisor keeps
/// time by. The fallbacks only guess: leaf 0x15/0x16 report a nominal rate
/// (leaf 0x16 to the MHz), and a calibration against the host clock is off by
/// ~10 ppm when the thread runs undisturbed and by much more when it is
/// preempted, which a guest with no NTP turns into clock drift.
fn measure_tsc_hz() -> u64 {
    if let Some(hz) = crate::whp::hv::processor_clock_hz() {
        return hz;
    }
    let r = __cpuid(0x15);
    let den = r.eax;
    let num = r.ebx;
    let ccc = r.ecx;
    if den != 0 && num != 0 && ccc != 0 {
        return (ccc as u64 * num as u64) / den as u64;
    }
    let r = __cpuid(0x16);
    let base_mhz = r.eax;
    if base_mhz != 0 {
        return base_mhz as u64 * 1_000_000;
    }
    // Last resort: ~50 ms calibration against the monotonic clock.
    let t0 = std::time::Instant::now();
    // SAFETY: _rdtsc just reads the timestamp counter; always available on x86_64.
    let tsc_a = unsafe { _rdtsc() };
    std::thread::sleep(std::time::Duration::from_millis(50));
    let tsc_b = unsafe { _rdtsc() };
    let secs = t0.elapsed().as_secs_f64();
    if secs <= 0.0 {
        return 2_000_000_000;
    }
    ((tsc_b - tsc_a) as f64 / secs) as u64
}

pub fn cached_tsc_hz() -> u64 {
    static CACHED: OnceLock<u64> = OnceLock::new();
    *CACHED.get_or_init(measure_tsc_hz)
}

/// Whether the host CPU is AMD's (or Hygon's): WHP passes the host's vendor
/// string through to the guest, which then follows AMD's code paths.
pub fn host_is_amd() -> bool {
    static AMD: OnceLock<bool> = OnceLock::new();
    *AMD.get_or_init(|| {
        let r = __cpuid(0);
        let mut vendor = [0u8; 12];
        vendor[0..4].copy_from_slice(&r.ebx.to_le_bytes());
        vendor[4..8].copy_from_slice(&r.edx.to_le_bytes());
        vendor[8..12].copy_from_slice(&r.ecx.to_le_bytes());
        &vendor == b"AuthenticAMD" || &vendor == b"HygonGenuine"
    })
}

pub fn resolve_cpuid(
    leaf: u32,
    subleaf: u32,
    default_eax: u32,
    default_ebx: u32,
    default_ecx: u32,
    default_edx: u32,
    ctx: &CpuidContext,
) -> CpuidResult {
    let mut r = CpuidResult {
        eax: default_eax,
        ebx: default_ebx,
        ecx: default_ecx,
        edx: default_edx,
    };

    let vcpu_index = if ctx.vcpu_index < 256 {
        ctx.vcpu_index
    } else {
        0
    };
    let vcpu_count = if ctx.vcpu_count >= 1 && ctx.vcpu_count <= 256 {
        ctx.vcpu_count
    } else {
        1
    };
    const CORE_SHIFT: u32 = 5; // ceil(log2(32))

    match leaf {
        0x0000_0000 => {
            if r.eax < 0x1F {
                r.eax = 0x1F;
            }
        }
        0x0000_0001 => {
            // Advertise x2APIC even if the host masks it: WHP's LAPIC runs in
            // x2APIC mode, and the MADT describes the vCPUs as x2APIC entries.
            r.ecx |= ECX_X2APIC;
            if !HIDE_TSC_DEADLINE.load(Ordering::Relaxed) {
                r.ecx |= ECX_TSC_DEADLINE;
            } else {
                r.ecx &= !ECX_TSC_DEADLINE;
            }
            r.ecx |= ECX_HYPERVISOR;
            r.ecx &= !ECX_MONITOR;
            r.ebx =
                (r.ebx & 0x0000_FFFF) | ((vcpu_count & 0xFF) << 16) | ((vcpu_index & 0xFF) << 24);
        }
        0x0000_0005 => {
            // MONITOR/MWAIT leaf: empty, to match the hidden MONITOR bit.
            r = CpuidResult::default();
        }
        0x0000_0006 => {
            r.eax |= EAX_ARAT;
        }
        0x0000_000B | 0x0000_001F => {
            const LEVEL_INVALID: u32 = 0;
            const LEVEL_SMT: u32 = 1;
            const LEVEL_CORE: u32 = 2;
            let (eax, ebx, level) = match subleaf {
                0 => (0u32, 1u32, LEVEL_SMT),
                1 => (CORE_SHIFT, vcpu_count, LEVEL_CORE),
                _ => (0, 0, LEVEL_INVALID),
            };
            r.eax = eax;
            r.ebx = ebx & 0xFFFF;
            r.ecx = (subleaf & 0xFF) | (level << 8);
            r.edx = vcpu_index;
        }
        0x0000_0015 => {
            let tsc_hz = cached_tsc_hz();
            r.eax = 1;
            r.ebx = 1;
            r.ecx = if tsc_hz <= 0xFFFF_FFFF {
                tsc_hz as u32
            } else {
                0xFFFF_FFFF
            };
            r.edx = 0;
        }
        0x0000_0016 => {
            let tsc_hz = cached_tsc_hz();
            let base_mhz = (tsc_hz / 1_000_000) as u32;
            r.eax = base_mhz;
            r.ebx = base_mhz;
            r.ecx = 100;
            r.edx = 0;
        }
        0x8000_0001 => {
            r.ecx &= !ECX_EXT_MWAITX;
        }
        0x8000_0007 => {
            r.edx |= EDX_INVARIANT_TSC;
        }
        0x4000_0003 => {
            r.edx |= HV_MISC_GUEST_CRASH_MSRS_AVAILABLE;
        }
        _ => {}
    }

    r
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A guest must never see MONITOR/MWAIT (or AMD's MWAITX), whatever the
    /// host or WHP's default result reports: MWAIT is a #UD in a WHP guest.
    #[test]
    fn monitor_and_mwait_are_hidden() {
        let ctx = CpuidContext {
            vcpu_index: 0,
            vcpu_count: 1,
        };
        let r = resolve_cpuid(1, 0, 0, 0, u32::MAX, 0, &ctx);
        assert_eq!(r.ecx & ECX_MONITOR, 0, "leaf 1 must hide MONITOR");
        let r = resolve_cpuid(5, 0, 64, 64, 3, 0x0002_1120, &ctx);
        assert_eq!(
            (r.eax, r.ebx, r.ecx, r.edx),
            (0, 0, 0, 0),
            "leaf 5 must be empty"
        );
        let r = resolve_cpuid(0x8000_0001, 0, 0, 0, u32::MAX, u32::MAX, &ctx);
        assert_eq!(r.ecx, !ECX_EXT_MWAITX, "only MWAITX is hidden");
        assert_eq!(r.edx, u32::MAX);
    }

    /// The Hyper-V leaves describe the enlightenments the hypervisor runs, so
    /// its values reach the guest untouched; tinyvmm only adds the crash MSRs
    /// it implements itself. (These are the leaves WHP reported for OpenVMM's
    /// feature set on a nested AMD host.)
    #[test]
    fn hyper_v_leaves_are_the_hypervisors_plus_crash_msrs() {
        let ctx = CpuidContext {
            vcpu_index: 0,
            vcpu_count: 4,
        };
        let r = resolve_cpuid(0x4000_0003, 0, 0xe7f, 0x88020, 0x2, 0xec1b0, &ctx);
        assert_eq!(
            (r.eax, r.ebx, r.ecx, r.edx),
            (
                0xe7f,
                0x88020,
                0x2,
                0xec1b0 | HV_MISC_GUEST_CRASH_MSRS_AVAILABLE
            )
        );
        for leaf in [0x4000_0000, 0x4000_0001, 0x4000_0004, 0x4000_000A] {
            let r = resolve_cpuid(leaf, 0, 0x4000_000b, 0xe2c, 0x55, 0xaa, &ctx);
            assert_eq!(
                (r.eax, r.ebx, r.ecx, r.edx),
                (0x4000_000b, 0xe2c, 0x55, 0xaa),
                "leaf {leaf:#x}"
            );
        }
    }
}
