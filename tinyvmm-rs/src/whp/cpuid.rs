//! CPUID exit policy. Layers tinyvmm overrides (invariant TSC, ARAT, TSC
//! frequency via leaf 0x15/0x16, per-vCPU x2APIC topology, and the Hyper-V
//! vendor/feature leaves) on top of WHP's host-passthrough defaults. Port of
//! src/whp/cpuid.cpp.

use core::arch::x86_64::{__cpuid, __cpuid_count, _rdtsc};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use windows_sys::Win32::System::Hypervisor::WHV_X64_CPUID_RESULT;

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

const ECX_TSC_DEADLINE: u32 = 1 << 24;
const ECX_HYPERVISOR: u32 = 1 << 31;
const EAX_ARAT: u32 = 1 << 2;
const EDX_INVARIANT_TSC: u32 = 1 << 8;

const HV_MAX_LEAF: u32 = 0x4000_0006;

// Hyper-V CPUID.40000003H:EAX feature bits we advertise.
const HV_FEATURE_HYPERCALL: u32 = 1 << 5;
const HV_FEATURE_VP_INDEX: u32 = 1 << 6;
const HV_FEATURE_REFERENCE_TSC: u32 = 1 << 9;
const HV_FEATURE_TSC_INVARIANT: u32 = 1 << 15;
pub const HV_FEATURES_ADVERTISED: u32 =
    HV_FEATURE_HYPERCALL | HV_FEATURE_VP_INDEX | HV_FEATURE_REFERENCE_TSC | HV_FEATURE_TSC_INVARIANT;

static HIDE_TSC_DEADLINE: AtomicBool = AtomicBool::new(false);

pub fn set_hide_tsc_deadline(hide: bool) {
    HIDE_TSC_DEADLINE.store(hide, Ordering::Relaxed);
}

/// "Microsoft Hv" packed across three little-endian dwords (EBX:ECX:EDX).
pub fn hv_vendor() -> (u32, u32, u32) {
    let pack = |b: [u8; 4]| {
        (b[0] as u32) | ((b[1] as u32) << 8) | ((b[2] as u32) << 16) | ((b[3] as u32) << 24)
    };
    (
        pack(*b"Micr"),
        pack(*b"osof"),
        pack(*b"t Hv"),
    )
}

/// Hyper-V interface signature "Hv#1" packed into CPUID.40000001H:EAX.
pub fn hv_interface_eax() -> u32 {
    let b = *b"Hv#1";
    (b[0] as u32) | ((b[1] as u32) << 8) | ((b[2] as u32) << 16) | ((b[3] as u32) << 24)
}

fn measure_tsc_hz() -> u64 {
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

    let vcpu_index = if ctx.vcpu_index < 256 { ctx.vcpu_index } else { 0 };
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
            if !HIDE_TSC_DEADLINE.load(Ordering::Relaxed) {
                r.ecx |= ECX_TSC_DEADLINE;
            } else {
                r.ecx &= !ECX_TSC_DEADLINE;
            }
            r.ecx |= ECX_HYPERVISOR;
            r.ebx = (r.ebx & 0x0000_FFFF)
                | ((vcpu_count & 0xFF) << 16)
                | ((vcpu_index & 0xFF) << 24);
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
        0x8000_0007 => {
            r.edx |= EDX_INVARIANT_TSC;
        }
        0x4000_0000 => {
            r.eax = HV_MAX_LEAF;
            let (ebx, ecx, edx) = hv_vendor();
            r.ebx = ebx;
            r.ecx = ecx;
            r.edx = edx;
        }
        0x4000_0001 => {
            r.eax = hv_interface_eax();
            r.ebx = 0;
            r.ecx = 0;
            r.edx = 0;
        }
        0x4000_0002 => {
            r = CpuidResult::default();
        }
        0x4000_0003 => {
            r.eax = HV_FEATURES_ADVERTISED;
            r.ebx = 0;
            r.ecx = 0;
            r.edx = 0;
        }
        0x4000_0004..=0x4000_0006 => {
            r = CpuidResult::default();
        }
        other => {
            if (0x4000_0007..=0x4000_00FF).contains(&other) {
                r = CpuidResult::default();
            }
        }
    }

    r
}

fn host_cpuid(leaf: u32, subleaf: u32) -> CpuidResult {
    let r = __cpuid_count(leaf, subleaf);
    CpuidResult {
        eax: r.eax,
        ebx: r.ebx,
        ecx: r.ecx,
        edx: r.edx,
    }
}

fn entry(leaf: u32, r: &CpuidResult) -> WHV_X64_CPUID_RESULT {
    WHV_X64_CPUID_RESULT {
        Function: leaf,
        Reserved: [0; 3],
        Eax: r.eax,
        Ebx: r.ebx,
        Ecx: r.ecx,
        Edx: r.edx,
    }
}

/// Static CPUID result list mirroring `BuildStaticCpuidResultList`.
pub fn build_static_cpuid_result_list(hide_tsc_deadline: bool) -> Vec<WHV_X64_CPUID_RESULT> {
    let mut list = Vec::with_capacity(16);

    {
        let mut r0 = host_cpuid(0x0000_0000, 0);
        if r0.eax < 0x1F {
            r0.eax = 0x1F;
        }
        list.push(entry(0x0000_0000, &r0));
    }
    {
        let mut r1 = host_cpuid(0x0000_0001, 0);
        if !hide_tsc_deadline {
            r1.ecx |= ECX_TSC_DEADLINE;
        } else {
            r1.ecx &= !ECX_TSC_DEADLINE;
        }
        r1.ecx |= ECX_HYPERVISOR;
        r1.ebx = (r1.ebx & 0x0000_FFFF) | (1 << 16);
        list.push(entry(0x0000_0001, &r1));
    }
    {
        let mut r6 = host_cpuid(0x0000_0006, 0);
        r6.eax |= EAX_ARAT;
        list.push(entry(0x0000_0006, &r6));
    }
    {
        let tsc_hz = cached_tsc_hz();
        let r = CpuidResult {
            eax: 1,
            ebx: 1,
            ecx: if tsc_hz <= 0xFFFF_FFFF {
                tsc_hz as u32
            } else {
                0xFFFF_FFFF
            },
            edx: 0,
        };
        list.push(entry(0x0000_0015, &r));
    }
    {
        let tsc_hz = cached_tsc_hz();
        let base_mhz = (tsc_hz / 1_000_000) as u32;
        let r = CpuidResult {
            eax: base_mhz,
            ebx: base_mhz,
            ecx: 100,
            edx: 0,
        };
        list.push(entry(0x0000_0016, &r));
    }
    {
        let mut r = host_cpuid(0x8000_0007, 0);
        r.edx |= EDX_INVARIANT_TSC;
        list.push(entry(0x8000_0007, &r));
    }
    {
        let (ebx, ecx, edx) = hv_vendor();
        let r = CpuidResult {
            eax: HV_MAX_LEAF,
            ebx,
            ecx,
            edx,
        };
        list.push(entry(0x4000_0000, &r));
    }
    {
        let r = CpuidResult {
            eax: hv_interface_eax(),
            ebx: 0,
            ecx: 0,
            edx: 0,
        };
        list.push(entry(0x4000_0001, &r));
    }
    list.push(entry(0x4000_0002, &CpuidResult::default()));
    {
        let r = CpuidResult {
            eax: HV_FEATURES_ADVERTISED,
            ebx: 0,
            ecx: 0,
            edx: 0,
        };
        list.push(entry(0x4000_0003, &r));
    }
    for leaf in 0x4000_0004..=0x4000_0006u32 {
        list.push(entry(leaf, &CpuidResult::default()));
    }

    list
}
