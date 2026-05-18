#include "cpuid.h"

#include "hv_enlightenment.h"

#include <Windows.h>
#include <intrin.h>

#include <atomic>
#include <vector>

namespace tinyvmm::whp {

namespace {

constexpr std::uint32_t kBit(unsigned i) noexcept { return 1u << i; }

// Feature bits we care about.
constexpr std::uint32_t kEcx_TscDeadline = kBit(24);   // CPUID.01H:ECX[24]
constexpr std::uint32_t kEcx_Hypervisor  = kBit(31);   // CPUID.01H:ECX[31]
constexpr std::uint32_t kEax_Arat        = kBit(2);    // CPUID.06H:EAX[2]
constexpr std::uint32_t kEdx_InvariantTsc = kBit(8);   // CPUID.80000007H:EDX[8]

// Runtime knob: when true, the dynamic CPUID handler masks off
// CPUID.01H:ECX[24] so the guest never sees TSC-deadline. Used as a fallback
// when WHP rejects WRMSR to 0x6E0 even with TSC-deadline in the static
// CPUID result list.
std::atomic<bool> g_hide_tsc_deadline{false};

// Hyper-V max-hypervisor-leaf. Must be >= 0x40000005 to clear
// `ms_hyperv_platform()`'s HYPERV_CPUID_MIN/MAX bracket. We expose six
// leaves (0x40000000..0x40000005) with the high leaves zeroed.
constexpr std::uint32_t kHvMaxLeaf = 0x40000006u;

// Compute the host TSC frequency, in Hz. Tries CPUID.15h on the host first,
// then CPUID.16h, then falls back to a short QueryPerformanceCounter-based
// calibration. Result is cached.
std::uint64_t MeasureTscHz() noexcept {
    int regs[4];
    __cpuid(regs, 0x15);
    const std::uint32_t den = static_cast<std::uint32_t>(regs[0]);
    const std::uint32_t num = static_cast<std::uint32_t>(regs[1]);
    const std::uint32_t ccc = static_cast<std::uint32_t>(regs[2]);
    if (den != 0 && num != 0 && ccc != 0) {
        return (static_cast<std::uint64_t>(ccc) * num) / den;
    }
    __cpuid(regs, 0x16);
    const std::uint32_t base_mhz = static_cast<std::uint32_t>(regs[0]);
    if (base_mhz != 0) {
        return static_cast<std::uint64_t>(base_mhz) * 1'000'000ull;
    }
    // Last resort: 50 ms calibration against QPC.
    LARGE_INTEGER qpc_freq{};
    LARGE_INTEGER qpc_a{};
    LARGE_INTEGER qpc_b{};
    QueryPerformanceFrequency(&qpc_freq);
    QueryPerformanceCounter(&qpc_a);
    const std::uint64_t tsc_a = __rdtsc();
    Sleep(50);
    QueryPerformanceCounter(&qpc_b);
    const std::uint64_t tsc_b = __rdtsc();
    const double secs =
        static_cast<double>(qpc_b.QuadPart - qpc_a.QuadPart) /
        static_cast<double>(qpc_freq.QuadPart);
    if (secs <= 0.0) return 2'000'000'000ull;  // conservative fallback
    return static_cast<std::uint64_t>(
        static_cast<double>(tsc_b - tsc_a) / secs);
}

std::uint64_t GetTscHz() noexcept {
    static const std::uint64_t cached = MeasureTscHz();
    return cached;
}

}  // namespace

CpuidResult ResolveCpuid(std::uint32_t leaf,
                         std::uint32_t /*subleaf*/,
                         std::uint32_t default_eax,
                         std::uint32_t default_ebx,
                         std::uint32_t default_ecx,
                         std::uint32_t default_edx) noexcept {
    CpuidResult r{default_eax, default_ebx, default_ecx, default_edx};

    switch (leaf) {
        case 0x00000000u: {
            // Ensure max-standard-leaf is high enough for leaves 0x15 / 0x16
            // (which Linux uses to skip PIT calibration). Modern hosts already
            // report >= 0x16; this is just a safety raise.
            if (r.eax < 0x16u) r.eax = 0x16u;
            break;
        }

        case 0x00000001u: {
            // Standard feature flags. tsc-deadline lets Linux program the LAPIC
            // timer as a TSC deadline (no LAPIC frequency calibration). Set the
            // hypervisor-present bit so Linux reads the 0x40000000h vendor
            // string -- only a log line results, but it's informative and stops
            // the kernel from treating the host like bare metal.
            if (!g_hide_tsc_deadline.load(std::memory_order_relaxed)) {
                r.ecx |= kEcx_TscDeadline;
            } else {
                r.ecx &= ~kEcx_TscDeadline;
            }
            r.ecx |= kEcx_Hypervisor;
            break;
        }

        case 0x00000006u: {
            // Thermal / power leaf. Bit 2 of EAX is ARAT: APIC timer is always
            // running (doesn't stop in deep C-states). Setting this avoids
            // Linux falling back to slower clock sources for hrtimers.
            r.eax |= kEax_Arat;
            break;
        }

        case 0x00000015u: {
            // TSC / core-crystal frequency ratio. Encode as
            //   TSC_Hz = ECX * EBX / EAX
            // with EBX=EAX=1 so ECX is the literal TSC frequency. Linux's
            // arch/x86/kernel/tsc.c uses this to skip PIT calibration entirely
            // when ECX != 0 and (EBX,EAX) != 0.
            const std::uint64_t tsc_hz = GetTscHz();
            r.eax = 1;
            r.ebx = 1;
            r.ecx = (tsc_hz <= 0xFFFFFFFFull)
                ? static_cast<std::uint32_t>(tsc_hz)
                : 0xFFFFFFFFu;
            r.edx = 0;
            break;
        }

        case 0x00000016u: {
            // CPU base / max / bus frequency hint in MHz.
            const std::uint64_t tsc_hz = GetTscHz();
            const std::uint32_t base_mhz =
                static_cast<std::uint32_t>(tsc_hz / 1'000'000ull);
            r.eax = base_mhz;       // base
            r.ebx = base_mhz;       // max (we don't model turbo)
            r.ecx = 100;            // bus, conventional 100 MHz reference
            r.edx = 0;
            break;
        }

        case 0x80000007u: {
            // Power management leaf. Bit 8 of EDX is invariant_tsc. We set it
            // because the underlying host has invariant TSC on every CPU we
            // care about, and Linux uses this bit to pick the TSC clocksource.
            r.edx |= kEdx_InvariantTsc;
            break;
        }

        case 0x40000000u: {
            // Max hypervisor leaf + 12-byte vendor "Microsoft Hv" packed
            // across EBX:ECX:EDX. Linux's `ms_hyperv_platform()` requires
            // BOTH this exact vendor string AND a max leaf in
            // [HYPERV_CPUID_MIN, HYPERV_CPUID_MAX] = [0x40000005, 0x4000ffff]
            // before it will treat us as Hyper-V and route through the
            // Reference TSC page setup.
            r.eax = kHvMaxLeaf;
            std::uint32_t ebx = 0, ecx = 0, edx = 0;
            GetHvVendorEbxEcxEdx(&ebx, &ecx, &edx);
            r.ebx = ebx;
            r.ecx = ecx;
            r.edx = edx;
            break;
        }

        case 0x40000001u: {
            // Hyper-V interface signature "Hv#1". `ms_hyperv_platform()`
            // checks this with memcmp("Hv#1", &eax, 4); any deviation
            // disables the Hyper-V path entirely.
            r.eax = GetHvInterfaceEax();
            r.ebx = 0;
            r.ecx = 0;
            r.edx = 0;
            break;
        }

        case 0x40000002u: {
            // Hypervisor system identity (build/major/minor/service pack).
            // Linux logs the version but does not gate behavior on it.
            r.eax = 0; r.ebx = 0; r.ecx = 0; r.edx = 0;
            break;
        }

        case 0x40000003u: {
            // Feature flags. EAX advertises the four enlightenments we
            // implement (hypercall page, VP_INDEX, Reference TSC,
            // TSC-invariant control). EBX/ECX/EDX are zero so Linux skips
            // hypercall-only features (FREQUENCY_MSRS, SynIC, synthetic
            // timers, partition-reference-counter, etc.).
            r.eax = kHvFeaturesAdvertised;
            r.ebx = 0;
            r.ecx = 0;
            r.edx = 0;
            break;
        }

        case 0x40000004u:
        case 0x40000005u:
        case 0x40000006u: {
            // Recommended enlightenment hints (0x40000004) / implementation
            // limits (0x40000005) / hardware features (0x40000006). All
            // zero -- no PV-TLB-flush, no PV-IPI, no SynIC, no recommended
            // hypercall paths. Linux honors this by skipping the entire
            // Hyper-V fast-IPI / cluster-IPI plumbing.
            r.eax = 0; r.ebx = 0; r.ecx = 0; r.edx = 0;
            break;
        }

        default: {
            if (leaf >= 0x40000007u && leaf <= 0x400000FFu) {
                // Reserved hypervisor leaves -- zero everything so the guest
                // doesn't pick up stale host CPUID fragments here.
                r.eax = 0;
                r.ebx = 0;
                r.ecx = 0;
                r.edx = 0;
            }
            break;
        }
    }

    return r;
}

void SetHideTscDeadline(bool hide) noexcept {
    g_hide_tsc_deadline.store(hide, std::memory_order_relaxed);
}
bool GetHideTscDeadline() noexcept {
    return g_hide_tsc_deadline.load(std::memory_order_relaxed);
}

std::uint64_t GetCachedTscHz() noexcept {
    return GetTscHz();
}

std::vector<WHV_X64_CPUID_RESULT> BuildStaticCpuidResultList(
    bool hide_tsc_deadline) {
    auto host = [](std::uint32_t leaf,
                   std::uint32_t subleaf = 0) -> CpuidResult {
        int regs[4] = {};
        __cpuidex(regs, static_cast<int>(leaf), static_cast<int>(subleaf));
        return {static_cast<std::uint32_t>(regs[0]),
                static_cast<std::uint32_t>(regs[1]),
                static_cast<std::uint32_t>(regs[2]),
                static_cast<std::uint32_t>(regs[3])};
    };

    auto entry = [](std::uint32_t leaf, const CpuidResult& r,
                    std::uint32_t /*subleaf*/ = 0) {
        WHV_X64_CPUID_RESULT e = {};
        e.Function = leaf;
        e.Eax = r.eax;
        e.Ebx = r.ebx;
        e.Ecx = r.ecx;
        e.Edx = r.edx;
        return e;
    };

    std::vector<WHV_X64_CPUID_RESULT> list;
    list.reserve(16);

    // For each customized leaf, start with the host's CPUID value and apply
    // the same overrides as the runtime path. This keeps the static
    // architectural model WHP sees consistent with what the guest reads at
    // runtime via the CPUID exit handler.
    {
        CpuidResult r0 = host(0x00000000u);
        if (r0.eax < 0x16u) r0.eax = 0x16u;
        list.push_back(entry(0x00000000u, r0));
    }
    {
        CpuidResult r1 = host(0x00000001u);
        if (!hide_tsc_deadline) {
            r1.ecx |= kEcx_TscDeadline;
        } else {
            r1.ecx &= ~kEcx_TscDeadline;
        }
        r1.ecx |= kEcx_Hypervisor;
        list.push_back(entry(0x00000001u, r1));
    }
    {
        CpuidResult r6 = host(0x00000006u);
        r6.eax |= kEax_Arat;
        list.push_back(entry(0x00000006u, r6));
    }
    {
        // 0x15: TSC / core-crystal frequency ratio, same as runtime path.
        const std::uint64_t tsc_hz = GetTscHz();
        CpuidResult r{};
        r.eax = 1;
        r.ebx = 1;
        r.ecx = (tsc_hz <= 0xFFFFFFFFull)
                    ? static_cast<std::uint32_t>(tsc_hz)
                    : 0xFFFFFFFFu;
        r.edx = 0;
        list.push_back(entry(0x00000015u, r));
    }
    {
        // 0x16: CPU base / max / bus frequency in MHz.
        const std::uint64_t tsc_hz = GetTscHz();
        const std::uint32_t base_mhz =
            static_cast<std::uint32_t>(tsc_hz / 1'000'000ull);
        CpuidResult r{base_mhz, base_mhz, 100u, 0u};
        list.push_back(entry(0x00000016u, r));
    }
    {
        CpuidResult r = host(0x80000007u);
        r.edx |= kEdx_InvariantTsc;
        list.push_back(entry(0x80000007u, r));
    }
    {
        // 0x40000000: hypervisor max-leaf + vendor "Microsoft Hv".
        std::uint32_t ebx = 0, ecx = 0, edx = 0;
        GetHvVendorEbxEcxEdx(&ebx, &ecx, &edx);
        CpuidResult r{kHvMaxLeaf, ebx, ecx, edx};
        list.push_back(entry(0x40000000u, r));
    }
    {
        // 0x40000001: hypervisor interface signature "Hv#1".
        CpuidResult r{GetHvInterfaceEax(), 0, 0, 0};
        list.push_back(entry(0x40000001u, r));
    }
    {
        // 0x40000002: hypervisor build/version, all zero.
        list.push_back(entry(0x40000002u, CpuidResult{0, 0, 0, 0}));
    }
    {
        // 0x40000003: features. EAX = HYPERCALL | VP_INDEX | REFERENCE_TSC
        //             | TSC_INVARIANT. Other registers zero.
        CpuidResult r{kHvFeaturesAdvertised, 0, 0, 0};
        list.push_back(entry(0x40000003u, r));
    }
    // Mask 0x40000004..0x40000006 (hints / impl limits / hw features) so
    // the guest's `ms_hyperv.hints` etc. read zero, suppressing PV TLB
    // flush, PV IPI, SynIC, and similar features we don't implement.
    for (std::uint32_t leaf = 0x40000004u; leaf <= 0x40000006u; ++leaf) {
        list.push_back(entry(leaf, CpuidResult{0, 0, 0, 0}));
    }

    return list;
}

}  // namespace tinyvmm::whp
