#pragma once

#include "memory.h"

#include <cstdint>
#include <mutex>

namespace tinyvmm::whp {

// Hyper-V Top Level Functional Specification (TLFS) MSR numbers and feature
// bits relevant to the small subset of enlightenments we implement: the
// Reference TSC page (provides a paravirt clocksource backed by the host TSC)
// and TSC-invariant access (sets X86_FEATURE_TSC_RELIABLE in the guest so
// Linux's `clocksource watchdog` stops complaining about TSC under SMP load).
//
// Why we pretend to be Hyper-V:
//  - WHP runs each vCPU on whatever host logical-processor Windows schedules
//    it on. A vCPU thread can be descheduled for tens of milliseconds while
//    the kernel's TSC <-> watchdog-clocksource sampling is mid-flight. The
//    apparent skew exceeds Linux's WATCHDOG_THRESHOLD, and the kernel marks
//    TSC unstable: `clocksource: ... Marking 'tsc' as unstable`. The TSC
//    itself is invariant and fine -- it's a watchdog false-positive caused
//    by hypervisor scheduling jitter.
//  - The Reference-TSC-page-only path is not enough on modern Linux either:
//    `hv_init_tsc_clocksource()` registers `hyperv_clocksource_tsc_page` at
//    rating 500, but with HV_ACCESS_TSC_INVARIANT it gets demoted to 250 AND
//    the kernel forces X86_FEATURE_TSC_RELIABLE -- which is what actually
//    disables the watchdog for TSC. So we advertise BOTH bits: the watchdog
//    goes away (via reliable-TSC), and we also provide a real paravirt
//    clocksource at rating 250 as a fallback.
constexpr std::uint32_t kHvMsrGuestOsId          = 0x40000000u;
constexpr std::uint32_t kHvMsrHypercall          = 0x40000001u;
constexpr std::uint32_t kHvMsrVpIndex            = 0x40000002u;
constexpr std::uint32_t kHvMsrTimeRefCount       = 0x40000020u;
constexpr std::uint32_t kHvMsrReferenceTsc       = 0x40000021u;
constexpr std::uint32_t kHvMsrTscInvariantCtl    = 0x40000118u;

// Feature bits returned in CPUID.40000003H:EAX. We advertise these four:
//   bit 5  HV_MSR_HYPERCALL_AVAILABLE     (must implement HV_X64_MSR_HYPERCALL)
//   bit 6  HV_MSR_VP_INDEX_AVAILABLE      (must implement HV_X64_MSR_VP_INDEX)
//   bit 9  HV_MSR_REFERENCE_TSC_AVAILABLE (must implement HV_X64_MSR_REFERENCE_TSC)
//   bit 15 HV_ACCESS_TSC_INVARIANT        (must implement HV_X64_MSR_TSC_INVARIANT_CONTROL)
// Hypercall and VP_INDEX are NOT optional: Linux's `hyperv_init` writes
// HV_X64_MSR_HYPERCALL unconditionally once Hyper-V is detected, and per-cpu
// init reads VP_INDEX. Leaving either un-handled (=> #GP) prints
// `unchecked MSR access` traces; advertising them and implementing the
// minimum required behavior is cleaner.
constexpr std::uint32_t kHvFeatureHypercall     = 1u << 5;
constexpr std::uint32_t kHvFeatureVpIndex       = 1u << 6;
constexpr std::uint32_t kHvFeatureReferenceTsc  = 1u << 9;
constexpr std::uint32_t kHvFeatureTscInvariant  = 1u << 15;
constexpr std::uint32_t kHvFeaturesAdvertised   =
    kHvFeatureHypercall | kHvFeatureVpIndex |
    kHvFeatureReferenceTsc | kHvFeatureTscInvariant;

// Reference TSC Page layout (TLFS section 12.7). The full page is 4 KiB; the
// non-zero header is just these 24 bytes at the front.
//
// Linux's `read_hv_clock_tsc` computes the 100ns time as:
//   100ns = ((rdtsc() * tsc_scale) >> 64) + tsc_offset
// and uses a sequence-number protocol so a concurrent updater doesn't tear
// the read: reader reads `sequence`, reads scale/offset, re-reads sequence,
// and retries if they differ. `sequence == 0` means "invalid, fall back to
// RDMSR HV_X64_MSR_TIME_REF_COUNT".
struct HvReferenceTscPage {
    std::uint32_t tsc_sequence;
    std::uint32_t reserved1;
    std::uint64_t tsc_scale;
    std::int64_t  tsc_offset;
};
static_assert(sizeof(HvReferenceTscPage) == 24,
              "Hyper-V Reference TSC page header must be 24 bytes");

// Result of a single MSR-exit handler invocation.
enum class MsrHandled {
    Yes,         // handled; RunLoop should set Rax/Rdx (read) and advance RIP
    NoInjectGp,  // not ours -- RunLoop should inject #GP at the WRMSR/RDMSR
};

// Per-VM Hyper-V enlightenment state. One instance per partition; the same
// object services MSR exits from every vCPU. Thread-safe via an internal
// mutex on the cold MSR path.
class HvEnlightenment {
public:
    // `ram` is the guest's primary RAM region (starting at GPA 0). The
    // Reference TSC page write resolves a guest PFN against this region and
    // writes the page contents directly through the host-virtual mapping.
    // `tsc_hz` is the (cached) host TSC frequency in Hz -- the same value
    // used to populate CPUID.15h, so the guest sees the same time-base in
    // both the TSC clocksource and the Reference TSC page.
    HvEnlightenment(GuestMemory& ram, std::uint64_t tsc_hz);

    // Test-only constructor for host-side smoke tests that exercise the
    // MSR dispatch + scaling math without needing a real WHP partition.
    // With no backing RAM, WRMSR REFERENCE_TSC / HYPERCALL accept the
    // value (no #GP) but silently skip the guest-memory write -- exactly
    // the same behaviour as a bad PFN at runtime.
    explicit HvEnlightenment(std::uint64_t tsc_hz);

    // RDMSR/WRMSR dispatch. `vp_index` is the calling vCPU's index, used to
    // service RDMSR HV_X64_MSR_VP_INDEX. Returns whether the MSR was ours.
    MsrHandled HandleWrmsr(std::uint32_t vp_index,
                           std::uint32_t msr,
                           std::uint64_t value);
    MsrHandled HandleRdmsr(std::uint32_t vp_index,
                           std::uint32_t msr,
                           std::uint64_t* out_value);

    // Diagnostics: scale used in the Reference TSC page (testable).
    std::uint64_t tsc_scale() const noexcept { return tsc_scale_; }
    std::uint64_t tsc_hz() const noexcept { return tsc_hz_; }

    // M33.3 save/restore: snapshot of the MSR cache. The four values are
    // raw guest-visible MSR contents; restoring them with ApplyState is
    // equivalent to having seen the guest WRMSR each one in order.
    // ApplyState does NOT republish the Reference TSC page or the
    // hypercall page — the saved guest RAM bytes already contain them,
    // and the scale recomputed from `tsc_hz_` (passed at construction)
    // must match the captured save (Phase 33.6 callers must validate
    // host_tsc_hz before constructing HvEnlightenment).
    struct State {
        std::uint64_t guest_os_id;
        std::uint64_t hypercall_msr;
        std::uint64_t reference_tsc_msr;
        std::uint64_t tsc_invariant_ctl;
    };
    static_assert(sizeof(State) == 32, "HvEnlightenment::State must be 32 bytes");

    State CaptureState();
    void  ApplyState(const State& s);

private:
    // Write the Reference TSC page at the given guest PFN. The page is
    // expected to live inside the guest's primary RAM region. Returns false
    // on invalid GPA (out of range or last-page overflow); the caller can
    // then choose to inject #GP. Currently we accept silently and just
    // drop the update -- Linux falls back to RDMSR TIME_REF_COUNT.
    bool WriteReferenceTscPage(std::uint64_t guest_pfn);

    // Fill the hypercall page at the given guest PFN with a minimal safe
    // stub: `mov eax, 2 (HV_STATUS_INVALID_HYPERCALL_CODE); ret`. We don't
    // advertise any feature that would route Linux into a hypercall, but
    // leaving the page as undefined memory would crash the kernel if a
    // future path ever does call into hv_hypercall_pg.
    bool WriteHypercallPage(std::uint64_t guest_pfn);

    // Compute the current 100ns-domain counter from the current host TSC
    // value. Same formula as the Reference TSC page (offset=0): used to
    // service RDMSR HV_X64_MSR_TIME_REF_COUNT.
    std::uint64_t Read100nsCounter() const noexcept;

    GuestMemory*  ram_;            // nullptr in the test-only constructor
    std::uint64_t tsc_hz_;
    std::uint64_t tsc_scale_;     // (10^7 << 64) / tsc_hz, precomputed once

    std::mutex    mu_;
    std::uint64_t guest_os_id_       = 0;
    std::uint64_t hypercall_msr_     = 0;
    std::uint64_t reference_tsc_msr_ = 0;
    std::uint64_t tsc_invariant_ctl_ = 0;
};

// Helper exposed for tests: compute `(10^7 << 64) / tsc_hz`. Returns 0 when
// the divisor is 0 to avoid a hardware-trap divide-by-zero.
std::uint64_t ComputeTscScale(std::uint64_t tsc_hz) noexcept;

// Helper exposed for tests: render the Hyper-V vendor "Microsoft Hv" packed
// across three little-endian dwords. Returned via out parameters so the
// caller can compare against CPUID.40000000H:EBX/ECX/EDX directly.
void GetHvVendorEbxEcxEdx(std::uint32_t* ebx,
                          std::uint32_t* ecx,
                          std::uint32_t* edx) noexcept;

// Helper exposed for tests: Hyper-V interface signature "Hv#1" packed into
// CPUID.40000001H:EAX (= 0x31237648 little-endian).
std::uint32_t GetHvInterfaceEax() noexcept;

}  // namespace tinyvmm::whp
