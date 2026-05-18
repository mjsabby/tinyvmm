#include "hv_enlightenment.h"

#include <Windows.h>
#include <intrin.h>

#include <cstdio>
#include <cstring>

namespace tinyvmm::whp {

namespace {

constexpr std::uint64_t kPageSize  = 4096;
constexpr std::uint64_t kPageShift = 12;

// HV_STATUS_INVALID_HYPERCALL_CODE (TLFS): returned in rax by the stub we
// install in the hypercall page so Linux's `hv_do_hypercall` returns "I
// didn't recognise that call" rather than executing garbage bytes. The
// numeric value is baked into the byte sequence below; the named constant
// is kept here only so future hypercall-related code has somewhere to
// reference it.
[[maybe_unused]] constexpr std::uint64_t kHvStatusInvalidHypercallCode = 0x0002u;

// 7-byte stub: `mov eax, 2; ret`. Standard System V/x86-64 calling
// convention puts the return value in rax; HV_STATUS_INVALID_HYPERCALL_CODE
// fits in the low 16 bits so writing the low 32 is enough.
constexpr std::uint8_t kHypercallStub[] = {
    0xB8, 0x02, 0x00, 0x00, 0x00,  // mov eax, 0x00000002
    0xC3,                          // ret
};

}  // namespace

std::uint64_t ComputeTscScale(std::uint64_t tsc_hz) noexcept {
    if (tsc_hz == 0) return 0;
    // We want (10^7 << 64) / tsc_hz. The MSVC intrinsic does this directly;
    // clang-cl doesn't expose `_udiv128` and the `__int128` division route
    // emits a `__udivti3` reference that links only against compiler-rt
    // builtins. To stay portable we fall back to a shift-subtract long
    // division on Clang -- 64 iterations of u64 ops, runs once per VM, so
    // the speed cost is irrelevant.
#if defined(__clang__)
    // Precondition: numerator_high < divisor so the quotient fits in 64 bits.
    // 10^7 (numerator_high) is always less than tsc_hz on any modern CPU.
    std::uint64_t high = 10'000'000ull;
    std::uint64_t low  = 0ull;
    std::uint64_t q    = 0ull;
    for (int i = 0; i < 64; ++i) {
        // Shift 128-bit (high:low) left by 1, capturing the bit that
        // overflows out of the top of `high`.
        const bool overflow = (high >> 63) != 0;
        high = (high << 1) | (low >> 63);
        low <<= 1;
        q <<= 1;
        if (overflow || high >= tsc_hz) {
            high -= tsc_hz;
            q |= 1ull;
        }
    }
    return q;
#else
    // _udiv128(high, low, divisor, &rem): 128/64 -> 64 with remainder.
    std::uint64_t remainder = 0;
    return _udiv128(/*high=*/10'000'000ull, /*low=*/0ull, tsc_hz, &remainder);
#endif
}

void GetHvVendorEbxEcxEdx(std::uint32_t* ebx,
                          std::uint32_t* ecx,
                          std::uint32_t* edx) noexcept {
    // "Microsoft Hv" -- 12 bytes, packed across three little-endian dwords.
    *ebx = static_cast<std::uint32_t>('M')
         | static_cast<std::uint32_t>('i') << 8
         | static_cast<std::uint32_t>('c') << 16
         | static_cast<std::uint32_t>('r') << 24;
    *ecx = static_cast<std::uint32_t>('o')
         | static_cast<std::uint32_t>('s') << 8
         | static_cast<std::uint32_t>('o') << 16
         | static_cast<std::uint32_t>('f') << 24;
    *edx = static_cast<std::uint32_t>('t')
         | static_cast<std::uint32_t>(' ') << 8
         | static_cast<std::uint32_t>('H') << 16
         | static_cast<std::uint32_t>('v') << 24;
}

std::uint32_t GetHvInterfaceEax() noexcept {
    // "Hv#1" -- the Hyper-V Top-Level-Functional-Spec interface signature.
    // Linux's `ms_hyperv_platform` only matches a host as Hyper-V when this
    // dword reads exactly this value (memcmp("Hv#1", &eax, 4)).
    return static_cast<std::uint32_t>('H')
         | static_cast<std::uint32_t>('v') << 8
         | static_cast<std::uint32_t>('#') << 16
         | static_cast<std::uint32_t>('1') << 24;
}

HvEnlightenment::HvEnlightenment(GuestMemory& ram, std::uint64_t tsc_hz)
    : ram_(&ram),
      tsc_hz_(tsc_hz),
      tsc_scale_(ComputeTscScale(tsc_hz)) {}

HvEnlightenment::HvEnlightenment(std::uint64_t tsc_hz)
    : ram_(nullptr),
      tsc_hz_(tsc_hz),
      tsc_scale_(ComputeTscScale(tsc_hz)) {}

std::uint64_t HvEnlightenment::Read100nsCounter() const noexcept {
    // Match the Reference TSC page formula with offset=0:
    //   100ns_count = (rdtsc * tsc_scale_) >> 64
    // __umulh on MSVC produces the high 64 bits of a 64x64 -> 128 multiply,
    // which is exactly what we need.
    const std::uint64_t tsc = __rdtsc();
    return __umulh(tsc, tsc_scale_);
}

bool HvEnlightenment::WriteReferenceTscPage(std::uint64_t guest_pfn) {
    if (ram_ == nullptr) return false;
    const std::uint64_t gpa = guest_pfn << kPageShift;

    // Guard against the page straddling the end of the RAM region. This
    // catches malicious guests handing us a PFN one past the end -- the
    // base HostPointer check would succeed for the first byte but writing
    // 4 KiB would overrun the mapping.
    if (gpa + kPageSize < gpa) return false;  // GPA overflow
    if (gpa >= ram_->size())   return false;
    if (gpa + kPageSize > ram_->size()) return false;

    void* host = ram_->HostPointer(gpa);
    if (host == nullptr) return false;

    auto* page = static_cast<std::uint8_t*>(host);

    // Zero the whole page first, then write the header in the prescribed
    // order: sequence=0 (mark invalid), barrier, scale+offset, barrier,
    // sequence=1 (mark valid). Even though the guest hasn't started reading
    // yet -- this is its first write to the MSR -- we follow the protocol
    // to be conservative against re-enables on resume.
    std::memset(page, 0, kPageSize);

    HvReferenceTscPage header{};
    header.tsc_sequence = 0;
    header.reserved1    = 0;
    header.tsc_scale    = tsc_scale_;
    header.tsc_offset   = 0;

    // Step 1: write sequence=0 + scale + offset.
    std::memcpy(page, &header, sizeof(header));
    // Step 2: full barrier before publishing.
    std::atomic_thread_fence(std::memory_order_release);
    // Step 3: flip sequence to a stable non-zero value.
    header.tsc_sequence = 1;
    std::memcpy(page, &header.tsc_sequence, sizeof(header.tsc_sequence));

    return true;
}

bool HvEnlightenment::WriteHypercallPage(std::uint64_t guest_pfn) {
    if (ram_ == nullptr) return false;
    const std::uint64_t gpa = guest_pfn << kPageShift;
    if (gpa + kPageSize < gpa) return false;
    if (gpa >= ram_->size())   return false;
    if (gpa + kPageSize > ram_->size()) return false;

    void* host = ram_->HostPointer(gpa);
    if (host == nullptr) return false;

    auto* page = static_cast<std::uint8_t*>(host);
    std::memset(page, 0, kPageSize);
    std::memcpy(page, kHypercallStub, sizeof(kHypercallStub));
    return true;
}

MsrHandled HvEnlightenment::HandleWrmsr(std::uint32_t /*vp_index*/,
                                       std::uint32_t msr,
                                       std::uint64_t value) {
    std::lock_guard<std::mutex> lock(mu_);
    switch (msr) {
        case kHvMsrGuestOsId: {
            // Linux writes a packed (vendor|os|major|minor|build) identifier
            // here at boot. We don't need to interpret it; just remember it
            // so RDMSR reads back the same value.
            guest_os_id_ = value;
            return MsrHandled::Yes;
        }

        case kHvMsrHypercall: {
            // Bit 0 = Enable, bits 1..11 = reserved, bits 12.. = GPA PFN.
            hypercall_msr_ = value;
            if ((value & 0x1ull) != 0) {
                const std::uint64_t pfn = value >> kPageShift;
                if (!WriteHypercallPage(pfn)) {
                    std::fprintf(stderr,
                        "[hv] WRMSR HYPERCALL: bad PFN=0x%llx (page outside "
                        "guest RAM); accepting MSR but leaving page "
                        "untouched\n",
                        static_cast<unsigned long long>(pfn));
                }
            }
            return MsrHandled::Yes;
        }

        case kHvMsrReferenceTsc: {
            reference_tsc_msr_ = value;
            if ((value & 0x1ull) != 0) {
                const std::uint64_t pfn = value >> kPageShift;
                if (!WriteReferenceTscPage(pfn)) {
                    std::fprintf(stderr,
                        "[hv] WRMSR REFERENCE_TSC: bad PFN=0x%llx (page "
                        "outside guest RAM); accepting MSR but leaving "
                        "page untouched -- guest will fall back to RDMSR "
                        "TIME_REF_COUNT\n",
                        static_cast<unsigned long long>(pfn));
                }
            }
            return MsrHandled::Yes;
        }

        case kHvMsrTscInvariantCtl: {
            // Linux writes HV_EXPOSE_INVARIANT_TSC (= 1) and then sets
            // X86_FEATURE_TSC_RELIABLE, which is what actually disables
            // the clocksource watchdog for TSC. We don't need to do
            // anything host-side; just acknowledge the write.
            tsc_invariant_ctl_ = value;
            return MsrHandled::Yes;
        }

        default:
            return MsrHandled::NoInjectGp;
    }
}

MsrHandled HvEnlightenment::HandleRdmsr(std::uint32_t vp_index,
                                       std::uint32_t msr,
                                       std::uint64_t* out_value) {
    std::lock_guard<std::mutex> lock(mu_);
    switch (msr) {
        case kHvMsrGuestOsId:
            *out_value = guest_os_id_;
            return MsrHandled::Yes;

        case kHvMsrHypercall:
            *out_value = hypercall_msr_;
            return MsrHandled::Yes;

        case kHvMsrVpIndex:
            *out_value = static_cast<std::uint64_t>(vp_index);
            return MsrHandled::Yes;

        case kHvMsrTimeRefCount:
            // TIME_REF_COUNT is the fall-back reference counter the guest
            // reads if `tsc_sequence == 0` in the Reference TSC page. Same
            // formula, no offset.
            *out_value = Read100nsCounter();
            return MsrHandled::Yes;

        case kHvMsrReferenceTsc:
            *out_value = reference_tsc_msr_;
            return MsrHandled::Yes;

        case kHvMsrTscInvariantCtl:
            *out_value = tsc_invariant_ctl_;
            return MsrHandled::Yes;

        default:
            *out_value = 0;
            return MsrHandled::NoInjectGp;
    }
}

}  // namespace tinyvmm::whp
