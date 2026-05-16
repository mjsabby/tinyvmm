#pragma once

#include <Windows.h>
#include <WinHvPlatform.h>
#include <WinHvPlatformDefs.h>

#include "common.h"

namespace tinyvmm::whp {

// RAII wrapper around a WHV partition handle. Encapsulates the create / set
// properties / setup lifecycle. Properties are set in the c'tor and
// SetupPartition() finalizes the partition so vCPUs and memory regions can be
// created.
//
// Usage:
//   Partition p(/*vcpu_count=*/1);
//   p.EnableExtendedExits({.cpuid = true, .msr = true});
//   p.SetLocalApicEmulation(WHvX64LocalApicEmulationModeX2Apic);
//   p.Setup();   // after this point, no more property changes
class Partition {
public:
    explicit Partition(std::uint32_t vcpu_count);
    ~Partition();

    Partition(const Partition&) = delete;
    Partition& operator=(const Partition&) = delete;

    // Bit-flags that mirror WHvPartitionPropertyCodeExtendedVmExits but typed
    // so callers don't have to deal with the union directly.
    struct ExtendedExits {
        bool cpuid = false;
        bool msr = false;
        bool exception = false;
        bool hypercall = false;
        bool gpa_access_fault = false;
    };

    void EnableExtendedExits(const ExtendedExits& bits);
    void SetLocalApicEmulation(WHV_X64_LOCAL_APIC_EMULATION_MODE mode);

    // Register a list of static CPUID leaf values. WHP reads this list at
    // SetupPartition time to inform its internal architectural feature model
    // (e.g. whether to accept WRMSR 0x6E0 / IA32_TSC_DEADLINE in its LAPIC
    // emulation). When `X64CpuidExit` is also enabled, the runtime exit
    // handler still wins for guest-visible CPUID values; the static list is
    // only consulted by WHP itself. Must be called before Setup().
    void SetCpuidResultList(const WHV_X64_CPUID_RESULT* entries,
                            std::size_t count);

    // Finalize. Required before mapping memory or creating vCPUs.
    void Setup();

    WHV_PARTITION_HANDLE handle() const noexcept { return handle_; }
    std::uint32_t vcpu_count() const noexcept { return vcpu_count_; }

private:
    WHV_PARTITION_HANDLE handle_ = nullptr;
    std::uint32_t vcpu_count_ = 0;
    bool setup_done_ = false;

    template <typename T>
    void SetProperty(WHV_PARTITION_PROPERTY_CODE code, const T& value);
};

}  // namespace tinyvmm::whp
