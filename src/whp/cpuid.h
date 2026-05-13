#pragma once

#include <Windows.h>
#include <WinHvPlatform.h>
#include <WinHvPlatformDefs.h>

#include <cstdint>

namespace tinyvmm::whp {

// Computed CPUID values returned to the guest after we apply tinyvmm policy.
struct CpuidResult {
    std::uint32_t eax;
    std::uint32_t ebx;
    std::uint32_t ecx;
    std::uint32_t edx;
};

// Compute the values we want to return for a guest CPUID exit. Inputs are the
// guest-supplied leaf and subleaf, and the host-default values WHP would have
// returned on its own (taken from WHV_X64_CPUID_ACCESS_CONTEXT).
//
// Policy (geared at letting a tiny Linux guest pick the TSC clocksource and
// skip PIT calibration without any MSR / hypercall traffic):
//   * Leaf 0x00: raise max-standard-leaf to >= 0x16 if needed.
//   * Leaf 0x01: force ECX[24]=1 (tsc-deadline) and ECX[31]=1 (hypervisor).
//   * Leaf 0x06: force EAX[2]=1 (ARAT: APIC timer always running).
//   * Leaf 0x15: TSC/core-crystal ratio, ECX = host TSC frequency in Hz.
//   * Leaf 0x16: CPU base/max/bus frequency hint in MHz.
//   * Leaf 0x80000007: force EDX[8]=1 (invariant_tsc).
//   * Leaf 0x40000000: max hypervisor leaf 0x40000001 + vendor "TinyVMM".
//   * Leaf 0x40000001: interface signature "TVMM".
//   * Leaves 0x40000002..0x400000FF: zeroed.
//
// All other leaves are returned exactly as WHP defaulted them. The guest will
// thus see real-host CPU vendor / family / cache topology, which is what we
// want for now.
CpuidResult ResolveCpuid(std::uint32_t leaf,
                         std::uint32_t subleaf,
                         std::uint32_t default_eax,
                         std::uint32_t default_ebx,
                         std::uint32_t default_ecx,
                         std::uint32_t default_edx) noexcept;

}  // namespace tinyvmm::whp
