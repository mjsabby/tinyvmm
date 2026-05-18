#pragma once

#include <Windows.h>
#include <WinHvPlatform.h>
#include <WinHvPlatformDefs.h>

#include <cstdint>
#include <vector>

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
// skip PIT calibration without any MSR / hypercall traffic, plus advertise
// the Hyper-V Reference TSC page so the kernel's `clocksource watchdog`
// stops complaining about TSC under SMP load -- see whp/hv_enlightenment.h
// for the full rationale):
//   * Leaf 0x00: raise max-standard-leaf to >= 0x16 if needed.
//   * Leaf 0x01: force ECX[24]=1 (tsc-deadline, see SetHideTscDeadline) and
//                ECX[31]=1 (hypervisor).
//   * Leaf 0x06: force EAX[2]=1 (ARAT: APIC timer always running).
//   * Leaf 0x15: TSC/core-crystal ratio, ECX = host TSC frequency in Hz.
//   * Leaf 0x16: CPU base/max/bus frequency hint in MHz.
//   * Leaf 0x80000007: force EDX[8]=1 (invariant_tsc).
//   * Leaf 0x40000000: max hypervisor leaf 0x40000006 + vendor "Microsoft Hv".
//                      Linux's `ms_hyperv_platform()` requires both: a
//                      max-leaf >= 0x40000005 AND the literal vendor string.
//   * Leaf 0x40000001: interface signature "Hv#1" (= 0x31237648).
//   * Leaf 0x40000002: zeroed (build/version).
//   * Leaf 0x40000003: EAX = HV_MSR_HYPERCALL_AVAILABLE (bit 5)
//                          | HV_MSR_VP_INDEX_AVAILABLE  (bit 6)
//                          | HV_MSR_REFERENCE_TSC_AVAILABLE (bit 9)
//                          | HV_ACCESS_TSC_INVARIANT       (bit 15)
//                      EBX/ECX/EDX zero (no priv_high / power-mgmt / misc).
//   * Leaves 0x40000004..0x40000006: zero (no hints, no impl limits, no hw
//                      features). With hints=0 Linux skips PV TLB flush /
//                      PV IPI / SynIC / synthetic-timer enablement.
//   * Leaves 0x40000007..0x400000FF: zeroed.
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

// Build a static CPUID result list suitable for
// `WHvPartitionPropertyCodeCpuidResultList`. The list keeps WHP's internal
// architectural feature model in sync with what our runtime CPUID exit
// handler returns to the guest. WHP makes some decisions (e.g. about LAPIC
// behaviour) at SetupPartition time based on this list rather than on
// runtime-handled CPUID values, so providing it explicitly avoids surprises
// when the static and runtime views drift.
//
// Note: empirically WHP does NOT implement IA32_TSC_DEADLINE (MSR 0x6E0) in
// its LAPIC emulation -- WRMSR 0x6E0 is rejected even when CPUID.01H:ECX[24]
// is set in this list. Callers should default to passing
// `hide_tsc_deadline = true` so Linux uses LAPIC oneshot from the start
// instead of issuing a doomed WRMSR.
//
// If `hide_tsc_deadline` is true, CPUID.01H:ECX[24] is cleared in this
// static list AND the runtime handler is told to clear it too (via
// `SetHideTscDeadline(true)` -- callers should do both together).
std::vector<WHV_X64_CPUID_RESULT> BuildStaticCpuidResultList(
    bool hide_tsc_deadline = true);

// Runtime knob used by `ResolveCpuid`. When set, leaf 0x01 ECX[24] is masked
// off so the runtime CPUID handler returns the same view as the static list
// built with `hide_tsc_deadline=true`. Off by default; flip to true together
// with `BuildStaticCpuidResultList(true)`.
void SetHideTscDeadline(bool hide) noexcept;
bool GetHideTscDeadline() noexcept;

// Measure (and cache) the host TSC frequency in Hz. First call probes
// CPUID.15h, then CPUID.16h, then falls back to a 50 ms QPC calibration.
// All subsequent calls return the cached value. Exposed so callers building
// other TSC-dependent state (e.g. the Hyper-V Reference TSC page) use the
// exact same number we publish via CPUID.15h to the guest.
std::uint64_t GetCachedTscHz() noexcept;

}  // namespace tinyvmm::whp
