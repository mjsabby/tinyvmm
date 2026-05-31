#pragma once

// M33.3 vCPU state capture/apply for save/restore.
//
// Defines the canonical register-name arrays used to snapshot a single
// vCPU and the helpers that round-trip a `CapturedVcpuState` through the
// WHP State API. Lifted from `RunSaveRestoreProbe` (M33.2) so the same
// code paths are exercised by both the host-side probe/round-trip tests
// AND the production `--save` / `--restore` code paths.
//
// Capture/apply ordering (validated by `--save-restore-probe`):
//   Capture: arch -> timing -> intr_ctl (individually, with ok bits) ->
//            XSAVE blob -> APIC blob (may be empty).
//   Apply  : arch -> XSAVE -> APIC (if non-empty) -> intr_ctl
//            (individually, only entries marked ok at capture) -> timing.
//
// Rationale (rubber-duck-approved):
//   * Arch registers MUST come before XSAVE on apply, because XSAVE
//     interpretation depends on XCR0 / CR4.OSXSAVE which live in the
//     arch register set.
//   * APIC blob requires ApicBase to have been set (it lives in arch).
//   * Interrupt-control registers (high-bit "synthetic") can be
//     read-only on some WHP builds (observed: InternalActivityState
//     returns HRESULT 0xC0350006 on apply). Set them individually so a
//     failure pinpoints the offending register; tolerate failure with a
//     WARN.
//   * Timing registers (Tsc, TscAux) apply LAST to minimize wall-clock
//     skew between capture and apply. Phase 33.6 SMP path will set TSC
//     back-to-back across all vCPUs as the final step.

#include "vcpu.h"

#include <Windows.h>
#include <WinHvPlatform.h>
#include <WinHvPlatformDefs.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace tinyvmm::whp::snapshot {

// Architectural register set: GPRs, segments, tables, control, debug,
// MSR-as-register. Excludes Tsc / TscAux (kept in kTimingRegNames so
// they can be applied last) and the interrupt-control synthetic
// registers (kept in kIntrCtlRegNames so they can be applied
// individually).
extern const WHV_REGISTER_NAME kArchRegNames[];
std::size_t kArchRegCount() noexcept;

// Timing registers. Applied LAST during restore to minimize skew.
extern const WHV_REGISTER_NAME kTimingRegNames[];
std::size_t kTimingRegCount() noexcept;

// Interrupt-control synthetic register names. Get/Set individually so
// a failure pinpoints the offender; some WHP builds reject some.
extern const WHV_REGISTER_NAME kIntrCtlRegNames[];
std::size_t kIntrCtlRegCount() noexcept;

// M33.7: supervisor MSRs that affect XSAVES/XRSTORS validation. Always
// captured/applied individually with per-register ok bits because older
// WHP runtimes may not implement all of them, and the CET MSRs are
// gated by guest CET enablement (which depends on host CPUID + Linux
// kernel config). MUST be applied BEFORE the XSAVE blob, because
// XRSTORS validates supervisor state bits in XSTATE_BV/XCOMP_BV
// against IA32_XSS (0xDA0).
//
// Without this set, a Linux 6.6+ guest with CET enabled at boot saves
// a compacted XSAVE area with bit 11 (CET_U) / bit 12 (CET_S) set in
// XSTATE_BV and bit 63 (compact) set in XCOMP_BV. On restore, the
// kernel's first XRSTORS faults (#GP) because IA32_XSS reads back as
// zero on the fresh partition.
extern const WHV_REGISTER_NAME kSupervisorMsrNames[];
std::size_t kSupervisorMsrCount() noexcept;

// All state captured for a single vCPU. Pure value type — owns its own
// buffers, safe to move, default-constructible.
struct CapturedVcpuState {
    std::vector<WHV_REGISTER_VALUE> arch;       // size == kArchRegCount()
    std::vector<WHV_REGISTER_VALUE> timing;     // size == kTimingRegCount()
    std::vector<WHV_REGISTER_VALUE> intr_ctl;   // size == kIntrCtlRegCount()
    std::vector<bool>               intr_ctl_ok;// size == kIntrCtlRegCount()
    std::vector<WHV_REGISTER_VALUE> sup_msr;    // size == kSupervisorMsrCount()
    std::vector<bool>               sup_msr_ok; // size == kSupervisorMsrCount()
    std::vector<std::uint8_t>       xsave;      // size from WHP query (typ ~872)
    std::vector<std::uint8_t>       apic;       // size from WHP query; 0 if LAPIC not enabled
};

// Captures live state from `vp`. Resizes `out`'s vectors to the
// canonical sizes. Throws HrError on hard failures; logs a WARN to
// stderr and clears `out.apic` if APIC read fails (real-mode probes
// with no LAPIC emulation).
void CaptureVcpuState(Vcpu& vp,
                      WHV_PARTITION_HANDLE part,
                      std::uint32_t vp_idx,
                      CapturedVcpuState& out);

// Applies state in the rubber-duck-approved order. Tolerates:
//   * APIC blob empty (skipped)
//   * Individual intr_ctl entries failing (logged WARN, continue)
// Throws HrError on hard failures (arch SetRegisters, XSAVE).
void ApplyVcpuState(Vcpu& vp,
                    WHV_PARTITION_HANDLE part,
                    std::uint32_t vp_idx,
                    const CapturedVcpuState& in);

// Applies everything EXCEPT the timing (Tsc / TscAux) registers:
// arch -> XSAVE -> APIC (if non-empty) -> intr_ctl (individually).
// Used by Phase 33.6 production restore so the SMP path can apply
// TSC back-to-back across every vCPU as a final pass, minimizing
// observable cross-vCPU TSC skew.
void ApplyVcpuStateNonTiming(Vcpu& vp,
                             WHV_PARTITION_HANDLE part,
                             std::uint32_t vp_idx,
                             const CapturedVcpuState& in);

// Applies only the timing (Tsc / TscAux) registers. Must be called
// AFTER ApplyVcpuStateNonTiming on the same vCPU. The Phase 33.6
// production restore path calls this back-to-back across every vCPU
// after ALL non-timing state has been applied everywhere else
// (devices + every other vCPU's non-timing state).
void ApplyVcpuStateTiming(Vcpu& vp,
                          WHV_PARTITION_HANDLE part,
                          std::uint32_t vp_idx,
                          const CapturedVcpuState& in);

}  // namespace tinyvmm::whp::snapshot
