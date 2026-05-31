#pragma once

// M33 save/restore — Phase 33.1: trigger plumbing.
//
// User goal: "instant resume from a known checkpoint" — boot once, save the
// quiescent post-init state, then restore many times in ~100 ms instead of
// cold-booting in ~4 s.
//
// Trigger model: the guest signals "snapshot now" via a magic CPUID leaf.
// `/init` runs `sync; sleep 0.2`, then executes
//
//     CPUID(EAX=kMagicLeaf)
//
// via `/dev/cpu/0/cpuid` (CONFIG_X86_CPUID=y in the kernel) or a precompiled
// helper. `RunLoop::HandleCpuidExit` intercepts the leaf BEFORE
// `ResolveCpuid`:
//
//   * On any vCPU, regardless of the `--save` flag, the magic leaf always
//     returns the signature in `kSignature*` so the guest can detect support
//     safely.  This makes the magic CPUID a no-op when snapshotting is
//     disabled.
//
//   * When `g_snapshot_state.armed == true` (set by `--save <path>` argv
//     parsing), the magic leaf ALSO records the requesting vp_index and
//     returns `StopReason::SnapshotRequested`. The run loop has already
//     advanced RIP past the CPUID instruction, so the guest will resume past
//     it on restore (no re-trigger loop).
//
// SMP-safety: the magic CPUID can execute on any vCPU, not necessarily the
// BSP (the Linux scheduler decides). The "requested" flag is therefore
// partition-global, set by whichever RunLoop fires it. The main thread checks
// this flag once all RunLoops have returned and decides whether to write a
// snapshot or proceed with a normal shutdown.

#include <atomic>
#include <cstdint>
#include <string>

namespace tinyvmm::whp::snapshot {

// Magic CPUID leaf number. Lives in the Hyper-V range (0x40000000+) so the
// real host CPU never returns anything for it; the guest's view is whatever
// WHP defaults to (zeros), which we override unconditionally with the
// signature below.
//
// Mnemonic: "TINY-SAVE" (0xDE57 looks like "DEST"-rotated; chosen because
// most Microsoft-defined leaves cluster in 0x40000000..0x40000FF and
// 0x40000100..0x400001FF for Hyper-V).
inline constexpr std::uint32_t kMagicLeaf = 0x4000DE57u;

// Signature returned in (EAX, EBX, ECX, EDX) from the magic CPUID. Guests
// can compare EBX/ECX against these values to detect tinyvmm snapshot
// support before invoking the trigger.
//
// EAX = 0 (reserved for status; future versions may return non-zero if the
//          guest needs to know snapshotting is in progress)
// EBX = 'YNIT' little-endian -> spells "TINY"
// ECX = 'EVAS' little-endian -> spells "SAVE"
// EDX = version (1 = Phase 1 of M33)
inline constexpr std::uint32_t kSignatureEax = 0x00000000u;
inline constexpr std::uint32_t kSignatureEbx = 0x594E4954u;  // 'YNIT'
inline constexpr std::uint32_t kSignatureEcx = 0x45564153u;  // 'EVAS'
inline constexpr std::uint32_t kSignatureEdx = 0x00000001u;  // version

// Partition-global snapshot trigger state. Populated by `--save <path>` at
// argv parse time (armed=true, save_path=<path>). Read by every RunLoop on
// every CPUID exit; written-once by whichever RunLoop first sees the magic
// leaf with armed==true.
//
// We deliberately use a free-standing global instead of threading a
// reference through every RunLoop ctor: there is exactly one partition per
// tinyvmm process, the trigger fires at most once per process lifetime, and
// the alternative (a SnapshotState* on every RunLoop) would touch every
// test-only construction site.
struct SnapshotState {
    // Flipped true once by argv parsing when `--save <path>` is present. Read
    // by every CPUID exit; never written after argv parse.
    std::atomic<bool> armed{false};

    // Flipped true exactly once by whichever RunLoop first sees the magic
    // CPUID leaf while `armed == true`. The main thread checks this after
    // joining all RunLoops to decide whether to write a snapshot.
    std::atomic<bool> requested{false};

    // vp_index of the vCPU that fired the trigger. Diagnostic only — the
    // snapshot itself captures all vCPUs.
    std::atomic<std::uint32_t> requesting_vp_index{0};

    // Destination path passed to `--save`. Written once at argv parse; only
    // read after `armed == true` has been observed, so no atomic needed.
    std::string save_path;

    // Source path passed to `--restore`. Set by `--restore` argv parsing.
    std::string restore_path;
};

// The one-and-only global instance. Lives in snapshot.cpp.
SnapshotState& State() noexcept;

// Convenience: returns true if `armed` is set. Hot path on every CPUID exit.
inline bool IsArmed() noexcept {
    return State().armed.load(std::memory_order_acquire);
}

// Convenience: returns true if the trigger has fired (read by main after
// RunLoops join).
inline bool WasRequested() noexcept {
    return State().requested.load(std::memory_order_acquire);
}

}  // namespace tinyvmm::whp::snapshot
