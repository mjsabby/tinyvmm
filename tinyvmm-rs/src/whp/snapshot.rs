//! Save/restore trigger: a magic CPUID leaf the guest invokes to request a
//! snapshot. Port of src/whp/snapshot.{h,cpp}.
//!
//! The guest (after `sync; sleep 0.2`) issues `CPUID(EAX=0x4000DE57)` via
//! `/dev/cpu/0/cpuid` or a tiny helper. The run loop intercepts the leaf BEFORE
//! the normal CPUID policy:
//!   * Always returns the signature so the guest can detect support safely
//!     (a no-op when snapshotting is disabled).
//!   * When ARMED (set by `--save <path>`), it also records the requesting
//!     vp_index and makes the run loop return `StopReason::SnapshotRequested`.
//!     RIP is advanced past the CPUID first, so on restore the guest resumes
//!     just after it (no re-trigger loop).

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Magic CPUID leaf (Hyper-V range, so the real host CPU returns nothing for it).
pub const MAGIC_LEAF: u32 = 0x4000_DE57;

// Signature returned in (EAX, EBX, ECX, EDX): EBX='YNIT'->"TINY", ECX='EVAS'->"SAVE".
pub const SIG_EAX: u32 = 0x0000_0000;
pub const SIG_EBX: u32 = 0x594E_4954;
pub const SIG_ECX: u32 = 0x4556_4153;
pub const SIG_EDX: u32 = 0x0000_0001;

static ARMED: AtomicBool = AtomicBool::new(false);
static REQUESTED: AtomicBool = AtomicBool::new(false);
static REQ_VP: AtomicU32 = AtomicU32::new(0);

/// Arm the trigger (called once at `--save` argv parse).
pub fn arm() {
    ARMED.store(true, Ordering::Release);
}

pub fn is_armed() -> bool {
    ARMED.load(Ordering::Acquire)
}

pub fn was_requested() -> bool {
    REQUESTED.load(Ordering::Acquire)
}

pub fn requesting_vp() -> u32 {
    REQ_VP.load(Ordering::Acquire)
}

/// Called from the CPUID handler when the magic leaf fires. Records the request
/// if armed. Returns true if a snapshot was requested (the run loop should then
/// stop with `StopReason::SnapshotRequested`).
pub fn on_magic_leaf(vp_index: u32) -> bool {
    if is_armed() {
        REQ_VP.store(vp_index, Ordering::Release);
        REQUESTED.store(true, Ordering::Release);
        true
    } else {
        false
    }
}
