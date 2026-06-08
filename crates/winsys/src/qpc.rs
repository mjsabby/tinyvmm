//! QueryPerformanceCounter / -Frequency wrappers (high-resolution monotonic
//! timing). Concentrates the QPC FFI so callers (e.g. the boot timer) stay safe.

use windows_sys::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};

/// QueryPerformanceCounter ticks. Monotonic on all supported Windows versions.
pub fn now() -> i64 {
    let mut t: i64 = 0;
    // SAFETY: writes a single i64 through a valid stack pointer; never fails on
    // supported platforms.
    unsafe { QueryPerformanceCounter(&mut t) };
    t
}

/// QueryPerformanceFrequency ticks-per-second (never zero — returns 1 on the
/// impossible failure so callers can divide safely).
pub fn frequency() -> i64 {
    let mut f: i64 = 0;
    // SAFETY: as above.
    unsafe { QueryPerformanceFrequency(&mut f) };
    if f == 0 {
        1
    } else {
        f
    }
}
