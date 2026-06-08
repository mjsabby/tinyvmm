//! BootTimer: minimal QPC-based phase timing for tinyvmm boot. Port of
//! src/diag/boot_timer.h.
//!
//! Records named waypoints from T0 (construction). Prints elapsed milliseconds
//! (total vs T0 and per-phase delta) on stderr and emits an ETW "BootMark"
//! event per `mark` so the timeline shows up in WPA alongside system events.

use crate::diag::etw;
use winsys::qpc;

pub struct BootTimer {
    freq: i64,
    t0: i64,
    last: i64,
}

impl BootTimer {
    pub fn new() -> BootTimer {
        let freq = qpc::frequency();
        let now = qpc::now();
        BootTimer {
            freq,
            t0: now,
            last: now,
        }
    }

    /// Record a phase boundary: print a `[boot]` line and emit ETW "BootMark".
    pub fn mark(&mut self, phase: &str) {
        let now = qpc::now();
        let total_ms = (now - self.t0) as f64 * 1000.0 / self.freq as f64;
        let delta_ms = (now - self.last) as f64 * 1000.0 / self.freq as f64;
        self.last = now;
        eprintln!("[boot] {total_ms:8.3} ms (+{delta_ms:7.3} ms) {phase}");
        if etw::enabled(etw::INFO, etw::kw::BOOT) {
            etw::Event::new("BootMark", etw::INFO, etw::kw::BOOT)
                .str("phase", phase)
                .f64("total_ms", total_ms)
                .f64("delta_ms", delta_ms)
                .write();
        }
    }

    /// Milliseconds since construction.
    pub fn elapsed_ms(&self) -> f64 {
        let now = qpc::now();
        (now - self.t0) as f64 * 1000.0 / self.freq as f64
    }
}

impl Default for BootTimer {
    fn default() -> Self {
        Self::new()
    }
}
