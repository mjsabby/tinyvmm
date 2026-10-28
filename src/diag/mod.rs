//! Diagnostics: ETW (Event Tracing for Windows) instrumentation + boot timing.

pub mod alloc_trace;
pub mod boot_timer;

/// ETW TraceLogging now lives in the `winsys` crate (FFI concentration);
/// re-exported here so `crate::diag::etw::*` paths keep working.
pub mod etw {
    pub use winsys::etw::*;
}

/// Whether `TINYVMM_NET_DIAG` asks for live network diagnostics (host/guest
/// stall lines, per-flow loss summaries, RX backlog drops) on stderr: set to
/// a non-empty value whose first char isn't '0'. Read once, so hot paths can
/// gate on it for the cost of an atomic load. The always-on counters behind
/// the exit summary don't depend on it.
pub fn net_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        std::env::var("TINYVMM_NET_DIAG")
            .map(|v| !v.is_empty() && !v.starts_with('0'))
            .unwrap_or(false)
    })
}
