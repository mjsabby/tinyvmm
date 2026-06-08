//! Diagnostics: ETW (Event Tracing for Windows) instrumentation + boot timing.

pub mod alloc_trace;
pub mod boot_timer;

/// ETW TraceLogging now lives in the `winsys` crate (FFI concentration);
/// re-exported here so `crate::diag::etw::*` paths keep working.
pub mod etw {
    pub use winsys::etw::*;
}
