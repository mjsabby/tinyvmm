//! The shared error type now lives in the `winsys` crate (so the host/WHP FFI
//! wrappers can share it). Re-exported here as `crate::error` so existing paths
//! throughout the binary keep working unchanged.

pub use winsys::error::{Error, Result, check_hr};
