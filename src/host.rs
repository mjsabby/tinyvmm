//! Host Win32 helpers now live in the `winsys` crate (concentrating the host
//! FFI `unsafe` in one auditable place). Re-exported here as `crate::host` so
//! existing paths (`crate::host::random_fill`, `crate::host::block_file`, ...)
//! keep working unchanged.

pub use winsys::host::{enable_lock_memory_privilege, random_fill};

pub mod block_file {
    pub use winsys::host::block_file::*;
}

pub mod mapped_file {
    pub use winsys::host::mapped_file::*;
}
