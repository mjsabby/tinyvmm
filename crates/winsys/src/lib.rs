//! winsys — safe wrappers over the Win32 host APIs tinyvmm relies on.
//!
//! This crate exists to CONCENTRATE the host-FFI `unsafe` into one small,
//! separately-auditable place: overlapped/IOCP file I/O, memory-mapped files,
//! token privileges, large-page sizing, CNG randomness, ETW, CPU affinity, and
//! the Winsock/IOCP socket primitives. The main binary consumes the safe APIs
//! and stays (near) `unsafe`-free for host I/O.
//!
//! Several socket/IOCP/ICMP primitives take Win32 `HANDLE` / `OVERLAPPED` /
//! `SOCKET` values, which are raw-pointer-typed but are *opaque OS tokens*, not
//! dereferenceable Rust references. Clippy's `not_unsafe_ptr_arg_deref` is a
//! false positive for them, so it is allowed crate-wide; the genuinely
//! caller-unsafe async primitives (which require the OVERLAPPED + buffers to
//! outlive the operation) are marked `unsafe fn` with `# Safety` docs.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

pub mod audio;
pub mod cpu_affinity;
pub mod error;
pub mod etw;
pub mod fs;
pub mod host;
pub mod ptr;
pub mod qpc;
pub mod sock;
pub mod wintun;

pub use error::{Error, Result, check_hr, succeeded};
pub use host::block_file;
pub use host::mapped_file;
pub use ptr::SharedPtr;
