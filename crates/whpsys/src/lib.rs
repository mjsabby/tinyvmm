//! whpsys — safe wrappers over the Windows Hypervisor Platform (WHP).
//!
//! This crate concentrates the hypervisor-interface `unsafe` (the most
//! security-sensitive FFI in the project) into one small, separately-auditable
//! place: the partition, guest-physical memory mapping + typed accessors,
//! virtual processors (register/XSAVE/APIC/interrupt-controller get-set, run,
//! cancel), and MSI injection. The main binary's device + dispatch logic
//! consumes these safe APIs.
//!
//! `crate::error` / `crate::host` are re-exported from `winsys` so the moved
//! modules compile unchanged.

pub use winsys::error;
pub use winsys::host;

pub mod doorbell;
pub mod emulator;
pub mod memory;
pub mod msi;
pub mod partition;
pub mod regs;
pub mod vcpu;
pub mod vpci;
pub use memory::GuestMemory;
pub use partition::Partition;
pub use vcpu::Vcpu;
