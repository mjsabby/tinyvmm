//! WHP (Windows Hypervisor Platform) bindings and the VM core.
//!
//! The low-level WHP FFI wrappers (partition, guest memory, virtual processors,
//! MSI) now live in the separately-auditable `whpsys` crate and are re-exported
//! here so existing `crate::whp::*` paths keep working. The domain logic that
//! *uses* those wrappers — the per-vCPU run loop + instruction emulator, CPUID
//! policy, Hyper-V enlightenment, save/restore, CPU affinity — stays in the
//! binary.

pub mod cpu_affinity {
    pub use winsys::cpu_affinity::*;
}
pub mod cpuid;
pub mod hv;
pub mod run_loop;
pub mod snapshot;
pub mod snapshot_file;
pub mod vcpu_state;

// Facades over the whpsys crate (keep `crate::whp::memory::*` etc. resolving).
pub mod memory {
    pub use whpsys::memory::*;
}
pub mod partition {
    pub use whpsys::partition::*;
}
pub mod vcpu {
    pub use whpsys::vcpu::*;
}
pub mod regs {
    pub use whpsys::regs::*;
}
pub mod msi {
    pub use whpsys::msi::*;
}
pub mod emulator {
    pub use whpsys::emulator::*;
}

pub use memory::GuestMemory;
pub use partition::Partition;
pub use vcpu::Vcpu;
