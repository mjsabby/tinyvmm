//! Kernel boot support: ACPI table generation, the PVH ELF loader and the
//! bzImage (Linux boot protocol) loader.

pub mod acpi;
pub mod bzimage;
pub mod loader;
pub mod payload;

use crate::error::Result;
use crate::whp::{GuestMemory, Vcpu};

/// A kernel staged in guest RAM by whichever loader its format needs.
pub enum KernelLoad {
    /// An ELF `vmlinux` entered through its PVH note.
    Pvh(loader::PvhLoadResult),
    /// A compressed `bzImage` entered through the Linux/x86 boot protocol.
    BzImage(bzimage::BzImageLoad),
}

impl KernelLoad {
    /// Load `image` (a bzImage, or else a PVH ELF) with its initramfs and the
    /// boot data that describe the machine.
    pub fn load(
        ram: &GuestMemory,
        image: &[u8],
        cmdline: &str,
        ram_bytes: u64,
        initramfs: Option<&[u8]>,
        vcpu_count: u32,
    ) -> Result<Self> {
        if bzimage::is_bzimage(image) {
            bzimage::load(ram, image, cmdline, ram_bytes, initramfs, vcpu_count).map(Self::BzImage)
        } else {
            loader::load_pvh(ram, image, cmdline, ram_bytes, initramfs, vcpu_count).map(Self::Pvh)
        }
    }

    /// Put the boot vCPU at the kernel's entry point.
    pub fn setup_entry(&self, vp: &Vcpu) -> Result<()> {
        match self {
            Self::Pvh(load) => loader::setup_pvh_entry(vp, load),
            Self::BzImage(load) => bzimage::setup_entry(vp, load),
        }
    }

    /// One-line summary for the boot log.
    pub fn describe(&self) -> String {
        match self {
            Self::Pvh(l) => format!(
                "loaded {} bytes; entry=0x{:08x} start_info_gpa=0x{:x}",
                l.bytes_loaded, l.entry_point, l.start_info_gpa
            ),
            Self::BzImage(l) => format!(
                "loaded {} bytes (bzImage, boot protocol {}.{:02}); entry=0x{:08x} boot_params_gpa=0x{:x}",
                l.bytes_loaded,
                l.version >> 8,
                l.version & 0xFF,
                l.entry_point,
                l.boot_params_gpa
            ),
        }
    }

    /// Where the initramfs went: `(gpa, size)`, size 0 if none.
    pub fn initramfs(&self) -> (u64, u64) {
        match self {
            Self::Pvh(l) => (l.initramfs_gpa, l.initramfs_size),
            Self::BzImage(l) => (l.initramfs_gpa, l.initramfs_size),
        }
    }
}
