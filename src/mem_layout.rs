//! Guest-physical address-space layout constants shared by the PVH loader, the
//! PCI BAR allocator, and the guest-RAM allocator.
//!
//! The 32-bit PCI MMIO window (device BARs) is pre-assigned at a fixed location
//! just below the IOAPIC/LAPIC region. Guest RAM may not overlap it, so RAM
//! larger than [`MMIO_WINDOW_BASE`] is split: the first [`MMIO_WINDOW_BASE`]
//! bytes stay at GPA 0 and the remainder is relocated to [`HIGH_RAM_BASE`]
//! (4 GiB), leaving `[MMIO_WINDOW_BASE, HIGH_RAM_BASE)` free for BARs.

/// Base of the pre-assigned 32-bit PCI MMIO BAR window (3584 MiB).
pub const MMIO_WINDOW_BASE: u64 = 0xE000_0000;

/// End of the MMIO BAR window (just below the IOAPIC at `0xFEC0_0000`).
pub const MMIO_WINDOW_END: u64 = 0xFEC0_0000;

/// GPA where guest RAM beyond [`MMIO_WINDOW_BASE`] is remapped (4 GiB).
pub const HIGH_RAM_BASE: u64 = 0x1_0000_0000;
