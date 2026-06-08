//! Minimal PCI host bridge + Type-0 device model. Port of src/pci/.

pub mod bus;
pub mod config;
pub mod msix;
pub mod passthrough;

pub use bus::PciBus;
pub use config::BarKind;

// Configuration Mechanism #1 ports.
pub const CONFIG_ADDRESS_PORT: u16 = 0xCF8;
pub const CONFIG_DATA_PORT: u16 = 0xCFC;
pub const CONFIG_ADDRESS_ENABLE: u32 = 0x8000_0000;

// Type-0 header offsets.
pub const CFG_VENDOR_ID: u32 = 0x00;
pub const CFG_DEVICE_ID: u32 = 0x02;
pub const CFG_COMMAND: u32 = 0x04;
pub const CFG_STATUS: u32 = 0x06;
pub const CFG_REVISION_ID: u32 = 0x08;
pub const CFG_PROG_IF: u32 = 0x09;
pub const CFG_SUBCLASS: u32 = 0x0A;
pub const CFG_CLASS_CODE: u32 = 0x0B;
pub const CFG_CACHE_LINE_SIZE: u32 = 0x0C;
pub const CFG_LATENCY_TIMER: u32 = 0x0D;
pub const CFG_HEADER_TYPE: u32 = 0x0E;
pub const CFG_BAR0: u32 = 0x10;
pub const CFG_SUBSYS_VENDOR_ID: u32 = 0x2C;
pub const CFG_SUBSYS_ID: u32 = 0x2E;
pub const CFG_CAP_PTR: u32 = 0x34;
pub const CFG_INTERRUPT_LINE: u32 = 0x3C;
pub const CFG_INTERRUPT_PIN: u32 = 0x3D;

pub const CFG_SPACE_SIZE: u32 = 0x100;
pub const CAP_LIST_START: u32 = 0x40;

// COMMAND register bits.
pub const CMD_IO_SPACE: u16 = 1 << 0;
pub const CMD_MEMORY_SPACE: u16 = 1 << 1;

// STATUS register bits.
pub const STATUS_CAP_LIST: u16 = 1 << 4;

pub const HEADER_TYPE_NORMAL: u8 = 0x00;

// BAR type-encoding bits.
pub const BAR_IO_MARKER: u32 = 1 << 0;
pub const BAR_MMIO64: u32 = 2 << 1;
pub const BAR_PREFETCHABLE: u32 = 1 << 3;

// Capability IDs.
pub const CAP_ID_VENDOR: u8 = 0x09;
pub const CAP_ID_MSIX: u8 = 0x11;

/// Bus/device/function identifier (single bus 0).
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Bdf {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

pub struct DecodedAddress {
    pub enable: bool,
    pub bus: u8,
    pub dev: u8,
    pub fn_: u8,
    pub reg: u8,
}

pub fn decode_config_address(addr: u32) -> DecodedAddress {
    DecodedAddress {
        enable: (addr & CONFIG_ADDRESS_ENABLE) != 0,
        bus: ((addr >> 16) & 0xFF) as u8,
        dev: ((addr >> 11) & 0x1F) as u8,
        fn_: ((addr >> 8) & 0x07) as u8,
        reg: (addr & 0xFC) as u8,
    }
}

/// A PCI function the bus can route config accesses to.
pub trait PciFunction: Send + Sync {
    fn name(&self) -> &str;
    fn config_read(&self, offset: u32, size: u32) -> u32;
    fn config_write(&self, offset: u32, size: u32, value: u32);
    /// (kind, size) for each of the 6 BARs (for the bus's pre-assignment).
    fn bar_layout(&self) -> [(BarKind, u32); 6];
    /// Program a pre-assigned base GPA into BAR `idx`.
    fn assign_bar_base(&self, idx: usize, gpa: u64);
}
