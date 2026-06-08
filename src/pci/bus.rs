//! PCI host bridge: turns the 0xCF8/0xCFC port pair into Type-0 config-space
//! access on a list of devices, pre-assigning BAR base addresses. Port of
//! src/pci/pci_bus.cpp.

use super::config::BarKind;
use super::{decode_config_address, Bdf, PciFunction, CONFIG_ADDRESS_PORT, CONFIG_DATA_PORT};
use crate::devices::io_bus::{IoAccess, IoBus};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

// Pre-assigned BAR windows (below the LAPIC window 0xFEE00000).
const MMIO_WINDOW_BASE: u64 = 0xE000_0000;
const MMIO_WINDOW_END: u64 = 0xFEC0_0000;

struct Slot {
    bus: u8,
    device: u8,
    function: u8,
    dev: Arc<dyn PciFunction>,
}

pub struct PciBus {
    config_address: AtomicU32,
    devices: Mutex<Vec<Slot>>,
    mmio_next: Mutex<u64>,
}

impl PciBus {
    pub fn new() -> Arc<Self> {
        Arc::new(PciBus {
            config_address: AtomicU32::new(0),
            devices: Mutex::new(Vec::new()),
            mmio_next: Mutex::new(MMIO_WINDOW_BASE),
        })
    }

    fn assign_bars(&self, dev: &Arc<dyn PciFunction>) {
        let layout = dev.bar_layout();
        let mut mmio_next = self.mmio_next.lock().unwrap();
        for (i, (kind, size)) in layout.iter().enumerate() {
            match kind {
                BarKind::Mmio32 | BarKind::Mmio64 => {
                    let mask = (*size as u64) - 1;
                    let base = (*mmio_next + mask) & !mask;
                    if base + *size as u64 > MMIO_WINDOW_END {
                        panic!("PciBus: ran out of MMIO BAR window");
                    }
                    dev.assign_bar_base(i, base);
                    *mmio_next = base + *size as u64;
                }
                BarKind::Io => {
                    // Phase 2 devices are MMIO-only; no IO BAR allocator yet.
                    panic!("PciBus: IO BARs not supported in phase 2");
                }
                BarKind::None => {}
            }
        }
    }

    /// Add a device at the next free slot on bus 0. Returns its BDF.
    pub fn add_device(self: &Arc<Self>, dev: Arc<dyn PciFunction>) -> Bdf {
        self.assign_bars(&dev);
        let mut devices = self.devices.lock().unwrap();
        let device = devices.len() as u8;
        devices.push(Slot {
            bus: 0,
            device,
            function: 0,
            dev,
        });
        Bdf {
            bus: 0,
            device,
            function: 0,
        }
    }

    /// Snapshot the host-bridge state the guest can program: the CONFIG_ADDRESS
    /// (0xCF8) selector latch (4 bytes). The BAR allocator (`mmio_next`) is
    /// re-derived deterministically when devices are re-added on restore.
    pub fn snapshot_capture(&self) -> Vec<u8> {
        self.config_address
            .load(Ordering::Relaxed)
            .to_le_bytes()
            .to_vec()
    }

    pub fn snapshot_apply(&self, bytes: &[u8]) {
        if bytes.len() < 4 {
            return;
        }
        self.config_address.store(
            u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            Ordering::Relaxed,
        );
    }

    pub fn attach_io_bus(self: &Arc<Self>, io_bus: &mut IoBus) {
        let b = self.clone();
        io_bus.register(
            CONFIG_ADDRESS_PORT,
            4,
            "pci-cfg-addr",
            Box::new(move |a| b.handle_address(a)),
        );
        let b = self.clone();
        io_bus.register(
            CONFIG_DATA_PORT,
            4,
            "pci-cfg-data",
            Box::new(move |a| b.handle_data(a)),
        );
    }

    fn handle_address(&self, access: &mut IoAccess) {
        if access.is_write {
            if access.access_size == 4 {
                self.config_address.store(access.value, Ordering::Relaxed);
            } else {
                let byte_off = (access.port - CONFIG_ADDRESS_PORT) as u32;
                let mask = (if access.access_size == 4 {
                    0xFFFF_FFFFu32
                } else {
                    (1u32 << (8 * access.access_size)) - 1
                }) << (8 * byte_off);
                let cur = self.config_address.load(Ordering::Relaxed);
                self.config_address.store(
                    (cur & !mask) | ((access.value << (8 * byte_off)) & mask),
                    Ordering::Relaxed,
                );
            }
        } else {
            let byte_off = (access.port - CONFIG_ADDRESS_PORT) as u32;
            let mut v = self.config_address.load(Ordering::Relaxed) >> (8 * byte_off);
            if access.access_size != 4 {
                v &= (1u32 << (8 * access.access_size)) - 1;
            }
            access.value = v;
        }
    }

    fn find(&self, devices: &[Slot], bus: u8, dev: u8, f: u8) -> Option<Arc<dyn PciFunction>> {
        devices
            .iter()
            .find(|s| s.bus == bus && s.device == dev && s.function == f)
            .map(|s| s.dev.clone())
    }

    fn handle_data(&self, access: &mut IoAccess) {
        let dec = decode_config_address(self.config_address.load(Ordering::Relaxed));
        if !dec.enable {
            if !access.is_write {
                access.value = 0xFFFF_FFFF;
            }
            return;
        }
        let dev = {
            let devices = self.devices.lock().unwrap();
            self.find(&devices, dec.bus, dec.dev, dec.fn_)
        };
        let Some(dev) = dev else {
            if !access.is_write {
                access.value = 0xFFFF_FFFF;
            }
            return;
        };
        let byte_off = (access.port - CONFIG_DATA_PORT) as u32;
        let reg_offset = dec.reg as u32 + byte_off;
        if access.is_write {
            dev.config_write(reg_offset, access.access_size as u32, access.value);
        } else {
            access.value = dev.config_read(reg_offset, access.access_size as u32);
        }
    }
}
