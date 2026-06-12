//! MMIO bus: routes accesses to device handlers by GPA range. Phase 1 boots
//! with no MMIO devices (no PCI/virtio yet) but the bus is implemented for the
//! later phases.

use std::sync::RwLock;

pub type Handler = Box<dyn Fn(&mut MmioAccess) + Send + Sync>;

/// One in-flight MMIO access. `data` holds little-endian bytes.
pub struct MmioAccess {
    pub gpa: u64,
    pub access_size: u8,
    pub is_write: bool,
    pub data: [u8; 8],
}

struct Entry {
    base: u64,
    size: u64,
    name: String,
    handler: Handler,
}

#[derive(Default)]
pub struct MmioBus {
    entries: RwLock<Vec<Entry>>,
}

fn ranges_overlap(a_base: u64, a_size: u64, b_base: u64, b_size: u64) -> bool {
    a_base < b_base + b_size && b_base < a_base + a_size
}

impl MmioBus {
    pub fn new() -> Self {
        MmioBus::default()
    }

    /// Register a handler for `[base, base+size)`. Returns `false` (registering
    /// nothing) if the range overlaps an existing entry. A guest can reprogram a
    /// device BAR to any GPA, so an overlap must NEVER panic — that would abort
    /// the whole VMM. Callers validate BAR placement up front (see
    /// `PciTransport::on_bar_mapped`); this is the backstop for a concurrent
    /// reprogram race.
    pub fn register(&self, base: u64, size: u64, name: &str, handler: Handler) -> bool {
        assert!(size > 0, "MmioBus::register: size must be > 0");
        let mut entries = self.entries.write().unwrap();
        for e in entries.iter() {
            if ranges_overlap(base, size, e.base, e.size) {
                return false;
            }
        }
        entries.push(Entry {
            base,
            size,
            name: name.to_string(),
            handler,
        });
        true
    }

    /// True iff `[base, base+size)` overlaps no currently-registered range.
    pub fn is_range_free(&self, base: u64, size: u64) -> bool {
        let entries = self.entries.read().unwrap();
        !entries
            .iter()
            .any(|e| ranges_overlap(base, size, e.base, e.size))
    }

    pub fn unregister(&self, base: u64) -> bool {
        let mut entries = self.entries.write().unwrap();
        if let Some(pos) = entries.iter().position(|e| e.base == base) {
            entries.remove(pos);
            true
        } else {
            false
        }
    }

    pub fn dispatch(&self, acc: &mut MmioAccess) -> bool {
        let entries = self.entries.read().unwrap();
        for e in entries.iter() {
            if acc.gpa >= e.base && acc.gpa < e.base + e.size {
                (e.handler)(acc);
                return true;
            }
        }
        if !acc.is_write {
            acc.data = [0u8; 8];
        }
        false
    }
}
