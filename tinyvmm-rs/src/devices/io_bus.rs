//! Port-IO bus: routes accesses to device handlers by port range. Built once
//! during setup, then shared immutably across vCPU threads.

pub type Handler = Box<dyn Fn(&mut IoAccess) + Send + Sync>;

/// One in-flight port-IO access. `is_write` true == OUT (guest -> device).
pub struct IoAccess {
    pub port: u16,
    pub access_size: u16,
    pub is_write: bool,
    pub value: u32,
}

struct Entry {
    base: u16,
    size: u16,
    name: String,
    handler: Handler,
}

#[derive(Default)]
pub struct IoBus {
    entries: Vec<Entry>,
}

fn ranges_overlap(a_base: u32, a_size: u32, b_base: u32, b_size: u32) -> bool {
    a_base < b_base + b_size && b_base < a_base + a_size
}

impl IoBus {
    pub fn new() -> Self {
        IoBus::default()
    }

    pub fn register(&mut self, base: u16, size: u16, name: &str, handler: Handler) {
        assert!(size > 0, "IoBus::register: size must be > 0");
        assert!(
            base as u32 + size as u32 <= 0x10000,
            "IoBus::register: range exceeds 16-bit IO space"
        );
        for e in &self.entries {
            if ranges_overlap(base as u32, size as u32, e.base as u32, e.size as u32) {
                panic!(
                    "IoBus::register: range [{:04x}..{:04x}) for '{}' overlaps '{}' [{:04x}..{:04x})",
                    base,
                    base as u32 + size as u32,
                    name,
                    e.name,
                    e.base,
                    e.base as u32 + e.size as u32
                );
            }
        }
        self.entries.push(Entry {
            base,
            size,
            name: name.to_string(),
            handler,
        });
    }

    /// Dispatch one access. Returns true if a handler claimed it. Unclaimed
    /// reads see the ISA floating-bus all-ones convention.
    pub fn dispatch(&self, acc: &mut IoAccess) -> bool {
        for e in &self.entries {
            if acc.port >= e.base && (acc.port as u32) < e.base as u32 + e.size as u32 {
                (e.handler)(acc);
                return true;
            }
        }
        if !acc.is_write {
            acc.value = 0xFFFF_FFFF;
        }
        false
    }
}
