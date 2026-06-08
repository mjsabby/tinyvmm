//! PCI Type-0 configuration space: 256-byte config buffer, 6 BAR descriptors,
//! capability list, and the COMMAND.MEM_SPACE -> BAR (un)map state machine.
//! Port of src/pci/pci_device.cpp (save/restore omitted).

use super::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BarKind {
    None,
    Io,
    Mmio32,
    Mmio64,
}

#[derive(Clone, Copy)]
pub struct Bar {
    pub kind: BarKind,
    pub prefetchable: bool,
    pub size: u32,
    pub value_lo: u32,
    pub value_hi: u32,
    pub mapped: bool,
    pub mapped_gpa: u64,
}

impl Default for Bar {
    fn default() -> Self {
        Bar {
            kind: BarKind::None,
            prefetchable: false,
            size: 0,
            value_lo: 0,
            value_hi: 0,
            mapped: false,
            mapped_gpa: 0,
        }
    }
}

/// A BAR (un)map event emitted by `write()` when COMMAND.MEM_SPACE toggles.
#[derive(Clone, Copy, Debug)]
pub enum BarEvent {
    Mapped { idx: usize, gpa: u64, size: u32 },
    Unmapped { idx: usize },
}

pub struct PciConfigSpace {
    cfg: [u8; 256],
    writable_mask: [u8; 256],
    bars: [Bar; 6],
    cap_next_alloc: u32,
}

fn is_pow2(v: u32) -> bool {
    v != 0 && (v & (v - 1)) == 0
}

fn read_le(p: &[u8], size: u32) -> u32 {
    let mut v = 0u32;
    for (i, &b) in p.iter().take(size as usize).enumerate() {
        v |= (b as u32) << (8 * i);
    }
    v
}

impl PciConfigSpace {
    pub fn new() -> Self {
        PciConfigSpace {
            cfg: [0; 256],
            writable_mask: [0; 256],
            bars: [Bar::default(); 6],
            cap_next_alloc: CAP_LIST_START,
        }
    }

    pub fn set_ids(&mut self, vid: u16, did: u16, sub_vid: u16, sub_id: u16) {
        self.put16(CFG_VENDOR_ID, vid);
        self.put16(CFG_DEVICE_ID, did);
        self.put16(CFG_SUBSYS_VENDOR_ID, sub_vid);
        self.put16(CFG_SUBSYS_ID, sub_id);
        self.cfg[CFG_HEADER_TYPE as usize] = HEADER_TYPE_NORMAL;
        self.writable_mask[CFG_COMMAND as usize] = 0xFF;
        self.writable_mask[CFG_COMMAND as usize + 1] = 0xFF;
        self.writable_mask[CFG_INTERRUPT_LINE as usize] = 0xFF;
        self.writable_mask[CFG_CACHE_LINE_SIZE as usize] = 0xFF;
        self.writable_mask[CFG_LATENCY_TIMER as usize] = 0xFF;
    }

    pub fn set_class(&mut self, class_code: u8, subclass: u8, prog_if: u8, revision: u8) {
        self.cfg[CFG_REVISION_ID as usize] = revision;
        self.cfg[CFG_PROG_IF as usize] = prog_if;
        self.cfg[CFG_SUBCLASS as usize] = subclass;
        self.cfg[CFG_CLASS_CODE as usize] = class_code;
    }

    pub fn set_interrupt_pin(&mut self, pin: u8) {
        self.cfg[CFG_INTERRUPT_PIN as usize] = pin;
    }

    pub fn declare_mmio64_bar(&mut self, idx: usize, size: u32, prefetchable: bool) {
        assert!(idx <= 4, "declare_mmio64_bar: idx out of range");
        assert!(
            is_pow2(size) && size >= 16,
            "mmio64 size must be pow2 >= 16"
        );
        assert!(
            self.bars[idx].kind == BarKind::None && self.bars[idx + 1].kind == BarKind::None,
            "BAR already declared"
        );
        self.bars[idx].kind = BarKind::Mmio64;
        self.bars[idx].size = size;
        self.bars[idx].prefetchable = prefetchable;
        for b in 0..8 {
            self.writable_mask[CFG_BAR0 as usize + 4 * idx + b] = 0xFF;
        }
    }

    pub fn append_capability(&mut self, cap_id: u8, payload_size: u32) -> u32 {
        assert!(payload_size >= 2, "cap payload must include 2-byte header");
        assert!(
            self.cap_next_alloc + payload_size <= CFG_SPACE_SIZE,
            "capabilities overflow config space"
        );
        let off = self.cap_next_alloc;
        if self.cfg[CFG_CAP_PTR as usize] == 0 {
            self.cfg[CFG_CAP_PTR as usize] = off as u8;
            let st = self.read16(CFG_STATUS) | STATUS_CAP_LIST;
            self.put16(CFG_STATUS, st);
        } else {
            let mut cur = self.cfg[CFG_CAP_PTR as usize] as usize;
            loop {
                let nxt = self.cfg[cur + 1];
                if nxt == 0 {
                    break;
                }
                cur = nxt as usize;
            }
            self.cfg[cur + 1] = off as u8;
        }
        self.cfg[off as usize] = cap_id;
        self.cfg[off as usize + 1] = 0;
        self.cap_next_alloc += payload_size;
        off
    }

    pub fn cfg_bytes_mut(&mut self, off: u32, len: usize) -> &mut [u8] {
        &mut self.cfg[off as usize..off as usize + len]
    }

    pub fn set_writable_byte(&mut self, offset: u32, mask: u8) {
        self.writable_mask[offset as usize] |= mask;
    }

    pub fn read16(&self, off: u32) -> u16 {
        read_le(&self.cfg[off as usize..], 2) as u16
    }

    fn put16(&mut self, off: u32, v: u16) {
        self.cfg[off as usize] = (v & 0xFF) as u8;
        self.cfg[off as usize + 1] = (v >> 8) as u8;
    }

    pub fn command(&self) -> u16 {
        self.read16(CFG_COMMAND)
    }

    pub fn bar_layout(&self) -> [(BarKind, u32); 6] {
        let mut out = [(BarKind::None, 0u32); 6];
        for (o, b) in out.iter_mut().zip(self.bars.iter()) {
            *o = (b.kind, b.size);
        }
        out
    }

    /// Capture writable PCI config for save/restore: the 256-byte config buffer
    /// plus each BAR's programmed (value_lo, value_hi). The BAR addresses live in
    /// `bars[]`, not the cfg buffer, so they must be captured separately.
    pub fn snapshot_capture(&self) -> ([u8; 256], [(u32, u32); 6]) {
        let mut bars = [(0u32, 0u32); 6];
        for (dst, b) in bars.iter_mut().zip(self.bars.iter()) {
            *dst = (b.value_lo, b.value_hi);
        }
        (self.cfg, bars)
    }

    /// Restore config + BAR addresses, then recompute BAR mappings against the
    /// restored COMMAND register. Returns the BAR (un)map events the transport
    /// must act on to re-register MMIO + MSI-X handlers.
    pub fn snapshot_apply(&mut self, cfg: &[u8; 256], bar_vals: &[(u32, u32); 6]) -> Vec<BarEvent> {
        self.cfg = *cfg;
        for (b, v) in self.bars.iter_mut().zip(bar_vals.iter()) {
            b.value_lo = v.0;
            b.value_hi = v.1;
            b.mapped = false;
            b.mapped_gpa = 0;
        }
        let mut events = Vec::new();
        let cmd = self.command();
        self.recompute_mappings(cmd, &mut events);
        events
    }

    pub fn set_bar_base(&mut self, idx: usize, gpa: u64) {
        match self.bars[idx].kind {
            BarKind::Io | BarKind::Mmio32 => self.bars[idx].value_lo = gpa as u32,
            BarKind::Mmio64 => {
                self.bars[idx].value_lo = (gpa & 0xFFFF_FFFF) as u32;
                self.bars[idx].value_hi = (gpa >> 32) as u32;
            }
            BarKind::None => {}
        }
    }

    fn bar_size_mask_low(b: &Bar) -> u32 {
        if b.size == 0 {
            return 0;
        }
        match b.kind {
            BarKind::Io => !(b.size - 1) & 0xFFFF_FFFC,
            BarKind::Mmio32 | BarKind::Mmio64 => !(b.size - 1) & 0xFFFF_FFF0,
            BarKind::None => 0,
        }
    }

    fn bar_size_mask_high(b: &Bar) -> u32 {
        if b.kind != BarKind::Mmio64 || b.size == 0 {
            return 0;
        }
        0xFFFF_FFFF
    }

    fn read_bar_dword(&self, idx: usize) -> u32 {
        let b = &self.bars[idx];
        if b.kind == BarKind::None {
            if idx > 0 && self.bars[idx - 1].kind == BarKind::Mmio64 {
                return self.bars[idx - 1].value_hi & Self::bar_size_mask_high(&self.bars[idx - 1]);
            }
            return 0;
        }
        let mut v = b.value_lo & Self::bar_size_mask_low(b);
        match b.kind {
            BarKind::Io => v |= BAR_IO_MARKER,
            BarKind::Mmio32 => {
                if b.prefetchable {
                    v |= BAR_PREFETCHABLE;
                }
            }
            BarKind::Mmio64 => {
                v |= BAR_MMIO64;
                if b.prefetchable {
                    v |= BAR_PREFETCHABLE;
                }
            }
            BarKind::None => {}
        }
        v
    }

    fn write_bar_dword(&mut self, idx: usize, value: u32) {
        let kind = self.bars[idx].kind;
        if kind == BarKind::None {
            if idx > 0 && self.bars[idx - 1].kind == BarKind::Mmio64 {
                let mask = Self::bar_size_mask_high(&self.bars[idx - 1]);
                self.bars[idx - 1].value_hi = value & mask;
            }
            return;
        }
        let mask = Self::bar_size_mask_low(&self.bars[idx]);
        self.bars[idx].value_lo = value & mask;
    }

    fn recompute_mappings(&mut self, new_cmd: u16, events: &mut Vec<BarEvent>) {
        let mem_on = (new_cmd & CMD_MEMORY_SPACE) != 0;
        for i in 0..6 {
            let kind = self.bars[i].kind;
            if kind != BarKind::Mmio32 && kind != BarKind::Mmio64 {
                continue;
            }
            let mut gpa = (self.bars[i].value_lo as u64) & !0xF;
            if kind == BarKind::Mmio64 {
                gpa |= (self.bars[i].value_hi as u64) << 32;
            }
            let want = mem_on && gpa != 0;
            let mapped = self.bars[i].mapped;
            let size = self.bars[i].size;
            if want && !mapped {
                self.bars[i].mapped = true;
                self.bars[i].mapped_gpa = gpa;
                events.push(BarEvent::Mapped { idx: i, gpa, size });
            } else if !want && mapped {
                self.bars[i].mapped = false;
                events.push(BarEvent::Unmapped { idx: i });
            } else if want && mapped && self.bars[i].mapped_gpa != gpa {
                events.push(BarEvent::Unmapped { idx: i });
                self.bars[i].mapped_gpa = gpa;
                events.push(BarEvent::Mapped { idx: i, gpa, size });
            }
        }
    }

    fn write_byte(&mut self, offset: u32, value: u8) {
        let mask = self.writable_mask[offset as usize];
        let o = offset as usize;
        self.cfg[o] = (self.cfg[o] & !mask) | (value & mask);
    }

    pub fn read(&self, offset: u32, size: u32) -> u32 {
        if offset + size > CFG_SPACE_SIZE {
            return if size == 4 {
                0xFFFF_FFFF
            } else {
                (1u32 << (8 * size)) - 1
            };
        }
        // BAR window?
        if offset >= CFG_BAR0 && offset + size <= CFG_BAR0 + 6 * 4 {
            let lo = (offset - CFG_BAR0) / 4;
            let hi = (offset + size - 1 - CFG_BAR0) / 4;
            if lo == hi {
                let dword = self.read_bar_dword(lo as usize);
                let byte_off = (offset - CFG_BAR0) % 4;
                let m = if size == 4 {
                    0xFFFF_FFFF
                } else {
                    (1u32 << (8 * size)) - 1
                };
                return (dword >> (8 * byte_off)) & m;
            }
        }
        read_le(&self.cfg[offset as usize..], size)
    }

    /// Apply a config write. Returns any BAR (un)map events to act on.
    pub fn write(&mut self, offset: u32, size: u32, value: u32) -> Vec<BarEvent> {
        let mut events = Vec::new();
        if offset + size > CFG_SPACE_SIZE {
            return events;
        }

        // COMMAND write?
        if offset <= CFG_COMMAND + 1 && offset + size > CFG_COMMAND {
            let old_cmd = self.command();
            for i in 0..size {
                self.write_byte(offset + i, ((value >> (8 * i)) & 0xFF) as u8);
            }
            let new_cmd = self.command();
            if old_cmd != new_cmd {
                self.recompute_mappings(new_cmd, &mut events);
            }
            return events;
        }

        // BAR write?
        if offset >= CFG_BAR0 && offset + size <= CFG_BAR0 + 6 * 4 {
            let bar_idx = ((offset - CFG_BAR0) / 4) as usize;
            let byte_off = (offset - CFG_BAR0) % 4;
            let mut cur = self.read_bar_dword(bar_idx);
            cur &= Self::bar_size_mask_low(&self.bars[bar_idx]);
            if size == 4 && byte_off == 0 {
                cur = value;
            } else {
                let m = (if size == 4 {
                    0xFFFF_FFFF
                } else {
                    (1u32 << (8 * size)) - 1
                }) << (8 * byte_off);
                cur = (cur & !m) | ((value << (8 * byte_off)) & m);
            }
            self.write_bar_dword(bar_idx, cur);
            return events;
        }

        // Default: per-byte writable-mask handling.
        for i in 0..size {
            self.write_byte(offset + i, ((value >> (8 * i)) & 0xFF) as u8);
        }
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pci::msix::MsiX;

    fn dev() -> PciConfigSpace {
        let mut c = PciConfigSpace::new();
        c.set_ids(0x1AF4, 0x1042, 0x1AF4, 0x0001);
        c.set_class(0x01, 0x00, 0x00, 0x01);
        c
    }

    #[test]
    fn ids_and_class_read_back() {
        let c = dev();
        assert_eq!(c.read(CFG_VENDOR_ID, 2), 0x1AF4);
        assert_eq!(c.read(CFG_DEVICE_ID, 2), 0x1042);
        assert_eq!(c.read(CFG_SUBSYS_VENDOR_ID, 2), 0x1AF4);
        assert_eq!(c.read(CFG_SUBSYS_ID, 2), 0x0001);
        assert_eq!(c.read(CFG_CLASS_CODE, 1), 0x01);
        assert_eq!(c.read(CFG_HEADER_TYPE, 1), HEADER_TYPE_NORMAL as u32);
        // Out-of-range / master-abort style read returns all-ones.
        assert_eq!(c.read(CFG_SPACE_SIZE, 4), 0xFFFF_FFFF);
    }

    #[test]
    fn mmio64_bar_sizing_dance() {
        let mut c = dev();
        // 16 KiB prefetchable 64-bit BAR in BAR0/BAR1.
        c.declare_mmio64_bar(0, 0x4000, true);
        // Write all-ones, read back the size mask + type bits (MMIO64|PREFETCH).
        c.write(CFG_BAR0, 4, 0xFFFF_FFFF);
        assert_eq!(c.read(CFG_BAR0, 4), 0xFFFF_C00C);
        // Decoding the size from the low dword: clear type bits, invert, +1.
        let masked = c.read(CFG_BAR0, 4) & 0xFFFF_FFF0;
        assert_eq!((!masked).wrapping_add(1), 0x4000);
        // High dword sizes to all-ones for a 64-bit BAR.
        c.write(CFG_BAR0 + 4, 4, 0xFFFF_FFFF);
        assert_eq!(c.read(CFG_BAR0 + 4, 4), 0xFFFF_FFFF);
        // Type bits: bit0=0 (memory), bits[2:1]=10 (64-bit), bit3=1 (prefetch).
        assert_eq!(c.read(CFG_BAR0, 4) & 0xF, BAR_MMIO64 | BAR_PREFETCHABLE);
    }

    #[test]
    fn command_mem_space_maps_and_unmaps_bar() {
        let mut c = dev();
        c.declare_mmio64_bar(0, 0x4000, false);
        // Program a base GPA into the 64-bit BAR.
        c.write(CFG_BAR0, 4, 0xE000_0000);
        c.write(CFG_BAR0 + 4, 4, 0x0000_0000);
        // Enabling COMMAND.MEM_SPACE maps BAR0 at the programmed GPA.
        let ev = c.write(CFG_COMMAND, 2, CMD_MEMORY_SPACE as u32);
        assert!(matches!(
            ev.as_slice(),
            [BarEvent::Mapped {
                idx: 0,
                gpa: 0xE000_0000,
                size: 0x4000
            }]
        ));
        // Clearing it unmaps.
        let ev = c.write(CFG_COMMAND, 2, 0);
        assert!(matches!(ev.as_slice(), [BarEvent::Unmapped { idx: 0 }]));
    }

    #[test]
    fn moving_a_mapped_bar_unmaps_then_remaps() {
        let mut c = dev();
        c.declare_mmio64_bar(0, 0x1000, false);
        c.write(CFG_BAR0, 4, 0xE000_0000);
        let _ = c.write(CFG_COMMAND, 2, CMD_MEMORY_SPACE as u32);
        // Reprogram the base while mapped: expect unmap(old) + map(new).
        c.write(CFG_BAR0, 4, 0xE100_0000);
        // The remap is observed on the next COMMAND touch (recompute on cmd write).
        let ev = c.write(
            CFG_COMMAND,
            2,
            CMD_MEMORY_SPACE as u32 | CMD_IO_SPACE as u32,
        );
        assert!(
            ev.iter()
                .any(|e| matches!(e, BarEvent::Unmapped { idx: 0 }))
        );
        assert!(ev.iter().any(|e| matches!(
            e,
            BarEvent::Mapped {
                idx: 0,
                gpa: 0xE100_0000,
                ..
            }
        )));
    }

    #[test]
    fn config_snapshot_roundtrip() {
        let mut c = dev();
        c.declare_mmio64_bar(0, 0x2000, true);
        c.write(CFG_BAR0, 4, 0xE000_0000);
        c.write(CFG_COMMAND, 2, CMD_MEMORY_SPACE as u32);
        let (cfg, bars) = c.snapshot_capture();
        let mut c2 = dev();
        c2.declare_mmio64_bar(0, 0x2000, true);
        c2.snapshot_apply(&cfg, &bars);
        assert_eq!(c2.command(), c.command());
        assert_eq!(c2.read(CFG_BAR0, 4), c.read(CFG_BAR0, 4));
        assert_eq!(c2.read(CFG_VENDOR_ID, 2), 0x1AF4);
    }

    #[test]
    fn decode_config_address_fields() {
        // enable | bus=0 | dev=3 | fn=0 | reg=0x10
        let addr = CONFIG_ADDRESS_ENABLE | (3 << 11) | 0x10;
        let d = decode_config_address(addr);
        assert!(d.enable);
        assert_eq!(d.bus, 0);
        assert_eq!(d.dev, 3);
        assert_eq!(d.fn_, 0);
        assert_eq!(d.reg, 0x10);
        // Low two bits of the register are masked off (dword aligned).
        let d2 = decode_config_address(CONFIG_ADDRESS_ENABLE | 0x13);
        assert_eq!(d2.reg, 0x10);
    }

    #[test]
    fn msix_required_bar_size_rounds_up_to_pow2() {
        // 3 vectors, table at 0, PBA at 0x800: table=48B, pba=8B -> hi=0x808 -> 4 KiB.
        assert_eq!(MsiX::required_bar_size(3, 0, 0x800), 0x1000);
        // 1 vector, both at 0: table=16, pba=8 -> hi=16 -> 16 (min).
        assert_eq!(MsiX::required_bar_size(1, 0, 0), 16);
        // 2048 vectors: table=32768, pba=256 -> hi=0x8000 -> 32 KiB.
        assert_eq!(MsiX::required_bar_size(2048, 0, 0x8000), 0x1_0000);
    }
}
