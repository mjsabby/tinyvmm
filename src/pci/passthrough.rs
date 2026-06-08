//! Discrete Device Assignment endpoint — pure shadow/translation logic.
//!
//! This module holds the *probe-independent* core of PCI passthrough: the BAR
//! shadow (driven by the assigned device's probed sizing masks) and the x86 MSI
//! message decoder used by the MSI-X interrupt bridge. Both are pure and
//! unit-tested; they don't depend on the still-open question of whether device
//! MMIO can be SLAT-mapped into the guest (`WHvMapGpaRange2`) or must be
//! trap-and-forwarded.
//!
//! Model (mirrors OpenVMM's `AssignedPciDevice`): the VMM virtualizes the BAR
//! registers and the command register; every other config-space access passes
//! through to the physical device via `WHvVpciConfigSpace`. Each guest MSI-X
//! table entry is translated into a `WHvMapVpciDeviceInterrupt` call whose
//! opaque `(address, data)` is then written into the real device's MSI-X table.

use whpsys::vpci::{ProbedBar, decode_probed_bars};

/// Shadow of an assigned device's six BAR dwords, driven by the device's probed
/// BAR sizing masks (`WHvVpciDevicePropertyCodeProbedBARs`). The guest programs
/// base addresses into this shadow exactly as it would real hardware; reads
/// return the programmed base OR'd with the device's fixed type bits, so the
/// Linux PCI core's BAR-sizing dance (write all-ones, read back the mask) works
/// unchanged.
pub struct AssignedBars {
    /// Guest-programmed dword, already masked to the writable (address) bits.
    value: [u32; 6],
    /// Constant type bits OR'd into reads: low dword has I/O/mem + 32/64-bit +
    /// prefetch bits; high dword of a 64-bit BAR and unimplemented BARs are 0.
    flags: [u32; 6],
    /// Writable (size-mask) bits per dword. 0 ⇒ unimplemented / not programmable.
    writable: [u32; 6],
    /// Decoded per-BAR view (index, kind, size); a 64-bit BAR appears once.
    decoded: Vec<ProbedBar>,
}

impl AssignedBars {
    pub fn new(probed: [u32; 6]) -> Self {
        let decoded = decode_probed_bars(&probed);
        // Mark which dwords are the high half of a 64-bit BAR.
        let mut high = [false; 6];
        for b in &decoded {
            if b.is_64bit && b.index + 1 < 6 {
                high[b.index + 1] = true;
            }
        }
        let mut flags = [0u32; 6];
        let mut writable = [0u32; 6];
        for i in 0..6 {
            let p = probed[i];
            if p == 0 {
                continue; // unimplemented
            }
            if high[i] {
                // Upper 32 bits of a 64-bit BAR: every probed bit is writable,
                // no type bits.
                writable[i] = p;
                continue;
            }
            if p & 0x1 != 0 {
                // I/O BAR: bit0 = 1 (indicator), bit1 reserved.
                flags[i] = p & 0x3;
                writable[i] = p & !0x3;
            } else {
                // Memory BAR: bits[3:0] = type (mem, 32/64-bit, prefetch).
                flags[i] = p & 0xF;
                writable[i] = p & !0xF;
            }
        }
        AssignedBars {
            value: [0; 6],
            flags,
            writable,
            decoded,
        }
    }

    /// Apply a guest write of one BAR dword (`idx` in 0..6).
    pub fn write_dword(&mut self, idx: usize, v: u32) {
        if idx < 6 {
            self.value[idx] = v & self.writable[idx];
        }
    }

    /// Read back one BAR dword as the guest would see it.
    pub fn read_dword(&self, idx: usize) -> u32 {
        if idx < 6 {
            self.value[idx] | self.flags[idx]
        } else {
            0
        }
    }

    /// The currently-programmed base GPA + size for each implemented BAR. The
    /// base comes from the guest's BAR programming (type bits already stripped
    /// via the writable mask). Use this to (re)map device MMIO on a command
    /// `MemoryEnable` toggle.
    pub fn mappings(&self) -> Vec<BarMapping> {
        self.decoded
            .iter()
            .map(|b| {
                let mut base = self.value[b.index] as u64;
                if b.is_64bit && b.index + 1 < 6 {
                    base |= (self.value[b.index + 1] as u64) << 32;
                }
                BarMapping {
                    index: b.index,
                    is_io: b.is_io,
                    base,
                    size: b.size,
                }
            })
            .collect()
    }
}

/// One BAR's resolved (base GPA, size) after the guest has programmed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BarMapping {
    pub index: usize,
    pub is_io: bool,
    pub base: u64,
    pub size: u64,
}

/// A decoded x86 MSI/MSI-X message (Intel SDM Vol 3 §10.11). The MSI-X bridge
/// turns each unmasked table entry into a `WHvMapVpciDeviceInterrupt` target:
/// `vector` + the destination VP (for ≤255 vCPUs, APIC id == VP index in
/// tinyvmm's model, so `dest_id` is used directly).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedMsi {
    pub vector: u8,
    pub dest_id: u8,
    /// Destination Mode: true = logical, false = physical.
    pub logical: bool,
    /// Redirection Hint (lowest-priority delivery when set).
    pub redirect_hint: bool,
    /// Delivery mode (0 = Fixed, 1 = LowestPri, 4 = NMI, 5 = INIT, …).
    pub delivery_mode: u8,
    /// Trigger mode: true = level, false = edge.
    pub level_trigger: bool,
}

/// Decode an MSI address/data pair into its routing fields.
pub fn decode_msi(address: u64, data: u32) -> DecodedMsi {
    let addr_lo = address as u32;
    DecodedMsi {
        vector: (data & 0xFF) as u8,
        dest_id: ((addr_lo >> 12) & 0xFF) as u8,
        logical: (addr_lo >> 2) & 0x1 != 0,
        redirect_hint: (addr_lo >> 3) & 0x1 != 0,
        delivery_mode: ((data >> 8) & 0x7) as u8,
        level_trigger: (data >> 15) & 0x1 != 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bar32_sizing_and_base() {
        // BAR0: 16 MiB non-prefetchable 32-bit MMIO (probed low = 0xFF000000).
        let mut bars = AssignedBars::new([0xFF00_0000, 0, 0, 0, 0, 0]);
        // BAR-size probe: guest writes all-ones, reads back mask | type bits.
        bars.write_dword(0, 0xFFFF_FFFF);
        assert_eq!(bars.read_dword(0), 0xFF00_0000);
        // Program a base; low type bits must not stick.
        bars.write_dword(0, 0xE000_0006);
        assert_eq!(bars.read_dword(0), 0xE000_0000);
        let m = bars.mappings();
        assert_eq!(m.len(), 1);
        assert_eq!(
            m[0],
            BarMapping {
                index: 0,
                is_io: false,
                base: 0xE000_0000,
                size: 0x100_0000,
            }
        );
    }

    #[test]
    fn bar64_prefetchable_above_4g() {
        // BAR1/2: 256 MiB prefetchable 64-bit (low=0xF000000C, high=0xFFFFFFFF).
        let mut bars = AssignedBars::new([0, 0xF000_000C, 0xFFFF_FFFF, 0, 0, 0]);
        // Type bits read back on the low dword.
        bars.write_dword(1, 0xFFFF_FFFF);
        assert_eq!(bars.read_dword(1), 0xF000_000C);
        // Program a base above 4 GiB.
        bars.write_dword(1, 0x1_0000_0000u64 as u32); // low = 0
        bars.write_dword(2, 0x0000_0001); // high = 1 -> base = 0x1_0000_0000
        let m = bars.mappings();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].index, 1);
        assert_eq!(m[0].base, 0x1_0000_0000);
        assert_eq!(m[0].size, 0x1000_0000);
        assert!(!m[0].is_io);
    }

    #[test]
    fn io_bar_low_bits_masked() {
        // BAR4: 256-byte I/O BAR (probed = 0xFFFFFF01).
        let mut bars = AssignedBars::new([0, 0, 0, 0, 0xFFFF_FF01, 0]);
        bars.write_dword(4, 0xFFFF_FFFF);
        // Read back keeps the I/O indicator bit.
        assert_eq!(bars.read_dword(4), 0xFFFF_FF01);
        bars.write_dword(4, 0x0000_C005);
        assert_eq!(bars.read_dword(4), 0x0000_C001);
        let m = bars.mappings();
        assert_eq!(m[0].is_io, true);
        assert_eq!(m[0].base, 0x0000_C000);
        assert_eq!(m[0].size, 0x100);
    }

    #[test]
    fn unimplemented_bars_read_zero() {
        let bars = AssignedBars::new([0; 6]);
        for i in 0..6 {
            assert_eq!(bars.read_dword(i), 0);
        }
        assert!(bars.mappings().is_empty());
    }

    #[test]
    fn decode_msi_physical_fixed() {
        // addr 0xFEE03000 -> dest_id=3, physical; data 0x4030 -> vector 0x30,
        // delivery Fixed(0), edge.
        let d = decode_msi(0xFEE0_3000, 0x0000_4030);
        assert_eq!(d.vector, 0x30);
        assert_eq!(d.dest_id, 3);
        assert!(!d.logical);
        assert_eq!(d.delivery_mode, 0);
        assert!(!d.level_trigger);
    }

    #[test]
    fn decode_msi_logical_and_trigger() {
        // bit2 set => logical dest; data bit15 set => level trigger.
        let d = decode_msi(0xFEE0_5004, 0x0000_8051);
        assert_eq!(d.vector, 0x51);
        assert_eq!(d.dest_id, 5);
        assert!(d.logical);
        assert!(d.level_trigger);
    }
}
