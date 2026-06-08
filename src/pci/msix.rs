//! MSI-X capability + table + PBA helper. Port of src/pci/msix.cpp.
//!
//! Decoupled from `PciConfigSpace`: the transport pushes the MSI-X Message
//! Control register (enable/funcmask) here via `set_control` after each config
//! write, so the hot Trigger path never touches the config-space lock.

use super::CAP_ID_MSIX;
use super::config::PciConfigSpace;
use crate::devices::mmio_bus::{MmioAccess, MmioBus};
use crate::diag::etw;
use crate::whp::msi::inject_msi;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use windows_sys::Win32::System::Hypervisor::WHV_PARTITION_HANDLE;

#[derive(Clone, Copy, Default)]
struct Entry {
    addr_lo: u32,
    addr_hi: u32,
    data: u32,
    ctrl: u32, // bit 0 = masked; spec init = masked
}

struct Tables {
    table: Vec<Entry>,
    pba: Vec<u64>,
}

pub struct MsiX {
    num_vectors: u32,
    part: WHV_PARTITION_HANDLE,
    control: AtomicU16, // MSI-X Message Control: bit15 enable, bit14 funcmask
    tables: Mutex<Tables>,
    bar_idx: u8,
    table_offset: u32,
    pba_offset: u32,
    bar_base_gpa: AtomicU64,
    injected_count: AtomicU64,
}

fn next_pow2(v: u32) -> u32 {
    if v < 2 {
        return 1;
    }
    let mut r = 1u32;
    while r < v {
        r <<= 1;
    }
    r
}

impl MsiX {
    pub fn new(
        num_vectors: u32,
        part: WHV_PARTITION_HANDLE,
        bar_idx: u8,
        table_offset: u32,
        pba_offset: u32,
    ) -> Arc<Self> {
        assert!((1..=2048).contains(&num_vectors), "MsiX vectors 1..2048");
        assert!(
            table_offset & 0x7 == 0 && pba_offset & 0x7 == 0,
            "8-byte aligned"
        );
        Arc::new(MsiX {
            num_vectors,
            part,
            control: AtomicU16::new(0),
            tables: Mutex::new(Tables {
                table: vec![
                    Entry {
                        ctrl: 1,
                        ..Default::default()
                    };
                    num_vectors as usize
                ],
                pba: vec![0u64; num_vectors.div_ceil(64) as usize],
            }),
            bar_idx,
            table_offset,
            pba_offset,
            bar_base_gpa: AtomicU64::new(0),
            injected_count: AtomicU64::new(0),
        })
    }

    /// Snapshot the MSI-X routing table for save/restore: (control, per-entry
    /// [addr_lo, addr_hi, data, ctrl], pba words). Restoring this is mandatory
    /// or completions won't route to the guest after a restore.
    pub fn snapshot_capture(&self) -> (u16, Vec<[u32; 4]>, Vec<u64>) {
        let t = self.tables.lock().unwrap();
        let table: Vec<[u32; 4]> = t
            .table
            .iter()
            .map(|e| [e.addr_lo, e.addr_hi, e.data, e.ctrl])
            .collect();
        let pba = t.pba.clone();
        (self.control.load(Ordering::Relaxed), table, pba)
    }

    pub fn snapshot_apply(&self, control: u16, table: &[[u32; 4]], pba: &[u64]) {
        {
            let mut t = self.tables.lock().unwrap();
            for (i, e) in table.iter().enumerate() {
                if i < t.table.len() {
                    t.table[i] = Entry {
                        addr_lo: e[0],
                        addr_hi: e[1],
                        data: e[2],
                        ctrl: e[3],
                    };
                }
            }
            for (i, p) in pba.iter().enumerate() {
                if i < t.pba.len() {
                    t.pba[i] = *p;
                }
            }
        }
        self.control.store(control, Ordering::Relaxed);
    }

    pub fn table_size(&self) -> u32 {
        self.num_vectors * 16
    }
    pub fn pba_size(&self) -> u32 {
        self.num_vectors.div_ceil(64) * 8
    }
    pub fn injected_count(&self) -> u64 {
        self.injected_count.load(Ordering::Relaxed)
    }

    pub fn required_bar_size(num_vectors: u32, table_offset: u32, pba_offset: u32) -> u32 {
        let table_size = num_vectors * 16;
        let pba_size = num_vectors.div_ceil(64) * 8;
        let hi = (table_offset + table_size).max(pba_offset + pba_size);
        if hi < 16 { 16 } else { next_pow2(hi) }
    }

    /// Write the MSI-X capability into a config space (construction-time).
    pub fn add_capability(&self, cfg: &mut PciConfigSpace) -> u32 {
        let cap_off = cfg.append_capability(CAP_ID_MSIX, 12);
        let mc = (self.num_vectors - 1) as u16;
        {
            let p = cfg.cfg_bytes_mut(cap_off, 12);
            p[2] = (mc & 0xFF) as u8;
            p[3] = ((mc >> 8) & 0x07) as u8;
            let toff = (self.table_offset & !0x7) | (self.bar_idx as u32 & 0x7);
            p[4..8].copy_from_slice(&toff.to_le_bytes());
            let poff = (self.pba_offset & !0x7) | (self.bar_idx as u32 & 0x7);
            p[8..12].copy_from_slice(&poff.to_le_bytes());
        }
        // High byte of Message Control writable: bit6 FuncMask | bit7 Enable.
        cfg.set_writable_byte(cap_off + 3, 0xC0);
        cap_off
    }

    /// Sync the MSI-X Message Control register from config space after a write.
    pub fn set_control(&self, mc: u16) {
        self.control.store(mc, Ordering::Relaxed);
    }

    fn enabled(&self) -> bool {
        self.control.load(Ordering::Relaxed) & 0x8000 != 0
    }
    fn function_masked(&self) -> bool {
        self.control.load(Ordering::Relaxed) & 0x4000 != 0
    }

    pub fn install(self: &Arc<Self>, bus: &MmioBus, bar_gpa: u64) {
        self.bar_base_gpa.store(bar_gpa, Ordering::Relaxed);
        let me = self.clone();
        bus.register(
            bar_gpa + self.table_offset as u64,
            self.table_size() as u64,
            "msix-table",
            Box::new(move |a| me.handle_table(a)),
        );
        let me = self.clone();
        bus.register(
            bar_gpa + self.pba_offset as u64,
            self.pba_size() as u64,
            "msix-pba",
            Box::new(move |a| me.handle_pba(a)),
        );
    }

    pub fn uninstall(&self, bus: &MmioBus) {
        let base = self.bar_base_gpa.load(Ordering::Relaxed);
        bus.unregister(base + self.table_offset as u64);
        bus.unregister(base + self.pba_offset as u64);
    }

    fn handle_table(&self, access: &mut MmioAccess) {
        let base = self.bar_base_gpa.load(Ordering::Relaxed) + self.table_offset as u64;
        let off = access.gpa - base;
        let vec = (off / 16) as usize;
        let field = off % 16;
        if access.access_size != 4 || (off & 0x3) != 0 || vec >= self.num_vectors as usize {
            if !access.is_write {
                access.data = [0; 8];
            }
            return;
        }

        let mut do_replay = false;
        {
            let mut t = self.tables.lock().unwrap();
            if access.is_write {
                let v = u32::from_le_bytes(access.data[0..4].try_into().unwrap());
                match field {
                    0 => t.table[vec].addr_lo = v,
                    4 => t.table[vec].addr_hi = v,
                    8 => t.table[vec].data = v,
                    12 => {
                        let new_ctrl = v & 0x1;
                        let was_masked = t.table[vec].ctrl & 0x1 != 0;
                        t.table[vec].ctrl = new_ctrl;
                        let pending = (t.pba[vec / 64] >> (vec % 64)) & 0x1 != 0;
                        if was_masked
                            && new_ctrl & 0x1 == 0
                            && self.enabled()
                            && !self.function_masked()
                            && pending
                        {
                            t.pba[vec / 64] &= !(1u64 << (vec % 64));
                            do_replay = true;
                        }
                    }
                    _ => {}
                }
            } else {
                let v = match field {
                    0 => t.table[vec].addr_lo,
                    4 => t.table[vec].addr_hi,
                    8 => t.table[vec].data,
                    12 => t.table[vec].ctrl,
                    _ => 0,
                };
                access.data[0..4].copy_from_slice(&v.to_le_bytes());
            }
        }
        if do_replay {
            self.do_inject(vec as u32);
        }
    }

    fn handle_pba(&self, access: &mut MmioAccess) {
        if access.is_write {
            return;
        }
        if access.access_size != 4 && access.access_size != 8 {
            access.data = [0; 8];
            return;
        }
        let base = self.bar_base_gpa.load(Ordering::Relaxed) + self.pba_offset as u64;
        let off = access.gpa - base;
        let qword = (off / 8) as usize;
        let value = {
            let t = self.tables.lock().unwrap();
            t.pba.get(qword).copied().unwrap_or(0)
        };
        if access.access_size == 8 {
            access.data.copy_from_slice(&value.to_le_bytes());
        } else {
            let shift = ((off & 4) * 8) as u32;
            let half = (value >> shift) as u32;
            access.data[0..4].copy_from_slice(&half.to_le_bytes());
        }
    }

    /// Submit interrupt for `vector`. Latches PBA + returns false if masked.
    pub fn trigger(&self, vector: u32) -> bool {
        if vector >= self.num_vectors {
            return false;
        }
        if !self.enabled() || self.function_masked() {
            let mut t = self.tables.lock().unwrap();
            t.pba[vector as usize / 64] |= 1u64 << (vector % 64);
            return false;
        }
        {
            let mut t = self.tables.lock().unwrap();
            if t.table[vector as usize].ctrl & 0x1 != 0 {
                t.pba[vector as usize / 64] |= 1u64 << (vector % 64);
                return false;
            }
        }
        self.do_inject(vector)
    }

    fn do_inject(&self, vector: u32) -> bool {
        let (addr, data) = {
            let t = self.tables.lock().unwrap();
            let e = &t.table[vector as usize];
            (((e.addr_hi as u64) << 32) | e.addr_lo as u64, e.data)
        };
        self.injected_count.fetch_add(1, Ordering::Relaxed);
        if etw::enabled(etw::VERBOSE, etw::kw::MSI) {
            etw::Event::new("MsiInject", etw::VERBOSE, etw::kw::MSI)
                .u32("vector", vector)
                .hex64("addr", addr)
                .u32("data", data)
                .write();
        }
        inject_msi(self.part, addr, data)
    }
}
