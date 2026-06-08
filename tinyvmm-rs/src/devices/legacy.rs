//! Tiny ISA stubs Linux touches at boot: MC146818 CMOS RTC (0x70/0x71), POST
//! port 0x80, and system control port A (0x92). Port of devices/legacy_isa.cpp.

use crate::devices::io_bus::{IoAccess, IoBus};
use std::sync::{Arc, Mutex};

const CMOS_SECONDS: u8 = 0x00;
const CMOS_MINUTES: u8 = 0x02;
const CMOS_HOURS: u8 = 0x04;
const CMOS_DAY_OF_MONTH: u8 = 0x07;
const CMOS_MONTH: u8 = 0x08;
const CMOS_YEAR: u8 = 0x09;
const CMOS_STATUS_A: u8 = 0x0a;
const CMOS_STATUS_B: u8 = 0x0b;
const CMOS_CENTURY: u8 = 0x32;

fn bcd(v: u8) -> u8 {
    ((v / 10) << 4) | (v % 10)
}

struct Inner {
    cmos_index: u8,
    port92: u8,
}

pub struct LegacyIsaStubs {
    inner: Mutex<Inner>,
}

impl LegacyIsaStubs {
    pub fn new() -> Arc<Self> {
        Arc::new(LegacyIsaStubs {
            inner: Mutex::new(Inner {
                cmos_index: 0,
                port92: 0x02, // bit 1 = A20 gate enabled
            }),
        })
    }

    pub fn attach(self: &Arc<Self>, bus: &mut IoBus) {
        let d = self.clone();
        bus.register(0x70, 1, "cmos-idx", Box::new(move |a| d.cmos_index(a)));
        let d = self.clone();
        bus.register(0x71, 1, "cmos-dat", Box::new(move |a| d.cmos_data(a)));
        bus.register(0x80, 1, "post-diag", Box::new(Self::port80));
        let d = self.clone();
        bus.register(0x92, 1, "port92", Box::new(move |a| d.port92(a)));
    }

    fn port80(acc: &mut IoAccess) {
        if !acc.is_write {
            acc.value = 0xff;
        }
    }

    /// Snapshot the writable ISA stub state: CMOS index + port 0x92 (2 bytes).
    pub fn snapshot_capture(&self) -> Vec<u8> {
        let i = self.inner.lock().unwrap();
        vec![i.cmos_index, i.port92]
    }

    pub fn snapshot_apply(&self, bytes: &[u8]) {
        if bytes.len() < 2 {
            return;
        }
        let mut i = self.inner.lock().unwrap();
        i.cmos_index = bytes[0];
        i.port92 = bytes[1];
    }

    fn cmos_index(&self, acc: &mut IoAccess) {
        let mut inner = self.inner.lock().unwrap();
        if acc.is_write {
            inner.cmos_index = (acc.value & 0x7f) as u8;
        } else {
            acc.value = inner.cmos_index as u32;
        }
    }

    fn cmos_data(&self, acc: &mut IoAccess) {
        let inner = self.inner.lock().unwrap();
        if acc.is_write {
            return;
        }
        acc.value = read_cmos(inner.cmos_index) as u32;
    }

    fn port92(&self, acc: &mut IoAccess) {
        let mut inner = self.inner.lock().unwrap();
        if acc.is_write {
            inner.port92 = (acc.value & 0xff) as u8;
        } else {
            acc.value = inner.port92 as u32;
        }
    }
}

/// Fixed wall clock: 2024-01-01 00:00:00 UTC.
fn read_cmos(reg: u8) -> u8 {
    match reg {
        CMOS_SECONDS => bcd(0),
        CMOS_MINUTES => bcd(0),
        CMOS_HOURS => bcd(0),
        CMOS_DAY_OF_MONTH => bcd(1),
        CMOS_MONTH => bcd(1),
        CMOS_YEAR => bcd(24),
        CMOS_CENTURY => bcd(20),
        CMOS_STATUS_A => 0x26,
        CMOS_STATUS_B => 0x02,
        _ => 0,
    }
}
