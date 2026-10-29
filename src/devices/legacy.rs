//! Tiny ISA stubs Linux touches at boot: MC146818 CMOS RTC (0x70/0x71), POST
//! port 0x80, and system control port A (0x92). Port of devices/legacy_isa.cpp.

use crate::devices::io_bus::{IoAccess, IoBus};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const CMOS_SECONDS: u8 = 0x00;
const CMOS_MINUTES: u8 = 0x02;
const CMOS_HOURS: u8 = 0x04;
const CMOS_DAY_OF_WEEK: u8 = 0x06;
const CMOS_DAY_OF_MONTH: u8 = 0x07;
const CMOS_MONTH: u8 = 0x08;
const CMOS_YEAR: u8 = 0x09;
const CMOS_STATUS_A: u8 = 0x0a;
const CMOS_STATUS_B: u8 = 0x0b;
const CMOS_STATUS_D: u8 = 0x0d;
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

/// The RTC tracks the host clock in UTC (what Linux assumes of a PC RTC), so a
/// guest boots with the right wall-clock time; guest writes are ignored.
fn read_cmos(reg: u8) -> u8 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    cmos_register(reg, now)
}

/// Register `reg` of an RTC reading `unix_secs` (UTC), in the format Status B
/// advertises: BCD, 24-hour. Each register is computed independently; Linux
/// re-reads the seconds after the others and retries if they ticked over.
fn cmos_register(reg: u8, unix_secs: u64) -> u8 {
    let days = unix_secs / 86_400;
    let secs = unix_secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    match reg {
        CMOS_SECONDS => bcd((secs % 60) as u8),
        CMOS_MINUTES => bcd((secs / 60 % 60) as u8),
        CMOS_HOURS => bcd((secs / 3600) as u8),
        // 1..=7 with Sunday = 1; 1970-01-01 was a Thursday.
        CMOS_DAY_OF_WEEK => bcd(((days + 4) % 7 + 1) as u8),
        CMOS_DAY_OF_MONTH => bcd(day),
        CMOS_MONTH => bcd(month),
        CMOS_YEAR => bcd((year % 100) as u8),
        CMOS_CENTURY => bcd((year / 100) as u8),
        CMOS_STATUS_A => 0x26,
        CMOS_STATUS_B => 0x02,
        CMOS_STATUS_D => 0x80, // VRT: the time is valid
        _ => 0,
    }
}

/// Days since 1970-01-01 to a proleptic-Gregorian (year, month, day); Howard
/// Hinnant's `civil_from_days`.
fn civil_from_days(days: u64) -> (u64, u8, u8) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    (era * 400 + yoe + u64::from(month <= 2), month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (century, year, month, day, weekday, hours, minutes, seconds) as BCD.
    fn rtc_at(unix_secs: u64) -> [u8; 8] {
        [
            CMOS_CENTURY,
            CMOS_YEAR,
            CMOS_MONTH,
            CMOS_DAY_OF_MONTH,
            CMOS_DAY_OF_WEEK,
            CMOS_HOURS,
            CMOS_MINUTES,
            CMOS_SECONDS,
        ]
        .map(|reg| cmos_register(reg, unix_secs))
    }

    #[test]
    fn rtc_reports_utc_calendar_time_in_bcd() {
        // 2026-10-29 05:47:09, a Thursday.
        assert_eq!(
            rtc_at(1_793_252_829),
            [0x20, 0x26, 0x10, 0x29, 0x05, 0x05, 0x47, 0x09]
        );
        // Leap day rolling into March, a Thursday into a Friday.
        assert_eq!(
            rtc_at(1_709_251_199),
            [0x20, 0x24, 0x02, 0x29, 0x05, 0x23, 0x59, 0x59]
        );
        assert_eq!(
            rtc_at(1_709_251_200),
            [0x20, 0x24, 0x03, 0x01, 0x06, 0x00, 0x00, 0x00]
        );
        // Century rollover.
        assert_eq!(
            rtc_at(946_684_799),
            [0x19, 0x99, 0x12, 0x31, 0x06, 0x23, 0x59, 0x59]
        );
        assert_eq!(
            rtc_at(946_684_800),
            [0x20, 0x00, 0x01, 0x01, 0x07, 0x00, 0x00, 0x00]
        );
        // 2100 is not a leap year: Feb 28 is followed by Mar 1, a Monday.
        assert_eq!(
            rtc_at(4_107_585_600),
            [0x21, 0x00, 0x03, 0x01, 0x02, 0x12, 0x00, 0x00]
        );
    }

    #[test]
    fn rtc_follows_the_host_clock() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let (year, _, _) = civil_from_days(now / 86_400);
        assert_eq!(read_cmos(CMOS_YEAR), bcd((year % 100) as u8));
    }
}
