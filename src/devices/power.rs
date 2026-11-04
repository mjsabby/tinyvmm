//! Guest power control: the ACPI fixed-hardware PM1 registers the FADT points
//! at (`boot::acpi`), the FADT's reset register, and the keyboard controller's
//! reset command. tinyvmm never restarts a guest: powering off (S5) or
//! rebooting records the request and stops the VM.
//!
//! No event ever raises the SCI: there are no power or sleep buttons, no GPEs
//! and no PM timer, so PM1_STS always reads 0. PM1_EN still keeps what the
//! guest writes, since ACPICA reads an enable bit back to decide whether the
//! hardware is there (it enables the global lock's).

use crate::devices::io_bus::{IoAccess, IoBus};
use std::sync::{Arc, Mutex, OnceLock};

/// PM1a event block: PM1_STS, then PM1_EN, 16 bits each.
pub const PM1A_EVT_PORT: u16 = 0x600;
pub const PM1_EVT_LEN: u8 = 4;
/// PM1a control block: PM1_CNT, 16 bits.
pub const PM1A_CNT_PORT: u16 = 0x604;
pub const PM1_CNT_LEN: u8 = 2;
/// The FADT's RESET_REG: writing [`RESET_VALUE`] resets the machine.
pub const RESET_PORT: u16 = 0x60C;
pub const RESET_VALUE: u8 = 1;
/// The SLP_TYP that the DSDT's `\_S5_` object gives for soft-off.
pub const SLP_TYP_S5: u8 = 5;

/// The i8042 command port. There is no keyboard controller behind it; reads
/// float to all-ones, as they would unclaimed, so Linux still finds none.
const KBD_COMMAND_PORT: u16 = 0x64;
/// i8042 command: pulse the CPU reset line.
const KBD_PULSE_RESET: u8 = 0xFE;

const PM1_BLOCK_LEN: usize = (PM1_EVT_LEN + PM1_CNT_LEN) as usize;
const PM1_CNT_SCI_EN: u16 = 1 << 0;
const PM1_CNT_GBL_RLS: u16 = 1 << 2;
const PM1_CNT_SLP_TYP_SHIFT: u16 = 10;
const PM1_CNT_SLP_EN: u16 = 1 << 13;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerRequest {
    /// ACPI soft-off: S5 written to PM1_CNT.
    PowerOff,
    /// A reboot through the FADT reset register.
    AcpiReset,
    /// A reboot through the keyboard controller.
    KeyboardReset,
}

impl PowerRequest {
    pub fn describe(self) -> &'static str {
        match self {
            PowerRequest::PowerOff => "the guest powered off (ACPI S5)",
            PowerRequest::AcpiReset => {
                "the guest rebooted (ACPI reset register); tinyvmm stops instead of restarting it"
            }
            PowerRequest::KeyboardReset => {
                "the guest rebooted (keyboard-controller reset); tinyvmm stops instead of \
                 restarting it"
            }
        }
    }
}

#[derive(Default)]
struct Pm1 {
    en: u16,
    cnt: u16,
}

pub struct PowerDevice {
    pm1: Mutex<Pm1>,
    request: Mutex<Option<PowerRequest>>,
    on_request: OnceLock<Box<dyn Fn() + Send + Sync>>,
}

impl PowerDevice {
    pub fn new() -> Arc<Self> {
        Arc::new(PowerDevice {
            pm1: Mutex::new(Pm1::default()),
            request: Mutex::new(None),
            on_request: OnceLock::new(),
        })
    }

    pub fn attach(self: &Arc<Self>, bus: &mut IoBus) {
        let d = self.clone();
        bus.register(
            PM1A_EVT_PORT,
            PM1_BLOCK_LEN as u16,
            "acpi-pm1",
            Box::new(move |a| d.pm1(a)),
        );
        let d = self.clone();
        bus.register(RESET_PORT, 1, "acpi-reset", Box::new(move |a| d.reset(a)));
        let d = self.clone();
        bus.register(
            KBD_COMMAND_PORT,
            1,
            "kbd-reset",
            Box::new(move |a| d.kbd(a)),
        );
    }

    /// Called (from the vCPU thread that asked) when the guest powers off or
    /// reboots; it should stop the VM. Set once.
    pub fn set_on_request(&self, f: impl Fn() + Send + Sync + 'static) {
        let _ = self.on_request.set(Box::new(f));
    }

    /// What the guest asked for, if it powered off or rebooted. The first
    /// request wins.
    pub fn request(&self) -> Option<PowerRequest> {
        *self.request.lock().unwrap()
    }

    /// Snapshot what the guest programmed: PM1_EN and PM1_CNT (4 bytes). A
    /// power request never is: the VM stops on one.
    pub fn snapshot_capture(&self) -> Vec<u8> {
        let pm1 = self.pm1.lock().unwrap();
        [pm1.en, pm1.cnt].map(u16::to_le_bytes).concat()
    }

    pub fn snapshot_apply(&self, bytes: &[u8]) {
        if let [en0, en1, cnt0, cnt1, ..] = *bytes {
            let mut pm1 = self.pm1.lock().unwrap();
            pm1.en = u16::from_le_bytes([en0, en1]);
            pm1.cnt = u16::from_le_bytes([cnt0, cnt1]);
        }
    }

    fn raise(&self, r: PowerRequest) {
        self.request.lock().unwrap().get_or_insert(r);
        if let Some(f) = self.on_request.get() {
            f();
        }
    }

    /// PM1_STS, PM1_EN and PM1_CNT as one 6-byte block, any access width.
    fn pm1(&self, acc: &mut IoAccess) {
        let off = usize::from(acc.port - PM1A_EVT_PORT);
        let size = usize::from(acc.access_size).clamp(1, 4);
        let mut pm1 = self.pm1.lock().unwrap();
        if !acc.is_write {
            // Always in ACPI mode: there is no SMI_CMD to switch modes.
            let cnt = pm1.cnt | PM1_CNT_SCI_EN;
            let regs = [0, pm1.en, cnt].map(u16::to_le_bytes).concat();
            acc.value = (0..size).fold(0, |v, i| {
                let byte = regs.get(off + i).copied().unwrap_or(0xFF);
                v | (u32::from(byte) << (8 * i))
            });
            return;
        }
        let mut sleep = false;
        for i in (0..size).filter(|i| off + i < PM1_BLOCK_LEN) {
            let at = off + i;
            let shift = 8 * (at % 2);
            let bits = u16::from((acc.value >> (8 * i)) as u8) << shift;
            let keep = !(0xFF << shift);
            match at / 2 {
                0 => {} // PM1_STS: no status bit is ever set to clear
                1 => pm1.en = (pm1.en & keep) | bits,
                _ => {
                    sleep |= bits & PM1_CNT_SLP_EN != 0;
                    // SLP_EN and GBL_RLS are write-only and read as 0.
                    pm1.cnt = (pm1.cnt & keep) | (bits & !(PM1_CNT_SLP_EN | PM1_CNT_GBL_RLS));
                }
            }
        }
        let slp_typ = (pm1.cnt >> PM1_CNT_SLP_TYP_SHIFT) & 0b111;
        drop(pm1);
        // \_S5_ is the only sleep state the DSDT declares; ignore any other.
        if sleep && slp_typ == u16::from(SLP_TYP_S5) {
            self.raise(PowerRequest::PowerOff);
        }
    }

    fn reset(&self, acc: &mut IoAccess) {
        if !acc.is_write {
            acc.value = 0;
        } else if acc.value as u8 == RESET_VALUE {
            self.raise(PowerRequest::AcpiReset);
        }
    }

    fn kbd(&self, acc: &mut IoAccess) {
        if !acc.is_write {
            acc.value = 0xFFFF_FFFF;
        } else if acc.value as u8 == KBD_PULSE_RESET {
            self.raise(PowerRequest::KeyboardReset);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn machine() -> (Arc<PowerDevice>, IoBus, Arc<AtomicUsize>) {
        let dev = PowerDevice::new();
        let mut bus = IoBus::new();
        dev.attach(&mut bus);
        let stops = Arc::new(AtomicUsize::new(0));
        let s = stops.clone();
        dev.set_on_request(move || {
            s.fetch_add(1, Ordering::SeqCst);
        });
        (dev, bus, stops)
    }

    fn out(bus: &IoBus, port: u16, size: u16, value: u32) {
        let mut acc = IoAccess {
            port,
            access_size: size,
            is_write: true,
            value,
        };
        assert!(bus.dispatch(&mut acc));
    }

    fn inp(bus: &IoBus, port: u16, size: u16) -> u32 {
        let mut acc = IoAccess {
            port,
            access_size: size,
            is_write: false,
            value: 0,
        };
        bus.dispatch(&mut acc);
        acc.value
    }

    #[test]
    fn writing_s5_with_slp_en_powers_off() {
        let (dev, bus, stops) = machine();
        // ACPICA's sequence: SLP_TYP alone, then SLP_TYP | SLP_EN.
        let slp_typ = u32::from(SLP_TYP_S5) << 10;
        out(&bus, PM1A_CNT_PORT, 2, slp_typ);
        assert_eq!(dev.request(), None);
        assert_eq!(inp(&bus, PM1A_CNT_PORT, 2), slp_typ | 1, "SCI_EN reads set");
        out(&bus, PM1A_CNT_PORT, 2, slp_typ | (1 << 13));
        assert_eq!(dev.request(), Some(PowerRequest::PowerOff));
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        assert_eq!(
            inp(&bus, PM1A_CNT_PORT, 2),
            slp_typ | 1,
            "SLP_EN is write-only"
        );

        // Another sleep type is not a power-off, and only the first request
        // is kept.
        let (dev, bus, stops) = machine();
        out(&bus, PM1A_CNT_PORT + 1, 1, (3 << 2) | (1 << 5));
        assert_eq!((dev.request(), stops.load(Ordering::SeqCst)), (None, 0));
        out(&bus, RESET_PORT, 1, u32::from(RESET_VALUE));
        out(&bus, PM1A_CNT_PORT + 1, 1, (5 << 2) | (1 << 5));
        assert_eq!(dev.request(), Some(PowerRequest::AcpiReset));
        assert_eq!(stops.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn pm1_enable_bits_stick_and_survive_a_snapshot() {
        let (dev, bus, _) = machine();
        // A dword at PM1_STS covers PM1_STS and PM1_EN; PM1_STS stays 0.
        out(&bus, PM1A_EVT_PORT, 4, (0x0120 << 16) | 0xFFFF);
        assert_eq!(inp(&bus, PM1A_EVT_PORT, 4), 0x0120 << 16);
        out(&bus, PM1A_EVT_PORT + 3, 1, 0);
        assert_eq!(inp(&bus, PM1A_EVT_PORT + 2, 2), 0x0020);
        out(&bus, PM1A_CNT_PORT, 2, 3 << 10);

        let (restored, bus, _) = machine();
        restored.snapshot_apply(&dev.snapshot_capture());
        assert_eq!(inp(&bus, PM1A_EVT_PORT, 4), 0x0020 << 16);
        assert_eq!(inp(&bus, PM1A_CNT_PORT, 2), (3 << 10) | 1);
    }

    #[test]
    fn reset_register_and_keyboard_controller_reboot() {
        let (dev, bus, stops) = machine();
        out(&bus, RESET_PORT, 1, 0);
        out(&bus, KBD_COMMAND_PORT, 1, 0xAA);
        assert_eq!((dev.request(), stops.load(Ordering::SeqCst)), (None, 0));
        // No controller: the status port floats, as before it was claimed.
        assert_eq!(inp(&bus, KBD_COMMAND_PORT, 1) as u8, 0xFF);
        out(&bus, KBD_COMMAND_PORT, 1, u32::from(KBD_PULSE_RESET));
        assert_eq!(dev.request(), Some(PowerRequest::KeyboardReset));

        let (dev, bus, _) = machine();
        out(&bus, RESET_PORT, 1, u32::from(RESET_VALUE));
        assert_eq!(dev.request(), Some(PowerRequest::AcpiReset));
    }
}
