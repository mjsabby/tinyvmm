//! Minimal 8250/16550 UART. TX bytes go to host stdout (this is the phase-1
//! serial console). Optional IRQ4 raise for the guest's IRQ-driven TX path.
//! Port of devices/serial8250.cpp (TX-only; RX path is a later phase).

use crate::devices::io_bus::{IoAccess, IoBus};
use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};

const LCR_DLAB: u8 = 0x80;
const IER_ETBEI: u8 = 0x02;
const LSR_ALWAYS_READY: u8 = (1 << 5) | (1 << 6); // THRE | TEMT
const IIR_NO_INTR: u8 = 0x01;
const IIR_THRE_INTR: u8 = 0x02;
const MSR_DEFAULT: u8 = 0x90 | 0x20 | 0x10; // DCD | DSR | CTS

pub type IrqRaiseFn = Box<dyn Fn(i32) + Send + Sync>;

struct Inner {
    ier: u8,
    lcr: u8,
    mcr: u8,
    scr: u8,
    fcr: u8,
    dll: u8,
    dlm: u8,
    tx_irq_pending: bool,
    tx_bytes: u64,
}

pub struct Serial8250 {
    base: u16,
    inner: Mutex<Inner>,
    irq: OnceLock<IrqRaiseFn>,
}

const ISA_IRQ: i32 = 4;

impl Serial8250 {
    pub fn new(base_port: u16) -> Arc<Self> {
        Arc::new(Serial8250 {
            base: base_port,
            inner: Mutex::new(Inner {
                ier: 0,
                lcr: 0,
                mcr: 0,
                scr: 0,
                fcr: 0,
                dll: 0,
                dlm: 0,
                tx_irq_pending: false,
                tx_bytes: 0,
            }),
            irq: OnceLock::new(),
        })
    }

    pub fn attach(self: &Arc<Self>, bus: &mut IoBus) {
        let d = self.clone();
        bus.register(self.base, 8, "serial8250", Box::new(move |a| d.handle(a)));
    }

    pub fn set_irq_callback(&self, f: IrqRaiseFn) {
        let _ = self.irq.set(f);
    }

    pub fn tx_bytes(&self) -> u64 {
        self.inner.lock().unwrap().tx_bytes
    }

    /// Snapshot the UART register state (16 bytes).
    pub fn snapshot_capture(&self) -> Vec<u8> {
        let i = self.inner.lock().unwrap();
        let mut b = Vec::with_capacity(16);
        b.push(i.ier);
        b.push(i.lcr);
        b.push(i.mcr);
        b.push(i.scr);
        b.push(i.fcr);
        b.push(i.dll);
        b.push(i.dlm);
        b.push(i.tx_irq_pending as u8);
        b.extend_from_slice(&i.tx_bytes.to_le_bytes());
        b
    }

    pub fn snapshot_apply(&self, bytes: &[u8]) {
        if bytes.len() < 16 {
            return;
        }
        let mut i = self.inner.lock().unwrap();
        i.ier = bytes[0];
        i.lcr = bytes[1];
        i.mcr = bytes[2];
        i.scr = bytes[3];
        i.fcr = bytes[4];
        i.dll = bytes[5];
        i.dlm = bytes[6];
        i.tx_irq_pending = bytes[7] != 0;
        i.tx_bytes = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    }

    fn handle(&self, acc: &mut IoAccess) {
        let mut inner = self.inner.lock().unwrap();
        if acc.is_write {
            self.write_reg(&mut inner, acc);
        } else {
            self.read_reg(&mut inner, acc);
        }
    }

    fn maybe_raise_tx_irq(&self, inner: &mut Inner) {
        let Some(cb) = self.irq.get() else {
            return;
        };
        if inner.ier & IER_ETBEI == 0 || inner.tx_irq_pending {
            return;
        }
        inner.tx_irq_pending = true;
        cb(ISA_IRQ);
    }

    fn write_reg(&self, inner: &mut Inner, acc: &IoAccess) {
        let off = acc.port - self.base;
        let v = (acc.value & 0xFF) as u8;
        match off {
            0 => {
                if inner.lcr & LCR_DLAB != 0 {
                    inner.dll = v;
                } else {
                    inner.tx_bytes += 1;
                    let mut out = std::io::stdout().lock();
                    let _ = out.write_all(&[v]);
                    let _ = out.flush();
                    self.maybe_raise_tx_irq(inner);
                }
            }
            1 => {
                if inner.lcr & LCR_DLAB != 0 {
                    inner.dlm = v;
                } else {
                    let prev = inner.ier;
                    inner.ier = v;
                    if prev & IER_ETBEI == 0 && inner.ier & IER_ETBEI != 0 {
                        self.maybe_raise_tx_irq(inner);
                    }
                    if inner.ier & IER_ETBEI == 0 {
                        inner.tx_irq_pending = false;
                    }
                }
            }
            2 => inner.fcr = v,
            3 => inner.lcr = v,
            4 => inner.mcr = v,
            7 => inner.scr = v,
            _ => {}
        }
    }

    fn read_reg(&self, inner: &mut Inner, acc: &mut IoAccess) {
        let off = acc.port - self.base;
        let v = match off {
            0 if inner.lcr & LCR_DLAB != 0 => inner.dll,
            1 => {
                if inner.lcr & LCR_DLAB != 0 {
                    inner.dlm
                } else {
                    inner.ier
                }
            }
            2 => {
                if inner.tx_irq_pending {
                    inner.tx_irq_pending = false;
                    IIR_THRE_INTR
                } else {
                    IIR_NO_INTR
                }
            }
            3 => inner.lcr,
            4 => inner.mcr,
            5 => LSR_ALWAYS_READY,
            6 => MSR_DEFAULT,
            7 => inner.scr,
            _ => 0,
        };
        acc.value = v as u32;
    }
}
