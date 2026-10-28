//! Minimal Intel 8259A PIC pair (master @ 0x20/0x21, slave @ 0xa0/0xa1).
//! Port of devices/i8259.cpp.
//!
//! # Delivery: ExtINT only
//!
//! The pair's INT output is the BSP's LINT0 (virtual-wire mode), so its
//! interrupts must reach the guest as **ExtINT** events -- never as Fixed
//! interrupts through the LAPIC. Linux acknowledges an 8259 IRQ only at the PIC
//! (`mask_and_ack_8259A`), never with a LAPIC EOI, so a Fixed delivery leaves
//! the vector's LAPIC ISR bit set for good: the processor priority stays at the
//! PIC vectors' class (0x30 with Linux's remap) and every vector at or below it
//! -- all of the virtio MSIs -- is blocked forever. That wedge used to hang
//! virtio-blk the first time COM1 raised IRQ4.
//!
//! So this device has no injection callback. [`Pic8259::raise`] latches the IRQ
//! in the IRR and calls `notify` once the INT output may be asserted; the BSP
//! run loop polls [`Pic8259::output_pending`] and, when the vCPU can take an
//! interrupt, runs the INTA cycle with [`Pic8259::acknowledge`] and injects the
//! returned vector as an ExtINT event (`whpsys::vcpu::Vcpu::inject_ext_int`).
//!
//! The in-service register isn't modelled: EOIs are absorbed and every IRQ is
//! edge-triggered, which is all the UART (the only ISA IRQ source) needs.

use crate::devices::io_bus::{IoAccess, IoBus};
use std::sync::{Arc, Mutex};

const ICW1_IS_INIT: u8 = 0x10;
const ICW1_IC4: u8 = 0x01;
/// Master input that the slave's INT output is cascaded into.
const CASCADE_IRQ: u8 = 2;

/// Called when the INT output may have become asserted (an unmasked IRQ was
/// latched, or a latched one was unmasked). Runs on the raising thread, possibly
/// under another device's lock, so it must be cheap and must not call back into
/// the PIC; the VMM wires it to a `WHvCancelRunVirtualProcessor` kick of the BSP.
pub type NotifyFn = Box<dyn Fn() + Send + Sync>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum IcwStep {
    Idle,
    Icw2,
    Icw3,
    Icw4,
}

#[derive(Clone, Copy)]
struct Chip {
    vector_base: u8,
    mask: u8,
    irr: u8,
    expect_icw4: bool,
    step: IcwStep,
}

impl Default for Chip {
    fn default() -> Self {
        Chip {
            vector_base: 0,
            mask: 0xff,
            irr: 0,
            expect_icw4: false,
            step: IcwStep::Idle,
        }
    }
}

struct Inner {
    master: Chip,
    slave: Chip,
}

impl Inner {
    fn chip(&mut self, is_slave: bool) -> &mut Chip {
        if is_slave {
            &mut self.slave
        } else {
            &mut self.master
        }
    }

    /// Highest-priority IRQ the INT output would present on the next INTA, as
    /// `(is_slave, local_irq)`. Fixed priority: master IR0 first; the slave's
    /// requests sit at the cascade input's (IR2) position and need it unmasked.
    fn highest(&self) -> Option<(bool, u8)> {
        let master = self.master.irr & !self.master.mask;
        let slave = self.slave.irr & !self.slave.mask;
        for irq in 0..8u8 {
            if irq == CASCADE_IRQ && self.master.mask & (1 << CASCADE_IRQ) == 0 && slave != 0 {
                return Some((true, slave.trailing_zeros() as u8));
            }
            if master & (1 << irq) != 0 {
                return Some((false, irq));
            }
        }
        None
    }
}

pub struct Pic8259 {
    inner: Mutex<Inner>,
    notify: NotifyFn,
}

impl Pic8259 {
    pub fn new(notify: NotifyFn) -> Arc<Self> {
        Arc::new(Pic8259 {
            inner: Mutex::new(Inner {
                master: Chip::default(),
                slave: Chip::default(),
            }),
            notify,
        })
    }

    pub fn attach(self: &Arc<Self>, bus: &mut IoBus) {
        let d = self.clone();
        bus.register(0x20, 2, "pic-master", Box::new(move |a| d.handle(false, a)));
        let d = self.clone();
        bus.register(0xa0, 2, "pic-slave", Box::new(move |a| d.handle(true, a)));
    }

    /// Latch ISA `irq` (0..=15) in its chip's IRR. Kicks the consumer if the INT
    /// output is now asserted; a masked IRQ stays latched until it's unmasked.
    pub fn raise(&self, irq: i32) {
        if !(0..=15).contains(&irq) {
            return;
        }
        let asserted = {
            let mut inner = self.inner.lock().unwrap();
            inner.chip(irq >= 8).irr |= 1 << (irq & 7);
            inner.highest().is_some()
        };
        if asserted {
            (self.notify)();
        }
    }

    /// True while the INT output is asserted (some unmasked IRQ awaits INTA).
    pub fn output_pending(&self) -> bool {
        self.inner.lock().unwrap().highest().is_some()
    }

    /// The INTA cycle: clear the highest-priority pending request and return its
    /// vector (`ICW2 base + IRQ`), or `None` if the output isn't asserted.
    pub fn acknowledge(&self) -> Option<u8> {
        let mut inner = self.inner.lock().unwrap();
        let (is_slave, irq) = inner.highest()?;
        let chip = inner.chip(is_slave);
        chip.irr &= !(1 << irq);
        Some(chip.vector_base.wrapping_add(irq))
    }

    fn handle(&self, is_slave: bool, acc: &mut IoAccess) {
        let cmd_port = acc.port == 0x20 || acc.port == 0xa0;
        let unmasked_pending = {
            let mut inner = self.inner.lock().unwrap();
            Self::handle_chip(&mut inner, is_slave, cmd_port, acc)
        };
        if unmasked_pending {
            (self.notify)();
        }
    }

    /// Returns true when a mask write unmasked a latched request.
    fn handle_chip(inner: &mut Inner, is_slave: bool, cmd_port: bool, acc: &mut IoAccess) -> bool {
        if !acc.is_write {
            let chip = inner.chip(is_slave);
            acc.value = if cmd_port { chip.irr } else { chip.mask } as u32;
            return false;
        }
        let v = (acc.value & 0xff) as u8;
        let chip = inner.chip(is_slave);
        if cmd_port {
            if v & ICW1_IS_INIT != 0 {
                chip.expect_icw4 = v & ICW1_IC4 != 0;
                chip.mask = 0xff;
                chip.irr = 0;
                chip.step = IcwStep::Icw2;
            }
            // OCW3 (status-read select) and OCW2 (EOI) need no state: the ISR
            // isn't modelled and the IRR is always what a status read returns.
            return false;
        }
        // Data port: ICW sequence or OCW1 mask.
        match chip.step {
            IcwStep::Icw2 => {
                chip.vector_base = v & 0xf8;
                chip.step = IcwStep::Icw3;
                false
            }
            IcwStep::Icw3 => {
                chip.step = if chip.expect_icw4 {
                    IcwStep::Icw4
                } else {
                    IcwStep::Idle
                };
                false
            }
            IcwStep::Icw4 => {
                chip.step = IcwStep::Idle;
                false
            }
            IcwStep::Idle => {
                let newly_unmasked = chip.mask & !v;
                chip.mask = v;
                newly_unmasked != 0 && inner.highest().is_some()
            }
        }
    }

    /// Snapshot the PIC pair for save/restore (master then slave; 5 bytes each).
    pub fn snapshot_capture(&self) -> Vec<u8> {
        let inner = self.inner.lock().unwrap();
        let mut b = Vec::with_capacity(10);
        for c in [&inner.master, &inner.slave] {
            b.push(c.vector_base);
            b.push(c.mask);
            b.push(c.irr);
            b.push(c.expect_icw4 as u8);
            b.push(match c.step {
                IcwStep::Idle => 0,
                IcwStep::Icw2 => 1,
                IcwStep::Icw3 => 2,
                IcwStep::Icw4 => 3,
            });
        }
        b
    }

    pub fn snapshot_apply(&self, bytes: &[u8]) {
        if bytes.len() < 10 {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        let mut o = 0;
        for ci in 0..2 {
            let chip = inner.chip(ci == 1);
            chip.vector_base = bytes[o];
            chip.mask = bytes[o + 1];
            chip.irr = bytes[o + 2];
            chip.expect_icw4 = bytes[o + 3] != 0;
            chip.step = match bytes[o + 4] {
                1 => IcwStep::Icw2,
                2 => IcwStep::Icw3,
                3 => IcwStep::Icw4,
                _ => IcwStep::Idle,
            };
            o += 5;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn pic() -> (Arc<Pic8259>, Arc<AtomicUsize>) {
        let kicks = Arc::new(AtomicUsize::new(0));
        let k = kicks.clone();
        let p = Pic8259::new(Box::new(move || {
            k.fetch_add(1, Ordering::SeqCst);
        }));
        (p, kicks)
    }

    fn outb(p: &Pic8259, port: u16, value: u8) {
        let mut a = IoAccess {
            port,
            access_size: 1,
            is_write: true,
            value: value as u32,
        };
        p.handle(port >= 0xa0, &mut a);
    }

    /// Linux's `init_8259A`: master vectors 0x30.., slave 0x38.., everything
    /// masked except the cascade input.
    fn init_like_linux(p: &Pic8259) {
        for (cmd, data, base, wire) in [(0x20, 0x21, 0x30, 0x04), (0xa0, 0xa1, 0x38, 0x02)] {
            outb(p, cmd, 0x11);
            outb(p, data, base);
            outb(p, data, wire);
            outb(p, data, 0x01);
        }
        outb(p, 0x21, !(1 << CASCADE_IRQ));
        outb(p, 0xa1, 0xff);
    }

    #[test]
    fn unmasked_irq_reaches_inta_once_as_icw2_base_plus_irq() {
        let (p, kicks) = pic();
        init_like_linux(&p);
        outb(&p, 0x21, !((1 << CASCADE_IRQ) | (1 << 4)));
        let before = kicks.load(Ordering::SeqCst);

        p.raise(4);
        assert!(p.output_pending());
        assert!(
            kicks.load(Ordering::SeqCst) > before,
            "raise must kick the BSP"
        );
        assert_eq!(p.acknowledge(), Some(0x34));
        assert!(!p.output_pending());
        assert_eq!(p.acknowledge(), None);
    }

    #[test]
    fn masked_irq_latches_and_asserts_when_unmasked() {
        let (p, kicks) = pic();
        init_like_linux(&p);
        let before = kicks.load(Ordering::SeqCst);

        p.raise(4);
        assert!(!p.output_pending());
        assert_eq!(p.acknowledge(), None);
        assert_eq!(kicks.load(Ordering::SeqCst), before);

        outb(&p, 0x21, !((1 << CASCADE_IRQ) | (1 << 4)));
        assert!(p.output_pending());
        assert!(
            kicks.load(Ordering::SeqCst) > before,
            "unmask must kick the BSP"
        );
        assert_eq!(p.acknowledge(), Some(0x34));
    }

    #[test]
    fn repeated_raises_before_inta_coalesce() {
        let (p, _) = pic();
        init_like_linux(&p);
        outb(&p, 0x21, !((1 << CASCADE_IRQ) | (1 << 4)));
        p.raise(4);
        p.raise(4);
        p.raise(4);
        assert_eq!(p.acknowledge(), Some(0x34));
        assert_eq!(p.acknowledge(), None);
    }

    #[test]
    fn fixed_priority_with_slave_requests_at_the_cascade_slot() {
        let (p, _) = pic();
        init_like_linux(&p);
        outb(&p, 0x21, !((1 << 1) | (1 << CASCADE_IRQ) | (1 << 4)));
        outb(&p, 0xa1, !(1 << 1));
        p.raise(4);
        p.raise(9);
        p.raise(1);
        assert_eq!(p.acknowledge(), Some(0x31));
        assert_eq!(p.acknowledge(), Some(0x39));
        assert_eq!(p.acknowledge(), Some(0x34));
        assert_eq!(p.acknowledge(), None);
    }

    #[test]
    fn slave_requests_wait_for_the_cascade_input() {
        let (p, _) = pic();
        init_like_linux(&p);
        outb(&p, 0x21, 0xff);
        outb(&p, 0xa1, !(1 << 1));
        p.raise(9);
        assert!(!p.output_pending());
        outb(&p, 0x21, !(1 << CASCADE_IRQ));
        assert_eq!(p.acknowledge(), Some(0x39));
    }

    #[test]
    fn reinitialisation_drops_latched_requests() {
        let (p, _) = pic();
        init_like_linux(&p);
        p.raise(4);
        init_like_linux(&p);
        outb(&p, 0x21, !((1 << CASCADE_IRQ) | (1 << 4)));
        assert!(!p.output_pending());
    }

    #[test]
    fn snapshot_round_trip_keeps_a_pending_request() {
        let (a, _) = pic();
        init_like_linux(&a);
        outb(&a, 0x21, !((1 << CASCADE_IRQ) | (1 << 4)));
        a.raise(4);
        let (b, _) = pic();
        b.snapshot_apply(&a.snapshot_capture());
        assert_eq!(b.acknowledge(), Some(0x34));
    }
}
