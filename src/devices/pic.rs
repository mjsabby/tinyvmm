//! Minimal Intel 8259A PIC pair (master @ 0x20/0x21, slave @ 0xa0/0xa1).
//! Port of devices/i8259.cpp (save/restore omitted).

use crate::devices::io_bus::{IoAccess, IoBus};
use std::sync::{Arc, Mutex};

const ICW1_IS_INIT: u8 = 0x10;
const ICW1_IC4: u8 = 0x01;
const OCW3_MARK: u8 = 0x08;

pub type InjectFn = Box<dyn Fn(u8, u32) -> bool + Send + Sync>;

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

pub struct Pic8259 {
    inner: Mutex<Inner>,
    inject: InjectFn,
}

impl Pic8259 {
    pub fn new(inject: InjectFn) -> Arc<Self> {
        Arc::new(Pic8259 {
            inner: Mutex::new(Inner {
                master: Chip::default(),
                slave: Chip::default(),
            }),
            inject,
        })
    }

    pub fn attach(self: &Arc<Self>, bus: &mut IoBus) {
        let d = self.clone();
        bus.register(0x20, 2, "pic-master", Box::new(move |a| d.handle(false, a)));
        let d = self.clone();
        bus.register(0xa0, 2, "pic-slave", Box::new(move |a| d.handle(true, a)));
    }

    fn handle(&self, is_slave: bool, acc: &mut IoAccess) {
        let cmd_port = acc.port == 0x20 || acc.port == 0xa0;
        let mut inner = self.inner.lock().unwrap();
        self.handle_chip(&mut inner, is_slave, cmd_port, acc);
    }

    fn handle_chip(&self, inner: &mut Inner, is_slave: bool, cmd_port: bool, acc: &mut IoAccess) {
        if acc.is_write {
            let v = (acc.value & 0xff) as u8;
            if cmd_port {
                if v & ICW1_IS_INIT != 0 {
                    let chip = if is_slave {
                        &mut inner.slave
                    } else {
                        &mut inner.master
                    };
                    chip.expect_icw4 = v & ICW1_IC4 != 0;
                    chip.mask = 0xff;
                    chip.irr = 0;
                    chip.step = IcwStep::Icw2;
                } else if v & OCW3_MARK != 0 {
                    // OCW3 status-read config: nothing to track.
                } else {
                    // OCW2: EOI -- absorbed (we don't track ISR).
                }
                return;
            }
            // Data port: ICW sequence or OCW1 mask.
            let step = if is_slave {
                inner.slave.step
            } else {
                inner.master.step
            };
            match step {
                IcwStep::Icw2 => {
                    let chip = if is_slave {
                        &mut inner.slave
                    } else {
                        &mut inner.master
                    };
                    chip.vector_base = v & 0xf8;
                    chip.step = IcwStep::Icw3;
                }
                IcwStep::Icw3 => {
                    let chip = if is_slave {
                        &mut inner.slave
                    } else {
                        &mut inner.master
                    };
                    chip.step = if chip.expect_icw4 {
                        IcwStep::Icw4
                    } else {
                        IcwStep::Idle
                    };
                }
                IcwStep::Icw4 => {
                    let chip = if is_slave {
                        &mut inner.slave
                    } else {
                        &mut inner.master
                    };
                    chip.step = IcwStep::Idle;
                }
                IcwStep::Idle => {
                    let prev = if is_slave {
                        inner.slave.mask
                    } else {
                        inner.master.mask
                    };
                    if is_slave {
                        inner.slave.mask = v;
                    } else {
                        inner.master.mask = v;
                    }
                    self.replay(inner, is_slave, prev);
                }
            }
            return;
        }

        // Read side.
        let chip = if is_slave {
            &inner.slave
        } else {
            &inner.master
        };
        acc.value = if cmd_port { chip.irr } else { chip.mask } as u32;
    }

    fn inject_chip(&self, chip: &Chip, local_irq: i32) {
        let vector = chip.vector_base.wrapping_add((local_irq & 7) as u8);
        (self.inject)(vector, 0);
    }

    fn replay(&self, inner: &mut Inner, is_slave: bool, prev_mask: u8) {
        let (mask, irr) = if is_slave {
            (inner.slave.mask, inner.slave.irr)
        } else {
            (inner.master.mask, inner.master.irr)
        };
        let newly_unmasked = prev_mask & !mask;
        if newly_unmasked == 0 {
            return;
        }
        for i in 0..8 {
            let bit = 1u8 << i;
            if newly_unmasked & bit != 0 && irr & bit != 0 {
                if is_slave {
                    inner.slave.irr &= !bit;
                    let chip = inner.slave;
                    self.inject_chip(&chip, i);
                } else {
                    inner.master.irr &= !bit;
                    let chip = inner.master;
                    self.inject_chip(&chip, i);
                }
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
            let chip = if ci == 0 {
                &mut inner.master
            } else {
                &mut inner.slave
            };
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

    pub fn raise(&self, irq: i32) {
        if !(0..=15).contains(&irq) {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        let is_slave = irq >= 8;
        let local = irq & 7;
        let bit = 1u8 << local;

        let masked = if is_slave {
            inner.slave.mask & bit != 0
        } else {
            inner.master.mask & bit != 0
        };
        if masked {
            if is_slave {
                inner.slave.irr |= bit;
            } else {
                inner.master.irr |= bit;
            }
            return;
        }

        if is_slave {
            const CASCADE_BIT: u8 = 1 << 2;
            if inner.master.mask & CASCADE_BIT != 0 {
                inner.slave.irr |= bit;
                return;
            }
            let chip = inner.slave;
            self.inject_chip(&chip, local);
        } else {
            let chip = inner.master;
            self.inject_chip(&chip, local);
        }
    }
}
