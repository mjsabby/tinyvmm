//! Minimal Intel 8254 PIT (channels 0..2) + system control port 0x61.
//! Counters only -- IRQ0 generation is intentionally not wired (the boot path
//! relies on the LAPIC clockevent, matching the C++ `(void)pit` decision).
//! Port of devices/pit8254.cpp.

use crate::devices::io_bus::{IoAccess, IoBus};
use std::sync::{Arc, Mutex};
use std::time::Instant;

const PIT_HZ: u128 = 1_193_182;

#[derive(Clone, Copy, PartialEq, Eq)]
enum AccessMode {
    Latch,
    LsbOnly,
    MsbOnly,
    LsbThenMsb,
}

impl AccessMode {
    fn from_bits(b: u8) -> AccessMode {
        match b & 0x3 {
            0 => AccessMode::Latch,
            1 => AccessMode::LsbOnly,
            2 => AccessMode::MsbOnly,
            _ => AccessMode::LsbThenMsb,
        }
    }
}

#[derive(Clone, Copy)]
struct Channel {
    access: AccessMode,
    mode: u8,
    reload: u16,
    reload_have_lsb: bool,
    reload_lsb: u8,
    read_msb_next: bool,
    latch_valid: bool,
    latched: u16,
    latched_msb_next: bool,
    gate: bool,
    start_ticks: u64,
    running: bool,
}

impl Default for Channel {
    fn default() -> Self {
        Channel {
            access: AccessMode::LsbThenMsb,
            mode: 0,
            reload: 0,
            reload_have_lsb: false,
            reload_lsb: 0,
            read_msb_next: false,
            latch_valid: false,
            latched: 0,
            latched_msb_next: false,
            gate: false,
            start_ticks: 0,
            running: false,
        }
    }
}

struct Inner {
    ch: [Channel; 3],
    port61: u8,
}

pub struct Pit8254 {
    inner: Mutex<Inner>,
    start: Instant,
}

impl Pit8254 {
    pub fn new() -> Arc<Self> {
        let mut ch = [Channel::default(); 3];
        ch[0].gate = true;
        ch[1].gate = true;
        ch[2].gate = false;
        Arc::new(Pit8254 {
            inner: Mutex::new(Inner { ch, port61: 0 }),
            start: Instant::now(),
        })
    }

    pub fn attach(self: &Arc<Self>, bus: &mut IoBus) {
        for ch in 0..3u16 {
            let d = self.clone();
            bus.register(
                0x40 + ch,
                1,
                "pit-chan",
                Box::new(move |a| d.handle_counter(ch as usize, a)),
            );
        }
        let d = self.clone();
        bus.register(0x43, 1, "pit-ctl", Box::new(move |a| d.handle_control(a)));
        let d = self.clone();
        bus.register(0x61, 1, "sys-ctrl-b", Box::new(move |a| d.handle_port61(a)));
    }

    fn now_ticks(&self) -> u64 {
        (self.start.elapsed().as_nanos() * PIT_HZ / 1_000_000_000) as u64
    }

    fn read_count(ch: &Channel, now: u64) -> u16 {
        if !ch.running || !ch.gate {
            return ch.reload;
        }
        let elapsed = now.wrapping_sub(ch.start_ticks);
        let reload: u32 = if ch.reload == 0 {
            0x10000
        } else {
            ch.reload as u32
        };
        if ch.mode == 0 {
            if elapsed >= reload as u64 {
                return 0;
            }
            return (reload - elapsed as u32) as u16;
        }
        let pos = (elapsed % reload as u64) as u32;
        (reload - pos) as u16
    }

    fn program_channel(&self, inner: &mut Inner, ch: usize, cw: u8) {
        let access = AccessMode::from_bits((cw & 0x30) >> 4);
        if access == AccessMode::Latch {
            let now = self.now_ticks();
            let c = &mut inner.ch[ch];
            c.latched = Self::read_count(c, now);
            c.latch_valid = true;
            c.latched_msb_next = false;
            return;
        }
        let c = &mut inner.ch[ch];
        c.access = access;
        c.mode = (cw & 0x0E) >> 1;
        c.reload_have_lsb = false;
        c.reload_lsb = 0;
        c.read_msb_next = false;
        c.latch_valid = false;
        c.running = false;
    }

    fn handle_control(&self, acc: &mut IoAccess) {
        if !acc.is_write {
            acc.value = 0xff;
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        let cw = (acc.value & 0xff) as u8;
        let sel = ((cw & 0xC0) >> 6) as usize;
        if sel == 3 {
            // Read-back: latch each selected channel.
            let now = self.now_ticks();
            for (i, mask) in [(0usize, 0x02u8), (1, 0x04), (2, 0x08)] {
                if cw & mask != 0 {
                    let c = &mut inner.ch[i];
                    c.latched = Self::read_count(c, now);
                    c.latch_valid = true;
                    c.latched_msb_next = false;
                }
            }
            return;
        }
        self.program_channel(&mut inner, sel, cw);
    }

    fn handle_counter(&self, ch: usize, acc: &mut IoAccess) {
        let mut inner = self.inner.lock().unwrap();

        if acc.is_write {
            let b = (acc.value & 0xff) as u8;
            let now = self.now_ticks();
            let c = &mut inner.ch[ch];
            match c.access {
                AccessMode::LsbOnly => {
                    c.reload = (c.reload & 0xff00) | b as u16;
                    c.start_ticks = now;
                    c.running = true;
                }
                AccessMode::MsbOnly => {
                    c.reload = (c.reload & 0x00ff) | ((b as u16) << 8);
                    c.start_ticks = now;
                    c.running = true;
                }
                AccessMode::LsbThenMsb => {
                    if !c.reload_have_lsb {
                        c.reload_lsb = b;
                        c.reload_have_lsb = true;
                    } else {
                        c.reload = c.reload_lsb as u16 | ((b as u16) << 8);
                        c.reload_have_lsb = false;
                        c.start_ticks = now;
                        c.running = true;
                    }
                }
                AccessMode::Latch => {}
            }
            return;
        }

        let now = self.now_ticks();
        let c = &mut inner.ch[ch];
        let from_latch = c.latch_valid;
        let val = if from_latch {
            c.latched
        } else {
            Self::read_count(c, now)
        };
        let out = match c.access {
            AccessMode::LsbOnly => (val & 0xff) as u8,
            AccessMode::MsbOnly => ((val >> 8) & 0xff) as u8,
            AccessMode::LsbThenMsb => {
                let msb_next = if from_latch {
                    &mut c.latched_msb_next
                } else {
                    &mut c.read_msb_next
                };
                if !*msb_next {
                    *msb_next = true;
                    (val & 0xff) as u8
                } else {
                    *msb_next = false;
                    if from_latch {
                        c.latch_valid = false;
                    }
                    ((val >> 8) & 0xff) as u8
                }
            }
            AccessMode::Latch => 0xff,
        };
        acc.value = out as u32;
    }

    fn handle_port61(&self, acc: &mut IoAccess) {
        let mut inner = self.inner.lock().unwrap();
        if acc.is_write {
            let b = (acc.value & 0xff) as u8;
            inner.port61 = b & 0x0f;
            let new_gate = b & 0x01 != 0;
            if new_gate != inner.ch[2].gate {
                inner.ch[2].gate = new_gate;
                if new_gate && inner.ch[2].running {
                    inner.ch[2].start_ticks = self.now_ticks();
                }
            }
            return;
        }
        let now = self.now_ticks();
        let mut v = inner.port61 & 0x03;
        let cnt = Self::read_count(&inner.ch[2], now);
        if inner.ch[2].mode == 0 && inner.ch[2].running && cnt == 0 {
            v |= 0x20;
        }
        acc.value = v as u32;
    }

    /// Snapshot the PIT: port61 + 3 channels. Per channel we store `elapsed`
    /// (ticks since start_ticks) rather than the absolute anchor, then re-anchor
    /// to the fresh Instant on apply (mirrors the C++ ResumeRuntime).
    pub fn snapshot_capture(&self) -> Vec<u8> {
        let now = self.now_ticks();
        let inner = self.inner.lock().unwrap();
        let mut b = Vec::new();
        b.push(inner.port61);
        for c in inner.ch.iter() {
            b.push(c.access as u8);
            b.push(c.mode);
            b.extend_from_slice(&c.reload.to_le_bytes());
            b.push(c.reload_have_lsb as u8);
            b.push(c.reload_lsb);
            b.push(c.read_msb_next as u8);
            b.push(c.latch_valid as u8);
            b.extend_from_slice(&c.latched.to_le_bytes());
            b.push(c.latched_msb_next as u8);
            b.push(c.gate as u8);
            b.push(c.running as u8);
            let elapsed = if c.running {
                now.wrapping_sub(c.start_ticks)
            } else {
                0
            };
            b.extend_from_slice(&elapsed.to_le_bytes());
        }
        b
    }

    pub fn snapshot_apply(&self, bytes: &[u8]) {
        const PER_CH: usize = 21;
        if bytes.len() < 1 + 3 * PER_CH {
            return;
        }
        let now = self.now_ticks();
        let mut inner = self.inner.lock().unwrap();
        inner.port61 = bytes[0];
        let mut o = 1;
        for i in 0..3 {
            let c = &mut inner.ch[i];
            c.access = AccessMode::from_bits(bytes[o] & 0x3);
            c.mode = bytes[o + 1];
            c.reload = u16::from_le_bytes([bytes[o + 2], bytes[o + 3]]);
            c.reload_have_lsb = bytes[o + 4] != 0;
            c.reload_lsb = bytes[o + 5];
            c.read_msb_next = bytes[o + 6] != 0;
            c.latch_valid = bytes[o + 7] != 0;
            c.latched = u16::from_le_bytes([bytes[o + 8], bytes[o + 9]]);
            c.latched_msb_next = bytes[o + 10] != 0;
            c.gate = bytes[o + 11] != 0;
            c.running = bytes[o + 12] != 0;
            let elapsed = u64::from_le_bytes(bytes[o + 13..o + 21].try_into().unwrap());
            c.start_ticks = now.wrapping_sub(elapsed);
            o += PER_CH;
        }
    }
}
