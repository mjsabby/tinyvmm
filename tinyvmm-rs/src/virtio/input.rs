//! virtio-input device (spec §5.8). Models Linux evdev input devices over two
//! virtqueues:
//!
//!   * eventq (queue 0): device -> driver. The driver posts device-writable
//!     8-byte buffers; we write one `virtio_input_event` per buffer as host
//!     input arrives, terminating each logical frame with `EV_SYN/SYN_REPORT`.
//!   * statusq (queue 1): driver -> device. The driver posts device-readable
//!     events (e.g. `EV_LED` keyboard LED state); we consume and ack them.
//!
//! Device config space uses the spec's select/subsel scheme: the driver writes
//! `select` + `subsel`, then reads back `size` and a 128-byte payload union
//! (name string / capability bitmap / absinfo / device ids). The probe order
//! and semantics are ported against the upstream Linux driver
//! (`drivers/virtio/virtio_input.c`): a select/subsel combination the device
//! does not support reports `size == 0` so the driver skips it.
//!
//! Two device personalities are provided ([`InputKind`]):
//!   * `Keyboard` — `EV_KEY` (key codes) + `EV_LED`.
//!   * `Tablet`   — an absolute pointer: `EV_ABS` (`ABS_X`/`ABS_Y`, 0..0x7fff)
//!     plus `EV_REL` (`REL_WHEEL`/`REL_HWHEEL` for scroll) and `EV_KEY`
//!     (`BTN_LEFT`/`BTN_RIGHT`/`BTN_MIDDLE`).
//!
//! Host input is delivered through [`InputDevice::submit_frame`]; the current
//! source is the Windows console (see `main.rs`), but the API is source-neutral
//! so a future virtio-gpu window can drive it directly.

use crate::diag::etw;
use crate::virtio::device::{
    VirtioDevice, DEVICE_ID_INPUT, FEATURE_RING_EVENT_IDX, FEATURE_VERSION_1,
};
use crate::virtio::queue::{ChainScratch, PoppedChain, QueueState, Virtqueue};
use crate::whp::GuestMemory;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

pub const EVENT_QUEUE: u32 = 0;
pub const STATUS_QUEUE: u32 = 1;
pub const INPUT_QUEUE_MAX: u32 = 64;

// ---- evdev event types (linux/input-event-codes.h) ----
pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_REL: u16 = 0x02;
pub const EV_ABS: u16 = 0x03;
pub const EV_MSC: u16 = 0x04;
pub const EV_LED: u16 = 0x11;
pub const EV_REP: u16 = 0x14;

pub const SYN_REPORT: u16 = 0x00;

// Relative axes.
pub const REL_HWHEEL: u16 = 0x06;
pub const REL_WHEEL: u16 = 0x08;

// Absolute axes.
pub const ABS_X: u16 = 0x00;
pub const ABS_Y: u16 = 0x01;

// Pointer buttons.
pub const BTN_LEFT: u16 = 0x110;
pub const BTN_RIGHT: u16 = 0x111;
pub const BTN_MIDDLE: u16 = 0x112;

// Keyboard LEDs.
const LED_NUML: u16 = 0x00;
const LED_CAPSL: u16 = 0x01;
const LED_SCROLLL: u16 = 0x02;

/// Inclusive maximum reported on `ABS_X`/`ABS_Y`. Host sources scale their
/// device coordinates into `0..=ABS_AXIS_MAX`.
pub const ABS_AXIS_MAX: u32 = 0x7fff;

/// Sentinel for "no absolute position reported yet" (distinct from a real
/// coordinate, which is always `<= ABS_AXIS_MAX`).
pub const ABS_NONE: u32 = u32::MAX;

// ---- config-space select values (spec §5.8.5) ----
const CFG_UNSET: u8 = 0x00;
const CFG_ID_NAME: u8 = 0x01;
const CFG_ID_SERIAL: u8 = 0x02;
const CFG_ID_DEVIDS: u8 = 0x03;
const CFG_PROP_BITS: u8 = 0x10;
const CFG_EV_BITS: u8 = 0x11;
const CFG_ABS_INFO: u8 = 0x12;

/// PCI/usb-style bus id reported in `virtio_input_devids.bustype` (BUS_VIRTUAL).
const BUS_VIRTUAL: u16 = 0x06;
/// `virtio_input_config` header is 8 bytes; the payload union is 128 bytes.
const CONFIG_LEN: usize = 8 + 128;

pub type IrqFn = Box<dyn Fn(u32) + Send + Sync>;

/// One evdev event (`struct virtio_input_event`: type, code, value), 8 bytes
/// on the wire. `value` is logically an `i32` (relative deltas / button state)
/// transported as little-endian `u32`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputEvent {
    pub type_: u16,
    pub code: u16,
    pub value: u32,
}

impl InputEvent {
    pub fn new(type_: u16, code: u16, value: u32) -> Self {
        InputEvent { type_, code, value }
    }
    /// A key/button press (`value = 1`) or release (`value = 0`).
    pub fn key(code: u16, down: bool) -> Self {
        Self::new(EV_KEY, code, if down { 1 } else { 0 })
    }
    /// A key event with an explicit value (`2` = autorepeat).
    pub fn key_value(code: u16, value: u32) -> Self {
        Self::new(EV_KEY, code, value)
    }
    pub fn abs(axis: u16, value: u32) -> Self {
        Self::new(EV_ABS, axis, value)
    }
    pub fn rel(axis: u16, delta: i32) -> Self {
        Self::new(EV_REL, axis, delta as u32)
    }
    pub fn syn() -> Self {
        Self::new(EV_SYN, SYN_REPORT, 0)
    }

    fn encode(&self) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0..2].copy_from_slice(&self.type_.to_le_bytes());
        b[2..4].copy_from_slice(&self.code.to_le_bytes());
        b[4..8].copy_from_slice(&self.value.to_le_bytes());
        b
    }

    fn decode(b: &[u8]) -> InputEvent {
        InputEvent {
            type_: u16::from_le_bytes([b[0], b[1]]),
            code: u16::from_le_bytes([b[2], b[3]]),
            value: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        }
    }
}

/// Which evdev personality a device exposes. Determines the config-space
/// capability advertisement only; the queue/event machinery is shared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputKind {
    Keyboard,
    Tablet,
}

impl InputKind {
    fn name(self) -> &'static [u8] {
        match self {
            InputKind::Keyboard => b"tinyvmm Keyboard",
            InputKind::Tablet => b"tinyvmm Tablet",
        }
    }

    fn product(self) -> u16 {
        match self {
            InputKind::Keyboard => 1,
            InputKind::Tablet => 2,
        }
    }

    /// Write the `EV_BITS`/`subsel` capability bitmap into `dst`, returning its
    /// length in bytes. 0 => unsupported event type (the driver skips it).
    fn fill_ev_bitmap(self, subsel: u8, dst: &mut [u8]) -> usize {
        match (self, subsel as u16) {
            // Full standard keyboard key range (codes 1..=255). KEY_RESERVED
            // (bit 0) is intentionally clear.
            (InputKind::Keyboard, EV_KEY) => {
                dst[..32].fill(0xFF);
                dst[0] = 0xFE;
                32
            }
            (InputKind::Keyboard, EV_LED) => {
                dst[0] = (1 << LED_NUML) | (1 << LED_CAPSL) | (1 << LED_SCROLLL);
                1
            }
            (InputKind::Tablet, EV_KEY) => fill_bits(dst, &[BTN_LEFT, BTN_RIGHT, BTN_MIDDLE]),
            (InputKind::Tablet, EV_REL) => fill_bits(dst, &[REL_HWHEEL, REL_WHEEL]),
            (InputKind::Tablet, EV_ABS) => fill_bits(dst, &[ABS_X, ABS_Y]),
            _ => 0,
        }
    }

    /// Write the `ABS_INFO` payload (`struct virtio_input_absinfo`) for `subsel`
    /// into `dst`, returning its length (0 if the axis is not absolute here).
    fn fill_abs_info(self, subsel: u8, dst: &mut [u8]) -> usize {
        match (self, subsel as u16) {
            (InputKind::Tablet, ABS_X) | (InputKind::Tablet, ABS_Y) => {
                // min, max, fuzz, flat, res
                write_le32s(dst, &[0, ABS_AXIS_MAX, 0, 0, 0])
            }
            _ => 0,
        }
    }
}

/// Set the bits for `codes` in `dst` (LE bitmap: byte 0 holds codes 0..=7,
/// byte 1 holds 8..=15, … — spec §5.8.5.2), returning the number of bytes
/// needed to hold the highest set bit.
fn fill_bits(dst: &mut [u8], codes: &[u16]) -> usize {
    let mut size = 0;
    for &c in codes {
        let byte = c as usize / 8;
        dst[byte] |= 1 << (c % 8);
        size = size.max(byte + 1);
    }
    size
}

/// Write each value as little-endian `u32` into `dst`; returns bytes written.
fn write_le32s(dst: &mut [u8], vals: &[u32]) -> usize {
    let mut off = 0;
    for &v in vals {
        dst[off..off + 4].copy_from_slice(&v.to_le_bytes());
        off += 4;
    }
    off
}

/// Write each value as little-endian `u16` into `dst`; returns bytes written.
fn write_le16s(dst: &mut [u8], vals: &[u16]) -> usize {
    let mut off = 0;
    for &v in vals {
        dst[off..off + 2].copy_from_slice(&v.to_le_bytes());
        off += 2;
    }
    off
}

/// Write the config payload (union) for `select`/`subsel` into `dst` (the
/// 128-byte union region), returning the `size` the device reports. 0 => the
/// combination advertises nothing. `struct virtio_input_devids` is
/// `{ bustype, vendor, product, version }`.
fn fill_payload(kind: InputKind, select: u8, subsel: u8, dst: &mut [u8]) -> usize {
    match select {
        CFG_ID_NAME => {
            let n = kind.name();
            dst[..n.len()].copy_from_slice(n);
            n.len()
        }
        CFG_ID_DEVIDS => write_le16s(dst, &[BUS_VIRTUAL, 0x1AF4, kind.product(), 1]),
        CFG_EV_BITS => kind.fill_ev_bitmap(subsel, dst),
        CFG_ABS_INFO => kind.fill_abs_info(subsel, dst),
        // CFG_ID_SERIAL, CFG_PROP_BITS, CFG_UNSET and unknowns advertise nothing.
        _ => 0,
    }
}

/// Build the 136-byte device config image for the current select/subsel. No
/// heap allocation: the payload is written straight into the stack buffer.
fn config_image(kind: InputKind, select: u8, subsel: u8) -> [u8; CONFIG_LEN] {
    let mut buf = [0u8; CONFIG_LEN];
    buf[0] = select;
    buf[1] = subsel;
    let size = fill_payload(kind, select, subsel, &mut buf[8..]);
    buf[2] = size as u8;
    buf
}

/// Durable device-internal state captured in the virtio snapshot's device-state
/// blob — everything not already held in the virtqueue rings or the PCI/MSI-X
/// state the transport snapshots separately. Length-versioned so a reader can
/// default any trailing fields a shorter (older) blob omits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DeviceState {
    driver_ok: bool,
    acked_features: u64,
    cfg_select: u8,
    cfg_subsel: u8,
    led_state: u32,
    last_abs_x: u32,
    last_abs_y: u32,
}

impl DeviceState {
    fn encode(&self) -> Vec<u8> {
        // Little-endian layout:
        //   [0]      driver_ok          [1..8]  reserved (0)
        //   [8..16]  acked_features
        //   [16] cfg_select  [17] cfg_subsel
        //   [18..22] led_state
        //   [22..26] last_abs_x         [26..30] last_abs_y  (ABS_NONE if unset)
        let mut b = vec![0u8; 16];
        b[0] = self.driver_ok as u8;
        b[8..16].copy_from_slice(&self.acked_features.to_le_bytes());
        b.push(self.cfg_select);
        b.push(self.cfg_subsel);
        b.extend_from_slice(&self.led_state.to_le_bytes());
        b.extend_from_slice(&self.last_abs_x.to_le_bytes());
        b.extend_from_slice(&self.last_abs_y.to_le_bytes());
        b
    }

    fn decode(b: &[u8]) -> DeviceState {
        let mut s = DeviceState {
            driver_ok: false,
            acked_features: 0,
            cfg_select: CFG_UNSET,
            cfg_subsel: 0,
            led_state: 0,
            last_abs_x: ABS_NONE,
            last_abs_y: ABS_NONE,
        };
        if b.len() >= 16 {
            s.driver_ok = b[0] != 0;
            s.acked_features = u64::from_le_bytes(b[8..16].try_into().unwrap());
        }
        if b.len() >= 18 {
            s.cfg_select = b[16];
            s.cfg_subsel = b[17];
        }
        if b.len() >= 22 {
            s.led_state = u32::from_le_bytes(b[18..22].try_into().unwrap());
        }
        if b.len() >= 30 {
            s.last_abs_x = u32::from_le_bytes(b[22..26].try_into().unwrap());
            s.last_abs_y = u32::from_le_bytes(b[26..30].try_into().unwrap());
        }
        s
    }
}

pub struct InputDevice {
    kind: InputKind,
    eventq: Mutex<Virtqueue>,
    statusq: Mutex<Virtqueue>,
    cfg_select: AtomicU8,
    cfg_subsel: AtomicU8,
    driver_ok: AtomicBool,
    acked_features: AtomicU64,
    led_state: AtomicU32,
    // Last absolute pointer position reported to the guest (tablet only),
    // captured in the device snapshot so it survives save/restore. The
    // authoritative copy also lives in the guest's evdev `absinfo` (restored
    // with guest RAM); persisting it here keeps the device snapshot
    // self-describing and lets a host source re-sync after restore.
    // `ABS_NONE` means "no position reported yet".
    last_abs_x: AtomicU32,
    last_abs_y: AtomicU32,
    irq: OnceLock<IrqFn>,
    event_scratch: Mutex<ChainScratch>,
    status_scratch: Mutex<ChainScratch>,
    events_sent: AtomicU64,
    events_dropped: AtomicU64,
}

impl InputDevice {
    pub fn new_keyboard(mem: Arc<GuestMemory>) -> Arc<Self> {
        Self::new(InputKind::Keyboard, mem)
    }

    pub fn new_tablet(mem: Arc<GuestMemory>) -> Arc<Self> {
        Self::new(InputKind::Tablet, mem)
    }

    fn new(kind: InputKind, mem: Arc<GuestMemory>) -> Arc<Self> {
        Arc::new(InputDevice {
            kind,
            eventq: Mutex::new(Virtqueue::new(mem.clone(), INPUT_QUEUE_MAX)),
            statusq: Mutex::new(Virtqueue::new(mem, INPUT_QUEUE_MAX)),
            cfg_select: AtomicU8::new(CFG_UNSET),
            cfg_subsel: AtomicU8::new(0),
            driver_ok: AtomicBool::new(false),
            acked_features: AtomicU64::new(0),
            led_state: AtomicU32::new(0),
            last_abs_x: AtomicU32::new(ABS_NONE),
            last_abs_y: AtomicU32::new(ABS_NONE),
            irq: OnceLock::new(),
            event_scratch: Mutex::new(ChainScratch::default()),
            status_scratch: Mutex::new(ChainScratch::default()),
            events_sent: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
        })
    }

    pub fn kind(&self) -> InputKind {
        self.kind
    }

    pub fn set_irq_callback(&self, f: IrqFn) {
        let _ = self.irq.set(f);
    }

    pub fn events_sent(&self) -> u64 {
        self.events_sent.load(Ordering::Relaxed)
    }
    pub fn events_dropped(&self) -> u64 {
        self.events_dropped.load(Ordering::Relaxed)
    }

    /// Last absolute pointer position delivered to the guest, or `None` if no
    /// `ABS_X`/`ABS_Y` has been reported yet. Survives save/restore. A host
    /// source (e.g. the planned virtio-gpu window) can use this after restore
    /// to re-sync its cursor to where the guest left it.
    pub fn last_abs(&self) -> Option<(u32, u32)> {
        let x = self.last_abs_x.load(Ordering::Relaxed);
        let y = self.last_abs_y.load(Ordering::Relaxed);
        if x == ABS_NONE || y == ABS_NONE {
            None
        } else {
            Some((x, y))
        }
    }

    /// Re-assert the last known absolute position as a fresh frame so the
    /// guest's pointer snaps back to where it was left. No-op if no position
    /// has been reported. Intended to be called by a host source when it knows
    /// the guest is running (e.g. on window focus-in after a restore); it is
    /// deliberately NOT invoked automatically during restore — the position is
    /// already in restored guest RAM, so this is only a belt-and-suspenders
    /// re-sync for hosts that want it.
    pub fn resync_pointer(&self) {
        if let Some((x, y)) = self.last_abs() {
            self.submit_frame(&[InputEvent::abs(ABS_X, x), InputEvent::abs(ABS_Y, y)]);
        }
    }

    fn track_abs(&self, events: &[InputEvent]) {
        for ev in events {
            if ev.type_ == EV_ABS {
                match ev.code {
                    ABS_X => self.last_abs_x.store(ev.value, Ordering::Relaxed),
                    ABS_Y => self.last_abs_y.store(ev.value, Ordering::Relaxed),
                    _ => {}
                }
            }
        }
    }

    fn raise(&self, qidx: u32) {
        if let Some(cb) = self.irq.get() {
            cb(qidx);
        }
    }

    /// Deliver one logical input frame to the guest: every event in `events`
    /// followed by a trailing `EV_SYN/SYN_REPORT`, raising a single eventq
    /// interrupt. Events are dropped (and counted) if the guest has not posted
    /// enough eventq buffers, mirroring real hardware backpressure. Safe to call
    /// from any thread (the host input source thread).
    pub fn submit_frame(&self, events: &[InputEvent]) {
        if events.is_empty() {
            return;
        }
        // Remember the last absolute position even if the frame is dropped
        // below, so it is preserved across save/restore and queryable by a
        // host source.
        self.track_abs(events);
        let mut sent = 0u64;
        let mut dropped = 0u64;
        let interrupt;
        {
            let mut q = self.eventq.lock().unwrap();
            if !q.ready() {
                // No ring yet: the whole frame (+ SYN) is lost.
                self.events_dropped
                    .fetch_add(events.len() as u64 + 1, Ordering::Relaxed);
                return;
            }
            let mut scratch = self.event_scratch.lock().unwrap();
            for ev in events {
                if push_event(&mut q, &mut scratch, ev) {
                    sent += 1;
                } else {
                    dropped += 1;
                }
            }
            if push_event(&mut q, &mut scratch, &InputEvent::syn()) {
                sent += 1;
            } else {
                dropped += 1;
            }
            // Only consult the interrupt suppression logic when we actually
            // published used entries; a fully-dropped frame must not raise a
            // spurious eventq interrupt.
            interrupt = sent > 0 && q.should_interrupt_driver();
        }
        if sent > 0 {
            self.events_sent.fetch_add(sent, Ordering::Relaxed);
        }
        if dropped > 0 {
            self.events_dropped.fetch_add(dropped, Ordering::Relaxed);
        }
        if etw::enabled(etw::VERBOSE, etw::kw::VIRTIO) {
            etw::Event::new("VirtioInputFrame", etw::VERBOSE, etw::kw::VIRTIO)
                .u64("sent", sent)
                .u64("dropped", dropped)
                .write();
        }
        if interrupt {
            self.raise(EVENT_QUEUE);
        }
    }

    /// Drain the statusq: the driver writes status events here (e.g. keyboard
    /// LED state). We track LED state for diagnostics and ack each chain.
    fn drain_status(&self) {
        let mut interrupt = false;
        let mut any = false;
        {
            let mut q = self.statusq.lock().unwrap();
            if !q.ready() {
                return;
            }
            let mut scratch = self.status_scratch.lock().unwrap();
            while q.pop_into(&mut scratch) {
                for buf in scratch.bufs.iter() {
                    // statusq buffers are device-readable (driver-written).
                    if buf.write || buf.len == 0 {
                        continue;
                    }
                    let data = buf.as_slice();
                    let mut off = 0;
                    while off + 8 <= data.len() {
                        self.handle_status_event(InputEvent::decode(&data[off..off + 8]));
                        off += 8;
                    }
                }
                q.push(scratch.head_index, 0);
                any = true;
            }
            if any {
                interrupt = q.should_interrupt_driver();
            }
        }
        if interrupt {
            self.raise(STATUS_QUEUE);
        }
    }

    fn handle_status_event(&self, ev: InputEvent) {
        if ev.type_ == EV_LED && ev.code < 32 {
            let bit = 1u32 << ev.code;
            if ev.value != 0 {
                self.led_state.fetch_or(bit, Ordering::Relaxed);
            } else {
                self.led_state.fetch_and(!bit, Ordering::Relaxed);
            }
        }
    }
}

/// Pop one eventq chain and write `ev` into its first device-writable buffer,
/// then publish it with the bytes-written length. Returns false (event dropped)
/// when the ring is empty.
fn push_event(q: &mut Virtqueue, scratch: &mut PoppedChain, ev: &InputEvent) -> bool {
    if !q.pop_into(scratch) {
        return false;
    }
    let bytes = ev.encode();
    let mut wrote = 0u32;
    for buf in scratch.bufs.iter_mut() {
        if !buf.write || buf.len == 0 {
            continue;
        }
        let dst = buf.as_mut_slice();
        let n = dst.len().min(bytes.len());
        dst[..n].copy_from_slice(&bytes[..n]);
        wrote = n as u32;
        break;
    }
    q.push(scratch.head_index, wrote);
    true
}

impl VirtioDevice for InputDevice {
    fn device_id(&self) -> u32 {
        DEVICE_ID_INPUT
    }

    fn device_features(&self) -> u64 {
        FEATURE_VERSION_1 | FEATURE_RING_EVENT_IDX
    }

    fn set_driver_features(&self, acked: u64) -> bool {
        if acked & FEATURE_VERSION_1 == 0 {
            return false;
        }
        if acked & !self.device_features() != 0 {
            return false;
        }
        self.acked_features.store(acked, Ordering::Relaxed);
        true
    }

    fn queue_count(&self) -> u32 {
        2
    }

    fn queue_max(&self, idx: u32) -> u32 {
        if idx == EVENT_QUEUE || idx == STATUS_QUEUE {
            INPUT_QUEUE_MAX
        } else {
            0
        }
    }

    fn enable_queue(&self, idx: u32, desc: u64, avail: u64, used: u64, size: u16, event_idx: bool) {
        let q = match idx {
            EVENT_QUEUE => &self.eventq,
            STATUS_QUEUE => &self.statusq,
            _ => return,
        };
        let mut q = q.lock().unwrap();
        q.set_desc_gpa(desc);
        q.set_avail_gpa(avail);
        q.set_used_gpa(used);
        q.set_size(size as u32);
        q.set_event_idx_enabled(event_idx);
        q.set_ready(true);
    }

    fn disable_queue(&self, idx: u32) {
        let q = match idx {
            EVENT_QUEUE => &self.eventq,
            STATUS_QUEUE => &self.statusq,
            _ => return,
        };
        q.lock().unwrap().set_ready(false);
    }

    fn notify_queue(&self, idx: u32) {
        // eventq replenishment (the driver re-posting read buffers) needs no
        // action: we consume buffers lazily as host events arrive. Only the
        // statusq carries driver -> device work.
        if idx == STATUS_QUEUE {
            self.drain_status();
        }
    }

    fn driver_ok(&self) {
        self.driver_ok.store(true, Ordering::Relaxed);
    }

    fn reset(&self) {
        self.driver_ok.store(false, Ordering::Relaxed);
        self.acked_features.store(0, Ordering::Relaxed);
        self.led_state.store(0, Ordering::Relaxed);
        self.cfg_select.store(CFG_UNSET, Ordering::Relaxed);
        self.cfg_subsel.store(0, Ordering::Relaxed);
        self.eventq.lock().unwrap().reset();
        self.statusq.lock().unwrap().reset();
    }

    fn read_config(&self, offset: u32, size: u32) -> u32 {
        let img = config_image(
            self.kind,
            self.cfg_select.load(Ordering::Relaxed),
            self.cfg_subsel.load(Ordering::Relaxed),
        );
        let off = offset as usize;
        if off >= img.len() {
            return 0;
        }
        let mut take = (size as usize).min(4);
        if off + take > img.len() {
            take = img.len() - off;
        }
        let mut v = [0u8; 4];
        v[..take].copy_from_slice(&img[off..off + take]);
        u32::from_le_bytes(v)
    }

    fn write_config(&self, offset: u32, size: u32, value: u32) {
        // Only `select` (byte 0) and `subsel` (byte 1) are writable; `size` and
        // the payload union are read-only, reserved bytes are ignored.
        let bytes = value.to_le_bytes();
        for (i, &b) in bytes.iter().take((size as usize).min(4)).enumerate() {
            match offset + i as u32 {
                0 => self.cfg_select.store(b, Ordering::Relaxed),
                1 => self.cfg_subsel.store(b, Ordering::Relaxed),
                _ => {}
            }
        }
    }

    fn capture_queue(&self, idx: u32) -> Option<QueueState> {
        match idx {
            EVENT_QUEUE => Some(self.eventq.lock().unwrap().capture()),
            STATUS_QUEUE => Some(self.statusq.lock().unwrap().capture()),
            _ => None,
        }
    }

    fn apply_queue(&self, idx: u32, st: &QueueState) {
        match idx {
            EVENT_QUEUE => self.eventq.lock().unwrap().apply(st),
            STATUS_QUEUE => self.statusq.lock().unwrap().apply(st),
            _ => {}
        }
    }

    fn capture_device_state(&self) -> Vec<u8> {
        DeviceState {
            driver_ok: self.driver_ok.load(Ordering::Relaxed),
            acked_features: self.acked_features.load(Ordering::Relaxed),
            cfg_select: self.cfg_select.load(Ordering::Relaxed),
            cfg_subsel: self.cfg_subsel.load(Ordering::Relaxed),
            led_state: self.led_state.load(Ordering::Relaxed),
            last_abs_x: self.last_abs_x.load(Ordering::Relaxed),
            last_abs_y: self.last_abs_y.load(Ordering::Relaxed),
        }
        .encode()
    }

    fn apply_device_state(&self, bytes: &[u8]) {
        let s = DeviceState::decode(bytes);
        self.driver_ok.store(s.driver_ok, Ordering::Relaxed);
        self.acked_features.store(s.acked_features, Ordering::Relaxed);
        self.cfg_select.store(s.cfg_select, Ordering::Relaxed);
        self.cfg_subsel.store(s.cfg_subsel, Ordering::Relaxed);
        self.led_state.store(s.led_state, Ordering::Relaxed);
        self.last_abs_x.store(s.last_abs_x, Ordering::Relaxed);
        self.last_abs_y.store(s.last_abs_y, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn size_byte(kind: InputKind, select: u8, subsel: u8) -> u8 {
        config_image(kind, select, subsel)[2]
    }

    fn payload(kind: InputKind, select: u8, subsel: u8) -> Vec<u8> {
        let img = config_image(kind, select, subsel);
        let n = img[2] as usize;
        img[8..8 + n].to_vec()
    }

    #[test]
    fn event_encode_roundtrip() {
        let ev = InputEvent::new(EV_ABS, ABS_X, 0x1234);
        let b = ev.encode();
        assert_eq!(b, [0x03, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00]);
        assert_eq!(InputEvent::decode(&b), ev);
    }

    #[test]
    fn event_helpers() {
        assert_eq!(InputEvent::key(BTN_LEFT, true), InputEvent::new(EV_KEY, BTN_LEFT, 1));
        assert_eq!(InputEvent::key(BTN_LEFT, false), InputEvent::new(EV_KEY, BTN_LEFT, 0));
        assert_eq!(InputEvent::rel(REL_WHEEL, -1), InputEvent::new(EV_REL, REL_WHEEL, u32::MAX));
        assert_eq!(InputEvent::syn(), InputEvent::new(EV_SYN, SYN_REPORT, 0));
    }

    #[test]
    fn config_header_reflects_select_subsel() {
        let img = config_image(InputKind::Keyboard, CFG_ID_NAME, 0);
        assert_eq!(img[0], CFG_ID_NAME);
        assert_eq!(img[1], 0);
        assert_eq!(&img[8..8 + img[2] as usize], InputKind::Keyboard.name());
    }

    #[test]
    fn keyboard_advertises_keys_and_leds_only() {
        // EV_KEY: 32-byte bitmap, KEY_RESERVED (bit 0) clear, all else set.
        let keys = payload(InputKind::Keyboard, CFG_EV_BITS, EV_KEY as u8);
        assert_eq!(keys.len(), 32);
        assert_eq!(keys[0], 0xFE);
        assert!(keys[1..].iter().all(|&b| b == 0xFF));
        // Common keycodes the console source emits must be advertised.
        for code in [1u16 /*ESC*/, 28 /*ENTER*/, 57 /*SPACE*/, 103 /*UP*/, 125 /*LEFTMETA*/] {
            assert!(keys[code as usize / 8] & (1 << (code % 8)) != 0);
        }
        // EV_LED: NUML|CAPSL|SCROLLL.
        assert_eq!(payload(InputKind::Keyboard, CFG_EV_BITS, EV_LED as u8), vec![0x07]);
        // No relative or absolute axes on a keyboard.
        assert_eq!(size_byte(InputKind::Keyboard, CFG_EV_BITS, EV_REL as u8), 0);
        assert_eq!(size_byte(InputKind::Keyboard, CFG_EV_BITS, EV_ABS as u8), 0);
    }

    #[test]
    fn tablet_advertises_abs_rel_and_buttons() {
        // Buttons: BTN_LEFT/RIGHT/MIDDLE at 0x110..0x112 -> byte 34 = 0b111.
        let btns = payload(InputKind::Tablet, CFG_EV_BITS, EV_KEY as u8);
        assert_eq!(btns.len(), 35);
        assert_eq!(btns[34], 0x07);
        assert!(btns[..34].iter().all(|&b| b == 0));
        // ABS_X|ABS_Y.
        assert_eq!(payload(InputKind::Tablet, CFG_EV_BITS, EV_ABS as u8), vec![0x03]);
        // REL_HWHEEL (bit 6) + REL_WHEEL (bit 8).
        assert_eq!(payload(InputKind::Tablet, CFG_EV_BITS, EV_REL as u8), vec![0x40, 0x01]);
        // A tablet is not a keyboard: it must not claim EV_LED.
        assert_eq!(size_byte(InputKind::Tablet, CFG_EV_BITS, EV_LED as u8), 0);
    }

    #[test]
    fn tablet_absinfo_axes() {
        for axis in [ABS_X, ABS_Y] {
            let info = payload(InputKind::Tablet, CFG_ABS_INFO, axis as u8);
            assert_eq!(info.len(), 20);
            assert_eq!(u32::from_le_bytes(info[0..4].try_into().unwrap()), 0); // min
            assert_eq!(u32::from_le_bytes(info[4..8].try_into().unwrap()), ABS_AXIS_MAX); // max
        }
        // Keyboard has no absinfo.
        assert_eq!(size_byte(InputKind::Keyboard, CFG_ABS_INFO, ABS_X as u8), 0);
    }

    #[test]
    fn devids_reported_for_id_query() {
        let ids = payload(InputKind::Tablet, CFG_ID_DEVIDS, 0);
        assert_eq!(ids.len(), 8);
        assert_eq!(u16::from_le_bytes([ids[0], ids[1]]), BUS_VIRTUAL);
        assert_eq!(u16::from_le_bytes([ids[2], ids[3]]), 0x1AF4);
        assert_eq!(u16::from_le_bytes([ids[4], ids[5]]), 2); // tablet product id
    }

    #[test]
    fn unsupported_selects_report_zero_size() {
        // PROP_BITS and SERIAL are advertised as empty (size 0) on both kinds,
        // matching the upstream reference device.
        for kind in [InputKind::Keyboard, InputKind::Tablet] {
            assert_eq!(size_byte(kind, CFG_PROP_BITS, 0), 0);
            assert_eq!(size_byte(kind, CFG_ID_SERIAL, 0), 0);
            assert_eq!(size_byte(kind, CFG_UNSET, 0), 0);
            assert_eq!(size_byte(kind, CFG_EV_BITS, EV_REP as u8), 0);
        }
    }

    #[test]
    fn device_state_roundtrip() {
        // Everything the device snapshot must preserve, including the last
        // absolute pointer position ("where it was left").
        let s = DeviceState {
            driver_ok: true,
            acked_features: FEATURE_VERSION_1 | FEATURE_RING_EVENT_IDX,
            cfg_select: CFG_EV_BITS,
            cfg_subsel: EV_ABS as u8,
            led_state: 0b101,
            last_abs_x: 12345,
            last_abs_y: ABS_AXIS_MAX,
        };
        let bytes = s.encode();
        assert_eq!(bytes.len(), 30);
        assert_eq!(DeviceState::decode(&bytes), s);
    }

    #[test]
    fn device_state_decode_is_length_tolerant() {
        // A short (older-format) blob must decode with the missing trailing
        // fields defaulted, never panic.
        let full = DeviceState {
            driver_ok: true,
            acked_features: 0xABCD,
            cfg_select: 1,
            cfg_subsel: 2,
            led_state: 7,
            last_abs_x: 100,
            last_abs_y: 200,
        }
        .encode();

        // Truncate to the pre-position 22-byte format: positions default to NONE.
        let no_pos = DeviceState::decode(&full[..22]);
        assert!(no_pos.driver_ok);
        assert_eq!(no_pos.led_state, 7);
        assert_eq!(no_pos.last_abs_x, ABS_NONE);
        assert_eq!(no_pos.last_abs_y, ABS_NONE);

        // An empty blob yields the all-default state without panicking.
        let empty = DeviceState::decode(&[]);
        assert!(!empty.driver_ok);
        assert_eq!(empty.acked_features, 0);
        assert_eq!(empty.last_abs_x, ABS_NONE);
    }

    #[test]
    fn track_abs_remembers_last_position() {
        // Pure check of the position-tracking rule submit_frame applies.
        let mut x = ABS_NONE;
        let mut y = ABS_NONE;
        let frame = [
            InputEvent::abs(ABS_X, 4096),
            InputEvent::abs(ABS_Y, 8192),
            InputEvent::key(BTN_LEFT, true),
        ];
        for ev in frame {
            if ev.type_ == EV_ABS {
                match ev.code {
                    ABS_X => x = ev.value,
                    ABS_Y => y = ev.value,
                    _ => {}
                }
            }
        }
        assert_eq!((x, y), (4096, 8192));
    }
}
