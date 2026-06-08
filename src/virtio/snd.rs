//! virtio-snd device (spec §5.14): a sound card with one playback and one
//! capture PCM stream, backed by Windows WASAPI in shared mode.
//!
//! # Queues
//!   * controlq (0): driver -> device PCM/jack/chmap control requests, serviced
//!     inline on the vCPU thread (cold path).
//!   * eventq   (1): device -> driver async events. We don't emit any (period
//!     elapse is implicit in tx/rx completion), so it stays idle.
//!   * txq      (2): playback PCM frames (guest -> host). Hot path.
//!   * rxq      (3): capture PCM frames (host -> guest). Hot path.
//!
//! # Format
//! A single fixed contract is advertised to the guest: 48 kHz / S16_LE / stereo.
//! The WASAPI clients are opened with `AUTOCONVERTPCM`, so the audio engine
//! resamples/reformats to the endpoint's mix format and the guest PCM and the
//! WASAPI buffer share the exact same byte layout — the data path is a plain
//! `copy_from_slice` with no per-period allocation and no software DSP.
//!
//! # Threading
//! Two dedicated worker threads (one per direction) own the WASAPI client
//! lifecycle and run the event-driven audio clock. The control queue only flips
//! per-stream `running` flags and signals the workers; the workers pull/produce
//! PCM paced by the WASAPI buffer-ready event. If no endpoint can be opened (a
//! headless host), a worker falls back to completing I/O buffers on a period
//! timer so the guest's audio pipeline still flows (playback discarded, capture
//! silent). All Win32/COM `unsafe` lives in `winsys::audio`; this device is
//! `unsafe`-free except for the `Send` assertion on its reused popped chains
//! (the same one virtio-net makes).

use crate::diag::etw;
use crate::host::audio::{
    self, CaptureClient, ComInit, Event, INFINITE, RenderClient, WaitOutcome, wait_any,
};
use crate::virtio::device::{
    DEVICE_ID_SOUND, FEATURE_RING_EVENT_IDX, FEATURE_VERSION_1, VirtioDevice,
};
use crate::virtio::queue::{ChainScratch, PoppedChain, QueueState, Virtqueue};
use crate::whp::GuestMemory;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::thread::JoinHandle;

pub const SND_CONTROL_QUEUE: u32 = 0;
pub const SND_EVENT_QUEUE: u32 = 1;
pub const SND_TX_QUEUE: u32 = 2;
pub const SND_RX_QUEUE: u32 = 3;
pub const SND_QUEUE_COUNT: u32 = 4;

const CTRL_QUEUE_MAX: u32 = 64;
const PCM_QUEUE_MAX: u32 = 256;

// ---- control request codes (uapi/linux/virtio_snd.h) ----
const R_JACK_INFO: u32 = 1;
const R_JACK_REMAP: u32 = 2;
const R_PCM_INFO: u32 = 0x0100;
const R_PCM_SET_PARAMS: u32 = 0x0101;
const R_PCM_PREPARE: u32 = 0x0102;
const R_PCM_RELEASE: u32 = 0x0103;
const R_PCM_START: u32 = 0x0104;
const R_PCM_STOP: u32 = 0x0105;
const R_CHMAP_INFO: u32 = 0x0200;

// ---- common status codes ----
const S_OK: u32 = 0x8000;
const S_BAD_MSG: u32 = 0x8001;
const S_NOT_SUPP: u32 = 0x8002;

// ---- dataflow directions ----
const D_OUTPUT: u8 = 0;
const D_INPUT: u8 = 1;

// ---- selected PCM format / rate bits ----
const FMT_S16: u8 = 5;
const RATE_48000: u8 = 7;

// ---- channel-map positions ----
const CHMAP_FL: u8 = 3;
const CHMAP_FR: u8 = 4;

// ---- on-the-wire sizes ----
const XFER_BYTES: usize = 4; // virtio_snd_pcm_xfer { stream_id }
const STATUS_BYTES: usize = 8; // virtio_snd_pcm_status { status, latency_bytes }

const NUM_JACKS: u32 = 2;
const NUM_STREAMS: u32 = 2;
const NUM_CHMAPS: u32 = 2;

const STREAM_OUTPUT: u32 = 0;
const STREAM_INPUT: u32 = 1;

/// HDA pin default-config "device" field (bits 23:20): Speaker(1) / Mic-in(0xA).
const DEFCONF_SPEAKER: u32 = 0x0010_0000;
const DEFCONF_MIC: u32 = 0x00A0_0000;

pub type IrqFn = Box<dyn Fn(u32) + Send + Sync>;

/// One PCM direction's virtqueue plus the in-flight chain being filled/drained
/// across worker iterations (so a guest period can span several WASAPI ticks
/// without ever re-popping it). The reused `PoppedChain` holds raw guest
/// pointers; like virtio-net's scratch it is only touched under this lock during
/// a single transfer, so asserting `Send` for the owning struct is sound.
struct PcmIo {
    q: Virtqueue,
    cur: PoppedChain,
    cur_valid: bool,
    cur_off: usize,
    cur_payload: usize,
}

// SAFETY: see the doc comment above — `cur`'s raw pointers are only dereferenced
// under the owning `Mutex` during a transfer, never shared across threads.
unsafe impl Send for PcmIo {}

impl PcmIo {
    fn new(mem: Arc<GuestMemory>) -> Self {
        PcmIo {
            q: Virtqueue::new(mem, PCM_QUEUE_MAX),
            cur: PoppedChain::default(),
            cur_valid: false,
            cur_off: 0,
            cur_payload: 0,
        }
    }
}

pub struct SndDevice {
    controlq: Mutex<Virtqueue>,
    eventq: Mutex<Virtqueue>,
    play: Mutex<PcmIo>,
    cap: Mutex<PcmIo>,
    ctrl_scratch: Mutex<ChainScratch>,
    ctrl_resp: Mutex<Vec<u8>>,
    driver_ok: AtomicBool,
    acked_features: AtomicU64,
    irq: OnceLock<IrqFn>,

    play_running: AtomicBool,
    cap_running: AtomicBool,
    play_period_bytes: AtomicU32,
    cap_period_bytes: AtomicU32,

    stop_evt: Arc<Event>,
    wake_play: Arc<Event>,
    wake_cap: Arc<Event>,
    workers: Mutex<Option<(JoinHandle<()>, JoinHandle<()>)>>,

    tx_periods: AtomicU64,
    rx_periods: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    ctrl_cmds: AtomicU64,
}

impl SndDevice {
    pub fn new(mem: Arc<GuestMemory>) -> Arc<Self> {
        Arc::new(SndDevice {
            controlq: Mutex::new(Virtqueue::new(mem.clone(), CTRL_QUEUE_MAX)),
            eventq: Mutex::new(Virtqueue::new(mem.clone(), CTRL_QUEUE_MAX)),
            play: Mutex::new(PcmIo::new(mem.clone())),
            cap: Mutex::new(PcmIo::new(mem)),
            ctrl_scratch: Mutex::new(ChainScratch::default()),
            ctrl_resp: Mutex::new(Vec::new()),
            driver_ok: AtomicBool::new(false),
            acked_features: AtomicU64::new(0),
            irq: OnceLock::new(),
            play_running: AtomicBool::new(false),
            cap_running: AtomicBool::new(false),
            play_period_bytes: AtomicU32::new(0),
            cap_period_bytes: AtomicU32::new(0),
            stop_evt: Arc::new(Event::new(true).expect("create snd stop event")),
            wake_play: Arc::new(Event::new(false).expect("create snd play wake event")),
            wake_cap: Arc::new(Event::new(false).expect("create snd capture wake event")),
            workers: Mutex::new(None),
            tx_periods: AtomicU64::new(0),
            rx_periods: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            ctrl_cmds: AtomicU64::new(0),
        })
    }

    /// Spawn the playback + capture worker threads. Idempotent.
    pub fn start_audio(self: &Arc<Self>) {
        let mut guard = self.workers.lock().unwrap();
        if guard.is_some() {
            return;
        }
        let play = {
            let dev = Arc::downgrade(self);
            let stop = self.stop_evt.clone();
            let wake = self.wake_play.clone();
            std::thread::Builder::new()
                .name("virtio-snd-play".into())
                .spawn(move || play_worker(dev, stop, wake))
                .expect("spawn virtio-snd play worker")
        };
        let cap = {
            let dev = Arc::downgrade(self);
            let stop = self.stop_evt.clone();
            let wake = self.wake_cap.clone();
            std::thread::Builder::new()
                .name("virtio-snd-capture".into())
                .spawn(move || cap_worker(dev, stop, wake))
                .expect("spawn virtio-snd capture worker")
        };
        *guard = Some((play, cap));
    }

    pub fn set_irq_callback(&self, f: IrqFn) {
        let _ = self.irq.set(f);
    }

    pub fn tx_periods(&self) -> u64 {
        self.tx_periods.load(Ordering::Relaxed)
    }
    pub fn rx_periods(&self) -> u64 {
        self.rx_periods.load(Ordering::Relaxed)
    }
    pub fn tx_bytes(&self) -> u64 {
        self.tx_bytes.load(Ordering::Relaxed)
    }
    pub fn rx_bytes(&self) -> u64 {
        self.rx_bytes.load(Ordering::Relaxed)
    }

    fn raise(&self, qidx: u32) {
        if let Some(cb) = self.irq.get() {
            cb(qidx);
        }
    }

    fn play_period_ms(&self) -> u32 {
        period_bytes_to_ms(self.play_period_bytes.load(Ordering::Relaxed))
    }
    fn cap_period_ms(&self) -> u32 {
        period_bytes_to_ms(self.cap_period_bytes.load(Ordering::Relaxed))
    }

    // ---- hot path: playback (txq) ----

    /// Fill `dst` (a WASAPI render buffer, S16 stereo) from queued playback
    /// chains, completing each as its whole period is consumed. Returns the
    /// number of frames actually written (the remainder is zero-filled) and
    /// whether the txq interrupt should be raised. Allocation-free.
    fn fill_playback(&self, dst: &mut [u8]) -> (u32, bool) {
        let frame_bytes = audio::FRAME_BYTES as usize;
        let mut completed = 0u64;
        let mut bytes = 0u64;
        let (written, irq) = {
            let mut g = self.play.lock().unwrap();
            let io = &mut *g;
            if !io.q.ready() {
                for b in dst.iter_mut() {
                    *b = 0;
                }
                return (0, false);
            }
            let mut written = 0usize;
            while written < dst.len() {
                if !io.cur_valid {
                    if !io.q.pop_into(&mut io.cur) {
                        break;
                    }
                    io.cur_off = 0;
                    io.cur_payload = readable_len(&io.cur).saturating_sub(XFER_BYTES);
                }
                let n = copy_from_readable(&io.cur, XFER_BYTES, io.cur_off, &mut dst[written..]);
                io.cur_off += n;
                written += n;
                if io.cur_off >= io.cur_payload {
                    write_status(&mut io.cur, S_OK, 0);
                    let head = io.cur.head_index;
                    io.q.push(head, STATUS_BYTES as u32);
                    io.cur_valid = false;
                    completed += 1;
                    bytes += io.cur_payload as u64;
                } else {
                    break; // dst full, chain partially consumed
                }
            }
            for b in dst[written..].iter_mut() {
                *b = 0;
            }
            let irq = completed > 0 && io.q.should_interrupt_driver();
            (written, irq)
        };
        if completed > 0 {
            self.tx_periods.fetch_add(completed, Ordering::Relaxed);
            self.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
            trace_pcm("SndPlay", completed, bytes);
        }
        ((written / frame_bytes) as u32, irq)
    }

    /// Silent-fallback playback: complete one pending period (audio discarded),
    /// paced by the caller's period timer. Returns whether to raise txq.
    fn drain_playback_discard(&self) -> bool {
        let irq = {
            let mut g = self.play.lock().unwrap();
            let io = &mut *g;
            if !io.q.ready() {
                return false;
            }
            if !io.cur_valid && !io.q.pop_into(&mut io.cur) {
                return false;
            }
            write_status(&mut io.cur, S_OK, 0);
            let head = io.cur.head_index;
            io.q.push(head, STATUS_BYTES as u32);
            io.cur_valid = false;
            io.q.should_interrupt_driver()
        };
        self.tx_periods.fetch_add(1, Ordering::Relaxed);
        irq
    }

    // ---- hot path: capture (rxq) ----

    /// Write a captured packet (`frames` of S16 stereo, or silence when
    /// `silent`) into queued capture chains, completing each as a full period is
    /// produced. Excess data with no buffer available is dropped (overrun).
    /// Returns whether to raise rxq.
    fn push_capture(&self, data: &[u8], frames: u32, silent: bool) -> bool {
        let total = frames as usize * audio::FRAME_BYTES as usize;
        let mut completed = 0u64;
        let mut bytes = 0u64;
        let irq = {
            let mut g = self.cap.lock().unwrap();
            let io = &mut *g;
            if !io.q.ready() {
                return false;
            }
            let mut produced = 0usize;
            while produced < total {
                if !io.cur_valid {
                    if !io.q.pop_into(&mut io.cur) {
                        break; // overrun: no buffer for the rest of this packet
                    }
                    io.cur_off = 0;
                    io.cur_payload = writable_len(&io.cur).saturating_sub(STATUS_BYTES);
                }
                let room = io.cur_payload - io.cur_off;
                if room == 0 {
                    // Degenerate zero-length period: complete and move on.
                    write_status(&mut io.cur, S_OK, 0);
                    let head = io.cur.head_index;
                    let used = writable_len(&io.cur) as u32;
                    io.q.push(head, used);
                    io.cur_valid = false;
                    completed += 1;
                    continue;
                }
                let n = room.min(total - produced);
                if silent {
                    zero_writable(&mut io.cur, io.cur_off, io.cur_off + n);
                } else {
                    copy_to_writable(
                        &mut io.cur,
                        io.cur_payload,
                        io.cur_off,
                        &data[produced..produced + n],
                    );
                }
                io.cur_off += n;
                produced += n;
                bytes += n as u64;
                if io.cur_off >= io.cur_payload {
                    write_status(&mut io.cur, S_OK, 0);
                    let head = io.cur.head_index;
                    let used = writable_len(&io.cur) as u32;
                    io.q.push(head, used);
                    io.cur_valid = false;
                    completed += 1;
                }
            }
            completed > 0 && io.q.should_interrupt_driver()
        };
        if completed > 0 {
            self.rx_periods.fetch_add(completed, Ordering::Relaxed);
            self.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
            trace_pcm("SndCapture", completed, bytes);
        }
        irq
    }

    /// Silent-fallback capture: complete one pending period filled with silence,
    /// paced by the caller's period timer. Returns whether to raise rxq.
    fn fill_capture_silence(&self) -> bool {
        let irq = {
            let mut g = self.cap.lock().unwrap();
            let io = &mut *g;
            if !io.q.ready() {
                return false;
            }
            if !io.cur_valid {
                if !io.q.pop_into(&mut io.cur) {
                    return false;
                }
                io.cur_off = 0;
                io.cur_payload = writable_len(&io.cur).saturating_sub(STATUS_BYTES);
            }
            zero_writable(&mut io.cur, io.cur_off, io.cur_payload);
            write_status(&mut io.cur, S_OK, 0);
            let head = io.cur.head_index;
            let used = writable_len(&io.cur) as u32;
            io.q.push(head, used);
            io.cur_valid = false;
            io.q.should_interrupt_driver()
        };
        self.rx_periods.fetch_add(1, Ordering::Relaxed);
        irq
    }

    /// Complete every pending I/O buffer for a stream (RELEASE handling). The
    /// spec requires the device to return all in-flight messages so the guest's
    /// `sync_stop()` wait can drain. Returns whether to raise the queue.
    fn flush_pcm(&self, playback: bool) -> bool {
        let mux = if playback { &self.play } else { &self.cap };
        let mut completed = 0u64;
        let mut g = mux.lock().unwrap();
        let io = &mut *g;
        if io.cur_valid {
            write_status(&mut io.cur, S_OK, 0);
            let head = io.cur.head_index;
            io.q.push(head, STATUS_BYTES as u32);
            io.cur_valid = false;
            completed += 1;
        }
        while io.q.pop_into(&mut io.cur) {
            write_status(&mut io.cur, S_OK, 0);
            let head = io.cur.head_index;
            io.q.push(head, STATUS_BYTES as u32);
            completed += 1;
        }
        io.cur_valid = false;
        io.cur_off = 0;
        completed > 0 && io.q.should_interrupt_driver()
    }

    // ---- control queue (cold path) ----

    fn drain_control(&self) {
        let mut raise_mask = 0u32;
        let mut cmds = 0u64;
        {
            let mut q = self.controlq.lock().unwrap();
            if !q.ready() {
                return;
            }
            let mut chain = self.ctrl_scratch.lock().unwrap();
            let mut resp = self.ctrl_resp.lock().unwrap();
            while q.pop_into(&mut chain) {
                let (used, bits) = self.process_ctrl(&mut chain, &mut resp);
                let head = chain.head_index;
                q.push(head, used);
                raise_mask |= bits;
                cmds += 1;
            }
            if cmds > 0 && q.should_interrupt_driver() {
                raise_mask |= 1 << SND_CONTROL_QUEUE;
            }
        }
        if cmds > 0 {
            self.ctrl_cmds.fetch_add(cmds, Ordering::Relaxed);
        }
        if raise_mask & (1 << SND_CONTROL_QUEUE) != 0 {
            self.raise(SND_CONTROL_QUEUE);
        }
        if raise_mask & (1 << SND_TX_QUEUE) != 0 {
            self.raise(SND_TX_QUEUE);
        }
        if raise_mask & (1 << SND_RX_QUEUE) != 0 {
            self.raise(SND_RX_QUEUE);
        }
    }

    /// Process one control chain, building the response into `resp`. Returns the
    /// used length and a bitmask of extra queues (tx/rx) to interrupt.
    fn process_ctrl(&self, chain: &mut PoppedChain, resp: &mut Vec<u8>) -> (u32, u32) {
        resp.clear();
        let mut req = [0u8; 32];
        let req_len = copy_from_readable(chain, 0, 0, &mut req);
        if req_len < 4 {
            resp.extend_from_slice(&S_BAD_MSG.to_le_bytes());
            return (scatter(chain, resp), 0);
        }
        let code = rd32(&req, 0);
        let mut raise_bits = 0u32;
        match code {
            R_JACK_INFO => build_jack_info(&req, resp),
            R_PCM_INFO => build_pcm_info(&req, resp),
            R_CHMAP_INFO => build_chmap_info(&req, resp),
            R_PCM_SET_PARAMS => self.do_set_params(&req, resp),
            R_PCM_PREPARE => resp.extend_from_slice(&S_OK.to_le_bytes()),
            R_PCM_START => self.do_start(&req, resp),
            R_PCM_STOP => self.do_stop(&req, resp),
            R_PCM_RELEASE => raise_bits = self.do_release(&req, resp),
            R_JACK_REMAP => resp.extend_from_slice(&S_OK.to_le_bytes()),
            _ => resp.extend_from_slice(&S_NOT_SUPP.to_le_bytes()),
        }
        (scatter(chain, resp), raise_bits)
    }

    fn do_set_params(&self, req: &[u8], resp: &mut Vec<u8>) {
        // virtio_snd_pcm_set_params: code(4) stream_id(4) buffer_bytes(4)
        // period_bytes(4) features(4) channels(1) format(1) rate(1) pad(1)
        let stream = rd32(req, 4);
        let period_bytes = rd32(req, 12);
        let channels = req[20];
        let format = req[21];
        let rate = req[22];
        let supported = (stream == STREAM_OUTPUT || stream == STREAM_INPUT)
            && channels == audio::CHANNELS as u8
            && format == FMT_S16
            && rate == RATE_48000;
        if supported {
            if stream == STREAM_OUTPUT {
                self.play_period_bytes
                    .store(period_bytes, Ordering::Relaxed);
            } else {
                self.cap_period_bytes.store(period_bytes, Ordering::Relaxed);
            }
            etw_ctrl("SndSetParams", stream, period_bytes);
            resp.extend_from_slice(&S_OK.to_le_bytes());
        } else {
            resp.extend_from_slice(&S_NOT_SUPP.to_le_bytes());
        }
    }

    fn do_start(&self, req: &[u8], resp: &mut Vec<u8>) {
        match rd32(req, 4) {
            STREAM_OUTPUT => {
                self.play_running.store(true, Ordering::Release);
                self.wake_play.set();
            }
            STREAM_INPUT => {
                self.cap_running.store(true, Ordering::Release);
                self.wake_cap.set();
            }
            _ => {}
        }
        resp.extend_from_slice(&S_OK.to_le_bytes());
    }

    fn do_stop(&self, req: &[u8], resp: &mut Vec<u8>) {
        match rd32(req, 4) {
            STREAM_OUTPUT => {
                self.play_running.store(false, Ordering::Release);
                self.wake_play.set();
            }
            STREAM_INPUT => {
                self.cap_running.store(false, Ordering::Release);
                self.wake_cap.set();
            }
            _ => {}
        }
        resp.extend_from_slice(&S_OK.to_le_bytes());
    }

    fn do_release(&self, req: &[u8], resp: &mut Vec<u8>) -> u32 {
        let mut bits = 0u32;
        match rd32(req, 4) {
            STREAM_OUTPUT => {
                self.play_running.store(false, Ordering::Release);
                self.wake_play.set();
                if self.flush_pcm(true) {
                    bits |= 1 << SND_TX_QUEUE;
                }
            }
            STREAM_INPUT => {
                self.cap_running.store(false, Ordering::Release);
                self.wake_cap.set();
                if self.flush_pcm(false) {
                    bits |= 1 << SND_RX_QUEUE;
                }
            }
            _ => {}
        }
        resp.extend_from_slice(&S_OK.to_le_bytes());
        bits
    }

    fn program_queue(
        q: &mut Virtqueue,
        desc: u64,
        avail: u64,
        used: u64,
        size: u16,
        event_idx: bool,
    ) {
        q.set_desc_gpa(desc);
        q.set_avail_gpa(avail);
        q.set_used_gpa(used);
        q.set_size(size as u32);
        q.set_event_idx_enabled(event_idx);
        q.set_ready(true);
    }
}

fn period_bytes_to_ms(period_bytes: u32) -> u32 {
    if period_bytes == 0 {
        return 10;
    }
    // ms = period_bytes / (rate * frame_bytes) * 1000 = period_bytes / 192.
    (period_bytes / (audio::SAMPLE_RATE * audio::FRAME_BYTES / 1000)).max(1)
}

// ---------------------------------------------------------------------------
// Descriptor-chain helpers (alloc-free; operate on the reused PoppedChain).
// ---------------------------------------------------------------------------

fn readable_len(chain: &PoppedChain) -> usize {
    chain.bufs.iter().filter(|b| !b.write).map(|b| b.len).sum()
}

fn writable_len(chain: &PoppedChain) -> usize {
    chain.bufs.iter().filter(|b| b.write).map(|b| b.len).sum()
}

fn rd32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Copy from a chain's readable region, skipping `skip` leading header bytes and
/// `off` payload bytes, into `dst`. Returns bytes copied.
fn copy_from_readable(chain: &PoppedChain, skip: usize, off: usize, dst: &mut [u8]) -> usize {
    let mut to_skip = skip + off;
    let mut copied = 0usize;
    for b in &chain.bufs {
        if b.write {
            continue;
        }
        let s = b.as_slice();
        if to_skip >= s.len() {
            to_skip -= s.len();
            continue;
        }
        let src = &s[to_skip..];
        to_skip = 0;
        let n = src.len().min(dst.len() - copied);
        dst[copied..copied + n].copy_from_slice(&src[..n]);
        copied += n;
        if copied == dst.len() {
            break;
        }
    }
    copied
}

/// Copy `src` into a chain's writable region at logical offset `off`, never
/// writing past `data_cap` total writable bytes. Returns bytes copied. Handles a
/// writable region split across multiple descriptors.
fn copy_to_writable(chain: &mut PoppedChain, data_cap: usize, off: usize, src: &[u8]) -> usize {
    let mut region_pos = 0usize;
    let mut copied = 0usize;
    for b in chain.bufs.iter_mut() {
        if !b.write {
            continue;
        }
        if copied >= src.len() {
            break;
        }
        let s = b.as_mut_slice();
        let seg_start = region_pos;
        region_pos += s.len();
        let seg_end = region_pos.min(data_cap);
        if seg_end <= seg_start {
            if region_pos >= data_cap {
                break;
            }
            continue;
        }
        let want_start = off + copied;
        if want_start >= seg_end {
            continue;
        }
        let lo = want_start.max(seg_start);
        let hi = (off + src.len()).min(seg_end);
        if lo >= hi {
            continue;
        }
        let src_lo = lo - off;
        s[(lo - seg_start)..(hi - seg_start)].copy_from_slice(&src[src_lo..(src_lo + (hi - lo))]);
        copied += hi - lo;
    }
    copied
}

/// Zero a chain's writable region over the logical byte range `[lo, hi)`.
fn zero_writable(chain: &mut PoppedChain, lo: usize, hi: usize) {
    let mut region_pos = 0usize;
    for b in chain.bufs.iter_mut() {
        if !b.write {
            continue;
        }
        let s = b.as_mut_slice();
        let seg_start = region_pos;
        region_pos += s.len();
        let a = lo.max(seg_start);
        let e = hi.min(region_pos);
        if a >= e {
            if region_pos >= hi {
                break;
            }
            continue;
        }
        for x in &mut s[(a - seg_start)..(e - seg_start)] {
            *x = 0;
        }
    }
}

/// Write the 8-byte `virtio_snd_pcm_status` into the tail of the writable region.
fn write_status(chain: &mut PoppedChain, status: u32, latency: u32) {
    let total = writable_len(chain);
    if total < STATUS_BYTES {
        return;
    }
    let mut bytes = [0u8; STATUS_BYTES];
    bytes[0..4].copy_from_slice(&status.to_le_bytes());
    bytes[4..8].copy_from_slice(&latency.to_le_bytes());
    copy_to_writable(chain, total, total - STATUS_BYTES, &bytes);
}

/// Scatter a control response across the chain's writable buffers. Returns the
/// used length.
fn scatter(chain: &mut PoppedChain, resp: &[u8]) -> u32 {
    let total = writable_len(chain);
    copy_to_writable(chain, total, 0, resp) as u32
}

// ---------------------------------------------------------------------------
// Static item-information builders.
// ---------------------------------------------------------------------------

/// Append `count` info entries (each padded to `size` bytes) produced by `make`
/// for ids `start..start+count`, prefixed by an `S_OK` status header.
fn build_info<F: Fn(u32, &mut [u8; 64])>(req: &[u8], resp: &mut Vec<u8>, make: F) {
    let start = rd32(req, 4);
    let count = rd32(req, 8);
    let size = rd32(req, 12) as usize;
    resp.extend_from_slice(&S_OK.to_le_bytes());
    for i in 0..count {
        let mut entry = [0u8; 64];
        make(start + i, &mut entry);
        let n = size.min(entry.len());
        resp.extend_from_slice(&entry[..n]);
        for _ in entry.len()..size {
            resp.push(0);
        }
    }
}

fn build_jack_info(req: &[u8], resp: &mut Vec<u8>) {
    build_info(req, resp, |id, e| {
        // virtio_snd_jack_info: hda_fn_nid(4) features(4) defconf(4) caps(4)
        // connected(1) padding[7]
        let defconf = if id == STREAM_INPUT {
            DEFCONF_MIC
        } else {
            DEFCONF_SPEAKER
        };
        e[8..12].copy_from_slice(&defconf.to_le_bytes());
        e[16] = 1; // connected
    });
}

fn build_pcm_info(req: &[u8], resp: &mut Vec<u8>) {
    build_info(req, resp, |id, e| {
        // virtio_snd_pcm_info: hda_fn_nid(4) features(4) formats(8) rates(8)
        // direction(1) channels_min(1) channels_max(1) padding[5]
        let formats: u64 = 1u64 << FMT_S16;
        let rates: u64 = 1u64 << RATE_48000;
        e[8..16].copy_from_slice(&formats.to_le_bytes());
        e[16..24].copy_from_slice(&rates.to_le_bytes());
        e[24] = if id == STREAM_INPUT {
            D_INPUT
        } else {
            D_OUTPUT
        };
        e[25] = audio::CHANNELS as u8;
        e[26] = audio::CHANNELS as u8;
    });
}

fn build_chmap_info(req: &[u8], resp: &mut Vec<u8>) {
    build_info(req, resp, |id, e| {
        // virtio_snd_chmap_info: hda_fn_nid(4) direction(1) channels(1)
        // positions[18]
        e[4] = if id == STREAM_INPUT {
            D_INPUT
        } else {
            D_OUTPUT
        };
        e[5] = audio::CHANNELS as u8;
        e[6] = CHMAP_FL;
        e[7] = CHMAP_FR;
    });
}

// ---------------------------------------------------------------------------
// Diagnostics.
// ---------------------------------------------------------------------------

fn trace_pcm(name: &str, periods: u64, bytes: u64) {
    if etw::enabled(etw::VERBOSE, etw::kw::VIRTIO) {
        etw::Event::new(name, etw::VERBOSE, etw::kw::VIRTIO)
            .u64("periods", periods)
            .u64("bytes", bytes)
            .write();
    }
}

fn etw_ctrl(name: &str, stream: u32, period_bytes: u32) {
    if etw::enabled(etw::INFO, etw::kw::VIRTIO) {
        etw::Event::new(name, etw::INFO, etw::kw::VIRTIO)
            .u32("stream", stream)
            .u32("period_bytes", period_bytes)
            .write();
    }
}

// ---------------------------------------------------------------------------
// Worker threads.
// ---------------------------------------------------------------------------

fn play_worker(dev: Weak<SndDevice>, stop: Arc<Event>, wake: Arc<Event>) {
    let _com = ComInit::mta();
    let mut client: Option<RenderClient> = None;
    let mut wasapi_evt: Option<Arc<Event>> = None;
    let mut prev_running = false;
    let mut open_failed = false;

    loop {
        let Some(d) = dev.upgrade() else { break };
        let running = d.play_running.load(Ordering::Acquire);
        if running && !prev_running {
            open_failed = false;
        }
        if !running && prev_running {
            if let Some(c) = client.take() {
                c.stop();
            }
            wasapi_evt = None;
        }
        prev_running = running;

        if !running {
            drop(d);
            match wait_any(&[&*stop, &*wake], INFINITE) {
                WaitOutcome::Signaled(0) => break,
                _ => continue,
            }
        }

        if client.is_none() && !open_failed {
            if let Some(ev) = Event::new(false) {
                let ev = Arc::new(ev);
                if let Some(mut c) = RenderClient::open(&ev) {
                    // Pre-roll the endpoint buffer before starting the clock.
                    let bf = c.buffer_frames();
                    if let Some(dst) = c.begin(bf) {
                        let (filled, _irq) = d.fill_playback(dst);
                        c.commit(bf, filled == 0);
                    }
                    c.start();
                    client = Some(c);
                    wasapi_evt = Some(ev);
                } else {
                    open_failed = true;
                }
            } else {
                open_failed = true;
            }
        }

        let period_ms = d.play_period_ms();
        let evt = wasapi_evt.clone();
        drop(d);

        let mut invalidate = false;
        if let (Some(c), Some(ev)) = (client.as_mut(), evt) {
            if let WaitOutcome::Signaled(0) = wait_any(&[&*stop, &*wake, &*ev], INFINITE) {
                break;
            }
            let Some(d) = dev.upgrade() else { break };
            if d.play_running.load(Ordering::Acquire) {
                match c.available_frames() {
                    Some(avail) if avail > 0 => {
                        if let Some(dst) = c.begin(avail) {
                            let (filled, irq) = d.fill_playback(dst);
                            c.commit(avail, filled == 0);
                            if irq {
                                d.raise(SND_TX_QUEUE);
                            }
                        }
                    }
                    Some(_) => {}
                    None => invalidate = true,
                }
            }
        } else {
            // No endpoint: pace buffer completion on a period timer.
            if let WaitOutcome::Signaled(0) = wait_any(&[&*stop, &*wake], period_ms) {
                break;
            }
            let Some(d) = dev.upgrade() else { break };
            if d.play_running.load(Ordering::Acquire) && d.drain_playback_discard() {
                d.raise(SND_TX_QUEUE);
            }
        }
        if invalidate {
            if let Some(c) = client.take() {
                c.stop();
            }
            wasapi_evt = None;
            open_failed = true;
        }
    }
    if let Some(c) = client.take() {
        c.stop();
    }
}

fn cap_worker(dev: Weak<SndDevice>, stop: Arc<Event>, wake: Arc<Event>) {
    let _com = ComInit::mta();
    let mut client: Option<CaptureClient> = None;
    let mut wasapi_evt: Option<Arc<Event>> = None;
    let mut prev_running = false;
    let mut open_failed = false;

    loop {
        let Some(d) = dev.upgrade() else { break };
        let running = d.cap_running.load(Ordering::Acquire);
        if running && !prev_running {
            open_failed = false;
        }
        if !running && prev_running {
            if let Some(c) = client.take() {
                c.stop();
            }
            wasapi_evt = None;
        }
        prev_running = running;

        if !running {
            drop(d);
            match wait_any(&[&*stop, &*wake], INFINITE) {
                WaitOutcome::Signaled(0) => break,
                _ => continue,
            }
        }

        if client.is_none() && !open_failed {
            if let Some(ev) = Event::new(false) {
                let ev = Arc::new(ev);
                if let Some(c) = CaptureClient::open(&ev) {
                    c.start();
                    client = Some(c);
                    wasapi_evt = Some(ev);
                } else {
                    open_failed = true;
                }
            } else {
                open_failed = true;
            }
        }

        let period_ms = d.cap_period_ms();
        let evt = wasapi_evt.clone();
        drop(d);

        if let (Some(c), Some(ev)) = (client.as_mut(), evt) {
            if let WaitOutcome::Signaled(0) = wait_any(&[&*stop, &*wake, &*ev], INFINITE) {
                break;
            }
            let Some(d) = dev.upgrade() else { break };
            if d.cap_running.load(Ordering::Acquire) {
                let mut irq = false;
                while let Some((data, frames, silent)) = c.next_packet() {
                    irq |= d.push_capture(data, frames, silent);
                    c.release_packet();
                }
                if irq {
                    d.raise(SND_RX_QUEUE);
                }
            }
        } else {
            if let WaitOutcome::Signaled(0) = wait_any(&[&*stop, &*wake], period_ms) {
                break;
            }
            let Some(d) = dev.upgrade() else { break };
            if d.cap_running.load(Ordering::Acquire) && d.fill_capture_silence() {
                d.raise(SND_RX_QUEUE);
            }
        }
    }
    if let Some(c) = client.take() {
        c.stop();
    }
}

impl Drop for SndDevice {
    fn drop(&mut self) {
        self.stop_evt.set();
        self.wake_play.set();
        self.wake_cap.set();
        if let Some((p, c)) = self.workers.lock().unwrap().take() {
            let _ = p.join();
            let _ = c.join();
        }
    }
}

impl VirtioDevice for SndDevice {
    fn device_id(&self) -> u32 {
        DEVICE_ID_SOUND
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
        SND_QUEUE_COUNT
    }

    fn queue_max(&self, idx: u32) -> u32 {
        match idx {
            SND_CONTROL_QUEUE | SND_EVENT_QUEUE => CTRL_QUEUE_MAX,
            SND_TX_QUEUE | SND_RX_QUEUE => PCM_QUEUE_MAX,
            _ => 0,
        }
    }

    fn enable_queue(&self, idx: u32, desc: u64, avail: u64, used: u64, size: u16, event_idx: bool) {
        match idx {
            SND_CONTROL_QUEUE => Self::program_queue(
                &mut self.controlq.lock().unwrap(),
                desc,
                avail,
                used,
                size,
                event_idx,
            ),
            SND_EVENT_QUEUE => Self::program_queue(
                &mut self.eventq.lock().unwrap(),
                desc,
                avail,
                used,
                size,
                event_idx,
            ),
            SND_TX_QUEUE => Self::program_queue(
                &mut self.play.lock().unwrap().q,
                desc,
                avail,
                used,
                size,
                event_idx,
            ),
            SND_RX_QUEUE => Self::program_queue(
                &mut self.cap.lock().unwrap().q,
                desc,
                avail,
                used,
                size,
                event_idx,
            ),
            _ => {}
        }
    }

    fn disable_queue(&self, idx: u32) {
        match idx {
            SND_CONTROL_QUEUE => self.controlq.lock().unwrap().set_ready(false),
            SND_EVENT_QUEUE => self.eventq.lock().unwrap().set_ready(false),
            SND_TX_QUEUE => self.play.lock().unwrap().q.set_ready(false),
            SND_RX_QUEUE => self.cap.lock().unwrap().q.set_ready(false),
            _ => {}
        }
    }

    fn notify_queue(&self, idx: u32) {
        match idx {
            SND_CONTROL_QUEUE => self.drain_control(),
            SND_EVENT_QUEUE => {} // device never posts events
            SND_TX_QUEUE => self.wake_play.set(),
            SND_RX_QUEUE => self.wake_cap.set(),
            _ => {}
        }
    }

    fn driver_ok(&self) {
        self.driver_ok.store(true, Ordering::Relaxed);
    }

    fn reset(&self) {
        self.driver_ok.store(false, Ordering::Relaxed);
        self.acked_features.store(0, Ordering::Relaxed);
        self.play_running.store(false, Ordering::Release);
        self.cap_running.store(false, Ordering::Release);
        self.wake_play.set();
        self.wake_cap.set();
        self.controlq.lock().unwrap().reset();
        self.eventq.lock().unwrap().reset();
        {
            let mut g = self.play.lock().unwrap();
            g.q.reset();
            g.cur_valid = false;
            g.cur_off = 0;
        }
        {
            let mut g = self.cap.lock().unwrap();
            g.q.reset();
            g.cur_valid = false;
            g.cur_off = 0;
        }
    }

    fn read_config(&self, offset: u32, size: u32) -> u32 {
        // virtio_snd_config { jacks, streams, chmaps, controls } — all le32.
        let mut img = [0u8; 16];
        img[0..4].copy_from_slice(&NUM_JACKS.to_le_bytes());
        img[4..8].copy_from_slice(&NUM_STREAMS.to_le_bytes());
        img[8..12].copy_from_slice(&NUM_CHMAPS.to_le_bytes());
        // controls = 0 (VIRTIO_SND_F_CTLS not offered)
        let mut v = [0u8; 4];
        let n = size.min(4) as usize;
        for (i, slot) in v.iter_mut().enumerate().take(n) {
            *slot = img.get(offset as usize + i).copied().unwrap_or(0);
        }
        u32::from_le_bytes(v)
    }

    fn capture_queue(&self, idx: u32) -> Option<QueueState> {
        match idx {
            SND_CONTROL_QUEUE => Some(self.controlq.lock().unwrap().capture()),
            SND_EVENT_QUEUE => Some(self.eventq.lock().unwrap().capture()),
            SND_TX_QUEUE => Some(self.play.lock().unwrap().q.capture()),
            SND_RX_QUEUE => Some(self.cap.lock().unwrap().q.capture()),
            _ => None,
        }
    }

    fn apply_queue(&self, idx: u32, st: &QueueState) {
        match idx {
            SND_CONTROL_QUEUE => self.controlq.lock().unwrap().apply(st),
            SND_EVENT_QUEUE => self.eventq.lock().unwrap().apply(st),
            SND_TX_QUEUE => self.play.lock().unwrap().q.apply(st),
            SND_RX_QUEUE => self.cap.lock().unwrap().q.apply(st),
            _ => {}
        }
    }

    fn capture_device_state(&self) -> Vec<u8> {
        let mut b = vec![0u8; 16];
        b[0] = self.driver_ok.load(Ordering::Relaxed) as u8;
        b[8..16].copy_from_slice(&self.acked_features.load(Ordering::Relaxed).to_le_bytes());
        b
    }

    fn apply_device_state(&self, bytes: &[u8]) {
        if bytes.len() >= 16 {
            self.driver_ok.store(bytes[0] != 0, Ordering::Relaxed);
            self.acked_features.store(
                u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
                Ordering::Relaxed,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::queue::ChainBuf;

    fn cb(write: bool, data: &mut [u8]) -> ChainBuf {
        ChainBuf {
            ptr: data.as_mut_ptr(),
            len: data.len(),
            write,
        }
    }

    /// A TX (playback) chain — [readable xfer(4)][readable data][writable
    /// status(8)] — must surface the right payload length, copy the PCM data
    /// past the 4-byte header, and write the status into the writable tail.
    #[test]
    fn tx_chain_payload_and_status() {
        let mut xfer = 0u32.to_le_bytes();
        let mut data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut status = [0xAAu8; 8];
        let mut chain = PoppedChain::default();
        chain.head_index = 9;
        chain.bufs.push(cb(false, &mut xfer));
        chain.bufs.push(cb(false, &mut data));
        chain.bufs.push(cb(true, &mut status));

        assert_eq!(readable_len(&chain), 12);
        assert_eq!(writable_len(&chain), 8);
        let payload = readable_len(&chain) - XFER_BYTES;
        assert_eq!(payload, 8);

        let mut dst = [0u8; 8];
        let n = copy_from_readable(&chain, XFER_BYTES, 0, &mut dst);
        assert_eq!(n, 8);
        assert_eq!(dst, [1, 2, 3, 4, 5, 6, 7, 8]);

        // Partial copy honouring the running payload offset.
        let mut half = [0u8; 4];
        let n = copy_from_readable(&chain, XFER_BYTES, 4, &mut half);
        assert_eq!(n, 4);
        assert_eq!(half, [5, 6, 7, 8]);

        write_status(&mut chain, S_OK, 0x1234);
        assert_eq!(u32::from_le_bytes(status[0..4].try_into().unwrap()), S_OK);
        assert_eq!(u32::from_le_bytes(status[4..8].try_into().unwrap()), 0x1234);
    }

    /// An RX (capture) chain — [readable xfer(4)][writable data...][writable
    /// status(8)] — with a data region split across two descriptors. The capture
    /// copy must fill the data region (respecting the status tail) and the status
    /// must land in the last 8 bytes.
    #[test]
    fn rx_chain_split_data_region() {
        let mut xfer = 1u32.to_le_bytes();
        let mut d0 = [0u8; 6];
        let mut d1 = [0u8; 6];
        let mut status = [0u8; 8];
        let mut chain = PoppedChain::default();
        chain.bufs.push(cb(false, &mut xfer));
        chain.bufs.push(cb(true, &mut d0));
        chain.bufs.push(cb(true, &mut d1));
        chain.bufs.push(cb(true, &mut status));

        let total = writable_len(&chain);
        assert_eq!(total, 20);
        let data_cap = total - STATUS_BYTES;
        assert_eq!(data_cap, 12);

        let src: [u8; 12] = [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21];
        let copied = copy_to_writable(&mut chain, data_cap, 0, &src);
        assert_eq!(copied, 12);
        assert_eq!(d0, [10, 11, 12, 13, 14, 15]);
        assert_eq!(d1, [16, 17, 18, 19, 20, 21]);
        // Status tail untouched by the data copy.
        assert_eq!(status, [0u8; 8]);

        write_status(&mut chain, S_OK, 12);
        assert_eq!(u32::from_le_bytes(status[0..4].try_into().unwrap()), S_OK);
        assert_eq!(u32::from_le_bytes(status[4..8].try_into().unwrap()), 12);
    }

    /// `copy_to_writable` must never write past `data_cap`, even mid-descriptor.
    #[test]
    fn copy_to_writable_respects_cap() {
        let mut d0 = [0xFFu8; 8];
        let mut chain = PoppedChain::default();
        chain.bufs.push(cb(true, &mut d0));
        let src = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let copied = copy_to_writable(&mut chain, 4, 0, &src);
        assert_eq!(copied, 4);
        assert_eq!(d0, [1, 2, 3, 4, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    /// Writing silence into a sub-range of the data region leaves the rest alone.
    #[test]
    fn zero_writable_partial_range() {
        let mut d0 = [9u8; 10];
        let mut chain = PoppedChain::default();
        chain.bufs.push(cb(true, &mut d0));
        zero_writable(&mut chain, 2, 6);
        assert_eq!(d0, [9, 9, 0, 0, 0, 0, 9, 9, 9, 9]);
    }

    /// A query-info control response (status header + info array) scatters across
    /// the writable buffers and reports the used length.
    #[test]
    fn scatter_control_response() {
        let mut hdr = [0u8; 4];
        let mut body = [0u8; 32];
        let mut chain = PoppedChain::default();
        chain.bufs.push(cb(true, &mut hdr));
        chain.bufs.push(cb(true, &mut body));

        let mut resp = Vec::new();
        build_pcm_info(
            // start_id=0, count=1, size=32
            &{
                let mut r = [0u8; 32];
                r[0..4].copy_from_slice(&R_PCM_INFO.to_le_bytes());
                r[4..8].copy_from_slice(&0u32.to_le_bytes());
                r[8..12].copy_from_slice(&1u32.to_le_bytes());
                r[12..16].copy_from_slice(&32u32.to_le_bytes());
                r
            },
            &mut resp,
        );
        // status(4) + one pcm_info(32)
        assert_eq!(resp.len(), 4 + 32);
        let used = scatter(&mut chain, &resp);
        assert_eq!(used as usize, resp.len());
        assert_eq!(u32::from_le_bytes(hdr.try_into().unwrap()), S_OK);
        // The 4-byte status header fills the first writable buffer, so the info
        // entry starts at body[0]. direction byte is at info offset 24.
        assert_eq!(body[24], D_OUTPUT);
        // formats bitmap low byte (info offset 8) has the S16 bit set.
        assert_eq!(body[8], 1u8 << FMT_S16);
    }

    /// `period_bytes_to_ms` maps the negotiated period to a sane pacing interval.
    #[test]
    fn period_pacing() {
        assert_eq!(period_bytes_to_ms(0), 10); // default when unset
        // 48 kHz stereo S16: 192 bytes/ms. 4096 bytes ~= 21 ms.
        assert_eq!(period_bytes_to_ms(4096), 4096 / 192);
        assert!(period_bytes_to_ms(64) >= 1); // never zero
    }
}
