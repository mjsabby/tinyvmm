//! Guest A/V recorder (`--record`): tees the virtio-gpu scanout and the
//! virtio-snd playback stream into an MP4 (H.264 + AAC), encoded in real time on
//! a dedicated thread through Media Foundation ([`crate::host::media`]).
//!
//! Everything lands on one timeline that starts when the recorder starts (`t0`,
//! QPC via [`Instant`]):
//!   * Video is constant frame rate. At tick `k` (time `k / fps`) the encoder
//!     takes the most recently presented frame, repeating the previous one when
//!     the guest hasn't flushed since (a static desktop), and encodes it with
//!     that timestamp. A present only copies into a single latest-frame slot, so
//!     the vCPU never waits on the encoder; frames presented between two ticks
//!     are dropped. A frame whose size differs from the recording's (a guest
//!     mode change) is scaled to fit and letterboxed. If the encoder falls
//!     behind, the ticks it missed are folded into one longer frame.
//!   * Audio: while tapped, virtio-snd playback is clock-paced, so every PCM
//!     chunk carries its exact position on a 48 kHz clock. The recorder places
//!     it on the track at `(epoch - t0) * 48 kHz + offset` and fills gaps (the
//!     guest not playing, a skipped host stall) with silence. Silence is also
//!     written up to `now - AUDIO_LAG` so the streams stay interleaved: the
//!     sink writer stalls a stream that runs far ahead of the other.
//!
//! The output is a fragmented MP4, playable while it grows and still playable
//! (up to the last fragment) if tinyvmm dies before finalizing it.

use crate::error::{Error, Result};
use crate::host::audio::{Event, INFINITE, SAMPLE_RATE, WaitOutcome, wait_any};
use crate::host::media::{Mp4Options, Mp4Writer, VideoFormat};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const DEFAULT_FPS: u32 = 30;
const MAX_FPS: u32 = 60;
/// Bytes per PCM frame (S16LE stereo), the virtio-snd contract.
const PCM_FRAME: usize = 4;
/// How far behind real time the audio track is padded with silence while the
/// guest isn't playing. PCM arriving later than this is dropped (counted).
const AUDIO_LAG_FRAMES: i64 = SAMPLE_RATE as i64 / 5;
/// Cap on PCM queued for the encoder (2 s); beyond it new PCM is dropped.
const AUDIO_QUEUE_MAX_BYTES: usize = 2 * SAMPLE_RATE as usize * PCM_FRAME;
/// Ticks the encoder may run behind before the missed ones are folded into a
/// single longer frame.
const MAX_LATE_TICKS: u64 = 2;
/// 100-ns units per second (Media Foundation timestamps).
const HNS_PER_SEC: u128 = 10_000_000;

/// `--record <path>[,fps=N][,kbps=N]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordSpec {
    pub path: PathBuf,
    pub fps: u32,
    /// Mean H.264 bitrate; `None` picks one from the frame size and rate.
    pub kbps: Option<u32>,
}

impl RecordSpec {
    pub fn parse(spec: &str) -> Result<RecordSpec> {
        const WANT: &str = "<path.mp4>[,fps=N][,kbps=N]";
        let mut parts = spec.split(',');
        let path = parts.next().unwrap_or("");
        if path.is_empty() {
            return Err(Error::msg(format!("--record: empty path (want {WANT})")));
        }
        let mut out = RecordSpec {
            path: PathBuf::from(path),
            fps: DEFAULT_FPS,
            kbps: None,
        };
        for kv in parts {
            let num = |v: &str, lo: u32, hi: u32| {
                v.parse::<u32>()
                    .ok()
                    .filter(|n| (lo..=hi).contains(n))
                    .ok_or_else(|| {
                        Error::msg(format!("--record: '{kv}' wants an integer in {lo}..={hi}"))
                    })
            };
            if let Some(v) = kv.strip_prefix("fps=") {
                out.fps = num(v, 1, MAX_FPS)?;
            } else if let Some(v) = kv.strip_prefix("kbps=") {
                out.kbps = Some(num(v, 100, 100_000)?);
            } else {
                return Err(Error::msg(format!(
                    "--record: unknown option '{kv}' (want {WANT})"
                )));
            }
        }
        Ok(out)
    }
}

/// A BGRA frame (top-down, `stride == width * 4`) and its present sequence.
#[derive(Default)]
struct Frame {
    buf: Vec<u8>,
    width: u32,
    height: u32,
    seq: u64,
}

/// PCM handed over by the playback tap: bytes plus `(track position, bytes)`
/// for each chunk.
#[derive(Default)]
struct AudioQueue {
    data: Vec<u8>,
    chunks: Vec<(i64, usize)>,
}

struct Shared {
    t0: Instant,
    video: Mutex<Frame>,
    audio: Mutex<AudioQueue>,
    stopping: AtomicBool,
    wake: Event,
    presents: AtomicU64,
    audio_overflow_frames: AtomicU64,
}

impl Shared {
    /// The producer/encoder rendezvous; the timeline starts now.
    fn new() -> Option<Arc<Shared>> {
        Some(Arc::new(Shared {
            t0: Instant::now(),
            video: Mutex::new(Frame::default()),
            audio: Mutex::new(AudioQueue {
                data: Vec::with_capacity(AUDIO_QUEUE_MAX_BYTES / 4),
                chunks: Vec::with_capacity(256),
            }),
            stopping: AtomicBool::new(false),
            wake: Event::new(false)?,
            presents: AtomicU64::new(0),
            audio_overflow_frames: AtomicU64::new(0),
        }))
    }
}

/// What the encoder thread did, for the shutdown report.
#[derive(Default)]
pub struct Summary {
    path: PathBuf,
    fps: u32,
    /// Video ticks covered (frame count at the nominal rate).
    ticks: u64,
    /// Ticks that showed a newly presented frame (vs a repeat).
    new_frames: u64,
    /// Ticks folded into a longer frame because the encoder fell behind.
    late_ticks: u64,
    presents: u64,
    audio: bool,
    audio_frames: u64,
    late_audio_frames: u64,
    overflow_audio_frames: u64,
    error: Option<String>,
}

impl std::fmt::Display for Summary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let secs = self.ticks as f64 / self.fps.max(1) as f64;
        write!(
            f,
            "{}: {:.1} s, {} frames @ {} fps ({} new of {} guest presents, {} late)",
            self.path.display(),
            secs,
            self.ticks,
            self.fps,
            self.new_frames,
            self.presents,
            self.late_ticks
        )?;
        if self.audio {
            write!(
                f,
                ", audio {:.1} s",
                self.audio_frames as f64 / SAMPLE_RATE as f64
            )?;
            let dropped = self.late_audio_frames + self.overflow_audio_frames;
            if dropped > 0 {
                write!(f, " ({dropped} frames dropped)")?;
            }
        }
        if let Some(e) = &self.error {
            write!(f, "; ERROR: {e}")?;
        }
        Ok(())
    }
}

/// A running recording. Feed it with [`Self::video_frame`] (the GPU present
/// hook) and [`Self::audio_pcm`] (the virtio-snd playback tap); [`Self::finish`]
/// (or drop) finalizes the file.
pub struct Recorder {
    shared: Arc<Shared>,
    worker: Mutex<Option<JoinHandle<Summary>>>,
    /// One-line description of the stream setup, for the startup log.
    pub description: String,
}

impl Recorder {
    /// Create the output file and start the encoder thread. `width`x`height` is
    /// the GPU's display size (rounded up to even for H.264); `audio` adds an
    /// AAC track for the guest's playback stream.
    pub fn start(spec: &RecordSpec, width: u32, height: u32, audio: bool) -> Result<Arc<Self>> {
        let width = (width + 1) & !1;
        let height = (height + 1) & !1;
        let bitrate = match spec.kbps {
            Some(k) => k * 1000,
            None => default_bitrate(width, height, spec.fps),
        };
        let fmt = VideoFormat {
            width,
            height,
            fps: spec.fps,
            bitrate,
        };
        // The encoder thread owns the Media Foundation writer (COM objects stay
        // on their thread). It starts the timeline only once the writer exists,
        // so encoder start-up time isn't recorded.
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(String, Arc<Shared>)>>();
        let worker = {
            let path = spec.path.clone();
            std::thread::Builder::new()
                .name("recorder".into())
                .spawn(move || {
                    let opts = Mp4Options {
                        audio,
                        fragmented: true,
                        hardware: true,
                    };
                    let writer = match Mp4Writer::create(&path, &fmt, opts) {
                        Ok(w) => w,
                        Err(e) => {
                            let _ = ready_tx.send(Err(e));
                            return Summary::default();
                        }
                    };
                    let Some(shared) = Shared::new() else {
                        let _ = ready_tx.send(Err(Error::msg("create recorder event")));
                        return Summary::default();
                    };
                    let encoder = writer
                        .encoder()
                        .map_or_else(|| "H.264 encoder".to_string(), |e| e.to_string());
                    let _ = ready_tx.send(Ok((encoder, shared.clone())));
                    encode(&shared, writer, &fmt, path)
                })
                .map_err(|e| Error::msg(format!("--record: spawn encoder thread: {e}")))?
        };
        let (encoder, shared) = match ready_rx.recv() {
            Ok(Ok(ready)) => ready,
            Ok(Err(e)) => {
                let _ = worker.join();
                return Err(Error::msg(format!(
                    "--record: cannot record to '{}': {e}",
                    spec.path.display()
                )));
            }
            Err(_) => {
                let _ = worker.join();
                return Err(Error::msg("--record: encoder thread exited"));
            }
        };
        let description = format!(
            "{}x{} @ {} fps, {} kbps H.264 ({encoder}){} -> {} (fragmented MP4)",
            width,
            height,
            spec.fps,
            bitrate / 1000,
            if audio { " + AAC 192 kbps" } else { "" },
            spec.path.display()
        );
        Ok(Arc::new(Recorder {
            shared,
            worker: Mutex::new(Some(worker)),
            description,
        }))
    }

    /// GPU present hook: copy the frame into the latest-frame slot. Runs on the
    /// vCPU thread under the GPU lock, so it only copies (allocating only when
    /// the frame grows).
    pub fn video_frame(&self, bgra: &[u8], width: u32, height: u32) {
        let mut slot = self.shared.video.lock().unwrap();
        slot.buf.clear();
        slot.buf.extend_from_slice(bgra);
        slot.width = width;
        slot.height = height;
        slot.seq += 1;
        self.shared.presents.fetch_add(1, Ordering::Relaxed);
    }

    /// virtio-snd playback tap: queue `pcm`, which sits `offset` frames into
    /// the playback run whose 48 kHz clock started at `epoch`.
    pub fn audio_pcm(&self, epoch: Instant, offset: u64, pcm: &[u8]) {
        let pos = frames_since(self.shared.t0, epoch) + offset as i64;
        let mut q = self.shared.audio.lock().unwrap();
        if q.data.len() + pcm.len() > AUDIO_QUEUE_MAX_BYTES {
            self.shared
                .audio_overflow_frames
                .fetch_add((pcm.len() / PCM_FRAME) as u64, Ordering::Relaxed);
            return;
        }
        q.data.extend_from_slice(pcm);
        q.chunks.push((pos, pcm.len()));
    }

    /// Stop recording, finalize the file and report. Later calls return `None`.
    pub fn finish(&self) -> Option<Summary> {
        let worker = self.worker.lock().unwrap().take()?;
        self.shared.stopping.store(true, Ordering::Release);
        self.shared.wake.set();
        worker.join().ok()
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

/// Default mean bitrate: 0.15 bit per pixel per frame (~4.6 Mbps for
/// 1280x800 @ 30), within 0.5..=50 Mbps.
fn default_bitrate(width: u32, height: u32, fps: u32) -> u32 {
    let bps = width as u64 * height as u64 * fps as u64 * 3 / 20;
    bps.clamp(500_000, 50_000_000) as u32
}

/// Signed 48 kHz frame count from `t0` to `t`.
fn frames_since(t0: Instant, t: Instant) -> i64 {
    let frames = |d: Duration| (d.as_nanos() * SAMPLE_RATE as u128 / 1_000_000_000) as i64;
    match t.checked_duration_since(t0) {
        Some(d) => frames(d),
        None => -frames(t0 - t),
    }
}

/// Video tick `k`'s timestamp in 100-ns units.
fn tick_hns(k: u64, fps: u32) -> i64 {
    (k as u128 * HNS_PER_SEC / fps as u128) as i64
}

/// Audio frame `n`'s timestamp in 100-ns units.
fn audio_hns(n: u64) -> i64 {
    (n as u128 * HNS_PER_SEC / SAMPLE_RATE as u128) as i64
}

/// The encoder thread: one video frame per tick, audio up to the tick's
/// horizon, until [`Recorder::finish`].
fn encode(shared: &Shared, mut writer: Mp4Writer, fmt: &VideoFormat, path: PathBuf) -> Summary {
    let fps = fmt.fps;
    let tick_ns = |k: u64| Duration::from_nanos((k as u128 * 1_000_000_000 / fps as u128) as u64);
    let ticks_at = |t: Instant| {
        (t.saturating_duration_since(shared.t0).as_nanos() * fps as u128 / 1_000_000_000) as u64
    };
    let timer = Event::timer();
    let mut nv12 = vec![0u8; fmt.nv12_len()];
    let luma = fmt.width as usize * fmt.height as usize;
    nv12[..luma].fill(16); // black until the guest presents
    nv12[luma..].fill(128);
    let mut frame = Frame::default();
    let mut fit = Fit::default();
    let mut track = AudioTrack::default();
    let mut s = Summary {
        path,
        fps,
        audio: writer.has_audio(),
        ..Summary::default()
    };
    let mut k = 0u64;
    while !shared.stopping.load(Ordering::Acquire) {
        let due = shared.t0 + tick_ns(k);
        let now = Instant::now();
        if now < due {
            let wait = due - now;
            let stop = match &timer {
                Some(t) if t.arm_timer((wait.as_nanos() / 100) as i64, 0) => {
                    wait_any(&[&shared.wake, t], INFINITE)
                }
                _ => wait_any(&[&shared.wake], (wait.as_millis() as u32).max(1)),
            };
            if let WaitOutcome::Failed = stop {
                s.error = Some("recorder wait failed".into());
                break;
            }
            continue;
        }
        // This sample covers ticks k..=last; a stall folds the missed ticks in.
        let current = ticks_at(now);
        let last = if current > k + MAX_LATE_TICKS {
            current
        } else {
            k
        };
        if take_frame(shared, &mut frame) && convert(&frame, fmt, &mut fit, &mut nv12) {
            s.new_frames += 1;
        }
        let (t, end) = (tick_hns(k, fps), tick_hns(last + 1, fps));
        if let Err(e) = writer.write_video(&nv12, t, end - t) {
            s.error = Some(e.to_string());
            break;
        }
        s.late_ticks += last - k;
        k = last + 1;
        if writer.has_audio() {
            track.take(shared);
            track.pad_to(frames_since(shared.t0, now) - AUDIO_LAG_FRAMES);
            if let Err(e) = track.flush(|pcm, t, d| writer.write_audio(pcm, t, d)) {
                s.error = Some(e.to_string());
                break;
            }
        }
    }
    s.ticks = k;
    if writer.has_audio() && s.error.is_none() {
        // End the audio with the video.
        track.take(shared);
        track.pad_to((k as u128 * SAMPLE_RATE as u128 / fps as u128) as i64);
        if let Err(e) = track.flush(|pcm, t, d| writer.write_audio(pcm, t, d)) {
            s.error = Some(e.to_string());
        }
    }
    s.audio_frames = track.written;
    s.late_audio_frames = track.late;
    s.overflow_audio_frames = shared.audio_overflow_frames.load(Ordering::Relaxed);
    s.presents = shared.presents.load(Ordering::Relaxed);
    if let Err(e) = writer.finalize() {
        s.error.get_or_insert(e.to_string());
    }
    s
}

/// Swap the latest presented frame into `local` if one arrived since it was
/// last taken (O(1) under the lock; the slot keeps `local`'s old buffer, which
/// the next present overwrites).
fn take_frame(shared: &Shared, local: &mut Frame) -> bool {
    let mut slot = shared.video.lock().unwrap();
    if slot.seq == local.seq {
        return false;
    }
    std::mem::swap(&mut slot.buf, &mut local.buf);
    local.width = slot.width;
    local.height = slot.height;
    local.seq = slot.seq;
    true
}

/// Convert `frame` into the recording's NV12 buffer, scaling it to fit when
/// its size differs. False (buffer untouched) for a malformed frame.
fn convert(frame: &Frame, fmt: &VideoFormat, fit: &mut Fit, nv12: &mut [u8]) -> bool {
    let (w, h) = (frame.width as usize, frame.height as usize);
    if w == 0 || h == 0 || frame.buf.len() != w * h * 4 {
        return false;
    }
    let (ow, oh) = (fmt.width as usize, fmt.height as usize);
    if (w, h) == (ow, oh) {
        bgra_to_nv12(&frame.buf, ow, oh, nv12);
    } else {
        fit.scale(&frame.buf, w, h, ow, oh);
        bgra_to_nv12(&fit.canvas, ow, oh, nv12);
    }
    true
}

/// Convert a top-down BGRA frame to NV12, BT.709 limited range (what the
/// encoder's VUI declares). `w` and `h` must be even. Chroma is the average of
/// each 2x2 block.
fn bgra_to_nv12(bgra: &[u8], w: usize, h: usize, nv12: &mut [u8]) {
    debug_assert!(w.is_multiple_of(2) && h.is_multiple_of(2));
    debug_assert!(bgra.len() == w * h * 4 && nv12.len() == w * h * 3 / 2);
    // 16.16 fixed point: Y = 16 + 219/255 * (0.2126 R + 0.7152 G + 0.0722 B),
    // Cb/Cr = 128 + 224/255 * (B - Y') / 1.8556 and (R - Y') / 1.5748.
    fn luma(p: &[u8]) -> u8 {
        let (b, g, r) = (p[0] as i32, p[1] as i32, p[2] as i32);
        (16 + ((11966 * r + 40254 * g + 4064 * b + 32768) >> 16)) as u8
    }
    let (y_plane, uv_plane) = nv12.split_at_mut(w * h);
    let rows = bgra
        .chunks_exact(w * 8)
        .zip(y_plane.chunks_exact_mut(w * 2))
        .zip(uv_plane.chunks_exact_mut(w));
    for ((src, ys), uv) in rows {
        let (top, bottom) = src.split_at(w * 4);
        let (y_top, y_bottom) = ys.split_at_mut(w);
        let (top, _) = top.as_chunks::<8>();
        let (bottom, _) = bottom.as_chunks::<8>();
        let (y_top, _) = y_top.as_chunks_mut::<2>();
        let (y_bottom, _) = y_bottom.as_chunks_mut::<2>();
        let (uv, _) = uv.as_chunks_mut::<2>();
        let quads = top.iter().zip(bottom).zip(y_top).zip(y_bottom).zip(uv);
        for ((((t, b), yt), yb), c) in quads {
            yt[0] = luma(&t[0..4]);
            yt[1] = luma(&t[4..8]);
            yb[0] = luma(&b[0..4]);
            yb[1] = luma(&b[4..8]);
            let sum = |i: usize| t[i] as i32 + t[i + 4] as i32 + b[i] as i32 + b[i + 4] as i32;
            let (bs, gs, rs) = (sum(0), sum(1), sum(2));
            c[0] = (128 + ((-6596 * rs - 22188 * gs + 28784 * bs + 131072) >> 18)) as u8;
            c[1] = (128 + ((28784 * rs - 26145 * gs - 2639 * bs + 131072) >> 18)) as u8;
        }
    }
}

/// Scratch for scaling a frame of another size into the recording's: aspect
/// preserved, centered, black borders, nearest neighbour (a rare path: guest
/// mode changes).
#[derive(Default)]
struct Fit {
    canvas: Vec<u8>,
    cols: Vec<usize>,
}

impl Fit {
    fn scale(&mut self, src: &[u8], sw: usize, sh: usize, dw: usize, dh: usize) {
        self.canvas.clear();
        self.canvas.resize(dw * dh * 4, 0);
        // Largest sw:sh box inside dw x dh.
        let (fw, fh) = if sw * dh <= dw * sh {
            ((sw * dh / sh).clamp(1, dw), dh)
        } else {
            (dw, (sh * dw / sw).clamp(1, dh))
        };
        let (x0, y0) = ((dw - fw) / 2, (dh - fh) / 2);
        self.cols.clear();
        self.cols.extend((0..fw).map(|x| (x * sw / fw) * 4));
        for y in 0..fh {
            let src_row = &src[(y * sh / fh) * sw * 4..][..sw * 4];
            let dst_row = &mut self.canvas[((y0 + y) * dw + x0) * 4..][..fw * 4];
            for (dst, &sx) in dst_row.as_chunks_mut::<4>().0.iter_mut().zip(&self.cols) {
                dst.copy_from_slice(&src_row[sx..sx + 4]);
            }
        }
    }
}

/// The AAC track's PCM timeline: frames committed to the encoder, plus PCM
/// staged after them for the next write.
#[derive(Default)]
struct AudioTrack {
    written: u64,
    staged: Vec<u8>,
    late: u64,
    queue: AudioQueue,
}

impl AudioTrack {
    /// Frames on the track so far (written + staged).
    fn end(&self) -> i64 {
        (self.written + (self.staged.len() / PCM_FRAME) as u64) as i64
    }

    /// Move the tap's queued chunks onto the track.
    fn take(&mut self, shared: &Shared) {
        {
            let mut q = shared.audio.lock().unwrap();
            std::mem::swap(&mut *q, &mut self.queue);
        }
        let mut off = 0;
        let queue = std::mem::take(&mut self.queue);
        for &(pos, len) in &queue.chunks {
            self.place(pos, &queue.data[off..off + len]);
            off += len;
        }
        // Hand the (cleared) buffers back for reuse by the next swap.
        self.queue = queue;
        self.queue.data.clear();
        self.queue.chunks.clear();
    }

    /// Put `pcm` at track frame `pos`: silence fills a gap before it; the part
    /// that overlaps what is already on the track (late, or before `t0`) is
    /// dropped.
    fn place(&mut self, pos: i64, pcm: &[u8]) {
        let frames = (pcm.len() / PCM_FRAME) as i64;
        let skip = (self.end() - pos).clamp(0, frames);
        self.late += skip as u64;
        if skip == frames {
            return;
        }
        self.pad_to(pos);
        self.staged
            .extend_from_slice(&pcm[skip as usize * PCM_FRAME..frames as usize * PCM_FRAME]);
    }

    /// Extend the track with silence up to frame `pos`.
    fn pad_to(&mut self, pos: i64) {
        let gap = pos - self.end();
        if gap > 0 {
            let len = self.staged.len() + gap as usize * PCM_FRAME;
            self.staged.resize(len, 0);
        }
    }

    /// Commit the staged PCM through `write(pcm, time, duration)`.
    fn flush(&mut self, write: impl FnOnce(&[u8], i64, i64) -> Result<()>) -> Result<()> {
        if self.staged.is_empty() {
            return Ok(());
        }
        let frames = (self.staged.len() / PCM_FRAME) as u64;
        let (t, end) = (audio_hns(self.written), audio_hns(self.written + frames));
        write(&self.staged, t, end - t)?;
        self.written += frames;
        self.staged.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_record_spec() {
        let s = RecordSpec::parse("out.mp4").unwrap();
        assert_eq!(
            s,
            RecordSpec {
                path: PathBuf::from("out.mp4"),
                fps: DEFAULT_FPS,
                kbps: None
            }
        );
        let s = RecordSpec::parse(r"C:\rec\vm.mp4,fps=60,kbps=8000").unwrap();
        assert_eq!(s.path, PathBuf::from(r"C:\rec\vm.mp4"));
        assert_eq!((s.fps, s.kbps), (60, Some(8000)));
        for bad in [
            "",
            ",fps=30",
            "a.mp4,fps=0",
            "a.mp4,fps=61",
            "a.mp4,kbps=x",
            "a.mp4,hz=5",
        ] {
            assert!(RecordSpec::parse(bad).is_err(), "{bad}");
        }
    }

    fn bgra(px: &[[u8; 3]]) -> Vec<u8> {
        px.iter().flat_map(|&[r, g, b]| [b, g, r, 255]).collect()
    }

    /// Primaries convert to their BT.709 limited-range codes; a mixed 2x2
    /// block's chroma is the block average.
    #[test]
    fn nv12_bt709_limited() {
        let cases: [([u8; 3], [u8; 3]); 5] = [
            ([255, 0, 0], [63, 102, 240]),
            ([0, 255, 0], [173, 42, 26]),
            ([0, 0, 255], [32, 240, 118]),
            ([255, 255, 255], [235, 128, 128]),
            ([0, 0, 0], [16, 128, 128]),
        ];
        for (rgb, [y, u, v]) in cases {
            let src = bgra(&[rgb; 4]);
            let mut out = [0u8; 6];
            bgra_to_nv12(&src, 2, 2, &mut out);
            assert_eq!(out, [y, y, y, y, u, v], "{rgb:?}");
        }
        // Top row white, bottom row black: luma per pixel, chroma neutral.
        let src = bgra(&[[255; 3], [255; 3], [0; 3], [0; 3]]);
        let mut out = [0u8; 6];
        bgra_to_nv12(&src, 2, 2, &mut out);
        assert_eq!(out, [235, 235, 16, 16, 128, 128]);
        // 4x2: each 2x2 block gets its own chroma pair.
        let red = [255, 0, 0];
        let blue = [0, 0, 255];
        let src = bgra(&[red, red, blue, blue, red, red, blue, blue]);
        let mut out = [0u8; 12];
        bgra_to_nv12(&src, 4, 2, &mut out);
        assert_eq!(&out[8..], &[102, 240, 240, 118]);
    }

    /// A frame of another aspect ratio is scaled to fit, centered with black
    /// borders.
    #[test]
    fn fit_letterboxes() {
        // 2x1 source (red, blue) into 4x4: scaled to 4x2, rows 1..3.
        let src = bgra(&[[255, 0, 0], [0, 0, 255]]);
        let mut fit = Fit::default();
        fit.scale(&src, 2, 1, 4, 4);
        let px = |x: usize, y: usize| &fit.canvas[(y * 4 + x) * 4..][..3];
        for x in 0..4 {
            assert_eq!(px(x, 0), [0, 0, 0]);
            assert_eq!(px(x, 3), [0, 0, 0]);
        }
        for y in 1..3 {
            assert_eq!(px(0, y), [0, 0, 255]); // BGR of red
            assert_eq!(px(1, y), [0, 0, 255]);
            assert_eq!(px(2, y), [255, 0, 0]); // BGR of blue
            assert_eq!(px(3, y), [255, 0, 0]);
        }
        // Tall source: pillarboxed.
        let src = bgra(&[[255, 255, 255]; 2]); // 1x2
        fit.scale(&src, 1, 2, 4, 2);
        assert_eq!(&fit.canvas[0..3], &[0, 0, 0]);
        assert_eq!(&fit.canvas[4..7], &[255, 255, 255]);
        assert_eq!(&fit.canvas[12..15], &[0, 0, 0]);
    }

    fn pcm(frames: usize, v: u8) -> Vec<u8> {
        vec![v; frames * PCM_FRAME]
    }

    /// Chunks land at their clock position: contiguous chunks append, a gap is
    /// filled with silence, and anything already covered is dropped as late.
    #[test]
    fn audio_track_placement() {
        let mut t = AudioTrack::default();
        t.place(0, &pcm(480, 1));
        t.place(480, &pcm(480, 2));
        assert_eq!(t.end(), 960);
        // Gap of 40 frames (e.g. the guest restarted playback).
        t.place(1000, &pcm(10, 3));
        assert_eq!(t.end(), 1010);
        assert!(t.staged[960 * 4..1000 * 4].iter().all(|&b| b == 0));
        assert!(t.staged[1000 * 4..].iter().all(|&b| b == 3));
        // Overlapping chunk: the first 5 frames are late, the rest append.
        t.place(1005, &pcm(10, 4));
        assert_eq!((t.end(), t.late), (1015, 5));
        // Entirely late (and pre-t0) chunks are dropped.
        t.place(0, &pcm(10, 5));
        t.place(-100, &pcm(10, 5));
        assert_eq!((t.end(), t.late), (1015, 25));
        // Idle padding only ever extends the track.
        t.pad_to(900);
        assert_eq!(t.end(), 1015);
        t.pad_to(1100);
        assert_eq!(t.end(), 1100);

        let mut writes = Vec::new();
        t.flush(|pcm, time, dur| {
            writes.push((pcm.len(), time, dur));
            Ok(())
        })
        .unwrap();
        t.place(1100, &pcm(48, 6));
        t.flush(|pcm, time, dur| {
            writes.push((pcm.len(), time, dur));
            Ok(())
        })
        .unwrap();
        // Timestamps are contiguous in 100-ns units.
        assert_eq!(writes[0], (1100 * 4, 0, audio_hns(1100)));
        assert_eq!(writes[1].1, audio_hns(1100));
        assert_eq!(writes[1].1 + writes[1].2, audio_hns(1148));
        assert_eq!(t.written, 1148);
    }

    #[test]
    fn timeline_math() {
        let t0 = Instant::now();
        assert_eq!(frames_since(t0, t0 + Duration::from_millis(10)), 480);
        assert_eq!(frames_since(t0 + Duration::from_secs(1), t0), -48_000);
        assert_eq!(tick_hns(30, 30), 10_000_000);
        assert_eq!(tick_hns(1, 30), 333_333);
        assert_eq!(audio_hns(48_000), 10_000_000);
        assert_eq!(default_bitrate(1280, 800, 30), 4_608_000);
        assert_eq!(default_bitrate(64, 64, 1), 500_000);
    }
}
