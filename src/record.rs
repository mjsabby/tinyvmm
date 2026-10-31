//! Guest A/V recorder (`--record`): tees the virtio-gpu scanout and the
//! virtio-snd playback stream into an MP4 (H.264 + AAC), encoded in real time on
//! a dedicated thread through Media Foundation ([`crate::host::media`]).
//!
//! Everything lands on one timeline that starts when the recorder starts (`t0`,
//! QPC via [`Instant`]):
//!   * Video is constant frame rate: tick `k` (time `k / fps`) is one sample one
//!     frame period long. Never a longer one: some hardware encoders replace
//!     sample durations with the nominal period, which would shorten the video
//!     track. At each tick the encoder converts the scanout's latest picture,
//!     holding it by reference (flushes draw on other buffers meanwhile), or
//!     queues the previous picture again when the guest hasn't flushed since
//!     (a static desktop; the encoder resubmits that picture's buffer, no copy).
//!     A present only bumps a counter, so the vCPU neither copies a frame for
//!     the recorder nor waits on the encoder; pictures flushed between two
//!     ticks are dropped. A frame whose size differs from the
//!     recording's (a guest mode change) is scaled to fit and letterboxed.
//!   * If the encoder falls behind, it catches up by repeating the previous
//!     picture for each tick it missed, and takes a new frame only for the tick
//!     the present falls in, so no frame is shown before it was presented. A
//!     stall longer than [`MAX_BACKLOG`] (the host suspended, a long encoder
//!     block) is cut from both tracks instead: the next tick shows the current
//!     frame, audio from inside the gap is dropped, the summary reports the time
//!     skipped, and the tracks stay in sync.
//!   * Audio: while tapped, virtio-snd playback is clock-paced, so every PCM
//!     chunk carries its exact position on a 48 kHz clock. The recorder places
//!     it on the track at `(epoch - t0) * 48 kHz + offset` (less any time cut)
//!     and fills gaps (the guest not playing, a skipped host stall) with
//!     silence. Each tick commits audio up to the end of the video written so
//!     far, padding silence up to `now - AUDIO_LAG`: the streams stay
//!     interleaved (the sink writer stalls a stream that runs far ahead of the
//!     other), silence is generated a tick at a time, and staged PCM is capped.
//!   * [`Recorder::finish`] ends both tracks at the tick showing the moment it
//!     was called, even if the encoder was stalled then.
//!
//! The output is a fragmented MP4, playable while it grows and still playable
//! (up to the last fragment) if tinyvmm dies before finalizing it.

use crate::error::{Error, Result};
use crate::host::audio::{Event, INFINITE, SAMPLE_RATE, WaitOutcome, wait_any};
use crate::host::media::{Mp4Options, Mp4Writer, VideoFormat};
use crate::scanout::Scanout;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const DEFAULT_FPS: u32 = 30;
const MAX_FPS: u32 = 60;
/// Bytes per PCM frame (S16LE stereo), the virtio-snd contract.
const PCM_FRAME: usize = 4;
/// How far behind real time the audio track is padded with silence while the
/// guest isn't playing. PCM arriving later than this is dropped (counted).
const AUDIO_LAG_FRAMES: i64 = SAMPLE_RATE as i64 / 5;
/// How far the encoder may fall behind before the gap is cut rather than
/// caught up. Also the PCM queued for the encoder: beyond it, new PCM is
/// dropped (counted).
const MAX_BACKLOG: Duration = Duration::from_secs(2);
const AUDIO_QUEUE_MAX_BYTES: usize =
    MAX_BACKLOG.as_secs() as usize * SAMPLE_RATE as usize * PCM_FRAME;
/// Cap on PCM staged on the track ahead of what was committed: twice what the
/// backlog can leave there. PCM that would stage beyond it is dropped (counted).
const MAX_STAGED_FRAMES: i64 = 2 * MAX_BACKLOG.as_secs() as i64 * SAMPLE_RATE as i64;
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

/// PCM handed over by the playback tap: bytes plus `(track position, bytes)`
/// for each chunk.
#[derive(Default)]
struct AudioQueue {
    data: Vec<u8>,
    chunks: Vec<(i64, usize)>,
}

struct Shared {
    t0: Instant,
    /// What the guest shows; the encoder converts its latest picture at each
    /// tick when it changed.
    scanout: Arc<Scanout>,
    audio: Mutex<AudioQueue>,
    /// When [`Recorder::finish`] was called: the recording ends there.
    stop_at: OnceLock<Instant>,
    wake: Event,
    presents: AtomicU64,
    audio_overflow_frames: AtomicU64,
}

impl Shared {
    /// The producer/encoder rendezvous; the timeline starts now.
    fn new(scanout: Arc<Scanout>) -> Option<Arc<Shared>> {
        Some(Arc::new(Shared {
            t0: Instant::now(),
            scanout,
            audio: Mutex::new(AudioQueue {
                data: Vec::with_capacity(AUDIO_QUEUE_MAX_BYTES / 4),
                chunks: Vec::with_capacity(256),
            }),
            stop_at: OnceLock::new(),
            wake: Event::new(false)?,
            presents: AtomicU64::new(0),
            audio_overflow_frames: AtomicU64::new(0),
        }))
    }

    /// See [`Recorder::audio_pcm`].
    fn queue_pcm(&self, epoch: Instant, offset: u64, pcm: &[u8]) {
        let pos = frames_since(self.t0, epoch) + offset as i64;
        let mut q = self.audio.lock().unwrap();
        if q.data.len() + pcm.len() > AUDIO_QUEUE_MAX_BYTES {
            self.audio_overflow_frames
                .fetch_add((pcm.len() / PCM_FRAME) as u64, Ordering::Relaxed);
            return;
        }
        q.data.extend_from_slice(pcm);
        q.chunks.push((pos, pcm.len()));
    }
}

/// What the encoder thread did, for the shutdown report.
#[derive(Default)]
pub struct Summary {
    path: PathBuf,
    fps: u32,
    /// Video ticks written (frame count at the nominal rate).
    ticks: u64,
    /// Ticks that showed a newly presented frame (vs a repeat).
    new_frames: u64,
    /// Ticks written behind schedule, repeating the previous picture, while
    /// the encoder caught up.
    late_ticks: u64,
    /// Time cut from both tracks at stalls longer than [`MAX_BACKLOG`].
    skipped: Duration,
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
            "{}: {:.1} s, {} frames @ {} fps ({} new of {} guest presents, {} late",
            self.path.display(),
            secs,
            self.ticks,
            self.fps,
            self.new_frames,
            self.presents,
            self.late_ticks
        )?;
        if !self.skipped.is_zero() {
            write!(f, ", {:.1} s skipped", self.skipped.as_secs_f64())?;
        }
        f.write_str(")")?;
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

/// A running recording. Feed it through the scanout (telling it with
/// [`Self::frame_ready`]) and [`Self::audio_pcm`] (the virtio-snd playback
/// tap); [`Self::finish`] (or drop) finalizes the file.
pub struct Recorder {
    shared: Arc<Shared>,
    worker: Mutex<Option<JoinHandle<Summary>>>,
    /// One-line description of the stream setup, for the startup log.
    pub description: String,
}

impl Recorder {
    /// Create the output file and start the encoder thread, which records
    /// `scanout`. `width`x`height` is the GPU's display size (rounded up to
    /// even for H.264); `audio` adds an AAC track for the guest's playback
    /// stream.
    pub fn start(
        spec: &RecordSpec,
        width: u32,
        height: u32,
        audio: bool,
        scanout: Arc<Scanout>,
    ) -> Result<Arc<Self>> {
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
                    let Some(shared) = Shared::new(scanout) else {
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

    /// GPU present hook: a flush published a new picture in the scanout. The
    /// encoder converts it at its next tick, on its own thread.
    pub fn frame_ready(&self) {
        self.shared.presents.fetch_add(1, Ordering::Relaxed);
    }

    /// virtio-snd playback tap: queue `pcm`, which sits `offset` frames into
    /// the playback run whose 48 kHz clock started at `epoch`.
    pub fn audio_pcm(&self, epoch: Instant, offset: u64, pcm: &[u8]) {
        self.shared.queue_pcm(epoch, offset, pcm);
    }

    /// Stop recording now, finalize the file and report. Both tracks end at the
    /// tick showing this moment. Later calls return `None`.
    pub fn finish(&self) -> Option<Summary> {
        let worker = self.worker.lock().unwrap().take()?;
        let _ = self.shared.stop_at.set(Instant::now());
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

/// Audio track frames (48 kHz) before video tick `k`.
fn tick_frames(k: u64, fps: u32) -> i64 {
    (k as u128 * SAMPLE_RATE as u128 / fps as u128) as i64
}

/// Where the encoder sends samples (times and durations in 100-ns units): the
/// MP4 writer, or a fake in tests.
trait Sink {
    /// A new picture (NV12).
    fn video(&mut self, nv12: &[u8], time: i64, duration: i64) -> Result<()>;
    /// The previous picture again.
    fn repeat_video(&mut self, time: i64, duration: i64) -> Result<()>;
    fn audio(&mut self, pcm: &[u8], time: i64, duration: i64) -> Result<()>;
}

impl Sink for Mp4Writer {
    fn video(&mut self, nv12: &[u8], time: i64, duration: i64) -> Result<()> {
        self.write_video(nv12, time, duration)
    }
    fn repeat_video(&mut self, time: i64, duration: i64) -> Result<()> {
        Mp4Writer::repeat_video(self, time, duration)
    }
    fn audio(&mut self, pcm: &[u8], time: i64, duration: i64) -> Result<()> {
        self.write_audio(pcm, time, duration)
    }
}

/// The encoder thread's timeline: the video clock and current picture, plus
/// the audio track.
struct Encoder {
    t0: Instant,
    fmt: VideoFormat,
    /// When tick 0 was due: `t0` plus the time cut from the recording so far.
    base: Instant,
    /// The next tick to write.
    next: u64,
    /// The current picture, and whether the sink has it (so later ticks can
    /// repeat it).
    nv12: Vec<u8>,
    pictured: bool,
    /// The number of the last flush converted.
    seen: u64,
    fit: Fit,
    /// `None` without an audio stream.
    track: Option<AudioTrack>,
    new_frames: u64,
    late_ticks: u64,
    skipped: Duration,
}

impl Encoder {
    fn new(t0: Instant, fmt: VideoFormat, audio: bool) -> Encoder {
        let mut nv12 = vec![0u8; fmt.nv12_len()];
        let luma = fmt.width as usize * fmt.height as usize;
        nv12[..luma].fill(16); // black until the guest presents
        nv12[luma..].fill(128);
        Encoder {
            t0,
            fmt,
            base: t0,
            next: 0,
            nv12,
            pictured: false,
            seen: 0,
            fit: Fit::default(),
            track: audio.then(AudioTrack::default),
            new_frames: 0,
            late_ticks: 0,
            skipped: Duration::ZERO,
        }
    }

    /// When the next tick is due.
    fn due(&self) -> Instant {
        let ns = self.next as u128 * 1_000_000_000 / self.fmt.fps as u128;
        self.base + Duration::from_nanos(ns as u64)
    }

    /// The tick whose period contains `t`.
    fn tick_at(&self, t: Instant) -> u64 {
        let ns = t.saturating_duration_since(self.base).as_nanos();
        (ns * self.fmt.fps as u128 / 1_000_000_000) as u64
    }

    /// Write the next tick, which is due at or before `now`, then commit audio
    /// up to the end of the video.
    fn tick(&mut self, shared: &Shared, sink: &mut impl Sink, now: Instant) -> Result<()> {
        let late = now.saturating_duration_since(self.due());
        if late > MAX_BACKLOG {
            self.cut(shared, now, late);
        }
        let (k, fps) = (self.next, self.fmt.fps);
        let (t, end) = (tick_hns(k, fps), tick_hns(k + 1, fps));
        // Behind schedule, repeat the previous picture: a frame presented by
        // now belongs to a later tick, not this past one. A new picture is
        // converted where the scanout keeps it: holding it doesn't hold up
        // flushes, which draw on other buffers.
        let behind = self.tick_at(now) > k;
        let new = !behind
            && shared.scanout.newer_than(self.seen).is_some_and(|f| {
                self.seen = f.seq();
                convert(
                    &f.buf,
                    f.width,
                    f.height,
                    &self.fmt,
                    &mut self.fit,
                    &mut self.nv12,
                )
            });
        if new || !self.pictured {
            sink.video(&self.nv12, t, end - t)?;
            self.pictured = true;
        } else {
            sink.repeat_video(t, end - t)?;
        }
        self.next = k + 1;
        self.new_frames += u64::from(new);
        self.late_ticks += u64::from(behind);
        let video_end = tick_frames(self.next, fps);
        let pad = (frames_since(self.base, now) - AUDIO_LAG_FRAMES).min(video_end);
        if let Some(track) = &mut self.track {
            track.take(shared);
            track.commit(pad, video_end, |pcm, t, d| sink.audio(pcm, t, d))?;
        }
        Ok(())
    }

    /// Cut the `late` stretch before `now` from both tracks: the next tick is
    /// shown from `now`, and PCM from inside the gap is dropped.
    fn cut(&mut self, shared: &Shared, now: Instant, late: Duration) {
        self.base += late;
        self.skipped += late;
        let at = tick_frames(self.next, self.fmt.fps);
        let wall_end = frames_since(self.t0, now);
        let shift = frames_since(self.t0, self.base);
        if let Some(track) = &mut self.track {
            // Place what the tap queued before the gap (still at the old
            // offset); what that stages past the cut point is from the gap, and
            // so is whatever the full queue turned away since the last take.
            let seen = track.tap_overflow;
            track.take(shared);
            track.cut_overflow += track.tap_overflow - seen;
            track.cut(at, wall_end, shift);
        }
    }

    /// End the recording at `stop`: write the ticks through the one showing it
    /// (catching up, or cutting a long gap, as while recording), then end the
    /// audio exactly where the video ends.
    fn finish(&mut self, shared: &Shared, sink: &mut impl Sink, stop: Instant) -> Result<()> {
        while self.due() <= stop {
            self.tick(shared, sink, stop)?;
        }
        let end = tick_frames(self.next, self.fmt.fps);
        if let Some(track) = &mut self.track {
            track.take(shared);
            track.truncate(end);
            track.commit(end, end, |pcm, t, d| sink.audio(pcm, t, d))?;
        }
        Ok(())
    }

    /// The shutdown report.
    fn summary(&self, shared: &Shared, path: PathBuf) -> Summary {
        let track = self.track.as_ref();
        let tap_overflow = shared.audio_overflow_frames.load(Ordering::Relaxed);
        Summary {
            path,
            fps: self.fmt.fps,
            ticks: self.next,
            new_frames: self.new_frames,
            late_ticks: self.late_ticks,
            skipped: self.skipped,
            presents: shared.presents.load(Ordering::Relaxed),
            audio: track.is_some(),
            audio_frames: track.map_or(0, |t| t.written),
            late_audio_frames: track.map_or(0, |t| t.late),
            overflow_audio_frames: track
                .map_or(tap_overflow, |t| tap_overflow - t.cut_overflow + t.overflow),
            error: None,
        }
    }
}

/// The encoder thread: one video sample per tick, audio alongside, until
/// [`Recorder::finish`].
fn encode(shared: &Shared, mut writer: Mp4Writer, fmt: &VideoFormat, path: PathBuf) -> Summary {
    let mut enc = Encoder::new(shared.t0, *fmt, writer.has_audio());
    let timer = Event::timer();
    let result = loop {
        if let Some(&stop) = shared.stop_at.get() {
            break enc.finish(shared, &mut writer, stop);
        }
        let now = Instant::now();
        let due = enc.due();
        if now < due {
            let wait = due - now;
            let outcome = match &timer {
                Some(t) if t.arm_timer((wait.as_nanos() / 100) as i64, 0) => {
                    wait_any(&[&shared.wake, t], INFINITE)
                }
                _ => wait_any(&[&shared.wake], (wait.as_millis() as u32).max(1)),
            };
            if let WaitOutcome::Failed = outcome {
                break Err(Error::msg("recorder wait failed"));
            }
            continue;
        }
        if let Err(e) = enc.tick(shared, &mut writer, now) {
            break Err(e);
        }
    };
    let mut s = enc.summary(shared, path);
    if let Err(e) = result {
        s.error = Some(e.to_string());
    }
    if let Err(e) = writer.finalize() {
        s.error.get_or_insert(e.to_string());
    }
    s
}

/// Convert a `width`x`height` BGRA frame into the recording's NV12 buffer,
/// scaling it to fit when its size differs. False (buffer untouched) for a
/// malformed frame.
fn convert(
    bgra: &[u8],
    width: u32,
    height: u32,
    fmt: &VideoFormat,
    fit: &mut Fit,
    nv12: &mut [u8],
) -> bool {
    let (w, h) = (width as usize, height as usize);
    if w == 0 || h == 0 || bgra.len() != w * h * 4 {
        return false;
    }
    let (ow, oh) = (fmt.width as usize, fmt.height as usize);
    if (w, h) == (ow, oh) {
        bgra_to_nv12(bgra, ow, oh, nv12);
    } else {
        fit.scale(bgra, w, h, ow, oh);
        bgra_to_nv12(&fit.canvas, ow, oh, nv12);
    }
    true
}

/// Convert a top-down BGRA frame to NV12, BT.709 limited range (what the
/// encoder's VUI declares). `w` and `h` must be even. Chroma is the average of
/// each 2x2 block. Uses AVX2 when the CPU has it (~3 ms for a 4K frame, about
/// 4x the scalar loop), else [`nv12_rows`]; both produce the same bytes.
fn bgra_to_nv12(bgra: &[u8], w: usize, h: usize, nv12: &mut [u8]) {
    debug_assert!(w.is_multiple_of(2) && h.is_multiple_of(2));
    debug_assert!(bgra.len() == w * h * 4 && nv12.len() == w * h * 3 / 2);
    let (y_plane, uv_plane) = nv12.split_at_mut(w * h);
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("avx2") {
        // SAFETY: the CPU supports AVX2 (checked just above).
        return unsafe { nv12_avx2(bgra, w, y_plane, uv_plane) };
    }
    nv12_rows(bgra, w, y_plane, uv_plane, 0);
}

/// The scalar converter, one 2x2 block at a time, from column `x0` (even) of
/// every row pair.
fn nv12_rows(bgra: &[u8], w: usize, y_plane: &mut [u8], uv_plane: &mut [u8], x0: usize) {
    // 16.16 fixed point: Y = 16 + 219/255 * (0.2126 R + 0.7152 G + 0.0722 B),
    // Cb/Cr = 128 + 224/255 * (B - Y') / 1.8556 and (R - Y') / 1.5748.
    fn luma(p: &[u8]) -> u8 {
        let (b, g, r) = (p[0] as i32, p[1] as i32, p[2] as i32);
        (16 + ((11966 * r + 40254 * g + 4064 * b + 32768) >> 16)) as u8
    }
    let rows = bgra
        .chunks_exact(w * 8)
        .zip(y_plane.chunks_exact_mut(w * 2))
        .zip(uv_plane.chunks_exact_mut(w));
    for ((src, ys), uv) in rows {
        let (top, bottom) = src.split_at(w * 4);
        let (y_top, y_bottom) = ys.split_at_mut(w);
        let (top, _) = top[x0 * 4..].as_chunks::<8>();
        let (bottom, _) = bottom[x0 * 4..].as_chunks::<8>();
        let (y_top, _) = y_top[x0..].as_chunks_mut::<2>();
        let (y_bottom, _) = y_bottom[x0..].as_chunks_mut::<2>();
        let (uv, _) = uv[x0..].as_chunks_mut::<2>();
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

/// [`nv12_rows`] 16 pixels of a row pair at a time with the same integer math,
/// so the output is bit-identical; the last `w % 16` columns go to
/// [`nv12_rows`]. Each BGRA pixel is one 32-bit lane: masking leaves the
/// 16-bit pair [B, R] and shifting each half right by 8 leaves [G, A], so one
/// `vpmaddwd` yields `B * cb + R * cr` per pixel. Green's luma weight (40254)
/// doesn't fit in an i16, so G is multiplied by 20127 and doubled. Chroma sums
/// each 2x2 block in 16 bits (at most 1020) before the same multiply-add.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
fn nv12_avx2(bgra: &[u8], w: usize, y_plane: &mut [u8], uv_plane: &mut [u8]) {
    use std::arch::x86_64::*;

    // The i16 pair [lo, hi] in every 32-bit lane.
    let pair = |lo: i16, hi: i16| _mm256_set1_epi32(((hi as u16 as i32) << 16) | lo as u16 as i32);
    let mask = _mm256_set1_epi32(0x00ff_00ff);
    let (y_br, y_g) = (pair(4064, 11966), pair(20127, 0));
    let (y_round, y_off) = (_mm256_set1_epi32(32768), _mm256_set1_epi32(16));
    let (cb_br, cb_g) = (pair(28784, -6596), pair(-22188, 0));
    let (cr_br, cr_g) = (pair(-2639, 28784), pair(-26145, 0));
    let (c_round, c_off) = (_mm256_set1_epi32(131072), _mm256_set1_epi32(128));
    let order = _mm256_setr_epi32(0, 4, 1, 5, 2, 6, 3, 7);

    // Eight pixels as their [B, R] and [G, A] pairs.
    let load = |px: &[u8]| {
        assert!(px.len() >= 32);
        // SAFETY: `px` has at least 32 readable bytes; the load is unaligned.
        let p = unsafe { _mm256_loadu_si256(px.as_ptr().cast()) };
        (_mm256_and_si256(p, mask), _mm256_srli_epi16::<8>(p))
    };
    let luma = |(br, ga): (__m256i, __m256i)| {
        let g = _mm256_madd_epi16(ga, y_g);
        let s = _mm256_add_epi32(_mm256_madd_epi16(br, y_br), _mm256_add_epi32(g, g));
        _mm256_add_epi32(_mm256_srli_epi32::<16>(_mm256_add_epi32(s, y_round)), y_off)
    };
    // [Cb, Cr] in each 64-bit lane: the 2x2 block of pixels 2i and 2i+1.
    let chroma = |(tbr, tga): (__m256i, __m256i), (bbr, bga): (__m256i, __m256i)| {
        let (br, ga) = (_mm256_add_epi16(tbr, bbr), _mm256_add_epi16(tga, bga));
        let br = _mm256_add_epi16(br, _mm256_srli_epi64::<32>(br));
        let ga = _mm256_add_epi16(ga, _mm256_srli_epi64::<32>(ga));
        let c = |k_br, k_g| {
            let s = _mm256_add_epi32(_mm256_madd_epi16(br, k_br), _mm256_madd_epi16(ga, k_g));
            _mm256_add_epi32(_mm256_srai_epi32::<18>(_mm256_add_epi32(s, c_round)), c_off)
        };
        _mm256_blend_epi32::<0b1010_1010>(c(cb_br, cb_g), _mm256_slli_epi64::<32>(c(cr_br, cr_g)))
    };
    // Two vectors of eight 0..=255 lanes -> 16 bytes, in order.
    let store = |dst: &mut [u8; 16], a: __m256i, b: __m256i| {
        let v = _mm256_packs_epi32(a, b);
        let v = _mm256_permutevar8x32_epi32(_mm256_packus_epi16(v, v), order);
        // SAFETY: `dst` is 16 writable bytes; the store is unaligned.
        unsafe { _mm_storeu_si128(dst.as_mut_ptr().cast(), _mm256_castsi256_si128(v)) }
    };

    let simd_w = w & !15;
    let rows = bgra
        .chunks_exact(w * 8)
        .zip(y_plane.chunks_exact_mut(w * 2))
        .zip(uv_plane.chunks_exact_mut(w));
    for ((src, ys), uv) in rows {
        let (top, bottom) = src.split_at(w * 4);
        let (y_top, y_bottom) = ys.split_at_mut(w);
        let (top, _) = top[..simd_w * 4].as_chunks::<64>();
        let (bottom, _) = bottom[..simd_w * 4].as_chunks::<64>();
        let (y_top, _) = y_top[..simd_w].as_chunks_mut::<16>();
        let (y_bottom, _) = y_bottom[..simd_w].as_chunks_mut::<16>();
        let (uv, _) = uv[..simd_w].as_chunks_mut::<16>();
        let blocks = top.iter().zip(bottom).zip(y_top).zip(y_bottom).zip(uv);
        for ((((t, b), yt), yb), c) in blocks {
            let (t0, t1) = (load(&t[..32]), load(&t[32..]));
            let (b0, b1) = (load(&b[..32]), load(&b[32..]));
            store(yt, luma(t0), luma(t1));
            store(yb, luma(b0), luma(b1));
            store(c, chroma(t0, b0), chroma(t1, b1));
        }
    }
    if simd_w < w {
        nv12_rows(bgra, w, y_plane, uv_plane, simd_w);
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
/// staged after them for later commits. The tap queues chunks at wall-clock
/// positions (48 kHz frames since `t0`); the track maps them past any time cut
/// from the recording.
#[derive(Default)]
struct AudioTrack {
    written: u64,
    staged: Vec<u8>,
    /// A chunk at wall position `p` lands at track frame `p - shift`.
    shift: i64,
    /// Wall positions before this aren't part of the recording (before `t0`,
    /// or cut).
    floor: i64,
    late: u64,
    /// PCM dropped by the [`MAX_STAGED_FRAMES`] cap.
    overflow: u64,
    /// The tap's queue-overflow count at the last [`Self::take`], and how much
    /// of it fell inside cuts (the queue only fills while the encoder stalls).
    tap_overflow: u64,
    cut_overflow: u64,
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
            // The tap counts overflow under this lock.
            self.tap_overflow = shared.audio_overflow_frames.load(Ordering::Relaxed);
        }
        let mut off = 0;
        let queue = std::mem::take(&mut self.queue);
        for &(pos, len) in &queue.chunks {
            self.add(pos, &queue.data[off..off + len]);
            off += len;
        }
        // Hand the (cleared) buffers back for reuse by the next swap.
        self.queue = queue;
        self.queue.data.clear();
        self.queue.chunks.clear();
    }

    /// Put a chunk queued at wall position `pos` on the track, less any part
    /// before `floor`.
    fn add(&mut self, pos: i64, pcm: &[u8]) {
        let frames = (pcm.len() / PCM_FRAME) as i64;
        let skip = (self.floor - pos).clamp(0, frames);
        if skip < frames {
            let pcm = &pcm[skip as usize * PCM_FRAME..frames as usize * PCM_FRAME];
            self.place(pos + skip - self.shift, pcm);
        }
    }

    /// Put `pcm` at track frame `pos`: silence fills a gap before it; the part
    /// that overlaps what is already on the track (late) is dropped, and so is
    /// any part that would stage more than [`MAX_STAGED_FRAMES`].
    fn place(&mut self, pos: i64, pcm: &[u8]) {
        let frames = (pcm.len() / PCM_FRAME) as i64;
        let skip = (self.end() - pos).clamp(0, frames);
        self.late += skip as u64;
        let start = pos + skip;
        let keep = (self.written as i64 + MAX_STAGED_FRAMES - start).clamp(0, frames - skip);
        self.overflow += (frames - skip - keep) as u64;
        if keep == 0 {
            return;
        }
        self.pad_to(start);
        self.staged
            .extend_from_slice(&pcm[skip as usize * PCM_FRAME..(skip + keep) as usize * PCM_FRAME]);
    }

    /// Extend the track with silence up to frame `pos`, staging at most
    /// [`MAX_STAGED_FRAMES`].
    fn pad_to(&mut self, pos: i64) {
        let gap = pos.min(self.written as i64 + MAX_STAGED_FRAMES) - self.end();
        if gap > 0 {
            let len = self.staged.len() + gap as usize * PCM_FRAME;
            self.staged.resize(len, 0);
        }
    }

    /// Drop the track after frame `at` (never what was committed).
    fn truncate(&mut self, at: i64) {
        let keep = (at - self.written as i64).max(0) as usize;
        self.staged.truncate(keep * PCM_FRAME);
    }

    /// The recording jumps from track frame `at` to wall position `wall_end`:
    /// drop what is staged after `at` and PCM queued from before `wall_end`;
    /// later PCM lands at `wall - shift` (`wall_end - shift` is `at`).
    fn cut(&mut self, at: i64, wall_end: i64, shift: i64) {
        self.truncate(at);
        self.floor = wall_end;
        self.shift = shift;
    }

    /// Commit the track through frame `limit` with `write(pcm, time,
    /// duration)`, first padding it with silence up to `pad`. Writes pieces of
    /// at most [`MAX_STAGED_FRAMES`]; PCM staged after `limit` stays.
    fn commit(
        &mut self,
        pad: i64,
        limit: i64,
        mut write: impl FnMut(&[u8], i64, i64) -> Result<()>,
    ) -> Result<()> {
        loop {
            self.pad_to(pad);
            let n = self.end().min(limit) - self.written as i64;
            if n <= 0 {
                return Ok(());
            }
            let bytes = n as usize * PCM_FRAME;
            let (t, end) = (audio_hns(self.written), audio_hns(self.written + n as u64));
            write(&self.staged[..bytes], t, end - t)?;
            self.written += n as u64;
            self.staged.drain(..bytes);
        }
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

    /// The AVX2 converter writes exactly the scalar one's bytes: over widths
    /// that fill whole 16-pixel steps and ones that leave a scalar tail, for
    /// noise (alpha included, which both ignore) and 2x2 blocks mixing extreme
    /// colors.
    #[test]
    fn nv12_simd_matches_scalar() {
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut noise = |len: usize| -> Vec<u8> {
            (0..len)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    (seed >> 24) as u8
                })
                .collect()
        };
        let extremes = [
            [0, 0, 0],
            [255, 255, 255],
            [255, 0, 0],
            [0, 255, 0],
            [0, 0, 255],
            [255, 255, 0],
            [0, 255, 255],
        ];
        for (w, h) in [(16, 2), (18, 4), (32, 2), (34, 6), (1366, 8), (3840, 4)] {
            let mixed = (0..w * h)
                .flat_map(|i| {
                    let [r, g, b] = extremes[(i + i / w) % extremes.len()];
                    [b, g, r, 255]
                })
                .collect();
            for src in [noise(w * h * 4), mixed] {
                let mut want = vec![0u8; w * h * 3 / 2];
                let (y, uv) = want.split_at_mut(w * h);
                nv12_rows(&src, w, y, uv, 0);
                let mut got = vec![0u8; want.len()];
                bgra_to_nv12(&src, w, h, &mut got);
                assert!(got == want, "{w}x{h}");
            }
        }
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
        // Entirely late chunks are dropped.
        t.place(0, &pcm(10, 5));
        t.place(-100, &pcm(10, 5));
        assert_eq!((t.end(), t.late), (1015, 25));
        // Idle padding only ever extends the track.
        t.pad_to(900);
        assert_eq!(t.end(), 1015);
        t.pad_to(1100);
        assert_eq!(t.end(), 1100);

        let mut writes = Vec::new();
        let mut log = |pcm: &[u8], time: i64, dur: i64| -> Result<()> {
            writes.push((pcm.len(), time, dur));
            Ok(())
        };
        t.commit(1100, 1100, &mut log).unwrap();
        t.place(1100, &pcm(48, 6));
        // A commit stops at its limit; the rest stays staged.
        t.commit(0, 1120, &mut log).unwrap();
        assert_eq!((t.written, t.end()), (1120, 1148));
        t.commit(0, 1148, &mut log).unwrap();
        // Timestamps are contiguous in 100-ns units.
        assert_eq!(writes[0], (1100 * 4, 0, audio_hns(1100)));
        assert_eq!(
            writes[1],
            (20 * 4, audio_hns(1100), audio_hns(1120) - audio_hns(1100))
        );
        assert_eq!(writes[2].1 + writes[2].2, audio_hns(1148));
        assert_eq!(t.written, 1148);
    }

    /// Staging is capped: a chunk far past the track is dropped (counted)
    /// rather than padded up to, and long silence is committed in capped
    /// pieces.
    #[test]
    fn audio_staging_is_bounded() {
        let mut t = AudioTrack::default();
        t.place(0, &pcm(10, 1));
        t.place(10 + MAX_STAGED_FRAMES, &pcm(10, 2));
        assert_eq!((t.end(), t.overflow), (10, 10));
        t.pad_to(3 * MAX_STAGED_FRAMES);
        assert_eq!(t.end(), MAX_STAGED_FRAMES);
        let mut sizes = Vec::new();
        let far = 3 * MAX_STAGED_FRAMES;
        t.commit(far, far, |pcm: &[u8], _, _| -> Result<()> {
            sizes.push(pcm.len());
            Ok(())
        })
        .unwrap();
        assert_eq!(t.written, far as u64);
        let cap = MAX_STAGED_FRAMES as usize * PCM_FRAME;
        assert!(sizes.iter().all(|&n| n <= cap), "{sizes:?}");
    }

    /// Records what the encoder sends, checking that audio never runs ahead
    /// of the video already written.
    #[derive(Default)]
    struct FakeSink {
        /// `(time, duration, luma of pixel 0)`, `None` for a repeat.
        video: Vec<(i64, i64, Option<u8>)>,
        audio: Vec<(i64, i64, Vec<u8>)>,
    }

    impl Sink for FakeSink {
        fn video(&mut self, nv12: &[u8], time: i64, duration: i64) -> Result<()> {
            self.video.push((time, duration, Some(nv12[0])));
            Ok(())
        }
        fn repeat_video(&mut self, time: i64, duration: i64) -> Result<()> {
            self.video.push((time, duration, None));
            Ok(())
        }
        fn audio(&mut self, pcm: &[u8], time: i64, duration: i64) -> Result<()> {
            let video_end = self.video.last().map_or(0, |v| v.0 + v.1);
            assert!(time + duration <= video_end, "audio ahead of video");
            self.audio.push((time, duration, pcm.to_vec()));
            Ok(())
        }
    }

    impl FakeSink {
        /// One nominal-length sample per tick, from 0.
        fn assert_cfr(&self) {
            for (k, v) in (0u64..).zip(&self.video) {
                let t = tick_hns(k, FPS);
                assert_eq!((v.0, v.1), (t, tick_hns(k + 1, FPS) - t), "tick {k}");
            }
        }

        /// The pictures in tick order (`None` = repeat).
        fn pictures(&self) -> Vec<Option<u8>> {
            self.video.iter().map(|v| v.2).collect()
        }

        /// The audio track, checking the writes are contiguous from 0.
        fn track(&self) -> Vec<u8> {
            let mut next = 0;
            let mut out = Vec::new();
            for (time, duration, pcm) in &self.audio {
                assert_eq!(*time, next);
                next = time + duration;
                out.extend_from_slice(pcm);
            }
            out
        }
    }

    const FPS: u32 = 10;
    const WHITE: u8 = 235;
    const RED: u8 = 63;
    const GREEN: u8 = 173;

    /// A 4x2 encoder at 10 fps, its shared state, and a fake sink.
    fn test_encoder(audio: bool) -> (Arc<Shared>, Encoder, FakeSink) {
        let shared = Shared::new(Arc::new(Scanout::default())).expect("event");
        let fmt = VideoFormat {
            width: 4,
            height: 2,
            fps: FPS,
            bitrate: 500_000,
        };
        let enc = Encoder::new(shared.t0, fmt, audio);
        (shared, enc, FakeSink::default())
    }

    fn solid(rgb: [u8; 3]) -> Vec<u8> {
        bgra(&[rgb; 8])
    }

    /// The guest flushes a whole 4x2 frame of one color.
    fn show(shared: &Shared, rgb: [u8; 3]) {
        let frame = solid(rgb);
        let full = crate::scanout::Area::full(4, 2);
        shared
            .scanout
            .flush(4, 2, full, |buf, _| buf.copy_from_slice(&frame));
    }

    /// Frame `n`'s first byte on an audio track.
    fn sample(track: &[u8], n: usize) -> u8 {
        track[n * PCM_FRAME]
    }

    /// An encoder that falls behind writes one nominal-length sample per tick
    /// it missed, repeating the previous picture, and shows a new frame only
    /// on the tick it arrived in.
    #[test]
    fn stall_catches_up_one_sample_per_tick() {
        let (shared, mut enc, mut sink) = test_encoder(false);
        let at = |ms| shared.t0 + Duration::from_millis(ms);
        show(&shared, [255, 255, 255]);
        enc.tick(&shared, &mut sink, at(0)).unwrap();
        // The encoder stalls until 450 ms; a red frame arrives meanwhile.
        show(&shared, [255, 0, 0]);
        while enc.due() <= at(450) {
            enc.tick(&shared, &mut sink, at(450)).unwrap();
        }
        sink.assert_cfr();
        assert_eq!(sink.pictures(), [Some(WHITE), None, None, None, Some(RED)]);
        assert_eq!((enc.late_ticks, enc.new_frames), (3, 2));
        assert!(enc.skipped.is_zero());
    }

    /// A stall longer than MAX_BACKLOG is cut from both tracks: the next tick
    /// shows the current frame, PCM from inside the gap is dropped, and PCM
    /// after it lands where the video resumes.
    #[test]
    fn long_stall_is_cut_from_both_tracks() {
        let (shared, mut enc, mut sink) = test_encoder(true);
        let at = |ms| shared.t0 + Duration::from_millis(ms);
        show(&shared, [255, 255, 255]);
        enc.tick(&shared, &mut sink, at(0)).unwrap();
        shared.queue_pcm(at(0), 0, &pcm(2400, 1));
        // The host sleeps for 5 s. PCM from inside the gap is still queued (more
        // than the queue holds), and a green frame arrives as it wakes.
        shared.queue_pcm(at(1000), 0, &pcm(480, 2));
        shared.queue_pcm(at(1010), 0, &pcm(96_000, 2));
        show(&shared, [0, 255, 0]);
        enc.tick(&shared, &mut sink, at(5000)).unwrap();
        assert_eq!(enc.skipped, Duration::from_millis(4900));
        // Playback after the gap lands on tick 1 (100 ms), with the green frame.
        shared.queue_pcm(at(5000), 0, &pcm(480, 3));
        enc.tick(&shared, &mut sink, at(5100)).unwrap();
        enc.finish(&shared, &mut sink, at(5150)).unwrap();

        sink.assert_cfr();
        assert_eq!(sink.pictures(), [Some(WHITE), Some(GREEN), None]);
        let track = sink.track();
        assert_eq!(track.len(), tick_frames(3, FPS) as usize * PCM_FRAME);
        assert!((0..2400).all(|n| sample(&track, n) == 1));
        assert!((2400..4800).all(|n| sample(&track, n) == 0));
        assert!((4800..5280).all(|n| sample(&track, n) == 3));
        assert!((5280..14_400).all(|n| sample(&track, n) == 0));
        // PCM from the gap, including what the full queue turned away, went with
        // the cut: none of it counts as dropped.
        let t = enc.track.as_ref().unwrap();
        assert_eq!((t.late, t.overflow), (0, 0));
        let summary = enc.summary(&shared, PathBuf::new());
        assert_eq!(summary.overflow_audio_frames, 0);
    }

    /// Stopping while the encoder is stalled still ends both tracks at the
    /// stop: the missed ticks repeat, the last frame lands on the tick showing
    /// the stop, and PCM past the end of the video is dropped.
    #[test]
    fn finish_during_stall_ends_both_tracks_at_the_stop() {
        let (shared, mut enc, mut sink) = test_encoder(true);
        let at = |ms| shared.t0 + Duration::from_millis(ms);
        show(&shared, [255, 255, 255]);
        enc.tick(&shared, &mut sink, at(0)).unwrap();
        // While the encoder is stalled the guest plays 1.5 s and presents red;
        // then the VM stops at 1.3 s.
        shared.queue_pcm(at(0), 0, &pcm(48_000, 1));
        shared.queue_pcm(at(1000), 0, &pcm(24_000, 2));
        show(&shared, [255, 0, 0]);
        enc.finish(&shared, &mut sink, at(1300)).unwrap();

        sink.assert_cfr();
        // Ticks 0..=13 cover 0..1.4 s; red shows from tick 13 (1.3 s).
        let mut want = vec![None; 14];
        (want[0], want[13]) = (Some(WHITE), Some(RED));
        assert_eq!(sink.pictures(), want);
        assert_eq!(enc.late_ticks, 12);
        let track = sink.track();
        assert_eq!(track.len(), tick_frames(14, FPS) as usize * PCM_FRAME);
        assert!((0..48_000).all(|n| sample(&track, n) == 1));
        assert!((48_000..67_200).all(|n| sample(&track, n) == 2));
    }

    #[test]
    fn timeline_math() {
        let t0 = Instant::now();
        assert_eq!(frames_since(t0, t0 + Duration::from_millis(10)), 480);
        assert_eq!(frames_since(t0 + Duration::from_secs(1), t0), -48_000);
        assert_eq!(tick_hns(30, 30), 10_000_000);
        assert_eq!(tick_hns(1, 30), 333_333);
        assert_eq!(tick_frames(1, 30), 1600);
        assert_eq!(audio_hns(48_000), 10_000_000);
        assert_eq!(default_bitrate(1280, 800, 30), 4_608_000);
        assert_eq!(default_bitrate(64, 64, 1), 500_000);
    }
}
