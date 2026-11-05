//! The time-sync integration component: how Hyper-V sets a Linux guest's clock
//! from the host's, as WSL's is. The host pushes and the guest's `hv_utils`
//! applies, with no daemon. Once the guest opens the channel, and again after a
//! restore, tinyvmm negotiates versions and sends a SYNC, which the guest sets
//! its clock to at once. Then it sends a SAMPLE every 5 seconds, which the guest
//! applies only once it has fallen 5 s behind and `hv_utils.timesync_implicit=1`
//! asks it to (after the host slept, say), and which otherwise keeps its
//! "hyperv" PTP clock fresh. Each message pairs the host's UTC with the
//! partition reference time read alongside it, so the guest adds the time the
//! message took to reach it. Like OpenVMM's, it keeps no state in a snapshot.

use super::ic::{self, Version};
use super::protocol::guid;
use super::{Channel, Device};
use crate::whp::partition::reference_time;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::System::Hypervisor::WHV_PARTITION_HANDLE;

pub const INTERFACE: [u8; 16] = guid(
    0x9527e630,
    0xd0ae,
    0x497b,
    [0xad, 0xce, 0xe8, 0x0a, 0xb0, 0x17, 0x5c, 0xaf],
);
/// The instance OpenVMM and Hyper-V offer.
pub const INSTANCE: [u8; 16] = guid(
    0x2dd1ce17,
    0x079e,
    0x403c,
    [0xb3, 0x52, 0xa1, 0x92, 0x1e, 0xe2, 0x07, 0xee],
);
/// Version 4.0 pairs the host's time with the guest's reference time.
const VERSION_4: Version = (4, 0);
const SAMPLE_PERIOD: Duration = Duration::from_secs(5);
const FLAG_SYNC: u8 = 1;
const FLAG_SAMPLE: u8 = 2;
/// The 100 ns intervals from 1601-01-01, the epoch of the host's time in a
/// message, to 1970-01-01.
const UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
/// The largest packet the guest sends back: one of tinyvmm's, answered.
const MAX_PACKET: usize = 256;

/// The host's UTC in 100 ns units since 1601, and the partition reference time
/// read with it.
pub type Clock = Box<dyn Fn() -> Option<(u64, u64)> + Send + Sync>;

/// The host's UTC in 100 ns units since 1601.
fn host_time() -> u64 {
    let since_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    UNIX_EPOCH_100NS + (since_unix.as_nanos() / 100) as u64
}

/// [`Clock`] for a partition: reads its reference time between two reads of
/// the host's time and pairs it with their midpoint.
pub fn partition_clock(part: WHV_PARTITION_HANDLE) -> Clock {
    Box::new(move || {
        let before = host_time();
        let reference = reference_time(part).ok()?;
        let after = host_time();
        Some((before / 2 + after / 2, reference))
    })
}

/// A time message: the host's time, the reference time, the flags, then the
/// leap indicator, stratum and reserved bytes, all zero.
fn time_message(versions: (Version, Version), flags: u8, (host, reference): (u64, u64)) -> Vec<u8> {
    let mut body = Vec::with_capacity(24);
    body.extend(host.to_le_bytes());
    body.extend(reference.to_le_bytes());
    body.push(flags);
    body.extend([0u8; 7]);
    ic::request(ic::TYPE_TIMESYNC, versions, &body)
}

#[derive(Default)]
struct State {
    channel: Option<Channel>,
    /// Counts opens and closes, so the thread notices each.
    generation: u64,
    signaled: bool,
    stop: bool,
}

struct Shared {
    state: Mutex<State>,
    wake: Condvar,
    clock: Clock,
}

pub struct Timesync {
    shared: Arc<Shared>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl Timesync {
    pub fn new(clock: Clock) -> Arc<Self> {
        let shared = Arc::new(Shared {
            state: Mutex::default(),
            wake: Condvar::new(),
            clock,
        });
        let thread = {
            let shared = shared.clone();
            std::thread::Builder::new()
                .name("vmbus-timesync".into())
                .spawn(move || run(&shared))
                .expect("spawn the time-sync thread")
        };
        Arc::new(Timesync {
            shared,
            thread: Mutex::new(Some(thread)),
        })
    }

    fn update(&self, f: impl FnOnce(&mut State)) {
        f(&mut self.shared.state.lock().unwrap());
        self.shared.wake.notify_one();
    }
}

impl Device for Timesync {
    fn interface(&self) -> [u8; 16] {
        INTERFACE
    }

    fn instance(&self) -> [u8; 16] {
        INSTANCE
    }

    fn open(&self, channel: Channel) {
        self.update(|s| {
            s.channel = Some(channel);
            s.generation += 1;
        });
    }

    fn close(&self) {
        self.update(|s| {
            s.channel = None;
            s.generation += 1;
        });
    }

    fn signal(&self) {
        self.update(|s| s.signaled = true);
    }

    fn stop(&self) {
        self.update(|s| s.stop = true);
        if let Some(t) = self.thread.lock().unwrap().take() {
            let _ = t.join();
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// No channel, or a guest that takes no version of ours.
    Idle,
    /// Just opened: negotiate.
    Start,
    Negotiating,
    Ready {
        versions: (Version, Version),
        next_sample: Instant,
    },
}

fn run(shared: &Shared) {
    let mut generation = 0;
    let mut channel = None;
    let mut phase = Phase::Idle;
    let mut buf = Vec::with_capacity(MAX_PACKET);
    loop {
        {
            let mut s = shared.state.lock().unwrap();
            loop {
                if s.stop {
                    return;
                }
                if s.generation != generation {
                    generation = s.generation;
                    channel = s.channel.clone();
                    phase = if channel.is_some() {
                        Phase::Start
                    } else {
                        Phase::Idle
                    };
                    break;
                }
                if std::mem::take(&mut s.signaled) {
                    break;
                }
                let wait = match phase {
                    Phase::Ready { next_sample, .. } => {
                        next_sample.saturating_duration_since(Instant::now())
                    }
                    // The guest signals its answer; look anyway now and then,
                    // so a lost signal can't strand the negotiation.
                    Phase::Negotiating => Duration::from_secs(1),
                    _ => Duration::from_secs(3600),
                };
                if wait.is_zero() {
                    break;
                }
                s = shared.wake.wait_timeout(s, wait).unwrap().0;
            }
        }
        if let Some(channel) = &channel {
            phase = step(channel, phase, &shared.clock, &mut buf);
        }
    }
}

/// Advance the protocol on `channel`: negotiate when just opened, answer the
/// negotiation with a SYNC, and send each SAMPLE when due.
fn step(channel: &Channel, mut phase: Phase, clock: &Clock, buf: &mut Vec<u8>) -> Phase {
    if phase == Phase::Start {
        return if channel.send(&ic::negotiate(&[VERSION_4])) {
            Phase::Negotiating
        } else {
            Phase::Idle
        };
    }
    let negotiating = phase == Phase::Negotiating;
    // The guest's packets: the negotiation's answer, then acknowledgments of
    // time messages, which need nothing.
    loop {
        match channel.recv(buf, MAX_PACKET) {
            Ok(true) => {}
            Ok(false) => break,
            Err(_) => return Phase::Idle,
        }
        if phase != Phase::Negotiating {
            continue;
        }
        let Some((ic::TYPE_NEGOTIATE, body)) = ic::response(buf) else {
            continue;
        };
        phase = match ic::negotiated(body) {
            Some(versions) if versions.1 == VERSION_4 => {
                send_time(channel, versions, FLAG_SYNC, clock);
                Phase::Ready {
                    versions,
                    next_sample: Instant::now() + SAMPLE_PERIOD,
                }
            }
            _ => {
                eprintln!("[timesync] the guest takes no time-sync version tinyvmm speaks");
                Phase::Idle
            }
        };
    }
    // Still no answer: in case the guest missed the signal, signal again.
    if negotiating && phase == Phase::Negotiating {
        channel.notify();
    }
    if let Phase::Ready {
        versions,
        next_sample,
    } = &mut phase
        && Instant::now() >= *next_sample
    {
        send_time(channel, *versions, FLAG_SAMPLE, clock);
        *next_sample = Instant::now() + SAMPLE_PERIOD;
    }
    phase
}

fn send_time(channel: &Channel, versions: (Version, Version), flags: u8, clock: &Clock) {
    if let Some(now) = clock() {
        channel.send(&time_message(versions, flags, now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vmbus::protocol::{u16_at, u64_at};

    #[test]
    fn time_messages_carry_the_host_time_and_the_reference_time() {
        let m = time_message(((3, 0), (4, 0)), FLAG_SYNC, (0x1122_3344_5566_7788, 42));
        let (kind, body) = (u16_at(&m, 12), &m[ic::BODY..]);
        assert_eq!(kind, Some(ic::TYPE_TIMESYNC));
        // Linux's ictimesync_ref_data: parenttime, vmreferencetime, flags.
        assert_eq!(body.len(), 24);
        assert_eq!(u64_at(body, 0), Some(0x1122_3344_5566_7788));
        assert_eq!(u64_at(body, 8), Some(42));
        assert_eq!(body[16], FLAG_SYNC);
        assert_eq!(&body[17..], &[0; 7]);
    }

    #[test]
    fn host_time_counts_from_1601() {
        // 2020-01-01T00:00:00Z as a Windows FILETIME.
        const Y2020: u64 = 132_223_104_000_000_000;
        let now = host_time();
        assert!(now > Y2020 && now < Y2020 + 100 * 365 * 86_400 * 10_000_000);
    }
}
