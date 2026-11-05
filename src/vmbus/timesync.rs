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

use super::ic::{self, Response, Runner, Service, Version, Versions};
use super::protocol::guid;
use super::{Channel, Device};
use crate::whp::partition::reference_time;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::System::Hypervisor::WHV_PARTITION_HANDLE;

const INTERFACE: [u8; 16] = guid(
    0x9527e630,
    0xd0ae,
    0x497b,
    [0xad, 0xce, 0xe8, 0x0a, 0xb0, 0x17, 0x5c, 0xaf],
);
/// The instance OpenVMM and Hyper-V offer.
const INSTANCE: [u8; 16] = guid(
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
fn time_message(versions: Versions, flags: u8, (host, reference): (u64, u64)) -> Vec<u8> {
    let mut body = Vec::with_capacity(24);
    body.extend(host.to_le_bytes());
    body.extend(reference.to_le_bytes());
    body.push(flags);
    body.extend([0u8; 7]);
    ic::request(ic::TYPE_TIMESYNC, versions, &body)
}

/// Builds the bus device.
pub fn new(clock: Clock) -> Arc<dyn Device> {
    Runner::spawn(Timesync { clock, ready: None })
}

struct Timesync {
    clock: Clock,
    /// The versions the guest took, and when the next SAMPLE is due.
    ready: Option<(Versions, Instant)>,
}

impl Timesync {
    fn send(&self, channel: &Channel, versions: Versions, flags: u8) {
        if let Some(now) = (self.clock)() {
            channel.send(&time_message(versions, flags, now));
        }
    }
}

impl Service for Timesync {
    const NAME: &'static str = "timesync";
    const INTERFACE: [u8; 16] = INTERFACE;
    const INSTANCE: [u8; 16] = INSTANCE;
    const VERSIONS: &'static [Version] = &[VERSION_4];

    fn ready(&mut self, channel: &Channel, versions: Versions) {
        self.send(channel, versions, FLAG_SYNC);
        self.ready = Some((versions, Instant::now() + SAMPLE_PERIOD));
    }

    /// The guest acknowledges each time message; that needs nothing.
    fn response(&mut self, _: &Channel, _: Response<'_>) {}

    fn tick(&mut self, channel: &Channel) -> Option<Instant> {
        let (versions, due) = self.ready?;
        if Instant::now() < due {
            return Some(due);
        }
        self.send(channel, versions, FLAG_SAMPLE);
        let next = Instant::now() + SAMPLE_PERIOD;
        self.ready = Some((versions, next));
        Some(next)
    }

    fn down(&mut self) {
        self.ready = None;
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
