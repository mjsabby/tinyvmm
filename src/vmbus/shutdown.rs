//! The shutdown integration component: how Hyper-V asks a guest to shut down
//! cleanly, as `Stop-VM` does. The guest's `hv_utils` answers at once, then
//! starts the kernel's orderly power-off, which runs
//! `/proc/sys/kernel/poweroff_cmd` (tinyinit points it at its own `poweroff`)
//! and powers off through ACPI once the guest's programs are stopped. Like
//! OpenVMM's, it keeps no state in a snapshot: a request in flight when one is
//! taken goes unanswered, and whoever asked gives up.

use super::ic::{self, Response, Runner, Service, Version, Versions};
use super::protocol::guid;
use super::{Channel, Device};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const INTERFACE: [u8; 16] = guid(
    0x0e0b6031,
    0x5213,
    0x4934,
    [0x81, 0x8b, 0x38, 0xd9, 0x0c, 0xed, 0x39, 0xdb],
);
/// The instance OpenVMM and Hyper-V offer.
const INSTANCE: [u8; 16] = guid(
    0xb6650ff7,
    0x33bc,
    0x4840,
    [0x80, 0x48, 0xe0, 0x67, 0x67, 0x86, 0xf3, 0x93],
);
/// `SHTDN_REASON_FLAG_PLANNED`, the reason OpenVMM gives.
const REASON_PLANNED: u32 = 0x8000_0000;
/// Linux's `shutdown_msg_data`: the reason, a timeout in seconds, the flags
/// (0 shuts down; Linux also takes restart and hibernate), and a message to
/// show of 2048 bytes. Linux ignores a shorter one.
const MESSAGE_LEN: usize = 12 + 2048;

/// The shutdown request: the reason, then all zeros, which shuts down at once
/// with no message.
fn message(versions: Versions) -> Vec<u8> {
    let mut body = Vec::with_capacity(MESSAGE_LEN);
    body.extend(REASON_PLANNED.to_le_bytes());
    body.resize(MESSAGE_LEN, 0);
    ic::request(ic::TYPE_SHUTDOWN, versions, &body)
}

/// Asks the guest to shut down; see [`Shutdown::request`].
#[derive(Clone)]
pub struct Shutdown {
    runner: Arc<Runner>,
    shared: Arc<Shared>,
}

/// The bus device, and the handle that asks through it.
pub fn new() -> (Arc<dyn Device>, Shutdown) {
    let shared = Arc::new(Shared::default());
    let runner = Runner::spawn(Ic(shared.clone()));
    (runner.clone(), Shutdown { runner, shared })
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    answered: Condvar,
}

#[derive(Default)]
struct State {
    /// The versions the guest took, while it has the channel open.
    versions: Option<Versions>,
    ask: Ask,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Ask {
    #[default]
    None,
    /// Send the request at the next tick.
    Wanted,
    /// Sent; awaiting the guest's answer.
    Sent,
    /// Whether the guest took it.
    Answered(bool),
}

impl Shutdown {
    /// Ask the guest to shut down, one asker at a time, and wait up to
    /// `timeout` for its answer: whether it took the request. False at once if
    /// it hasn't opened the channel: it is still booting, or its kernel has no
    /// `hv_utils`.
    pub fn request(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        {
            let mut s = self.shared.state.lock().unwrap();
            if s.versions.is_none() {
                return false;
            }
            s.ask = Ask::Wanted;
        }
        self.runner.wake();
        let mut s = self.shared.state.lock().unwrap();
        let took = loop {
            if let Ask::Answered(took) = s.ask {
                break took;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break false;
            }
            s = self.shared.answered.wait_timeout(s, left).unwrap().0;
        };
        s.ask = Ask::None;
        took
    }
}

/// The service, on the runner's thread.
struct Ic(Arc<Shared>);

impl Ic {
    fn answer(&self, s: &mut State, took: bool) {
        s.ask = Ask::Answered(took);
        self.0.answered.notify_all();
    }
}

impl Service for Ic {
    const NAME: &'static str = "shutdown";
    const INTERFACE: [u8; 16] = INTERFACE;
    const INSTANCE: [u8; 16] = INSTANCE;
    /// The versions Linux and OpenVMM speak; the message is the same in each.
    const VERSIONS: &'static [Version] = &[(3, 2), (3, 1), (3, 0), (1, 0)];

    fn ready(&mut self, _: &Channel, versions: Versions) {
        self.0.state.lock().unwrap().versions = Some(versions);
    }

    fn response(&mut self, _: &Channel, r: Response<'_>) {
        let mut s = self.0.state.lock().unwrap();
        if r.kind == ic::TYPE_SHUTDOWN && s.ask == Ask::Sent {
            self.answer(&mut s, r.status == ic::HV_S_OK);
        }
    }

    fn tick(&mut self, channel: &Channel) -> Option<Instant> {
        let mut s = self.0.state.lock().unwrap();
        if let (Ask::Wanted, Some(versions)) = (s.ask, s.versions) {
            if channel.send(&message(versions)) {
                s.ask = Ask::Sent;
            } else {
                self.answer(&mut s, false);
            }
        }
        None
    }

    fn down(&mut self) {
        let mut s = self.0.state.lock().unwrap();
        s.versions = None;
        if matches!(s.ask, Ask::Wanted | Ask::Sent) {
            self.answer(&mut s, false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vmbus::ic::tests::{Guest, channel, guest_answers};
    use crate::vmbus::protocol::{u16_at, u32_at};
    use std::thread;

    /// The IC on a channel the guest opened, at the version Linux takes.
    fn connected() -> (Arc<dyn Device>, Shutdown, Guest) {
        let (device, shutdown) = new();
        let (ch, guest) = channel();
        device.open(ch);
        let mut m = guest.recv();
        guest_answers(&mut m, (3, 0), (3, 2));
        guest.send(&m);
        device.signal();
        let deadline = Instant::now() + Duration::from_secs(5);
        while shutdown.shared.state.lock().unwrap().versions.is_none() {
            assert!(Instant::now() < deadline, "the IC never got ready");
            thread::sleep(Duration::from_millis(1));
        }
        (device, shutdown, guest)
    }

    fn ask(shutdown: &Shutdown) -> thread::JoinHandle<bool> {
        let shutdown = shutdown.clone();
        thread::spawn(move || shutdown.request(Duration::from_secs(30)))
    }

    #[test]
    fn the_guest_is_asked_to_shut_down_and_its_answer_returned() {
        let (device, shutdown, guest) = connected();
        for (status, took) in [(ic::HV_S_OK, true), (0x8000_4005, false)] {
            let asker = ask(&shutdown);
            let mut m = guest.recv();
            assert_eq!(
                m.len(),
                8 + 20 + 2060,
                "Linux needs the whole shutdown_msg_data"
            );
            assert_eq!(u16_at(&m, 12), Some(ic::TYPE_SHUTDOWN));
            assert_eq!((u16_at(&m, 14), u16_at(&m, 16)), (Some(3), Some(2)));
            assert_eq!(u32_at(&m, ic::BODY), Some(REASON_PLANNED));
            assert!(
                m[ic::BODY + 4..].iter().all(|&b| b == 0),
                "no timeout, flags 0 (shut down), no message"
            );
            // What Linux's shutdown_onchannelcallback does: answer in place.
            m[20..24].copy_from_slice(&status.to_le_bytes());
            m[25] = 1 | 4; // transaction, response
            guest.send(&m);
            device.signal();
            assert_eq!(asker.join().unwrap(), took);
        }
        device.stop();
    }

    #[test]
    fn nothing_waits_on_a_guest_without_the_channel() {
        let (device, shutdown) = new();
        assert!(!shutdown.request(Duration::from_secs(30)), "never opened");
        device.stop();

        let (device, shutdown, guest) = connected();
        let start = Instant::now();
        let asker = ask(&shutdown);
        guest.recv();
        device.close();
        assert!(!asker.join().unwrap(), "closed before answering");
        assert!(start.elapsed() < Duration::from_secs(10), "and at once");
        assert!(!shutdown.request(Duration::from_secs(30)), "closed");
        device.stop();
    }
}
