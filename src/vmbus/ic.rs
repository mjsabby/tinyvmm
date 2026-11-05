//! Hyper-V integration components (ICs; Linux's `hv_utils`): small services
//! offered as message-mode VMBus pipes. A message is a pipe header, an IC
//! header and a body. Every exchange is a transaction the host starts and the
//! guest answers in place, flipping the request flag to a response; the first
//! one negotiates the framework and message versions.
//!
//! [`Runner`] does what every IC shares: a thread that negotiates each time the
//! guest opens the channel, reads the guest's answers, and hands the service
//! [`Event`]s, so a service is only its own messages.

use super::protocol::{u16_at, u32_at};
use super::{Channel, Device};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// A version: major, minor.
pub type Version = (u16, u16);
/// The negotiated framework and message versions.
pub type Versions = (Version, Version);
/// The framework version; Linux takes 3.0 or 1.0 and prefers 3.0.
pub const FRAMEWORK: Version = (3, 0);
pub const TYPE_NEGOTIATE: u16 = 0;
pub const TYPE_SHUTDOWN: u16 = 3;
pub const TYPE_TIMESYNC: u16 = 4;
/// The guest's answer to a request it carried out.
pub const HV_S_OK: u32 = 0;
const FLAG_TRANSACTION: u8 = 1;
const FLAG_REQUEST: u8 = 2;
const FLAG_RESPONSE: u8 = 4;
/// The pipe header's packet type for data.
const PIPE_DATA: u32 = 1;
const PIPE_HEADER_LEN: usize = 8;
const HEADER_LEN: usize = 20;
/// Where the body starts.
pub const BODY: usize = PIPE_HEADER_LEN + HEADER_LEN;
/// The largest packet a guest's IC driver sends: Linux's buffer is a page.
const MAX_PACKET: usize = 4096;
/// How often to look for a negotiation answer whose signal went missing.
const NEGOTIATE_POLL: Duration = Duration::from_secs(1);
/// How long an idle runner sleeps between looks at its state.
const IDLE_WAIT: Duration = Duration::from_secs(3600);

fn put_version(m: &mut Vec<u8>, (major, minor): Version) {
    m.extend(major.to_le_bytes());
    m.extend(minor.to_le_bytes());
}

/// A request of type `kind` at `versions` (framework, message) with `body`.
pub fn request(kind: u16, versions: Versions, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(BODY + body.len());
    m.extend(PIPE_DATA.to_le_bytes());
    m.extend(((HEADER_LEN + body.len()) as u32).to_le_bytes());
    put_version(&mut m, versions.0);
    m.extend(kind.to_le_bytes());
    put_version(&mut m, versions.1);
    m.extend((body.len() as u16).to_le_bytes());
    m.extend(0u32.to_le_bytes()); // status
    m.push(0); // transaction ID
    m.push(FLAG_TRANSACTION | FLAG_REQUEST);
    m.extend([0, 0]);
    m.extend(body);
    m
}

/// The version negotiation request: [`FRAMEWORK`] and `versions` of the
/// service's own protocol.
pub fn negotiate(versions: &[Version]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(1u16.to_le_bytes()); // framework versions
    body.extend((versions.len() as u16).to_le_bytes());
    body.extend(0u32.to_le_bytes());
    put_version(&mut body, FRAMEWORK);
    for &v in versions {
        put_version(&mut body, v);
    }
    request(TYPE_NEGOTIATE, ((0, 0), (0, 0)), &body)
}

/// A response from the guest.
#[derive(Debug, PartialEq, Eq)]
pub struct Response<'a> {
    /// The message type of the request it answers.
    pub kind: u16,
    /// [`HV_S_OK`], or an HRESULT for a request the guest refused.
    pub status: u32,
    pub body: &'a [u8],
}

/// The response in `packet`; None for anything else.
pub fn response(packet: &[u8]) -> Option<Response<'_>> {
    if u32_at(packet, 0)? != PIPE_DATA || packet.get(PIPE_HEADER_LEN + 17)? & FLAG_RESPONSE == 0 {
        return None;
    }
    let kind = u16_at(packet, PIPE_HEADER_LEN + 4)?;
    let size = usize::from(u16_at(packet, PIPE_HEADER_LEN + 10)?);
    let status = u32_at(packet, PIPE_HEADER_LEN + 12)?;
    let body = packet.get(BODY..)?;
    Some(Response {
        kind,
        status,
        body: &body[..size.min(body.len())],
    })
}

/// The framework and service versions a negotiation response settled on, or
/// None if the guest takes none of those offered.
pub fn negotiated(body: &[u8]) -> Option<Versions> {
    if u16_at(body, 0)? != 1 || u16_at(body, 2)? != 1 {
        return None;
    }
    let version = |at| Some((u16_at(body, at)?, u16_at(body, at + 2)?));
    Some((version(8)?, version(12)?))
}

/// An integration component's own protocol, which a [`Runner`] runs.
pub trait Service: Send + 'static {
    /// Names its thread and its log lines.
    const NAME: &'static str;
    const INTERFACE: [u8; 16];
    const INSTANCE: [u8; 16];
    /// The versions of its messages it speaks, preferred first.
    const VERSIONS: &'static [Version];
    /// The guest opened the channel and took `versions`: start sending.
    fn ready(&mut self, channel: &Channel, versions: Versions);
    /// The guest answered one of the service's requests.
    fn response(&mut self, channel: &Channel, response: Response<'_>);
    /// Ends every pass while the channel is up: when the guest signals, when
    /// [`Runner::wake`] is called, and when the time this last returned comes.
    /// Returns when to tick next, if ever.
    fn tick(&mut self, channel: &Channel) -> Option<Instant>;
    /// The channel closed or broke, or the bus stopped: send nothing until the
    /// next `ready`.
    fn down(&mut self);
}

/// The bus device that runs a [`Service`] on a thread of its own. Each time
/// the guest opens the channel, it negotiates the service's versions and, once
/// the guest takes one, reads the guest's answers and passes them on.
pub struct Runner {
    interface: [u8; 16],
    instance: [u8; 16],
    shared: Arc<RunShared>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Default)]
struct RunState {
    channel: Option<Channel>,
    /// Counts opens and closes, so the thread notices each.
    generation: u64,
    woken: bool,
    stop: bool,
}

#[derive(Default)]
struct RunShared {
    state: Mutex<RunState>,
    wake: Condvar,
}

/// Why the thread woke.
enum Wake {
    Stop,
    /// The guest opened the channel (Some) or closed it.
    Reopen(Option<Channel>),
    Pass,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// No channel, or one the thread gave up on.
    Idle,
    Negotiating,
    Ready,
}

impl Runner {
    pub fn spawn<S: Service>(service: S) -> Arc<Runner> {
        let shared = Arc::new(RunShared::default());
        let thread = {
            let shared = shared.clone();
            std::thread::Builder::new()
                .name(format!("vmbus-{}", S::NAME))
                .spawn(move || run(&shared, service))
                .expect("spawn an integration component's thread")
        };
        Arc::new(Runner {
            interface: S::INTERFACE,
            instance: S::INSTANCE,
            shared,
            thread: Mutex::new(Some(thread)),
        })
    }

    fn update(&self, f: impl FnOnce(&mut RunState)) {
        f(&mut self.shared.state.lock().unwrap());
        self.shared.wake.notify_one();
    }

    /// Run a pass, ending with a tick: the service has work.
    pub fn wake(&self) {
        self.update(|s| s.woken = true);
    }
}

impl Device for Runner {
    fn interface(&self) -> [u8; 16] {
        self.interface
    }

    fn instance(&self) -> [u8; 16] {
        self.instance
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
        self.wake();
    }

    fn stop(&self) {
        self.update(|s| s.stop = true);
        if let Some(t) = self.thread.lock().unwrap().take() {
            let _ = t.join();
        }
    }
}

impl RunShared {
    /// Wait until there's something to do, or `deadline`.
    fn wait(&self, generation: &mut u64, deadline: Option<Instant>) -> Wake {
        let mut s = self.state.lock().unwrap();
        loop {
            if s.stop {
                return Wake::Stop;
            }
            if s.generation != *generation {
                *generation = s.generation;
                return Wake::Reopen(s.channel.clone());
            }
            let left = deadline.map_or(IDLE_WAIT, |t| t.saturating_duration_since(Instant::now()));
            if std::mem::take(&mut s.woken) || left.is_zero() {
                return Wake::Pass;
            }
            s = self.wake.wait_timeout(s, left).unwrap().0;
        }
    }
}

fn run<S: Service>(shared: &RunShared, mut service: S) {
    let mut generation = 0;
    let mut channel = None;
    let mut phase = Phase::Idle;
    let mut deadline = None;
    let mut buf = Vec::with_capacity(MAX_PACKET);
    loop {
        let wake = shared.wait(&mut generation, deadline);
        if !matches!(wake, Wake::Pass) && phase == Phase::Ready {
            service.down();
        }
        match wake {
            Wake::Stop => return,
            Wake::Reopen(ch) => {
                channel = ch;
                phase = match &channel {
                    Some(ch) if ch.send(&negotiate(S::VERSIONS)) => Phase::Negotiating,
                    _ => Phase::Idle,
                };
                deadline = (phase == Phase::Negotiating).then(|| Instant::now() + NEGOTIATE_POLL);
            }
            Wake::Pass => {
                if let Some(ch) = channel.as_ref().filter(|_| phase != Phase::Idle) {
                    (phase, deadline) = pass(&mut service, ch, phase, &mut buf);
                }
            }
        }
    }
}

/// Take what the guest sent, then tick; returns the new phase and when to
/// look again.
fn pass<S: Service>(
    service: &mut S,
    ch: &Channel,
    mut phase: Phase,
    buf: &mut Vec<u8>,
) -> (Phase, Option<Instant>) {
    loop {
        match ch.recv(buf, MAX_PACKET) {
            Ok(true) => {}
            Ok(false) => break,
            Err(_) => {
                eprintln!(
                    "[vmbus] {}: the guest's ring is broken; giving up on the channel",
                    S::NAME
                );
                if phase == Phase::Ready {
                    service.down();
                }
                return (Phase::Idle, None);
            }
        }
        let Some(r) = response(buf) else {
            continue;
        };
        match phase {
            Phase::Negotiating if r.kind == TYPE_NEGOTIATE => {
                let offered = |&(framework, version): &Versions| {
                    framework == FRAMEWORK && S::VERSIONS.contains(&version)
                };
                let Some(versions) = negotiated(r.body).filter(offered) else {
                    eprintln!(
                        "[vmbus] {}: the guest takes no version tinyvmm speaks",
                        S::NAME
                    );
                    return (Phase::Idle, None);
                };
                phase = Phase::Ready;
                service.ready(ch, versions);
            }
            Phase::Ready => service.response(ch, r),
            _ => {}
        }
    }
    if phase == Phase::Ready {
        return (phase, service.tick(ch));
    }
    // Still no answer: in case the guest missed the signal, signal again.
    ch.notify();
    (phase, Some(Instant::now() + NEGOTIATE_POLL))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::vmbus::ring::Ring;
    use crate::whp::GuestMemory;

    /// The guest's end of a [`channel`].
    pub struct Guest {
        mem: Arc<GuestMemory>,
        to_host: Ring,
        to_guest: Ring,
    }

    /// A channel in host memory, with the guest's end of it. The guest masks
    /// its interrupts, so the host never signals it.
    pub fn channel() -> (Channel, Guest) {
        let mem = Arc::new(GuestMemory::new_host_only(8 * 4096).unwrap());
        let to_host = Ring::new(&[1, 2, 3]).unwrap();
        let to_guest = Ring::new(&[4, 5, 6]).unwrap();
        assert!(mem.store_release_u32(4 * 4096 + 8, 1), "interrupt mask");
        let ch = Channel {
            mem: mem.clone(),
            part: 0,
            relid: 1,
            target_vp: Arc::default(),
            incoming: to_host.clone(),
            outgoing: to_guest.clone(),
        };
        (
            ch,
            Guest {
                mem,
                to_host,
                to_guest,
            },
        )
    }

    impl Guest {
        /// Wait for the host's next packet.
        pub fn recv(&self) -> Vec<u8> {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut buf = Vec::new();
            while self
                .to_guest
                .read(&self.mem, &mut buf, 8192)
                .unwrap()
                .is_none()
            {
                assert!(Instant::now() < deadline, "the host sent nothing");
                std::thread::sleep(Duration::from_millis(1));
            }
            buf
        }

        pub fn send(&self, packet: &[u8]) {
            self.to_host.write(&self.mem, packet).unwrap();
        }
    }

    /// What Linux's `vmbus_prep_negotiate_resp` does to a negotiation request
    /// it receives, for a guest taking `framework` and `service`: picks the
    /// versions in place and turns the request into a response.
    pub fn guest_answers(request: &mut [u8], framework: Version, service: Version) {
        let neg = BODY;
        let frameworks = usize::from(u16_at(request, neg).unwrap());
        let services = usize::from(u16_at(request, neg + 2).unwrap());
        let at = |i: usize| {
            (
                u16_at(request, neg + 8 + 4 * i),
                u16_at(request, neg + 10 + 4 * i),
            )
        };
        let has = |range: std::ops::Range<usize>, (major, minor): Version| {
            range
                .into_iter()
                .any(|i| at(i) == (Some(major), Some(minor)))
        };
        let found =
            has(0..frameworks, framework) && has(frameworks..frameworks + services, service);
        request[PIPE_HEADER_LEN + 10..PIPE_HEADER_LEN + 12].copy_from_slice(&16u16.to_le_bytes());
        let count = u16::from(found).to_le_bytes();
        request[neg..neg + 2].copy_from_slice(&count);
        request[neg + 2..neg + 4].copy_from_slice(&count);
        for (i, (major, minor)) in [framework, service].into_iter().enumerate() {
            let v = neg + 8 + 4 * i;
            request[v..v + 2].copy_from_slice(&major.to_le_bytes());
            request[v + 2..v + 4].copy_from_slice(&minor.to_le_bytes());
        }
        request[PIPE_HEADER_LEN + 17] = FLAG_TRANSACTION | FLAG_RESPONSE;
    }

    #[test]
    fn a_negotiation_settles_on_the_versions_both_sides_take() {
        let mut m = negotiate(&[(4, 0)]);
        assert_eq!(response(&m), None, "a request isn't a response");
        guest_answers(&mut m, (3, 0), (4, 0));
        let r = response(&m).unwrap();
        assert_eq!((r.kind, r.status), (TYPE_NEGOTIATE, HV_S_OK));
        assert_eq!(negotiated(r.body), Some(((3, 0), (4, 0))));

        let mut m = negotiate(&[(4, 0)]);
        guest_answers(&mut m, (3, 0), (3, 0));
        assert_eq!(negotiated(response(&m).unwrap().body), None);
    }

    #[test]
    fn requests_carry_their_header_fields() {
        let m = request(TYPE_TIMESYNC, ((3, 0), (4, 0)), &[0xAA; 24]);
        assert_eq!(m.len(), BODY + 24);
        assert_eq!(u32_at(&m, 0), Some(PIPE_DATA));
        assert_eq!(
            u32_at(&m, 4),
            Some(20 + 24),
            "pipe payload: IC header + body"
        );
        assert_eq!(u16_at(&m, 8), Some(3), "framework major");
        assert_eq!(u16_at(&m, 12), Some(TYPE_TIMESYNC));
        assert_eq!(u16_at(&m, 14), Some(4), "message major");
        assert_eq!(u16_at(&m, 18), Some(24), "icmsgsize");
        assert_eq!(m[25], FLAG_TRANSACTION | FLAG_REQUEST);
    }
}
