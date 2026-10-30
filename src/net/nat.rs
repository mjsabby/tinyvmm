//! Slirp-style user-mode NAT backend for virtio-net. Terminates the guest's
//! L2/L3 inside tinyvmm and translates flows to Windows host sockets via IOCP.
//!
//! Topology (matching the initramfs): gateway 10.0.0.1, guest 10.0.0.2.
//!
//! Concurrency model (per the agreed design): a single precreated worker
//! thread owns ALL NAT state and the IOCP. The vCPU thread never touches NAT
//! state; `on_guest_frame` just copies the frame and posts it to the IOCP, so
//! the worker is the sole accessor of the flow tables (lock-free by
//! single-threading). Host socket completions arrive on the same IOCP.
//! Implemented: ARP, ICMP echo (local gateway reply + proxied via
//! `IcmpSendEcho`), UDP NAT, and TCP terminate-and-proxy (guest-facing TCB in
//! `tcp-sans-io`, host socket via `ConnectEx`), plus inbound `--portfwd`.

use crate::diag::etw;
use crate::host;
use crate::net::sys::{self, Iocp};
use crate::net::wire::*;
use crate::virtio::net::{
    HDR_F_NEEDS_CSUM, HDR_GSO_TCPV4, NetBackend, NetDevice, RxHeader, TX_FRAME_CAP, TxHeader,
    tx_offload_software,
};
use std::cell::UnsafeCell;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread::JoinHandle;
use std::time::Instant;
use tcp_sans_io::{Endpoint, State, Tcb, TcbConfig, TcbStats, TcpError};
use windows_sys::Win32::Networking::WinSock::{INVALID_SOCKET, SOCKET, WSABUF};
use windows_sys::Win32::System::IO::OVERLAPPED;

const KEY_FRAME: usize = 1;
const KEY_UDP: usize = 2;
const KEY_TCP: usize = 3;
const KEY_ICMP: usize = 4;
const KEY_ACCEPT: usize = 5;
/// Cap on accepted-but-undrained port-forward connections in flight to the
/// worker. A remote accept-flood is dropped past this rather than piling up host
/// sockets/memory unboundedly.
const MAX_ACCEPT_INFLIGHT: usize = 64;
/// Guest TX frame with offload metadata (partial L4 checksum and/or a TCPv4
/// super-segment): small-pool slot / big-pool slot respectively.
const KEY_FRAME_OFFLOAD: usize = 6;
const KEY_FRAME_OFFLOAD_BIG: usize = 7;
/// The NIC's RX backlog drained after the worker paused on it
/// (`NetDevice::rx_congested`): resume the paused flows.
const KEY_RX_SPACE: usize = 8;
const KEY_STOP: usize = 9;

const FRAME_CAP: usize = 2048;
/// Max coalesced TCP payload per GSO super-frame (just under 64 KiB so the IPv4
/// total-length field — u16, header included — doesn't overflow).
const GSO_PAYLOAD_CAP: usize = 65000;
const GSO_FRAME_CAP: usize = ETH_HDR + 60 + GSO_PAYLOAD_CAP;
const UDP_BUF: usize = 2048;
// Host-socket send buffer per overlapped op (one host send in flight per flow).
const TCP_BUF: usize = 65536;
// Most a host recv takes at once. Each WSARecv lands straight in the free
// space of the flow's TCB send ring (`Tcb::send_reserve`) and its completion
// drives one `tcp_drive` pass, so bigger recvs mean fewer syscalls, kernel
// wakeups, guest interrupts and drives per byte: 256 KiB carried ~11% more
// single-stream download than 64 KiB at ~11% less VMM CPU per byte. A pass
// still delivers at most GSO_PAYLOAD_CAP per super-frame.
const TCP_RECV_MAX: usize = 256 * 1024;
/// Least free send-ring space worth a recv (half the ring for smaller tiers),
/// so a nearly full ring refills in a few large recvs, not many small ones.
const TCP_RECV_MIN: usize = 64 * 1024;
const MAX_UDP_FLOWS: usize = 256;
const MAX_TCP_FLOWS: usize = 256;
/// Number of preallocated guest-TX frame slots shared across all shards.
const POOL_SLOTS: usize = 1024;
/// Slots for >`FRAME_CAP` TSO super-segments (each [`TX_FRAME_CAP`] bytes,
/// ~4 MiB total). When exhausted the frame is segmented in software into the
/// small pool instead of being dropped.
const BIG_POOL_SLOTS: usize = 64;
/// Free-list end marker for the frame pool.
const POOL_SENTINEL: u32 = u32::MAX;
/// Cap on the per-flow guest->host queue. When reached we stop draining the
/// tcb receive ring, which closes the guest-facing window (backpressure).
const TO_HOST_CAP: usize = 64 * 1024;
/// Fixed receive buffer for host sockets whose peer is this host. Windows'
/// receive-window autotuning keeps such sub-millisecond connections at a small
/// window, and the sender then stalls in ~15 ms steps: about 5.7 Gbps with ~40
/// stalls per 512 MiB, vs ~25 Gbps with none at a fixed 1 MiB. Remote peers
/// keep autotuning, since a fixed buffer would cap their window instead.
const LOCAL_PEER_RCVBUF: i32 = 1 << 20;

// ICMP echo proxy (guest pings to non-gateway hosts).
const ICMP_WORKERS: usize = 2; // precreated blocking IcmpSendEcho threads
const MAX_ICMP_INFLIGHT: usize = 16; // bound the handoff queue
const ICMP_TIMEOUT_MS: u32 = 4_000;

// Flow-lifecycle timeouts. A TCP flow the NAT gives up on is reset toward the
// guest, never dropped silently. The idle limits are RFC 5382's minimums
// (REQ-5): 2 h 4 min for an established connection, 4 min for a half-closed
// one.
const UDP_IDLE_MS: u64 = 60_000; // reap a UDP NAT entry idle this long
const TCP_CONNECT_MS: u64 = 10_000; // limit on the host connect, then on the guest handshake
const TCP_IDLE_MS: u64 = (2 * 60 + 4) * 60_000; // reset an established flow idle this long
const TCP_HALF_CLOSE_MS: u64 = 4 * 60_000; // reset a half-closed flow idle this long
const EXPIRE_GATE_MS: u64 = 1_000; // how often the idle sweep runs

// tcp-sans-io poll() event flags (mirror crate::tcb::events).
const EV_READABLE: u32 = 1 << 0;
const EV_PEER_CLOSED: u32 = 1 << 3;
const EV_CLOSED: u32 = 1 << 4;
const EV_ERROR: u32 = 1 << 6;

/// One inbound port-forward rule: a host TCP listener at `host_addr:host_port`
/// whose accepted clients are proxied to `guest_ip:guest_port` inside the
/// guest (the VMM originates a SYN toward the guest).
#[derive(Clone, Copy)]
pub struct PortForward {
    pub host_addr: [u8; 4],
    pub host_port: u16,
    pub guest_ip: [u8; 4],
    pub guest_port: u16,
}

pub struct NatOptions {
    pub gateway_ip: [u8; 4],
    pub gateway_mac: [u8; 6],
    pub port_forwards: Vec<PortForward>,
    /// Per-tier count of Tcbs to preallocate at startup (warm pool). Pools
    /// still grow on demand up to the flow cap and recycle thereafter, so this
    /// only governs cold-start latency, not the hard ceiling.
    pub tcb_warm: [usize; N_TCB_TIERS],
    /// Tier index assigned to a flow when no port override matches.
    pub default_tier: usize,
    /// Optional service-port → tier overrides (e.g. route known small-transfer
    /// ports to a smaller tier to save memory). Keyed by the destination port
    /// (outbound) / guest service port (inbound).
    pub tcb_port_tier: Vec<(u16, usize)>,
    /// Worker threads (shards), each with its own IOCP and the flows assigned
    /// to it (see `FlowRouter`); ARP, ICMP and other non-TCP/UDP traffic goes
    /// to the first. Clamped to 1..=MAX_WORKERS.
    pub workers: usize,
}

impl Default for NatOptions {
    fn default() -> Self {
        NatOptions {
            gateway_ip: [10, 0, 0, 1],
            gateway_mac: [0x02, 0x53, 0x54, 0x00, 0x00, 0x01],
            port_forwards: Vec::new(),
            tcb_warm: DEFAULT_TCB_WARM,
            default_tier: DEFAULT_TIER,
            tcb_port_tier: Vec::new(),
            workers: default_workers(),
        }
    }
}

/// Default NAT worker threads: a quarter of the host's logical CPUs, at most
/// four (where a 1-vCPU guest already saturates on 16 download streams) and
/// at least one.
pub fn default_workers() -> usize {
    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
    (cpus / 4).clamp(1, 4)
}

/// Most NAT worker threads `--nat-workers` accepts.
pub const MAX_WORKERS: usize = 16;

/// The shard that owns a flow. Guest frames are routed by it, and a shard
/// opening an inbound flow picks an ephemeral port whose key maps back to
/// itself, so every frame and completion of a flow reaches the one worker
/// that owns it.
fn shard_of(key: &FlowKey, shards: usize) -> usize {
    if shards <= 1 {
        return 0;
    }
    let (sip, sport, dip, dport) = *key;
    let mut x = (u64::from(u32::from_be_bytes(sip)) << 32 | u64::from(u32::from_be_bytes(dip)))
        ^ (u64::from(sport) << 16 | u64::from(dport)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    // splitmix64's finalizer: every input bit reaches every output bit.
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^= x >> 31;
    (x % shards as u64) as usize
}

/// The shard for a guest frame: by 4-tuple for unfragmented TCP and UDP over
/// IPv4, the first shard for everything else (ARP, ICMP, fragments). Returns
/// the TCP flow key and SYN flag too, for [`FlowRouter::route`]. Reads the
/// datagram as the worker does (within its total length), so a frame routed
/// as TCP here is the TCP segment the owning worker sees.
fn shard_of_frame(frame: &[u8], shards: usize) -> (usize, Option<(FlowKey, bool)>) {
    if shards <= 1 || frame.len() < ETH_HDR + 20 || frame[12..14] != [0x08, 0x00] {
        return (0, None);
    }
    let ip = &frame[ETH_HDR..];
    let total = usize::from(u16::from_be_bytes([ip[2], ip[3]])).min(ip.len());
    let ip = &ip[..total];
    if total < 20 {
        return (0, None);
    }
    let ihl = usize::from(ip[0] & 0x0F) * 4;
    let frag = u16::from_be_bytes([ip[6], ip[7]]) & 0x3FFF;
    if ip[0] >> 4 != 4
        || ihl < 20
        || ip.len() < ihl + 4
        || frag != 0
        || (ip[9] != IP_PROTO_TCP && ip[9] != IP_PROTO_UDP)
    {
        return (0, None);
    }
    let port = |o: usize| u16::from_be_bytes([ip[ihl + o], ip[ihl + o + 1]]);
    let src = [ip[12], ip[13], ip[14], ip[15]];
    let dst = [ip[16], ip[17], ip[18], ip[19]];
    let key = (src, port(0), dst, port(2));
    let tcp =
        (ip[9] == IP_PROTO_TCP && ip.len() >= ihl + 20).then(|| (key, ip[ihl + 13] & TCP_SYN != 0));
    (shard_of(&key, shards), tcp)
}

/// NAT-wide flow counts behind the MAX_*_FLOWS caps, shared by the shards. A
/// shard checks before it creates a flow, so concurrent shards can pass a cap
/// by at most one flow each.
#[derive(Default)]
struct FlowCounts {
    tcp: AtomicUsize,
    udp: AtomicUsize,
}

/// Which shard owns each TCP flow. Hashing a handful of bulk flows onto a few
/// shards leaves some workers with twice their share, so TCP flows are
/// assigned instead: the guest TX path gives a new outbound flow (its SYN)
/// to the shard with the fewest flows, a shard opening an inbound flow claims
/// its key, and the owning shard releases the key when the flow is gone.
/// Frames of unknown TCP flows, and all other traffic, are routed by hash.
struct FlowRouter {
    owner: std::sync::RwLock<HashMap<FlowKey, usize>>,
    /// TCP flows per shard.
    load: Box<[AtomicUsize]>,
}

impl FlowRouter {
    fn new(shards: usize) -> Self {
        FlowRouter {
            owner: std::sync::RwLock::new(HashMap::new()),
            load: (0..shards).map(|_| AtomicUsize::new(0)).collect(),
        }
    }

    /// The shard for a guest TCP frame, and whether this call assigned it (a
    /// SYN for a flow no shard owns: the shard creates a flow for any SYN).
    fn route(&self, key: &FlowKey, syn: bool) -> (usize, bool) {
        if let Some(&s) = self.owner.read().unwrap().get(key) {
            return (s, false);
        }
        if !syn {
            return (shard_of(key, self.load.len()), false);
        }
        let mut owner = self.owner.write().unwrap();
        if let Some(&s) = owner.get(key) {
            return (s, false);
        }
        let s = (0..self.load.len())
            .min_by_key(|&i| self.load[i].load(Ordering::Relaxed))
            .unwrap_or(0);
        owner.insert(*key, s);
        self.load[s].fetch_add(1, Ordering::Relaxed);
        (s, true)
    }

    /// Claim `key` for shard `s` (an inbound flow, or a flow `s` creates from
    /// a SYN): true if it was free or is already `s`'s.
    fn claim(&self, key: &FlowKey, s: usize) -> bool {
        let mut owner = self.owner.write().unwrap();
        match owner.get(key) {
            Some(&o) => o == s,
            None => {
                owner.insert(*key, s);
                self.load[s].fetch_add(1, Ordering::Relaxed);
                true
            }
        }
    }

    /// Shard `s` has no flow for `key` (reaped, refused, or its SYN never
    /// arrived): drop the entry if `s` still owns it.
    fn release(&self, key: &FlowKey, s: usize) {
        let mut owner = self.owner.write().unwrap();
        if owner.get(key) == Some(&s) {
            owner.remove(key);
            self.load[s].fetch_sub(1, Ordering::Relaxed);
        }
    }
}

// ---------------------------------------------------------------------------
// Tcb buffer tiers + preallocated control-plane object pools
// ---------------------------------------------------------------------------
//
// Per-flow / per-event objects (the Tcb, the overlapped op buffers, and the
// cross-thread accept/ICMP messages) are drawn from preallocated free-lists
// rather than `Box::new`-d per connection, so steady state is allocation-free
// (ArrayPool<T> semantics). The data plane was already alloc-free (FramePool +
// reused scratch buffers); this extends the same discipline to flow setup.
//
// Tcb ring sizes are COMPILE-TIME tiers (const-generic `Tcb<BUF>`); the WAN
// bandwidth-delay product is absorbed by the host kernel socket, so these
// rings only bridge the in-VMM guest leg. That leg is still window-bound: a
// guest upload can have at most one ring of unacknowledged data in flight,
// and under nested virtualization each round trip is ~0.4 ms (mostly the
// guest's ACK -> next-TX reaction), so 256 KiB rings cap uploads near 4 Gbps
// while 1 MiB reaches ~9 Gbps. Counts are RUNTIME pool config (see
// `NatOptions`). Sizes MUST be powers of two.

/// Number of compile-time Tcb ring-size tiers.
pub const N_TCB_TIERS: usize = 3;
/// The tier ring sizes, smallest first. Each is a power of two. Single source
/// of truth — `TIER_MAKE` builds one `Tcb<{TIER_BUF[i]}>` constructor per entry.
const TIER_BUF: [usize; N_TCB_TIERS] = [64 * 1024, 256 * 1024, 1024 * 1024];
/// Per-tier constructors (one monomorphization of `make_tcb` per size).
const TIER_MAKE: [fn() -> Box<dyn TcbDyn>; N_TCB_TIERS] = [
    make_tcb::<{ TIER_BUF[0] }>,
    make_tcb::<{ TIER_BUF[1] }>,
    make_tcb::<{ TIER_BUF[2] }>,
];
/// Default warm counts (cold-start preallocation; pools still grow on demand).
/// Most flows ride the default 1 MiB tier; the small/mid tiers are opt-in via
/// `tcb_port_tier`. Preallocated ring memory (two rings per Tcb):
/// 192 x 128 KiB + 8 x 512 KiB + 16 x 2 MiB = 60 MiB.
const DEFAULT_TCB_WARM: [usize; N_TCB_TIERS] = [192, 8, 16];
/// Default tier index (1 MiB) when no port override matches.
const DEFAULT_TIER: usize = 2;

/// Placeholder config a pooled Tcb is built with; `reinit` on acquire fully
/// overwrites it, so these values never reach the wire.
const TCB_PLACEHOLDER: TcbConfig = TcbConfig {
    local: Endpoint {
        ip: [0; 4],
        port: 0,
    },
    remote: Endpoint {
        ip: [0; 4],
        port: 0,
    },
    iss: 0,
    initial_rto_ms: 1000,
};

fn make_tcb<const BUF: usize>() -> Box<dyn TcbDyn> {
    Box::new(Tcb::<BUF>::new(TCB_PLACEHOLDER).expect("nat: Tcb pool allocation"))
}

/// The subset of `Tcb`'s API the NAT drives, made object-safe so a flow can
/// hold any compile-time ring size behind a single `Box<dyn TcbDyn>`. This is
/// a worker-local trait; the vtable indirection is irrelevant here (profiling
/// shows ~all CPU is the hypervisor + kernel I/O, not our code). The forwarding
/// bodies call the inherent `Tcb` methods — inherent methods win over trait
/// methods in resolution, so `self.method(..)` forwards rather than recurses.
trait TcbDyn {
    fn set_now(&mut self, now: u64);
    fn listen(&mut self) -> Result<(), TcpError>;
    fn connect(&mut self) -> Result<(), TcpError>;
    fn inject_packet(&mut self, pkt: &[u8]) -> Result<(), TcpError>;
    fn inject_packet_l4_csum_trusted(&mut self, pkt: &[u8]) -> Result<(), TcpError>;
    /// Pop one staged datagram and lend it to `f`; false when none is staged.
    fn extract_packet_with(&mut self, f: &mut dyn FnMut(&[u8])) -> bool;
    /// Leave TCP checksums of staged segments partial (CHECKSUM_PARTIAL).
    fn set_tx_csum_offload(&mut self, on: bool);
    fn poll(&self) -> u32;
    fn recv(&mut self, dst: &mut [u8]) -> Result<usize, TcpError>;
    /// Lend the send ring's free space (two slices when it wraps) for the
    /// host to fill in place; `send_commit` appends a prefix and ends the loan.
    fn send_reserve(&mut self, max: usize) -> Result<(&mut [u8], &mut [u8]), TcpError>;
    fn send_commit(&mut self, n: usize) -> Result<usize, TcpError>;
    fn state(&self) -> State;
    fn tick(&mut self) -> Result<(), TcpError>;
    /// Host back-pressure: build no more segments until resumed.
    fn set_egress_paused(&mut self, paused: bool);
    fn abort(&mut self) -> Result<(), TcpError>;
    fn close(&mut self) -> Result<(), TcpError>;
    /// Recycle this Tcb onto a new connection in place (reuses its rings).
    fn reinit(&mut self, cfg: TcbConfig);
    /// Key ISNs, TSval offsets and SYN cookies; `listen` requires it and
    /// `reinit` clears it.
    fn set_secret(&mut self, secret: &[u8; 16]);
    fn stats(&self) -> TcbStats;
}

impl<const BUF: usize> TcbDyn for Tcb<BUF> {
    fn set_now(&mut self, now: u64) {
        self.set_now(now)
    }
    fn listen(&mut self) -> Result<(), TcpError> {
        self.listen()
    }
    fn connect(&mut self) -> Result<(), TcpError> {
        self.connect()
    }
    fn inject_packet(&mut self, pkt: &[u8]) -> Result<(), TcpError> {
        self.inject_packet(pkt)
    }
    fn inject_packet_l4_csum_trusted(&mut self, pkt: &[u8]) -> Result<(), TcpError> {
        self.inject_packet_l4_csum_trusted(pkt)
    }
    fn extract_packet_with(&mut self, f: &mut dyn FnMut(&[u8])) -> bool {
        self.extract_packet_with(|p| f(p)).is_some()
    }
    fn set_tx_csum_offload(&mut self, on: bool) {
        self.set_tx_csum_offload(on)
    }
    fn poll(&self) -> u32 {
        self.poll()
    }
    fn recv(&mut self, dst: &mut [u8]) -> Result<usize, TcpError> {
        self.recv(dst)
    }
    fn send_reserve(&mut self, max: usize) -> Result<(&mut [u8], &mut [u8]), TcpError> {
        self.send_reserve(max)
    }
    fn send_commit(&mut self, n: usize) -> Result<usize, TcpError> {
        self.send_commit(n)
    }
    fn state(&self) -> State {
        self.state()
    }
    fn tick(&mut self) -> Result<(), TcpError> {
        self.tick()
    }
    fn set_egress_paused(&mut self, paused: bool) {
        self.set_egress_paused(paused)
    }
    fn abort(&mut self) -> Result<(), TcpError> {
        self.abort()
    }
    fn close(&mut self) -> Result<(), TcpError> {
        self.close()
    }
    fn reinit(&mut self, cfg: TcbConfig) {
        self.reinit(cfg)
    }
    fn set_secret(&mut self, secret: &[u8; 16]) {
        self.set_secret(secret)
    }
    fn stats(&self) -> TcbStats {
        self.stats()
    }
}

/// Worker-thread-only free-list of preallocated boxed objects (ArrayPool<T>).
/// `acquire` pops a recycled box or, on a cold miss, makes one (bounded by the
/// flow caps); `release` returns it. Single-threaded → no locking, and no
/// steady-state allocation once the high-water mark is warmed. `T: ?Sized` so
/// the same type serves both concrete ops and `dyn TcbDyn`.
struct BoxPool<T: ?Sized> {
    free: Vec<Box<T>>,
    make: fn() -> Box<T>,
}

impl<T: ?Sized> BoxPool<T> {
    fn new(warm: usize, make: fn() -> Box<T>) -> Self {
        let mut pool = BoxPool {
            free: Vec::new(),
            make,
        };
        pool.warm(warm);
        pool
    }
    fn warm(&mut self, count: usize) {
        self.free.reserve(count);
        for _ in 0..count {
            self.free.push((self.make)());
        }
    }
    fn acquire(&mut self) -> Box<T> {
        match self.free.pop() {
            Some(b) => b,
            None => (self.make)(),
        }
    }
    fn release(&mut self, b: Box<T>) {
        self.free.push(b);
    }
}

/// Cross-thread variant for the rare producer→worker handoffs (port-forward
/// accepts, ICMP replies): producer threads acquire+fill, the worker releases.
/// Cold path, so the mutex is uncontended.
struct SyncBoxPool<T> {
    free: Mutex<Vec<Box<T>>>,
    make: fn() -> Box<T>,
}

impl<T> SyncBoxPool<T> {
    fn new(warm: usize, make: fn() -> Box<T>) -> Self {
        let mut v = Vec::with_capacity(warm);
        for _ in 0..warm {
            v.push(make());
        }
        SyncBoxPool {
            free: Mutex::new(v),
            make,
        }
    }
    fn acquire(&self) -> Box<T> {
        match self.free.lock().unwrap().pop() {
            Some(b) => b,
            None => (self.make)(),
        }
    }
    fn release(&self, b: Box<T>) {
        self.free.lock().unwrap().push(b);
    }
}

fn make_tcp_op() -> Box<TcpOp> {
    // All fields are POD (integers, OVERLAPPED/WSABUF), so a fully zeroed
    // value is valid; the acquire site sets key/kind and arms the op.
    Box::new(unsafe { core::mem::zeroed() })
}
fn make_tcp_send_op() -> Box<TcpSendOp> {
    Box::new(unsafe { core::mem::zeroed() })
}
fn make_udp_op() -> Box<UdpOp> {
    Box::new(unsafe { core::mem::zeroed() })
}
fn make_accept_msg() -> Box<AcceptMsg> {
    Box::new(unsafe { core::mem::zeroed() })
}
fn make_icmp_reply() -> Box<IcmpReplyMsg> {
    // IcmpReplyMsg holds a Vec, which is not safe to `zeroed()`; build it empty.
    Box::new(IcmpReplyMsg {
        guest_ip: [0; 4],
        dst_ip: [0; 4],
        icmp: Vec::new(),
    })
}

/// A preallocated guest-TX frame slot. The producer (vCPU/TX path) acquires a
/// free slot, writes the frame into `data`, and posts `&slot` to a shard IOCP;
/// the consuming worker reads it and releases the slot. Ownership is exclusive
/// between acquire and release, so the `UnsafeCell` access is race-free; the
/// data handoff itself is synchronized by the IOCP post/completion.
#[repr(C)]
struct FrameSlot<const CAP: usize> {
    idx: u32,
    data: UnsafeCell<[u8; CAP]>,
}

/// Fixed pool of frame slots with a lock-free Treiber free-list (ABA-guarded
/// by a tag in the high 32 bits of `head`). Multi-producer acquire (vCPUs) and
/// multi-producer release (shard workers) — fully MPMC. No per-frame heap
/// allocation on the hot path.
struct FramePool<const CAP: usize> {
    slots: Box<[FrameSlot<CAP>]>,
    next: Box<[AtomicU32]>,
    head: AtomicU64, // (tag << 32) | free-list head index
}

// The slots are accessed through raw pointers handed off via the IOCP; the
// free-list guarantees a slot is owned by at most one party at a time.
unsafe impl<const CAP: usize> Send for FramePool<CAP> {}
unsafe impl<const CAP: usize> Sync for FramePool<CAP> {}

impl<const CAP: usize> FramePool<CAP> {
    fn new(n: usize) -> Self {
        let slots: Vec<FrameSlot<CAP>> = (0..n)
            .map(|i| FrameSlot {
                idx: i as u32,
                data: UnsafeCell::new([0u8; CAP]),
            })
            .collect();
        let next: Vec<AtomicU32> = (0..n)
            .map(|i| {
                AtomicU32::new(if i + 1 < n {
                    (i + 1) as u32
                } else {
                    POOL_SENTINEL
                })
            })
            .collect();
        FramePool {
            slots: slots.into_boxed_slice(),
            next: next.into_boxed_slice(),
            head: AtomicU64::new(0), // (tag=0, index=0)
        }
    }

    /// Pop a free slot index, or None if the pool is exhausted.
    fn acquire(&self) -> Option<u32> {
        let mut h = self.head.load(Ordering::Acquire);
        loop {
            let idx = (h & 0xFFFF_FFFF) as u32;
            if idx == POOL_SENTINEL {
                return None;
            }
            let tag = h >> 32;
            let nxt = self.next[idx as usize].load(Ordering::Relaxed);
            let new = (tag.wrapping_add(1) << 32) | (nxt as u64);
            match self
                .head
                .compare_exchange_weak(h, new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Some(idx),
                Err(cur) => h = cur,
            }
        }
    }

    /// Return a slot index to the free-list.
    fn release(&self, idx: u32) {
        let mut h = self.head.load(Ordering::Acquire);
        loop {
            let old_idx = (h & 0xFFFF_FFFF) as u32;
            let tag = h >> 32;
            self.next[idx as usize].store(old_idx, Ordering::Relaxed);
            let new = (tag.wrapping_add(1) << 32) | (idx as u64);
            match self
                .head
                .compare_exchange_weak(h, new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return,
                Err(cur) => h = cur,
            }
        }
    }

    fn slot_ptr(&self, idx: u32) -> *mut FrameSlot<CAP> {
        &self.slots[idx as usize] as *const FrameSlot<CAP> as *mut FrameSlot<CAP>
    }

    /// Copy a frame into slot `idx`. Caller must own the slot (just acquired).
    fn fill(&self, idx: u32, frame: &[u8]) -> usize {
        let n = frame.len().min(CAP);
        unsafe {
            let data = &mut *self.slots[idx as usize].data.get();
            data[..n].copy_from_slice(&frame[..n]);
        }
        n
    }

    /// Worker side of the handoff: the (slot index, frame bytes) behind a
    /// `KEY_FRAME*` completion.
    ///
    /// # Safety
    /// `ov` must be a slot pointer of this pool posted by the producer, and the
    /// returned slice must not be used after `release(idx)`.
    unsafe fn received<'a>(ov: *mut OVERLAPPED, bytes: u32) -> (u32, &'a [u8]) {
        let slot = ov as *mut FrameSlot<CAP>;
        let n = (bytes as usize).min(CAP);
        unsafe {
            let idx = (*slot).idx;
            let arr = &*UnsafeCell::raw_get(core::ptr::addr_of!((*slot).data));
            (idx, &arr[..n])
        }
    }
}

/// An accepted host client socket for a port-forward, posted from a listener
/// thread to the worker (which owns all flow state).
struct AcceptMsg {
    sock: SOCKET,
    guest_ip: [u8; 4],
    guest_port: u16,
}

/// A guest ICMP echo request to be proxied to a real remote host.
struct IcmpJob {
    guest_ip: [u8; 4],
    dst_ip: [u8; 4],
    icmp: Vec<u8>, // original echo-request message (echoed back on success)
}

/// Result of a proxied ping, posted back to the worker via KEY_ICMP so the
/// (single) worker is the only thread that injects to the guest.
struct IcmpReplyMsg {
    guest_ip: [u8; 4],
    dst_ip: [u8; 4],
    icmp: Vec<u8>,
}

/// Hands guest pings to a small pool of precreated blocking IcmpSendEcho
/// threads (IcmpSendEcho has no IOCP form). Replies are posted back to the
/// worker's IOCP, so the NAT data path stays single-threaded/lock-free; only
/// this rare handoff uses a mutex. The main worker never blocks on ICMP.
struct IcmpPool {
    iocp: Iocp,
    queue: Mutex<VecDeque<IcmpJob>>,
    cv: Condvar,
    running: AtomicBool,
    reply_pool: Arc<SyncBoxPool<IcmpReplyMsg>>,
}

impl IcmpPool {
    fn new(iocp: Iocp, reply_pool: Arc<SyncBoxPool<IcmpReplyMsg>>) -> Self {
        IcmpPool {
            iocp,
            queue: Mutex::new(VecDeque::new()),
            cv: Condvar::new(),
            running: AtomicBool::new(true),
            reply_pool,
        }
    }

    /// Enqueue a ping for a worker. Drops it if the queue is at capacity.
    fn submit(&self, job: IcmpJob) {
        let mut q = self.queue.lock().unwrap();
        if q.len() >= MAX_ICMP_INFLIGHT {
            return;
        }
        q.push_back(job);
        drop(q);
        self.cv.notify_one();
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.cv.notify_all();
    }

    /// Worker thread body: block for a job, ping, post the result back.
    fn worker(self: Arc<Self>) {
        let h = sys::icmp_create();
        while self.running.load(Ordering::SeqCst) {
            let job = {
                let mut q = self.queue.lock().unwrap();
                while q.is_empty() && self.running.load(Ordering::SeqCst) {
                    q = self.cv.wait(q).unwrap();
                }
                match q.pop_front() {
                    Some(j) => j,
                    None => continue,
                }
            };
            // ICMP payload (after the 8-byte header) is the echo data.
            let data = if job.icmp.len() > 8 {
                &job.icmp[8..]
            } else {
                &[][..]
            };
            if sys::icmp_echo(h, job.dst_ip, data, ICMP_TIMEOUT_MS) {
                // Reuse a pooled reply (and its Vec capacity) for the handoff.
                let mut msg = self.reply_pool.acquire();
                msg.guest_ip = job.guest_ip;
                msg.dst_ip = job.dst_ip;
                msg.icmp.clear();
                msg.icmp.extend_from_slice(&job.icmp);
                let ptr = Box::into_raw(msg);
                if !sys::post(self.iocp, 0, KEY_ICMP, ptr as *mut OVERLAPPED) {
                    // Handoff failed; reclaim the box to the pool.
                    self.reply_pool.release(unsafe { Box::from_raw(ptr) });
                }
            }
        }
        sys::icmp_close(h);
    }
}

type FlowKey = ([u8; 4], u16, [u8; 4], u16);

/// One overlapped UDP receive, owned by its flow. `overlapped` MUST be first
/// so a completion's OVERLAPPED* casts straight back to `*mut UdpOp`.
#[repr(C)]
struct UdpOp {
    overlapped: OVERLAPPED,
    buf: [u8; UDP_BUF],
    wsabuf: WSABUF,
    sock: SOCKET,
    guest_ip: [u8; 4],
    guest_port: u16,
    dst_ip: [u8; 4],
    dst_port: u16,
    key: FlowKey,
}

struct UdpFlow {
    // Option so the pooled box can be reclaimed at reap via take() while the
    // struct still implements Drop: you can't move a field out of a Drop type,
    // but you can take() an Option. Always Some while the flow is live.
    op: Option<Box<UdpOp>>,
    last_use: u64,
    dead: bool,
}

// TcpFlow/UdpFlow keep a Drop impl as a socket-close safety net: even if a
// future reap path forgets to clean up, the host socket is still closed. The
// pooled boxes (Tcb / overlapped ops) are instead recycled explicitly at the
// reap sites — Drop can't reach the pools (it has no &mut NatState). To allow
// that without a partial move, each pooled field is an Option<Box<_>> the reap
// site take()s; a debug_assert in Drop then flags any flow dropped with a box
// still resident (a missed reap), turning a silent pool-drain into a loud test
// failure. The worker's shutdown drain take()s the boxes first, so those
// intentional drops don't trip the assert.
impl Drop for UdpFlow {
    fn drop(&mut self) {
        debug_assert!(
            self.op.is_none(),
            "UdpFlow dropped without reap: pooled UdpOp leaked (not returned to pool)"
        );
        // The host socket lives inside the op; if the op is still resident
        // (un-reaped), close it so the handle can't leak in release builds.
        if let Some(op) = self.op.as_ref()
            && op.sock != INVALID_SOCKET
        {
            sys::close_sock(op.sock);
        }
    }
}

/// Common prefix of every overlapped TCP op so a completion's `OVERLAPPED*`
/// can be classified before being cast to the concrete op type. Every TCP op
/// struct is `#[repr(C)]` and starts with these two fields at identical
/// offsets (overlapped first, kind immediately after).
#[repr(C)]
struct TcpOvHeader {
    overlapped: OVERLAPPED,
    kind: u8,
}

/// The connect/recv op, owned by its flow and reused (ConnectEx, then WSARecv;
/// the two are never in flight at the same time). A recv's buffers are the
/// free space of the flow's TCB send ring (`wsabuf[1]` only where it wraps).
/// `overlapped` MUST be first, `kind` second.
#[repr(C)]
struct TcpOp {
    overlapped: OVERLAPPED,
    kind: u8, // 0 = connect, 1 = recv
    key: FlowKey,
    wsabuf: [WSABUF; 2],
}

/// The send op, owned by its flow. At most one host send is in flight per flow
/// (the next chunk is posted from the completion), which preserves stream
/// order and bounds memory. Runs concurrently with the recv op (full duplex,
/// distinct OVERLAPPED). `overlapped` MUST be first, `kind` second.
#[repr(C)]
struct TcpSendOp {
    overlapped: OVERLAPPED,
    kind: u8, // 2 = send
    key: FlowKey,
    buf: [u8; TCP_BUF],
    wsabuf: WSABUF,
}

struct TcpFlow {
    // Option so the pooled boxes can be take()n into their pools at reap while
    // TcpFlow still implements Drop (socket-close safety net). Always Some while
    // the flow is live.
    tcb: Option<Box<dyn TcbDyn>>,
    tier: usize, // which compile-time Tcb size-tier pool to recycle into
    sock: SOCKET,
    op: Option<Box<TcpOp>>,          // connect/recv op
    send_op: Option<Box<TcpSendOp>>, // send op
    connected: bool,
    connect_pending: bool, // ConnectEx is in flight on `op`
    recv_pending: bool,
    send_inflight: bool,
    pending_to_host: Vec<u8>, // guest->host queue (drained by overlapped sends)
    closing: bool,            // host sent FIN: our recv side is closing
    want_shutdown: bool,      // guest sent FIN: SD_SEND the host once the queue drains
    shutdown_done: bool,      // SD_SEND already issued
    dead: bool,               // tearing down; socket closed, awaiting op drain
    created_at: u64,          // ms at flow creation (connect-deadline watchdog)
    last_activity: u64,       // ms of last real TX/RX (idle/half-close watchdogs)
    diag: FlowDiag,           // net-diag stall tracking
    published: Losses,        // TCB loss counters already added to NatStats
    rx_blocked: bool,         // paused on the NIC's RX backlog (in rx_blocked list)
    csum_offload: bool,       // the TCB leaves TCP checksums partial (guest GUEST_CSUM)
    /// Length of the guest's SYN, kept in `send_op.buf` (idle until the host
    /// connect completes) while the host connect is pending; 0 otherwise.
    syn_len: usize,
    /// That SYN came with a partial (offloaded) TCP checksum.
    syn_csum_trusted: bool,
}

impl Drop for TcpFlow {
    fn drop(&mut self) {
        debug_assert!(
            self.tcb.is_none() && self.op.is_none() && self.send_op.is_none(),
            "TcpFlow dropped without reap: pooled boxes leaked (not returned to pool)"
        );
        if self.sock != INVALID_SOCKET {
            sys::close_sock(self.sock);
        }
    }
}

impl TcpFlow {
    /// Finished both ways, with only the guest-facing TIME_WAIT left: the
    /// guest's FIN is acknowledged (tcp-sans-io ACKs a FIN at once), every
    /// guest byte went to the host socket before its send-side shutdown, and
    /// no host op is in flight. Such a flow goes at once.
    ///
    /// tcp-sans-io holds TIME_WAIT for 2·MSL (60 s) to re-ACK a FIN whose ACK
    /// was lost and to keep stale segments out of a reused 4-tuple. Over the
    /// virtual link nothing is reordered, and a FIN the guest retransmits
    /// after the flow is gone draws a RST ([`NatState::reset_stray`]), which
    /// ends the guest's LAST_ACK just as well. Holding the full 60 s pinned a
    /// flow slot per connection the host closed first (HTTP/1.0, `Connection:
    /// close`): after 256 of those in a minute, every further guest connect()
    /// was refused. And tcp-sans-io answers a new SYN on a TIME_WAIT TCB with
    /// a challenge ACK, so a guest reusing the 4-tuple waited out a 1 s SYN
    /// retransmit.
    fn lingering(&self) -> bool {
        !self.dead
            && self.shutdown_done
            && !self.send_inflight
            && !self.recv_pending
            && self.pending_to_host.is_empty()
            && self
                .tcb
                .as_ref()
                .is_some_and(|t| t.state() == State::TimeWait && t.poll() & EV_READABLE == 0)
    }

    /// The sequence number of the guest SYN waiting on the host connect, if
    /// any; the SYN is then dropped.
    fn take_syn_seq(&mut self) -> Option<u32> {
        let len = std::mem::take(&mut self.syn_len);
        let syn = &self.send_op.as_ref()?.buf[..len];
        let at = usize::from(syn.first()? & 0x0F) * 4 + 4;
        Some(u32::from_be_bytes(syn.get(at..at + 4)?.try_into().ok()?))
    }
}

/// The (seq, ack, flags) of the RST that answers segment `tcp`, carrying `data`
/// payload bytes, on a connection that doesn't exist (RFC 9293 §3.10.7.1): an
/// ACK is answered from its acknowledgment number, anything else is
/// acknowledged in full.
fn reset_for(tcp: &TcpView, data: usize) -> (u32, u32, u8) {
    if tcp.flags & TCP_ACK != 0 {
        return (tcp.ack, 0, TCP_RST);
    }
    let len =
        data as u32 + u32::from(tcp.flags & TCP_SYN != 0) + u32::from(tcp.flags & TCP_FIN != 0);
    (0, tcp.seq.wrapping_add(len), TCP_RST | TCP_ACK)
}

/// Split a TCP/IPv4 datagram into (ip+tcp header, payload, seq, flags). `None`
/// if it's not a parseable TCPv4 datagram.
fn split_tcp_dgram(ip: &[u8]) -> Option<(&[u8], &[u8], u32, u8)> {
    if ip.len() < 20 || ip[0] >> 4 != 4 || ip[9] != IP_PROTO_TCP {
        return None;
    }
    let ihl = (ip[0] & 0x0F) as usize * 4;
    if ihl < 20 || ip.len() < ihl + 20 {
        return None;
    }
    let thl = ((ip[ihl + 12] >> 4) as usize) * 4;
    if thl < 20 || ip.len() < ihl + thl {
        return None;
    }
    let seq = be32(&ip[ihl + 4..ihl + 8]);
    let flags = ip[ihl + 13];
    Some((&ip[..ihl + thl], &ip[ihl + thl..], seq, flags))
}

/// Bytes reserved in front of a coalesced payload for its Ethernet, IPv4 and
/// TCP headers (an IPv4 or TCP header is at most 60 bytes).
const GSO_HDR_ROOM: usize = ETH_HDR + 60 + 60;

/// One coalesced TCP super-frame toward the guest, built in place: payloads
/// are appended behind `GSO_HDR_ROOM` reserved bytes, and the headers are
/// written in front of them once, at flush, so each payload byte is copied
/// exactly once on its way to the NIC.
struct GsoFrame {
    buf: Vec<u8>,
    /// IP+TCP header of the latest segment (its ack/window/flags are fresh).
    hdr: [u8; 120],
    hdr_len: usize,
    /// Sequence number of the first segment, and its payload size (gso_size).
    seq: u32,
    mss: u16,
}

impl GsoFrame {
    fn new() -> Self {
        let mut buf = Vec::with_capacity(GSO_HDR_ROOM + GSO_PAYLOAD_CAP);
        buf.resize(GSO_HDR_ROOM, 0);
        GsoFrame {
            buf,
            hdr: [0; 120],
            hdr_len: 0,
            seq: 0,
            mss: 0,
        }
    }

    fn payload_len(&self) -> usize {
        self.buf.len() - GSO_HDR_ROOM
    }

    /// Whether a data segment `(seq, len)` extends the frame contiguously.
    fn extends(&self, seq: u32, len: usize) -> bool {
        seq == self.seq.wrapping_add(self.payload_len() as u32)
            && self.payload_len() + len <= GSO_PAYLOAD_CAP
    }

    fn push(&mut self, hdr: &[u8], pay: &[u8], seq: u32) {
        if self.payload_len() == 0 {
            self.seq = seq;
            self.mss = pay.len() as u16;
        }
        self.buf.extend_from_slice(pay);
        self.hdr[..hdr.len()].copy_from_slice(hdr);
        self.hdr_len = hdr.len();
    }

    fn flush(&mut self, dev: Option<&NetDevice>, dst_mac: [u8; 6], src_mac: [u8; 6]) {
        if self.payload_len() == 0 {
            return;
        }
        if let Some(d) = dev {
            emit_gso_tcp(
                d,
                &mut self.buf,
                &self.hdr[..self.hdr_len],
                self.seq,
                self.mss,
                dst_mac,
                src_mac,
            );
        }
        self.buf.truncate(GSO_HDR_ROOM);
    }
}

/// Emit one coalesced TCP super-segment toward the guest. `frame` holds the
/// payload after `GSO_HDR_ROOM` bytes; `hdr_tmpl` is the IP+TCP header of the
/// *last* contributing segment (so ack/window/flags are fresh); `seq` is the
/// *first* segment's sequence number; `mss` is the original segment size
/// (`gso_size`). Writes Eth+IP+TCP in front of the payload with correct
/// checksums and delivers via `inject_rx_gso_batched` with a TCPv4 GSO header
/// so the guest's GRO path sees one skb (the worker interrupts the guest once
/// per batch of completions).
fn emit_gso_tcp(
    dev: &NetDevice,
    frame: &mut [u8],
    hdr_tmpl: &[u8],
    seq: u32,
    mss: u16,
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
) {
    let ihl = (hdr_tmpl[0] & 0x0F) as usize * 4;
    let thl = ((hdr_tmpl[ihl + 12] >> 4) as usize) * 4;
    let pay_len = frame.len() - GSO_HDR_ROOM;
    let l3_len = ihl + thl + pay_len;

    let eth = &mut frame[GSO_HDR_ROOM - ETH_HDR - ihl - thl..];
    eth[..6].copy_from_slice(&dst_mac);
    eth[6..12].copy_from_slice(&src_mac);
    eth[12..ETH_HDR].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    eth[ETH_HDR..ETH_HDR + ihl + thl].copy_from_slice(hdr_tmpl);

    // Patch IP: total_len + recompute header checksum.
    let b = &mut eth[ETH_HDR..];
    b[2] = (l3_len >> 8) as u8;
    b[3] = l3_len as u8;
    b[10] = 0;
    b[11] = 0;
    let c = checksum16(&[&b[..ihl]]);
    b[10] = (c >> 8) as u8;
    b[11] = c as u8;

    // Patch TCP: seq + PARTIAL checksum. With GUEST_CSUM negotiated we deliver
    // `CHECKSUM_PARTIAL` (csum field = ones-complement sum of the pseudo-header
    // only; csum_start/offset tell the guest where the full sum would land).
    // Linux trusts CHECKSUM_PARTIAL for local delivery, so we skip summing the
    // ~64 KiB payload — the dominant remaining NAT-worker cost at 625 MB/s.
    b[ihl + 4..ihl + 8].copy_from_slice(&seq.to_be_bytes());
    let tcp_len = (thl + pay_len) as u16;
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&b[12..16]); // src ip
    pseudo[4..8].copy_from_slice(&b[16..20]); // dst ip
    pseudo[9] = IP_PROTO_TCP;
    pseudo[10] = (tcp_len >> 8) as u8;
    pseudo[11] = tcp_len as u8;
    // checksum16 returns the COMPLEMENTED sum; the partial-csum convention is
    // the un-complemented folded sum, so invert it back.
    let partial = !checksum16(&[&pseudo]);
    b[ihl + 16] = (partial >> 8) as u8;
    b[ihl + 17] = partial as u8;

    let csum_start = (ETH_HDR + ihl) as u16;
    let vhdr = if pay_len > mss as usize {
        RxHeader {
            flags: HDR_F_NEEDS_CSUM,
            gso_type: HDR_GSO_TCPV4,
            hdr_len: (ETH_HDR + ihl + thl) as u16,
            gso_size: mss,
            csum_start,
            csum_offset: 16,
        }
    } else {
        RxHeader {
            flags: HDR_F_NEEDS_CSUM,
            csum_start,
            csum_offset: 16,
            ..Default::default()
        }
    };
    dev.inject_rx_gso_batched(eth, vhdr);
}

/// The host side reached EOF (or failed): stop receiving and queue the FIN
/// toward the guest. Every byte the host sent is already in the tcb's send
/// ring (recvs land there), so the FIN follows them.
fn on_host_eof(flow: &mut TcpFlow) {
    if !flow.closing {
        flow.closing = true;
        let _ = flow.tcb.as_mut().unwrap().close();
    }
}

/// Re-arm a host receive, straight into the free space of the flow's tcb send
/// ring. Nothing is posted until the guest connection can take data and
/// enough of the ring is free; the drive that frees it (a guest ACK) calls
/// back here. A full ring leaves the host socket unread, which closes the
/// host's TCP window (backpressure).
/// Returns false only if the receive failed synchronously (no completion will
/// arrive) — the caller must tear the flow down rather than wait on a recv that
/// will never complete.
#[must_use]
fn maybe_post_recv(flow: &mut TcpFlow) -> bool {
    if !flow.connected || flow.recv_pending || flow.closing || flow.dead {
        return true;
    }
    let min = TCP_RECV_MIN.min(TIER_BUF[flow.tier] / 2);
    let tcb = flow.tcb.as_mut().unwrap();
    let Ok((a, b)) = tcb.send_reserve(TCP_RECV_MAX) else {
        return true;
    };
    if a.len() + b.len() < min {
        let _ = tcb.send_commit(0);
        return true;
    }
    let nbufs = if b.is_empty() { 1 } else { 2 };
    let op = flow.op.as_mut().unwrap();
    op.kind = 1;
    op.wsabuf = [
        sys::wsabuf(a.as_mut_ptr(), a.len()),
        sys::wsabuf(b.as_mut_ptr(), b.len()),
    ];
    let bufs = op.wsabuf.as_ptr();
    let ovl = &mut op.overlapped as *mut OVERLAPPED;
    // SAFETY: the buffers are the tcb's lent ring space, which the tcb leaves
    // alone until `send_commit`, and the tcb outlives the recv (a flow is
    // reaped only after its recv completes). `op` is pinned in its Box.
    let posted = unsafe { sys::wsa_recv(flow.sock, bufs, nbufs, ovl) };
    if posted {
        flow.recv_pending = true;
        if crate::diag::net_enabled() {
            flow.diag.recv_posted = Some(Instant::now());
        }
    } else {
        let _ = flow.tcb.as_mut().unwrap().send_commit(0);
    }
    posted
}

/// Post the next queued guest->host chunk as an overlapped send (one in flight
/// at a time, which keeps stream order and bounds memory). When the queue is
/// empty, perform any deferred host-send half-close. Returns false if the send
/// failed synchronously (the caller should tear the flow down).
fn pump_send(flow: &mut TcpFlow) -> bool {
    if !flow.connected || flow.send_inflight || flow.dead {
        return true;
    }
    if flow.pending_to_host.is_empty() {
        if flow.want_shutdown {
            flow.want_shutdown = false;
            flow.shutdown_done = true;
            sys::shutdown_send(flow.sock);
        }
        return true;
    }
    let n = flow.pending_to_host.len().min(TCP_BUF);
    {
        let op = flow.send_op.as_mut().unwrap();
        op.kind = 2;
        op.buf[..n].copy_from_slice(&flow.pending_to_host[..n]);
        op.wsabuf = sys::wsabuf(op.buf.as_mut_ptr(), n);
    }
    let sock = flow.sock;
    let wb = &flow.send_op.as_ref().unwrap().wsabuf as *const WSABUF;
    let ovl = &mut flow.send_op.as_mut().unwrap().overlapped as *mut OVERLAPPED;
    if unsafe { sys::wsa_send_ov(sock, wb, ovl) } {
        flow.pending_to_host.drain(..n);
        flow.send_inflight = true;
        true
    } else {
        false
    }
}

/// What woke the NAT worker for the current dispatch. Net-diag mode uses it to
/// attribute a guest-bound data stall to whatever ended it.
#[derive(Clone, Copy)]
enum Wake {
    Guest,
    HostRecv,
    HostSend,
    Timer,
    RxSpace,
    Other,
}

impl Wake {
    fn as_str(self) -> &'static str {
        match self {
            Wake::Guest => "guest frame",
            Wake::HostRecv => "host recv",
            Wake::HostSend => "host send",
            Wake::Timer => "timer",
            Wake::RxSpace => "guest rx space",
            Wake::Other => "other",
        }
    }
}

/// The cumulative loss counters of a tcp-sans-io [`TcbStats`], which also
/// carries gauges (srtt, cwnd, ...) that aren't summed across flows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Losses {
    segs_retrans: u64,
    bytes_retrans: u64,
    rto: u64,
    tlp: u64,
    fast_recoveries: u64,
    /// D-SACKs from the guest: it got a duplicate, so we retransmitted
    /// spuriously.
    dsacks: u64,
    /// Payload the guest sent us again that we already had.
    dup_bytes_received: u64,
    /// Guest segments dropped because the out-of-order tracker was full.
    ooo_drops: u64,
}

impl From<&TcbStats> for Losses {
    fn from(s: &TcbStats) -> Self {
        Losses {
            segs_retrans: s.segs_retrans,
            bytes_retrans: s.bytes_retrans,
            rto: s.rto_count.into(),
            tlp: s.tlp_count.into(),
            fast_recoveries: s.fast_recoveries.into(),
            dsacks: s.dsacks_received,
            dup_bytes_received: s.dup_bytes_received,
            ooo_drops: s.ooo_drops.into(),
        }
    }
}

/// NAT counters, shared by the worker with [`NatBackend`] for the exit
/// summary. Each flow's [`Losses`] are published on every timer sweep and
/// at reap; the stall counters are only kept in net-diag mode.
#[derive(Default)]
struct NatStats {
    tcp_flows: AtomicU64,
    segs_retrans: AtomicU64,
    bytes_retrans: AtomicU64,
    rto: AtomicU64,
    tlp: AtomicU64,
    fast_recoveries: AtomicU64,
    dsacks: AtomicU64,
    dup_bytes_received: AtomicU64,
    ooo_drops: AtomicU64,
    /// Guest frames dropped because the frame pool was exhausted.
    tx_drops: AtomicU64,
    /// Most completions a due timer sweep found already queued and handled
    /// first (within its catch-up budget): how far the worker fell behind.
    iocp_backlog_max: AtomicU64,
    host_stalls: AtomicU64,
    host_stall_ms: AtomicU64,
    rx_stalls: AtomicU64,
    rx_stall_ms: AtomicU64,
    other_stalls: AtomicU64,
    other_stall_ms: AtomicU64,
}

impl NatStats {
    /// Add what a flow's loss counters gained since `old` (they only grow
    /// within one connection).
    fn add_delta(&self, new: &Losses, old: &Losses) {
        let add = |a: &AtomicU64, n: u64, o: u64| {
            a.fetch_add(n.saturating_sub(o), Ordering::Relaxed);
        };
        add(&self.segs_retrans, new.segs_retrans, old.segs_retrans);
        add(&self.bytes_retrans, new.bytes_retrans, old.bytes_retrans);
        add(&self.rto, new.rto, old.rto);
        add(&self.tlp, new.tlp, old.tlp);
        add(
            &self.fast_recoveries,
            new.fast_recoveries,
            old.fast_recoveries,
        );
        add(&self.dsacks, new.dsacks, old.dsacks);
        add(
            &self.dup_bytes_received,
            new.dup_bytes_received,
            old.dup_bytes_received,
        );
        add(&self.ooo_drops, new.ooo_drops, old.ooo_drops);
    }

    fn summary(&self) -> String {
        let ld = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let mut s = format!(
            "nat: tcp_flows={} retransmits={} ({} B) rto={} tlp={} recoveries={} dsacks={} \
             dup_bytes_from_guest={} ooo_drops={} tx_drops={} iocp_backlog_max={}",
            ld(&self.tcp_flows),
            ld(&self.segs_retrans),
            ld(&self.bytes_retrans),
            ld(&self.rto),
            ld(&self.tlp),
            ld(&self.fast_recoveries),
            ld(&self.dsacks),
            ld(&self.dup_bytes_received),
            ld(&self.ooo_drops),
            ld(&self.tx_drops),
            ld(&self.iocp_backlog_max),
        );
        if crate::diag::net_enabled() {
            s.push_str(&format!(
                " stalls: host={} ({} ms) guest_rx={} ({} ms) other={} ({} ms)",
                ld(&self.host_stalls),
                ld(&self.host_stall_ms),
                ld(&self.rx_stalls),
                ld(&self.rx_stall_ms),
                ld(&self.other_stalls),
                ld(&self.other_stall_ms),
            ));
        }
        s
    }
}

/// Net-diag stall tracking for one TCP flow (untouched unless net-diag is on).
#[derive(Default)]
struct FlowDiag {
    /// When guest-bound data last left this flow.
    last_data_out: Option<Instant>,
    /// When the outstanding host recv was posted.
    recv_posted: Option<Instant>,
    /// How long the most recently completed host recv was outstanding.
    last_recv_wait_ms: u64,
}

/// Publish what `flow`'s loss counters gained since the last call.
fn publish_tcb_stats(flow: &mut TcpFlow, stats: &NatStats) {
    if let Some(tcb) = flow.tcb.as_ref() {
        let now = Losses::from(&tcb.stats());
        if now != flow.published {
            stats.add_delta(&now, &flow.published);
            flow.published = now;
        }
    }
}

fn fmt_flow(k: FlowKey) -> String {
    let (gi, gp, ri, rp) = k;
    format!(
        "{}.{}.{}.{}:{gp} <-> {}.{}.{}.{}:{rp}",
        gi[0], gi[1], gi[2], gi[3], ri[0], ri[1], ri[2], ri[3]
    )
}

/// Net-diag: guest-bound data just left `key`. A gap of 3 ms to 1 s since the
/// previous data is a stall (shorter is normal pacing, longer an idle flow):
/// count it by what ended it, and log it if it reached 10 ms (shorter stalls
/// ended by a guest frame are routine ACK clocking under load). A stall a host
/// recv ended, with that recv outstanding about as long, is the host sender
/// stalling; one ended by guest RX space is the guest slow to take frames
/// (the NIC backlog was full); one a guest frame ended is the guest's window
/// or ACK clock.
fn note_data_out(d: &mut FlowDiag, key: FlowKey, wake: Wake, stats: &NatStats) {
    let now = Instant::now();
    if let Some(prev) = d.last_data_out {
        let gap = now.duration_since(prev).as_millis() as u64;
        if (3..1000).contains(&gap) {
            let (n, ms) = match wake {
                Wake::HostRecv => (&stats.host_stalls, &stats.host_stall_ms),
                Wake::RxSpace => (&stats.rx_stalls, &stats.rx_stall_ms),
                _ => (&stats.other_stalls, &stats.other_stall_ms),
            };
            n.fetch_add(1, Ordering::Relaxed);
            ms.fetch_add(gap, Ordering::Relaxed);
            if gap >= 10 {
                eprintln!(
                    "[nat] {} stalled {gap} ms, resumed by {} (host recv outstanding {} ms)",
                    fmt_flow(key),
                    wake.as_str(),
                    d.last_recv_wait_ms
                );
            }
        }
    }
    d.last_data_out = Some(now);
}

struct NatState {
    net: Weak<NetDevice>,
    iocp: Iocp,
    /// This worker's shard index, of `shards`; see [`FlowRouter`].
    shard: usize,
    shards: usize,
    router: Arc<FlowRouter>,
    flows: Arc<FlowCounts>,
    gw_ip: [u8; 4],
    gw_mac: [u8; 6],
    guest_mac: [u8; 6],
    udp: HashMap<FlowKey, UdpFlow>,
    tcp: HashMap<FlowKey, TcpFlow>,
    icmp: Arc<IcmpPool>,
    pool: Arc<FramePool<FRAME_CAP>>,
    big_pool: Arc<FramePool<TX_FRAME_CAP>>,
    /// Set while handling a frame whose TCP checksum the guest left to us
    /// (offload): the flow's TCB skips verifying it.
    l4_csum_trusted: bool,
    // Preallocated control-plane object pools (no steady-state allocation).
    tcb_pools: Vec<BoxPool<dyn TcbDyn>>, // one free-list per compile-time tier
    tcp_op_pool: BoxPool<TcpOp>,
    tcp_send_op_pool: BoxPool<TcpSendOp>,
    udp_op_pool: BoxPool<UdpOp>,
    accept_pool: Arc<SyncBoxPool<AcceptMsg>>,
    /// Count of accepted-but-undrained port-forward connections (bounds the
    /// accept backlog; shared with each `listener_loop`).
    accept_inflight: Arc<AtomicUsize>,
    icmp_reply_pool: Arc<SyncBoxPool<IcmpReplyMsg>>,
    default_tier: usize,
    port_tier: HashMap<u16, usize>,
    start: Instant,
    rng: u32,
    /// Per-NAT 128-bit secret from the OS CSPRNG, installed into every Tcb
    /// after `reinit`: tcp-sans-io keys listener ISNs, TSval offsets and SYN
    /// cookies with it, and `listen` fails without one.
    tcb_secret: [u8; 16],
    last_tick: u64,
    last_expire: u64,
    tick_keys: Vec<FlowKey>,
    /// Flows paused because the NIC's RX backlog was deep, in pause order;
    /// `rx_spare` recycles the list's allocation across resumes.
    rx_blocked: Vec<FlowKey>,
    rx_spare: Vec<FlowKey>,
    // Reusable scratch buffers for building guest-bound frames without a
    // per-packet heap allocation (the worker is single-threaded).
    tx_scratch: Vec<u8>,
    l3_scratch: Vec<u8>,
    // GSO coalescing frame and the TCB receive-drain buffer, reused across
    // `tcp_drive` calls so the hot path neither allocates nor zeroes.
    gso: GsoFrame,
    drain_scratch: Vec<u8>,
    wake: Wake,
    stats: Arc<NatStats>,
}

// After construction the state is moved into and owned solely by the worker
// thread; the raw pointers it holds are never shared.
unsafe impl Send for NatState {}

impl NatState {
    fn inject(&self, frame: &[u8]) {
        if let Some(n) = self.net.upgrade() {
            n.inject_rx(frame);
        }
    }

    /// Wrap the L4 payload currently sitting in `l3_scratch` in IPv4 +
    /// Ethernet (reusing the scratch buffers) and inject it to the guest.
    /// Alloc-free.
    fn wrap_and_inject(&mut self, src_ip: [u8; 4], dst_ip: [u8; 4], proto: u8) {
        build_ipv4_into(
            &mut self.tx_scratch,
            src_ip,
            dst_ip,
            proto,
            &self.l3_scratch,
        );
        build_eth_into(
            &mut self.l3_scratch,
            self.guest_mac,
            self.gw_mac,
            ETHERTYPE_IPV4,
            &self.tx_scratch,
        );
        self.inject(&self.l3_scratch);
    }

    fn run(mut self) {
        const IDLE_MS: u32 = 25;
        const TICK_GATE_MS: u64 = 20;
        // Time a due timer sweep spends first on completions already queued:
        // enough to catch up after a hiccup, bounded so a completion flood
        // cannot starve the timers.
        const SWEEP_CATCHUP_MS: u64 = 10;
        // Completions taken per dequeue (one syscall). The guest's interrupt
        // for what they deliver waits for the whole batch, so this also bounds
        // that wait; the catch-up below checks its budget between dequeues.
        const IOCP_BATCH: usize = 16;
        let mut batch: [sys::Completion; IOCP_BATCH] =
            [(false, 0, 0, std::ptr::null_mut()); IOCP_BATCH];
        'run: loop {
            let n = sys::get_many(self.iocp, &mut batch, IDLE_MS);
            for &(ok, bytes, key, ov) in &batch[..n] {
                if !self.dispatch(ok, bytes, key, ov) {
                    break 'run;
                }
            }
            // One guest interrupt for the frames the whole batch delivered.
            self.notify_guest();
            // Drive per-flow TCP timers (retransmit / delayed-ACK) on a coarse
            // cadence rather than on every completion: those timers are coarse
            // (>=200ms) and the flow that just completed was already driven
            // inline. This keeps the sweep off the hot path (was O(flows) per
            // packet).
            let now = self.now();
            if now.wrapping_sub(self.last_tick) >= TICK_GATE_MS {
                // Catch up first. When this worker falls behind, the guest's
                // ACKs wait in the queue; a sweep that ran ahead of them would
                // read that silence as a lost tail and probe every busy flow.
                let mut queued = 0u64;
                loop {
                    let n = sys::get_many(self.iocp, &mut batch, 0);
                    if n == 0 {
                        break;
                    }
                    queued += n as u64;
                    for &(ok, bytes, key, ov) in &batch[..n] {
                        if !self.dispatch(ok, bytes, key, ov) {
                            break 'run;
                        }
                    }
                    self.notify_guest();
                    if self.now().wrapping_sub(now) >= SWEEP_CATCHUP_MS {
                        break;
                    }
                }
                self.stats
                    .iocp_backlog_max
                    .fetch_max(queued, Ordering::Relaxed);
                self.last_tick = self.now();
                self.wake = Wake::Timer;
                let tlp0 = self.stats.tlp.load(Ordering::Relaxed);
                self.tcp_tick();
                if crate::diag::net_enabled() {
                    let fired = self.stats.tlp.load(Ordering::Relaxed) - tlp0;
                    if fired > 0 {
                        eprintln!(
                            "[nat] timer sweep fired {fired} tail-loss probes \
                             ({queued} queued completions handled first)"
                        );
                    }
                }
            }
            // Re-read the clock: the catch-up above may have created flows or
            // stamped activity after `now`, and those must not look ancient.
            let now = self.now();
            if now.wrapping_sub(self.last_expire) >= EXPIRE_GATE_MS {
                self.last_expire = now;
                self.expire_idle(now);
            }
            // The sweep may have delivered retransmissions and ACKs.
            self.notify_guest();
        }
        self.notify_guest();
        self.shutdown();
    }

    /// Interrupt the guest, if it asked for one, for the frames delivered with
    /// `inject_rx_gso_batched` since the last call. One atomic swap when none.
    fn notify_guest(&self) {
        if let Some(d) = self.net.upgrade() {
            d.notify_rx();
        }
    }

    /// Handle one IOCP dequeue (a timeout is a no-op). Returns false on stop.
    fn dispatch(&mut self, ok: bool, bytes: u32, key: usize, ov: *mut OVERLAPPED) -> bool {
        if ov.is_null() {
            if key == KEY_STOP {
                return false;
            }
            if key == KEY_RX_SPACE {
                self.wake = Wake::RxSpace;
                self.resume_rx_blocked();
            }
            return true;
        }
        self.wake = Wake::Other;
        match key {
            KEY_FRAME | KEY_FRAME_OFFLOAD => {
                self.wake = Wake::Guest;
                let (idx, frame) = unsafe { FramePool::<FRAME_CAP>::received(ov, bytes) };
                self.l4_csum_trusted = key == KEY_FRAME_OFFLOAD;
                self.handle_frame(frame);
                self.l4_csum_trusted = false;
                self.settle_route(frame);
                self.pool.release(idx);
            }
            KEY_FRAME_OFFLOAD_BIG => {
                self.wake = Wake::Guest;
                let (idx, frame) = unsafe { FramePool::<TX_FRAME_CAP>::received(ov, bytes) };
                self.l4_csum_trusted = true;
                self.handle_frame(frame);
                self.l4_csum_trusted = false;
                self.settle_route(frame);
                self.big_pool.release(idx);
            }
            KEY_UDP => self.on_udp_recv(ov as *mut UdpOp, ok, bytes),
            KEY_ICMP => {
                let msg = unsafe { Box::from_raw(ov as *mut IcmpReplyMsg) };
                self.on_icmp_reply(&msg);
                self.icmp_reply_pool.release(msg);
            }
            KEY_ACCEPT => {
                let msg = unsafe { Box::from_raw(ov as *mut AcceptMsg) };
                let (sock, guest_ip, guest_port) = (msg.sock, msg.guest_ip, msg.guest_port);
                self.accept_pool.release(msg);
                self.accept_inflight.fetch_sub(1, Ordering::AcqRel);
                self.new_inbound_flow(sock, guest_ip, guest_port);
            }
            KEY_TCP => {
                // The completion key comes from the socket's IOCP
                // association, so connect/recv/send all arrive as
                // KEY_TCP; the op kind disambiguates them.
                let kind = unsafe { (*(ov as *const TcpOvHeader)).kind };
                self.wake = match kind {
                    1 => Wake::HostRecv,
                    2 => Wake::HostSend,
                    _ => Wake::Other,
                };
                match kind {
                    0 => self.on_tcp_connect(ov as *mut TcpOp, ok),
                    1 => self.on_tcp_recv(ov as *mut TcpOp, ok, bytes),
                    2 => self.on_tcp_send(ov as *mut TcpSendOp, ok, bytes),
                    _ => {}
                }
            }
            _ => {}
        }
        true
    }

    /// Shutdown: drop all live flows. take() the pooled boxes first (the pools
    /// are dying, so just discard them) so the Drop-bomb treats these
    /// intentional drops as reaped. Closing a socket cancels its overlapped
    /// ops, but their completions may still write into the op structs and
    /// buffers (a recv, into the tcb's send ring) after the close returns, so
    /// a flow's boxes are leaked instead of freed while it has an op in
    /// flight. For UDP the socket lives in the op, so close it here.
    fn shutdown(&mut self) {
        for (_, mut f) in self.tcp.drain() {
            publish_tcb_stats(&mut f, &self.stats);
            if f.sock != INVALID_SOCKET {
                sys::close_sock(f.sock);
                f.sock = INVALID_SOCKET;
            }
            let boxes = (f.tcb.take(), f.op.take(), f.send_op.take());
            if f.recv_pending || f.send_inflight || f.connect_pending {
                // Deliberate, bounded leak, not a buffer we forgot to free:
                // close_sock cancels the op asynchronously, so the kernel may
                // still write a cancelled recv into the tcb's send ring after
                // it returns. Freeing these now would be a use-after-free; the
                // process is tearing down, so the OS reclaims them instead.
                std::mem::forget(boxes);
            }
        }
        for (_, mut f) in self.udp.drain() {
            if let Some(op) = f.op.take()
                && op.sock != INVALID_SOCKET
            {
                sys::close_sock(op.sock);
            }
        }
    }

    fn now(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Whether the guest accepts partial checksums (`HDR_F_NEEDS_CSUM`), so
    /// a TCB can leave its TCP checksums to the guest.
    fn rx_csum_ok(&self) -> bool {
        self.net.upgrade().is_some_and(|d| d.rx_csum_ok())
    }

    /// Pick the Tcb size-tier for a flow from its service port, falling back to
    /// the configured default. No mid-flow promotion: the tier is fixed here.
    fn choose_tier(&self, port: u16) -> usize {
        self.port_tier
            .get(&port)
            .copied()
            .unwrap_or(self.default_tier)
    }

    fn next_iss(&mut self) -> u32 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.rng = x;
        x
    }

    fn handle_frame(&mut self, frame: &[u8]) {
        let Some(eth) = parse_eth(frame) else {
            return;
        };
        self.guest_mac = eth.src;
        match eth.ethertype {
            ETHERTYPE_ARP => self.handle_arp(&eth),
            ETHERTYPE_IPV4 => self.handle_ipv4(&eth),
            _ => {}
        }
    }

    fn handle_arp(&mut self, eth: &EthView) {
        let Some(arp) = parse_arp(eth.payload) else {
            return;
        };
        if arp.op != 1 || arp.tpa != self.gw_ip {
            return;
        }
        let reply = build_arp_reply(self.gw_mac, self.gw_ip, arp.sha, arp.spa);
        build_eth_into(
            &mut self.tx_scratch,
            arp.sha,
            self.gw_mac,
            ETHERTYPE_ARP,
            &reply,
        );
        self.inject(&self.tx_scratch);
    }

    fn handle_ipv4(&mut self, eth: &EthView) {
        let Some(ip) = parse_ipv4(eth.payload) else {
            return;
        };
        match ip.proto {
            IP_PROTO_ICMP => self.handle_icmp(&ip),
            IP_PROTO_UDP => self.handle_udp(&ip),
            IP_PROTO_TCP => self.handle_tcp(&ip),
            _ => {}
        }
    }

    fn handle_icmp(&mut self, ip: &Ipv4View) {
        // Pings to the gateway are answered locally; pings to any other host
        // are proxied to the real network via the ICMP worker pool.
        if ip.dst == self.gw_ip {
            if build_icmp_echo_reply_into(&mut self.l3_scratch, ip.payload) {
                self.wrap_and_inject(self.gw_ip, ip.src, IP_PROTO_ICMP);
            }
            return;
        }
        // Only proxy echo requests; ignore other ICMP types.
        if ip.payload.first().copied() != Some(ICMP_ECHO_REQUEST) || ip.payload.len() < 8 {
            return;
        }
        // The job crosses to a worker thread, so it owns its payload copy.
        self.icmp.submit(IcmpJob {
            guest_ip: ip.src,
            dst_ip: ip.dst,
            icmp: ip.payload.to_vec(),
        });
    }

    /// Worker-thread callback for a successful proxied ping: synthesize the
    /// echo reply (from the pinged host) and inject it to the guest.
    fn on_icmp_reply(&mut self, msg: &IcmpReplyMsg) {
        if build_icmp_echo_reply_into(&mut self.l3_scratch, &msg.icmp) {
            self.wrap_and_inject(msg.dst_ip, msg.guest_ip, IP_PROTO_ICMP);
        }
    }

    fn handle_udp(&mut self, ip: &Ipv4View) {
        let Some(udp) = parse_udp(ip.payload) else {
            return;
        };
        if let Some(sock) = self.ensure_udp_flow(ip.src, udp.src_port, ip.dst, udp.dst_port) {
            // Synchronous is fine for UDP (see wsa_send): datagram sends don't
            // block on peer flow-control, so this can't stall the worker.
            sys::wsa_send(sock, udp.payload);
        }
    }

    fn ensure_udp_flow(
        &mut self,
        gip: [u8; 4],
        gport: u16,
        dip: [u8; 4],
        dport: u16,
    ) -> Option<SOCKET> {
        let key = (gip, gport, dip, dport);
        let now = self.now();
        if let Some(f) = self.udp.get_mut(&key) {
            f.last_use = now;
            return Some(f.op.as_ref().unwrap().sock);
        }
        if self.flows.udp.load(Ordering::Relaxed) >= MAX_UDP_FLOWS {
            return None;
        }
        let sock = sys::new_udp_socket()?;
        sys::connect_sock(sock, dip, dport);
        if !sys::associate(self.iocp, sock, KEY_UDP) {
            sys::close_sock(sock);
            return None;
        }
        let mut op = self.udp_op_pool.acquire();
        op.overlapped = unsafe { core::mem::zeroed() };
        op.sock = sock;
        op.guest_ip = gip;
        op.guest_port = gport;
        op.dst_ip = dip;
        op.dst_port = dport;
        op.key = key;
        let p = op.buf.as_mut_ptr();
        let l = op.buf.len();
        op.wsabuf = sys::wsabuf(p, l);
        let opp: *mut UdpOp = &mut *op;
        let posted = unsafe { sys::wsa_recv(sock, &(*opp).wsabuf, 1, &mut (*opp).overlapped) };
        if !posted {
            // Recv failed synchronously: no completion will arrive, so a tracked
            // flow could never be reaped through its recv. Release everything now
            // instead of leaking it until the idle sweep.
            sys::close_sock(sock);
            self.udp_op_pool.release(op);
            return None;
        }
        self.udp.insert(
            key,
            UdpFlow {
                op: Some(op),
                last_use: now,
                dead: false,
            },
        );
        self.flows.udp.fetch_add(1, Ordering::Relaxed);
        Some(sock)
    }

    /// Remove a UDP flow: close its socket if still open and return the pooled
    /// op buffer. The pending recv has already drained (called from the recv
    /// completion, or after expire_idle closed the socket).
    fn reap_udp(&mut self, key: FlowKey) {
        if let Some(mut f) = self.udp.remove(&key) {
            self.flows.udp.fetch_sub(1, Ordering::Relaxed);
            if let Some(op) = f.op.take() {
                if op.sock != INVALID_SOCKET {
                    sys::close_sock(op.sock);
                }
                self.udp_op_pool.release(op);
            }
            // f drops here with op == None: Drop-bomb passes, socket closed.
        }
    }

    fn on_udp_recv(&mut self, opp: *mut UdpOp, ok: bool, bytes: u32) {
        if opp.is_null() {
            return;
        }
        let op = unsafe { &mut *opp };
        let key = op.key;
        let now = self.now();
        // If the flow was reaped while this recv was in flight, the socket was
        // closed (aborting it); the op has now drained, so free it safely.
        let dead = self.udp.get(&key).map(|f| f.dead).unwrap_or(true);
        if dead {
            self.reap_udp(key);
            return;
        }
        if !ok || bytes == 0 {
            // Socket error/closed (e.g. ICMP port-unreachable). Drop the flow;
            // a later guest send recreates it. No other op is pending.
            self.reap_udp(key);
            return;
        }
        let n = (bytes as usize).min(op.buf.len());
        // Build the udp datagram into l3_scratch, then wrap+inject (alloc-free).
        build_udp_into(
            &mut self.l3_scratch,
            op.dst_ip,
            op.guest_ip,
            op.dst_port,
            op.guest_port,
            &op.buf[..n],
        );
        let (dst_ip, guest_ip) = (op.dst_ip, op.guest_ip);
        self.wrap_and_inject(dst_ip, guest_ip, IP_PROTO_UDP);
        if let Some(f) = self.udp.get_mut(&key) {
            f.last_use = now;
        }
        let buf = &op.wsabuf as *const WSABUF;
        let ovl = &mut op.overlapped as *mut OVERLAPPED;
        let sock = op.sock;
        let posted = unsafe { sys::wsa_recv(sock, buf, 1, ovl) };
        if !posted {
            // Re-arm failed synchronously: no further completion will arrive, so
            // reap now (the op is not in flight).
            self.reap_udp(key);
        }
    }

    fn handle_tcp(&mut self, ip: &Ipv4View) {
        let Some(tcp) = parse_tcp(ip.payload) else {
            return;
        };
        let key = (ip.src, tcp.src_port, ip.dst, tcp.dst_port);
        let syn_only = tcp.flags & (TCP_SYN | TCP_ACK | TCP_RST) == TCP_SYN;
        let now = self.now();
        let Some(flow) = self.tcp.get_mut(&key) else {
            if syn_only {
                self.open_tcp_flow(key, ip, &tcp);
            } else if tcp.flags & TCP_RST == 0 {
                self.reset_stray(ip, &tcp);
            }
            return;
        };
        if flow.syn_len > 0 {
            // The host connect is still pending, so the guest has had no
            // SYN-ACK: it can only be retransmitting its SYN (keep the latest,
            // for its timestamp) or giving up.
            if tcp.flags & TCP_RST != 0 {
                self.begin_teardown(key);
            } else if syn_only && ip.datagram.len() <= TCP_BUF {
                flow.send_op.as_mut().unwrap().buf[..ip.datagram.len()]
                    .copy_from_slice(ip.datagram);
                flow.syn_len = ip.datagram.len();
                flow.syn_csum_trusted = self.l4_csum_trusted;
            }
            return;
        }
        flow.tcb.as_mut().unwrap().set_now(now);
        let tcb = flow.tcb.as_mut().unwrap();
        let _ = if self.l4_csum_trusted {
            tcb.inject_packet_l4_csum_trusted(ip.datagram)
        } else {
            tcb.inject_packet(ip.datagram)
        };
        flow.last_activity = now;
        self.tcp_drive(key);
    }

    /// A guest SYN for a new connection: create the flow and start the host
    /// connect, or refuse.
    fn open_tcp_flow(&mut self, key: FlowKey, ip: &Ipv4View, tcp: &TcpView) {
        // Own the key before creating the flow, so the guest's later segments
        // are routed here; if another shard has it, that shard gets the
        // guest's next SYN instead.
        if !self.claim_flow(&key) {
            return;
        }
        // At capacity (or socket setup failed): refuse with a RST so the
        // guest's connect() fails fast instead of retrying for ~minutes.
        if self.flows.tcp.load(Ordering::Relaxed) >= MAX_TCP_FLOWS
            || self.new_tcp_flow(key, ip.datagram).is_none()
        {
            self.refuse_syn(key, tcp.seq);
            self.release_flow(&key);
        }
    }

    /// Refuse the guest SYN with sequence number `seq` on `key`: the guest's
    /// connect() fails with ECONNREFUSED.
    fn refuse_syn(&mut self, key: FlowKey, seq: u32) {
        let (gip, gport, dip, dport) = key;
        build_tcp_rst_for_syn_into(&mut self.l3_scratch, gip, gport, dip, dport, seq);
        self.wrap_and_inject(dip, gip, IP_PROTO_TCP);
    }

    /// Answer a guest segment that belongs to no flow (one the NAT has closed,
    /// or never had) with a RST, as a host without that connection would (RFC
    /// 9293 §3.10.7.1), so the guest drops its side rather than retransmitting
    /// into silence until it times out.
    fn reset_stray(&mut self, ip: &Ipv4View, tcp: &TcpView) {
        let data = ip.payload.len().saturating_sub(tcp.hdr_len);
        let (seq, ack, flags) = reset_for(tcp, data);
        build_tcp_into(
            &mut self.l3_scratch,
            ip.dst,
            ip.src,
            tcp.dst_port,
            tcp.src_port,
            seq,
            ack,
            flags,
            0,
        );
        self.wrap_and_inject(ip.dst, ip.src, IP_PROTO_TCP);
    }

    /// Create the flow for guest SYN `syn` and start the host connect. The
    /// TCB stays in LISTEN, and `syn` waits in the send op's buffer, until
    /// the host connect completes ([`Self::on_tcp_connect`]): the guest's
    /// connect() succeeds only if the host's does, and is refused otherwise.
    fn new_tcp_flow(&mut self, key: FlowKey, syn: &[u8]) -> Option<()> {
        if syn.len() > TCP_BUF {
            return None;
        }
        let (gip, gport, dip, dport) = key;
        let iss = self.next_iss();
        let now = self.now();
        let cfg = TcbConfig {
            local: Endpoint {
                ip: dip,
                port: dport,
            },
            remote: Endpoint {
                ip: gip,
                port: gport,
            },
            iss,
            initial_rto_ms: 1000,
        };
        // Set up the host socket first so an early failure needs no pool cleanup.
        let sock = sys::new_tcp_socket()?;
        if !sys::bind_any(sock) {
            sys::close_sock(sock);
            return None;
        }
        if !sys::associate(self.iocp, sock, KEY_TCP) {
            sys::close_sock(sock);
            return None;
        }
        // Acquire a Tcb of the chosen size-tier plus the overlapped ops, all
        // from preallocated pools, and arm them for this connection.
        let tier = self.choose_tier(dport);
        let csum_offload = self.rx_csum_ok();
        let mut tcb = self.tcb_pools[tier].acquire();
        tcb.reinit(cfg);
        tcb.set_secret(&self.tcb_secret);
        tcb.set_now(now);
        tcb.set_tx_csum_offload(csum_offload);
        if tcb.listen().is_err() {
            self.tcb_pools[tier].release(tcb);
            sys::close_sock(sock);
            return None;
        }
        let mut op = self.tcp_op_pool.acquire();
        op.overlapped = unsafe { core::mem::zeroed() };
        op.kind = 0;
        op.key = key;
        let mut send_op = self.tcp_send_op_pool.acquire();
        send_op.overlapped = unsafe { core::mem::zeroed() };
        send_op.kind = 2;
        send_op.key = key;
        send_op.buf[..syn.len()].copy_from_slice(syn);
        let ovl = &mut op.overlapped as *mut OVERLAPPED;
        // Slirp convention: connections to the gateway IP target the host
        // loopback (so the guest can reach host-local services at 10.0.0.1:*).
        // The remap applies ONLY to the host-side ConnectEx — the guest-facing
        // Tcb keeps the original `dip` so its packets carry the address the
        // guest expects.
        let host_dip = if dip == self.gw_ip {
            [127, 0, 0, 1]
        } else {
            dip
        };
        let started = unsafe { sys::connect_ex(sock, host_dip, dport, ovl) };
        if !started {
            sys::close_sock(sock);
            self.tcb_pools[tier].release(tcb);
            self.tcp_op_pool.release(op);
            self.tcp_send_op_pool.release(send_op);
            return None;
        }
        self.stats.tcp_flows.fetch_add(1, Ordering::Relaxed);
        self.tcp.insert(
            key,
            TcpFlow {
                tcb: Some(tcb),
                tier,
                sock,
                op: Some(op),
                send_op: Some(send_op),
                connected: false,
                connect_pending: true,
                recv_pending: false,
                send_inflight: false,
                pending_to_host: Vec::new(),
                closing: false,
                want_shutdown: false,
                shutdown_done: false,
                dead: false,
                created_at: now,
                last_activity: now,
                diag: FlowDiag::default(),
                published: Losses::default(),
                rx_blocked: false,
                csum_offload,
                syn_len: syn.len(),
                syn_csum_trusted: self.l4_csum_trusted,
            },
        );
        self.flows.tcp.fetch_add(1, Ordering::Relaxed);
        Some(())
    }

    /// Pick a free gateway-side ephemeral port for an inbound flow and claim
    /// the resulting key for this shard, so the guest's replies are routed
    /// here. Returns None if none found.
    fn alloc_ephem_port(&mut self, guest_ip: [u8; 4], guest_port: u16) -> Option<u16> {
        for _ in 0..64 {
            let p = 49152u16 + (self.next_iss() % 16384) as u16;
            let key = (guest_ip, guest_port, self.gw_ip, p);
            if !self.tcp.contains_key(&key) && self.claim_flow(&key) {
                return Some(p);
            }
        }
        None
    }

    /// Claim `key` for this shard in the flow router (only multi-shard NATs
    /// route by it); false if another shard owns it.
    fn claim_flow(&self, key: &FlowKey) -> bool {
        self.shards == 1 || self.router.claim(key, self.shard)
    }

    /// Drop this shard's flow-router entry for a flow it no longer has.
    fn release_flow(&self, key: &FlowKey) {
        if self.shards > 1 {
            self.router.release(key, self.shard);
        }
    }

    /// After handling a guest frame: a SYN routed here that left no flow (it
    /// was malformed or refused, or another shard owns its key) must not keep
    /// a router entry, or the table would grow with every such SYN.
    fn settle_route(&self, frame: &[u8]) {
        if self.shards > 1
            && let (_, Some((key, true))) = shard_of_frame(frame, self.shards)
            && !self.tcp.contains_key(&key)
        {
            self.router.release(&key, self.shard);
        }
    }

    /// Create an inbound (port-forwarded) flow: the host already accepted a
    /// client (`host_sock`), and we originate an active-open TCB toward the
    /// guest server. Reuses the normal TcpFlow data path; the only differences
    /// from an outbound flow are tcb.connect() (vs listen) and that the host
    /// socket is already connected.
    fn new_inbound_flow(&mut self, host_sock: SOCKET, guest_ip: [u8; 4], guest_port: u16) {
        if self.flows.tcp.load(Ordering::Relaxed) >= MAX_TCP_FLOWS {
            sys::close_sock(host_sock);
            return;
        }
        let Some(ephem) = self.alloc_ephem_port(guest_ip, guest_port) else {
            sys::close_sock(host_sock);
            return;
        };
        let key = (guest_ip, guest_port, self.gw_ip, ephem);
        let iss = self.next_iss();
        let now = self.now();
        let cfg = TcbConfig {
            local: Endpoint {
                ip: self.gw_ip,
                port: ephem,
            },
            remote: Endpoint {
                ip: guest_ip,
                port: guest_port,
            },
            iss,
            initial_rto_ms: 1000,
        };
        // Acquire a Tcb of the chosen tier and actively open it toward the guest.
        let tier = self.choose_tier(guest_port);
        let csum_offload = self.rx_csum_ok();
        let mut tcb = self.tcb_pools[tier].acquire();
        tcb.reinit(cfg);
        tcb.set_secret(&self.tcb_secret);
        tcb.set_now(now);
        tcb.set_tx_csum_offload(csum_offload);
        if tcb.connect().is_err() {
            // active open: emits a SYN toward the guest
            self.tcb_pools[tier].release(tcb);
            self.release_flow(&key);
            sys::close_sock(host_sock);
            return;
        }
        if !sys::associate(self.iocp, host_sock, KEY_TCP) {
            self.tcb_pools[tier].release(tcb);
            self.release_flow(&key);
            sys::close_sock(host_sock);
            return;
        }
        if sys::peer_is_local(host_sock) {
            sys::set_rcvbuf(host_sock, LOCAL_PEER_RCVBUF);
        }
        let mut op = self.tcp_op_pool.acquire();
        op.overlapped = unsafe { core::mem::zeroed() };
        op.kind = 0;
        op.key = key;
        let mut send_op = self.tcp_send_op_pool.acquire();
        send_op.overlapped = unsafe { core::mem::zeroed() };
        send_op.kind = 2;
        send_op.key = key;
        self.stats.tcp_flows.fetch_add(1, Ordering::Relaxed);
        self.tcp.insert(
            key,
            TcpFlow {
                tcb: Some(tcb),
                tier,
                sock: host_sock,
                op: Some(op),
                send_op: Some(send_op),
                connected: true, // host side is already connected (accepted)
                connect_pending: false,
                recv_pending: false,
                send_inflight: false,
                pending_to_host: Vec::new(),
                closing: false,
                want_shutdown: false,
                shutdown_done: false,
                dead: false,
                created_at: now,
                last_activity: now,
                diag: FlowDiag::default(),
                published: Losses::default(),
                rx_blocked: false,
                csum_offload,
                syn_len: 0,
                syn_csum_trusted: false,
            },
        );
        self.flows.tcp.fetch_add(1, Ordering::Relaxed);
        // Emit the SYN toward the guest and arm the host receive.
        self.tcp_drive(key);
    }

    fn on_tcp_connect(&mut self, op_ptr: *mut TcpOp, ok: bool) {
        let key = unsafe { (*op_ptr).key };
        let now = self.now();
        let mut dead = false;
        let mut refused = None;
        if let Some(flow) = self.tcp.get_mut(&key) {
            flow.connect_pending = false;
            if flow.dead {
                dead = true;
            } else if !ok {
                // Refused, unreachable or timed out: the guest's connect()
                // fails as it would have against the destination itself.
                refused = flow.take_syn_seq();
            } else {
                sys::update_connect_ctx(flow.sock);
                if sys::peer_is_local(flow.sock) {
                    sys::set_rcvbuf(flow.sock, LOCAL_PEER_RCVBUF);
                }
                flow.connected = true;
                flow.last_activity = now;
                // The guest's handshake gets its own TCP_CONNECT_MS.
                flow.created_at = now;
                // Now answer the guest's SYN, checked as it arrived.
                let TcpFlow {
                    tcb,
                    send_op,
                    syn_len,
                    syn_csum_trusted,
                    ..
                } = flow;
                let tcb = tcb.as_mut().unwrap();
                tcb.set_now(now);
                let syn = &send_op.as_ref().unwrap().buf[..std::mem::take(syn_len)];
                let _ = if *syn_csum_trusted {
                    tcb.inject_packet_l4_csum_trusted(syn)
                } else {
                    tcb.inject_packet(syn)
                };
            }
        }
        if dead {
            // The flow was torn down while ConnectEx was in flight; this was
            // the last outstanding op, so reap now.
            self.reap_if_idle(key);
            return;
        }
        if !ok {
            if let Some(seq) = refused {
                self.refuse_syn(key, seq);
            }
            self.begin_teardown(key);
            return;
        }
        // Send the SYN-ACK; the guest's data follows the handshake.
        self.tcp_drive(key);
    }

    fn on_tcp_recv(&mut self, op_ptr: *mut TcpOp, ok: bool, bytes: u32) {
        let key = unsafe { (*op_ptr).key };
        let now = self.now();
        let mut dead = false;
        let mut reset = false;
        if let Some(flow) = self.tcp.get_mut(&key) {
            flow.recv_pending = false;
            if let Some(t) = flow.diag.recv_posted.take() {
                flow.diag.last_recv_wait_ms = t.elapsed().as_millis() as u64;
            }
            if flow.dead {
                // The recv is done writing the lent ring space: end the loan.
                let _ = flow.tcb.as_mut().unwrap().send_commit(0);
                dead = true;
            } else {
                let tcb = flow.tcb.as_mut().unwrap();
                tcb.set_now(now);
                if !ok {
                    // The host connection was reset or failed: reset the
                    // guest's too. Passing it on as EOF would make a cut-off
                    // stream look complete.
                    let _ = tcb.send_commit(0);
                    reset = true;
                } else if bytes == 0 {
                    let _ = tcb.send_commit(0);
                    on_host_eof(flow);
                } else {
                    // The recv landed in the tcb's send ring: append it to the
                    // stream. This fails only if the guest connection closed
                    // or reset meanwhile, when the bytes have nowhere to go.
                    let _ = tcb.send_commit(bytes as usize);
                    flow.last_activity = now;
                }
            }
        }
        if dead {
            self.reap_if_idle(key);
            return;
        }
        if reset {
            self.abort_flow(key);
            return;
        }
        self.tcp_drive(key);
    }

    fn on_tcp_send(&mut self, op_ptr: *mut TcpSendOp, ok: bool, bytes: u32) {
        let key = unsafe { (*op_ptr).key };
        let now = self.now();
        let mut dead = false;
        let mut failed = false;
        if let Some(flow) = self.tcp.get_mut(&key) {
            flow.send_inflight = false;
            if flow.dead {
                dead = true;
            } else if !ok {
                failed = true;
            } else {
                // The completed op is this flow's send_op, so read it through
                // the safe borrow. Overlapped stream sends normally transfer
                // the whole request; requeue any short tail at the front to
                // preserve byte order.
                let req = flow.send_op.as_ref().unwrap().wsabuf.len as usize;
                let sent = (bytes as usize).min(req);
                if sent < req {
                    // Requeue the unsent tail at the front (disjoint fields, no
                    // temporary Vec).
                    let tail = flow.send_op.as_ref().unwrap().buf[sent..req]
                        .iter()
                        .copied();
                    flow.pending_to_host.splice(0..0, tail);
                }
                flow.last_activity = now;
            }
        }
        if dead {
            self.reap_if_idle(key);
            return;
        }
        if failed {
            // The host connection broke: reset the guest's.
            self.abort_flow(key);
            return;
        }
        // Post the next chunk and make any other progress (re-arm recv, etc.).
        self.tcp_drive(key);
    }

    /// The NIC drained its RX backlog: drive every flow that paused on it, in
    /// pause order. Each drive runs until the backlog fills again, so rotate
    /// the re-paused list to let a different flow go first next time.
    fn resume_rx_blocked(&mut self) {
        let spare = std::mem::take(&mut self.rx_spare);
        let mut keys = std::mem::replace(&mut self.rx_blocked, spare);
        for key in &keys {
            if let Some(f) = self.tcp.get_mut(key) {
                f.rx_blocked = false;
            }
        }
        for &key in &keys {
            self.tcp_drive(key);
        }
        if self.rx_blocked.len() > 1 {
            self.rx_blocked.rotate_left(1);
        }
        keys.clear();
        self.rx_spare = keys;
    }

    fn tcp_drive(&mut self, key: FlowKey) {
        let gw = self.gw_mac;
        let gm = self.guest_mac;
        let now = self.now();
        let dev = self.net.upgrade();
        let gso_ok = dev.as_ref().is_some_and(|d| d.rx_gso_ok());
        let csum_ok = dev.as_ref().is_some_and(|d| d.rx_csum_ok());
        let mut scratch = std::mem::take(&mut self.tx_scratch);
        let mut teardown = false;
        let mut finished = false;
        let mut reset = false;
        if let Some(flow) = self.tcp.get_mut(&key) {
            if flow.dead {
                self.tx_scratch = scratch;
                return;
            }
            // Segments built here carry this time (timestamps, RTT samples,
            // loss timers); some callers (host send completion, RX-space
            // resume) arrive without having set it.
            flow.tcb.as_mut().unwrap().set_now(now);
            // Follow the guest if it renegotiated checksum offload.
            if flow.csum_offload != csum_ok {
                flow.csum_offload = csum_ok;
                flow.tcb.as_mut().unwrap().set_tx_csum_offload(csum_ok);
            }
            let offload = flow.csum_offload;
            // Drain the tcb's egress queue, coalescing consecutive data segments
            // into one GSO super-frame so the guest's TCP stack processes 1 skb
            // per ~64 KiB instead of ~45 per-MSS skbs (the ~207 MB/s ceiling was
            // the guest CPU at ~148 K segments/s). SYN/FIN/RST and pure-ACK
            // segments are delivered standalone; out-of-order or cap-overflow
            // flushes the accumulated batch first.
            //
            // `Tcb::send` only fills the send ring; staging into the 32-slot
            // egress ring happens in `maybe_send_data`, which `tick()` drives.
            // The outer loop pumps extract→tick until a tick stages nothing,
            // so one `tcp_drive` drains the whole send ring (not just 32 segs).
            let gso = &mut self.gso;
            // Drain the tcb receive ring into the guest->host queue before
            // pumping egress, so the window update `recv` queues once space
            // frees leaves in this same drive (the guest sender may be stalled
            // on our window). Stop at the cap so a slow host send keeps the
            // guest window closed (backpressure) instead of buffering without
            // bound.
            if flow.tcb.as_ref().unwrap().poll() & EV_READABLE != 0 {
                let rb = &mut self.drain_scratch;
                while flow.pending_to_host.len() < TO_HOST_CAP {
                    match flow.tcb.as_mut().unwrap().recv(rb) {
                        Ok(0) => break,
                        Ok(n) => flow.pending_to_host.extend_from_slice(&rb[..n]),
                        Err(_) => break,
                    }
                }
            }
            let diag = crate::diag::net_enabled();
            let mut data_out = false;
            let mut rx_paused = false;
            let mut ticked = false;
            'pump: loop {
                // Deliver everything already staged, even into a deep backlog:
                // it was built for now (ACK, window, timestamp, loss timers),
                // and held in the egress ring it would go stale — the tail
                // draws a spurious tail-loss probe after one PTO, a hold past
                // the RTO collapses cwnd, and the hold inflates the RTT sample.
                // Each datagram is lent straight out of the TCB's egress ring.
                let mut any = false;
                while flow
                    .tcb
                    .as_mut()
                    .unwrap()
                    .extract_packet_with(&mut |dgram| {
                        if diag && !data_out {
                            data_out =
                                split_tcp_dgram(dgram).is_some_and(|(_, p, _, _)| !p.is_empty());
                        }
                        let seg = split_tcp_dgram(dgram).filter(|&(_, pay, _, flags)| {
                            gso_ok && !pay.is_empty() && flags & (TCP_SYN | TCP_FIN | TCP_RST) == 0
                        });
                        if let Some((hdr, pay, seq, _)) = seg {
                            if gso.payload_len() > 0 && !gso.extends(seq, pay.len()) {
                                gso.flush(dev.as_deref(), gm, gw);
                            }
                            gso.push(hdr, pay, seq);
                            return;
                        }
                        gso.flush(dev.as_deref(), gm, gw);
                        if let Some(d) = &dev {
                            build_eth_into(&mut scratch, gm, gw, ETHERTYPE_IPV4, dgram);
                            if offload {
                                // The TCB left the TCP checksum for the guest.
                                let ihl = (dgram[0] & 0x0F) as usize * 4;
                                let vhdr = RxHeader {
                                    flags: HDR_F_NEEDS_CSUM,
                                    csum_start: (ETH_HDR + ihl) as u16,
                                    csum_offset: 16,
                                    ..Default::default()
                                };
                                d.inject_rx_gso_batched(&scratch, vhdr);
                            } else {
                                d.inject_rx_gso_batched(&scratch, RxHeader::default());
                            }
                        }
                    })
                {
                    any = true;
                }
                if ticked && !any {
                    break 'pump;
                }
                // Backpressure (like TCP Small Queues): while the guest's RX
                // backlog is deep, the TCB builds nothing more, so nothing
                // ages in its egress ring. Its rings fill, which closes the
                // host-recv side too (`maybe_post_recv`); the NIC wakes us via
                // KEY_RX_SPACE once the guest has taken the backlog.
                let congested = dev.as_ref().is_some_and(|d| d.rx_congested());
                flow.tcb.as_mut().unwrap().set_egress_paused(congested);
                if congested {
                    rx_paused = true;
                    break 'pump;
                }
                let _ = flow.tcb.as_mut().unwrap().tick();
                ticked = true;
            } // 'pump
            gso.flush(dev.as_deref(), gm, gw);
            if rx_paused && !flow.rx_blocked {
                flow.rx_blocked = true;
                self.rx_blocked.push(key);
            }
            if data_out {
                note_data_out(&mut flow.diag, key, self.wake, &self.stats);
            }
            let ev = flow.tcb.as_ref().unwrap().poll();
            if ev & EV_PEER_CLOSED != 0 && !flow.shutdown_done {
                flow.want_shutdown = true;
            }
            if ev & (EV_CLOSED | EV_ERROR) != 0 {
                teardown = true;
            }
            if !teardown && !pump_send(flow) {
                teardown = true;
            }
            if !teardown && !maybe_post_recv(flow) {
                teardown = true;
            }
            finished = !teardown && flow.lingering();
            // A host-side failure tears down a guest connection that is still
            // open: it gets a RST.
            reset = teardown && flow.tcb.as_ref().unwrap().state() != State::Closed;
        }
        self.tx_scratch = scratch;
        if reset {
            self.abort_flow(key);
        } else if teardown || finished {
            self.begin_teardown(key);
        }
    }

    /// Give up on a live flow and tell the guest: a guest SYN still waiting on
    /// the host connect is refused; an open connection gets a RST. Then tear
    /// the flow down.
    fn abort_flow(&mut self, key: FlowKey) {
        let Some(flow) = self.tcp.get_mut(&key) else {
            return;
        };
        if flow.dead {
            return;
        }
        if flow.syn_len > 0 {
            if let Some(seq) = flow.take_syn_seq() {
                self.refuse_syn(key, seq);
            }
            self.begin_teardown(key);
            return;
        }
        if flow.tcb.as_mut().unwrap().abort().is_ok() {
            // Deliver the RST `abort` queued; the drive then sees the TCB
            // closed and tears the flow down.
            self.tcp_drive(key);
        } else {
            // No room to queue the RST (the egress ring is emptied by every
            // drive, so not expected): go without it.
            self.begin_teardown(key);
        }
    }

    /// Begin tearing a flow down: close the host socket once (which aborts any
    /// pending overlapped ops so their completions drain), then reap. The
    /// TcpFlow (and its op buffers) stay alive until every outstanding op has
    /// completed, so the kernel never touches freed memory.
    fn begin_teardown(&mut self, key: FlowKey) {
        if let Some(flow) = self.tcp.get_mut(&key)
            && !flow.dead
        {
            flow.dead = true;
            if flow.sock != INVALID_SOCKET {
                sys::close_sock(flow.sock);
                flow.sock = INVALID_SOCKET;
            }
        }
        self.reap_if_idle(key);
    }

    fn reap_if_idle(&mut self, key: FlowKey) {
        let reap = self
            .tcp
            .get(&key)
            .map(|f| f.dead && !f.recv_pending && !f.send_inflight && !f.connect_pending)
            .unwrap_or(false);
        if reap && let Some(mut f) = self.tcp.remove(&key) {
            self.flows.tcp.fetch_sub(1, Ordering::Relaxed);
            self.release_flow(&key);
            // The socket was already closed by begin_teardown and all ops
            // have drained, so recycle the pooled Tcb (into its size-tier)
            // and the overlapped op buffers via take(); TcpFlow::drop then
            // closes the socket (a no-op — already INVALID) and the Drop-bomb
            // confirms every box was reclaimed.
            let tier = f.tier;
            publish_tcb_stats(&mut f, &self.stats);
            if crate::diag::net_enabled() && f.published != Losses::default() {
                let rtt = f.tcb.as_ref().map_or(0, |t| t.stats().min_rtt_ms);
                eprintln!(
                    "[nat] {} closed (min rtt {rtt} ms): {:?}",
                    fmt_flow(key),
                    f.published
                );
            }
            if let Some(tcb) = f.tcb.take() {
                self.tcb_pools[tier].release(tcb);
            }
            if let Some(op) = f.op.take() {
                self.tcp_op_pool.release(op);
            }
            if let Some(send_op) = f.send_op.take() {
                self.tcp_send_op_pool.release(send_op);
            }
        }
    }

    /// Periodic idle sweep (runs every EXPIRE_GATE_MS): reap idle UDP NAT
    /// entries, and reset stuck or idle TCP flows (connect-deadline, idle, and
    /// half-close watchdogs). Mirrors the C++ backend's ExpireIdle + the TSI
    /// engine's per-conn watchdogs.
    fn expire_idle(&mut self, now: u64) {
        // UDP: reap entries idle longer than UDP_IDLE_MS. Marking dead +
        // closing the socket aborts the pending recv; on_udp_recv frees it.
        let udp_dead: Vec<FlowKey> = self
            .udp
            .iter()
            .filter(|(_, f)| !f.dead && now.saturating_sub(f.last_use) > UDP_IDLE_MS)
            .map(|(k, _)| *k)
            .collect();
        for k in udp_dead {
            if let Some(f) = self.udp.get_mut(&k) {
                f.dead = true;
                let op = f.op.as_mut().unwrap();
                if op.sock != INVALID_SOCKET {
                    sys::close_sock(op.sock);
                    op.sock = INVALID_SOCKET;
                }
            }
        }

        // TCP: collect flows that tripped a watchdog, then reset them.
        let tcp_victims: Vec<FlowKey> = self
            .tcp
            .iter()
            .filter(|(_, f)| {
                if f.dead {
                    return false;
                }
                let idle = now.saturating_sub(f.last_activity);
                let st = f.tcb.as_ref().unwrap().state();
                let half = matches!(
                    st,
                    State::FinWait1
                        | State::FinWait2
                        | State::Closing
                        | State::CloseWait
                        | State::LastAck
                );
                // Establishment watchdog: fire if the host connect hasn't
                // completed (outbound; the guest's SYN is then refused) or,
                // since it did, the TCB hasn't reached a synchronized state
                // (also covers an inbound flow whose guest never accepts).
                let establishing = !f.connected || !st.is_synchronized();
                (establishing && now.saturating_sub(f.created_at) > TCP_CONNECT_MS)
                    || (half && idle > TCP_HALF_CLOSE_MS)
                    || (idle > TCP_IDLE_MS)
            })
            .map(|(k, _)| *k)
            .collect();
        for k in tcp_victims {
            self.abort_flow(k);
        }
    }

    fn tcp_tick(&mut self) {
        if self.tcp.is_empty() {
            return;
        }
        let now = self.now();
        let mut keys = std::mem::take(&mut self.tick_keys);
        keys.clear();
        keys.extend(self.tcp.keys().copied());
        for &key in &keys {
            let mut tick = false;
            if let Some(flow) = self.tcp.get_mut(&key)
                && !flow.dead
            {
                flow.tcb.as_mut().unwrap().set_now(now);
                let _ = flow.tcb.as_mut().unwrap().tick();
                publish_tcb_stats(flow, &self.stats);
                tick = true;
            }
            if tick {
                self.tcp_drive(key);
            }
        }
        keys.clear();
        self.tick_keys = keys;
    }
}

/// One worker thread and the IOCP its flows' sockets complete to.
struct Shard {
    iocp: Iocp,
    worker: Mutex<Option<JoinHandle<()>>>,
}

pub struct NatBackend {
    /// Empty when the NAT could not start (no IOCP).
    shards: Vec<Shard>,
    router: Arc<FlowRouter>,
    icmp: Option<Arc<IcmpPool>>,
    icmp_workers: Mutex<Vec<JoinHandle<()>>>,
    listeners: Mutex<Vec<SOCKET>>,
    listener_threads: Mutex<Vec<JoinHandle<()>>>,
    pool: Arc<FramePool<FRAME_CAP>>,
    big_pool: Arc<FramePool<TX_FRAME_CAP>>,
    stats: Arc<NatStats>,
}

impl NatBackend {
    pub fn new(net: &Arc<NetDevice>, opts: NatOptions) -> Arc<Self> {
        sys::wsa_startup();
        let pool = Arc::new(FramePool::new(POOL_SLOTS));
        let big_pool = Arc::new(FramePool::new(BIG_POOL_SLOTS));
        let stats = Arc::new(NatStats::default());
        let n = opts.workers.clamp(1, MAX_WORKERS);
        let iocps: Option<Vec<Iocp>> = (0..n).map(|_| sys::create_iocp()).collect();
        let Some(iocps) = iocps else {
            eprintln!("[nat] CreateIoCompletionPort failed; NAT disabled");
            return Arc::new(NatBackend {
                shards: Vec::new(),
                router: Arc::new(FlowRouter::new(1)),
                icmp: None,
                icmp_workers: Mutex::new(Vec::new()),
                listeners: Mutex::new(Vec::new()),
                listener_threads: Mutex::new(Vec::new()),
                pool,
                big_pool,
                stats,
            });
        };
        // Cross-thread message pools: producer threads (listeners / ICMP
        // workers) acquire+fill, the NAT workers release. Warmed lightly; they
        // grow on demand and recycle, so steady state is allocation-free.
        let accept_pool = Arc::new(SyncBoxPool::new(32, make_accept_msg));
        let accept_inflight = Arc::new(AtomicUsize::new(0));
        let icmp_reply_pool = Arc::new(SyncBoxPool::new(MAX_ICMP_INFLIGHT, make_icmp_reply));
        // Precreate the ICMP echo worker pool (blocking IcmpSendEcho threads).
        // ICMP is handled by the first shard, so replies complete there.
        let icmp = Arc::new(IcmpPool::new(iocps[0], icmp_reply_pool.clone()));
        let mut icmp_workers = Vec::with_capacity(ICMP_WORKERS);
        for i in 0..ICMP_WORKERS {
            let pool = icmp.clone();
            if let Ok(h) = std::thread::Builder::new()
                .name(format!("nat-icmp-{i}"))
                .spawn(move || pool.worker())
            {
                icmp_workers.push(h);
            }
        }
        // Start a listener (+ accept thread) for each port-forward rule. The
        // accept thread blocks in accept() and hands each connected client to
        // a worker via its IOCP (KEY_ACCEPT), round-robin; closing the
        // listener socket on shutdown unblocks it.
        let mut listeners = Vec::new();
        let mut listener_threads = Vec::new();
        for pf in &opts.port_forwards {
            let Some(lsock) = sys::new_tcp_listener(pf.host_addr, pf.host_port) else {
                eprintln!(
                    "[nat] port-forward listen on {:?}:{} failed",
                    pf.host_addr, pf.host_port
                );
                continue;
            };
            listeners.push(lsock);
            let pf = *pf;
            let ap = accept_pool.clone();
            let ai = accept_inflight.clone();
            let targets = iocps.clone();
            if let Ok(h) = std::thread::Builder::new()
                .name(format!("nat-listen-{}", pf.host_port))
                .spawn(move || listener_loop(lsock, &targets, pf, ap, ai))
            {
                listener_threads.push(h);
            }
        }
        let default_tier = if opts.default_tier < N_TCB_TIERS {
            opts.default_tier
        } else {
            DEFAULT_TIER
        };
        let mut port_tier = HashMap::new();
        for &(port, tier) in &opts.tcb_port_tier {
            if tier < N_TCB_TIERS {
                port_tier.insert(port, tier);
            }
        }
        let mut tcb_secret = [0u8; 16];
        if !host::random_fill(&mut tcb_secret) {
            panic!("nat: BCryptGenRandom failed (Tcb secret)");
        }
        let flows = Arc::new(FlowCounts::default());
        let router = Arc::new(FlowRouter::new(n));
        let mut shards = Vec::with_capacity(n);
        for (s, &iocp) in iocps.iter().enumerate() {
            // Worker-only object pools: one Tcb free-list per compile-time
            // tier, plus the overlapped op buffers. Each worker warms its own
            // share before serving completions, so VM start does not wait for
            // tens of MiB of ring buffers to be zeroed.
            let tcb_pools: Vec<BoxPool<dyn TcbDyn>> = (0..N_TCB_TIERS)
                .map(|i| BoxPool::new(0, TIER_MAKE[i]))
                .collect();
            let tcb_warm: [usize; N_TCB_TIERS] =
                std::array::from_fn(|i| opts.tcb_warm[i].div_ceil(n));
            let state = NatState {
                net: Arc::downgrade(net),
                iocp,
                shard: s,
                shards: n,
                router: router.clone(),
                flows: flows.clone(),
                gw_ip: opts.gateway_ip,
                gw_mac: opts.gateway_mac,
                guest_mac: net.mac(),
                udp: HashMap::new(),
                tcp: HashMap::new(),
                icmp: icmp.clone(),
                pool: pool.clone(),
                big_pool: big_pool.clone(),
                l4_csum_trusted: false,
                tcb_pools,
                tcp_op_pool: BoxPool::new(0, make_tcp_op),
                tcp_send_op_pool: BoxPool::new(0, make_tcp_send_op),
                udp_op_pool: BoxPool::new(0, make_udp_op),
                accept_pool: accept_pool.clone(),
                accept_inflight: accept_inflight.clone(),
                icmp_reply_pool: icmp_reply_pool.clone(),
                default_tier,
                port_tier: port_tier.clone(),
                start: Instant::now(),
                // Distinct non-zero xorshift seeds per shard.
                rng: 0x2545_F491 ^ (s as u32).wrapping_mul(0x9E37_79B9),
                tcb_secret,
                last_tick: 0,
                last_expire: 0,
                tick_keys: Vec::new(),
                rx_blocked: Vec::new(),
                rx_spare: Vec::new(),
                tx_scratch: Vec::with_capacity(GSO_FRAME_CAP),
                l3_scratch: Vec::with_capacity(FRAME_CAP),
                gso: GsoFrame::new(),
                drain_scratch: vec![0; 16384],
                wake: Wake::Other,
                stats: stats.clone(),
            };
            // With `heap-buffers` the Tcb rings are boxed, so a Tcb is no
            // longer a multi-MiB stack temporary. Workers still get a generous
            // stack for deep frames.
            let name = if n == 1 {
                "nat-worker".to_string()
            } else {
                format!("nat-worker-{s}")
            };
            let handle = std::thread::Builder::new()
                .name(name)
                .stack_size(16 * 1024 * 1024)
                .spawn(move || {
                    let mut state = state;
                    for (pool, count) in state.tcb_pools.iter_mut().zip(tcb_warm) {
                        pool.warm(count);
                    }
                    state.tcp_op_pool.warm(MAX_TCP_FLOWS.div_ceil(n));
                    state.tcp_send_op_pool.warm(MAX_TCP_FLOWS.div_ceil(n));
                    state.udp_op_pool.warm(MAX_UDP_FLOWS.div_ceil(n));
                    state.run()
                })
                .ok();
            shards.push(Shard {
                iocp,
                worker: Mutex::new(handle),
            });
        }
        Arc::new(NatBackend {
            shards,
            router,
            icmp: Some(icmp),
            icmp_workers: Mutex::new(icmp_workers),
            listeners: Mutex::new(listeners),
            listener_threads: Mutex::new(listener_threads),
            pool,
            big_pool,
            stats,
        })
    }
}

/// Accept loop for one port-forward listener; runs on its own thread. Hands
/// accepted clients to the workers in turn (`iocps`, one per shard).
fn listener_loop(
    lsock: SOCKET,
    iocps: &[Iocp],
    pf: PortForward,
    accept_pool: Arc<SyncBoxPool<AcceptMsg>>,
    accept_inflight: Arc<AtomicUsize>,
) {
    let mut next = 0usize;
    loop {
        let c = sys::accept_one(lsock);
        if c == INVALID_SOCKET {
            break; // listener closed for shutdown
        }
        // Bound accepted-but-undrained connections: a remote accept-flood is
        // dropped here (the client can retry) rather than piling up host sockets
        // and AcceptMsg boxes faster than the workers drain them.
        if accept_inflight.load(Ordering::Acquire) >= MAX_ACCEPT_INFLIGHT {
            sys::close_sock(c);
            continue;
        }
        accept_inflight.fetch_add(1, Ordering::AcqRel);
        let mut msg = accept_pool.acquire();
        msg.sock = c;
        msg.guest_ip = pf.guest_ip;
        msg.guest_port = pf.guest_port;
        let ptr = Box::into_raw(msg);
        let iocp = iocps[next % iocps.len()];
        next = next.wrapping_add(1);
        if !sys::post(iocp, 0, KEY_ACCEPT, ptr as *mut OVERLAPPED) {
            accept_inflight.fetch_sub(1, Ordering::AcqRel);
            accept_pool.release(unsafe { Box::from_raw(ptr) });
            sys::close_sock(c);
        }
    }
}

impl NatBackend {
    /// Copy `frame` into a slot of `pool` and post it, under `key`, to the
    /// worker that owns its flow. Returns false only if the pool is exhausted.
    fn post_frame<const CAP: usize>(
        &self,
        pool: &FramePool<CAP>,
        frame: &[u8],
        key: usize,
    ) -> bool {
        // Acquire a preallocated slot (no heap alloc on the hot path).
        let Some(idx) = pool.acquire() else {
            return false;
        };
        let n = pool.fill(idx, frame);
        let ptr = pool.slot_ptr(idx);
        let (hashed, tcp) = shard_of_frame(frame, self.shards.len());
        let (s, assigned) = match tcp {
            Some((key, syn)) => self.router.route(&key, syn),
            None => (hashed, false),
        };
        if !sys::post(self.shards[s].iocp, n as u32, key, ptr as *mut OVERLAPPED) {
            pool.release(idx);
            // The SYN that claimed a shard never got there.
            if let (true, Some((flow, _))) = (assigned, tcp) {
                self.router.release(&flow, s);
            }
        }
        true
    }

    fn tx_drop(frame: &[u8]) {
        if etw::enabled(etw::VERBOSE, etw::kw::NET) {
            etw::Event::new("NetTxDrop", etw::VERBOSE, etw::kw::NET)
                .u32("len", frame.len() as u32)
                .write();
        }
    }
}

impl NetBackend for NatBackend {
    fn on_guest_frame(&self, frame: &[u8]) {
        if self.shards.is_empty() || frame.is_empty() || frame.len() > FRAME_CAP {
            return;
        }
        // If the pool is exhausted, drop the frame (the guest will retransmit).
        if !self.post_frame(&self.pool, frame, KEY_FRAME) {
            self.stats.tx_drops.fetch_add(1, Ordering::Relaxed);
            Self::tx_drop(frame);
        }
    }

    /// The worker terminates guest TCP in a tcp-sans-io TCB, which accepts
    /// multi-MSS super-segments and (via the trusted inject) the unfinished
    /// checksum; guest UDP checksums are never verified (only the payload is
    /// forwarded). So offloaded frames are handed over as-is — no per-MSS
    /// segmentation and no 64 KiB checksum pass on the vCPU thread.
    fn on_guest_frame_offload(&self, frame: &mut [u8], hdr: &TxHeader) {
        if self.shards.is_empty() || frame.is_empty() {
            return;
        }
        let posted = if frame.len() <= FRAME_CAP {
            self.post_frame(&self.pool, frame, KEY_FRAME_OFFLOAD)
        } else {
            self.post_frame(&self.big_pool, frame, KEY_FRAME_OFFLOAD_BIG)
        };
        if !posted {
            // Big pool busy: segment in software into the small pool.
            tx_offload_software(frame, hdr, &mut |f| self.on_guest_frame(f));
        }
    }

    fn diag_summary(&self) -> Option<String> {
        Some(self.stats.summary())
    }

    /// The NIC's RX backlog drained: every worker resumes the flows it paused.
    fn on_rx_space(&self) {
        for s in &self.shards {
            sys::post(s.iocp, 0, KEY_RX_SPACE, std::ptr::null_mut());
        }
    }

    fn stop(&self) {
        // Close listener sockets to unblock their accept() threads, then join.
        for s in self.listeners.lock().unwrap().drain(..) {
            sys::close_sock(s);
        }
        for h in self.listener_threads.lock().unwrap().drain(..) {
            let _ = h.join();
        }
        // Signal the ICMP workers to wind down. We deliberately don't join
        // them: one may be blocked in IcmpSendEcho for up to ICMP_TIMEOUT_MS.
        // They observe `running=false` and exit on their own, and only ever
        // post to the (never-closed) IOCP, so abandoning them is safe and
        // keeps shutdown prompt.
        if let Some(icmp) = &self.icmp {
            icmp.stop();
        }
        self.icmp_workers.lock().unwrap().clear();
        for s in &self.shards {
            sys::post(s.iocp, 0, KEY_STOP, std::ptr::null_mut());
        }
        for s in &self.shards {
            if let Some(h) = s.worker.lock().unwrap().take() {
                let _ = h.join();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guest frames without a routed flow go to the shard of their key's hash
    /// (spread over the shards), anything but unfragmented TCP/UDP to shard 0,
    /// and a TCP flow's SYN assigns it to the shard with the fewest flows,
    /// which its later frames follow until the flow is released.
    #[test]
    fn frames_route_to_the_shard_that_owns_their_flow() {
        use crate::net::wire::{build_eth, build_ipv4, build_tcp};
        let guest = [10, 0, 0, 2];
        let host = [93, 184, 216, 34];
        let frame = |sport: u16, flags: u8, frag: bool| {
            let tcp = build_tcp(guest, host, sport, 443, 1, 0, flags, 512);
            let mut ip = build_ipv4(guest, host, IP_PROTO_TCP, &tcp);
            if frag {
                ip[6] |= 0x20; // more fragments
            }
            build_eth([2; 6], [4; 6], ETHERTYPE_IPV4, &ip)
        };
        for shards in [2usize, 3, 4] {
            let mut per = vec![0usize; shards];
            for sport in 40000u16..41000 {
                let (s, tcp) = shard_of_frame(&frame(sport, TCP_ACK, false), shards);
                assert_eq!(s, shard_of(&(guest, sport, host, 443), shards));
                assert_eq!(tcp, Some(((guest, sport, host, 443), false)));
                per[s] += 1;
            }
            assert!(per.iter().all(|&c| c * shards * 2 >= 1000), "{per:?}");
        }
        let sport = (40000u16..)
            .find(|&p| shard_of(&(guest, p, host, 443), 4) != 0)
            .unwrap();
        assert_eq!(
            shard_of_frame(&frame(sport, 0, true), 4),
            (0, None),
            "fragment"
        );
        let arp = build_eth([0xff; 6], [2; 6], ETHERTYPE_ARP, &[0u8; 28]);
        assert_eq!(shard_of_frame(&arp, 4), (0, None), "ARP");
        // A SYN whose IPv4 total length leaves no full TCP header is not a
        // TCP segment to the worker either: hash-routed, no router state.
        let mut short = frame(sport, TCP_SYN, false);
        short[ETH_HDR + 2..ETH_HDR + 4].copy_from_slice(&34u16.to_be_bytes());
        assert_eq!(shard_of_frame(&short, 4).1, None, "truncated SYN");

        // Eight SYNs spread two per shard over four shards, whatever their
        // hashes; later segments follow, only the owner can claim or release
        // a key, and a released flow is routed (and reassigned) afresh.
        let router = FlowRouter::new(4);
        let key = |p: u16| (guest, p, host, 443);
        let owners: Vec<usize> = (0..8).map(|p| router.route(&key(p), true).0).collect();
        for s in 0..4 {
            assert_eq!(owners.iter().filter(|&&o| o == s).count(), 2, "{owners:?}");
        }
        for (p, &o) in owners.iter().enumerate() {
            assert_eq!(router.route(&key(p as u16), false), (o, false));
        }
        let other = (owners[0] + 1) % 4;
        assert!(router.claim(&key(0), owners[0]), "the owner's own key");
        assert!(!router.claim(&key(0), other), "another shard's key");
        router.release(&key(0), other);
        assert_eq!(
            router.route(&key(0), false),
            (owners[0], false),
            "not the owner"
        );
        router.release(&key(0), owners[0]);
        assert_eq!(router.route(&key(0), false).0, shard_of(&key(0), 4));
        assert_eq!(
            router.route(&key(0), true),
            (owners[0], true),
            "the emptied shard"
        );
    }

    /// Move every datagram `from` has staged into `to`.
    fn shuttle(from: &mut dyn TcbDyn, to: &mut dyn TcbDyn) {
        while from.extract_packet_with(&mut |pkt| {
            let _ = to.inject_packet(pkt);
        }) {}
    }

    /// A NAT-side tcb (listening on 10.0.0.1:80) and a guest-side tcb,
    /// handshaken to ESTABLISHED.
    fn established_pair() -> (Box<dyn TcbDyn>, Box<dyn TcbDyn>) {
        let nat_end = Endpoint {
            ip: [10, 0, 0, 1],
            port: 80,
        };
        let guest_end = Endpoint {
            ip: [10, 0, 0, 2],
            port: 40000,
        };
        let mut nat = TIER_MAKE[0]();
        nat.reinit(TcbConfig {
            local: nat_end,
            remote: guest_end,
            iss: 1000,
            initial_rto_ms: 1000,
        });
        nat.set_secret(&[0x5a; 16]);
        nat.listen().unwrap();
        let mut guest = TIER_MAKE[0]();
        guest.reinit(TcbConfig {
            local: guest_end,
            remote: nat_end,
            iss: 2000,
            initial_rto_ms: 1000,
        });
        guest.connect().unwrap();
        for _ in 0..4 {
            guest.tick().unwrap();
            shuttle(&mut *guest, &mut *nat);
            nat.tick().unwrap();
            shuttle(&mut *nat, &mut *guest);
        }
        assert_eq!(nat.state(), State::Established);
        (nat, guest)
    }

    /// A connected flow around `nat`, with no host socket or ops.
    fn connected_flow(nat: Box<dyn TcbDyn>) -> TcpFlow {
        TcpFlow {
            tcb: Some(nat),
            tier: 0,
            sock: INVALID_SOCKET,
            op: None,
            send_op: None,
            connected: true,
            connect_pending: false,
            recv_pending: false,
            send_inflight: false,
            pending_to_host: Vec::new(),
            closing: false,
            want_shutdown: false,
            shutdown_done: false,
            dead: false,
            created_at: 0,
            last_activity: 0,
            diag: FlowDiag::default(),
            published: Losses::default(),
            rx_blocked: false,
            csum_offload: false,
            syn_len: 0,
            syn_csum_trusted: false,
        }
    }

    /// Host bytes land in the tcb's send ring as recvs complete (wrapping
    /// around it as the guest drains it); when the host then closes, the guest
    /// gets every byte, then the FIN.
    #[test]
    fn host_bytes_reach_the_guest_through_the_ring_then_fin() {
        let (nat, mut guest) = established_pair();

        // The host sends three rings' worth, then closes.
        let data: Vec<u8> = (0..3 * TIER_BUF[0] as u32).map(|i| (i * 7) as u8).collect();
        let mut flow = connected_flow(nat);

        // Pump both ends, as `tcp_drive` and the guest would, completing a
        // host recv into the lent ring space whenever there is room.
        let mut off = 0;
        let mut got = Vec::new();
        let mut rb = [0u8; 16384];
        for now in (0..10_000).step_by(10) {
            if off < data.len() {
                let nat = flow.tcb.as_mut().unwrap();
                if let Ok((a, b)) = nat.send_reserve(TCP_RECV_MAX) {
                    let mut n = 0;
                    for part in [a, b] {
                        let k = part.len().min(data.len() - off - n);
                        part[..k].copy_from_slice(&data[off + n..off + n + k]);
                        n += k;
                    }
                    assert_eq!(nat.send_commit(n), Ok(n));
                    off += n;
                }
                if off == data.len() {
                    on_host_eof(&mut flow);
                }
            }
            let nat = flow.tcb.as_mut().unwrap();
            nat.set_now(now);
            nat.tick().unwrap();
            shuttle(&mut **nat, &mut *guest);
            guest.set_now(now);
            while let Ok(n) = guest.recv(&mut rb) {
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&rb[..n]);
            }
            guest.tick().unwrap();
            shuttle(&mut *guest, &mut **nat);
            if guest.poll() & EV_PEER_CLOSED != 0 {
                break;
            }
        }
        assert_eq!(got.len(), data.len());
        assert!(got == data);
        assert_ne!(guest.poll() & EV_PEER_CLOSED, 0, "the FIN follows the data");
        flow.tcb.take();
    }

    /// A segment for a connection the NAT doesn't have is reset the way the
    /// guest will accept: an ACK (like a FIN retransmitted after the flow
    /// was released) from its acknowledgment number, anything else by
    /// acknowledging the whole segment, SYN and FIN included.
    #[test]
    fn stray_segments_are_reset_as_rfc_9293_says() {
        let seg = |flags: u8| TcpView {
            src_port: 40000,
            dst_port: 80,
            seq: 0xFFFF_FFF0,
            ack: 1234,
            hdr_len: 20,
            flags,
        };
        assert_eq!(reset_for(&seg(TCP_ACK | TCP_FIN), 0), (1234, 0, TCP_RST));
        assert_eq!(reset_for(&seg(TCP_ACK), 100), (1234, 0, TCP_RST));
        assert_eq!(
            reset_for(&seg(TCP_FIN), 0x20),
            (0, 0x11, TCP_RST | TCP_ACK),
            "data and FIN acknowledged, with wraparound"
        );
        assert_eq!(
            reset_for(&seg(TCP_SYN), 0),
            (0, 0xFFFF_FFF1, TCP_RST | TCP_ACK)
        );
    }

    /// When the host closes first, the NAT's tcb ends in TIME_WAIT. The flow
    /// may give up its slot early only once the guest's last bytes have gone
    /// to the host and the host send side is shut down.
    #[test]
    fn a_time_wait_flow_lingers_only_once_the_guest_bytes_are_out() {
        let (nat, mut guest) = established_pair();
        let mut flow = connected_flow(nat);
        on_host_eof(&mut flow);
        {
            let nat = flow.tcb.as_mut().unwrap();
            nat.tick().unwrap();
            shuttle(&mut **nat, &mut *guest);
            assert_ne!(guest.poll() & EV_PEER_CLOSED, 0);
            // The guest answers with its last bytes, then closes too.
            let (a, _) = guest.send_reserve(4).unwrap();
            a[..4].copy_from_slice(b"bye\n");
            assert_eq!(guest.send_commit(4), Ok(4));
            guest.close().unwrap();
            guest.tick().unwrap();
            shuttle(&mut *guest, &mut **nat);
            assert_eq!(nat.state(), State::TimeWait);
        }
        assert!(!flow.lingering(), "guest bytes still in the tcb");

        // The worker drains them toward the host (as `tcp_drive` does)...
        let mut rb = [0u8; 16];
        let n = flow.tcb.as_mut().unwrap().recv(&mut rb).unwrap();
        assert_eq!(&rb[..n], b"bye\n");
        flow.pending_to_host.extend_from_slice(&rb[..n]);
        flow.want_shutdown = true;
        assert!(!flow.lingering(), "guest bytes queued for the host");
        flow.pending_to_host.clear();
        flow.send_inflight = true;
        assert!(!flow.lingering(), "guest bytes in flight to the host");
        flow.send_inflight = false;
        // ...and, with the queue empty, shuts down the host send side.
        assert!(pump_send(&mut flow));
        assert!(flow.shutdown_done);
        assert!(flow.lingering());
        flow.tcb.take();
    }
}
