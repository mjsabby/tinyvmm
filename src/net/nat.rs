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
use crate::net::sys::{self, Iocp};
use crate::net::wire::*;
use crate::virtio::net::{NetBackend, NetDevice};
use std::cell::UnsafeCell;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread::JoinHandle;
use std::time::Instant;
use tcp_sans_io::{Endpoint, State, Tcb, TcbConfig, TcpError};
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
const KEY_STOP: usize = 9;

const FRAME_CAP: usize = 2048;
const UDP_BUF: usize = 2048;
const TCP_BUF: usize = 4096;
const MAX_UDP_FLOWS: usize = 256;
const MAX_TCP_FLOWS: usize = 256;
/// Number of preallocated guest-TX frame slots shared across all shards.
const POOL_SLOTS: usize = 1024;
/// Free-list end marker for the frame pool.
const POOL_SENTINEL: u32 = u32::MAX;
/// Cap on the per-flow guest->host queue. When reached we stop draining the
/// tcb receive ring, which closes the guest-facing window (backpressure).
const TO_HOST_CAP: usize = 64 * 1024;

// ICMP echo proxy (guest pings to non-gateway hosts).
const ICMP_WORKERS: usize = 2; // precreated blocking IcmpSendEcho threads
const MAX_ICMP_INFLIGHT: usize = 16; // bound the handoff queue
const ICMP_TIMEOUT_MS: u32 = 4_000;

// Flow-lifecycle timeouts (mirrors the C++ usernet backend).
const UDP_IDLE_MS: u64 = 60_000; // reap a UDP NAT entry idle this long
const TCP_CONNECT_MS: u64 = 10_000; // abort if the host connect never completes
const TCP_IDLE_MS: u64 = 10 * 60_000; // abort an established flow idle this long
const TCP_HALF_CLOSE_MS: u64 = 30_000; // abort a half-closed flow idle this long
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
    /// Optional service-port → tier overrides (e.g. route known-bulk ports to
    /// the big-ring tier). Keyed by the destination port (outbound) / guest
    /// service port (inbound).
    pub tcb_port_tier: Vec<(u16, usize)>,
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
// bandwidth-delay product is absorbed by the host kernel socket, so for the
// NAT these rings only bridge the sub-millisecond in-VMM guest leg — the
// default tier is ample. Counts are RUNTIME pool config (see `NatOptions`).
// Sizes MUST be powers of two.

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
/// Default warm counts: most flows ride the mid tier; the small/big tiers are
/// lightly warmed (big is opt-in via `tcb_port_tier`).
const DEFAULT_TCB_WARM: [usize; N_TCB_TIERS] = [192, 56, 8];
/// Default tier index (256 KiB) when no port override matches.
const DEFAULT_TIER: usize = 1;

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
    fn extract_packet(&mut self, out: &mut [u8]) -> Result<usize, TcpError>;
    fn poll(&self) -> u32;
    fn recv(&mut self, dst: &mut [u8]) -> Result<usize, TcpError>;
    fn send(&mut self, data: &[u8]) -> Result<usize, TcpError>;
    fn state(&self) -> State;
    fn tick(&mut self) -> Result<(), TcpError>;
    fn abort(&mut self) -> Result<(), TcpError>;
    fn close(&mut self) -> Result<(), TcpError>;
    /// Recycle this Tcb onto a new connection in place (reuses its rings).
    fn reinit(&mut self, cfg: TcbConfig);
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
    fn extract_packet(&mut self, out: &mut [u8]) -> Result<usize, TcpError> {
        self.extract_packet(out)
    }
    fn poll(&self) -> u32 {
        self.poll()
    }
    fn recv(&mut self, dst: &mut [u8]) -> Result<usize, TcpError> {
        self.recv(dst)
    }
    fn send(&mut self, data: &[u8]) -> Result<usize, TcpError> {
        self.send(data)
    }
    fn state(&self) -> State {
        self.state()
    }
    fn tick(&mut self) -> Result<(), TcpError> {
        self.tick()
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
        let mut free = Vec::with_capacity(warm);
        for _ in 0..warm {
            free.push(make());
        }
        BoxPool { free, make }
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
    // All fields are POD (integers, byte arrays, OVERLAPPED/WSABUF), so a fully
    // zeroed value is valid; the acquire site sets key/kind and arms the op.
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
struct FrameSlot {
    idx: u32,
    data: UnsafeCell<[u8; FRAME_CAP]>,
}

/// Fixed pool of frame slots with a lock-free Treiber free-list (ABA-guarded
/// by a tag in the high 32 bits of `head`). Multi-producer acquire (vCPUs) and
/// multi-producer release (shard workers) — fully MPMC. No per-frame heap
/// allocation on the hot path.
struct FramePool {
    slots: Box<[FrameSlot]>,
    next: Box<[AtomicU32]>,
    head: AtomicU64, // (tag << 32) | free-list head index
}

// The slots are accessed through raw pointers handed off via the IOCP; the
// free-list guarantees a slot is owned by at most one party at a time.
unsafe impl Send for FramePool {}
unsafe impl Sync for FramePool {}

impl FramePool {
    fn new(n: usize) -> Self {
        let slots: Vec<FrameSlot> = (0..n)
            .map(|i| FrameSlot {
                idx: i as u32,
                data: UnsafeCell::new([0u8; FRAME_CAP]),
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

    fn slot_ptr(&self, idx: u32) -> *mut FrameSlot {
        &self.slots[idx as usize] as *const FrameSlot as *mut FrameSlot
    }

    /// Copy a frame into slot `idx`. Caller must own the slot (just acquired).
    fn fill(&self, idx: u32, frame: &[u8]) -> usize {
        let n = frame.len().min(FRAME_CAP);
        unsafe {
            let data = &mut *self.slots[idx as usize].data.get();
            data[..n].copy_from_slice(&frame[..n]);
        }
        n
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
        if let Some(op) = self.op.as_ref() {
            if op.sock != INVALID_SOCKET {
                sys::close_sock(op.sock);
            }
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
/// the two are never in flight at the same time). `overlapped` MUST be first,
/// `kind` second.
#[repr(C)]
struct TcpOp {
    overlapped: OVERLAPPED,
    kind: u8, // 0 = connect, 1 = recv
    key: FlowKey,
    buf: [u8; TCP_BUF],
    wsabuf: WSABUF,
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
    pending_to_guest: Vec<u8>, // host->guest bytes the tcb hasn't accepted yet
    closing: bool,            // host sent FIN: our recv side is closing
    want_shutdown: bool,      // guest sent FIN: SD_SEND the host once the queue drains
    shutdown_done: bool,      // SD_SEND already issued
    dead: bool,               // tearing down; socket closed, awaiting op drain
    created_at: u64,          // ms at flow creation (connect-deadline watchdog)
    last_activity: u64,       // ms of last real TX/RX (idle/half-close watchdogs)
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

/// Push buffered host->guest bytes into the tcb send ring (as much as fits).
fn flush_to_tcb(flow: &mut TcpFlow) {
    while !flow.pending_to_guest.is_empty() {
        match flow.tcb.as_mut().unwrap().send(&flow.pending_to_guest) {
            Ok(0) => break,
            Ok(n) => {
                flow.pending_to_guest.drain(..n);
            }
            Err(_) => break,
        }
    }
}

/// Re-arm a host receive if the flow is connected, idle, and the send ring
/// has room (simple backpressure).
/// Returns false only if the receive failed synchronously (no completion will
/// arrive) — the caller must tear the flow down rather than wait on a recv that
/// will never complete.
#[must_use]
fn maybe_post_recv(flow: &mut TcpFlow) -> bool {
    if !flow.connected || flow.recv_pending || flow.closing || flow.dead {
        return true;
    }
    if flow.pending_to_guest.len() > TCP_BUF {
        return true;
    }
    let op = flow.op.as_mut().unwrap();
    op.kind = 1;
    let p = op.buf.as_mut_ptr();
    let l = op.buf.len();
    op.wsabuf = sys::wsabuf(p, l);
    let sock = flow.sock;
    let buf = &op.wsabuf as *const WSABUF;
    let ovl = &mut op.overlapped as *mut OVERLAPPED;
    let posted = unsafe { sys::wsa_recv(sock, buf, ovl) };
    if posted {
        flow.recv_pending = true;
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

struct NatState {
    net: Weak<NetDevice>,
    iocp: Iocp,
    gw_ip: [u8; 4],
    gw_mac: [u8; 6],
    guest_mac: [u8; 6],
    udp: HashMap<FlowKey, UdpFlow>,
    tcp: HashMap<FlowKey, TcpFlow>,
    icmp: Arc<IcmpPool>,
    pool: Arc<FramePool>,
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
    last_tick: u64,
    last_expire: u64,
    tick_keys: Vec<FlowKey>,
    // Reusable scratch buffers for building guest-bound frames without a
    // per-packet heap allocation (the worker is single-threaded).
    tx_scratch: Vec<u8>,
    l3_scratch: Vec<u8>,
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
        loop {
            let (ok, bytes, key, ov) = sys::get_ms(self.iocp, IDLE_MS);
            if ov.is_null() {
                if key == KEY_STOP {
                    break;
                }
                // timeout: fall through to the timer sweep below.
            } else {
                match key {
                    KEY_FRAME => {
                        let slot = ov as *mut FrameSlot;
                        let n = (bytes as usize).min(FRAME_CAP);
                        let idx = unsafe { (*slot).idx };
                        let data_ptr =
                            UnsafeCell::raw_get(unsafe { core::ptr::addr_of!((*slot).data) });
                        let arr = unsafe { &*data_ptr };
                        self.handle_frame(&arr[..n]);
                        self.pool.release(idx);
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
                        match kind {
                            0 => self.on_tcp_connect(ov as *mut TcpOp, ok),
                            1 => self.on_tcp_recv(ov as *mut TcpOp, ok, bytes),
                            2 => self.on_tcp_send(ov as *mut TcpSendOp, ok, bytes),
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
            // Drive per-flow TCP timers (retransmit / delayed-ACK) on a coarse
            // cadence rather than on every completion: those timers are coarse
            // (>=200ms) and the flow that just completed was already driven
            // inline. This keeps the sweep off the hot path (was O(flows) per
            // packet).
            let now = self.now();
            if now.wrapping_sub(self.last_tick) >= TICK_GATE_MS {
                self.last_tick = now;
                self.tcp_tick();
            }
            if now.wrapping_sub(self.last_expire) >= EXPIRE_GATE_MS {
                self.last_expire = now;
                self.expire_idle(now);
            }
        }
        // Shutdown: drop all live flows. take() the pooled boxes first (the
        // pools are dying, so just discard them) so the Drop-bomb treats these
        // intentional drops as reaped. TcpFlow::drop then closes the host
        // socket; for UDP the socket lives in the op, so close it here.
        for (_, mut f) in self.tcp.drain() {
            f.tcb.take();
            f.op.take();
            f.send_op.take();
            // TcpFlow::drop closes f.sock
        }
        for (_, mut f) in self.udp.drain() {
            if let Some(op) = f.op.take() {
                if op.sock != INVALID_SOCKET {
                    sys::close_sock(op.sock);
                }
            }
        }
    }

    fn now(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
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
        if self.udp.len() >= MAX_UDP_FLOWS {
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
        let posted = unsafe { sys::wsa_recv(sock, &(*opp).wsabuf, &mut (*opp).overlapped) };
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
        Some(sock)
    }

    /// Remove a UDP flow: close its socket if still open and return the pooled
    /// op buffer. The pending recv has already drained (called from the recv
    /// completion, or after expire_idle closed the socket).
    fn reap_udp(&mut self, key: FlowKey) {
        if let Some(mut f) = self.udp.remove(&key) {
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
        let posted = unsafe { sys::wsa_recv(sock, buf, ovl) };
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
        if !self.tcp.contains_key(&key) {
            if tcp.flags & TCP_SYN == 0 {
                return;
            }
            // At capacity (or socket setup failed): refuse with a RST so the
            // guest's connect() fails fast instead of retrying for ~minutes.
            if self.tcp.len() >= MAX_TCP_FLOWS || self.new_tcp_flow(key).is_none() {
                build_tcp_rst_for_syn_into(
                    &mut self.l3_scratch,
                    ip.src,
                    tcp.src_port,
                    ip.dst,
                    tcp.dst_port,
                    tcp.seq,
                );
                self.wrap_and_inject(ip.dst, ip.src, IP_PROTO_TCP);
                return;
            }
        }
        let now = self.now();
        if let Some(flow) = self.tcp.get_mut(&key) {
            flow.tcb.as_mut().unwrap().set_now(now);
            let _ = flow.tcb.as_mut().unwrap().inject_packet(ip.datagram);
            flow.last_activity = now;
        }
        self.tcp_drive(key);
    }

    fn new_tcp_flow(&mut self, key: FlowKey) -> Option<()> {
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
        let mut tcb = self.tcb_pools[tier].acquire();
        tcb.reinit(cfg);
        tcb.set_now(now);
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
        let ovl = &mut op.overlapped as *mut OVERLAPPED;
        let started = unsafe { sys::connect_ex(sock, dip, dport, ovl) };
        if !started {
            sys::close_sock(sock);
            self.tcb_pools[tier].release(tcb);
            self.tcp_op_pool.release(op);
            self.tcp_send_op_pool.release(send_op);
            return None;
        }
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
                pending_to_guest: Vec::new(),
                closing: false,
                want_shutdown: false,
                shutdown_done: false,
                dead: false,
                created_at: now,
                last_activity: now,
            },
        );
        Some(())
    }

    /// Pick a free gateway-side ephemeral port for an inbound flow such that
    /// the resulting FlowKey is unique. Returns None if none found.
    fn alloc_ephem_port(&mut self, guest_ip: [u8; 4], guest_port: u16) -> Option<u16> {
        for _ in 0..64 {
            let p = 49152u16 + (self.next_iss() % 16384) as u16;
            let key = (guest_ip, guest_port, self.gw_ip, p);
            if !self.tcp.contains_key(&key) {
                return Some(p);
            }
        }
        None
    }

    /// Create an inbound (port-forwarded) flow: the host already accepted a
    /// client (`host_sock`), and we originate an active-open TCB toward the
    /// guest server. Reuses the normal TcpFlow data path; the only differences
    /// from an outbound flow are tcb.connect() (vs listen) and that the host
    /// socket is already connected.
    fn new_inbound_flow(&mut self, host_sock: SOCKET, guest_ip: [u8; 4], guest_port: u16) {
        if self.tcp.len() >= MAX_TCP_FLOWS {
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
        let mut tcb = self.tcb_pools[tier].acquire();
        tcb.reinit(cfg);
        tcb.set_now(now);
        if tcb.connect().is_err() {
            // active open: emits a SYN toward the guest
            self.tcb_pools[tier].release(tcb);
            sys::close_sock(host_sock);
            return;
        }
        if !sys::associate(self.iocp, host_sock, KEY_TCP) {
            self.tcb_pools[tier].release(tcb);
            sys::close_sock(host_sock);
            return;
        }
        let mut op = self.tcp_op_pool.acquire();
        op.overlapped = unsafe { core::mem::zeroed() };
        op.kind = 0;
        op.key = key;
        let mut send_op = self.tcp_send_op_pool.acquire();
        send_op.overlapped = unsafe { core::mem::zeroed() };
        send_op.kind = 2;
        send_op.key = key;
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
                pending_to_guest: Vec::new(),
                closing: false,
                want_shutdown: false,
                shutdown_done: false,
                dead: false,
                created_at: now,
                last_activity: now,
            },
        );
        // Emit the SYN toward the guest and arm the host receive.
        self.tcp_drive(key);
    }

    fn on_tcp_connect(&mut self, op_ptr: *mut TcpOp, ok: bool) {
        let key = unsafe { (*op_ptr).key };
        let now = self.now();
        let mut dead = false;
        if let Some(flow) = self.tcp.get_mut(&key) {
            flow.connect_pending = false;
            if flow.dead {
                dead = true;
            } else {
                flow.tcb.as_mut().unwrap().set_now(now);
                if !ok {
                    let _ = flow.tcb.as_mut().unwrap().abort();
                } else {
                    sys::update_connect_ctx(flow.sock);
                    flow.connected = true;
                    flow.last_activity = now;
                }
            }
        }
        if dead {
            // The flow was torn down while ConnectEx was in flight; this was
            // the last outstanding op, so reap now.
            self.reap_if_idle(key);
            return;
        }
        // tcp_drive flushes any data buffered before the connect completed (and,
        // on abort, the RST toward the guest) and tears down on EV_CLOSED/ERROR.
        self.tcp_drive(key);
    }

    fn on_tcp_recv(&mut self, op_ptr: *mut TcpOp, ok: bool, bytes: u32) {
        let key = unsafe { (*op_ptr).key };
        let now = self.now();
        let mut dead = false;
        if let Some(flow) = self.tcp.get_mut(&key) {
            flow.recv_pending = false;
            if flow.dead {
                dead = true;
            } else {
                flow.tcb.as_mut().unwrap().set_now(now);
                if !ok || bytes == 0 {
                    let _ = flow.tcb.as_mut().unwrap().close();
                    flow.closing = true;
                } else {
                    let n = (bytes as usize).min(flow.op.as_ref().unwrap().buf.len());
                    // op.buf and pending_to_guest are disjoint fields, so this
                    // extends in place with no temporary Vec.
                    flow.pending_to_guest
                        .extend_from_slice(&flow.op.as_ref().unwrap().buf[..n]);
                    flow.last_activity = now;
                }
            }
        }
        if dead {
            self.reap_if_idle(key);
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
            self.begin_teardown(key);
            return;
        }
        // Post the next chunk and make any other progress (re-arm recv, etc.).
        self.tcp_drive(key);
    }

    fn tcp_drive(&mut self, key: FlowKey) {
        let gw = self.gw_mac;
        let gm = self.guest_mac;
        let dev = self.net.upgrade();
        let mut scratch = std::mem::take(&mut self.tx_scratch);
        let mut teardown = false;
        if let Some(flow) = self.tcp.get_mut(&key) {
            if flow.dead {
                self.tx_scratch = scratch;
                return;
            }
            flush_to_tcb(flow);
            let mut pbuf = [0u8; tcp_sans_io::MAX_PACKET];
            loop {
                match flow.tcb.as_mut().unwrap().extract_packet(&mut pbuf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Some(d) = &dev {
                            // Build the Ethernet frame into the reused scratch
                            // and inject it — no per-segment allocation.
                            build_eth_into(&mut scratch, gm, gw, ETHERTYPE_IPV4, &pbuf[..n]);
                            d.inject_rx(&scratch);
                        }
                    }
                    Err(_) => break,
                }
            }
            let ev = flow.tcb.as_ref().unwrap().poll();
            if ev & EV_READABLE != 0 {
                // Drain the tcb receive ring into the guest->host queue, but
                // stop at the cap so a slow host send keeps the guest window
                // closed (backpressure) instead of buffering without bound.
                let mut rb = [0u8; 4096];
                while flow.pending_to_host.len() < TO_HOST_CAP {
                    match flow.tcb.as_mut().unwrap().recv(&mut rb) {
                        Ok(0) => break,
                        Ok(n) => flow.pending_to_host.extend_from_slice(&rb[..n]),
                        Err(_) => break,
                    }
                }
            }
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
        }
        self.tx_scratch = scratch;
        if teardown {
            self.begin_teardown(key);
        }
    }

    /// Begin tearing a flow down: close the host socket once (which aborts any
    /// pending overlapped ops so their completions drain), then reap. The
    /// TcpFlow (and its op buffers) stay alive until every outstanding op has
    /// completed, so the kernel never touches freed memory.
    fn begin_teardown(&mut self, key: FlowKey) {
        if let Some(flow) = self.tcp.get_mut(&key) {
            if !flow.dead {
                flow.dead = true;
                if flow.sock != INVALID_SOCKET {
                    sys::close_sock(flow.sock);
                    flow.sock = INVALID_SOCKET;
                }
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
        if reap {
            if let Some(mut f) = self.tcp.remove(&key) {
                // The socket was already closed by begin_teardown and all ops
                // have drained, so recycle the pooled Tcb (into its size-tier)
                // and the overlapped op buffers via take(); TcpFlow::drop then
                // closes the socket (a no-op — already INVALID) and the Drop-bomb
                // confirms every box was reclaimed.
                let tier = f.tier;
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
    }

    /// Periodic idle sweep (runs every EXPIRE_GATE_MS): reap idle UDP NAT
    /// entries and abort stuck/dead TCP flows (connect-deadline, idle, and
    /// half-close watchdogs). Mirrors the C++ backend's ExpireIdle + the TSI
    /// engine's per-conn watchdogs.
    fn expire_idle(&mut self, now: u64) {
        // UDP: reap entries idle longer than UDP_IDLE_MS. Marking dead +
        // closing the socket aborts the pending recv; on_udp_recv frees it.
        let udp_dead: Vec<FlowKey> = self
            .udp
            .iter()
            .filter(|(_, f)| !f.dead && now.wrapping_sub(f.last_use) > UDP_IDLE_MS)
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

        // TCP: collect flows that tripped a watchdog, then tear them down.
        let tcp_victims: Vec<FlowKey> = self
            .tcp
            .iter()
            .filter(|(_, f)| {
                if f.dead {
                    return false;
                }
                let idle = now.wrapping_sub(f.last_activity);
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
                // completed (outbound) or the TCB hasn't reached a synchronized
                // state (covers an inbound flow whose guest never accepts).
                let establishing = !f.connected || !st.is_synchronized();
                (establishing && now.wrapping_sub(f.created_at) > TCP_CONNECT_MS)
                    || (half && idle > TCP_HALF_CLOSE_MS)
                    || (idle > TCP_IDLE_MS)
            })
            .map(|(k, _)| *k)
            .collect();
        for k in tcp_victims {
            if let Some(f) = self.tcp.get_mut(&k) {
                let _ = f.tcb.as_mut().unwrap().abort();
            }
            self.begin_teardown(k);
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
            if let Some(flow) = self.tcp.get_mut(&key) {
                if !flow.dead {
                    flow.tcb.as_mut().unwrap().set_now(now);
                    let _ = flow.tcb.as_mut().unwrap().tick();
                    tick = true;
                }
            }
            if tick {
                self.tcp_drive(key);
            }
        }
        keys.clear();
        self.tick_keys = keys;
    }
}

pub struct NatBackend {
    iocp: Iocp,
    worker: Mutex<Option<JoinHandle<()>>>,
    icmp: Option<Arc<IcmpPool>>,
    icmp_workers: Mutex<Vec<JoinHandle<()>>>,
    listeners: Mutex<Vec<SOCKET>>,
    listener_threads: Mutex<Vec<JoinHandle<()>>>,
    pool: Arc<FramePool>,
}

impl NatBackend {
    pub fn new(net: &Arc<NetDevice>, opts: NatOptions) -> Arc<Self> {
        sys::wsa_startup();
        let pool = Arc::new(FramePool::new(POOL_SLOTS));
        let iocp = match sys::create_iocp() {
            Some(i) => i,
            None => {
                eprintln!("[nat] CreateIoCompletionPort failed; NAT disabled");
                return Arc::new(NatBackend {
                    iocp: Iocp(std::ptr::null_mut()),
                    worker: Mutex::new(None),
                    icmp: None,
                    icmp_workers: Mutex::new(Vec::new()),
                    listeners: Mutex::new(Vec::new()),
                    listener_threads: Mutex::new(Vec::new()),
                    pool,
                });
            }
        };
        // Cross-thread message pools: producer threads (listeners / ICMP
        // workers) acquire+fill, the NAT worker releases. Warmed lightly; they
        // grow on demand and recycle, so steady state is allocation-free.
        let accept_pool = Arc::new(SyncBoxPool::new(32, make_accept_msg));
        let accept_inflight = Arc::new(AtomicUsize::new(0));
        let icmp_reply_pool = Arc::new(SyncBoxPool::new(MAX_ICMP_INFLIGHT, make_icmp_reply));
        // Precreate the ICMP echo worker pool (blocking IcmpSendEcho threads).
        let icmp = Arc::new(IcmpPool::new(iocp, icmp_reply_pool.clone()));
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
        // the worker via the IOCP (KEY_ACCEPT); closing the listener socket on
        // shutdown unblocks it.
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
            if let Ok(h) = std::thread::Builder::new()
                .name(format!("nat-listen-{}", pf.host_port))
                .spawn(move || listener_loop(lsock, iocp, pf, ap, ai))
            {
                listener_threads.push(h);
            }
        }
        // Worker-only object pools: one Tcb free-list per compile-time tier,
        // plus the overlapped op buffers. Built here (heap-buffers keeps each
        // boxed Tcb small on the stack) and owned solely by the worker thread.
        let default_tier = if opts.default_tier < N_TCB_TIERS {
            opts.default_tier
        } else {
            DEFAULT_TIER
        };
        let tcb_pools: Vec<BoxPool<dyn TcbDyn>> = (0..N_TCB_TIERS)
            .map(|i| BoxPool::new(opts.tcb_warm[i], TIER_MAKE[i]))
            .collect();
        let mut port_tier = HashMap::new();
        for &(port, tier) in &opts.tcb_port_tier {
            if tier < N_TCB_TIERS {
                port_tier.insert(port, tier);
            }
        }
        let state = NatState {
            net: Arc::downgrade(net),
            iocp,
            gw_ip: opts.gateway_ip,
            gw_mac: opts.gateway_mac,
            guest_mac: net.mac(),
            udp: HashMap::new(),
            tcp: HashMap::new(),
            icmp: icmp.clone(),
            pool: pool.clone(),
            tcb_pools,
            tcp_op_pool: BoxPool::new(MAX_TCP_FLOWS, make_tcp_op),
            tcp_send_op_pool: BoxPool::new(MAX_TCP_FLOWS, make_tcp_send_op),
            udp_op_pool: BoxPool::new(MAX_UDP_FLOWS, make_udp_op),
            accept_pool,
            accept_inflight,
            icmp_reply_pool,
            default_tier,
            port_tier,
            start: Instant::now(),
            rng: 0x2545_F491,
            last_tick: 0,
            last_expire: 0,
            tick_keys: Vec::new(),
            tx_scratch: Vec::with_capacity(FRAME_CAP),
            l3_scratch: Vec::with_capacity(FRAME_CAP),
        };
        // With `heap-buffers` the Tcb rings are boxed, so a Tcb is no longer a
        // multi-MiB stack temporary; pooled construction above is cheap. The
        // worker still gets a generous stack for deep packet-processing frames.
        let handle = std::thread::Builder::new()
            .name("nat-worker".into())
            .stack_size(16 * 1024 * 1024)
            .spawn(move || state.run())
            .ok();
        Arc::new(NatBackend {
            iocp,
            worker: Mutex::new(handle),
            icmp: Some(icmp),
            icmp_workers: Mutex::new(icmp_workers),
            listeners: Mutex::new(listeners),
            listener_threads: Mutex::new(listener_threads),
            pool,
        })
    }
}

/// Accept loop for one port-forward listener; runs on its own thread.
fn listener_loop(
    lsock: SOCKET,
    iocp: Iocp,
    pf: PortForward,
    accept_pool: Arc<SyncBoxPool<AcceptMsg>>,
    accept_inflight: Arc<AtomicUsize>,
) {
    loop {
        let c = sys::accept_one(lsock);
        if c == INVALID_SOCKET {
            break; // listener closed for shutdown
        }
        // Bound accepted-but-undrained connections: a remote accept-flood is
        // dropped here (the client can retry) rather than piling up host sockets
        // and AcceptMsg boxes faster than the single worker drains them.
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
        if !sys::post(iocp, 0, KEY_ACCEPT, ptr as *mut OVERLAPPED) {
            accept_inflight.fetch_sub(1, Ordering::AcqRel);
            accept_pool.release(unsafe { Box::from_raw(ptr) });
            sys::close_sock(c);
        }
    }
}

impl NetBackend for NatBackend {
    fn on_guest_frame(&self, frame: &[u8]) {
        if self.iocp.0.is_null() || frame.is_empty() || frame.len() > FRAME_CAP {
            return;
        }
        // Acquire a preallocated slot (no heap alloc on the hot path); if the
        // pool is exhausted, drop the frame (the guest will retransmit).
        let Some(idx) = self.pool.acquire() else {
            if etw::enabled(etw::VERBOSE, etw::kw::NET) {
                etw::Event::new("NetTxDrop", etw::VERBOSE, etw::kw::NET)
                    .u32("len", frame.len() as u32)
                    .write();
            }
            return;
        };
        let n = self.pool.fill(idx, frame);
        let ptr = self.pool.slot_ptr(idx);
        if !sys::post(self.iocp, n as u32, KEY_FRAME, ptr as *mut OVERLAPPED) {
            self.pool.release(idx);
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
        if !self.iocp.0.is_null() {
            sys::post(self.iocp, 0, KEY_STOP, std::ptr::null_mut());
        }
        if let Some(h) = self.worker.lock().unwrap().take() {
            let _ = h.join();
        }
    }
}
