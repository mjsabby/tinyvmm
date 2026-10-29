//! Split-virtqueue accessor (virtio v1.0+ layout, spec §2.7). Port of
//! src/virtio/virtqueue.cpp.

use crate::whp::GuestMemory;
use std::sync::Arc;
use std::sync::atomic::{Ordering, fence};

pub const VRING_DESC_F_NEXT: u16 = 1;
pub const VRING_DESC_F_WRITE: u16 = 2;
pub const VRING_DESC_F_INDIRECT: u16 = 4;

/// Snapshot of a virtqueue's durable programming + ring position (40 bytes).
#[derive(Clone, Copy, Default)]
pub struct QueueState {
    pub size: u32,
    pub ready: bool,
    pub event_idx: bool,
    pub desc_gpa: u64,
    pub avail_gpa: u64,
    pub used_gpa: u64,
    pub last_avail: u16,
    pub last_used_idx: u16,
    pub last_used_signaled: u16,
}

pub const QUEUE_STATE_ENCODED: usize = 40;

impl QueueState {
    pub fn encode(&self) -> [u8; QUEUE_STATE_ENCODED] {
        let mut b = [0u8; QUEUE_STATE_ENCODED];
        b[0..4].copy_from_slice(&self.size.to_le_bytes());
        b[4] = self.ready as u8;
        b[5] = self.event_idx as u8;
        b[8..16].copy_from_slice(&self.desc_gpa.to_le_bytes());
        b[16..24].copy_from_slice(&self.avail_gpa.to_le_bytes());
        b[24..32].copy_from_slice(&self.used_gpa.to_le_bytes());
        b[32..34].copy_from_slice(&self.last_avail.to_le_bytes());
        b[34..36].copy_from_slice(&self.last_used_idx.to_le_bytes());
        b[36..38].copy_from_slice(&self.last_used_signaled.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Option<QueueState> {
        if b.len() < QUEUE_STATE_ENCODED {
            return None;
        }
        Some(QueueState {
            size: u32::from_le_bytes(b[0..4].try_into().unwrap()),
            ready: b[4] != 0,
            event_idx: b[5] != 0,
            desc_gpa: u64::from_le_bytes(b[8..16].try_into().unwrap()),
            avail_gpa: u64::from_le_bytes(b[16..24].try_into().unwrap()),
            used_gpa: u64::from_le_bytes(b[24..32].try_into().unwrap()),
            last_avail: u16::from_le_bytes(b[32..34].try_into().unwrap()),
            last_used_idx: u16::from_le_bytes(b[34..36].try_into().unwrap()),
            last_used_signaled: u16::from_le_bytes(b[36..38].try_into().unwrap()),
        })
    }
}

/// One element of a popped descriptor chain. `ptr`/`len` view a guest buffer
/// already bounds-checked against the RAM mapping.
#[derive(Clone, Copy)]
pub struct ChainBuf {
    pub ptr: *mut u8,
    pub len: usize,
    pub write: bool,
}

impl ChainBuf {
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

#[derive(Default)]
pub struct PoppedChain {
    pub head_index: u16,
    pub bufs: Vec<ChainBuf>,
}

/// A reusable [`PoppedChain`] a device can hold in a `Mutex` field to drain its
/// ring without per-request allocation. Its `ChainBuf` raw pointers are only
/// dereferenced under the device's queue lock during a drain (and cleared then
/// refilled on each `pop_into`), so sending the owning device between threads is
/// safe — the same reasoning the net device uses for its reused scratch. Only
/// `Send` is asserted (all that `Mutex<T>: Sync` requires).
#[derive(Default)]
pub struct ChainScratch(PoppedChain);

unsafe impl Send for ChainScratch {}

impl std::ops::Deref for ChainScratch {
    type Target = PoppedChain;
    fn deref(&self) -> &PoppedChain {
        &self.0
    }
}
impl std::ops::DerefMut for ChainScratch {
    fn deref_mut(&mut self) -> &mut PoppedChain {
        &mut self.0
    }
}

struct Desc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

fn read_desc(b: &[u8; 16]) -> Desc {
    Desc {
        addr: u64::from_le_bytes(b[0..8].try_into().unwrap()),
        len: u32::from_le_bytes(b[8..12].try_into().unwrap()),
        flags: u16::from_le_bytes(b[12..14].try_into().unwrap()),
        next: u16::from_le_bytes(b[14..16].try_into().unwrap()),
    }
}

pub struct Virtqueue {
    mem: Arc<GuestMemory>,
    max_size: u32,
    size: u32,
    ready: bool,
    event_idx: bool,
    desc_gpa: u64,
    avail_gpa: u64,
    used_gpa: u64,
    last_avail: u16,
    last_used_idx: u16,
    last_used_signaled: u16,
}

impl Virtqueue {
    pub fn new(mem: Arc<GuestMemory>, max_size: u32) -> Self {
        Virtqueue {
            mem,
            max_size,
            size: 0,
            ready: false,
            event_idx: false,
            desc_gpa: 0,
            avail_gpa: 0,
            used_gpa: 0,
            last_avail: 0,
            last_used_idx: 0,
            last_used_signaled: 0,
        }
    }

    pub fn set_size(&mut self, size: u32) {
        self.size = size;
    }
    pub fn set_desc_gpa(&mut self, gpa: u64) {
        self.desc_gpa = gpa;
    }
    pub fn set_avail_gpa(&mut self, gpa: u64) {
        self.avail_gpa = gpa;
    }
    pub fn set_used_gpa(&mut self, gpa: u64) {
        self.used_gpa = gpa;
    }
    pub fn set_ready(&mut self, ready: bool) {
        self.ready = ready;
    }
    pub fn set_event_idx_enabled(&mut self, en: bool) {
        self.event_idx = en;
    }
    pub fn ready(&self) -> bool {
        self.ready
    }
    pub fn size(&self) -> u32 {
        self.size
    }
    pub fn max_size(&self) -> u32 {
        self.max_size
    }

    pub fn reset(&mut self) {
        self.size = 0;
        self.ready = false;
        self.desc_gpa = 0;
        self.avail_gpa = 0;
        self.used_gpa = 0;
        self.last_avail = 0;
        self.last_used_idx = 0;
        self.last_used_signaled = 0;
    }

    /// Capture the durable queue programming + ring position for snapshot.
    pub fn capture(&self) -> QueueState {
        QueueState {
            size: self.size,
            ready: self.ready,
            event_idx: self.event_idx,
            desc_gpa: self.desc_gpa,
            avail_gpa: self.avail_gpa,
            used_gpa: self.used_gpa,
            last_avail: self.last_avail,
            last_used_idx: self.last_used_idx,
            last_used_signaled: self.last_used_signaled,
        }
    }

    /// Restore queue programming + ring position from a snapshot.
    pub fn apply(&mut self, s: &QueueState) {
        // Clamp: a hostile/corrupt snapshot with size > u16::MAX would make
        // `last_avail % size as u16` divide by zero (panic=abort). The transport
        // already enforces size ≤ max_size on the live path; do the same here.
        self.size = s.size.min(self.max_size);
        self.ready = s.ready;
        self.event_idx = s.event_idx;
        self.desc_gpa = s.desc_gpa;
        self.avail_gpa = s.avail_gpa;
        self.used_gpa = s.used_gpa;
        self.last_avail = s.last_avail;
        self.last_used_idx = s.last_used_idx;
        self.last_used_signaled = s.last_used_signaled;
    }

    fn host(&self, gpa: u64, bytes: u64) -> Option<*mut u8> {
        self.mem.host_range(gpa, bytes)
    }

    fn load_acq16(&self, gpa: u64) -> Option<u16> {
        self.mem.load_acquire_u16(gpa)
    }
    fn store_rel16(&self, gpa: u64, v: u16) {
        let _ = self.mem.store_release_u16(gpa, v);
    }
    fn load16(&self, gpa: u64) -> Option<u16> {
        self.mem.read_u16(gpa)
    }

    fn avail_idx(&self) -> u16 {
        self.load_acq16(self.avail_gpa + 2)
            .unwrap_or(self.last_avail)
    }
    fn avail_flags(&self) -> u16 {
        self.load_acq16(self.avail_gpa).unwrap_or(0)
    }
    fn avail_ring(&self, slot: u16) -> u16 {
        self.load16(self.avail_gpa + 4 + 2 * slot as u64)
            .unwrap_or(0)
    }
    fn used_event(&self) -> u16 {
        self.load_acq16(self.avail_gpa + 4 + 2 * self.size as u64)
            .unwrap_or(0)
    }

    fn store_used_idx(&self, idx: u16) {
        self.store_rel16(self.used_gpa + 2, idx);
    }
    fn store_used_ring(&self, slot: u16, id: u32, len: u32) {
        let mut b = [0u8; 8];
        b[0..4].copy_from_slice(&id.to_le_bytes());
        b[4..8].copy_from_slice(&len.to_le_bytes());
        let _ = self
            .mem
            .write_bytes(self.used_gpa + 4 + 8 * slot as u64, &b);
    }
    fn store_avail_event(&self, event_idx: u16) {
        self.store_rel16(self.used_gpa + 4 + 8 * self.size as u64, event_idx);
    }

    /// Pop one available chain into `out` (reusing its `bufs` allocation),
    /// returning false if the ring is empty. Alloc-free on the hot path.
    pub fn pop_into(&mut self, out: &mut PoppedChain) -> bool {
        out.bufs.clear();
        if !self.ready || self.size == 0 {
            return false;
        }
        // Without EVENT_IDX the driver kicks for every publish (we never set
        // VRING_USED_F_NO_NOTIFY), so an empty ring needs no re-check.
        if self.avail_idx() == self.last_avail
            && (!self.event_idx || self.arm_kick_and_recheck() == self.last_avail)
        {
            return false;
        }
        let slot = self.last_avail % self.size as u16;
        let head = self.avail_ring(slot);
        if head >= self.size as u16 {
            self.last_avail = self.last_avail.wrapping_add(1);
            return false;
        }

        let desc_base = self.desc_gpa;
        // Validate the descriptor table is mapped; individual descriptors are
        // then read with bounds-checked `read_array` (no raw pointer math).
        if self.host(desc_base, 16 * self.size as u64).is_none() {
            self.last_avail = self.last_avail.wrapping_add(1);
            return false;
        }

        out.head_index = head;

        // Spec §2.7.5.3.1: a chain (indirect or not) has at most queue-size
        // descriptors total. Enforce it so a hostile size×size indirect chain
        // can't quadratically inflate `out.bufs` (and downstream gather buffers).
        let cap = self.size;
        let mut cur = head;
        for _ in 0..self.size {
            if out.bufs.len() as u32 >= cap {
                break;
            }
            let Some(db) = self.mem.read_array::<16>(desc_base + cur as u64 * 16) else {
                break;
            };
            let d = read_desc(&db);

            if d.flags & VRING_DESC_F_INDIRECT != 0 {
                let inner_count = d.len / 16;
                if self.host(d.addr, d.len as u64).is_none() {
                    break;
                }
                let mut i = 0u32;
                let mut step = 0u32;
                while step < inner_count && step < self.size && (out.bufs.len() as u32) < cap {
                    let Some(ib) = self.mem.read_array::<16>(d.addr + i as u64 * 16) else {
                        break;
                    };
                    let id = read_desc(&ib);
                    if let Some(host) = self.host(id.addr, id.len as u64) {
                        out.bufs.push(ChainBuf {
                            ptr: host,
                            len: id.len as usize,
                            write: id.flags & VRING_DESC_F_WRITE != 0,
                        });
                    }
                    if id.flags & VRING_DESC_F_NEXT == 0 {
                        break;
                    }
                    if id.next >= inner_count as u16 {
                        break;
                    }
                    i = id.next as u32;
                    step += 1;
                }
            } else if let Some(host) = self.host(d.addr, d.len as u64) {
                out.bufs.push(ChainBuf {
                    ptr: host,
                    len: d.len as usize,
                    write: d.flags & VRING_DESC_F_WRITE != 0,
                });
            }

            if d.flags & VRING_DESC_F_NEXT == 0 {
                break;
            }
            if d.next >= self.size as u16 {
                break;
            }
            cur = d.next;
        }

        self.last_avail = self.last_avail.wrapping_add(1);
        if self.event_idx {
            self.store_avail_event(self.last_avail);
        }
        true
    }

    /// Allocating convenience wrapper around [`Self::pop_into`] for cold paths.
    pub fn pop(&mut self) -> Option<PoppedChain> {
        let mut c = PoppedChain::default();
        if self.pop_into(&mut c) { Some(c) } else { None }
    }

    /// Whether the driver has published entries not yet popped. A plain peek:
    /// unlike an empty [`Self::pop_into`] it does not arm a kick.
    pub fn has_avail(&self) -> bool {
        self.avail_pending() != 0
    }

    /// Entries the driver has published but the device hasn't popped yet
    /// (capped at the ring size, since `avail.idx` is guest-controlled).
    pub fn avail_pending(&self) -> u16 {
        if !self.ready || self.size == 0 {
            return 0;
        }
        self.avail_idx()
            .wrapping_sub(self.last_avail)
            .min(self.size as u16)
    }

    /// The ring looked empty: ask the driver to kick when it publishes the
    /// next entry, then look again (`vhost_enable_notify`). Returns the fresh
    /// `avail.idx`.
    ///
    /// The fence pairs with the full barrier the driver executes between
    /// publishing `avail.idx` and reading `avail_event`
    /// (`virtqueue_kick_prepare`). Release/Acquire do not order a store before
    /// a later load: without the fence this CPU can complete the `avail.idx`
    /// load while the `avail_event` store still sits in its store buffer, a
    /// driver publishing in that window reads the old event and skips the
    /// kick, and the entry waits for a kick that never comes.
    fn arm_kick_and_recheck(&self) -> u16 {
        self.store_avail_event(self.last_avail);
        fence(Ordering::SeqCst);
        self.avail_idx()
    }

    /// Position of the next available-ring entry [`Self::pop_into`] will take;
    /// pass it to [`Self::rewind_avail`] to give back the chains popped since.
    pub fn avail_cursor(&self) -> u16 {
        self.last_avail
    }

    /// Un-pop every chain taken since `cursor`, after a pop found the ring
    /// empty. None of them may have been pushed to the used ring. With
    /// EVENT_IDX, `pop_into` already left `avail_event` at the index where the
    /// ring ran dry, so the driver's next refill kicks the device. Returns true
    /// if the driver published more buffers since that empty check; the caller
    /// should retry now rather than wait for the kick.
    pub fn rewind_avail(&mut self, cursor: u16) -> bool {
        let dry_at = self.last_avail;
        self.last_avail = cursor;
        fence(Ordering::SeqCst);
        self.avail_idx() != dry_at
    }

    pub fn push(&mut self, head_index: u16, used_len: u32) {
        self.add_used(head_index, used_len);
        self.publish_used();
    }

    /// Write a used-ring element without making it visible to the driver.
    /// Call [`Self::publish_used`] once every element of a multi-buffer
    /// (MRG_RXBUF) packet is written: the driver reads `num_buffers` from the
    /// first buffer and drops the packet if the rest aren't already in the
    /// used ring.
    pub fn add_used(&mut self, head_index: u16, used_len: u32) {
        if !self.ready || self.size == 0 {
            return;
        }
        let slot = self.last_used_idx % self.size as u16;
        self.store_used_ring(slot, head_index as u32, used_len);
        self.last_used_idx = self.last_used_idx.wrapping_add(1);
    }

    /// Publish `used.idx` for every element written by [`Self::add_used`].
    pub fn publish_used(&mut self) {
        if !self.ready || self.size == 0 {
            return;
        }
        // Publish used.idx after writing the elements.
        fence(Ordering::Release);
        self.store_used_idx(self.last_used_idx);
    }

    fn vring_need_event(event_idx: u16, new_idx: u16, old_idx: u16) -> bool {
        new_idx.wrapping_sub(event_idx).wrapping_sub(1) < new_idx.wrapping_sub(old_idx)
    }

    pub fn should_interrupt_driver(&mut self) -> bool {
        if !self.ready {
            return false;
        }
        // Pairs with the full barrier the driver executes between re-enabling
        // interrupts (writing `used_event`, or clearing NO_INTERRUPT) and
        // re-reading `used.idx` (`virtqueue_enable_cb_prepare` +
        // `virtqueue_poll`; vhost_notify). Without it this CPU can read the
        // old `used_event` while the `used.idx` it just published still sits
        // in its store buffer: a driver re-arming in that window sees nothing
        // new and waits for an interrupt that never comes.
        fence(Ordering::SeqCst);
        let new_used = self.last_used_idx;
        let old_used = self.last_used_signaled;
        self.last_used_signaled = new_used;
        if self.event_idx {
            let used_event = self.used_event();
            Self::vring_need_event(used_event, new_used, old_used)
        } else {
            (self.avail_flags() & 1) == 0
        }
    }
}

// `Virtqueue` AUTO-derives Send: its only non-trivial field is an
// `Arc<GuestMemory>` (Send+Sync), the rest are scalars. No `unsafe impl`
// needed. (The raw guest pointers live in `ChainBuf`/`PoppedChain`, which are
// separate and never escape a single drain on one thread.)

#[cfg(test)]
mod tests {
    use super::*;

    /// Tiny deterministic xorshift PRNG — keeps the fuzz reproducible with no
    /// external dependency.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    // The hostile-guest property: `pop()` over a fully attacker-controlled
    // descriptor table / avail ring must never panic, never loop unbounded, and
    // never hand back a buffer outside guest RAM. We scribble random bytes over
    // the ring region and drain repeatedly. Mirrors C++ `--virtio-queue-fuzz-test`.
    #[test]
    fn pop_never_panics_on_random_rings() {
        let mem = Arc::new(GuestMemory::new_host_only(256 * 1024).unwrap());
        let slab = mem.size() as u64;
        let desc_gpa = 0x1000u64;
        let avail_gpa = 0x8000u64;
        let used_gpa = 0x1_0000u64;
        let mut rng = Rng(0x1234_5678_9abc_def0);
        let mut scratch = [0u8; 256];

        for iter in 0..20_000u32 {
            // Random size: power of two in 2..=256.
            let size = 1u32 << (1 + (rng.next() % 8));
            // Scribble random bytes over each ring structure.
            for &base in &[desc_gpa, avail_gpa, used_gpa] {
                let span = 16 * size as u64 + 8;
                let mut off = 0u64;
                while off < span && base + off + 256 <= slab {
                    for b in scratch.iter_mut() {
                        *b = rng.next() as u8;
                    }
                    let _ = mem.write_at(base + off, &scratch);
                    off += 256;
                }
            }

            let mut q = Virtqueue::new(mem.clone(), 256);
            q.set_size(size);
            q.set_desc_gpa(desc_gpa);
            q.set_avail_gpa(avail_gpa);
            q.set_used_gpa(used_gpa);
            q.set_event_idx_enabled(iter & 1 == 0);
            q.set_ready(true);

            // Drain a bounded number of chains; must always terminate. Any chain
            // we get back must point inside the slab.
            for _ in 0..(size + 4) {
                match q.pop() {
                    Some(chain) => {
                        for buf in &chain.bufs {
                            assert!(buf.len as u64 <= slab, "chain buf len escapes slab");
                        }
                    }
                    None => break,
                }
            }
        }
    }

    // EVENT_IDX notification races, run as store-buffer litmus tests on real
    // CPUs: the device and a model of the Linux driver each store their side
    // of the handshake and then load the other's. Without a full fence on the
    // device side both loads can miss, and the notification is lost.
    const SIZE: u32 = 256;
    const DESC: u64 = 0x1000;
    const AVAIL: u64 = 0x2000;
    const USED: u64 = 0x3000;
    const USED_EVENT: u64 = AVAIL + 4 + 2 * SIZE as u64;
    const AVAIL_EVENT: u64 = USED + 4 + 8 * SIZE as u64;
    const ROUNDS: u32 = 200_000;

    fn litmus_queue() -> (Arc<GuestMemory>, Virtqueue) {
        let mem = Arc::new(GuestMemory::new_host_only(64 * 1024).unwrap());
        // Every avail entry names descriptor 0: one 64-byte readable buffer.
        let mut d = [0u8; 16];
        d[..8].copy_from_slice(&0x8000u64.to_le_bytes());
        d[8..12].copy_from_slice(&64u32.to_le_bytes());
        mem.write_at(DESC, &d).unwrap();
        let mut q = Virtqueue::new(mem.clone(), SIZE);
        q.set_size(SIZE);
        q.set_desc_gpa(DESC);
        q.set_avail_gpa(AVAIL);
        q.set_used_gpa(USED);
        q.set_event_idx_enabled(true);
        q.set_ready(true);
        (mem, q)
    }

    /// Both threads arrive, then go on together.
    fn rendezvous(gate: &std::sync::atomic::AtomicU32, phase: u32) {
        gate.fetch_add(1, Ordering::SeqCst);
        let mut spins = 0u32;
        while gate.load(Ordering::SeqCst) < 2 * (phase + 1) {
            spins += 1;
            if spins % 1024 == 0 {
                std::thread::yield_now();
            } else {
                std::hint::spin_loop();
            }
        }
    }

    /// Run `ROUNDS` rounds of `device` and `driver` on two threads, starting
    /// each round on both at once, and count the rounds in which neither saw
    /// the other's store: notifications lost. Each side calls the `decided`
    /// callback it is given once per round, after its race and before it
    /// readies the next round, so neither reads the other's clean-up.
    fn lost_notifications(
        mut device: impl FnMut(u32, &dyn Fn()) -> bool + Send,
        mut driver: impl FnMut(u32, &dyn Fn()) -> bool + Send,
    ) -> usize {
        let gate = std::sync::atomic::AtomicU32::new(0);
        let gate = &gate;
        let (dev, drv) = std::thread::scope(|s| {
            let d = s.spawn(move || {
                (0..ROUNDS)
                    .map(|r| {
                        rendezvous(gate, 2 * r);
                        device(r, &|| rendezvous(gate, 2 * r + 1))
                    })
                    .collect::<Vec<_>>()
            });
            let r = s.spawn(move || {
                (0..ROUNDS)
                    .map(|r| {
                        rendezvous(gate, 2 * r);
                        driver(r, &|| rendezvous(gate, 2 * r + 1))
                    })
                    .collect::<Vec<_>>()
            });
            (d.join().unwrap(), r.join().unwrap())
        });
        dev.iter().zip(&drv).filter(|&(&d, &r)| !d && !r).count()
    }

    /// Round r: the device publishes used entry r and decides whether to
    /// interrupt, while the driver, having consumed entries < r, re-enables
    /// interrupts at r and re-checks `used.idx` (`virtqueue_enable_cb_prepare`
    /// + `virtqueue_poll`).
    #[test]
    fn used_buffer_interrupt_is_never_lost() {
        let (mem, mut q) = litmus_queue();
        // The driver last re-enabled at "round -1".
        assert!(mem.store_release_u16(USED_EVENT, u16::MAX));
        let lost = lost_notifications(
            |_, decided| {
                q.push(0, 0);
                let irq = q.should_interrupt_driver();
                decided();
                irq
            },
            |r, decided| {
                let r = r as u16;
                assert!(mem.store_release_u16(USED_EVENT, r));
                fence(Ordering::SeqCst);
                let more = mem.load_acquire_u16(USED + 2) != Some(r);
                decided();
                more
            },
        );
        assert_eq!(lost, 0, "{lost} of {ROUNDS} used-buffer interrupts lost");
    }

    /// Round r: entry 2r is already available. The device pops it, then finds
    /// the ring empty unless it sees entry 2r+1, which the driver publishes
    /// meanwhile before deciding whether to kick (`virtqueue_kick_prepare`).
    #[test]
    fn available_buffer_kick_is_never_lost() {
        let (mem, mut q) = litmus_queue();
        let mut chain = ChainScratch::default();
        assert!(mem.store_release_u16(AVAIL + 2, 1)); // entry 0
        let lost = lost_notifications(
            |_, decided| {
                assert!(q.pop_into(&mut chain), "entry 2r was published");
                let got = q.pop_into(&mut chain);
                decided();
                // Take a missed entry 2r+1 now, so the next round starts alike.
                if !got {
                    assert!(q.pop_into(&mut chain));
                }
                got
            },
            |r, decided| {
                let new = (2 * r + 2) as u16;
                assert!(mem.store_release_u16(AVAIL + 2, new));
                fence(Ordering::SeqCst);
                let event = mem.load_acquire_u16(AVAIL_EVENT).unwrap();
                decided();
                // Entry 2r+2, which the device pops next round.
                assert!(mem.store_release_u16(AVAIL + 2, new.wrapping_add(1)));
                Virtqueue::vring_need_event(event, new, new.wrapping_sub(1))
            },
        );
        assert_eq!(lost, 0, "{lost} of {ROUNDS} available-buffer kicks lost");
    }
}
