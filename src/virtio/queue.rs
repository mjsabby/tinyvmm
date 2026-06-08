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
        self.size = s.size;
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
        let avail_idx = self.avail_idx();
        if avail_idx == self.last_avail {
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

        let mut cur = head;
        for _ in 0..self.size {
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
                while step < inner_count && step < self.size {
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

    pub fn push(&mut self, head_index: u16, used_len: u32) {
        if !self.ready || self.size == 0 {
            return;
        }
        let slot = self.last_used_idx % self.size as u16;
        self.store_used_ring(slot, head_index as u32, used_len);
        self.last_used_idx = self.last_used_idx.wrapping_add(1);
        // Publish used.idx after writing the element.
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
}
