//! virtio-console device (spec §5.3). Single-port. TX (queue 1) routed to host
//! stdout; host stdin pushed into RX (queue 0) for an interactive hvc0.
//! Port of src/virtio/virtio_console.cpp.

use crate::virtio::device::{
    DEVICE_ID_CONSOLE, FEATURE_RING_EVENT_IDX, FEATURE_VERSION_1, VirtioDevice, vm_stopping,
};
use crate::virtio::queue::{ChainScratch, PoppedChain, Virtqueue};
use crate::whp::GuestMemory;
use std::collections::VecDeque;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

pub const CONSOLE_RX_QUEUE: u32 = 0;
pub const CONSOLE_TX_QUEUE: u32 = 1;
pub const CONSOLE_QUEUE_MAX: u32 = 64;
/// The most bytes of one TX chain written to the host. A chain's descriptors
/// can each name all of guest RAM, so without a limit one chain is gigabytes
/// of output written under the queue lock. Linux's driver sends at most
/// 256 KiB in a chain (a spliced pipe, a page per descriptor; a write is
/// 32 KiB, a console line a page); what a chain holds beyond this is dropped.
const TX_CHAIN_MAX: usize = 1 << 20;
/// The same limit once the VM is stopping, when the output still queued (at
/// most a ring of chains) stands between the user and the stop they asked
/// for: a console line or a write still fits whole.
const TX_CHAIN_MAX_STOPPING: usize = 64 << 10;
/// The most host input held for a guest that isn't taking it. Past it, new
/// input is dropped, as a full tty buffer drops it.
const RX_PENDING_MAX: usize = 16 << 20;

pub type IrqFn = Box<dyn Fn(u32) + Send + Sync>;
pub type ByteObserverFn = Box<dyn FnMut(&[u8]) + Send>;

pub struct ConsoleDevice {
    rxq: Mutex<Virtqueue>,
    txq: Mutex<Virtqueue>,
    rx_pending: Mutex<VecDeque<u8>>,
    driver_ok: AtomicBool,
    acked_features: AtomicU64,
    // Set once during setup (before any vCPU/backend thread runs), then read
    // lock-free on every interrupt raise. Mirrors block_file's OnceLock callback.
    irq: OnceLock<IrqFn>,
    byte_observer: Mutex<Option<ByteObserverFn>>,
    tx_bytes: AtomicU64,
    /// Bytes of oversized TX chains that were dropped (see `TX_CHAIN_MAX`).
    tx_dropped: AtomicU64,
    /// Host input bytes dropped at a full backlog (see `RX_PENDING_MAX`).
    rx_dropped: AtomicU64,
    // Reused descriptor-chain scratch per direction so draining the ring
    // allocates nothing (the console TX path carries every hvc0 byte).
    tx_scratch: Mutex<ChainScratch>,
    rx_scratch: Mutex<ChainScratch>,
}

impl ConsoleDevice {
    pub fn new(mem: Arc<GuestMemory>) -> Arc<Self> {
        Arc::new(ConsoleDevice {
            rxq: Mutex::new(Virtqueue::new(mem.clone(), CONSOLE_QUEUE_MAX)),
            txq: Mutex::new(Virtqueue::new(mem, CONSOLE_QUEUE_MAX)),
            rx_pending: Mutex::new(VecDeque::new()),
            driver_ok: AtomicBool::new(false),
            acked_features: AtomicU64::new(0),
            irq: OnceLock::new(),
            byte_observer: Mutex::new(None),
            tx_bytes: AtomicU64::new(0),
            tx_dropped: AtomicU64::new(0),
            rx_dropped: AtomicU64::new(0),
            tx_scratch: Mutex::new(ChainScratch::default()),
            rx_scratch: Mutex::new(ChainScratch::default()),
        })
    }

    pub fn set_irq_callback(&self, f: IrqFn) {
        let _ = self.irq.set(f);
    }
    pub fn set_byte_observer(&self, f: ByteObserverFn) {
        *self.byte_observer.lock().unwrap() = Some(f);
    }
    pub fn tx_bytes(&self) -> u64 {
        self.tx_bytes.load(Ordering::Relaxed)
    }
    /// Guest output bytes dropped from chains over the per-chain limit.
    pub fn tx_dropped(&self) -> u64 {
        self.tx_dropped.load(Ordering::Relaxed)
    }
    /// Host input bytes dropped because the guest wasn't taking input.
    pub fn rx_dropped(&self) -> u64 {
        self.rx_dropped.load(Ordering::Relaxed)
    }

    fn raise(&self, qidx: u32) {
        if let Some(cb) = self.irq.get() {
            cb(qidx);
        }
    }

    /// Push host-side input bytes toward the guest's /dev/hvc0. Thread-safe.
    pub fn write_host_input(&self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let mut interrupt = false;
        {
            let mut pending = self.rx_pending.lock().unwrap();
            let room = RX_PENDING_MAX.saturating_sub(pending.len());
            let take = data.len().min(room);
            if take < data.len() {
                self.rx_dropped
                    .fetch_add((data.len() - take) as u64, Ordering::Relaxed);
            }
            pending.extend(data[..take].iter().copied());
            let mut q = self.rxq.lock().unwrap();
            // Once the VM is stopping the ring is left alone: no vCPU will run
            // to read it, and a snapshot may be capturing it (the check is
            // under the queue's lock, which the capture takes before it reads
            // guest RAM, so a delivery already under way finishes first).
            if q.ready() && !vm_stopping() {
                let mut chain = self.rx_scratch.lock().unwrap();
                interrupt = drain_rx(&mut q, &mut pending, &mut chain);
            }
        }
        if interrupt {
            self.raise(CONSOLE_RX_QUEUE);
        }
    }

    fn drain_tx(&self) {
        let mut interrupt = false;
        let mut total_chains = 0u64;
        {
            let mut q = self.txq.lock().unwrap();
            if !q.ready() {
                return;
            }
            let mut observer = self.byte_observer.lock().unwrap();
            let mut chain = self.tx_scratch.lock().unwrap();
            while q.pop_into(&mut chain) {
                // The limit is read per chain: the observer below can be what
                // stops the VM (the shutdown sentinel).
                let limit = if vm_stopping() {
                    TX_CHAIN_MAX_STOPPING
                } else {
                    TX_CHAIN_MAX
                };
                // stdout is locked for one chain at a time, not for the whole
                // drain, so the rest of tinyvmm (teardown's own messages) is
                // never held up behind a guest that keeps the queue full.
                let mut out = std::io::stdout().lock();
                let (sent, dropped) = emit_chain(&chain, limit, |bytes| {
                    let _ = out.write_all(bytes);
                    if let Some(obs) = observer.as_mut() {
                        obs(bytes);
                    }
                });
                let _ = out.flush();
                drop(out);
                self.tx_bytes.fetch_add(sent, Ordering::Relaxed);
                if dropped > 0 {
                    self.tx_dropped.fetch_add(dropped, Ordering::Relaxed);
                }
                q.push(chain.head_index, 0);
                total_chains += 1;
            }
            if total_chains > 0 {
                interrupt = q.should_interrupt_driver();
            }
        }
        if interrupt {
            self.raise(CONSOLE_TX_QUEUE);
        }
    }
}

/// Hand the driver-written bytes of a TX chain to `emit`, in pieces of up to
/// 4 KiB, but no more than `limit` of them in all. Returns how many bytes
/// were emitted and how many the chain held beyond the limit.
fn emit_chain(chain: &PoppedChain, limit: usize, mut emit: impl FnMut(&[u8])) -> (u64, u64) {
    let mut bytes = [0u8; 4096];
    let mut left = limit;
    let (mut sent, mut dropped) = (0u64, 0u64);
    for buf in &chain.bufs {
        if buf.write || buf.len == 0 {
            continue;
        }
        let take = buf.len.min(left);
        let mut off = 0;
        while off < take {
            let want = (take - off).min(bytes.len());
            let n = buf.read_at(off, &mut bytes[..want]);
            emit(&bytes[..n]);
            off += n;
        }
        left -= take;
        sent += take as u64;
        dropped += (buf.len - take) as u64;
    }
    (sent, dropped)
}

/// Drain pending host input into the RX queue. Caller holds rx_pending + rxq +
/// the reusable `chain` scratch. Returns whether an RX interrupt should be raised.
fn drain_rx(q: &mut Virtqueue, pending: &mut VecDeque<u8>, chain: &mut PoppedChain) -> bool {
    let mut any = false;
    while !pending.is_empty() {
        if !q.pop_into(chain) {
            break;
        }
        let mut total = 0u32;
        for buf in chain.bufs.iter() {
            if !buf.write || buf.len == 0 {
                continue;
            }
            let (a, b) = pending.as_slices();
            let mut i = buf.write_at(0, a);
            if i == a.len() {
                i += buf.write_at(i, b);
            }
            pending.drain(..i);
            total += i as u32;
            if pending.is_empty() {
                break;
            }
        }
        q.push(chain.head_index, total);
        any = true;
        if total == 0 {
            break;
        }
    }
    any && q.should_interrupt_driver()
}

impl VirtioDevice for ConsoleDevice {
    fn device_id(&self) -> u32 {
        DEVICE_ID_CONSOLE
    }

    fn device_features(&self) -> u64 {
        FEATURE_VERSION_1 | FEATURE_RING_EVENT_IDX
    }

    fn set_driver_features(&self, acked: u64) -> bool {
        if acked & FEATURE_VERSION_1 == 0 {
            return false;
        }
        if acked & !self.device_features() != 0 {
            return false;
        }
        self.acked_features.store(acked, Ordering::Relaxed);
        true
    }

    fn queue_count(&self) -> u32 {
        2
    }

    fn queue_max(&self, idx: u32) -> u32 {
        if idx == CONSOLE_RX_QUEUE || idx == CONSOLE_TX_QUEUE {
            CONSOLE_QUEUE_MAX
        } else {
            0
        }
    }

    fn enable_queue(&self, idx: u32, desc: u64, avail: u64, used: u64, size: u16, event_idx: bool) {
        let q = match idx {
            CONSOLE_RX_QUEUE => &self.rxq,
            CONSOLE_TX_QUEUE => &self.txq,
            _ => return,
        };
        let mut q = q.lock().unwrap();
        q.set_desc_gpa(desc);
        q.set_avail_gpa(avail);
        q.set_used_gpa(used);
        q.set_size(size as u32);
        q.set_event_idx_enabled(event_idx);
        q.set_ready(true);
    }

    fn disable_queue(&self, idx: u32) {
        let q = match idx {
            CONSOLE_RX_QUEUE => &self.rxq,
            CONSOLE_TX_QUEUE => &self.txq,
            _ => return,
        };
        q.lock().unwrap().set_ready(false);
    }

    fn notify_queue(&self, idx: u32) {
        if idx == CONSOLE_TX_QUEUE {
            self.drain_tx();
        } else if idx == CONSOLE_RX_QUEUE {
            let mut interrupt = false;
            {
                let mut pending = self.rx_pending.lock().unwrap();
                let mut q = self.rxq.lock().unwrap();
                if q.ready() {
                    let mut chain = self.rx_scratch.lock().unwrap();
                    interrupt = drain_rx(&mut q, &mut pending, &mut chain);
                }
            }
            if interrupt {
                self.raise(CONSOLE_RX_QUEUE);
            }
        }
    }

    fn driver_ok(&self) {
        self.driver_ok.store(true, Ordering::Relaxed);
    }

    fn reset(&self) {
        self.driver_ok.store(false, Ordering::Relaxed);
        self.acked_features.store(0, Ordering::Relaxed);
        self.rx_pending.lock().unwrap().clear();
        self.rxq.lock().unwrap().reset();
        self.txq.lock().unwrap().reset();
    }

    fn read_config(&self, _offset: u32, _size: u32) -> u32 {
        0 // cols/rows/max_nr_ports/emerg_wr all zero
    }

    fn capture_queue(&self, idx: u32) -> Option<crate::virtio::queue::QueueState> {
        match idx {
            CONSOLE_RX_QUEUE => Some(self.rxq.lock().unwrap().capture()),
            CONSOLE_TX_QUEUE => Some(self.txq.lock().unwrap().capture()),
            _ => None,
        }
    }
    fn apply_queue(&self, idx: u32, st: &crate::virtio::queue::QueueState) {
        match idx {
            CONSOLE_RX_QUEUE => self.rxq.lock().unwrap().apply(st),
            CONSOLE_TX_QUEUE => self.txq.lock().unwrap().apply(st),
            _ => {}
        }
    }
    fn capture_device_state(&self) -> Vec<u8> {
        let mut b = vec![0u8; 16];
        b[0] = self.driver_ok.load(Ordering::Relaxed) as u8;
        b[8..16].copy_from_slice(&self.acked_features.load(Ordering::Relaxed).to_le_bytes());
        b
    }
    fn apply_device_state(&self, bytes: &[u8]) {
        if bytes.len() >= 16 {
            self.driver_ok.store(bytes[0] != 0, Ordering::Relaxed);
            self.acked_features.store(
                u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
                Ordering::Relaxed,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::queue::ChainBuf;

    /// A chain over `bufs` (host memory standing in for guest RAM).
    fn chain_of(bufs: &mut [(Vec<u8>, bool)]) -> PoppedChain {
        PoppedChain {
            head_index: 0,
            bufs: bufs
                .iter_mut()
                .map(|(data, write)| ChainBuf {
                    ptr: data.as_mut_ptr(),
                    len: data.len(),
                    write: *write,
                })
                .collect(),
        }
    }

    /// The driver-written buffers of a chain come out in order and whole,
    /// whatever their sizes; device-writable ones are skipped.
    #[test]
    fn a_chain_is_emitted_in_order() {
        let mut bufs = vec![
            ((0..5000u32).map(|i| i as u8).collect::<Vec<u8>>(), false),
            (vec![0xEE; 64], true),
            (Vec::new(), false),
            (b"tail".to_vec(), false),
        ];
        let want: Vec<u8> = [&bufs[0].0[..], b"tail"].concat();
        let chain = chain_of(&mut bufs);
        let mut got = Vec::new();
        let counts = emit_chain(&chain, TX_CHAIN_MAX, |b| got.extend_from_slice(b));
        assert_eq!(counts, (5004, 0));
        assert_eq!(got, want);
    }

    /// A chain's descriptors can each name all of guest RAM (64 of them, each
    /// gigabytes): only the first `limit` bytes are written, the rest counted.
    /// Before the limit, one TX notification wrote 3.9 GiB to the host's
    /// stdout from 64 descriptors aliasing one 64 KiB buffer.
    #[test]
    fn a_chain_is_cut_at_the_limit() {
        let mut bufs: Vec<(Vec<u8>, bool)> = (0..64u8).map(|i| (vec![i; 3000], false)).collect();
        let chain = chain_of(&mut bufs);
        let mut got = Vec::new();
        let (sent, dropped) = emit_chain(&chain, 10_000, |b| got.extend_from_slice(b));
        assert_eq!((sent, dropped), (10_000, 64 * 3000 - 10_000));
        assert_eq!(got.len(), 10_000);
        assert_eq!((got[2999], got[3000], got[9999]), (0, 1, 3));
    }

    /// Host input for a guest that posts no RX buffers is held up to a limit,
    /// then dropped, rather than growing without bound.
    #[test]
    fn host_input_backlog_is_bounded() {
        let mem = Arc::new(GuestMemory::new_host_only(4096).unwrap());
        let dev = ConsoleDevice::new(mem);
        let chunk = vec![b'x'; 1 << 20];
        for _ in 0..20 {
            dev.write_host_input(&chunk);
        }
        assert_eq!(dev.rx_pending.lock().unwrap().len(), RX_PENDING_MAX);
        assert_eq!(dev.rx_dropped(), (20 << 20) - RX_PENDING_MAX as u64);
    }
}
