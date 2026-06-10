//! virtio-rng device (spec §5.4). Port of src/virtio/virtio_rng.cpp.
//!
//! The simplest possible virtio device: a single "requestq" virtqueue (queue 0)
//! whose chains are entirely device-writable. We fill each writable buffer with
//! cryptographically-random bytes from the host CNG provider
//! ([`crate::host::random_fill`]) and post the chain to the used ring with
//! `len` equal to the total bytes written.
//!
//! No device-specific feature bits and no device config space. The fill is
//! cheap (no I/O), so — like the C++ — it runs inline on whichever thread wrote
//! the queue-notify MMIO (no doorbell installed). The `Mutex<Virtqueue>`
//! serializes concurrent notifies from multiple vCPUs.

use crate::diag::etw;
use crate::host;
use crate::virtio::device::{
    DEVICE_ID_RNG, FEATURE_RING_EVENT_IDX, FEATURE_VERSION_1, VirtioDevice,
};
use crate::virtio::queue::{PoppedChain, Virtqueue};
use crate::whp::GuestMemory;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

pub const RNG_REQUEST_QUEUE: u32 = 0;
pub const RNG_QUEUE_MAX: u32 = 64;
/// Cap on random bytes generated per request chain. `BCryptGenRandom` runs
/// synchronously on the vCPU thread (rng has no doorbell), and a hostile chain
/// can present device-writable buffers summing to gigabytes — which would freeze
/// the issuing vCPU. Returning fewer bytes than requested is spec-legal (the
/// guest simply re-requests).
const RNG_MAX_FILL: u32 = 1 << 20;

pub type IrqFn = Box<dyn Fn(u32) + Send + Sync>;

pub struct RngDevice {
    queue: Mutex<Virtqueue>,
    driver_ok: AtomicBool,
    acked_features: AtomicU64,
    irq: OnceLock<IrqFn>,
    ops_done: AtomicU64,
    bytes_out: AtomicU64,
}

impl RngDevice {
    pub fn new(mem: Arc<GuestMemory>) -> Arc<Self> {
        Arc::new(RngDevice {
            queue: Mutex::new(Virtqueue::new(mem, RNG_QUEUE_MAX)),
            driver_ok: AtomicBool::new(false),
            acked_features: AtomicU64::new(0),
            irq: OnceLock::new(),
            ops_done: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
        })
    }

    pub fn set_irq_callback(&self, f: IrqFn) {
        let _ = self.irq.set(f);
    }

    pub fn ops_done(&self) -> u64 {
        self.ops_done.load(Ordering::Relaxed)
    }
    pub fn bytes_out(&self) -> u64 {
        self.bytes_out.load(Ordering::Relaxed)
    }

    fn raise(&self, qidx: u32) {
        if let Some(cb) = self.irq.get() {
            cb(qidx);
        }
    }

    fn drain_request_queue(&self) {
        let mut chain = PoppedChain::default();
        let mut ops = 0u64;
        let mut bytes = 0u64;
        let mut interrupt = false;
        {
            let mut q = self.queue.lock().unwrap();
            if !q.ready() {
                return;
            }
            while q.pop_into(&mut chain) {
                let mut total = 0u32;
                // Spec §5.4.6.1: every buffer in the chain is device-writable.
                // Ignore any read-only buffers a misbehaving driver tacks on.
                for buf in chain.bufs.iter_mut() {
                    if !buf.write || buf.len == 0 {
                        continue;
                    }
                    if total >= RNG_MAX_FILL {
                        break;
                    }
                    let want = buf.len.min((RNG_MAX_FILL - total) as usize);
                    if host::random_fill(&mut buf.as_mut_slice()[..want]) {
                        total += want as u32;
                    }
                }
                q.push(chain.head_index, total);
                ops += 1;
                bytes += total as u64;
            }
            if ops > 0 {
                interrupt = q.should_interrupt_driver();
            }
        }
        if ops > 0 {
            self.ops_done.fetch_add(ops, Ordering::Relaxed);
            self.bytes_out.fetch_add(bytes, Ordering::Relaxed);
            if etw::enabled(etw::VERBOSE, etw::kw::VIRTIO) {
                etw::Event::new("RngFill", etw::VERBOSE, etw::kw::VIRTIO)
                    .u64("ops", ops)
                    .u64("bytes", bytes)
                    .write();
            }
        }
        if interrupt {
            self.raise(RNG_REQUEST_QUEUE);
        }
    }
}

impl VirtioDevice for RngDevice {
    fn device_id(&self) -> u32 {
        DEVICE_ID_RNG
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
        1
    }

    fn queue_max(&self, idx: u32) -> u32 {
        if idx == RNG_REQUEST_QUEUE {
            RNG_QUEUE_MAX
        } else {
            0
        }
    }

    fn enable_queue(&self, idx: u32, desc: u64, avail: u64, used: u64, size: u16, event_idx: bool) {
        if idx != RNG_REQUEST_QUEUE {
            return;
        }
        let mut q = self.queue.lock().unwrap();
        q.set_desc_gpa(desc);
        q.set_avail_gpa(avail);
        q.set_used_gpa(used);
        q.set_size(size as u32);
        q.set_event_idx_enabled(event_idx);
        q.set_ready(true);
    }

    fn disable_queue(&self, idx: u32) {
        if idx == RNG_REQUEST_QUEUE {
            self.queue.lock().unwrap().set_ready(false);
        }
    }

    fn notify_queue(&self, idx: u32) {
        if idx == RNG_REQUEST_QUEUE {
            self.drain_request_queue();
        }
    }

    fn driver_ok(&self) {
        self.driver_ok.store(true, Ordering::Relaxed);
    }

    fn reset(&self) {
        self.driver_ok.store(false, Ordering::Relaxed);
        self.acked_features.store(0, Ordering::Relaxed);
        self.queue.lock().unwrap().reset();
        // ops/bytes are diagnostic counters; deliberately not cleared.
    }

    fn capture_queue(&self, idx: u32) -> Option<crate::virtio::queue::QueueState> {
        if idx == RNG_REQUEST_QUEUE {
            Some(self.queue.lock().unwrap().capture())
        } else {
            None
        }
    }
    fn apply_queue(&self, idx: u32, st: &crate::virtio::queue::QueueState) {
        if idx == RNG_REQUEST_QUEUE {
            self.queue.lock().unwrap().apply(st);
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
