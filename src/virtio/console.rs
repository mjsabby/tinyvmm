//! virtio-console device (spec §5.3). Single-port. TX (queue 1) routed to host
//! stdout; host stdin pushed into RX (queue 0) for an interactive hvc0.
//! Port of src/virtio/virtio_console.cpp.

use crate::virtio::device::{
    DEVICE_ID_CONSOLE, FEATURE_RING_EVENT_IDX, FEATURE_VERSION_1, VirtioDevice,
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
            pending.extend(data.iter().copied());
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

    fn drain_tx(&self) {
        let mut interrupt = false;
        let mut total_chains = 0u64;
        {
            let mut q = self.txq.lock().unwrap();
            if !q.ready() {
                return;
            }
            let mut observer = self.byte_observer.lock().unwrap();
            let mut out = std::io::stdout().lock();
            let mut chain = self.tx_scratch.lock().unwrap();
            while q.pop_into(&mut chain) {
                for buf in &chain.bufs {
                    if buf.write || buf.len == 0 {
                        continue;
                    }
                    let bytes = buf.as_slice();
                    let _ = out.write_all(bytes);
                    if let Some(obs) = observer.as_mut() {
                        obs(bytes);
                    }
                    self.tx_bytes
                        .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                }
                let _ = out.flush();
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

/// Drain pending host input into the RX queue. Caller holds rx_pending + rxq +
/// the reusable `chain` scratch. Returns whether an RX interrupt should be raised.
fn drain_rx(q: &mut Virtqueue, pending: &mut VecDeque<u8>, chain: &mut PoppedChain) -> bool {
    let mut any = false;
    while !pending.is_empty() {
        if !q.pop_into(chain) {
            break;
        }
        let mut total = 0u32;
        for buf in chain.bufs.iter_mut() {
            if !buf.write || buf.len == 0 {
                continue;
            }
            let dst = buf.as_mut_slice();
            let mut i = 0;
            while i < dst.len() {
                match pending.pop_front() {
                    Some(b) => {
                        dst[i] = b;
                        i += 1;
                    }
                    None => break,
                }
            }
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
