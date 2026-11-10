//! Common virtio constants and the device-side interface the PCI transport
//! drives. Port of src/virtio/virtio.h (device hooks reshaped so queues stay
//! owned by the device).

use crate::virtio::queue::QueueState;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// The VM is stopping: its vCPUs have been told to stop and teardown (or a
/// snapshot) follows. One VM per process, so one flag.
static VM_STOPPING: AtomicBool = AtomicBool::new(false);

/// When the disk work a guest left queued stops being run (see
/// [`guest_work_cut_off`]). Set once, by the first stop.
static GUEST_WORK_UNTIL: OnceLock<Instant> = OnceLock::new();

/// Tell every device the VM is stopping (see [`vm_stopping`]). `patience` is
/// how much longer the disks run what the guest has queued on them (see
/// [`guest_work_cut_off`]): none for a stop that keeps nothing of the guest,
/// some for one a snapshot follows. The first call decides.
pub fn set_vm_stopping(patience: Duration) {
    // Before the flag, so that whoever sees the flag finds the time.
    GUEST_WORK_UNTIL.get_or_init(|| Instant::now() + patience);
    VM_STOPPING.store(true, Ordering::Release);
}

/// Whether the VM is stopping. Two things go by it:
///
/// * what the host itself would put on a ring (console input, input events,
///   the audio workers' periods): from here on they leave the rings alone,
///   checked under the queue's lock, so that a snapshot captures rings at
///   rest and teardown isn't racing them;
/// * the console's output drain, which writes less of each chain: the stop
///   flag of a vCPU is only looked at between VM exits, and a doorbell pump
///   is only joined between drains, so what the guest queued stands between
///   the user and the stop they asked for.
///
/// No drain leaves chains behind on its account: one that did would give a
/// snapshot requests the guest has kicked for and the restored guest would
/// never kick for again. A drain is bounded instead, by the ring's size and
/// by what each device does per chain. The disk is the exception, as one
/// chain of its can name the whole disk many times over: see
/// [`guest_work_cut_off`].
pub fn vm_stopping() -> bool {
    VM_STOPPING.load(Ordering::Acquire)
}

/// Whether the disks have stopped running what the guest queued on them: the
/// VM is stopping, and the time [`set_vm_stopping`] gave that work is up. A
/// disk's drain looks at this between requests and between the segments of
/// one, on whichever thread it runs (a vCPU's, when the kick was a VM exit),
/// so a guest can't choose how long a stop takes by what it queues. A disk
/// that left work behind on this account says so
/// (`BlockDevice::left_work_behind`), and no snapshot is written of it.
pub fn guest_work_cut_off() -> bool {
    vm_stopping()
        && GUEST_WORK_UNTIL
            .get()
            .is_some_and(|until| Instant::now() >= *until)
}

pub const DEVICE_ID_NET: u32 = 1;
pub const DEVICE_ID_BLOCK: u32 = 2;
pub const DEVICE_ID_CONSOLE: u32 = 3;
pub const DEVICE_ID_RNG: u32 = 4;
pub const DEVICE_ID_P9: u32 = 9;
pub const DEVICE_ID_GPU: u32 = 16;
pub const DEVICE_ID_INPUT: u32 = 18;
pub const DEVICE_ID_SOUND: u32 = 25;

pub const FEATURE_RING_EVENT_IDX: u64 = 1 << 29;
pub const FEATURE_VERSION_1: u64 = 1 << 32;

pub const STATUS_FEATURES_OK: u8 = 8;
pub const STATUS_DRIVER_OK: u8 = 4;
pub const STATUS_NEEDS_RESET: u8 = 0x40;

/// Implemented by each virtio device. The transport owns the register state
/// machine; the device owns its virtqueues and sees feature negotiation,
/// queue lifecycle, and notify kicks.
pub trait VirtioDevice: Send + Sync {
    fn device_id(&self) -> u32;
    fn device_features(&self) -> u64;
    fn set_driver_features(&self, acked: u64) -> bool;

    fn queue_count(&self) -> u32;
    fn queue_max(&self, idx: u32) -> u32;

    /// Program queue `idx` and mark it ready.
    fn enable_queue(&self, idx: u32, desc: u64, avail: u64, used: u64, size: u16, event_idx: bool);
    /// Mark queue `idx` not-ready.
    fn disable_queue(&self, idx: u32);

    /// Driver kicked QueueNotify with `idx`. Runs on the doorbell pump thread
    /// (or, without doorbells, the vCPU thread).
    fn notify_queue(&self, idx: u32);

    /// Whether queue `idx` has requests waiting, checked cheaply enough for the
    /// doorbell pump to spin on it (see `transport::doorbell_pump`). Devices
    /// returning `None`, the default, are never busy-polled.
    fn queue_has_work(&self, idx: u32) -> Option<bool> {
        let _ = idx;
        None
    }

    fn driver_ok(&self);
    fn reset(&self);

    /// Whether a reset is still settling requests taken before it. Until it
    /// clears, the transport keeps `device_status` non-zero, and the driver
    /// waits for 0 before reinitializing the device (virtio-pci requires this;
    /// Linux's `vp_reset` polls). Lets a device with I/O in flight finish a
    /// reset without blocking the vCPU under the transport lock. Default:
    /// resets complete immediately.
    fn reset_pending(&self) -> bool {
        false
    }

    fn read_config(&self, offset: u32, size: u32) -> u32 {
        let _ = (offset, size);
        0
    }
    fn write_config(&self, offset: u32, size: u32, value: u32) {
        let _ = (offset, size, value);
    }

    // ---- save/restore hooks (default: no-op / nothing to snapshot) ----
    /// Capture queue `idx`'s programming + ring position.
    fn capture_queue(&self, idx: u32) -> Option<QueueState> {
        let _ = idx;
        None
    }
    /// Restore queue `idx`'s programming + ring position.
    fn apply_queue(&self, idx: u32, st: &QueueState) {
        let _ = (idx, st);
    }
    /// Encode the device-specific durable state (driver_ok / features / config).
    fn capture_device_state(&self) -> Vec<u8> {
        Vec::new()
    }
    /// Restore the device-specific durable state.
    fn apply_device_state(&self, bytes: &[u8]) {
        let _ = bytes;
    }
}
