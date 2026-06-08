//! Common virtio constants and the device-side interface the PCI transport
//! drives. Port of src/virtio/virtio.h (device hooks reshaped so queues stay
//! owned by the device).

use crate::virtio::queue::QueueState;

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

    /// Driver kicked QueueNotify with `idx`. Runs on the vCPU thread.
    fn notify_queue(&self, idx: u32);

    fn driver_ok(&self);
    fn reset(&self);

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
