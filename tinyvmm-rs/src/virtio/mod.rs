//! virtio device model: split virtqueues, the modern PCI transport, and the
//! console device.

pub mod blk;
pub mod console;
pub mod device;
pub mod input;
pub mod net;
pub mod p9;
pub mod queue;
pub mod rng;
pub mod transport;
