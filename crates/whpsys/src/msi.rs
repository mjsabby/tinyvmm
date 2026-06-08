//! MSI message -> WHvRequestInterrupt translator. Port of src/whp/msi.cpp.
//!
//! On x86 an MSI is a 32-bit write to the LAPIC redirection window; for
//! host-side injection we mint the same effect via WHvRequestInterrupt.

use std::sync::atomic::{AtomicU64, Ordering};
use windows_sys::Win32::System::Hypervisor::{
    WHV_INTERRUPT_CONTROL, WHV_PARTITION_HANDLE, WHvRequestInterrupt,
};

static MSI_INJECT_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn msi_inject_count() -> u64 {
    MSI_INJECT_COUNT.load(Ordering::Relaxed)
}

/// Decode an x86 MSI message (Intel SDM Vol 3 §10.11) and submit it to the
/// partition's interrupt controller. Returns true on success.
pub fn inject_msi(partition: WHV_PARTITION_HANDLE, address: u64, data: u32) -> bool {
    let vector = data & 0xFF;
    let delivery = (data >> 8) & 0x7;
    let trig_level = (data & (1 << 15)) != 0;
    let dest_logical = (address & (1 << 2)) != 0;
    let destination = ((address >> 12) & 0xFF) as u32;

    // Map MSI delivery mode -> WHV interrupt type (Fixed=0, LowestPri=1,
    // NMI=4, Init=5). SMI/ExtINT have no MSI equivalent.
    let int_type: u64 = match delivery {
        0 => 0,
        1 => 1,
        4 => 4,
        5 => 5,
        _ => return false,
    };
    let dest_mode: u64 = if dest_logical { 1 } else { 0 };
    let trigger: u64 = if trig_level { 1 } else { 0 };
    // WHV_INTERRUPT_CONTROL bitfield: Type[7:0], DestinationMode[11:8],
    // TriggerMode[13:12].
    let bitfield = (int_type & 0xFF) | ((dest_mode & 0xF) << 8) | ((trigger & 0x3) << 12);

    let ctrl = WHV_INTERRUPT_CONTROL {
        _bitfield: bitfield,
        Destination: destination,
        Vector: vector,
    };
    let hr = unsafe {
        WHvRequestInterrupt(
            partition,
            &ctrl,
            std::mem::size_of::<WHV_INTERRUPT_CONTROL>() as u32,
        )
    };
    if hr >= 0 {
        MSI_INJECT_COUNT.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        false
    }
}
