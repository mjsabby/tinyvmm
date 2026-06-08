//! WHP partition MMIO doorbell: registers a guest-physical write-match so a
//! matching store signals an event instead of taking a VM exit. A safe RAII
//! wrapper — `new` creates the event + registers the match, `Drop` unregisters
//! it + closes the event. The caller waits on `event()` from its pump thread.

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Hypervisor::{
    WHvRegisterPartitionDoorbellEvent, WHvUnregisterPartitionDoorbellEvent, WHV_DOORBELL_MATCH_DATA,
    WHV_PARTITION_HANDLE,
};
use windows_sys::Win32::System::Threading::CreateEventW;

/// One registered MMIO doorbell. While alive, a guest write of `value`
/// (`length` bytes) to `gpa` signals `event()` with no VM exit.
pub struct Doorbell {
    part: WHV_PARTITION_HANDLE,
    match_: WHV_DOORBELL_MATCH_DATA,
    event: HANDLE,
}

// SAFETY: the only raw field is a manual-reset OS event HANDLE; it is owned here
// and only ever waited on by the caller's pump thread (joined before drop).
unsafe impl Send for Doorbell {}

impl Doorbell {
    /// Register a doorbell matching a `length`-byte write of `value` at `gpa`.
    /// Returns None if the event can't be created or the registration fails.
    pub fn new(part: WHV_PARTITION_HANDLE, gpa: u64, value: u64, length: u32) -> Option<Doorbell> {
        let event = unsafe { CreateEventW(std::ptr::null(), 1 /*manual reset*/, 0, std::ptr::null()) };
        if event.is_null() {
            return None;
        }
        let match_ = WHV_DOORBELL_MATCH_DATA {
            GuestAddress: gpa,
            Value: value,
            Length: length,
            _bitfield: 0x3, // MatchOnValue | MatchOnLength<<1
        };
        let hr = unsafe { WHvRegisterPartitionDoorbellEvent(part, &match_, event) };
        if hr < 0 {
            unsafe {
                CloseHandle(event);
            }
            return None;
        }
        Some(Doorbell { part, match_, event })
    }

    /// The manual-reset event this doorbell signals; wait on it from the pump.
    pub fn event(&self) -> HANDLE {
        self.event
    }
}

impl Drop for Doorbell {
    fn drop(&mut self) {
        unsafe {
            WHvUnregisterPartitionDoorbellEvent(self.part, &self.match_);
            CloseHandle(self.event);
        }
    }
}
