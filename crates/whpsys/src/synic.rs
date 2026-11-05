//! The host's side of the guest's synthetic interrupt controller (SynIC), which
//! the hypervisor implements: posting a message to a vCPU's message page and
//! setting a flag in its event flags page, each raising the SINT they target.
//! A VMBus host talks to the guest through these.

use crate::error::{Result, check_hr};
use core::ffi::c_void;
use windows_sys::Win32::System::Hypervisor::{
    WHV_PARTITION_HANDLE, WHV_SYNIC_EVENT_PARAMETERS, WHvPostVirtualProcessorSynicMessage,
    WHvSignalVirtualProcessorSynicEvent,
};

/// An `HV_MESSAGE`: a 16-byte header and a 240-byte payload.
pub const MESSAGE_SIZE: usize = 256;

/// Post `message` to `sint` of vCPU `vp`. Fails, leaving the guest's page
/// alone, while the SINT's message slot still holds an earlier message.
pub fn post_message(
    part: WHV_PARTITION_HANDLE,
    vp: u32,
    sint: u8,
    message: &[u8; MESSAGE_SIZE],
) -> Result<()> {
    // SAFETY: WHP reads MESSAGE_SIZE bytes from `message`.
    check_hr(
        unsafe {
            WHvPostVirtualProcessorSynicMessage(
                part,
                vp,
                u32::from(sint),
                message.as_ptr() as *const c_void,
                MESSAGE_SIZE as u32,
            )
        },
        "WHvPostVirtualProcessorSynicMessage",
    )
}

/// Set event flag `flag` of `sint` on vCPU `vp`, interrupting it if the flag
/// was clear. Returns whether it was.
pub fn signal_event(part: WHV_PARTITION_HANDLE, vp: u32, sint: u8, flag: u16) -> Result<bool> {
    let event = WHV_SYNIC_EVENT_PARAMETERS {
        VpIndex: vp,
        TargetSint: sint,
        Reserved: 0,
        FlagNumber: flag,
    };
    let mut newly: windows_sys::core::BOOL = 0;
    // SAFETY: WHP writes the BOOL.
    check_hr(
        unsafe { WHvSignalVirtualProcessorSynicEvent(part, event, &mut newly) },
        "WHvSignalVirtualProcessorSynicEvent",
    )?;
    Ok(newly != 0)
}
