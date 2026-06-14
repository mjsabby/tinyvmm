//! Safe wrapper over the WHP instruction emulator used to complete IO-port and
//! MMIO accesses that fault out of the guest. All of the `WHvEmulator*` FFI, the
//! five `extern "system"` callbacks, and the raw register get/set forwarding are
//! concentrated here. The caller supplies an [`EmulatorBus`] implementation
//! (the IO/MMIO device dispatch) and drives emulation via [`Emulator::try_io`]
//! and [`Emulator::try_mmio`], passing the [`Exit`] returned by
//! [`crate::vcpu::Vcpu::run_exit`].

use crate::vcpu::Exit;
use core::ffi::c_void;
use windows_sys::Win32::System::Hypervisor::{
    WHV_EMULATOR_CALLBACKS, WHV_EMULATOR_IO_ACCESS_INFO, WHV_EMULATOR_MEMORY_ACCESS_INFO,
    WHV_EMULATOR_STATUS, WHV_PARTITION_HANDLE, WHV_REGISTER_NAME, WHV_REGISTER_VALUE,
    WHV_TRANSLATE_GVA_FLAGS, WHV_TRANSLATE_GVA_RESULT, WHV_TRANSLATE_GVA_RESULT_CODE,
    WHvEmulatorCreateEmulator, WHvEmulatorDestroyEmulator, WHvEmulatorTryIoEmulation,
    WHvEmulatorTryMmioEmulation, WHvGetVirtualProcessorRegisters, WHvSetVirtualProcessorRegisters,
    WHvTranslateGva,
};
use winsys::SharedPtr;

/// A neutral IO-port access handed to the [`EmulatorBus`]. `value` is updated
/// in-place by the bus on reads.
pub struct IoAccess {
    pub port: u16,
    pub access_size: u16,
    pub is_write: bool,
    pub value: u32,
}

/// A neutral MMIO access handed to the [`EmulatorBus`]. `data` is filled by the
/// bus on reads.
pub struct MmioAccess {
    pub gpa: u64,
    pub access_size: u8,
    pub is_write: bool,
    pub data: [u8; 8],
}

/// The device dispatch the emulator calls back into. Implemented on the caller
/// side (the IO/MMIO buses); the implementation runs synchronously inside
/// `try_io`/`try_mmio`.
pub trait EmulatorBus {
    fn io(&self, acc: &mut IoAccess);
    fn mmio(&self, acc: &mut MmioAccess);
}

/// Why an emulation attempt failed.
pub enum EmuError {
    /// `WHvEmulatorTry*Emulation` returned a failing HRESULT.
    Hresult(i32),
    /// The call succeeded but the emulator reported an incomplete status.
    Incomplete(u32),
}

/// Context handed to the WHV emulator callbacks. Lives on the stack for the
/// duration of one `try_*` call, so the borrow of `bus` stays valid.
struct EmuCtx<'a> {
    part: WHV_PARTITION_HANDLE,
    vp: u32,
    bus: &'a dyn EmulatorBus,
}

/// Owns a `WHV_EMULATOR_HANDLE`. Created once per run loop; destroyed on drop.
pub struct Emulator {
    handle: SharedPtr<c_void>,
}

// SAFETY: the only raw field is the WHV emulator handle (single-owner: only the
// owning run loop's thread ever calls try_io/try_mmio on it), wrapped in the
// audited SharedPtr newtype so Emulator auto-derives Send.

impl Emulator {
    /// Create an emulator wired to the fixed callback set below.
    pub fn new() -> crate::error::Result<Emulator> {
        let cbs = WHV_EMULATOR_CALLBACKS {
            Size: std::mem::size_of::<WHV_EMULATOR_CALLBACKS>() as u32,
            Reserved: 0,
            WHvEmulatorIoPortCallback: Some(on_io_port),
            WHvEmulatorMemoryCallback: Some(on_memory),
            WHvEmulatorGetVirtualProcessorRegisters: Some(on_get_registers),
            WHvEmulatorSetVirtualProcessorRegisters: Some(on_set_registers),
            WHvEmulatorTranslateGvaPage: Some(on_translate_gva),
        };
        let mut emulator: *mut c_void = std::ptr::null_mut();
        crate::error::check_hr(
            unsafe { WHvEmulatorCreateEmulator(&cbs, &mut emulator) },
            "WHvEmulatorCreateEmulator",
        )?;
        Ok(Emulator {
            handle: SharedPtr::new(emulator),
        })
    }

    /// Complete an IO-port access exit, dispatching through `bus`.
    pub fn try_io(
        &self,
        exit: &Exit,
        part: WHV_PARTITION_HANDLE,
        vp: u32,
        bus: &dyn EmulatorBus,
    ) -> Result<(), EmuError> {
        let ctx = EmuCtx { part, vp, bus };
        let ctx_ptr = &ctx as *const EmuCtx as *const c_void;
        let mut status = WHV_EMULATOR_STATUS::default();
        let hr = unsafe {
            WHvEmulatorTryIoEmulation(
                self.handle.get(),
                ctx_ptr,
                exit.vp_context(),
                exit.io_access(),
                &mut status,
            )
        };
        Self::check(hr, &status)
    }

    /// Complete an MMIO access exit, dispatching through `bus`.
    pub fn try_mmio(
        &self,
        exit: &Exit,
        part: WHV_PARTITION_HANDLE,
        vp: u32,
        bus: &dyn EmulatorBus,
    ) -> Result<(), EmuError> {
        let ctx = EmuCtx { part, vp, bus };
        let ctx_ptr = &ctx as *const EmuCtx as *const c_void;
        let mut status = WHV_EMULATOR_STATUS::default();
        let hr = unsafe {
            WHvEmulatorTryMmioEmulation(
                self.handle.get(),
                ctx_ptr,
                exit.vp_context(),
                exit.mem_access(),
                &mut status,
            )
        };
        Self::check(hr, &status)
    }

    fn check(hr: i32, status: &WHV_EMULATOR_STATUS) -> Result<(), EmuError> {
        if hr < 0 {
            return Err(EmuError::Hresult(hr));
        }
        // Bit 0 of the status union is EmulationSuccessful.
        let s = unsafe { status.AsUINT32 };
        if s & 1 == 0 {
            return Err(EmuError::Incomplete(s));
        }
        Ok(())
    }
}

impl Drop for Emulator {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { WHvEmulatorDestroyEmulator(self.handle.get()) };
        }
    }
}

// ---------------------------------------------------------------------------
// Emulator callbacks. `context` is a `*const EmuCtx` valid for the call.
// ---------------------------------------------------------------------------

unsafe extern "system" fn on_io_port(
    context: *const c_void,
    io: *mut WHV_EMULATOR_IO_ACCESS_INFO,
) -> i32 {
    unsafe {
        let c = &*(context as *const EmuCtx);
        let io = &mut *io;
        let mut acc = IoAccess {
            port: io.Port,
            access_size: io.AccessSize,
            is_write: io.Direction == 1,
            value: io.Data,
        };
        c.bus.io(&mut acc);
        if !acc.is_write {
            io.Data = acc.value;
        }
        0 // S_OK
    }
}

unsafe extern "system" fn on_memory(
    context: *const c_void,
    mem: *mut WHV_EMULATOR_MEMORY_ACCESS_INFO,
) -> i32 {
    unsafe {
        let c = &*(context as *const EmuCtx);
        let mem = &mut *mem;
        let mut acc = MmioAccess {
            gpa: mem.GpaAddress,
            access_size: mem.AccessSize,
            is_write: mem.Direction == 1,
            data: [0u8; 8],
        };
        if acc.is_write {
            acc.data = mem.Data;
        }
        c.bus.mmio(&mut acc);
        if !acc.is_write {
            mem.Data = acc.data;
        }
        0
    }
}

unsafe extern "system" fn on_get_registers(
    context: *const c_void,
    names: *const WHV_REGISTER_NAME,
    count: u32,
    values: *mut WHV_REGISTER_VALUE,
) -> i32 {
    unsafe {
        let c = &*(context as *const EmuCtx);
        WHvGetVirtualProcessorRegisters(c.part, c.vp, names, count, values)
    }
}

unsafe extern "system" fn on_set_registers(
    context: *const c_void,
    names: *const WHV_REGISTER_NAME,
    count: u32,
    values: *const WHV_REGISTER_VALUE,
) -> i32 {
    unsafe {
        let c = &*(context as *const EmuCtx);
        WHvSetVirtualProcessorRegisters(c.part, c.vp, names, count, values)
    }
}

unsafe extern "system" fn on_translate_gva(
    context: *const c_void,
    gva: u64,
    flags: WHV_TRANSLATE_GVA_FLAGS,
    result_code: *mut WHV_TRANSLATE_GVA_RESULT_CODE,
    gpa: *mut u64,
) -> i32 {
    unsafe {
        // String port-IO (`rep insb`/`outsb`) and the rare MMIO instruction whose
        // memory operand is in guest RAM make the emulator ask for GVA→GPA. The
        // previous fail-closed E_NOTIMPL turned that into EmulationFailure → VMM
        // termination, i.e. a guest-triggerable DoS. Forward to WHP's page-table
        // walker instead; cold path (only string IO / RMW MMIO hit it).
        let c = &*(context as *const EmuCtx);
        let mut result = WHV_TRANSLATE_GVA_RESULT::default();
        let hr = WHvTranslateGva(c.part, c.vp, gva, flags, &mut result, gpa);
        *result_code = result.ResultCode;
        hr
    }
}
