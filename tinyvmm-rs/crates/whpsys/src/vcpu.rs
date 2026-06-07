//! Thin wrapper around a single virtual processor.

use crate::error::{check_hr, Error, Result};
use core::ffi::c_void;
use windows_sys::Win32::System::Hypervisor::{
    WHvCancelRunVirtualProcessor, WHvCreateVirtualProcessor, WHvDeleteVirtualProcessor,
    WHvGetVirtualProcessorInterruptControllerState2, WHvGetVirtualProcessorRegisters,
    WHvGetVirtualProcessorXsaveState, WHvRunVirtualProcessor,
    WHvSetVirtualProcessorInterruptControllerState2, WHvSetVirtualProcessorRegisters,
    WHvSetVirtualProcessorXsaveState, WHvRunVpExitReasonCanceled, WHvRunVpExitReasonException,
    WHvRunVpExitReasonInvalidVpRegisterValue, WHvRunVpExitReasonMemoryAccess,
    WHvRunVpExitReasonNone, WHvRunVpExitReasonUnrecoverableException,
    WHvRunVpExitReasonUnsupportedFeature, WHvRunVpExitReasonX64ApicEoi, WHvRunVpExitReasonX64Cpuid,
    WHvRunVpExitReasonX64Halt, WHvRunVpExitReasonX64InterruptWindow,
    WHvRunVpExitReasonX64IoPortAccess, WHvRunVpExitReasonX64MsrAccess, WHV_MEMORY_ACCESS_CONTEXT,
    WHV_PARTITION_HANDLE, WHV_REGISTER_NAME, WHV_REGISTER_VALUE, WHV_RUN_VP_EXIT_CONTEXT,
    WHV_VP_EXIT_CONTEXT, WHV_X64_IO_PORT_ACCESS_CONTEXT,
};

/// Reinterpret a 16-byte register value as the WHP union (LE byte image).
fn bytes_to_val(b: &[u8; 16]) -> WHV_REGISTER_VALUE {
    let mut v: WHV_REGISTER_VALUE = unsafe { core::mem::zeroed() };
    unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), &mut v as *mut _ as *mut u8, 16) };
    v
}

/// Reinterpret a WHP register-value union as its 16-byte LE image.
fn val_to_bytes(v: &WHV_REGISTER_VALUE) -> [u8; 16] {
    let mut b = [0u8; 16];
    unsafe { core::ptr::copy_nonoverlapping(v as *const _ as *const u8, b.as_mut_ptr(), 16) };
    b
}

pub struct Vcpu {
    part: WHV_PARTITION_HANDLE,
    index: u32,
}

impl Vcpu {
    pub fn new(part: WHV_PARTITION_HANDLE, index: u32) -> Result<Self> {
        check_hr(
            unsafe { WHvCreateVirtualProcessor(part, index, 0) },
            "WHvCreateVirtualProcessor",
        )?;
        Ok(Vcpu { part, index })
    }

    pub fn index(&self) -> u32 {
        self.index
    }
    pub fn part(&self) -> WHV_PARTITION_HANDLE {
        self.part
    }

    pub fn get_registers(
        &self,
        names: &[WHV_REGISTER_NAME],
        out: &mut [WHV_REGISTER_VALUE],
    ) -> Result<()> {
        if names.len() != out.len() {
            return Err(Error::msg("Vcpu::get_registers: name/value size mismatch"));
        }
        check_hr(
            unsafe {
                WHvGetVirtualProcessorRegisters(
                    self.part,
                    self.index,
                    names.as_ptr(),
                    names.len() as u32,
                    out.as_mut_ptr(),
                )
            },
            "WHvGetVirtualProcessorRegisters",
        )
    }

    pub fn set_registers(
        &self,
        names: &[WHV_REGISTER_NAME],
        values: &[WHV_REGISTER_VALUE],
    ) -> Result<()> {
        if names.len() != values.len() {
            return Err(Error::msg("Vcpu::set_registers: name/value size mismatch"));
        }
        check_hr(
            unsafe {
                WHvSetVirtualProcessorRegisters(
                    self.part,
                    self.index,
                    names.as_ptr(),
                    names.len() as u32,
                    values.as_ptr(),
                )
            },
            "WHvSetVirtualProcessorRegisters",
        )
    }

    pub fn set_register(&self, name: WHV_REGISTER_NAME, value: WHV_REGISTER_VALUE) -> Result<()> {
        self.set_registers(&[name], &[value])
    }

    pub fn get_register(&self, name: WHV_REGISTER_NAME) -> Result<WHV_REGISTER_VALUE> {
        let mut v = [WHV_REGISTER_VALUE { Reg64: 0 }];
        self.get_registers(&[name], &mut v)?;
        Ok(v[0])
    }

    // ---- Byte-oriented save/restore API (callers stay free of the WHP union
    // and the XSAVE/interrupt-controller FFI). Each register value is the raw
    // 16-byte LE image of the WHP register-value union. ----

    /// Read each named register as its raw 16-byte image.
    pub fn get_registers_bytes(&self, names: &[WHV_REGISTER_NAME]) -> Result<Vec<[u8; 16]>> {
        let mut vals = vec![WHV_REGISTER_VALUE { Reg64: 0 }; names.len()];
        self.get_registers(names, &mut vals)?;
        Ok(vals.iter().map(val_to_bytes).collect())
    }

    /// Read one register as its raw 16-byte image.
    pub fn get_register_bytes(&self, name: WHV_REGISTER_NAME) -> Result<[u8; 16]> {
        Ok(val_to_bytes(&self.get_register(name)?))
    }

    /// Write each named register from its raw 16-byte image.
    pub fn set_registers_bytes(&self, names: &[WHV_REGISTER_NAME], vals: &[[u8; 16]]) -> Result<()> {
        if names.len() != vals.len() {
            return Err(Error::msg("Vcpu::set_registers_bytes: size mismatch"));
        }
        let v: Vec<WHV_REGISTER_VALUE> = vals.iter().map(bytes_to_val).collect();
        self.set_registers(names, &v)
    }

    /// Write one register from its raw 16-byte image.
    pub fn set_register_bytes(&self, name: WHV_REGISTER_NAME, val: &[u8; 16]) -> Result<()> {
        self.set_register(name, bytes_to_val(val))
    }

    /// Capture the vCPU's XSAVE area (two-phase: query size, then read).
    pub fn get_xsave(&self) -> Result<Vec<u8>> {
        let mut needed: u32 = 0;
        unsafe {
            WHvGetVirtualProcessorXsaveState(
                self.part,
                self.index,
                core::ptr::null_mut(),
                0,
                &mut needed,
            )
        };
        if needed == 0 {
            return Err(Error::msg("Vcpu::get_xsave: query returned 0 bytes"));
        }
        let mut buf = vec![0u8; needed as usize];
        let mut actual: u32 = 0;
        check_hr(
            unsafe {
                WHvGetVirtualProcessorXsaveState(
                    self.part,
                    self.index,
                    buf.as_mut_ptr() as *mut c_void,
                    needed,
                    &mut actual,
                )
            },
            "WHvGetVirtualProcessorXsaveState",
        )?;
        buf.truncate(actual as usize);
        Ok(buf)
    }

    /// Restore the vCPU's XSAVE area from a previously-captured blob.
    pub fn set_xsave(&self, blob: &[u8]) -> Result<()> {
        check_hr(
            unsafe {
                WHvSetVirtualProcessorXsaveState(
                    self.part,
                    self.index,
                    blob.as_ptr() as *const c_void,
                    blob.len() as u32,
                )
            },
            "WHvSetVirtualProcessorXsaveState",
        )
    }

    /// Capture the local-APIC / interrupt-controller state (two-phase). Returns
    /// an empty Vec if unavailable (older WHP builds): the caller treats that as
    /// "nothing to restore".
    pub fn get_interrupt_controller(&self) -> Vec<u8> {
        let mut needed: u32 = 0;
        unsafe {
            WHvGetVirtualProcessorInterruptControllerState2(
                self.part,
                self.index,
                core::ptr::null_mut(),
                0,
                &mut needed,
            )
        };
        if needed == 0 {
            return Vec::new();
        }
        let mut buf = vec![0u8; needed as usize];
        let mut actual: u32 = 0;
        let hr = unsafe {
            WHvGetVirtualProcessorInterruptControllerState2(
                self.part,
                self.index,
                buf.as_mut_ptr() as *mut c_void,
                needed,
                &mut actual,
            )
        };
        if hr < 0 {
            eprintln!("[vcpu] WARN: APIC state read failed (HRESULT={hr:#010x}); skipping");
            return Vec::new();
        }
        buf.truncate(actual as usize);
        buf
    }

    /// Restore the local-APIC / interrupt-controller state.
    pub fn set_interrupt_controller(&self, blob: &[u8]) -> Result<()> {
        check_hr(
            unsafe {
                WHvSetVirtualProcessorInterruptControllerState2(
                    self.part,
                    self.index,
                    blob.as_ptr() as *const c_void,
                    blob.len() as u32,
                )
            },
            "WHvSetVirtualProcessorInterruptControllerState2",
        )
    }

    pub fn run(&self, exit: &mut WHV_RUN_VP_EXIT_CONTEXT) -> Result<()> {
        check_hr(
            unsafe {
                WHvRunVirtualProcessor(
                    self.part,
                    self.index,
                    exit as *mut WHV_RUN_VP_EXIT_CONTEXT as *mut c_void,
                    std::mem::size_of::<WHV_RUN_VP_EXIT_CONTEXT>() as u32,
                )
            },
            "WHvRunVirtualProcessor",
        )
    }

    /// Run the vCPU and return a decoded [`Exit`]. Preferred over [`run`] —
    /// the caller reads the exit through safe accessors instead of the raw
    /// WHP union.
    pub fn run_exit(&self) -> Result<Exit> {
        let mut raw = WHV_RUN_VP_EXIT_CONTEXT::default();
        self.run(&mut raw)?;
        Ok(Exit { raw })
    }

    pub fn cancel(&self) -> Result<()> {
        check_hr(
            unsafe { WHvCancelRunVirtualProcessor(self.part, self.index, 0) },
            "WHvCancelRunVirtualProcessor",
        )
    }
}

impl Drop for Vcpu {
    fn drop(&mut self) {
        unsafe {
            WHvDeleteVirtualProcessor(self.part, self.index);
        }
    }
}

/// Decoded reason for a vCPU exit (the subset the run loop acts on).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitReason {
    Halt,
    IoPort,
    Memory,
    Cpuid,
    Msr,
    InterruptWindow,
    ApicEoi,
    Canceled,
    Other(u32),
}

/// CPUID exit payload (leaf/subleaf + WHP's default result registers).
pub struct CpuidExit {
    pub leaf: u32,
    pub subleaf: u32,
    pub default_eax: u32,
    pub default_ebx: u32,
    pub default_ecx: u32,
    pub default_edx: u32,
}

/// MSR exit payload.
pub struct MsrExit {
    pub msr: u32,
    pub is_write: bool,
    pub rax: u64,
    pub rdx: u64,
}

/// A decoded vCPU exit. Wraps the raw WHP exit context; the union is only ever
/// read through the typed accessors here, so callers stay `unsafe`-free.
pub struct Exit {
    raw: WHV_RUN_VP_EXIT_CONTEXT,
}

impl Exit {
    /// The decoded exit reason.
    pub fn reason(&self) -> ExitReason {
        let r = self.raw.ExitReason;
        if r == WHvRunVpExitReasonX64Halt {
            ExitReason::Halt
        } else if r == WHvRunVpExitReasonX64IoPortAccess {
            ExitReason::IoPort
        } else if r == WHvRunVpExitReasonMemoryAccess {
            ExitReason::Memory
        } else if r == WHvRunVpExitReasonX64Cpuid {
            ExitReason::Cpuid
        } else if r == WHvRunVpExitReasonX64MsrAccess {
            ExitReason::Msr
        } else if r == WHvRunVpExitReasonX64InterruptWindow {
            ExitReason::InterruptWindow
        } else if r == WHvRunVpExitReasonX64ApicEoi {
            ExitReason::ApicEoi
        } else if r == WHvRunVpExitReasonCanceled {
            ExitReason::Canceled
        } else {
            ExitReason::Other(r as u32)
        }
    }

    /// The raw WHP exit-reason code (for diagnostics / ETW).
    pub fn raw_reason(&self) -> u32 {
        self.raw.ExitReason as u32
    }

    /// Guest RIP at the exit.
    pub fn rip(&self) -> u64 {
        self.raw.VpContext.Rip
    }

    /// Guest RFLAGS at the exit.
    pub fn rflags(&self) -> u64 {
        self.raw.VpContext.Rflags
    }

    /// Length of the faulting instruction (low nibble of the Vp-context bitfield).
    pub fn instruction_length(&self) -> u8 {
        self.raw.VpContext._bitfield & 0x0F
    }

    /// Decode a CPUID exit. Only meaningful when `reason() == Cpuid`.
    pub fn cpuid(&self) -> CpuidExit {
        let c = unsafe { &self.raw.Anonymous.CpuidAccess };
        CpuidExit {
            leaf: c.Rax as u32,
            subleaf: c.Rcx as u32,
            default_eax: c.DefaultResultRax as u32,
            default_ebx: c.DefaultResultRbx as u32,
            default_ecx: c.DefaultResultRcx as u32,
            default_edx: c.DefaultResultRdx as u32,
        }
    }

    /// Decode an MSR exit. Only meaningful when `reason() == Msr`.
    pub fn msr(&self) -> MsrExit {
        let m = unsafe { &self.raw.Anonymous.MsrAccess };
        MsrExit {
            msr: m.MsrNumber,
            is_write: (unsafe { m.AccessInfo.Anonymous._bitfield }) & 1 != 0,
            rax: m.Rax,
            rdx: m.Rdx,
        }
    }

    pub(crate) fn vp_context(&self) -> &WHV_VP_EXIT_CONTEXT {
        &self.raw.VpContext
    }

    pub(crate) fn io_access(&self) -> &WHV_X64_IO_PORT_ACCESS_CONTEXT {
        unsafe { &self.raw.Anonymous.IoPortAccess }
    }

    pub(crate) fn mem_access(&self) -> &WHV_MEMORY_ACCESS_CONTEXT {
        unsafe { &self.raw.Anonymous.MemoryAccess }
    }
}

/// Human-readable name for a raw WHP exit-reason code (diagnostics only).
pub fn exit_reason_name(reason: u32) -> &'static str {
    let r = reason as i32;
    if r == WHvRunVpExitReasonNone {
        "None"
    } else if r == WHvRunVpExitReasonMemoryAccess {
        "MemoryAccess"
    } else if r == WHvRunVpExitReasonX64IoPortAccess {
        "X64IoPortAccess"
    } else if r == WHvRunVpExitReasonUnrecoverableException {
        "UnrecoverableException"
    } else if r == WHvRunVpExitReasonInvalidVpRegisterValue {
        "InvalidVpRegisterValue"
    } else if r == WHvRunVpExitReasonUnsupportedFeature {
        "UnsupportedFeature"
    } else if r == WHvRunVpExitReasonX64InterruptWindow {
        "X64InterruptWindow"
    } else if r == WHvRunVpExitReasonX64Halt {
        "X64Halt"
    } else if r == WHvRunVpExitReasonX64ApicEoi {
        "X64ApicEoi"
    } else if r == WHvRunVpExitReasonX64MsrAccess {
        "X64MsrAccess"
    } else if r == WHvRunVpExitReasonX64Cpuid {
        "X64Cpuid"
    } else if r == WHvRunVpExitReasonException {
        "Exception"
    } else if r == WHvRunVpExitReasonCanceled {
        "Canceled"
    } else {
        "<unknown>"
    }
}
