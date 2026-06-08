//! RAII wrapper around a WHV partition handle.

use crate::error::{check_hr, Result};
use core::ffi::c_void;
use windows_sys::Win32::System::Hypervisor::{
    WHvCreatePartition, WHvDeletePartition, WHvPartitionPropertyCodeCpuidResultList,
    WHvPartitionPropertyCodeExceptionExitBitmap, WHvPartitionPropertyCodeExtendedVmExits,
    WHvPartitionPropertyCodeLocalApicEmulationMode, WHvPartitionPropertyCodeProcessorCount,
    WHvSetPartitionProperty, WHvSetupPartition, WHV_PARTITION_HANDLE, WHV_PARTITION_PROPERTY_CODE,
    WHV_X64_CPUID_RESULT, WHV_X64_LOCAL_APIC_EMULATION_MODE,
};

pub struct Partition {
    handle: WHV_PARTITION_HANDLE,
    vcpu_count: u32,
    setup_done: bool,
}

impl Partition {
    pub fn new(vcpu_count: u32) -> Result<Self> {
        let mut handle: WHV_PARTITION_HANDLE = 0;
        check_hr(
            unsafe { WHvCreatePartition(&mut handle) },
            "WHvCreatePartition",
        )?;
        let p = Partition {
            handle,
            vcpu_count,
            setup_done: false,
        };
        p.set_property(WHvPartitionPropertyCodeProcessorCount, &vcpu_count)?;
        Ok(p)
    }

    fn set_property<T>(&self, code: WHV_PARTITION_PROPERTY_CODE, value: &T) -> Result<()> {
        check_hr(
            unsafe {
                WHvSetPartitionProperty(
                    self.handle,
                    code,
                    value as *const T as *const c_void,
                    std::mem::size_of::<T>() as u32,
                )
            },
            "WHvSetPartitionProperty",
        )
    }

    /// Bit layout mirrors `WHV_EXTENDED_VM_EXITS`: bit0 cpuid, bit1 msr,
    /// bit2 exception, bit3 hypercall, bit4 gpa-access-fault.
    pub fn enable_extended_exits(&self, cpuid: bool, msr: bool, exception: bool) -> Result<()> {
        let mut bits: u64 = 0;
        if cpuid {
            bits |= 1 << 0;
        }
        if msr {
            bits |= 1 << 1;
        }
        if exception {
            bits |= 1 << 2;
        }
        self.set_property(WHvPartitionPropertyCodeExtendedVmExits, &bits)
    }

    pub fn set_exception_exit_bitmap(&self, bitmap: u64) -> Result<()> {
        self.set_property(WHvPartitionPropertyCodeExceptionExitBitmap, &bitmap)
    }

    pub fn set_local_apic_emulation(&self, mode: WHV_X64_LOCAL_APIC_EMULATION_MODE) -> Result<()> {
        self.set_property(WHvPartitionPropertyCodeLocalApicEmulationMode, &mode)
    }

    pub fn set_cpuid_result_list(&self, entries: &[WHV_X64_CPUID_RESULT]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let bytes = std::mem::size_of_val(entries) as u32;
        check_hr(
            unsafe {
                WHvSetPartitionProperty(
                    self.handle,
                    WHvPartitionPropertyCodeCpuidResultList,
                    entries.as_ptr() as *const c_void,
                    bytes,
                )
            },
            "WHvSetPartitionProperty(CpuidResultList)",
        )
    }

    pub fn setup(&mut self) -> Result<()> {
        if self.setup_done {
            return Ok(());
        }
        check_hr(
            unsafe { WHvSetupPartition(self.handle) },
            "WHvSetupPartition",
        )?;
        self.setup_done = true;
        Ok(())
    }

    pub fn handle(&self) -> WHV_PARTITION_HANDLE {
        self.handle
    }

    pub fn vcpu_count(&self) -> u32 {
        self.vcpu_count
    }
}

impl Drop for Partition {
    fn drop(&mut self) {
        if self.handle != 0 {
            unsafe {
                WHvDeletePartition(self.handle);
            }
        }
    }
}
