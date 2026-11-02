//! RAII wrapper around a WHV partition handle.

use crate::error::{Result, check_hr};
use core::ffi::c_void;
use windows_sys::Win32::System::Hypervisor::{
    WHV_PARTITION_HANDLE, WHV_PARTITION_PROPERTY_CODE, WHV_X64_CPUID_RESULT,
    WHV_X64_LOCAL_APIC_EMULATION_MODE, WHvCapabilityCodeSyntheticProcessorFeaturesBanks,
    WHvCreatePartition, WHvDeletePartition, WHvGetCapability, WHvGetPartitionProperty,
    WHvPartitionPropertyCodeAllowDeviceAssignment, WHvPartitionPropertyCodeCpuidResultList,
    WHvPartitionPropertyCodeExceptionExitBitmap, WHvPartitionPropertyCodeExtendedVmExits,
    WHvPartitionPropertyCodeLocalApicEmulationMode, WHvPartitionPropertyCodeProcessorCount,
    WHvPartitionPropertyCodeReferenceTime, WHvPartitionPropertyCodeSyntheticProcessorFeaturesBanks,
    WHvPartitionPropertyCodeX64MsrExitBitmap, WHvResumePartitionTime, WHvSetPartitionProperty,
    WHvSetupPartition, WHvSuspendPartitionTime,
};

/// `WHV_SYNTHETIC_PROCESSOR_FEATURES_BANKS` holding its one bank.
#[repr(C)]
#[derive(Default)]
struct SyntheticFeatureBanks {
    banks_count: u32,
    reserved: u32,
    bank0: u64,
}

/// The Hyper-V enlightenments (`WHV_SYNTHETIC_PROCESSOR_FEATURES` bits) this
/// host's hypervisor can implement for a partition.
pub fn synthetic_processor_features_supported() -> Result<u64> {
    let mut banks = SyntheticFeatureBanks::default();
    let mut written: u32 = 0;
    // SAFETY: WHvGetCapability writes at most size_of::<SyntheticFeatureBanks>() bytes.
    check_hr(
        unsafe {
            WHvGetCapability(
                WHvCapabilityCodeSyntheticProcessorFeaturesBanks,
                &mut banks as *mut SyntheticFeatureBanks as *mut c_void,
                std::mem::size_of::<SyntheticFeatureBanks>() as u32,
                &mut written,
            )
        },
        "WHvGetCapability(SyntheticProcessorFeaturesBanks)",
    )?;
    Ok(if banks.banks_count >= 1 {
        banks.bank0
    } else {
        0
    })
}

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

    /// `WHV_X64_MSR_EXIT_BITMAP` (a u64 of intercept bits): bit0 UnhandledMsrs,
    /// bit3 ApicBaseMsrWrite.
    pub fn set_msr_exit_bitmap(&self, bits: u64) -> Result<()> {
        self.set_property(WHvPartitionPropertyCodeX64MsrExitBitmap, &bits)
    }

    /// Permit Discrete Device Assignment (VPCI) in this partition. MUST be set
    /// *before* [`Self::setup`]; `WHvCreateVpciDevice` fails otherwise.
    pub fn set_allow_device_assignment(&self, allow: bool) -> Result<()> {
        let value: i32 = if allow { 1 } else { 0 };
        self.set_property(WHvPartitionPropertyCodeAllowDeviceAssignment, &value)
    }

    /// Have the hypervisor implement these Hyper-V enlightenments
    /// (`WHV_SYNTHETIC_PROCESSOR_FEATURES` bits) for the guest: their MSRs,
    /// hypercalls and overlay pages, and the Hyper-V CPUID leaves describing
    /// them. MUST be set before [`Self::setup`].
    pub fn set_synthetic_processor_features(&self, bank0: u64) -> Result<()> {
        let banks = SyntheticFeatureBanks {
            banks_count: 1,
            reserved: 0,
            bank0,
        };
        self.set_property(
            WHvPartitionPropertyCodeSyntheticProcessorFeaturesBanks,
            &banks,
        )
    }

    /// The partition's reference time, in 100 ns units: the clock behind the
    /// guest's reference TSC page, `TIME_REF_COUNT` and synthetic timers.
    pub fn reference_time(&self) -> Result<u64> {
        let mut time: u64 = 0;
        let mut written: u32 = 0;
        // SAFETY: the property is a u64; WHP writes at most 8 bytes.
        check_hr(
            unsafe {
                WHvGetPartitionProperty(
                    self.handle,
                    WHvPartitionPropertyCodeReferenceTime,
                    &mut time as *mut u64 as *mut c_void,
                    std::mem::size_of::<u64>() as u32,
                    &mut written,
                )
            },
            "WHvGetPartitionProperty(ReferenceTime)",
        )?;
        Ok(time)
    }

    /// Set the partition's reference time; partition time must be suspended.
    pub fn set_reference_time(&self, time: u64) -> Result<()> {
        self.set_property(WHvPartitionPropertyCodeReferenceTime, &time)
    }

    /// Stop the partition's clocks (reference time and every vCPU's TSC), so
    /// they can be read or set as one consistent instant.
    pub fn suspend_time(&self) -> Result<()> {
        check_hr(
            unsafe { WHvSuspendPartitionTime(self.handle) },
            "WHvSuspendPartitionTime",
        )
    }

    pub fn resume_time(&self) -> Result<()> {
        check_hr(
            unsafe { WHvResumePartitionTime(self.handle) },
            "WHvResumePartitionTime",
        )
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
