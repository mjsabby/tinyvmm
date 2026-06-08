//! RAII wrappers over the WHP "VPCI" device-assignment APIs — the primitives
//! behind Discrete Device Assignment (DDA) / PCI passthrough.
//!
//! These functions are exported from `winhvplatform.dll` (since Windows 10 RS4)
//! but are **absent from the public WHP documentation**; Microsoft's OpenVMM is
//! the authoritative reference for how to drive them. We concentrate all of the
//! associated FFI `unsafe` here, alongside the rest of the hypervisor interface.
//!
//! End-to-end (see `VpciDevice`):
//!   1. `WHvSetPartitionProperty(AllowDeviceAssignment, TRUE)` before setup.
//!   2. `WHvAllocateVpciResource(pnp_instance_id)` -> resource handle.
//!   3. `WHvCreateVpciDevice(id, resource, PhysicallyBacked)`.
//!   4. `WHvGetVpciDeviceProperty(HardwareIDs | ProbedBARs)`.
//!   5. On guest enabling memory decode: `WHvSetVpciDevicePowerState(D0)` +
//!      `WHvMapVpciDeviceMmioRanges` -> host VAs for the BARs.
//!   6. Config/BAR register access: `WHv{Read,Write}VpciDeviceRegister`.
//!   7. Interrupts: `WHvMapVpciDeviceInterrupt` translates a guest MSI target
//!      into the opaque (address, data) the device's MSI-X table must carry.

use crate::error::{Error, Result, check_hr};
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows_sys::Win32::System::Hypervisor::{
    WHV_PARTITION_HANDLE, WHV_SRIOV_RESOURCE_DESCRIPTOR, WHV_VPCI_DEVICE_NOTIFICATION,
    WHV_VPCI_DEVICE_REGISTER, WHV_VPCI_HARDWARE_IDS, WHV_VPCI_INTERRUPT_TARGET,
    WHV_VPCI_MMIO_MAPPING, WHV_VPCI_PROBED_BARS, WHvAllocateVpciResource, WHvCreateVpciDevice,
    WHvCreateVpciDeviceFlagPhysicallyBacked, WHvDeleteVpciDevice, WHvGetVpciDeviceNotification,
    WHvGetVpciDeviceProperty, WHvMapVpciDeviceInterrupt, WHvMapVpciDeviceMmioRanges,
    WHvReadVpciDeviceRegister, WHvRequestVpciDeviceInterrupt, WHvRetargetVpciDeviceInterrupt,
    WHvSetVpciDevicePowerState, WHvUnmapVpciDeviceInterrupt, WHvUnmapVpciDeviceMmioRanges,
    WHvVpciConfigSpace, WHvVpciDeviceNotificationMmioRemapping,
    WHvVpciDeviceNotificationSurpriseRemoval, WHvVpciDevicePropertyCodeHardwareIDs,
    WHvVpciDevicePropertyCodeProbedBARs, WHvVpciInterruptTargetFlagMulticast,
    WHvVpciMmioRangeFlagReadAccess, WHvVpciMmioRangeFlagWriteAccess, WHvWriteVpciDeviceRegister,
};
use windows_sys::Win32::System::Power::{PowerDeviceD0, PowerDeviceD3};

/// `WHV_VPCI_DEVICE_REGISTER_SPACE` selector for the device's PCI config space.
pub const CONFIG_SPACE: i32 = WHvVpciConfigSpace;

/// A host PCI(e) function reserved for assignment to a partition. Holds the
/// `WHvAllocateVpciResource` handle; closed on drop.
pub struct VpciResource {
    handle: HANDLE,
}

// SAFETY: the wrapped value is an opaque OS handle owned solely by this struct;
// it carries no thread affinity. We only ever close it (on drop) or hand it,
// by value, to `WHvCreateVpciDevice`.
unsafe impl Send for VpciResource {}
unsafe impl Sync for VpciResource {}

impl VpciResource {
    /// Allocate a VPCI resource for the assignable device identified by its
    /// Windows **PnP device instance ID** (Device Manager → Details → "Device
    /// instance path", or `Get-PnpDevice | Select InstanceId`), e.g.
    /// `PCI\VEN_10DE&DEV_2206&SUBSYS_...&REV_A1\4&1d2e3f&0&0019`.
    ///
    /// The device must already be dismounted from its host driver
    /// (`Dismount-VMHostAssignableDevice` / `pnputil /remove-device`) and the
    /// IOMMU must be enabled, or this fails.
    pub fn new(pnp_instance_id: &str) -> Result<Self> {
        let mut desc = WHV_SRIOV_RESOURCE_DESCRIPTOR {
            PnpInstanceId: [0u16; 200],
            VirtualFunctionId: LUID {
                LowPart: 0,
                HighPart: 0,
            },
            VirtualFunctionIndex: 0,
            Reserved: 0,
        };
        let mut utf16: Vec<u16> = pnp_instance_id.encode_utf16().collect();
        utf16.push(0); // null terminator
        if utf16.len() > desc.PnpInstanceId.len() {
            return Err(Error::msg(format!(
                "VpciResource: PnP instance id too long ({} > {} UTF-16 units)",
                utf16.len(),
                desc.PnpInstanceId.len()
            )));
        }
        desc.PnpInstanceId[..utf16.len()].copy_from_slice(&utf16);

        let mut handle: HANDLE = null_mut();
        check_hr(
            unsafe {
                WHvAllocateVpciResource(
                    null_mut(), // ProviderId: NULL == standard DDA provider
                    0,          // WHvAllocateVpciResourceFlagNone
                    (&desc as *const WHV_SRIOV_RESOURCE_DESCRIPTOR).cast(),
                    std::mem::size_of::<WHV_SRIOV_RESOURCE_DESCRIPTOR>() as u32,
                    &mut handle,
                )
            },
            "WHvAllocateVpciResource",
        )?;
        Ok(VpciResource { handle })
    }

    fn raw(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for VpciResource {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}

/// PCI 3-bit class triple + IDs reported by the physical device.
pub use windows_sys::Win32::System::Hypervisor::WHV_VPCI_HARDWARE_IDS as HardwareIds;

/// One contiguous device-MMIO region returned by `WHvMapVpciDeviceMmioRanges`,
/// flattened to plain data. `va` is a host process VA that aliases the device
/// MMIO; it stays valid until the ranges are unmapped (or an MmioRemapping
/// notification arrives).
#[derive(Clone, Copy, Debug)]
pub struct MmioMapping {
    /// `WHvVpciBar0..5` — which BAR this region belongs to.
    pub bar: i32,
    pub read: bool,
    pub write: bool,
    pub size: u64,
    pub offset: u64,
    pub va: usize,
}

/// A `WHvGetVpciDeviceNotification` result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceNotification {
    MmioRemapping,
    SurpriseRemoval,
}

/// A live assigned device inside a partition. Deletes itself on drop.
pub struct VpciDevice {
    part: WHV_PARTITION_HANDLE,
    id: u64,
    // Kept alive for the device's lifetime; the platform references it.
    _resource: VpciResource,
}

// SAFETY: the struct holds only a partition handle (`isize`), an opaque `u64`
// id, and the owned resource handle. All WHP VPCI calls take the partition +
// id, are internally synchronized by the platform, and carry no thread
// affinity. Higher layers serialize config/BAR/interrupt programming.
unsafe impl Send for VpciDevice {}
unsafe impl Sync for VpciDevice {}

impl VpciDevice {
    /// Create the assigned device in `part` under the caller-chosen opaque
    /// `id`. The partition must have been created with
    /// `AllowDeviceAssignment = TRUE` before `WHvSetupPartition`.
    pub fn new(part: WHV_PARTITION_HANDLE, id: u64, resource: VpciResource) -> Result<Self> {
        check_hr(
            unsafe {
                WHvCreateVpciDevice(
                    part,
                    id,
                    resource.raw(),
                    WHvCreateVpciDeviceFlagPhysicallyBacked,
                    null_mut(), // notification event: we poll instead
                )
            },
            "WHvCreateVpciDevice",
        )?;
        Ok(VpciDevice {
            part,
            id,
            _resource: resource,
        })
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn partition(&self) -> WHV_PARTITION_HANDLE {
        self.part
    }

    /// Vendor/device/class IDs of the physical device.
    pub fn hardware_ids(&self) -> Result<WHV_VPCI_HARDWARE_IDS> {
        let mut ids: WHV_VPCI_HARDWARE_IDS = unsafe { std::mem::zeroed() };
        let mut written: u32 = 0;
        check_hr(
            unsafe {
                WHvGetVpciDeviceProperty(
                    self.part,
                    self.id,
                    WHvVpciDevicePropertyCodeHardwareIDs,
                    (&mut ids as *mut WHV_VPCI_HARDWARE_IDS).cast(),
                    std::mem::size_of::<WHV_VPCI_HARDWARE_IDS>() as u32,
                    &mut written,
                )
            },
            "WHvGetVpciDeviceProperty(HardwareIDs)",
        )?;
        Ok(ids)
    }

    /// The 6 raw probed-BAR dwords (BAR sizing masks + type bits), i.e. what a
    /// guest would read back after writing all-ones to each BAR. Feed to
    /// [`decode_probed_bars`].
    pub fn probed_bars(&self) -> Result<[u32; 6]> {
        let mut bars: WHV_VPCI_PROBED_BARS = unsafe { std::mem::zeroed() };
        let mut written: u32 = 0;
        check_hr(
            unsafe {
                WHvGetVpciDeviceProperty(
                    self.part,
                    self.id,
                    WHvVpciDevicePropertyCodeProbedBARs,
                    (&mut bars as *mut WHV_VPCI_PROBED_BARS).cast(),
                    std::mem::size_of::<WHV_VPCI_PROBED_BARS>() as u32,
                    &mut written,
                )
            },
            "WHvGetVpciDeviceProperty(ProbedBARs)",
        )?;
        Ok(bars.Value)
    }

    /// `WHvSetVpciDevicePowerState`: `true` -> D0 (on), `false` -> D3 (off).
    pub fn set_power_on(&self, on: bool) -> Result<()> {
        let state = if on { PowerDeviceD0 } else { PowerDeviceD3 };
        check_hr(
            unsafe { WHvSetVpciDevicePowerState(self.part, self.id, state) },
            "WHvSetVpciDevicePowerState",
        )
    }

    /// Map the device's MMIO into this process and return the host VAs. Valid
    /// only while the device is powered (D0). The returned `va`s stay live until
    /// [`Self::unmap_mmio_ranges`] or device teardown.
    pub fn map_mmio_ranges(&self) -> Result<Vec<MmioMapping>> {
        let mut count: u32 = 0;
        let mut ptr: *mut WHV_VPCI_MMIO_MAPPING = null_mut();
        check_hr(
            unsafe { WHvMapVpciDeviceMmioRanges(self.part, self.id, &mut count, &mut ptr) },
            "WHvMapVpciDeviceMmioRanges",
        )?;
        let mut out = Vec::with_capacity(count as usize);
        if !ptr.is_null() {
            for i in 0..count as usize {
                let m = unsafe { &*ptr.add(i) };
                out.push(MmioMapping {
                    bar: m.Location,
                    read: (m.Flags & WHvVpciMmioRangeFlagReadAccess) != 0,
                    write: (m.Flags & WHvVpciMmioRangeFlagWriteAccess) != 0,
                    size: m.SizeInBytes,
                    offset: m.OffsetInBytes,
                    va: m.VirtualAddress as usize,
                });
            }
        }
        Ok(out)
    }

    pub fn unmap_mmio_ranges(&self) -> Result<()> {
        check_hr(
            unsafe { WHvUnmapVpciDeviceMmioRanges(self.part, self.id) },
            "WHvUnmapVpciDeviceMmioRanges",
        )
    }

    /// Read `data.len()` bytes from a register space (`CONFIG_SPACE` or a
    /// `WHvVpciBarN` constant) at `offset`.
    pub fn read_register(&self, space: i32, offset: u64, data: &mut [u8]) -> Result<()> {
        let reg = WHV_VPCI_DEVICE_REGISTER {
            Location: space,
            SizeInBytes: data.len() as u32,
            OffsetInBytes: offset,
        };
        check_hr(
            unsafe {
                WHvReadVpciDeviceRegister(self.part, self.id, &reg, data.as_mut_ptr().cast())
            },
            "WHvReadVpciDeviceRegister",
        )
    }

    /// Write `data.len()` bytes to a register space at `offset`.
    pub fn write_register(&self, space: i32, offset: u64, data: &[u8]) -> Result<()> {
        let reg = WHV_VPCI_DEVICE_REGISTER {
            Location: space,
            SizeInBytes: data.len() as u32,
            OffsetInBytes: offset,
        };
        check_hr(
            unsafe { WHvWriteVpciDeviceRegister(self.part, self.id, &reg, data.as_ptr().cast()) },
            "WHvWriteVpciDeviceRegister",
        )
    }

    pub fn read_config_dword(&self, offset: u32) -> Result<u32> {
        let mut d = [0u8; 4];
        self.read_register(CONFIG_SPACE, offset as u64, &mut d)?;
        Ok(u32::from_le_bytes(d))
    }

    pub fn write_config_dword(&self, offset: u32, value: u32) -> Result<()> {
        self.write_register(CONFIG_SPACE, offset as u64, &value.to_le_bytes())
    }

    /// `WHvMapVpciDeviceInterrupt`: translate a guest MSI target (`vector` +
    /// `processors` as **VP indices**, not APIC IDs) into the opaque
    /// `(msi_address, msi_data)` that the device's MSI-X table entry must carry
    /// for the interrupt to be routed to the guest. `index` is a caller-chosen
    /// slot; `message_count` is 1 for MSI-X (a power of two for multi-message
    /// MSI).
    pub fn map_interrupt(
        &self,
        index: u32,
        message_count: u32,
        vector: u32,
        multicast: bool,
        processors: &[u32],
    ) -> Result<(u64, u32)> {
        let target = build_interrupt_target(vector, multicast, processors);
        let mut address: u64 = 0;
        let mut data: u32 = 0;
        check_hr(
            unsafe {
                WHvMapVpciDeviceInterrupt(
                    self.part,
                    self.id,
                    index,
                    message_count,
                    target.as_ptr() as *const WHV_VPCI_INTERRUPT_TARGET,
                    &mut address,
                    &mut data,
                )
            },
            "WHvMapVpciDeviceInterrupt",
        )?;
        Ok((address, data))
    }

    pub fn unmap_interrupt(&self, index: u32) -> Result<()> {
        check_hr(
            unsafe { WHvUnmapVpciDeviceInterrupt(self.part, self.id, index) },
            "WHvUnmapVpciDeviceInterrupt",
        )
    }

    /// Re-affinitize an already-mapped interrupt (identified by its opaque
    /// `address`/`data`) to a new VP set.
    pub fn retarget_interrupt(
        &self,
        address: u64,
        data: u32,
        vector: u32,
        multicast: bool,
        processors: &[u32],
    ) -> Result<()> {
        let target = build_interrupt_target(vector, multicast, processors);
        check_hr(
            unsafe {
                WHvRetargetVpciDeviceInterrupt(
                    self.part,
                    self.id,
                    address,
                    data,
                    target.as_ptr() as *const WHV_VPCI_INTERRUPT_TARGET,
                )
            },
            "WHvRetargetVpciDeviceInterrupt",
        )
    }

    /// Inject a synthetic MSI as if the device had raised it (testing / replay).
    pub fn request_interrupt(&self, address: u64, data: u32) -> Result<()> {
        check_hr(
            unsafe { WHvRequestVpciDeviceInterrupt(self.part, self.id, address, data) },
            "WHvRequestVpciDeviceInterrupt",
        )
    }

    /// Poll for a pending device notification (non-blocking).
    pub fn get_notification(&self) -> Result<Option<DeviceNotification>> {
        let mut n: WHV_VPCI_DEVICE_NOTIFICATION = unsafe { std::mem::zeroed() };
        check_hr(
            unsafe {
                WHvGetVpciDeviceNotification(
                    self.part,
                    self.id,
                    &mut n,
                    std::mem::size_of::<WHV_VPCI_DEVICE_NOTIFICATION>() as u32,
                )
            },
            "WHvGetVpciDeviceNotification",
        )?;
        Ok(match n.NotificationType {
            x if x == WHvVpciDeviceNotificationMmioRemapping => {
                Some(DeviceNotification::MmioRemapping)
            }
            x if x == WHvVpciDeviceNotificationSurpriseRemoval => {
                Some(DeviceNotification::SurpriseRemoval)
            }
            _ => None,
        })
    }
}

impl Drop for VpciDevice {
    fn drop(&mut self) {
        unsafe {
            // Best-effort teardown; ignore failures (e.g. ranges not mapped).
            WHvUnmapVpciDeviceMmioRanges(self.part, self.id);
            WHvDeleteVpciDevice(self.part, self.id);
        }
    }
}

/// Build a variable-length `WHV_VPCI_INTERRUPT_TARGET` { Vector, Flags,
/// ProcessorCount, Processors[..] } in a 4-byte-aligned `Vec<u32>`. The struct
/// is `#[repr(C)]` with four `u32`-sized fields and no padding, so dword index
/// 0=Vector, 1=Flags, 2=ProcessorCount, 3.. = Processors.
fn build_interrupt_target(vector: u32, multicast: bool, processors: &[u32]) -> Vec<u32> {
    assert!(
        !processors.is_empty(),
        "interrupt target needs >=1 processor"
    );
    let mut buf = vec![0u32; 3 + processors.len()];
    buf[0] = vector;
    buf[1] = if multicast && processors.len() > 1 {
        WHvVpciInterruptTargetFlagMulticast as u32
    } else {
        0
    };
    buf[2] = processors.len() as u32;
    buf[3..].copy_from_slice(processors);
    buf
}

/// A decoded BAR from the probed-BAR sizing dwords.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbedBar {
    /// BAR register index (0..5). A 64-bit BAR occupies `index` and `index+1`.
    pub index: usize,
    pub is_io: bool,
    pub is_64bit: bool,
    pub prefetchable: bool,
    /// Region size in bytes (power of two), or 0 for an unimplemented BAR.
    pub size: u64,
}

/// Decode the 6 raw probed-BAR dwords from `WHvVpciDevicePropertyCodeProbedBARs`
/// into per-BAR (kind, size). A 64-bit BAR consumes two consecutive dwords.
pub fn decode_probed_bars(probed: &[u32; 6]) -> Vec<ProbedBar> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < 6 {
        let lo = probed[i];
        if lo == 0 {
            i += 1; // unimplemented
            continue;
        }
        if lo & 0x1 != 0 {
            // I/O BAR: bits[1:0] are flags; the rest is the address/size mask.
            let mask = (lo & !0x3) as u64;
            let size = if mask == 0 {
                0
            } else {
                ((!mask) & 0xFFFF_FFFF).wrapping_add(1)
            };
            out.push(ProbedBar {
                index: i,
                is_io: true,
                is_64bit: false,
                prefetchable: false,
                size,
            });
            i += 1;
            continue;
        }
        // Memory BAR: bits[2:1] type (0=32-bit, 2=64-bit), bit3 prefetchable.
        let type_bits = (lo >> 1) & 0x3;
        let prefetchable = (lo >> 3) & 0x1 != 0;
        let is_64bit = type_bits == 0x2;
        if is_64bit && i + 1 < 6 {
            let mask = ((lo & !0xF) as u64) | ((probed[i + 1] as u64) << 32);
            let size = if mask == 0 {
                0
            } else {
                (!mask).wrapping_add(1)
            };
            out.push(ProbedBar {
                index: i,
                is_io: false,
                is_64bit: true,
                prefetchable,
                size,
            });
            i += 2;
        } else {
            let mask = (lo & !0xF) as u64;
            let size = if mask == 0 {
                0
            } else {
                ((!mask) & 0xFFFF_FFFF).wrapping_add(1)
            };
            out.push(ProbedBar {
                index: i,
                is_io: false,
                is_64bit: false,
                prefetchable,
                size,
            });
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_32bit_mem_bar() {
        // 16 MiB non-prefetchable 32-bit MMIO BAR in BAR0.
        let probed = [0xFF00_0000u32, 0, 0, 0, 0, 0];
        let bars = decode_probed_bars(&probed);
        assert_eq!(bars.len(), 1);
        assert_eq!(
            bars[0],
            ProbedBar {
                index: 0,
                is_io: false,
                is_64bit: false,
                prefetchable: false,
                size: 0x100_0000,
            }
        );
    }

    #[test]
    fn decode_64bit_prefetchable_bar_256mib() {
        // 256 MiB prefetchable 64-bit BAR in BAR1/BAR2.
        let probed = [0, 0xF000_000C, 0xFFFF_FFFF, 0, 0, 0];
        let bars = decode_probed_bars(&probed);
        assert_eq!(bars.len(), 1);
        assert_eq!(
            bars[0],
            ProbedBar {
                index: 1,
                is_io: false,
                is_64bit: true,
                prefetchable: true,
                size: 0x1000_0000,
            }
        );
    }

    #[test]
    fn decode_64bit_rebar_16gib() {
        // 16 GiB resizable-BAR aperture (multi-GiB, above 4 GiB) in BAR1/BAR2.
        let probed = [0, 0x0000_000C, 0xFFFF_FFFC, 0, 0, 0];
        let bars = decode_probed_bars(&probed);
        assert_eq!(bars.len(), 1);
        assert_eq!(bars[0].index, 1);
        assert!(bars[0].is_64bit && bars[0].prefetchable);
        assert_eq!(bars[0].size, 0x4_0000_0000);
    }

    #[test]
    fn decode_io_bar() {
        // 256-byte I/O BAR in BAR4.
        let probed = [0, 0, 0, 0, 0xFFFF_FF01, 0];
        let bars = decode_probed_bars(&probed);
        assert_eq!(bars.len(), 1);
        assert_eq!(bars[0].index, 4);
        assert!(bars[0].is_io);
        assert_eq!(bars[0].size, 0x100);
    }

    #[test]
    fn decode_nvidia_gpu_like_layout() {
        // GA10x-style: BAR0 = 16 MiB regs (32-bit), BAR1/2 = 256 MiB pref 64-bit
        // aperture, BAR3/4 = 32 MiB pref 64-bit.
        let probed = [
            0xFF00_0000,
            0xF000_000C,
            0xFFFF_FFFF,
            0xFE00_000C,
            0xFFFF_FFFF,
            0,
        ];
        let bars = decode_probed_bars(&probed);
        assert_eq!(bars.len(), 3);
        assert_eq!(
            (bars[0].index, bars[0].size, bars[0].is_64bit),
            (0, 0x100_0000, false)
        );
        assert_eq!(
            (bars[1].index, bars[1].size, bars[1].is_64bit),
            (1, 0x1000_0000, true)
        );
        assert_eq!(
            (bars[2].index, bars[2].size, bars[2].is_64bit),
            (3, 0x200_0000, true)
        );
    }

    #[test]
    fn build_target_layout() {
        let t = build_interrupt_target(0x50, true, &[0, 2, 3]);
        assert_eq!(t[0], 0x50); // Vector
        assert_eq!(t[1], WHvVpciInterruptTargetFlagMulticast as u32); // Flags
        assert_eq!(t[2], 3); // ProcessorCount
        assert_eq!(&t[3..], &[0, 2, 3]); // Processors (VP indices)
    }

    #[test]
    fn build_target_single_processor_not_multicast() {
        let t = build_interrupt_target(0x30, true, &[1]);
        assert_eq!(t[1], 0); // multicast suppressed for a single target
        assert_eq!(t[2], 1);
        assert_eq!(&t[3..], &[1]);
    }
}
