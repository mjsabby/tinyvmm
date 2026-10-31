//! Native VHDX storage. VM-only attachment exposes sector I/O on the virtual
//! disk handle without mounting a host disk or requiring elevation.

use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows_sys::Win32::Foundation::{
    ERROR_GEN_FAILURE, ERROR_INVALID_DATA, ERROR_INVALID_PARAMETER, HANDLE,
};
use windows_sys::Win32::Storage::Vhd::*;
use windows_sys::core::GUID;

use super::{random_fill, wide};

fn check(error: u32) -> Result<(), u32> {
    if error == 0 { Ok(()) } else { Err(error) }
}

fn unique_guid() -> Result<GUID, u32> {
    let mut bytes = [0; 16];
    if !random_fill(&mut bytes) {
        return Err(ERROR_GEN_FAILURE);
    }
    Ok(GUID::from_u128(u128::from_le_bytes(bytes)))
}

fn storage_type() -> VIRTUAL_STORAGE_TYPE {
    VIRTUAL_STORAGE_TYPE {
        DeviceId: VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
        VendorId: VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
    }
}

/// The smallest virtual size VHDMP creates.
pub const MIN_SIZE: u64 = 3 * 1024 * 1024;

/// Create a dynamic VHDX with 2 MiB allocation blocks and 512-byte logical
/// sectors. The destination must not exist. `size` is the virtual size in
/// bytes, at least [`MIN_SIZE`].
pub fn create(path: &str, size: u64) -> Result<(), u32> {
    if path.contains('\0') || size < MIN_SIZE || !size.is_multiple_of(512) {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let parameters = CREATE_VIRTUAL_DISK_PARAMETERS {
        Version: CREATE_VIRTUAL_DISK_VERSION_2,
        Anonymous: CREATE_VIRTUAL_DISK_PARAMETERS_0 {
            Version2: CREATE_VIRTUAL_DISK_PARAMETERS_0_1 {
                UniqueId: unique_guid()?,
                MaximumSize: size,
                BlockSizeInBytes: 2 * 1024 * 1024,
                SectorSizeInBytes: 512,
                PhysicalSectorSizeInBytes: 4096,
                OpenFlags: OPEN_VIRTUAL_DISK_FLAG_CACHED_IO,
                ResiliencyGuid: unique_guid()?,
                ..Default::default()
            },
        },
    };
    let path = wide(path);
    let mut handle = core::ptr::null_mut();
    // Version 2 derives access from the parameters; all pointed-to data lives
    // through this synchronous call. Windows refuses an existing destination.
    unsafe {
        check(CreateVirtualDisk(
            &storage_type(),
            path.as_ptr(),
            VIRTUAL_DISK_ACCESS_NONE,
            core::ptr::null_mut(),
            CREATE_VIRTUAL_DISK_FLAG_NONE,
            0,
            &parameters,
            core::ptr::null_mut(),
            &mut handle,
        ))?;
        drop(OwnedHandle::from_raw_handle(handle));
    }
    Ok(())
}

pub(crate) struct VirtualDisk {
    handle: OwnedHandle,
    pub size: u64,
    unmap_sectors: u32,
}

impl VirtualDisk {
    pub fn open(path: &str, readonly: bool) -> Result<Self, u32> {
        if path.contains('\0') {
            return Err(ERROR_INVALID_PARAMETER);
        }

        let parameters = OPEN_VIRTUAL_DISK_PARAMETERS {
            Version: OPEN_VIRTUAL_DISK_VERSION_2,
            Anonymous: OPEN_VIRTUAL_DISK_PARAMETERS_0 {
                Version2: OPEN_VIRTUAL_DISK_PARAMETERS_0_1 {
                    GetInfoOnly: 0,
                    ReadOnly: readonly.into(),
                    // Avoid VHDMP merging independent opens into a shared disk.
                    ResiliencyGuid: unique_guid()?,
                },
            },
        };
        let path = wide(path);
        let mut handle = core::ptr::null_mut();
        unsafe {
            check(OpenVirtualDisk(
                &storage_type(),
                path.as_ptr(),
                VIRTUAL_DISK_ACCESS_NONE,
                OPEN_VIRTUAL_DISK_FLAG_CACHED_IO,
                &parameters,
                &mut handle,
            ))?;
        }
        // Ownership starts immediately so failures below close the handle.
        let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
        let flags = ATTACH_VIRTUAL_DISK_FLAG_NO_LOCAL_HOST
            | if readonly {
                ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY
            } else {
                0
            };
        let mut info = GET_VIRTUAL_DISK_INFO {
            Version: GET_VIRTUAL_DISK_INFO_SIZE,
            ..Default::default()
        };
        let mut info_size = core::mem::size_of_val(&info) as u32;
        unsafe {
            check(AttachVirtualDisk(
                handle.as_raw_handle(),
                core::ptr::null_mut(),
                flags,
                0,
                core::ptr::null(),
                core::ptr::null(),
            ))?;
            check(GetVirtualDiskInformation(
                handle.as_raw_handle(),
                &mut info_size,
                &mut info,
                core::ptr::null_mut(),
            ))?;
        }
        let size = unsafe { info.Anonymous.Size };
        // virtio-blk currently exposes only 512-byte logical sectors.
        if size.SectorSize != 512 || size.VirtualSize == 0 {
            return Err(ERROR_INVALID_PARAMETER);
        }
        let mut disk = Self {
            handle,
            size: size.VirtualSize,
            unmap_sectors: 0,
        };
        if !readonly {
            // Older VHDMP versions may not implement SCSI passthrough or UNMAP;
            // DISCARD is then ignored.
            disk.unmap_sectors = disk.query_unmap().unwrap_or(0);
        }
        Ok(disk)
    }

    pub fn handle(&self) -> HANDLE {
        self.handle.as_raw_handle()
    }

    fn command(&self, cdb: &mut [u8], data: &mut [u8], data_in: bool) -> Result<usize, u32> {
        let mut sense = [0; 32];
        let parameters = RAW_SCSI_VIRTUAL_DISK_PARAMETERS {
            Version: RAW_SCSI_VIRTUAL_DISK_VERSION_1,
            Anonymous: RAW_SCSI_VIRTUAL_DISK_PARAMETERS_0 {
                Version1: RAW_SCSI_VIRTUAL_DISK_PARAMETERS_0_0 {
                    DataIn: data_in.into(),
                    CdbLength: cdb.len().try_into().map_err(|_| ERROR_INVALID_PARAMETER)?,
                    SenseInfoLength: sense.len() as u8,
                    DataTransferLength: data
                        .len()
                        .try_into()
                        .map_err(|_| ERROR_INVALID_PARAMETER)?,
                    DataBuffer: data.as_mut_ptr().cast(),
                    SenseInfo: sense.as_mut_ptr(),
                    Cdb: cdb.as_mut_ptr(),
                    ..Default::default()
                },
            },
        };
        let mut response = RAW_SCSI_VIRTUAL_DISK_RESPONSE {
            Version: RAW_SCSI_VIRTUAL_DISK_VERSION_1,
            ..Default::default()
        };
        unsafe {
            check(RawSCSIVirtualDisk(
                self.handle(),
                &parameters,
                RAW_SCSI_VIRTUAL_DISK_FLAG_NONE,
                &mut response,
            ))?;
        }
        let response = unsafe { response.Anonymous.Version1 };
        if response.ScsiStatus != 0 {
            return Err(ERROR_GEN_FAILURE);
        }
        if response.DataTransferLength as usize > data.len()
            || response.SenseInfoLength as usize > sense.len()
        {
            return Err(ERROR_INVALID_DATA);
        }
        Ok(response.DataTransferLength as usize)
    }

    fn vpd<'a>(&self, page: u8, buffer: &'a mut [u8; 255]) -> Result<&'a [u8], u32> {
        let mut cdb = [0x12, 1, page, 0, 255, 0];
        let length = self.command(&mut cdb, buffer, true)?;
        if length < 4 || buffer[1] != page {
            return Err(ERROR_INVALID_DATA);
        }
        let page_length = u16::from_be_bytes([buffer[2], buffer[3]]) as usize;
        buffer[..length]
            .get(4..4 + page_length)
            .ok_or(ERROR_INVALID_DATA)
    }

    /// The most sectors one UNMAP may cover, or 0 without UNMAP support.
    fn query_unmap(&self) -> Result<u32, u32> {
        let mut buffer = [0; 255];
        let pages = self.vpd(0, &mut buffer)?;
        if !pages.contains(&0xb2) || !pages.contains(&0xb0) {
            return Ok(0);
        }
        let provisioning = self.vpd(0xb2, &mut buffer)?;
        if provisioning.get(1).ok_or(ERROR_INVALID_DATA)? & 0x80 == 0 {
            return Ok(0);
        }
        let limits = self.vpd(0xb0, &mut buffer)?;
        let max_sectors = limits.get(16..20).ok_or(ERROR_INVALID_DATA)?;
        let max_descriptors = limits.get(20..24).ok_or(ERROR_INVALID_DATA)?;
        if u32::from_be_bytes(max_descriptors.try_into().unwrap()) == 0 {
            return Ok(0);
        }
        Ok(u32::from_be_bytes(max_sectors.try_into().unwrap()))
    }

    /// Unmap a byte range. UNMAP is advisory: VHDMP reports success for parts
    /// it leaves mapped (anything not 4 KiB aligned), so discarded sectors are
    /// never promised to read back as zero.
    pub fn discard_range(&self, offset: u64, length: u64) -> bool {
        if !offset.is_multiple_of(512) || !length.is_multiple_of(512) {
            return false;
        }
        let mut sector = offset / 512;
        let mut sectors = length / 512;
        if self.unmap_sectors != 0 {
            while sectors != 0 {
                let count = sectors.min(self.unmap_sectors as u64) as u32;
                let mut data = [0; 24];
                data[..2].copy_from_slice(&22u16.to_be_bytes());
                data[2..4].copy_from_slice(&16u16.to_be_bytes());
                data[8..16].copy_from_slice(&sector.to_be_bytes());
                data[16..20].copy_from_slice(&count.to_be_bytes());
                let mut cdb = [0x42, 0, 0, 0, 0, 0, 0, 0, 24, 0];
                if self.command(&mut cdb, &mut data, false).is_err() {
                    return false;
                }
                sector += count as u64;
                sectors -= count as u64;
            }
        }
        // DISCARD may be ignored when the driver does not support UNMAP.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_vhdx_scsi_passthrough() {
        let path = std::env::temp_dir().join(format!(
            "tinyvmm-vhdx-scsi-{}-{}.vhdx",
            std::process::id(),
            unique_guid().unwrap().data1
        ));
        let path_str = path.to_str().unwrap();
        create(path_str, 64 * 1024 * 1024).unwrap();
        {
            let disk = VirtualDisk::open(path_str, false).unwrap();
            // A CHECK CONDITION must not be mistaken for transport success.
            assert!(disk.vpd(0xff, &mut [0; 255]).is_err());
            let mut bytes = [0x5a; 1024];
            let mut write = [0; 16];
            write[0] = 0x8a;
            write[10..14].copy_from_slice(&2u32.to_be_bytes());
            assert_eq!(disk.command(&mut write, &mut bytes, false), Ok(1024));
            let mut read = write;
            read[0] = 0x88;
            let mut back = [0; 1024];
            assert_eq!(disk.command(&mut read, &mut back, true), Ok(1024));
            assert_eq!(back, bytes);
        }
        std::fs::remove_file(path).unwrap();
    }
}
