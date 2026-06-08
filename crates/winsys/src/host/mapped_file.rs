//! Win32 file-mapping RAII wrapper. Port of src/host/mapped_file.cpp.
//!
//! Used by the PVH loader to bring vmlinux / initramfs into the address space
//! without the read-into-`Vec` copy: `CreateFileMapping` + `MapViewOfFile` lets
//! us hand the pages straight to a memcpy into guest RAM (~1/3 the cost of a
//! `std::fs::read` for tens-of-MB files).
//!
//! Read-only view by design. The OS handle is opened shared read/write so the
//! user can keep overwriting the file on disk; the view stays consistent for
//! this object's lifetime.

use super::wide;
use crate::error::{Error, Result};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFileSizeEx, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_SEQUENTIAL_SCAN, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_READ, MEMORY_MAPPED_VIEW_ADDRESS,
    PAGE_READONLY,
};

pub struct MappedFile {
    file: HANDLE,
    mapping: HANDLE,
    base: *const u8,
    size: usize,
}

// The mapped view is owned by this object for its whole lifetime and only ever
// read; the backing handles are closed on drop.
unsafe impl Send for MappedFile {}
unsafe impl Sync for MappedFile {}

impl MappedFile {
    /// Open and map `path` read-only. A zero-byte file maps as an empty view.
    pub fn open(path: &str) -> Result<MappedFile> {
        let wpath = wide(path);
        let file = unsafe {
            CreateFileW(
                wpath.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                core::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                core::ptr::null_mut(),
            )
        };
        if file == INVALID_HANDLE_VALUE {
            let err = unsafe { GetLastError() };
            return Err(Error::msg(format!(
                "MappedFile: open {path} failed (Win32 error {err})"
            )));
        }

        let mut li: i64 = 0;
        if unsafe { GetFileSizeEx(file, &mut li) } == 0 {
            let err = unsafe { GetLastError() };
            unsafe { CloseHandle(file) };
            return Err(Error::msg(format!(
                "MappedFile: GetFileSizeEx {path} failed (Win32 error {err})"
            )));
        }
        let size = li as usize;

        // Zero-byte file: CreateFileMapping(size 0) means "the file size" and
        // fails on an empty file, so handle it directly (empty view).
        if size == 0 {
            return Ok(MappedFile {
                file,
                mapping: core::ptr::null_mut(),
                base: core::ptr::null(),
                size: 0,
            });
        }

        let mapping = unsafe {
            CreateFileMappingW(
                file,
                core::ptr::null(),
                PAGE_READONLY,
                0,
                0,
                core::ptr::null(),
            )
        };
        if mapping.is_null() {
            let err = unsafe { GetLastError() };
            unsafe { CloseHandle(file) };
            return Err(Error::msg(format!(
                "MappedFile: CreateFileMapping {path} failed (Win32 error {err})"
            )));
        }

        let view: MEMORY_MAPPED_VIEW_ADDRESS =
            unsafe { MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0) };
        if view.Value.is_null() {
            let err = unsafe { GetLastError() };
            unsafe {
                CloseHandle(mapping);
                CloseHandle(file);
            }
            return Err(Error::msg(format!(
                "MappedFile: MapViewOfFile {path} failed (Win32 error {err})"
            )));
        }

        Ok(MappedFile {
            file,
            mapping,
            base: view.Value as *const u8,
            size,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        if self.size == 0 {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.base, self.size) }
    }

    pub fn size(&self) -> usize {
        self.size
    }
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

impl Drop for MappedFile {
    fn drop(&mut self) {
        unsafe {
            if !self.base.is_null() {
                UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                    Value: self.base as *mut core::ffi::c_void,
                });
            }
            if !self.mapping.is_null() {
                CloseHandle(self.mapping);
            }
            if self.file != INVALID_HANDLE_VALUE {
                CloseHandle(self.file);
            }
        }
    }
}
