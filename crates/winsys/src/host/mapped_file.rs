//! Win32 file-mapping RAII wrapper. Port of src/host/mapped_file.cpp.
//!
//! Used by the PVH loader to bring vmlinux / initramfs into the address space
//! without the read-into-`Vec` copy: `CreateFileMapping` + `MapViewOfFile` lets
//! us hand the pages straight to a memcpy into guest RAM (~1/3 the cost of a
//! `std::fs::read` for tens-of-MB files).
//!
//! Read-only view by design. The OS handle is opened shared read/write so the
//! user can keep overwriting the file on disk. The view is no snapshot of the
//! file: what another process writes to it while it is mapped can show
//! through, so a caller must not read a byte twice and count on the same
//! value (the boot loaders copy the header fields they validate). The view's
//! length does hold: the mapping is created for the size read at open, which
//! fails if the file has shrunk since, and Windows refuses to cut a file
//! short while a view of it is mapped.

use super::wide;
use crate::error::{Error, Result};

use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_SEQUENTIAL_SCAN, FILE_SHARE_READ,
    FILE_SHARE_WRITE, GetFileSizeEx, OPEN_EXISTING,
};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_READ, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile, PAGE_READONLY,
    UnmapViewOfFile,
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

        Self::map(file, size).map_err(|(call, err)| {
            unsafe { CloseHandle(file) };
            Error::msg(format!(
                "MappedFile: {call} {path} failed (Win32 error {err})"
            ))
        })
    }

    /// Map the first `size` (non-zero) bytes of `file`, which the mapping
    /// owns from then on; on failure, the call that failed and its error.
    ///
    /// The size is given to both calls rather than left to default to the
    /// file's: were the file cut short after `size` was read, a mapping of
    /// whatever it then holds would end before `size`, and `bytes()` would
    /// run past the view. A read-only mapping can't extend a file, so asking
    /// for more than the file holds fails instead.
    fn map(file: HANDLE, size: usize) -> std::result::Result<MappedFile, (&'static str, u32)> {
        let mapping = unsafe {
            CreateFileMappingW(
                file,
                core::ptr::null(),
                PAGE_READONLY,
                (size as u64 >> 32) as u32,
                size as u32,
                core::ptr::null(),
            )
        };
        if mapping.is_null() {
            return Err(("CreateFileMapping", unsafe { GetLastError() }));
        }

        let view: MEMORY_MAPPED_VIEW_ADDRESS =
            unsafe { MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, size) };
        if view.Value.is_null() {
            let err = unsafe { GetLastError() };
            unsafe { CloseHandle(mapping) };
            return Err(("MapViewOfFile", err));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::io::AsRawHandle;

    fn temp_file(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let name = format!("winsys-mapped-{}-{name}", std::process::id());
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn maps_a_file_and_an_empty_one() {
        let bytes: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
        let path = temp_file("whole", &bytes);
        let mapped = MappedFile::open(path.to_str().unwrap()).unwrap();
        assert_eq!(mapped.size(), bytes.len());
        assert!(mapped.bytes() == bytes);
        drop(mapped);
        std::fs::write(&path, b"").unwrap();
        let mapped = MappedFile::open(path.to_str().unwrap()).unwrap();
        assert!(mapped.is_empty() && mapped.bytes().is_empty());
        drop(mapped);
        std::fs::remove_file(&path).unwrap();
        assert!(MappedFile::open(path.to_str().unwrap()).is_err());
    }

    #[test]
    fn a_view_is_never_shorter_than_its_size() {
        let path = temp_file("short", &[7u8; 8192]);
        // As if the file held three pages when its size was read, and was cut
        // to two before it was mapped: that is no view of two pages with a
        // size of three, whose third `bytes()` would run into.
        let file = std::fs::File::open(&path).unwrap();
        assert!(MappedFile::map(file.as_raw_handle() as HANDLE, 12288).is_err());
        drop(file);
        // Nor can the file be cut short once it is mapped, though it is open
        // for others to write: Windows refuses until the view is gone.
        let mapped = MappedFile::open(path.to_str().unwrap()).unwrap();
        let writer = std::fs::OpenOptions::new().write(true).open(&path);
        let writer = writer.unwrap();
        assert!(writer.set_len(4096).is_err());
        assert!(mapped.bytes() == [7u8; 8192]);
        drop(mapped);
        writer.set_len(4096).unwrap();
        drop(writer);
        std::fs::remove_file(&path).unwrap();
    }
}
