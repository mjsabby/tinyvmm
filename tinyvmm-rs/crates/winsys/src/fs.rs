//! Safe wrappers over the Win32 file-system APIs the virtio-9p backend uses.
//!
//! All of the `CreateFileW`/`ReadFile`/`WriteFile`/`Find*`/`SetFile*`/etc. FFI is
//! concentrated here behind safe functions returning NEUTRAL types (no
//! windows-sys structs leak to the caller): file metadata comes back as
//! [`FileInfo`], timestamps as raw u64 FILETIME ticks, and directory iteration
//! as a [`ReadDir`] yielding [`DirEntry`]. Fallible calls return
//! `Result<_, u32>` where the `u32` is the raw Win32 error code (the caller maps
//! it to an errno).
//!
//! Callers pass NUL-terminated UTF-16 paths (`&[u16]`); building those (and any
//! `\\?\` long-path / path-security policy) stays the caller's concern.

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, FILETIME, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, DeleteFileW, FindClose, FindFirstFileW, FindNextFileW,
    FlushFileBuffers, GetDiskFreeSpaceExW, GetFileAttributesW, GetFileInformationByHandle,
    GetFinalPathNameByHandleW, MoveFileExW, ReadFile, RemoveDirectoryW, SetEndOfFile,
    SetFilePointerEx, SetFileTime, WriteFile, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
    FILE_BEGIN, WIN32_FIND_DATAW,
};
use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
use windows_sys::Win32::System::IO::OVERLAPPED;

pub use windows_sys::Win32::Foundation::HANDLE;

const ERROR_HANDLE_EOF: u32 = 38;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_NO_MORE_FILES: u32 = 18;

/// A neutral snapshot of `BY_HANDLE_FILE_INFORMATION`; all fields are plain
/// integers so no windows-sys type crosses the crate boundary. Timestamps are
/// raw FILETIME ticks (`(high << 32) | low`).
pub struct FileInfo {
    pub attributes: u32,
    pub size: u64,
    pub nlink: u32,
    pub file_index: u64,
    pub vol_serial: u32,
    pub creation_ticks: u64,
    pub last_access_ticks: u64,
    pub last_write_ticks: u64,
}

#[inline]
fn ft_to_ticks(ft: &FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64
}

#[inline]
fn ticks_to_ft(ticks: u64) -> FILETIME {
    FILETIME {
        dwLowDateTime: (ticks & 0xFFFF_FFFF) as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    }
}

/// `CreateFileW`. Returns `Err(GetLastError)` if the call yields
/// `INVALID_HANDLE_VALUE`.
pub fn create_file(
    path: &[u16],
    access: u32,
    share: u32,
    disposition: u32,
    flags: u32,
) -> Result<HANDLE, u32> {
    let h = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            share,
            core::ptr::null(),
            disposition,
            flags,
            core::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        Err(unsafe { GetLastError() })
    } else {
        Ok(h)
    }
}

/// `CloseHandle` (errors ignored). No-op on null / `INVALID_HANDLE_VALUE`.
pub fn close(h: HANDLE) {
    if !h.is_null() && h != INVALID_HANDLE_VALUE {
        unsafe { CloseHandle(h) };
    }
}

/// Resolve an open handle to its final canonical path (`\\?\C:\...`, with
/// symlinks / junctions / mount points fully resolved) via
/// `GetFinalPathNameByHandleW` (flags 0 == `FILE_NAME_NORMALIZED |
/// VOLUME_NAME_DOS`). Returns the NUL-free UTF-16 path, or `None` on failure.
///
/// The 9p backend uses this to re-check that an opened handle still lands inside
/// the share root: a lexical path check passes for a reparse point that lives
/// inside the share but targets a directory outside it, so the *real* path of
/// the opened handle must be re-validated to defeat that escape.
pub fn final_path_by_handle(h: HANDLE) -> Option<Vec<u16>> {
    // First probe with a zero-length buffer: the return is the required length
    // INCLUDING the terminating NUL.
    let needed = unsafe { GetFinalPathNameByHandleW(h, core::ptr::null_mut(), 0, 0) };
    if needed == 0 {
        return None;
    }
    let mut buf = vec![0u16; needed as usize];
    // On success the return is the length WITHOUT the NUL (and < needed).
    let written = unsafe { GetFinalPathNameByHandleW(h, buf.as_mut_ptr(), needed, 0) };
    if written == 0 || written >= needed {
        return None;
    }
    buf.truncate(written as usize);
    Some(buf)
}

/// `GetFileInformationByHandle` decoded into a [`FileInfo`].
pub fn file_info(h: HANDLE) -> Result<FileInfo, u32> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { core::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(h, &mut info) } == 0 {
        return Err(unsafe { GetLastError() });
    }
    Ok(FileInfo {
        attributes: info.dwFileAttributes,
        size: ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64,
        nlink: info.nNumberOfLinks,
        file_index: ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
        vol_serial: info.dwVolumeSerialNumber,
        creation_ticks: ft_to_ticks(&info.ftCreationTime),
        last_access_ticks: ft_to_ticks(&info.ftLastAccessTime),
        last_write_ticks: ft_to_ticks(&info.ftLastWriteTime),
    })
}

/// Positioned `ReadFile` (offset carried in the OVERLAPPED). Reading at/past EOF
/// returns `Ok(0)`. Returns the number of bytes read.
pub fn read_at(h: HANDLE, buf: &mut [u8], offset: u64) -> Result<u32, u32> {
    let mut got: u32 = 0;
    let mut ov: OVERLAPPED = unsafe { core::mem::zeroed() };
    ov.Anonymous.Anonymous.Offset = (offset & 0xFFFF_FFFF) as u32;
    ov.Anonymous.Anonymous.OffsetHigh = (offset >> 32) as u32;
    let ok = unsafe { ReadFile(h, buf.as_mut_ptr(), buf.len() as u32, &mut got, &mut ov) };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        if err == ERROR_HANDLE_EOF {
            return Ok(0);
        }
        return Err(err);
    }
    Ok(got)
}

/// Positioned `WriteFile` (offset carried in the OVERLAPPED). Returns the number
/// of bytes written.
pub fn write_at(h: HANDLE, buf: &[u8], offset: u64) -> Result<u32, u32> {
    let mut wrote: u32 = 0;
    let mut ov: OVERLAPPED = unsafe { core::mem::zeroed() };
    ov.Anonymous.Anonymous.Offset = (offset & 0xFFFF_FFFF) as u32;
    ov.Anonymous.Anonymous.OffsetHigh = (offset >> 32) as u32;
    let ok = unsafe { WriteFile(h, buf.as_ptr(), buf.len() as u32, &mut wrote, &mut ov) };
    if ok == 0 {
        return Err(unsafe { GetLastError() });
    }
    Ok(wrote)
}

/// Append `WriteFile` (OVERLAPPED offset = 0xFFFFFFFF:0xFFFFFFFF). Returns the
/// number of bytes written.
pub fn write_append(h: HANDLE, buf: &[u8]) -> Result<u32, u32> {
    let mut wrote: u32 = 0;
    let mut ov: OVERLAPPED = unsafe { core::mem::zeroed() };
    ov.Anonymous.Anonymous.Offset = 0xFFFF_FFFF;
    ov.Anonymous.Anonymous.OffsetHigh = 0xFFFF_FFFF;
    let ok = unsafe { WriteFile(h, buf.as_ptr(), buf.len() as u32, &mut wrote, &mut ov) };
    if ok == 0 {
        return Err(unsafe { GetLastError() });
    }
    Ok(wrote)
}

/// Truncate/extend the file to `size` (`SetFilePointerEx` + `SetEndOfFile`).
pub fn set_end_of_file(h: HANDLE, size: u64) -> Result<(), u32> {
    let ok = unsafe { SetFilePointerEx(h, size as i64, core::ptr::null_mut(), FILE_BEGIN) } != 0
        && unsafe { SetEndOfFile(h) } != 0;
    if ok {
        Ok(())
    } else {
        Err(unsafe { GetLastError() })
    }
}

/// `SetFileTime` of the access/write timestamps (raw FILETIME ticks). `None`
/// leaves that timestamp unchanged; creation time is always left untouched.
pub fn set_file_times(
    h: HANDLE,
    atime_ticks: Option<u64>,
    mtime_ticks: Option<u64>,
) -> Result<(), u32> {
    let a_ft = atime_ticks.map(ticks_to_ft);
    let m_ft = mtime_ticks.map(ticks_to_ft);
    let pa: *const FILETIME = a_ft.as_ref().map_or(core::ptr::null(), |f| f as *const FILETIME);
    let pm: *const FILETIME = m_ft.as_ref().map_or(core::ptr::null(), |f| f as *const FILETIME);
    if unsafe { SetFileTime(h, core::ptr::null(), pa, pm) } == 0 {
        return Err(unsafe { GetLastError() });
    }
    Ok(())
}

/// Current system time as raw FILETIME ticks (`GetSystemTimeAsFileTime`).
pub fn now_filetime_ticks() -> u64 {
    let mut ft: FILETIME = unsafe { core::mem::zeroed() };
    unsafe { GetSystemTimeAsFileTime(&mut ft) };
    ft_to_ticks(&ft)
}

/// `FlushFileBuffers`.
pub fn flush(h: HANDLE) -> Result<(), u32> {
    if unsafe { FlushFileBuffers(h) } == 0 {
        return Err(unsafe { GetLastError() });
    }
    Ok(())
}

/// `CreateDirectoryW`.
pub fn create_dir(path: &[u16]) -> Result<(), u32> {
    if unsafe { CreateDirectoryW(path.as_ptr(), core::ptr::null()) } == 0 {
        return Err(unsafe { GetLastError() });
    }
    Ok(())
}

/// `RemoveDirectoryW`.
pub fn remove_dir(path: &[u16]) -> Result<(), u32> {
    if unsafe { RemoveDirectoryW(path.as_ptr()) } == 0 {
        return Err(unsafe { GetLastError() });
    }
    Ok(())
}

/// `DeleteFileW`.
pub fn delete_file(path: &[u16]) -> Result<(), u32> {
    if unsafe { DeleteFileW(path.as_ptr()) } == 0 {
        return Err(unsafe { GetLastError() });
    }
    Ok(())
}

/// `MoveFileExW(from, to, flags)`.
pub fn move_file(from: &[u16], to: &[u16], flags: u32) -> Result<(), u32> {
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), flags) } == 0 {
        return Err(unsafe { GetLastError() });
    }
    Ok(())
}

/// `GetFileAttributesW`. Returns `INVALID_FILE_ATTRIBUTES` (`u32::MAX`) on error;
/// the caller decides whether that matters.
pub fn get_attributes(path: &[u16]) -> u32 {
    unsafe { GetFileAttributesW(path.as_ptr()) }
}

/// `GetDiskFreeSpaceExW` -> `(free_available_to_caller, total, total_free)`.
pub fn disk_free_space(path: &[u16]) -> Result<(u64, u64, u64), u32> {
    let mut avail: u64 = 0;
    let mut total: u64 = 0;
    let mut free: u64 = 0;
    if unsafe { GetDiskFreeSpaceExW(path.as_ptr(), &mut avail, &mut total, &mut free) } == 0 {
        return Err(unsafe { GetLastError() });
    }
    Ok((avail, total, free))
}

/// One directory entry from [`ReadDir`].
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
}

/// Lazy directory iterator over `FindFirstFileW`/`FindNextFileW`. `search` is a
/// NUL-terminated wide path already ending in `\*`. An empty directory yields no
/// entries (not an error). `FindClose` runs on drop.
pub struct ReadDir {
    handle: HANDLE,
    pending: Option<WIN32_FIND_DATAW>,
}

/// Begin enumerating `search` (`...\*`). `FILE_NOT_FOUND`/`NO_MORE_FILES` from
/// `FindFirstFileW` is treated as an empty (successful) listing.
pub fn read_dir(search: &[u16]) -> Result<ReadDir, u32> {
    let mut fd: WIN32_FIND_DATAW = unsafe { core::mem::zeroed() };
    let fh = unsafe { FindFirstFileW(search.as_ptr(), &mut fd) };
    if fh == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        if err == ERROR_FILE_NOT_FOUND || err == ERROR_NO_MORE_FILES {
            return Ok(ReadDir {
                handle: INVALID_HANDLE_VALUE,
                pending: None,
            });
        }
        return Err(err);
    }
    Ok(ReadDir {
        handle: fh,
        pending: Some(fd),
    })
}

fn decode_find(fd: &WIN32_FIND_DATAW) -> DirEntry {
    let len = fd.cFileName.iter().position(|&c| c == 0).unwrap_or(260);
    DirEntry {
        name: String::from_utf16_lossy(&fd.cFileName[..len]),
        is_dir: fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
    }
}

impl Iterator for ReadDir {
    type Item = DirEntry;

    fn next(&mut self) -> Option<DirEntry> {
        if let Some(fd) = self.pending.take() {
            return Some(decode_find(&fd));
        }
        if self.handle == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut fd: WIN32_FIND_DATAW = unsafe { core::mem::zeroed() };
        if unsafe { FindNextFileW(self.handle, &mut fd) } == 0 {
            return None;
        }
        Some(decode_find(&fd))
    }
}

impl Drop for ReadDir {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE {
            unsafe { FindClose(self.handle) };
        }
    }
}
