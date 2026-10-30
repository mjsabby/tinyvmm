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

use windows_sys::Wdk::Storage::FileSystem::{
    FILE_STAT_LX_INFORMATION, FileStatLxInformation, LX_FILE_METADATA_HAS_GID,
    LX_FILE_METADATA_HAS_MODE, LX_FILE_METADATA_HAS_UID, NtQueryInformationFile, NtSetEaFile,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, FILETIME, GetLastError, INVALID_HANDLE_VALUE, RtlNtStatusToDosError,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_ALWAYS, CREATE_NEW, CreateDirectoryW, CreateFileW,
    DeleteFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_BEGIN, FILE_ID_BOTH_DIR_INFO,
    FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo, FindClose, FindFirstFileW,
    FindNextFileW, FlushFileBuffers, GetDiskFreeSpaceExW, GetFileAttributesW,
    GetFileInformationByHandle, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
    MoveFileExW, OPEN_ALWAYS, ReadFile, RemoveDirectoryW, SetEndOfFile, SetFilePointerEx,
    SetFileTime, WIN32_FIND_DATAW, WriteFile,
};
use windows_sys::Win32::System::IO::{IO_STATUS_BLOCK, OVERLAPPED};
use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;

pub use windows_sys::Win32::Foundation::HANDLE;

const ERROR_HANDLE_EOF: u32 = 38;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_NO_MORE_FILES: u32 = 18;
const ERROR_ALREADY_EXISTS: u32 = 183;

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
    create_file_ex(path, access, share, disposition, flags).map(|(h, _)| h)
}

/// [`create_file`] that also says whether this call created the file, as
/// opposed to opening one that already existed.
pub fn create_file_ex(
    path: &[u16],
    access: u32,
    share: u32,
    disposition: u32,
    flags: u32,
) -> Result<(HANDLE, bool), u32> {
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
    let err = unsafe { GetLastError() };
    if h == INVALID_HANDLE_VALUE {
        return Err(err);
    }
    // OPEN_ALWAYS / CREATE_ALWAYS report an existing file through the last
    // error; CREATE_NEW only succeeds by creating, the others never create.
    let created = match disposition {
        CREATE_NEW => true,
        OPEN_ALWAYS | CREATE_ALWAYS => err != ERROR_ALREADY_EXISTS,
        _ => false,
    };
    Ok((h, created))
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
    final_path(h, 0)
}

/// As [`final_path_by_handle`], but with the volume as its NT device name
/// (`\Device\HarddiskVolume3\...`, `VOLUME_NAME_NT`). Same resolution, without
/// the Mount Manager round trip that maps the device to a drive letter: about
/// half the cost, which matters when it runs for every 9p walk and getattr.
pub fn final_nt_path_by_handle(h: HANDLE) -> Option<Vec<u16>> {
    const VOLUME_NAME_NT: u32 = 0x2;
    final_path(h, VOLUME_NAME_NT)
}

fn final_path(h: HANDLE, flags: u32) -> Option<Vec<u16>> {
    // One call into a buffer that fits nearly every path; each call repeats the
    // whole name query. On success the return is the length WITHOUT the NUL; if
    // the buffer is too small, it is the length needed INCLUDING the NUL.
    let mut buf = vec![0u16; 512];
    loop {
        let n = unsafe { GetFinalPathNameByHandleW(h, buf.as_mut_ptr(), buf.len() as u32, flags) };
        if n == 0 {
            return None;
        }
        if (n as usize) < buf.len() {
            buf.truncate(n as usize);
            return Some(buf);
        }
        if n as usize <= buf.len() {
            return None;
        }
        buf.resize(n as usize, 0);
    }
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

/// A file's WSL Linux metadata: the `$LXUID` / `$LXGID` / `$LXMOD` NTFS
/// extended attributes that WSL's drvfs `metadata` mount option reads and
/// writes. A field is `None` when the file doesn't carry that attribute.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LxMetadata {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    /// The full `st_mode`, file type included (e.g. `0o100644`).
    pub mode: Option<u32>,
}

#[inline]
fn nt_result(status: i32) -> Result<(), u32> {
    if status < 0 {
        Err(unsafe { RtlNtStatusToDosError(status) })
    } else {
        Ok(())
    }
}

/// Read a file's [`LxMetadata`] with `NtQueryInformationFile(FileStatLxInformation)`,
/// which has NTFS decode the `$LX*` attributes itself.
pub fn lx_metadata(h: HANDLE) -> Result<LxMetadata, u32> {
    let mut info: FILE_STAT_LX_INFORMATION = unsafe { core::mem::zeroed() };
    let mut iosb: IO_STATUS_BLOCK = unsafe { core::mem::zeroed() };
    nt_result(unsafe {
        NtQueryInformationFile(
            h,
            &mut iosb,
            &mut info as *mut FILE_STAT_LX_INFORMATION as *mut core::ffi::c_void,
            core::mem::size_of::<FILE_STAT_LX_INFORMATION>() as u32,
            FileStatLxInformation,
        )
    })?;
    let has = |flag: u32| info.LxFlags & flag != 0;
    Ok(LxMetadata {
        uid: has(LX_FILE_METADATA_HAS_UID).then_some(info.LxUid),
        gid: has(LX_FILE_METADATA_HAS_GID).then_some(info.LxGid),
        mode: has(LX_FILE_METADATA_HAS_MODE).then_some(info.LxMode),
    })
}

/// Write the `Some` fields of `md` as WSL's `$LXUID` / `$LXGID` / `$LXMOD`
/// extended attributes (each a little-endian u32) with `NtSetEaFile`, leaving
/// the others untouched. Needs a handle opened with `FILE_WRITE_EA`.
pub fn set_lx_metadata(h: HANDLE, md: LxMetadata) -> Result<(), u32> {
    let fields: Vec<(&str, u32)> = [("$LXUID", md.uid), ("$LXGID", md.gid), ("$LXMOD", md.mode)]
        .into_iter()
        .filter_map(|(name, v)| v.map(|v| (name, v)))
        .collect();
    if fields.is_empty() {
        return Ok(());
    }
    // A chain of FILE_FULL_EA_INFORMATION entries, each 4-byte aligned:
    // NextEntryOffset u32, Flags u8, EaNameLength u8, EaValueLength u16,
    // the name + NUL, then the value.
    let mut bytes = Vec::new();
    for (i, (name, value)) in fields.iter().enumerate() {
        let entry_len = (8 + name.len() + 1 + 4).next_multiple_of(4);
        let next = if i + 1 < fields.len() { entry_len } else { 0 };
        let start = bytes.len();
        bytes.extend_from_slice(&(next as u32).to_le_bytes());
        bytes.push(0);
        bytes.push(name.len() as u8);
        bytes.extend_from_slice(&4u16.to_le_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&value.to_le_bytes());
        bytes.resize(start + entry_len, 0);
    }
    // The kernel checks the entries' alignment, so hand it u32-aligned memory.
    let mut buf = vec![0u32; bytes.len() / 4];
    for (word, chunk) in buf.iter_mut().zip(bytes.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*chunk);
    }
    let mut iosb: IO_STATUS_BLOCK = unsafe { core::mem::zeroed() };
    nt_result(unsafe {
        NtSetEaFile(
            h,
            &mut iosb,
            buf.as_ptr() as *const core::ffi::c_void,
            bytes.len() as u32,
        )
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
    let pa: *const FILETIME = a_ft
        .as_ref()
        .map_or(core::ptr::null(), |f| f as *const FILETIME);
    let pm: *const FILETIME = m_ft
        .as_ref()
        .map_or(core::ptr::null(), |f| f as *const FILETIME);
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

/// One directory entry from [`ReadDirIds`] — like [`DirEntry`] but carries the
/// 64-bit NTFS file-ID (`nFileIndex`) so the caller doesn't have to open each
/// entry just to learn it.
pub struct DirEntryId {
    pub name: String,
    pub is_dir: bool,
    pub file_id: u64,
}

/// Handle-based directory iterator using `GetFileInformationByHandleEx` with
/// `FileIdBothDirectoryInfo`: each refill returns a buffer-full of
/// `FILE_ID_BOTH_DIR_INFO` entries (name + attributes + 64-bit FileId), so a
/// large directory enumerates in O(entries / ~500) syscalls instead of
/// `FindFirstFile` + a per-entry `CreateFile`/`GetFileInformationByHandle`
/// (the 9p backend's previous `build_dir_cache` did the latter — ~4 syscalls
/// per entry, the dominant cost of `Treaddir` on big directories).
///
/// `h` is a *borrowed* directory handle opened with `FILE_LIST_DIRECTORY`; the
/// caller owns it (this iterator does not close it).
pub struct ReadDirIds {
    handle: HANDLE,
    buf: Box<[u8]>,
    /// Byte offset of the next entry in `buf`; `usize::MAX` means "refill".
    pos: usize,
    done: bool,
    restart: bool,
}

pub fn read_dir_ids(h: HANDLE) -> ReadDirIds {
    ReadDirIds {
        handle: h,
        buf: vec![0u8; 64 * 1024].into_boxed_slice(),
        pos: usize::MAX,
        done: false,
        restart: true,
    }
}

impl Iterator for ReadDirIds {
    type Item = DirEntryId;

    fn next(&mut self) -> Option<DirEntryId> {
        if self.pos == usize::MAX {
            if self.done {
                return None;
            }
            let class = if self.restart {
                FileIdBothDirectoryRestartInfo
            } else {
                FileIdBothDirectoryInfo
            };
            self.restart = false;
            let ok = unsafe {
                GetFileInformationByHandleEx(
                    self.handle,
                    class,
                    self.buf.as_mut_ptr() as *mut core::ffi::c_void,
                    self.buf.len() as u32,
                )
            };
            if ok == 0 {
                // ERROR_NO_MORE_FILES on a clean end; anything else is also end
                // for our purposes (the caller treats a short listing as such).
                self.done = true;
                return None;
            }
            self.pos = 0;
        }
        // SAFETY: the kernel wrote a valid FILE_ID_BOTH_DIR_INFO at `pos`
        // (NextEntryOffset chain, 8-byte aligned). We read fields by unaligned
        // ptr to be defensive about the struct's declared alignment.
        let base = unsafe { self.buf.as_ptr().add(self.pos) };
        let rec = base as *const FILE_ID_BOTH_DIR_INFO;
        let (next_off, attrs, name_len, file_id) = unsafe {
            (
                (*rec).NextEntryOffset,
                (*rec).FileAttributes,
                (*rec).FileNameLength as usize / 2,
                (*rec).FileId as u64,
            )
        };
        // FileName is the trailing variable-length array.
        let name_ptr = unsafe { core::ptr::addr_of!((*rec).FileName) as *const u16 };
        let name =
            String::from_utf16_lossy(unsafe { core::slice::from_raw_parts(name_ptr, name_len) });
        self.pos = if next_off == 0 {
            usize::MAX
        } else {
            self.pos + next_off as usize
        };
        Some(DirEntryId {
            name,
            is_dir: attrs & FILE_ATTRIBUTE_DIRECTORY != 0,
            file_id,
        })
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, FILE_READ_ATTRIBUTES, FILE_READ_EA,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_EA, OPEN_EXISTING,
    };

    const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    fn wide(p: &std::path::Path) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        p.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    /// What we write must be what WSL writes: NTFS's own `FileStatLxInformation`
    /// decoder of the `$LX*` attributes has to read it back, field by field.
    #[test]
    fn lx_metadata_round_trips_through_ntfs() {
        let path = std::env::temp_dir().join(format!("winsys_lx_{}", std::process::id()));
        let w = wide(&path);
        let access = FILE_WRITE_EA | FILE_READ_EA | FILE_READ_ATTRIBUTES;
        let h = create_file(&w, access, SHARE_ALL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL).unwrap();
        assert_eq!(lx_metadata(h), Ok(LxMetadata::default()));
        let all = LxMetadata {
            uid: Some(1000),
            gid: Some(1001),
            mode: Some(0o100754),
        };
        set_lx_metadata(h, all).unwrap();
        let mode_only = LxMetadata {
            mode: Some(0o100640),
            ..Default::default()
        };
        set_lx_metadata(h, mode_only).unwrap();
        close(h);

        let h = create_file(
            &w,
            FILE_READ_ATTRIBUTES | FILE_READ_EA,
            SHARE_ALL,
            OPEN_EXISTING,
            0,
        )
        .unwrap();
        let got = lx_metadata(h);
        close(h);
        let _ = std::fs::remove_file(&path);
        assert_eq!(
            got,
            Ok(LxMetadata {
                mode: Some(0o100640),
                ..all
            })
        );
    }
}
