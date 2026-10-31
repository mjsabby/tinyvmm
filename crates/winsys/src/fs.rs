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
//! `\\?\` long-path / path-security policy) stays the caller's concern. The
//! exception is [`open_relative`], which takes a name relative to an open
//! directory and never parses it as a Win32 path.

use core::mem::{offset_of, size_of};
use core::ptr::{null, null_mut};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_DISPOSITION_DELETE, FILE_DISPOSITION_INFORMATION_EX,
    FILE_DISPOSITION_POSIX_SEMANTICS, FILE_INFORMATION_CLASS, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
    FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION, FILE_RENAME_POSIX_SEMANTICS,
    FILE_RENAME_REPLACE_IF_EXISTS, FILE_STAT_LX_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT,
    FileDispositionInformation, FileDispositionInformationEx, FileFsFullSizeInformation,
    FileRenameInformation, FileRenameInformationEx, FileStatLxInformation,
    LX_FILE_METADATA_HAS_GID, LX_FILE_METADATA_HAS_MODE, LX_FILE_METADATA_HAS_UID, NtCreateFile,
    NtQueryInformationFile, NtQueryVolumeInformationFile, NtSetEaFile, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_DELETE_PENDING, ERROR_DIRECTORY_NOT_SUPPORTED, ERROR_FILENAME_EXCED_RANGE,
    FILETIME, GetLastError, INVALID_HANDLE_VALUE, NTSTATUS, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE,
    RtlNtStatusToDosError, STATUS_DELETE_PENDING, STATUS_FILE_IS_A_DIRECTORY,
    STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_BEGIN, FILE_ID_BOTH_DIR_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_STANDARD_INFO, FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo,
    FileStandardInfo, FindClose, FindFirstFileW, FindNextFileW, FlushFileBuffers,
    GetFileInformationByHandle, GetFileInformationByHandleEx, GetFinalPathNameByHandleW, ReadFile,
    SYNCHRONIZE, SetEndOfFile, SetFilePointerEx, SetFileTime, WIN32_FIND_DATAW, WriteFile,
};
use windows_sys::Win32::System::IO::{IO_STATUS_BLOCK, OVERLAPPED};
use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;

pub use windows_sys::Win32::Foundation::HANDLE;

const ERROR_HANDLE_EOF: u32 = 38;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_NO_MORE_FILES: u32 = 18;
/// `IO_STATUS_BLOCK.Information` of an `NtCreateFile` that created the file.
const FILE_CREATED: usize = 2;

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
            null(),
            disposition,
            flags,
            null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(unsafe { GetLastError() });
    }
    Ok(h)
}

/// What [`open_relative`] does about an existing file of that name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Create {
    /// Open the existing file; fail if there is none (`FILE_OPEN`).
    Existing,
    /// Create the file; fail if the name exists (`FILE_CREATE`).
    New,
    /// Open the file, creating it if there is none (`FILE_OPEN_IF`).
    OpenOrNew,
}

/// The kind of file [`open_relative`] accepts, or creates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Any,
    /// Not a directory: a directory fails with `ERROR_DIRECTORY_NOT_SUPPORTED`.
    File,
    /// A directory: a file fails with `ERROR_DIRECTORY`.
    Directory,
}

/// How [`open_relative`] opens a name.
#[derive(Clone, Copy, Debug)]
pub struct Open {
    /// `GENERIC_*` / `FILE_*` access rights. `SYNCHRONIZE` and
    /// `FILE_READ_ATTRIBUTES` are always added, as `CreateFileW` adds them.
    pub access: u32,
    pub create: Create,
    pub kind: Kind,
    /// Open a final symlink or junction itself, not what it points at
    /// (`FILE_OPEN_REPARSE_POINT`), as `DeleteFileW` and `MoveFileExW` do.
    pub entry: bool,
    /// Follow symlinks, junctions and mount points on the way. Without it the
    /// open fails with `ERROR_REPARSE_POINT_ENCOUNTERED` at the first one, before
    /// it has any effect (`OBJ_DONT_REPARSE`), so whatever opens lies below the
    /// directory the name is relative to. Reparse points that a file system
    /// filter resolves in place (compressed, deduplicated or cloud files) are
    /// not links and open either way.
    pub follow: bool,
}

impl Open {
    /// Open an existing file of any kind with `access`, following no link.
    pub const fn existing(access: u32) -> Open {
        Open {
            access,
            create: Create::Existing,
            kind: Kind::Any,
            entry: false,
            follow: false,
        }
    }

    pub const fn with_create(self, create: Create) -> Open {
        Open { create, ..self }
    }

    pub const fn with_kind(self, kind: Kind) -> Open {
        Open { kind, ..self }
    }

    /// See [`Open::entry`].
    pub const fn as_entry(self) -> Open {
        Open {
            entry: true,
            ..self
        }
    }

    /// See [`Open::follow`].
    pub const fn following(self) -> Open {
        Open {
            follow: true,
            ..self
        }
    }
}

/// `NtCreateFile` of `name` relative to the open directory `dir`, sharing read,
/// write and delete with other openers, for synchronous I/O. `name` is one or
/// more components separated by `\`, without a terminating NUL. It is never
/// parsed as a Win32 path: `.` and `..` are invalid names, and nothing is
/// stripped or mapped (no trailing dots, no DOS device names), so the caller
/// must pass only names it has validated. An empty `name` reopens `dir`
/// itself. `dir` needs no particular access right. Returns the handle and
/// whether this call created the file.
pub fn open_relative(dir: HANDLE, name: &[u16], how: Open) -> Result<(HANDLE, bool), u32> {
    static EMPTY: [u16; 1] = [0];
    let bytes = u16::try_from(name.len() * 2).map_err(|_| ERROR_FILENAME_EXCED_RANGE)?;
    let buffer = if name.is_empty() {
        EMPTY.as_ptr()
    } else {
        name.as_ptr()
    };
    let us = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        // The kernel only reads the name.
        Buffer: buffer.cast_mut(),
    };
    let mut attributes = OBJ_CASE_INSENSITIVE;
    if !how.follow {
        attributes |= OBJ_DONT_REPARSE;
    }
    let oa = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: dir,
        ObjectName: &us,
        Attributes: attributes,
        SecurityDescriptor: null(),
        SecurityQualityOfService: null(),
    };
    let disposition = match how.create {
        Create::Existing => FILE_OPEN,
        Create::New => FILE_CREATE,
        Create::OpenOrNew => FILE_OPEN_IF,
    };
    let mut options = FILE_SYNCHRONOUS_IO_NONALERT;
    match how.kind {
        Kind::Any => {}
        Kind::File => options |= FILE_NON_DIRECTORY_FILE,
        Kind::Directory => options |= FILE_DIRECTORY_FILE,
    }
    if how.entry {
        options |= FILE_OPEN_REPARSE_POINT;
    }
    let mut h: HANDLE = null_mut();
    let mut iosb: IO_STATUS_BLOCK = unsafe { core::mem::zeroed() };
    let status = unsafe {
        NtCreateFile(
            &mut h,
            how.access | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
            &oa,
            &mut iosb,
            null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            disposition,
            options,
            null(),
            0,
        )
    };
    nt_result(status)?;
    Ok((h, iosb.Information == FILE_CREATED))
}

/// Open the file `h` refers to again, with `access`: an [`open_relative`] of the
/// empty name, so nothing is looked up by name and the new handle reaches the
/// same file even after it has been renamed.
pub fn reopen(h: HANDLE, access: u32) -> Result<HANDLE, u32> {
    open_relative(h, &[], Open::existing(access)).map(|(h, _)| h)
}

/// Whether `NtSetInformationFile` failed only because the file system lacks the
/// information class or flag, as POSIX semantics are missing outside NTFS and
/// ReFS. `DeleteFileW` falls back on the same statuses.
fn unsupported(status: NTSTATUS) -> bool {
    matches!(
        status,
        STATUS_INVALID_PARAMETER | STATUS_NOT_SUPPORTED | STATUS_INVALID_INFO_CLASS
    )
}

fn set_information(
    h: HANDLE,
    info: *const core::ffi::c_void,
    len: usize,
    class: FILE_INFORMATION_CLASS,
) -> NTSTATUS {
    let mut iosb: IO_STATUS_BLOCK = unsafe { core::mem::zeroed() };
    unsafe { NtSetInformationFile(h, &mut iosb, info, len as u32, class) }
}

/// Delete the file or empty directory `h` refers to, opened with `DELETE`
/// access. With POSIX semantics where the file system has them, the name goes
/// away at once even while other handles keep the file open; otherwise it goes
/// when the last handle closes.
pub fn delete_by_handle(h: HANDLE) -> Result<(), u32> {
    let posix = FILE_DISPOSITION_INFORMATION_EX {
        Flags: FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS,
    };
    let status = set_information(
        h,
        (&raw const posix).cast(),
        size_of::<FILE_DISPOSITION_INFORMATION_EX>(),
        FileDispositionInformationEx,
    );
    if !unsupported(status) {
        return nt_result(status);
    }
    // FILE_DISPOSITION_INFORMATION: one BOOLEAN DeleteFile.
    let delete = 1u8;
    nt_result(set_information(
        h,
        (&raw const delete).cast(),
        1,
        FileDispositionInformation,
    ))
}

/// Rename the file or directory `h` refers to, opened with `DELETE` access, to
/// `name` (one component, no NUL) in the open directory `dir`, replacing a file
/// of that name. With POSIX semantics where the file system has them, a target
/// that other handles hold open is replaced too, where `MoveFileExW` fails.
pub fn rename_by_handle(h: HANDLE, dir: HANDLE, name: &[u16]) -> Result<(), u32> {
    let name_off = offset_of!(FILE_RENAME_INFORMATION, FileName);
    let bytes = name.len() * 2;
    let len = (name_off + bytes).max(size_of::<FILE_RENAME_INFORMATION>());
    // u64 words keep the HANDLE field aligned.
    let mut buf = vec![0u64; len.div_ceil(8)];
    let info = buf.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    // SAFETY: `buf` is zeroed, aligned and at least `len` bytes long, which
    // covers the fixed fields and the `bytes` of name after `name_off`.
    unsafe {
        (*info).Anonymous.Flags = FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS;
        (*info).RootDirectory = dir;
        (*info).FileNameLength = u32::try_from(bytes).map_err(|_| ERROR_FILENAME_EXCED_RANGE)?;
        core::ptr::copy_nonoverlapping(
            name.as_ptr(),
            info.cast::<u8>().add(name_off).cast::<u16>(),
            name.len(),
        );
    }
    let status = set_information(h, info.cast(), len, FileRenameInformationEx);
    if !unsupported(status) {
        return nt_result(status);
    }
    // FILE_RENAME_INFORMATION starts with BOOLEAN ReplaceIfExists instead of
    // the flags.
    // SAFETY: as above.
    unsafe { (*info).Anonymous.Flags = 1 };
    nt_result(set_information(h, info.cast(), len, FileRenameInformation))
}

/// `FILE_FS_FULL_SIZE_INFORMATION`, which windows-sys keeps in a module this
/// crate doesn't otherwise need.
#[repr(C)]
#[derive(Default)]
struct FsFullSizeInformation {
    total_allocation_units: i64,
    caller_available_allocation_units: i64,
    actual_available_allocation_units: i64,
    sectors_per_allocation_unit: u32,
    bytes_per_sector: u32,
}

/// Space on the volume that holds the open file `h`, in bytes:
/// `(available_to_caller, total, free)`, as `GetDiskFreeSpaceExW` reports for a
/// path.
pub fn volume_space(h: HANDLE) -> Result<(u64, u64, u64), u32> {
    let mut info = FsFullSizeInformation::default();
    let mut iosb: IO_STATUS_BLOCK = unsafe { core::mem::zeroed() };
    nt_result(unsafe {
        NtQueryVolumeInformationFile(
            h,
            &mut iosb,
            (&raw mut info).cast(),
            size_of::<FsFullSizeInformation>() as u32,
            FileFsFullSizeInformation,
        )
    })?;
    let unit = u64::from(info.sectors_per_allocation_unit) * u64::from(info.bytes_per_sector);
    let bytes = |units: i64| u64::try_from(units).unwrap_or(0).saturating_mul(unit);
    Ok((
        bytes(info.caller_available_allocation_units),
        bytes(info.total_allocation_units),
        bytes(info.actual_available_allocation_units),
    ))
}

/// `CloseHandle` (errors ignored). No-op on null / `INVALID_HANDLE_VALUE`.
pub fn close(h: HANDLE) {
    if !h.is_null() && h != INVALID_HANDLE_VALUE {
        unsafe { CloseHandle(h) };
    }
}

/// Resolve an open handle to its final canonical path, with symlinks, junctions
/// and mount points resolved and the volume as its NT device name
/// (`\Device\HarddiskVolume3\...`, `VOLUME_NAME_NT`), via
/// `GetFinalPathNameByHandleW`. Returns the NUL-free UTF-16 path, or `None` on
/// failure. The NT form skips the Mount Manager round trip that maps the device
/// to a drive letter: about half the cost of the DOS form.
///
/// The 9p backend uses this to check that a file it reached by following a
/// symlink or junction lies inside the share: the real path of the opened handle
/// shows where the link actually led.
pub fn final_nt_path_by_handle(h: HANDLE) -> Option<Vec<u16>> {
    const VOLUME_NAME_NT: u32 = 0x2;
    // One call into a buffer that fits nearly every path; each call repeats the
    // whole name query. On success the return is the length WITHOUT the NUL; if
    // the buffer is too small, it is the length needed INCLUDING the NUL.
    let mut buf = vec![0u16; 512];
    loop {
        let n = unsafe {
            GetFinalPathNameByHandleW(h, buf.as_mut_ptr(), buf.len() as u32, VOLUME_NAME_NT)
        };
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

/// The Win32 error for a failed NT call. A directory refused where a file was
/// required is `ERROR_DIRECTORY_NOT_SUPPORTED`, and a file being deleted is
/// `ERROR_DELETE_PENDING`, not `RtlNtStatusToDosError`'s generic
/// `ERROR_ACCESS_DENIED` for both, so callers can tell them from "access
/// denied".
#[inline]
fn nt_result(status: NTSTATUS) -> Result<(), u32> {
    if status >= 0 {
        Ok(())
    } else if status == STATUS_FILE_IS_A_DIRECTORY {
        Err(ERROR_DIRECTORY_NOT_SUPPORTED)
    } else if status == STATUS_DELETE_PENDING {
        Err(ERROR_DELETE_PENDING)
    } else {
        Err(unsafe { RtlNtStatusToDosError(status) })
    }
}

/// Whether the file `h` refers to has been deleted: its last name is gone (with
/// POSIX semantics) or goes when the last handle closes. False if that can't be
/// queried.
pub fn is_deleted(h: HANDLE) -> bool {
    let mut info: FILE_STANDARD_INFO = unsafe { core::mem::zeroed() };
    let ok = unsafe {
        GetFileInformationByHandleEx(
            h,
            FileStandardInfo,
            (&raw mut info).cast(),
            size_of::<FILE_STANDARD_INFO>() as u32,
        )
    };
    ok != 0 && info.DeletePending
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
