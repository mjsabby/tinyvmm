//! virtio-9p (spec §5.16 "9P Transport Device"). Port of src/virtio/virtio_9p.cpp.
//!
//! One requestq (qidx 0). Each chain is a single request/reply pair: the driver
//! places the T-message (request) in the device-readable buffers, the device
//! writes the R-message (reply) into the device-writable buffers in the same
//! chain. We speak 9P2000.L (the dialect Linux uses) over a Win32 filesystem
//! backend exposing one host directory.
//!
//! Threading: `notify_queue` runs on whichever vCPU wrote the queue-notify MMIO;
//! we serialise the whole drain by holding the queue lock. Win32 calls run
//! inside the drain; the fid table is a separate mutex taken only for
//! lookup/insert/erase steps.
//!
//! Security: the share root is trusted (the operator chose it); what lies below
//! it is not, since host processes and the guest itself rearrange it. The
//! device holds the root open and keeps each fid as a path below it, built from
//! validated components (no separators, `:`, control characters or reserved DOS
//! names) with "."/".." resolved clamp-to-root. Every host operation parses that
//! path relative to the root handle with `OBJ_DONT_REPARSE`, so the kernel
//! refuses a symlink, junction or mount point on the way before it has any
//! effect: nothing outside the share is reachable by construction, and no path
//! check can race the operation. A path through a link takes
//! `P9Device::open_linked`, which follows links only to places inside the share.
//!
//! Ownership: NTFS has no POSIX owner or mode bits, so every entry reports the
//! share's configured `uid`/`gid` (default 0, root) and a synthesized mode
//! (dirs 0755, files 0644, or 0444 when read-only on the host). The guest
//! enforces those bits itself, so only that owner (or root) can write. chmod
//! and chown are accepted but not stored, unless the share has `metadata`.
//!
//! Metadata (opt-in, like WSL's drvfs `metadata` mount option): owner, group
//! and permission bits live in WSL's `$LXUID`/`$LXGID`/`$LXMOD` NTFS extended
//! attributes. chmod/chown write them, a new file records its creator (the
//! attaching user's `n_uname`), its `gid` and its mode, and getattr prefers
//! them over the defaults above, so the guest and WSL see the same owners and
//! permissions. The file type always comes from the host.

#![allow(clippy::too_many_arguments)]

use crate::virtio::device::{
    DEVICE_ID_P9, FEATURE_RING_EVENT_IDX, FEATURE_VERSION_1, VirtioDevice,
};
use crate::virtio::queue::{ChainBuf, ChainScratch, Virtqueue};
use crate::whp::GuestMemory;
use std::collections::HashMap;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use std::cell::UnsafeCell;
use std::thread;
use windows_sys::Win32::Foundation::HANDLE;
use winsys::fs;
use winsys::sock::{self, Iocp};

// ---- queue / feature constants -------------------------------------------
pub const P9_REQUEST_QUEUE: u32 = 0;
pub const P9_QUEUE_MAX: u32 = 128;
const P9_F_MOUNT_TAG: u64 = 1 << 0;
const FEATURE_RING_INDIRECT_DESC: u64 = 1 << 28;
const P9_MSIZE_MAX: u32 = 1 << 20;
/// Cap on live fids. A malicious guest can `Twalk` a fresh `newfid` indefinitely;
/// without a bound the fid table (and one host handle per opened fid) grows until
/// the host is out of memory. Real workloads use at most a few thousand.
const MAX_FIDS: usize = 1 << 16;
const P9_MSIZE_MIN: u32 = 4096;

// ---- 9P2000.L message types (Linux include/net/9p/9p.h) ------------------
const T_STATFS: u8 = 8;
const R_STATFS: u8 = 9;
const T_LOPEN: u8 = 12;
const R_LOPEN: u8 = 13;
const T_LCREATE: u8 = 14;
const R_LCREATE: u8 = 15;
const T_RENAME: u8 = 20;
const R_RENAME: u8 = 21;
const T_GETATTR: u8 = 24;
const R_GETATTR: u8 = 25;
const T_SETATTR: u8 = 26;
const R_SETATTR: u8 = 27;
const T_READDIR: u8 = 40;
const R_READDIR: u8 = 41;
const T_FSYNC: u8 = 50;
const R_FSYNC: u8 = 51;
const T_MKDIR: u8 = 72;
const R_MKDIR: u8 = 73;
const T_RENAMEAT: u8 = 74;
const R_RENAMEAT: u8 = 75;
const T_UNLINKAT: u8 = 76;
const R_UNLINKAT: u8 = 77;
const T_VERSION: u8 = 100;
const R_VERSION: u8 = 101;
const T_ATTACH: u8 = 104;
const R_ATTACH: u8 = 105;
const T_FLUSH: u8 = 108;
const R_FLUSH: u8 = 109;
const T_WALK: u8 = 110;
const R_WALK: u8 = 111;
const T_READ: u8 = 116;
const R_READ: u8 = 117;
const T_WRITE: u8 = 118;
const R_WRITE: u8 = 119;
const T_CLUNK: u8 = 120;
const R_CLUNK: u8 = 121;
const T_REMOVE: u8 = 122;
const R_REMOVE: u8 = 123;
const R_LERROR: u8 = 7;

// QID type bits.
const QT_DIR: u8 = 0x80;
const QT_FILE: u8 = 0x00;

const STATS_BASIC: u64 = 0x0000_07FF;
const NO_FID: u32 = 0xFFFF_FFFF;

// Linux errno values (do not use MSVC's <errno.h>).
const E_PERM: u32 = 1;
const E_NOENT: u32 = 2;
const E_IO: u32 = 5;
const E_BADF: u32 = 9;
const E_ACCES: u32 = 13;
const E_EXIST: u32 = 17;
const E_NOTDIR: u32 = 20;
const E_ISDIR: u32 = 21;
const E_INVAL: u32 = 22;
const E_MFILE: u32 = 24;
const E_NOSPC: u32 = 28;
const E_ROFS: u32 = 30;
const E_NAMETOOLONG: u32 = 36;
const E_NOSYS: u32 = 38;
const E_NOTEMPTY: u32 = 39;
const E_PROTO: u32 = 71;
const E_OPNOTSUPP: u32 = 95;

// 9P2000.L open flags (== Linux x86_64 <fcntl.h>).
const O_ACCMODE: u32 = 0x0003;
const O_RDONLY: u32 = 0x0000;
const O_WRONLY: u32 = 0x0001;
const O_RDWR: u32 = 0x0002;
const O_EXCL: u32 = 0x0080;
const O_TRUNC: u32 = 0x0200;
const O_APPEND: u32 = 0x0400;
const O_DIRECTORY: u32 = 0x10000;

// Tsetattr valid bits.
const SETATTR_MODE: u32 = 0x0000_0001;
const SETATTR_UID: u32 = 0x0000_0002;
const SETATTR_GID: u32 = 0x0000_0004;
const SETATTR_SIZE: u32 = 0x0000_0008;
const SETATTR_ATIME: u32 = 0x0000_0010;
const SETATTR_MTIME: u32 = 0x0000_0020;
const SETATTR_ATIME_SET: u32 = 0x0000_0080;
const SETATTR_MTIME_SET: u32 = 0x0000_0100;

// Tunlinkat flags.
const AT_REMOVEDIR: u32 = 0x200;

// Linux dirent d_type + mode bits.
const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const PERM_BITS: u32 = 0o7777;
// Tattach's n_uname when the client names no numeric user.
const NONUNAME: u32 = u32::MAX;

const V9FS_MAGIC: u32 = 0x0102_1997;
const FILETIME_BIAS_TO_1970: u64 = 116_444_736_000_000_000;
const REPLY_HEADER_SIZE: usize = 7;
const RREAD_HEADER_SIZE: usize = 11; // 7 hdr + 4 count
const MAX_WALK_NAMES: u16 = 16;

// ---- Win32 flag / error values (defined locally to avoid import churn) ----
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const DELETE: u32 = 0x0001_0000;
const FILE_LIST_DIRECTORY: u32 = 0x0001;
const FILE_APPEND_DATA: u32 = 0x0004;
const FILE_READ_EA: u32 = 0x0008;
const FILE_WRITE_EA: u32 = 0x0010;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
const FILE_SHARE_RWD: u32 = 0x0000_0007; // READ | WRITE | DELETE
const OPEN_EXISTING: u32 = 3;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PATH_NOT_FOUND: u32 = 3;
const ERROR_INVALID_DRIVE: u32 = 15;
const ERROR_NO_MORE_FILES: u32 = 18;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_SHARING_VIOLATION: u32 = 32;
const ERROR_LOCK_VIOLATION: u32 = 33;
const ERROR_FILE_EXISTS: u32 = 80;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_BROKEN_PIPE: u32 = 109;
const ERROR_DISK_FULL: u32 = 112;
const ERROR_INVALID_NAME: u32 = 123;
const ERROR_DIR_NOT_EMPTY: u32 = 145;
const ERROR_BAD_PATHNAME: u32 = 161;
const ERROR_ALREADY_EXISTS: u32 = 183;
const ERROR_FILENAME_EXCED_RANGE: u32 = 206;
const ERROR_DIRECTORY: u32 = 267;
/// A directory opened where a file was required (`winsys::fs` maps
/// `STATUS_FILE_IS_A_DIRECTORY` to it).
const ERROR_DIRECTORY_NOT_SUPPORTED: u32 = 336;
/// A file being deleted (`winsys::fs` maps `STATUS_DELETE_PENDING` to it), as
/// everything below a deleted share root is.
const ERROR_DELETE_PENDING: u32 = 303;
const ERROR_OPERATION_ABORTED: u32 = 995;
const ERROR_NOT_READY: u32 = 21;
const ERROR_WRITE_PROTECT: u32 = 19;
const ERROR_NOT_SUPPORTED: u32 = 50;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_TOO_MANY_OPEN_FILES: u32 = 4;
const ERROR_NEGATIVE_SEEK: u32 = 131;
const ERROR_EAS_NOT_SUPPORTED: u32 = 282;
/// A symlink, junction or mount point on a path opened without following
/// links (`winsys::fs::Open::follow`).
const ERROR_REPARSE_POINT_ENCOUNTERED: u32 = 4395;

pub type IrqFn = Box<dyn Fn(u32) + Send + Sync>;

/// Per-share policy from the `--virtio-9p-share` options.
#[derive(Clone, Copy, Debug, Default)]
pub struct ShareOptions {
    pub readonly: bool,
    /// Owner reported for entries without WSL metadata (see the module docs).
    pub uid: u32,
    pub gid: u32,
    /// Read and write WSL's `$LXUID`/`$LXGID`/`$LXMOD` metadata.
    pub metadata: bool,
}

// ============================================================
// Wire encoders
// ============================================================
fn enc1(o: &mut Vec<u8>, v: u8) {
    o.push(v);
}
fn enc2(o: &mut Vec<u8>, v: u16) {
    o.extend_from_slice(&v.to_le_bytes());
}
fn enc4(o: &mut Vec<u8>, v: u32) {
    o.extend_from_slice(&v.to_le_bytes());
}
fn enc8(o: &mut Vec<u8>, v: u64) {
    o.extend_from_slice(&v.to_le_bytes());
}
fn enc_str(o: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    let n = b.len().min(0xFFFF);
    enc2(o, n as u16);
    o.extend_from_slice(&b[..n]);
}
fn enc_qid(o: &mut Vec<u8>, qtype: u8, version: u32, path: u64) {
    enc1(o, qtype);
    enc4(o, version);
    enc8(o, path);
}

/// `qid.version` of a regular file: QEMU's `mtime ^ (size << 8)`, here over the
/// 100 ns FILETIME, and never 0. Linux treats version 0 as a synthetic file and
/// forces uncached I/O on it whatever the mount's cache mode, so a 0 here would
/// turn every read into one Tread per guest page. A host change to the file
/// changes the version, so the guest drops its cached inode on the next lookup.
/// Directories keep version 0: their contents never enter the page cache.
fn file_qid_version(info: &fs::FileInfo) -> u32 {
    let t = info.last_write_ticks;
    let v = (t ^ (t >> 32) ^ (info.size << 8) ^ (info.size >> 24)) as u32;
    v.max(1)
}

fn qid_version(info: &fs::FileInfo) -> u32 {
    if info.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        0
    } else {
        file_qid_version(info)
    }
}
fn finalize(o: &mut [u8]) {
    let sz = o.len() as u32;
    o[0..4].copy_from_slice(&sz.to_le_bytes());
}

/// Build an Rlerror(ecode) reply.
fn build_rlerror(reply: &mut Vec<u8>, tag: u16, ecode: u32) {
    reply.clear();
    enc4(reply, 0);
    enc1(reply, R_LERROR);
    enc2(reply, tag);
    enc4(reply, ecode);
    finalize(reply);
}

/// Build a header-only reply (Rclunk/Rremove/Rfsync/Rflush/Rrename/...).
fn build_header_only(reply: &mut Vec<u8>, reply_type: u8, tag: u16) {
    reply.clear();
    enc4(reply, 0);
    enc1(reply, reply_type);
    enc2(reply, tag);
    finalize(reply);
}

// ============================================================
// Wire decoder
// ============================================================
struct Dec<'a> {
    b: &'a [u8],
    off: usize,
}
impl<'a> Dec<'a> {
    fn new(b: &'a [u8]) -> Self {
        Dec { b, off: 0 }
    }
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.off)?;
        self.off += 1;
        Some(v)
    }
    fn u16(&mut self) -> Option<u16> {
        let s = self.b.get(self.off..self.off + 2)?;
        self.off += 2;
        Some(u16::from_le_bytes(s.try_into().unwrap()))
    }
    fn u32(&mut self) -> Option<u32> {
        let s = self.b.get(self.off..self.off + 4)?;
        self.off += 4;
        Some(u32::from_le_bytes(s.try_into().unwrap()))
    }
    fn u64(&mut self) -> Option<u64> {
        let s = self.b.get(self.off..self.off + 8)?;
        self.off += 8;
        Some(u64::from_le_bytes(s.try_into().unwrap()))
    }
    fn string(&mut self) -> Option<String> {
        let n = self.u16()? as usize;
        let s = self.b.get(self.off..self.off + n)?;
        self.off += n;
        String::from_utf8(s.to_vec()).ok()
    }
}

// ============================================================
// Path / Win32 helpers
// ============================================================
fn errno_from_win32(e: u32) -> u32 {
    match e {
        0 => 0,
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND | ERROR_INVALID_DRIVE | ERROR_NO_MORE_FILES => {
            E_NOENT
        }
        ERROR_ACCESS_DENIED
        | ERROR_SHARING_VIOLATION
        | ERROR_LOCK_VIOLATION
        | ERROR_DELETE_PENDING => E_ACCES,
        ERROR_FILE_EXISTS | ERROR_ALREADY_EXISTS => E_EXIST,
        ERROR_INVALID_NAME | ERROR_INVALID_PARAMETER | ERROR_BAD_PATHNAME | ERROR_NEGATIVE_SEEK => {
            E_INVAL
        }
        ERROR_FILENAME_EXCED_RANGE => E_NAMETOOLONG,
        ERROR_DIR_NOT_EMPTY => E_NOTEMPTY,
        ERROR_DISK_FULL => E_NOSPC,
        ERROR_INVALID_HANDLE => E_BADF,
        ERROR_TOO_MANY_OPEN_FILES => E_MFILE,
        ERROR_WRITE_PROTECT => E_ROFS,
        ERROR_NOT_SUPPORTED => E_NOSYS,
        ERROR_EAS_NOT_SUPPORTED => E_OPNOTSUPP,
        ERROR_DIRECTORY => E_NOTDIR,
        ERROR_DIRECTORY_NOT_SUPPORTED => E_ISDIR,
        ERROR_NOT_READY | ERROR_OPERATION_ABORTED | ERROR_BROKEN_PIPE => E_IO,
        _ => E_IO,
    }
}

fn filetime_to_unix(ticks: u64) -> (u64, u64) {
    let q = ticks;
    if q < FILETIME_BIAS_TO_1970 {
        return (0, 0);
    }
    let since = q - FILETIME_BIAS_TO_1970;
    (since / 10_000_000, (since % 10_000_000) * 100)
}

fn unix_to_filetime(sec: u64, nsec: u64) -> u64 {
    sec * 10_000_000 + nsec / 100 + FILETIME_BIAS_TO_1970
}

/// Prepend `\\?\` so Win32 lifts the MAX_PATH limit. Returns a NUL-terminated
/// wide string ready for the *W APIs. Most inputs are already canonical
/// (`\\?\C:\...`) so they pass through.
fn to_win32_long_path(p: &Path) -> Vec<u16> {
    let bs = b'\\' as u16;
    let mut w: Vec<u16> = p.as_os_str().encode_wide().collect();
    for c in w.iter_mut() {
        if *c == b'/' as u16 {
            *c = bs;
        }
    }
    let q = b'?' as u16;
    let dot = b'.' as u16;
    // Build the result in a single pre-sized allocation (prefix + body + NUL),
    // instead of materialising a second Vec and growing it.
    let mut result;
    if w.len() >= 4 && w[0] == bs && w[1] == bs && (w[2] == q || w[2] == dot) && w[3] == bs {
        // Already \\?\ or \\.\ — pass through.
        result = Vec::with_capacity(w.len() + 1);
        result.extend_from_slice(&w);
    } else if w.len() >= 2 && w[0] == bs && w[1] == bs {
        // \\server\share -> \\?\UNC\server\share (drop the leading "\\").
        let body = &w[2..];
        result = Vec::with_capacity(8 + body.len() + 1);
        result.extend("\\\\?\\UNC\\".encode_utf16());
        result.extend_from_slice(body);
    } else if w.len() >= 3
        && (w[0] as u8 as char).is_ascii_alphabetic()
        && w[1] == b':' as u16
        && w[2] == bs
    {
        // C:\... -> \\?\C:\...
        result = Vec::with_capacity(4 + w.len() + 1);
        result.extend("\\\\?\\".encode_utf16());
        result.extend_from_slice(&w);
    } else {
        result = Vec::with_capacity(w.len() + 1);
        result.extend_from_slice(&w);
    }
    result.push(0);
    result
}

/// Lexically normalise (lowercase + backslash + strip trailing) a real path from
/// `fs::final_nt_path_by_handle` for the containment prefix check.
fn normalize_for_containment(path: &[u16]) -> Vec<u16> {
    let mut w = path.to_vec();
    for c in w.iter_mut() {
        if *c == b'/' as u16 {
            *c = b'\\' as u16;
        }
        if *c >= b'A' as u16 && *c <= b'Z' as u16 {
            *c += 32;
        }
    }
    while w.len() > 3 && *w.last().unwrap() == b'\\' as u16 {
        w.pop();
    }
    w
}

/// Whether normalized path `p` is `root` or lies under it.
fn contained_in(p: &[u16], root: &[u16]) -> bool {
    p.starts_with(root) && (p.len() == root.len() || p[root.len()] == b'\\' as u16)
}

fn is_safe_name_component(comp: &str) -> bool {
    if comp.is_empty() || comp == "." || comp == ".." {
        return false;
    }
    if comp.len() > 255 {
        return false;
    }
    for c in comp.chars() {
        if (c as u32) < 0x20 {
            return false;
        }
        if matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
            return false;
        }
    }
    let last = comp.chars().last().unwrap();
    if last == '.' || last == ' ' {
        return false;
    }
    let stem = comp.split('.').next().unwrap_or(comp).to_ascii_uppercase();
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    !RESERVED.contains(&stem.as_str())
}

/// A fid's path below the share root as the name `fs::open_relative` takes:
/// its components joined by `\`, empty for the root itself.
fn rel_wide(rel: &Path) -> Vec<u16> {
    rel.as_os_str().encode_wide().collect()
}

/// The path below the share root that `path`, from a snapshot, names: `None`
/// unless it lies under `root` through components a walk could have produced.
fn rel_below(root: &Path, path: &Path) -> Option<PathBuf> {
    let rel = path.strip_prefix(root).ok()?;
    rel.components()
        .all(|c| {
            matches!(c, std::path::Component::Normal(n)
                if n.to_str().is_some_and(is_safe_name_component))
        })
        .then(|| rel.to_path_buf())
}

fn kind_of(is_dir: bool) -> fs::Kind {
    if is_dir {
        fs::Kind::Directory
    } else {
        fs::Kind::File
    }
}

/// The host access rights for a Tlopen with `flags`; `None` for an invalid
/// access mode. O_TRUNC is applied separately (see `P9Device::truncate`).
fn open_access(is_dir: bool, flags: u32) -> Option<u32> {
    if is_dir {
        return Some(FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES);
    }
    let append = flags & O_APPEND != 0;
    Some(match flags & O_ACCMODE {
        O_RDONLY => GENERIC_READ,
        O_WRONLY if append => FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES,
        O_WRONLY => GENERIC_WRITE,
        O_RDWR if append => GENERIC_READ | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES,
        O_RDWR => GENERIC_READ | GENERIC_WRITE,
        _ => return None,
    })
}

// ============================================================
// FidEntry
// ============================================================
#[derive(Default, Clone)]
struct DirEntryCached {
    qid_type: u8,
    qid_version: u32,
    qid_path: u64,
    d_type: u8,
    name: String,
}

/// Owns a host file HANDLE and closes it exactly once on drop. Stored as an
/// `Arc<OwnedHandle>` inside a `FidEntry` so a worker can clone the `Arc` under
/// the `fids` lock and then do its blocking I/O lock-free: a concurrent `Tclunk`
/// / `Tremove` / `Trename` drops the map's `Arc`, but the real `CloseHandle` is
/// deferred until the last in-flight user drops its clone. That closes the
/// use-after-close race without serialising the concurrent worker pool.
struct OwnedHandle(HANDLE);

// The only access is `get()` (a copy of the value, used while at least one `Arc`
// ref is held) and the one-shot close in `Drop`.
unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

impl OwnedHandle {
    fn get(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        fs::close(self.0);
    }
}

struct FidEntry {
    /// The file's path below the share root, empty for the root itself: made of
    /// validated components only, never `.` or `..`. Fids keep a path, not a
    /// handle, because Windows refuses to rename a directory while any handle
    /// to something under it is open.
    rel: PathBuf,
    is_dir: bool,
    qid_path: u64,
    /// The attaching user's uid (Tattach `n_uname`), recorded as the owner of
    /// files this fid creates on a `metadata` share.
    uid: u32,
    /// `None` = not open. Shared so in-flight I/O keeps the handle alive past a
    /// concurrent clunk/remove/rename (see [`OwnedHandle`]).
    handle: Option<Arc<OwnedHandle>>,
    opened: bool,
    open_flags: u32,
    dir_cache: Vec<DirEntryCached>,
    dir_cache_built: bool,
}

impl FidEntry {
    fn new(rel: PathBuf, is_dir: bool, qid_path: u64, uid: u32) -> FidEntry {
        FidEntry {
            rel,
            is_dir,
            qid_path,
            uid,
            handle: None,
            opened: false,
            open_flags: 0,
            dir_cache: Vec::new(),
            dir_cache_built: false,
        }
    }

    fn close_handle(&mut self) {
        // Drop our `Arc`; the real CloseHandle runs when the last in-flight user
        // (if any) releases its clone. The `Option<Arc<OwnedHandle>>` also frees
        // the handle automatically when a `FidEntry` is dropped, so there is no
        // manual `Drop for FidEntry`.
        self.handle = None;
        self.opened = false;
        self.dir_cache.clear();
        self.dir_cache_built = false;
    }
}

struct Fids {
    map: HashMap<u32, FidEntry>,
}

/// The pinned share root: its handle, and its real path (normalized, NT volume
/// name) when first pinned, the only place a deleted root is replaced from.
struct Root {
    handle: OwnedHandle,
    real: Vec<u16>,
}

// ============================================================
// P9Device
// ============================================================

const P9_MAX_WORKERS: usize = 8;
/// IOCP completion key that tells a worker to exit. Never a valid slot index
/// (those are 0..P9_QUEUE_MAX). Reserved for a clean-shutdown path; currently
/// unused because the workers live for the whole process.
const P9_STOP_KEY: usize = usize::MAX;

/// One in-flight request. Ownership is handed off LINEARLY:
///   free-list -> drain (fills t_msg/wbufs/head/cap) -> IOCP -> worker (fills
///   reply, writes guest RAM, pushes the used ring) -> free-list,
/// so no two threads ever touch the same slot at once; the IOCP post/get pair is
/// the synchronizing barrier. `t_msg`/`reply`/`bounce` are reused, so
/// steady-state request handling allocates nothing.
struct P9Slot {
    t_msg: Vec<u8>,
    reply: Vec<u8>,
    wbufs: Vec<ChainBuf>,
    /// Device-readable buffers of a Twrite whose payload was left in guest RAM
    /// (see `drain`); empty otherwise.
    rbufs: Vec<ChainBuf>,
    /// Total device-readable bytes of the request (capped at the max msize).
    msg_len: usize,
    /// Host bounce for Tread/Twrite payloads too scattered to move with one
    /// syscall per run. Grown on demand, never shrunk or re-zeroed.
    bounce: Vec<u8>,
    runs: Vec<(*mut u8, usize)>,
    head_index: u16,
    cap: u32,
}

impl P9Slot {
    fn new() -> Self {
        P9Slot {
            t_msg: Vec::new(),
            reply: Vec::new(),
            wbufs: Vec::new(),
            rbufs: Vec::new(),
            msg_len: 0,
            bounce: Vec::new(),
            runs: Vec::new(),
            head_index: 0,
            cap: 0,
        }
    }
}

/// Preallocated slot pool + free-list, sized to the max ring depth so an
/// acquire can never fail (the guest cannot have more requests in flight than
/// the ring holds).
struct SlotPool {
    slots: Vec<UnsafeCell<P9Slot>>,
    free: Mutex<Vec<u16>>,
    /// Slots currently acquired (requests between pop and used-ring push).
    in_use: AtomicU32,
}

// SAFETY: slots obey the linear-ownership discipline above, so the same slot is
// never touched by two threads at once; the free-list is Mutex-guarded. The raw
// guest-RAM pointers in `wbufs` stay valid from pop() to push() and point into
// GuestMemory, which lives for the whole process.
unsafe impl Send for SlotPool {}
unsafe impl Sync for SlotPool {}

impl SlotPool {
    fn new(n: usize) -> Self {
        let mut slots = Vec::with_capacity(n);
        for _ in 0..n {
            slots.push(UnsafeCell::new(P9Slot::new()));
        }
        SlotPool {
            slots,
            free: Mutex::new((0..n as u16).rev().collect()),
            in_use: AtomicU32::new(0),
        }
    }
    fn acquire(&self) -> Option<u16> {
        let i = self.free.lock().unwrap().pop()?;
        self.in_use.fetch_add(1, Ordering::Relaxed);
        Some(i)
    }
    fn release(&self, i: u16) {
        self.in_use.fetch_sub(1, Ordering::Relaxed);
        self.free.lock().unwrap().push(i);
    }
    /// SAFETY: the caller must currently own slot `i` per the handoff discipline.
    #[allow(clippy::mut_from_ref)]
    unsafe fn slot(&self, i: u16) -> &mut P9Slot {
        unsafe { &mut *self.slots[i as usize].get() }
    }
}

/// A precreated worker pool fed by an IOCP used purely as a thread-safe work
/// queue: no real overlapped I/O — workers run the existing blocking `dispatch`,
/// which yields K-way concurrency across requests. 9p tags every request, so
/// out-of-order completion is protocol-legal.
struct P9Engine {
    iocp: Iocp,
    pool: SlotPool,
}

/// One worker: block on the IOCP and run each posted request to completion.
fn p9_worker(dev: Arc<P9Device>) {
    let iocp = dev.engine.iocp;
    loop {
        let (ok, _bytes, key, _ov) = sock::get(iocp);
        if !ok || key == P9_STOP_KEY {
            break;
        }
        dev.complete_slot(key as u16);
    }
}

pub struct P9Device {
    queue: Mutex<Virtqueue>,
    tag: String,
    host_root: PathBuf,
    /// The share root, held open from first use (see [`Self::root`]); every host
    /// path is parsed relative to it. Replaced if the root is deleted.
    root: Mutex<Option<Arc<Root>>>,
    readonly: bool,
    // Owner reported for entries without metadata (see the module docs).
    uid: u32,
    gid: u32,
    metadata: bool,
    config_bytes: Vec<u8>,
    driver_ok: AtomicBool,
    acked_features: AtomicU64,
    negotiated_msize: AtomicU32,
    next_qid_path: AtomicU64,
    requests: AtomicU64,
    rlerrors: AtomicU64,
    // Data-path counters for the teardown `[9p]` line (relaxed increments).
    reads: AtomicU64,
    read_bytes: AtomicU64,
    writes: AtomicU64,
    write_bytes: AtomicU64,
    fids: Mutex<Fids>,
    irq: OnceLock<IrqFn>,
    engine: P9Engine,
    // Reused across drain calls so submit allocates nothing (see `drain`).
    drain_chain: Mutex<ChainScratch>,
}

impl P9Device {
    pub fn new(
        _mem: Arc<GuestMemory>,
        tag: String,
        host_root: PathBuf,
        opts: ShareOptions,
    ) -> Arc<Self> {
        let mut config_bytes = Vec::with_capacity(2 + tag.len());
        let n = tag.len().min(0xFFFF);
        config_bytes.extend_from_slice(&(n as u16).to_le_bytes());
        config_bytes.extend_from_slice(&tag.as_bytes()[..n]);
        let iocp = sock::create_iocp().expect("virtio-9p: CreateIoCompletionPort failed");
        let dev = Arc::new(P9Device {
            queue: Mutex::new(Virtqueue::new(_mem, P9_QUEUE_MAX)),
            tag,
            host_root,
            root: Mutex::new(None),
            readonly: opts.readonly,
            uid: opts.uid,
            gid: opts.gid,
            metadata: opts.metadata,
            config_bytes,
            driver_ok: AtomicBool::new(false),
            acked_features: AtomicU64::new(0),
            negotiated_msize: AtomicU32::new(0),
            next_qid_path: AtomicU64::new(1),
            requests: AtomicU64::new(0),
            rlerrors: AtomicU64::new(0),
            reads: AtomicU64::new(0),
            read_bytes: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            write_bytes: AtomicU64::new(0),
            fids: Mutex::new(Fids {
                map: HashMap::new(),
            }),
            irq: OnceLock::new(),
            engine: P9Engine {
                iocp,
                pool: SlotPool::new(P9_QUEUE_MAX as usize),
            },
            drain_chain: Mutex::new(ChainScratch::default()),
        });
        // Precreate the worker pool. Each worker holds a strong Arc<P9Device>
        // (the device never strong-refs the workers back, so there's no cycle);
        // they run for the process lifetime — no join, the OS reclaims at exit.
        let nworkers = thread::available_parallelism()
            .map(|n| n.get().clamp(2, P9_MAX_WORKERS))
            .unwrap_or(4);
        for w in 0..nworkers {
            let d = dev.clone();
            let _ = thread::Builder::new()
                .name(format!("p9-worker-{w}"))
                .spawn(move || p9_worker(d));
        }
        // Pin the share root now; if it can't be opened yet, every request tries
        // again until it can.
        if let Err(e) = dev.root() {
            eprintln!(
                "[9p] WARN: cannot open share root {} (Win32 error {e}); its requests fail until it can be",
                dev.host_root.display()
            );
        }
        dev
    }

    pub fn set_irq_callback(&self, f: IrqFn) {
        let _ = self.irq.set(f);
    }
    pub fn requests_handled(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }
    pub fn rlerrors_emitted(&self) -> u64 {
        self.rlerrors.load(Ordering::Relaxed)
    }

    /// One-line data-path summary for teardown. Average Tread/Twrite sizes show
    /// how the guest sized its requests (msize, cache mode, page pinning).
    pub fn diag_summary(&self, msix: u64) -> String {
        let r = self.reads.load(Ordering::Relaxed);
        let rb = self.read_bytes.load(Ordering::Relaxed);
        let w = self.writes.load(Ordering::Relaxed);
        let wb = self.write_bytes.load(Ordering::Relaxed);
        format!(
            "requests={} rlerrors={} msize={} reads={r} read_bytes={rb} (avg {}) \
             writes={w} write_bytes={wb} (avg {}) msix={msix}",
            self.requests_handled(),
            self.rlerrors_emitted(),
            self.negotiated_msize.load(Ordering::Relaxed),
            rb.checked_div(r).unwrap_or(0),
            wb.checked_div(w).unwrap_or(0),
        )
    }

    /// Wait for all in-flight 9p requests to drain (the slot pool becomes fully
    /// free) so a snapshot captures a consistent device — no reply landing in
    /// guest RAM / the used ring after the queue + device-state were captured.
    /// Bounded spin: the guest is already stopped, so no new requests arrive and
    /// the worker pool completes the in-flight ones promptly.
    pub fn quiesce(&self) {
        let total = self.engine.pool.slots.len();
        for _ in 0..5_000 {
            if self.engine.pool.free.lock().unwrap().len() >= total {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        eprintln!("[9p] WARN: quiesce timed out with requests still in flight");
    }

    fn raise(&self, qidx: u32) {
        if let Some(cb) = self.irq.get() {
            cb(qidx);
        }
    }

    fn alloc_qid_path(&self) -> u64 {
        self.next_qid_path.fetch_add(1, Ordering::Relaxed)
    }

    /// The share root's handle. It opens on first use (normally when the device
    /// is created) and then stays open, pinning the share: the root may be
    /// renamed or moved on the host and the share follows it, while Windows, as
    /// for any open folder, won't rename the folders containing it until the VM
    /// exits. If the root is deleted, [`Self::open_rel`] reattaches to the
    /// directory then at the share path. Attribute access only, sharing read,
    /// write and delete.
    fn root(&self) -> Result<Arc<Root>, u32> {
        if let Some(root) = self.root.lock().unwrap().as_ref() {
            return Ok(root.clone());
        }
        self.reopen_root(None)
    }

    /// Open the directory at the share path and pin it as the root, replacing
    /// `stale` (a root that was deleted) unless another request already has.
    /// A replacement must lie where the share first was: a link left in the
    /// deleted root's place doesn't move the share to wherever it points.
    fn reopen_root(&self, stale: Option<&Arc<Root>>) -> Result<Arc<Root>, u32> {
        let mut root = self.root.lock().unwrap();
        if let Some(cur) = root.as_ref()
            && !stale.is_some_and(|s| Arc::ptr_eq(s, cur))
        {
            return Ok(cur.clone());
        }
        let handle = OwnedHandle(fs::create_file(
            &to_win32_long_path(&self.host_root),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_RWD,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
        )?);
        if fs::file_info(handle.get())?.attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(ERROR_DIRECTORY);
        }
        let real = fs::final_nt_path_by_handle(handle.get())
            .map(|p| normalize_for_containment(&p))
            .ok_or(ERROR_ACCESS_DENIED)?;
        if root.as_ref().is_some_and(|old| old.real != real) {
            return Err(ERROR_ACCESS_DENIED);
        }
        let new = Arc::new(Root { handle, real });
        *root = Some(new.clone());
        Ok(new)
    }

    /// Whether the file `h` refers to lies inside the share: its real path,
    /// every link resolved, is the root's or below it. Both sides use the NT
    /// volume name (`\Device\HarddiskVolumeN\...`), which skips the drive-letter
    /// lookup, and the root's is read from its handle each time, so a root that
    /// moved is still recognized. Fails closed.
    fn handle_contained(&self, h: HANDLE) -> bool {
        let Ok(root) = self.root() else {
            return false;
        };
        match (
            fs::final_nt_path_by_handle(h),
            fs::final_nt_path_by_handle(root.handle.get()),
        ) {
            (Some(real), Some(root)) => contained_in(
                &normalize_for_containment(&real),
                &normalize_for_containment(&root),
            ),
            _ => false,
        }
    }

    /// Open `rel`, a path below the share root, without leaving the share. The
    /// whole path is parsed in one `NtCreateFile` relative to the root handle
    /// without following links (`OBJ_DONT_REPARSE`): the kernel refuses a
    /// symlink, junction or mount point on the way before the open has any
    /// effect, so what opens lies inside the share by construction, with no
    /// check afterwards to race. A path through a link takes
    /// [`Self::open_linked`]. Returns the handle and whether this call created
    /// the file.
    fn open_rel(&self, rel: &Path, how: fs::Open) -> Result<(OwnedHandle, bool), u32> {
        let root = self.root()?;
        let r = self.open_below(root.handle.get(), rel, how);
        // A root deleted on the host fails every open below it as delete
        // pending, though NTFS still reopens the root itself. Reattach to the
        // directory now at the share path, as when a build step deletes and
        // recreates its output folder, and try once more.
        let suspect = match &r {
            Ok(_) => rel.as_os_str().is_empty(),
            Err(e) => *e == ERROR_DELETE_PENDING,
        };
        if !(suspect && fs::is_deleted(root.handle.get())) {
            return r;
        }
        drop(r);
        let root = self.reopen_root(Some(&root))?;
        self.open_below(root.handle.get(), rel, how)
    }

    fn open_below(
        &self,
        root: HANDLE,
        rel: &Path,
        how: fs::Open,
    ) -> Result<(OwnedHandle, bool), u32> {
        match fs::open_relative(root, &rel_wide(rel), how) {
            Ok((h, created)) => Ok((OwnedHandle(h), created)),
            Err(ERROR_REPARSE_POINT_ENCOUNTERED) => self.open_linked(root, rel, how),
            Err(e) => Err(e),
        }
    }

    /// [`Self::open_rel`] of a path through a symlink or junction. Links are
    /// followed, as Windows would, but only to places inside the share: the
    /// parent directory opens following them and is checked against the root
    /// before anything happens in it, then the last component opens relative to
    /// that directory without following anything. If the last component is
    /// itself a link and `how` doesn't ask for the link itself, what it points
    /// at opens with attribute access only and is checked the same way before
    /// it gets `how.access`. So nothing outside the share is created, deleted,
    /// truncated or opened for data.
    fn open_linked(
        &self,
        root: HANDLE,
        rel: &Path,
        how: fs::Open,
    ) -> Result<(OwnedHandle, bool), u32> {
        // The root itself is not reached through a link.
        let (Some(parent), Some(name)) = (rel.parent(), rel.file_name()) else {
            return Err(ERROR_ACCESS_DENIED);
        };
        let dir = self.open_followed(root, &rel_wide(parent), fs::Kind::Directory)?;
        let name: Vec<u16> = name.encode_wide().collect();
        match fs::open_relative(dir.get(), &name, how) {
            Ok((h, created)) => Ok((OwnedHandle(h), created)),
            // The name exists, as a link: O_EXCL and mkdir must fail.
            Err(ERROR_REPARSE_POINT_ENCOUNTERED) if how.create == fs::Create::New => {
                Err(ERROR_ALREADY_EXISTS)
            }
            Err(ERROR_REPARSE_POINT_ENCOUNTERED) => {
                let target = self.open_followed(dir.get(), &name, how.kind)?;
                Ok((OwnedHandle(fs::reopen(target.get(), how.access)?), false))
            }
            Err(e) => Err(e),
        }
    }

    /// Open `name` below `dir` following links, with attribute access only, and
    /// keep it only if it lies inside the share.
    fn open_followed(&self, dir: HANDLE, name: &[u16], kind: fs::Kind) -> Result<OwnedHandle, u32> {
        let how = fs::Open::existing(0).with_kind(kind).following();
        let h = OwnedHandle(fs::open_relative(dir, name, how)?.0);
        if self.handle_contained(h.get()) {
            Ok(h)
        } else {
            Err(ERROR_ACCESS_DENIED)
        }
    }

    /// Open the file a fid names with `access`: through the fid's open handle
    /// when it has one, which reaches the same file even after a rename, else by
    /// the fid's path.
    fn open_fid_file(
        &self,
        rel: &Path,
        open: Option<&Arc<OwnedHandle>>,
        access: u32,
    ) -> Result<OwnedHandle, u32> {
        match open {
            Some(h) => fs::reopen(h.get(), access).map(OwnedHandle),
            None => self
                .open_rel(rel, fs::Open::existing(access))
                .map(|(h, _)| h),
        }
    }

    /// Open `rel` for Tgetattr: with FILE_READ_EA too on a `metadata` share, so
    /// [`Self::lx_metadata`] can read through the same handle.
    fn open_for_getattr(&self, rel: &Path) -> Result<OwnedHandle, u32> {
        if self.metadata
            && let Ok((h, _)) = self.open_rel(rel, fs::Open::existing(FILE_READ_EA))
        {
            return Ok(h);
        }
        self.open_rel(rel, fs::Open::existing(0)).map(|(h, _)| h)
    }

    /// Delete the entry at `rel`: a symlink or junction itself, never what it
    /// points at, as `DeleteFileW` and `RemoveDirectoryW` do.
    fn delete_entry(&self, rel: &Path, kind: fs::Kind) -> Result<(), u32> {
        let how = fs::Open::existing(DELETE).with_kind(kind).as_entry();
        let (h, _) = self.open_rel(rel, how)?;
        fs::delete_by_handle(h.get())
    }

    /// Rename the entry at `from` (a symlink or junction itself) to `name` in
    /// the directory `dir`, replacing a file of that name even if it is open.
    fn rename_entry(&self, from: &Path, dir: &Path, name: &str) -> Result<(), u32> {
        let (src, _) = self.open_rel(from, fs::Open::existing(DELETE).as_entry())?;
        let dir_how = fs::Open::existing(0).with_kind(fs::Kind::Directory);
        let (dst, _) = self.open_rel(dir, dir_how)?;
        let name: Vec<u16> = name.encode_utf16().collect();
        fs::rename_by_handle(src.get(), dst.get(), &name)
    }

    /// Truncate the file `h` (opened with `access`) to zero bytes for O_TRUNC.
    /// A truncating open would also drop the file's extended attributes, and
    /// with them a `metadata` share's owner and mode, which Linux keeps across
    /// O_TRUNC. A handle without write-data access (O_APPEND) truncates through
    /// a reopened one.
    fn truncate(h: HANDLE, access: u32) -> Result<(), u32> {
        if access & GENERIC_WRITE != 0 {
            return fs::set_end_of_file(h, 0);
        }
        let w = OwnedHandle(fs::reopen(h, GENERIC_WRITE)?);
        fs::set_end_of_file(w.get(), 0)
    }

    /// The WSL metadata of the file `h` refers to, read through a reopened
    /// handle if `h` lacks FILE_READ_EA. Empty unless the share has `metadata`,
    /// or when the file system keeps none.
    fn lx_metadata(&self, h: HANDLE) -> fs::LxMetadata {
        if !self.metadata {
            return fs::LxMetadata::default();
        }
        match fs::lx_metadata(h) {
            Ok(md) => md,
            Err(ERROR_ACCESS_DENIED) => fs::reopen(h, FILE_READ_EA)
                .map(OwnedHandle)
                .and_then(|h2| fs::lx_metadata(h2.get()))
                .unwrap_or_default(),
            Err(_) => fs::LxMetadata::default(),
        }
    }

    /// Store the `Some` fields of `md` as the WSL metadata of the file `h`
    /// refers to.
    fn set_lx_metadata(h: HANDLE, md: fs::LxMetadata) -> Result<(), u32> {
        let h = OwnedHandle(fs::reopen(h, FILE_WRITE_EA)?);
        fs::set_lx_metadata(h.get(), md)
    }

    /// Reopen a fid's host handle on restore from its saved (path, is_dir,
    /// open_flags): the existing file, never truncated (any truncation already
    /// happened before the snapshot), with the access `h_lopen` gives. `None` on
    /// failure: the fid is left unopened and the guest just re-errors on its
    /// next use of that fid.
    fn reopen_fid_handle(&self, rel: &Path, is_dir: bool, open_flags: u32) -> Option<OwnedHandle> {
        let access = open_access(is_dir, open_flags)?;
        let how = fs::Open::existing(access).with_kind(kind_of(is_dir));
        self.open_rel(rel, how).ok().map(|(h, _)| h)
    }

    /// qid type, version and path of a file.
    fn qid_of(&self, info: &fs::FileInfo) -> (u8, u32, u64) {
        let qt = if info.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            QT_DIR
        } else {
            QT_FILE
        };
        let qp = match info.file_index {
            0 => self.alloc_qid_path(),
            id => id,
        };
        (qt, qid_version(info), qp)
    }

    // Stat a path (no kept handle): fill qid type/version/path + is_dir.
    fn stat_rel(&self, rel: &Path) -> Result<(u8, u32, u64, bool), u32> {
        let (h, _) = self
            .open_rel(rel, fs::Open::existing(0))
            .map_err(errno_from_win32)?;
        let info = fs::file_info(h.get()).map_err(errno_from_win32)?;
        let (qt, qv, qp) = self.qid_of(&info);
        Ok((qt, qv, qp, qt == QT_DIR))
    }

    #[allow(clippy::type_complexity)]
    fn read_attrs_by_handle(
        &self,
        h: HANDLE,
    ) -> Result<
        (
            u8,  // qid_type
            u32, // qid_version
            u64, // qid_path
            u32, // mode
            u64, // nlink
            u64, // size
            u64, // blocks
            (u64, u64),
            (u64, u64),
            (u64, u64), // atime, mtime, ctime
        ),
        u32,
    > {
        let info = fs::file_info(h).map_err(errno_from_win32)?;
        let is_dir = info.attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        let qt = if is_dir { QT_DIR } else { QT_FILE };
        let mut qp = info.file_index;
        if qp == 0 {
            qp = self.alloc_qid_path();
        }
        let mode = if is_dir {
            S_IFDIR | 0o755
        } else {
            let ro = info.attributes & FILE_ATTRIBUTE_READONLY != 0;
            S_IFREG | if ro { 0o444 } else { 0o644 }
        };
        let nlink = if info.nlink != 0 {
            info.nlink as u64
        } else {
            1
        };
        let size = info.size;
        let blocks = size.div_ceil(512);
        Ok((
            qt,
            qid_version(&info),
            qp,
            mode,
            nlink,
            size,
            blocks,
            filetime_to_unix(info.last_access_ticks),
            filetime_to_unix(info.last_write_ticks),
            filetime_to_unix(info.creation_ticks),
        ))
    }

    // ---- drain (submit) + dispatch ----
    /// Pop every available request and run it. On the doorbell pump thread, a
    /// lone request (nothing else queued or in flight) runs right here: the
    /// guest is waiting on it alone, and waking a worker would add a thread
    /// hand-off to every round trip of a sequential workload. Everything else
    /// goes to the worker pool, so a slow request never stalls the pump while
    /// others wait. On the MMIO-fallback vCPU thread nothing runs inline.
    fn drain(&self) {
        let inline_ok = crate::virtio::transport::on_doorbell_pump();
        while let Some(idx) = self.submit_available(inline_ok) {
            self.complete_slot(idx);
        }
    }

    /// Pop available requests into slots and post them to the worker pool.
    /// Returns the slot of a lone request the caller should run itself.
    fn submit_available(&self, inline_ok: bool) -> Option<u16> {
        // Reuse one PoppedChain across the whole drain AND across drain calls so
        // submit never allocates: each popped chain is copied into the slot's
        // reused t_msg/wbufs before the next pop. Holding `drain_chain` (instead
        // of the queue lock) serialises the rare concurrent drain without
        // extending the contended queue-lock hold time.
        let mut chain = self.drain_chain.lock().unwrap();
        loop {
            let more = {
                let mut q = self.queue.lock().unwrap();
                if !q.ready() {
                    return None;
                }
                if !q.pop_into(&mut chain) {
                    return None;
                }
                q.has_avail()
            };
            let Some(idx) = self.engine.pool.acquire() else {
                // Pool exhausted (impossible when sized to ring depth): retire the
                // descriptor empty so the guest isn't wedged, then stop draining.
                let int = {
                    let mut q = self.queue.lock().unwrap();
                    q.push(chain.head_index, 0);
                    q.should_interrupt_driver()
                };
                if int {
                    self.raise(P9_REQUEST_QUEUE);
                }
                return None;
            };
            // SAFETY: we just acquired `idx` and own it until we post it. The
            // descriptors stay valid until the request is pushed to the used
            // ring, so keeping them now (and reading/writing through them later)
            // is sound.
            let slot = unsafe { self.engine.pool.slot(idx) };
            let readable: usize = chain.bufs.iter().filter(|b| !b.write).map(|b| b.len).sum();
            slot.msg_len = readable.min(P9_MSIZE_MAX as usize);
            slot.rbufs.clear();
            if peek_readable(&chain.bufs, 4) == Some(T_WRITE) && slot.msg_len > TWRITE_HEADER_SIZE {
                // Leave the payload in guest RAM; `write_from_chain` hands it to
                // the host file from there.
                read_chain(&chain.bufs, &mut slot.t_msg, TWRITE_HEADER_SIZE);
                slot.rbufs
                    .extend(chain.bufs.iter().filter(|b| !b.write).copied());
            } else {
                read_chain(&chain.bufs, &mut slot.t_msg, P9_MSIZE_MAX as usize);
            }
            slot.cap = writable_capacity(&chain.bufs);
            slot.head_index = chain.head_index;
            slot.wbufs.clear();
            slot.wbufs
                .extend(chain.bufs.iter().filter(|b| b.write).copied());
            if inline_ok && !more && self.engine.pool.in_use.load(Ordering::Relaxed) == 1 {
                return Some(idx);
            }
            if !sock::post(self.engine.iocp, 0, idx as usize, std::ptr::null_mut()) {
                // Posting failed: complete inline so the request isn't lost.
                self.complete_slot(idx);
            }
        }
    }

    /// Run one request to completion (on a worker, or inline on the pump):
    /// handle it straight into the guest's buffers, push the used ring, raise
    /// the IRQ, then recycle the slot.
    fn complete_slot(&self, idx: u16) {
        // SAFETY: this slot was handed to us via the IOCP (or kept by the
        // drain for inline execution); we own it until release.
        let slot = unsafe { self.engine.pool.slot(idx) };
        slot.reply.clear();
        let written = match slot.t_msg.get(4).copied() {
            Some(T_READ) if slot.t_msg.len() >= REPLY_HEADER_SIZE => self.read_into_chain(slot),
            Some(T_WRITE) if !slot.rbufs.is_empty() => self.write_from_chain(slot),
            _ => {
                self.dispatch(&slot.t_msg, &mut slot.reply, slot.cap);
                write_chain(&mut slot.wbufs, &slot.reply)
            }
        };
        let head = slot.head_index;
        let interrupt = {
            let mut q = self.queue.lock().unwrap();
            q.push(head, written);
            q.should_interrupt_driver()
        };
        self.engine.pool.release(idx);
        if interrupt {
            self.raise(P9_REQUEST_QUEUE);
        }
    }

    fn dispatch(&self, t_msg: &[u8], reply: &mut Vec<u8>, writable_cap: u32) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        if t_msg.len() < REPLY_HEADER_SIZE {
            build_rlerror(reply, 0, E_PROTO);
            self.rlerrors.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let mtype = t_msg[4];
        let tag = u16::from_le_bytes([t_msg[5], t_msg[6]]);
        let body = &t_msg[REPLY_HEADER_SIZE..];
        let cap = self.reply_cap(writable_cap);

        match mtype {
            T_VERSION => self.h_version(tag, body, reply),
            T_ATTACH => self.h_attach(tag, body, reply),
            T_WALK => self.h_walk(tag, body, reply),
            T_LOPEN => self.h_lopen(tag, body, reply),
            T_LCREATE => self.h_lcreate(tag, body, reply),
            T_READ => self.h_read(tag, body, reply, cap),
            T_WRITE => self.h_write(tag, body, reply),
            T_READDIR => self.h_readdir(tag, body, reply, cap),
            T_GETATTR => self.h_getattr(tag, body, reply),
            T_SETATTR => self.h_setattr(tag, body, reply),
            T_CLUNK => self.h_clunk(tag, body, reply),
            T_REMOVE => self.h_remove(tag, body, reply),
            T_FSYNC => self.h_fsync(tag, body, reply),
            T_FLUSH => build_header_only(reply, R_FLUSH, tag),
            T_MKDIR => self.h_mkdir(tag, body, reply),
            T_RENAME => self.h_rename(tag, body, reply),
            T_RENAMEAT => self.h_renameat(tag, body, reply),
            T_UNLINKAT => self.h_unlinkat(tag, body, reply),
            T_STATFS => self.h_statfs(tag, body, reply),
            _ => build_rlerror(reply, tag, E_NOSYS),
        }
        if reply.len() >= 5 && reply[4] == R_LERROR {
            self.rlerrors.fetch_add(1, Ordering::Relaxed);
        }
    }

    // ---- handlers ----
    /// Bound a reply by the negotiated msize, or — before T_version — by the
    /// protocol ceiling, so a pre-negotiation Tread/Treaddir with a multi-GB
    /// writable descriptor can't drive a giant buffer (alloc failure → VMM
    /// abort).
    fn reply_cap(&self, writable_cap: u32) -> u32 {
        let neg = self.negotiated_msize.load(Ordering::Relaxed);
        let cap = writable_cap.min(P9_MSIZE_MAX);
        if neg != 0 { cap.min(neg) } else { cap }
    }

    fn h_version(&self, tag: u16, body: &[u8], reply: &mut Vec<u8>) {
        let mut d = Dec::new(body);
        let (Some(msize_req), Some(version)) = (d.u32(), d.string()) else {
            build_rlerror(reply, tag, E_PROTO);
            return;
        };
        self.fids.lock().unwrap().map.clear();
        let agreed = msize_req.clamp(P9_MSIZE_MIN, P9_MSIZE_MAX);
        self.negotiated_msize.store(agreed, Ordering::Relaxed);
        let resp = if version == "9P2000.L" {
            "9P2000.L"
        } else {
            "unknown"
        };
        reply.clear();
        enc4(reply, 0);
        enc1(reply, R_VERSION);
        enc2(reply, tag);
        enc4(reply, agreed);
        enc_str(reply, resp);
        finalize(reply);
    }

    fn h_attach(&self, tag: u16, body: &[u8], reply: &mut Vec<u8>) {
        let mut d = Dec::new(body);
        let (Some(fid), Some(afid), Some(_uname), Some(aname), Some(n_uname)) =
            (d.u32(), d.u32(), d.string(), d.string(), d.u32())
        else {
            build_rlerror(reply, tag, E_PROTO);
            return;
        };
        if afid != NO_FID {
            build_rlerror(reply, tag, E_INVAL);
            return;
        }
        if !aname.is_empty() && aname != "/" && aname != self.tag {
            build_rlerror(reply, tag, E_NOENT);
            return;
        }
        let (qt, qv, qp, is_dir) = match self.stat_rel(Path::new("")) {
            Ok(v) => v,
            Err(e) => {
                build_rlerror(reply, tag, e);
                return;
            }
        };
        if !is_dir {
            build_rlerror(reply, tag, E_NOTDIR);
            return;
        }
        {
            let mut f = self.fids.lock().unwrap();
            if !f.map.contains_key(&fid) && f.map.len() >= MAX_FIDS {
                drop(f);
                build_rlerror(reply, tag, E_MFILE);
                return;
            }
            let uid = if n_uname == NONUNAME {
                self.uid
            } else {
                n_uname
            };
            f.map
                .insert(fid, FidEntry::new(PathBuf::new(), true, qp, uid));
        }
        reply.clear();
        enc4(reply, 0);
        enc1(reply, R_ATTACH);
        enc2(reply, tag);
        enc_qid(reply, qt, qv, qp);
        finalize(reply);
    }

    fn h_walk(&self, tag: u16, body: &[u8], reply: &mut Vec<u8>) {
        let mut d = Dec::new(body);
        let (Some(fid), Some(newfid), Some(nwname)) = (d.u32(), d.u32(), d.u16()) else {
            build_rlerror(reply, tag, E_PROTO);
            return;
        };
        if nwname > MAX_WALK_NAMES {
            build_rlerror(reply, tag, E_INVAL);
            return;
        }
        let mut wnames: Vec<String> = Vec::with_capacity(nwname as usize);
        for _ in 0..nwname {
            match d.string() {
                Some(s) => wnames.push(s),
                None => {
                    build_rlerror(reply, tag, E_PROTO);
                    return;
                }
            }
        }

        let (src_rel, src_is_dir, src_qid_path, src_uid);
        {
            let f = self.fids.lock().unwrap();
            let Some(src) = f.map.get(&fid) else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            if src.opened {
                build_rlerror(reply, tag, E_INVAL);
                return;
            }
            src_rel = src.rel.clone();
            src_is_dir = src.is_dir;
            src_qid_path = src.qid_path;
            src_uid = src.uid;
            if newfid != fid && f.map.contains_key(&newfid) {
                build_rlerror(reply, tag, E_INVAL);
                return;
            }
            // A new fid grows the table; cap it. The actual insert runs under a
            // later, fresh lock, so this can overshoot only by the worker count.
            if newfid != fid && f.map.len() >= MAX_FIDS {
                build_rlerror(reply, tag, E_MFILE);
                return;
            }
        }

        if nwname == 0 {
            self.fids.lock().unwrap().map.insert(
                newfid,
                FidEntry::new(src_rel, src_is_dir, src_qid_path, src_uid),
            );
            reply.clear();
            enc4(reply, 0);
            enc1(reply, R_WALK);
            enc2(reply, tag);
            enc2(reply, 0);
            finalize(reply);
            return;
        }

        if !src_is_dir {
            build_rlerror(reply, tag, E_NOTDIR);
            return;
        }

        let mut rel = src_rel;
        let mut qids: Vec<(u8, u32, u64)> = Vec::with_capacity(nwname as usize);
        for (i, name) in wnames.iter().enumerate() {
            // "." stays put; ".." goes up a level but never above the share root.
            let next = match name.as_str() {
                "." => rel.clone(),
                ".." => rel.parent().map_or_else(PathBuf::new, Path::to_path_buf),
                _ if is_safe_name_component(name) => rel.join(name),
                _ => {
                    if i == 0 {
                        build_rlerror(reply, tag, E_NOENT);
                        return;
                    }
                    break;
                }
            };
            let (qt, qv, qp, isd) = match self.stat_rel(&next) {
                Ok(v) => v,
                Err(e) => {
                    if i == 0 {
                        build_rlerror(reply, tag, e);
                        return;
                    }
                    break;
                }
            };
            if !isd && i + 1 < nwname as usize {
                if i == 0 {
                    build_rlerror(reply, tag, E_NOTDIR);
                    return;
                }
                break;
            }
            qids.push((qt, qv, qp));
            rel = next;
        }

        if qids.len() == nwname as usize {
            let (qt, _, qp) = *qids.last().unwrap();
            self.fids
                .lock()
                .unwrap()
                .map
                .insert(newfid, FidEntry::new(rel, qt & QT_DIR != 0, qp, src_uid));
        }

        reply.clear();
        enc4(reply, 0);
        enc1(reply, R_WALK);
        enc2(reply, tag);
        enc2(reply, qids.len() as u16);
        for (qt, qv, qp) in &qids {
            enc_qid(reply, *qt, *qv, *qp);
        }
        finalize(reply);
    }

    fn h_lopen(&self, tag: u16, body: &[u8], reply: &mut Vec<u8>) {
        let mut d = Dec::new(body);
        let (Some(fid), Some(flags)) = (d.u32(), d.u32()) else {
            build_rlerror(reply, tag, E_PROTO);
            return;
        };
        let (rel, is_dir, qid_path, already_open);
        {
            let f = self.fids.lock().unwrap();
            let Some(e) = f.map.get(&fid) else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            rel = e.rel.clone();
            is_dir = e.is_dir;
            qid_path = e.qid_path;
            already_open = e.opened;
        }
        if already_open {
            build_rlerror(reply, tag, E_INVAL);
            return;
        }
        let want_write = flags & O_ACCMODE != O_RDONLY;
        let want_trunc = flags & O_TRUNC != 0;
        let want_dir = flags & O_DIRECTORY != 0;
        if want_dir && !is_dir {
            build_rlerror(reply, tag, E_NOTDIR);
            return;
        }
        if self.readonly && (want_write || want_trunc) {
            build_rlerror(reply, tag, E_ROFS);
            return;
        }
        let Some(access) = open_access(is_dir, flags) else {
            build_rlerror(reply, tag, E_INVAL);
            return;
        };
        let how = fs::Open::existing(access).with_kind(kind_of(is_dir));
        let h = match self.open_rel(&rel, how) {
            Ok((h, _)) => h,
            Err(e) => {
                build_rlerror(reply, tag, errno_from_win32(e));
                return;
            }
        };
        if want_trunc
            && !is_dir
            && let Err(e) = Self::truncate(h.get(), access)
        {
            build_rlerror(reply, tag, errno_from_win32(e));
            return;
        }
        // Version from the opened (possibly just truncated) file; see
        // `file_qid_version` for why it must not be 0.
        let qv = if is_dir {
            0
        } else {
            fs::file_info(h.get()).map_or(1, |i| file_qid_version(&i))
        };
        {
            let mut f = self.fids.lock().unwrap();
            let Some(e) = f.map.get_mut(&fid) else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            if e.opened {
                build_rlerror(reply, tag, E_INVAL);
                return;
            }
            e.handle = Some(Arc::new(h));
            e.opened = true;
            e.open_flags = flags;
        }
        let qt = if is_dir { QT_DIR } else { QT_FILE };
        reply.clear();
        enc4(reply, 0);
        enc1(reply, R_LOPEN);
        enc2(reply, tag);
        enc_qid(reply, qt, qv, qid_path);
        enc4(reply, 0); // iounit
        finalize(reply);
    }

    fn h_lcreate(&self, tag: u16, body: &[u8], reply: &mut Vec<u8>) {
        let mut d = Dec::new(body);
        let (Some(fid), Some(name), Some(flags), Some(mode), Some(gid)) =
            (d.u32(), d.string(), d.u32(), d.u32(), d.u32())
        else {
            build_rlerror(reply, tag, E_PROTO);
            return;
        };
        if self.readonly {
            build_rlerror(reply, tag, E_ROFS);
            return;
        }
        if !is_safe_name_component(&name) {
            build_rlerror(reply, tag, E_INVAL);
            return;
        }
        let (parent_rel, creator);
        {
            let f = self.fids.lock().unwrap();
            let Some(e) = f.map.get(&fid) else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            if !e.is_dir {
                build_rlerror(reply, tag, E_NOTDIR);
                return;
            }
            if e.opened {
                build_rlerror(reply, tag, E_INVAL);
                return;
            }
            parent_rel = e.rel.clone();
            creator = e.uid;
        }
        let rel = parent_rel.join(&name);
        let acc = flags & O_ACCMODE;
        let want_append = flags & O_APPEND != 0;
        let mut access = GENERIC_WRITE | FILE_READ_ATTRIBUTES;
        if acc == O_RDWR || acc == O_RDONLY {
            access |= GENERIC_READ;
        }
        if want_append {
            access = (access & !GENERIC_WRITE) | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES;
        }
        let create = if flags & O_EXCL != 0 {
            fs::Create::New
        } else {
            fs::Create::OpenOrNew
        };
        let how = fs::Open::existing(access)
            .with_create(create)
            .with_kind(fs::Kind::File);
        let (h, created) = match self.open_rel(&rel, how) {
            Ok(v) => v,
            Err(e) => {
                build_rlerror(reply, tag, errno_from_win32(e));
                return;
            }
        };
        if flags & O_TRUNC != 0
            && !created
            && let Err(e) = Self::truncate(h.get(), access)
        {
            build_rlerror(reply, tag, errno_from_win32(e));
            return;
        }
        if self.metadata && created {
            // Best effort, like the create itself on a file system without
            // extended attributes: the file just stays without metadata.
            let _ = Self::set_lx_metadata(
                h.get(),
                fs::LxMetadata {
                    uid: Some(creator),
                    gid: Some(gid),
                    mode: Some(S_IFREG | (mode & PERM_BITS)),
                },
            );
        }
        let (_, qv, qp) = match fs::file_info(h.get()) {
            Ok(info) => self.qid_of(&info),
            Err(e) => {
                build_rlerror(reply, tag, errno_from_win32(e));
                return;
            }
        };
        {
            let mut f = self.fids.lock().unwrap();
            let Some(e) = f.map.get_mut(&fid) else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            e.rel = rel;
            e.is_dir = false;
            e.qid_path = qp;
            e.handle = Some(Arc::new(h));
            e.opened = true;
            e.open_flags = flags;
        }
        reply.clear();
        enc4(reply, 0);
        enc1(reply, R_LCREATE);
        enc2(reply, tag);
        enc_qid(reply, QT_FILE, qv, qp);
        enc4(reply, 0); // iounit
        finalize(reply);
    }

    /// The open, non-directory handle of `fid`, for Tread. The Arc keeps the
    /// handle alive through the I/O even if a concurrent Tclunk drops the fid.
    fn readable_handle(&self, fid: u32) -> Result<Arc<OwnedHandle>, u32> {
        let f = self.fids.lock().unwrap();
        let e = f.map.get(&fid).ok_or(E_BADF)?;
        let h = e.handle.clone().filter(|_| e.opened).ok_or(E_BADF)?;
        if e.is_dir {
            return Err(E_ISDIR);
        }
        Ok(h)
    }

    /// As [`Self::readable_handle`], for Twrite: also the fid's open flags.
    fn writable_handle(&self, fid: u32) -> Result<(Arc<OwnedHandle>, u32), u32> {
        if self.readonly {
            return Err(E_ROFS);
        }
        let f = self.fids.lock().unwrap();
        let e = f.map.get(&fid).ok_or(E_BADF)?;
        let h = e.handle.clone().filter(|_| e.opened).ok_or(E_BADF)?;
        if e.is_dir {
            return Err(E_ISDIR);
        }
        Ok((h, e.open_flags))
    }

    /// Reply Rlerror(ecode) to a request handled by the direct paths.
    fn fail_slot(&self, slot: &mut P9Slot, tag: u16, ecode: u32) -> u32 {
        self.rlerrors.fetch_add(1, Ordering::Relaxed);
        build_rlerror(&mut slot.reply, tag, ecode);
        write_chain(&mut slot.wbufs, &slot.reply)
    }

    /// Tread from the virtqueue: the data goes from the host file straight into
    /// the guest's buffers — one ReadFile per contiguous run, or one into the
    /// slot's bounce buffer plus a scatter when the runs are small — never
    /// through a zero-filled reply. Returns the bytes written to the chain.
    fn read_into_chain(&self, slot: &mut P9Slot) -> u32 {
        self.requests.fetch_add(1, Ordering::Relaxed);
        let tag = u16::from_le_bytes([slot.t_msg[5], slot.t_msg[6]]);
        let mut d = Dec::new(&slot.t_msg[REPLY_HEADER_SIZE..]);
        let (Some(fid), Some(offset), Some(count)) = (d.u32(), d.u64(), d.u32()) else {
            return self.fail_slot(slot, tag, E_PROTO);
        };
        let h = match self.readable_handle(fid) {
            Ok(h) => h,
            Err(e) => return self.fail_slot(slot, tag, e),
        };
        let cap = self.reply_cap(slot.cap) as usize;
        let count = (count as usize).min(cap.saturating_sub(RREAD_HEADER_SIZE));
        let len = chain_runs(&slot.wbufs, RREAD_HEADER_SIZE, count, &mut slot.runs);
        let got = if runs_direct(&slot.runs, len) {
            let mut got = 0usize;
            for &(p, n) in &slot.runs {
                // SAFETY: each run lies in a host_range-validated, device-writable
                // guest buffer that stays valid until the used-ring push. The OS
                // writes it directly; it is never borrowed as a slice.
                match unsafe { fs::read_at_raw(h.get(), p, n as u32, offset + got as u64) } {
                    Ok(k) => {
                        got += k as usize;
                        if (k as usize) < n {
                            break;
                        }
                    }
                    Err(e) if got == 0 => return self.fail_slot(slot, tag, errno_from_win32(e)),
                    Err(_) => break,
                }
            }
            got
        } else {
            if slot.bounce.len() < len {
                slot.bounce.resize(len, 0);
            }
            match fs::read_at(h.get(), &mut slot.bounce[..len], offset) {
                // SAFETY: as above; the runs cover `len` >= `k` bytes.
                Ok(k) => unsafe {
                    scatter(&slot.runs, &slot.bounce[..k as usize]);
                    k as usize
                },
                Err(e) => return self.fail_slot(slot, tag, errno_from_win32(e)),
            }
        };
        let mut hdr = [0u8; RREAD_HEADER_SIZE];
        hdr[0..4].copy_from_slice(&((RREAD_HEADER_SIZE + got) as u32).to_le_bytes());
        hdr[4] = R_READ;
        hdr[5..7].copy_from_slice(&tag.to_le_bytes());
        hdr[7..11].copy_from_slice(&(got as u32).to_le_bytes());
        write_chain(&mut slot.wbufs, &hdr);
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.read_bytes.fetch_add(got as u64, Ordering::Relaxed);
        (RREAD_HEADER_SIZE + got) as u32
    }

    /// Twrite from the virtqueue whose payload `drain` left in guest RAM
    /// (`slot.rbufs`): written to the host file from there, by run or through
    /// the bounce buffer, as in [`Self::read_into_chain`]. An append is always
    /// one WriteFile so concurrent appenders can't interleave its pieces.
    fn write_from_chain(&self, slot: &mut P9Slot) -> u32 {
        self.requests.fetch_add(1, Ordering::Relaxed);
        let tag = u16::from_le_bytes([slot.t_msg[5], slot.t_msg[6]]);
        let mut d = Dec::new(&slot.t_msg[REPLY_HEADER_SIZE..]);
        let (Some(fid), Some(offset), Some(count)) = (d.u32(), d.u64(), d.u32()) else {
            return self.fail_slot(slot, tag, E_PROTO);
        };
        let count = count as usize;
        if TWRITE_HEADER_SIZE + count > slot.msg_len {
            return self.fail_slot(slot, tag, E_PROTO);
        }
        let (h, open_flags) = match self.writable_handle(fid) {
            Ok(v) => v,
            Err(e) => return self.fail_slot(slot, tag, e),
        };
        let append = open_flags & O_APPEND != 0;
        let len = chain_runs(&slot.rbufs, TWRITE_HEADER_SIZE, count, &mut slot.runs);
        let res = if len == 0 {
            Ok(0)
        } else if slot.runs.len() == 1 || (!append && runs_direct(&slot.runs, len)) {
            let mut done = 0usize;
            let mut res = Ok(());
            for &(p, n) in &slot.runs {
                // SAFETY: each run lies in a host_range-validated, device-readable
                // guest buffer that stays valid until the used-ring push.
                match unsafe { write_raw(h.get(), append, p, n, offset + done as u64) } {
                    Ok(k) => {
                        done += k as usize;
                        if (k as usize) < n {
                            break;
                        }
                    }
                    Err(e) => {
                        if done == 0 {
                            res = Err(e);
                        }
                        break;
                    }
                }
            }
            res.map(|()| done)
        } else {
            if slot.bounce.len() < len {
                slot.bounce.resize(len, 0);
            }
            // SAFETY: as above; the runs cover exactly `len` bytes.
            unsafe { gather(&slot.runs, &mut slot.bounce[..len]) };
            if append {
                fs::write_append(h.get(), &slot.bounce[..len])
            } else {
                fs::write_at(h.get(), &slot.bounce[..len], offset)
            }
            .map(|k| k as usize)
        };
        let wrote = match res {
            Ok(n) => n as u32,
            Err(e) => return self.fail_slot(slot, tag, errno_from_win32(e)),
        };
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.write_bytes.fetch_add(wrote as u64, Ordering::Relaxed);
        let mut rep = [0u8; REPLY_HEADER_SIZE + 4];
        rep[0..4].copy_from_slice(&((REPLY_HEADER_SIZE + 4) as u32).to_le_bytes());
        rep[4] = R_WRITE;
        rep[5..7].copy_from_slice(&tag.to_le_bytes());
        rep[7..11].copy_from_slice(&wrote.to_le_bytes());
        write_chain(&mut slot.wbufs, &rep)
    }

    fn h_read(&self, tag: u16, body: &[u8], reply: &mut Vec<u8>, cap: u32) {
        let mut d = Dec::new(body);
        let (Some(fid), Some(offset), Some(mut count)) = (d.u32(), d.u64(), d.u32()) else {
            build_rlerror(reply, tag, E_PROTO);
            return;
        };
        let h = match self.readable_handle(fid) {
            Ok(h) => h,
            Err(e) => {
                build_rlerror(reply, tag, e);
                return;
            }
        };
        let max_payload = if cap as usize > RREAD_HEADER_SIZE {
            cap - RREAD_HEADER_SIZE as u32
        } else {
            0
        };
        if count > max_payload {
            count = max_payload;
        }
        // Read straight into the reply buffer after the 11-byte Rread header
        // (no per-read `data` allocation); `reply` is the reused scratch buffer.
        reply.clear();
        enc4(reply, 0);
        enc1(reply, R_READ);
        enc2(reply, tag);
        enc4(reply, 0); // count placeholder, patched after the read
        let mut got: u32 = 0;
        if count > 0 {
            let base = reply.len();
            reply.resize(base + count as usize, 0);
            match fs::read_at(h.get(), &mut reply[base..], offset) {
                Ok(n) => got = n,
                Err(e) => {
                    build_rlerror(reply, tag, errno_from_win32(e));
                    return;
                }
            }
            reply.truncate(base + got as usize);
        }
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.read_bytes.fetch_add(got as u64, Ordering::Relaxed);
        reply[7..11].copy_from_slice(&got.to_le_bytes());
        finalize(reply);
    }

    fn h_write(&self, tag: u16, body: &[u8], reply: &mut Vec<u8>) {
        let mut d = Dec::new(body);
        let (Some(fid), Some(offset), Some(count)) = (d.u32(), d.u64(), d.u32()) else {
            build_rlerror(reply, tag, E_PROTO);
            return;
        };
        let data_off = d.off;
        if data_off + count as usize > body.len() {
            build_rlerror(reply, tag, E_PROTO);
            return;
        }
        let (h, open_flags) = match self.writable_handle(fid) {
            Ok(v) => v,
            Err(e) => {
                build_rlerror(reply, tag, e);
                return;
            }
        };
        let mut wrote: u32 = 0;
        if count > 0 {
            let buf = &body[data_off..data_off + count as usize];
            let res = if open_flags & O_APPEND != 0 {
                fs::write_append(h.get(), buf)
            } else {
                fs::write_at(h.get(), buf, offset)
            };
            match res {
                Ok(n) => wrote = n,
                Err(e) => {
                    build_rlerror(reply, tag, errno_from_win32(e));
                    return;
                }
            }
        }
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.write_bytes.fetch_add(wrote as u64, Ordering::Relaxed);
        reply.clear();
        enc4(reply, 0);
        enc1(reply, R_WRITE);
        enc2(reply, tag);
        enc4(reply, wrote);
        finalize(reply);
    }

    fn h_readdir(&self, tag: u16, body: &[u8], reply: &mut Vec<u8>, cap: u32) {
        let mut d = Dec::new(body);
        let (Some(fid), Some(req_offset), Some(mut count)) = (d.u32(), d.u64(), d.u32()) else {
            build_rlerror(reply, tag, E_PROTO);
            return;
        };
        let (is_dir, opened, has_handle);
        {
            let f = self.fids.lock().unwrap();
            let Some(e) = f.map.get(&fid) else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            is_dir = e.is_dir;
            opened = e.opened;
            has_handle = e.handle.is_some();
        }
        if !is_dir {
            build_rlerror(reply, tag, E_NOTDIR);
            return;
        }
        if !opened || !has_handle {
            build_rlerror(reply, tag, E_BADF);
            return;
        }
        let max_payload = if cap as usize > RREAD_HEADER_SIZE {
            cap - RREAD_HEADER_SIZE as u32
        } else {
            0
        };
        if count > max_payload {
            count = max_payload;
        }

        if req_offset == 0 {
            // Clone the fid's already-open directory handle and enumerate by
            // HANDLE — no per-entry open.
            let dir_h = {
                let f = self.fids.lock().unwrap();
                f.map.get(&fid).and_then(|e| e.handle.clone())
            };
            let Some(dir_h) = dir_h else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            let cache = self.build_dir_cache(dir_h.get());
            let mut f = self.fids.lock().unwrap();
            if let Some(e) = f.map.get_mut(&fid) {
                e.dir_cache = cache;
                e.dir_cache_built = true;
            }
        }

        // Encode the requested chunk directly from the cached entries under the
        // fids lock — no per-call clone of the whole directory (that made a
        // multi-chunk readdir O(N^2) in the entry count). The encode loop is pure
        // CPU bounded by `count` (<= msize), so the lock hold is short and in fact
        // shorter than the previous O(N) clone.
        let f = self.fids.lock().unwrap();
        let Some(e) = f.map.get(&fid) else {
            build_rlerror(reply, tag, E_BADF);
            return;
        };
        let cache = &e.dir_cache;

        reply.clear();
        enc4(reply, 0);
        enc1(reply, R_READDIR);
        enc2(reply, tag);
        let count_off = reply.len();
        enc4(reply, 0);
        let start_payload = reply.len();

        let start_index = (req_offset as usize).min(cache.len());
        for (i, de) in cache.iter().enumerate().skip(start_index) {
            let need = 13 + 8 + 1 + 2 + de.name.len();
            if (reply.len() - start_payload) + need > count as usize {
                break;
            }
            enc_qid(reply, de.qid_type, de.qid_version, de.qid_path);
            enc8(reply, (i + 1) as u64);
            enc1(reply, de.d_type);
            enc_str(reply, &de.name);
        }
        drop(f);
        let payload_len = (reply.len() - start_payload) as u32;
        reply[count_off..count_off + 4].copy_from_slice(&payload_len.to_le_bytes());
        finalize(reply);
    }

    /// Build the readdir cache by enumerating the fid's open directory HANDLE
    /// with `FileIdBothDirectoryInfo`. Each entry comes back with its 64-bit
    /// file-ID, so there is **no per-entry open / GetFileInformation / Close**
    /// — one buffer-full per ~500 entries instead of ~4 syscalls per entry.
    /// (Profiled on a 5 000-entry dir: ~20 K host syscalls/readdir → ~10.)
    fn build_dir_cache(&self, dir_h: HANDLE) -> Vec<DirEntryCached> {
        let mut cache: Vec<DirEntryCached> = Vec::new();
        let mut saw_dot = false;
        let mut saw_dotdot = false;
        for e in fs::read_dir_ids(dir_h) {
            if e.name.is_empty() {
                continue;
            }
            saw_dot |= e.name == ".";
            saw_dotdot |= e.name == "..";
            let qp = if e.file_id != 0 {
                e.file_id
            } else {
                self.alloc_qid_path()
            };
            cache.push(DirEntryCached {
                qid_type: if e.is_dir { QT_DIR } else { QT_FILE },
                qid_version: 0,
                qid_path: qp,
                d_type: if e.is_dir { DT_DIR } else { DT_REG },
                name: e.name,
            });
        }
        if !saw_dot {
            cache.insert(
                0,
                DirEntryCached {
                    qid_type: QT_DIR,
                    qid_version: 0,
                    qid_path: self.alloc_qid_path(),
                    d_type: DT_DIR,
                    name: ".".into(),
                },
            );
        }
        if !saw_dotdot {
            cache.insert(
                1.min(cache.len()),
                DirEntryCached {
                    qid_type: QT_DIR,
                    qid_version: 0,
                    qid_path: self.alloc_qid_path(),
                    d_type: DT_DIR,
                    name: "..".into(),
                },
            );
        }
        cache
    }

    fn h_getattr(&self, tag: u16, body: &[u8], reply: &mut Vec<u8>) {
        let mut d = Dec::new(body);
        let (Some(fid), Some(request_mask)) = (d.u32(), d.u64()) else {
            build_rlerror(reply, tag, E_PROTO);
            return;
        };
        let (rel, was_open, existing);
        {
            let f = self.fids.lock().unwrap();
            let Some(e) = f.map.get(&fid) else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            rel = e.rel.clone();
            was_open = e.opened;
            existing = e.handle.clone();
        }
        let opened_here;
        // `existing` (the Arc) stays in scope through `read_attrs_by_handle`, so a
        // concurrent clunk can't close the fid's handle under us.
        let h = match &existing {
            Some(a) if was_open => a.get(),
            _ => match self.open_for_getattr(&rel) {
                Ok(nh) => {
                    opened_here = nh;
                    opened_here.get()
                }
                Err(e) => {
                    build_rlerror(reply, tag, errno_from_win32(e));
                    return;
                }
            },
        };
        let attrs = self.read_attrs_by_handle(h);
        let md = self.lx_metadata(h);
        let (qt, qv, qp, mut mode, nlink, size, blocks, atime, mtime, ctime) = match attrs {
            Ok(v) => v,
            Err(e) => {
                build_rlerror(reply, tag, e);
                return;
            }
        };
        if let Some(m) = md.mode {
            mode = (mode & S_IFMT) | (m & PERM_BITS);
        }
        reply.clear();
        enc4(reply, 0);
        enc1(reply, R_GETATTR);
        enc2(reply, tag);
        enc8(reply, STATS_BASIC & request_mask);
        enc_qid(reply, qt, qv, qp);
        enc4(reply, mode);
        enc4(reply, md.uid.unwrap_or(self.uid));
        enc4(reply, md.gid.unwrap_or(self.gid));
        enc8(reply, nlink);
        enc8(reply, 0); // rdev
        enc8(reply, size);
        enc8(reply, 4096); // blksize
        enc8(reply, blocks);
        enc8(reply, atime.0);
        enc8(reply, atime.1);
        enc8(reply, mtime.0);
        enc8(reply, mtime.1);
        enc8(reply, ctime.0);
        enc8(reply, ctime.1);
        enc8(reply, 0); // btime sec
        enc8(reply, 0); // btime nsec
        enc8(reply, 0); // gen
        enc8(reply, 0); // data_version
        finalize(reply);
    }

    fn h_setattr(&self, tag: u16, body: &[u8], reply: &mut Vec<u8>) {
        let mut d = Dec::new(body);
        let (
            Some(fid),
            Some(valid),
            Some(mode),
            Some(uid),
            Some(gid),
            Some(sz),
            Some(atime_s),
            Some(atime_n),
            Some(mtime_s),
            Some(mtime_n),
        ) = (
            d.u32(),
            d.u32(),
            d.u32(),
            d.u32(),
            d.u32(),
            d.u64(),
            d.u64(),
            d.u64(),
            d.u64(),
            d.u64(),
        )
        else {
            build_rlerror(reply, tag, E_PROTO);
            return;
        };
        if self.readonly {
            build_rlerror(reply, tag, E_ROFS);
            return;
        }
        let (rel, open, is_dir);
        {
            let f = self.fids.lock().unwrap();
            let Some(e) = f.map.get(&fid) else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            rel = e.rel.clone();
            open = e.handle.clone().filter(|_| e.opened);
            is_dir = e.is_dir;
        }
        // chmod/chown: stored on a `metadata` share, ignored otherwise.
        if self.metadata && valid & (SETATTR_MODE | SETATTR_UID | SETATTR_GID) != 0 {
            let file_type = if is_dir { S_IFDIR } else { S_IFREG };
            let md = fs::LxMetadata {
                uid: (valid & SETATTR_UID != 0).then_some(uid),
                gid: (valid & SETATTR_GID != 0).then_some(gid),
                mode: (valid & SETATTR_MODE != 0).then_some(file_type | (mode & PERM_BITS)),
            };
            let r = self
                .open_fid_file(&rel, open.as_ref(), FILE_WRITE_EA)
                .and_then(|h| fs::set_lx_metadata(h.get(), md));
            if let Err(e) = r {
                build_rlerror(reply, tag, errno_from_win32(e));
                return;
            }
        }
        let mut access = FILE_WRITE_ATTRIBUTES;
        if valid & SETATTR_SIZE != 0 {
            access |= GENERIC_WRITE;
        }
        let h = match self.open_fid_file(&rel, open.as_ref(), access) {
            Ok(h) => h,
            Err(e) => {
                build_rlerror(reply, tag, errno_from_win32(e));
                return;
            }
        };

        if valid & SETATTR_SIZE != 0
            && let Err(e) = fs::set_end_of_file(h.get(), sz)
        {
            build_rlerror(reply, tag, errno_from_win32(e));
            return;
        }
        if valid & (SETATTR_ATIME | SETATTR_MTIME) != 0 {
            let mut pa: Option<u64> = None;
            let mut pm: Option<u64> = None;
            if valid & SETATTR_ATIME != 0 {
                pa = Some(if valid & SETATTR_ATIME_SET != 0 {
                    unix_to_filetime(atime_s, atime_n)
                } else {
                    fs::now_filetime_ticks()
                });
            }
            if valid & SETATTR_MTIME != 0 {
                pm = Some(if valid & SETATTR_MTIME_SET != 0 {
                    unix_to_filetime(mtime_s, mtime_n)
                } else {
                    fs::now_filetime_ticks()
                });
            }
            if let Err(e) = fs::set_file_times(h.get(), pa, pm) {
                build_rlerror(reply, tag, errno_from_win32(e));
                return;
            }
        }
        build_header_only(reply, R_SETATTR, tag);
    }

    fn h_clunk(&self, tag: u16, body: &[u8], reply: &mut Vec<u8>) {
        let mut d = Dec::new(body);
        let Some(fid) = d.u32() else {
            build_rlerror(reply, tag, E_PROTO);
            return;
        };
        if self.fids.lock().unwrap().map.remove(&fid).is_none() {
            build_rlerror(reply, tag, E_BADF);
            return;
        }
        build_header_only(reply, R_CLUNK, tag);
    }

    fn h_remove(&self, tag: u16, body: &[u8], reply: &mut Vec<u8>) {
        let mut d = Dec::new(body);
        let Some(fid) = d.u32() else {
            build_rlerror(reply, tag, E_PROTO);
            return;
        };
        let (rel, is_dir);
        {
            let mut f = self.fids.lock().unwrap();
            let Some(mut e) = f.map.remove(&fid) else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            rel = e.rel.clone();
            is_dir = e.is_dir;
            e.close_handle(); // explicit; dropped at end of scope anyway
        }
        if self.readonly {
            build_rlerror(reply, tag, E_ROFS);
            return;
        }
        if rel.as_os_str().is_empty() {
            build_rlerror(reply, tag, E_ACCES);
            return;
        }
        if let Err(e) = self.delete_entry(&rel, kind_of(is_dir)) {
            build_rlerror(reply, tag, errno_from_win32(e));
            return;
        }
        build_header_only(reply, R_REMOVE, tag);
    }

    fn h_fsync(&self, tag: u16, body: &[u8], reply: &mut Vec<u8>) {
        let mut d = Dec::new(body);
        let (Some(fid), Some(_datasync)) = (d.u32(), d.u32()) else {
            build_rlerror(reply, tag, E_PROTO);
            return;
        };
        let h = {
            let f = self.fids.lock().unwrap();
            let Some(e) = f.map.get(&fid) else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            e.handle.clone()
        };
        if let Some(a) = &h
            && let Err(err) = fs::flush(a.get())
            && err != ERROR_ACCESS_DENIED
            && err != ERROR_INVALID_HANDLE
        {
            build_rlerror(reply, tag, errno_from_win32(err));
            return;
        }
        build_header_only(reply, R_FSYNC, tag);
    }

    fn h_mkdir(&self, tag: u16, body: &[u8], reply: &mut Vec<u8>) {
        let mut d = Dec::new(body);
        let (Some(dfid), Some(name), Some(mode), Some(gid)) =
            (d.u32(), d.string(), d.u32(), d.u32())
        else {
            build_rlerror(reply, tag, E_PROTO);
            return;
        };
        if self.readonly {
            build_rlerror(reply, tag, E_ROFS);
            return;
        }
        if !is_safe_name_component(&name) {
            build_rlerror(reply, tag, E_INVAL);
            return;
        }
        let (parent, creator);
        {
            let f = self.fids.lock().unwrap();
            let Some(e) = f.map.get(&dfid) else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            if !e.is_dir {
                build_rlerror(reply, tag, E_NOTDIR);
                return;
            }
            parent = e.rel.clone();
            creator = e.uid;
        }
        let how = fs::Open::existing(0)
            .with_create(fs::Create::New)
            .with_kind(fs::Kind::Directory);
        let h = match self.open_rel(&parent.join(&name), how) {
            Ok((h, _)) => h,
            Err(e) => {
                build_rlerror(reply, tag, errno_from_win32(e));
                return;
            }
        };
        if self.metadata {
            let _ = Self::set_lx_metadata(
                h.get(),
                fs::LxMetadata {
                    uid: Some(creator),
                    gid: Some(gid),
                    mode: Some(S_IFDIR | (mode & PERM_BITS)),
                },
            );
        }
        let (qt, qv, qp) = match fs::file_info(h.get()) {
            Ok(info) => self.qid_of(&info),
            Err(e) => {
                build_rlerror(reply, tag, errno_from_win32(e));
                return;
            }
        };
        reply.clear();
        enc4(reply, 0);
        enc1(reply, R_MKDIR);
        enc2(reply, tag);
        enc_qid(reply, qt, qv, qp);
        finalize(reply);
    }

    fn h_rename(&self, tag: u16, body: &[u8], reply: &mut Vec<u8>) {
        let mut d = Dec::new(body);
        let (Some(fid), Some(dfid), Some(name)) = (d.u32(), d.u32(), d.string()) else {
            build_rlerror(reply, tag, E_PROTO);
            return;
        };
        if self.readonly {
            build_rlerror(reply, tag, E_ROFS);
            return;
        }
        if !is_safe_name_component(&name) {
            build_rlerror(reply, tag, E_INVAL);
            return;
        }
        let (old_rel, new_parent);
        {
            let f = self.fids.lock().unwrap();
            let (Some(src), Some(dir)) = (f.map.get(&fid), f.map.get(&dfid)) else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            if !dir.is_dir {
                build_rlerror(reply, tag, E_NOTDIR);
                return;
            }
            old_rel = src.rel.clone();
            new_parent = dir.rel.clone();
        }
        // The share root can't be moved.
        if old_rel.as_os_str().is_empty() {
            build_rlerror(reply, tag, E_ACCES);
            return;
        }
        // The fid's open handle, if any, stays valid: it follows the file.
        if let Err(e) = self.rename_entry(&old_rel, &new_parent, &name) {
            build_rlerror(reply, tag, errno_from_win32(e));
            return;
        }
        if let Some(e) = self.fids.lock().unwrap().map.get_mut(&fid) {
            e.rel = new_parent.join(&name);
        }
        build_header_only(reply, R_RENAME, tag);
    }

    fn h_renameat(&self, tag: u16, body: &[u8], reply: &mut Vec<u8>) {
        let mut d = Dec::new(body);
        let (Some(old_dirfid), Some(old_name), Some(new_dirfid), Some(new_name)) =
            (d.u32(), d.string(), d.u32(), d.string())
        else {
            build_rlerror(reply, tag, E_PROTO);
            return;
        };
        if self.readonly {
            build_rlerror(reply, tag, E_ROFS);
            return;
        }
        if !is_safe_name_component(&old_name) || !is_safe_name_component(&new_name) {
            build_rlerror(reply, tag, E_INVAL);
            return;
        }
        let (old_dir, new_dir);
        {
            let f = self.fids.lock().unwrap();
            let (Some(o), Some(n)) = (f.map.get(&old_dirfid), f.map.get(&new_dirfid)) else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            if !o.is_dir || !n.is_dir {
                build_rlerror(reply, tag, E_NOTDIR);
                return;
            }
            old_dir = o.rel.clone();
            new_dir = n.rel.clone();
        }
        if let Err(e) = self.rename_entry(&old_dir.join(&old_name), &new_dir, &new_name) {
            build_rlerror(reply, tag, errno_from_win32(e));
            return;
        }
        build_header_only(reply, R_RENAMEAT, tag);
    }

    fn h_unlinkat(&self, tag: u16, body: &[u8], reply: &mut Vec<u8>) {
        let mut d = Dec::new(body);
        let (Some(dirfid), Some(name), Some(flags)) = (d.u32(), d.string(), d.u32()) else {
            build_rlerror(reply, tag, E_PROTO);
            return;
        };
        if self.readonly {
            build_rlerror(reply, tag, E_ROFS);
            return;
        }
        if !is_safe_name_component(&name) {
            build_rlerror(reply, tag, E_INVAL);
            return;
        }
        let parent;
        {
            let f = self.fids.lock().unwrap();
            let Some(e) = f.map.get(&dirfid) else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            if !e.is_dir {
                build_rlerror(reply, tag, E_NOTDIR);
                return;
            }
            parent = e.rel.clone();
        }
        // Without AT_REMOVEDIR a directory fails with EISDIR, as on Linux.
        let kind = kind_of(flags & AT_REMOVEDIR != 0);
        if let Err(e) = self.delete_entry(&parent.join(&name), kind) {
            build_rlerror(reply, tag, errno_from_win32(e));
            return;
        }
        build_header_only(reply, R_UNLINKAT, tag);
    }

    fn h_statfs(&self, tag: u16, body: &[u8], reply: &mut Vec<u8>) {
        let mut d = Dec::new(body);
        let Some(fid) = d.u32() else {
            build_rlerror(reply, tag, E_PROTO);
            return;
        };
        if !self.fids.lock().unwrap().map.contains_key(&fid) {
            build_rlerror(reply, tag, E_BADF);
            return;
        }
        const BLOCK: u64 = 4096;
        // Every fid is on the share root's volume: links are followed only to
        // places inside the share.
        let space = self
            .root()
            .and_then(|root| fs::volume_space(root.handle.get()));
        let (blocks_total, blocks_free, blocks_avail) = match space {
            Ok((avail, total, free)) => (total / BLOCK, free / BLOCK, avail / BLOCK),
            Err(_) => (1 << 20, 1 << 20, 1 << 20),
        };
        reply.clear();
        enc4(reply, 0);
        enc1(reply, R_STATFS);
        enc2(reply, tag);
        enc4(reply, V9FS_MAGIC);
        enc4(reply, BLOCK as u32);
        enc8(reply, blocks_total);
        enc8(reply, blocks_free);
        enc8(reply, blocks_avail);
        enc8(reply, 0); // files
        enc8(reply, 0); // ffree
        enc8(reply, 0); // fsid
        enc4(reply, 255); // namelen
        finalize(reply);
    }
}

// ============================================================
// Chain I/O
// ============================================================
/// Gather the chain's device-readable buffers into `out`, capped at `max` bytes.
/// A malicious guest can present a chain whose readable descriptors sum to
/// gigabytes; without the cap that allocation runs on the drain/vCPU thread and
/// an allocation failure aborts the whole VMM (`panic = "abort"`). A truncated
/// message simply fails the per-handler length checks and is answered with an
/// error, and a well-formed request never exceeds the negotiated msize.
fn read_chain(bufs: &[ChainBuf], out: &mut Vec<u8>, max: usize) {
    out.clear();
    for b in bufs.iter().filter(|b| !b.write) {
        if out.len() >= max {
            break;
        }
        b.extend_vec(0, max - out.len(), out);
    }
}

fn write_chain(bufs: &mut [ChainBuf], reply: &[u8]) -> u32 {
    let mut off = 0usize;
    for b in bufs.iter().filter(|b| b.write) {
        if off >= reply.len() {
            break;
        }
        off += b.write_at(0, &reply[off..]);
    }
    off as u32
}

fn writable_capacity(bufs: &[ChainBuf]) -> u32 {
    let total: usize = bufs.iter().filter(|b| b.write).map(|b| b.len).sum();
    total.min(0xFFFF_FFFF) as u32
}

/// Twrite header: size[4] type[1] tag[2] fid[4] offset[8] count[4].
const TWRITE_HEADER_SIZE: usize = 23;

/// A payload whose contiguous runs average below this goes through the slot's
/// bounce buffer (one syscall plus a memcpy) instead of one syscall per run.
const DIRECT_MIN_RUN: usize = 32 * 1024;

/// Byte `at` of the logical stream formed by `bufs`' readable buffers.
fn peek_readable(bufs: &[ChainBuf], mut at: usize) -> Option<u8> {
    for b in bufs.iter().filter(|b| !b.write) {
        if at < b.len {
            let mut byte = [0u8];
            b.read_at(at, &mut byte);
            return Some(byte[0]);
        }
        at -= b.len;
    }
    None
}

/// Collect bytes `[skip, skip + len)` of the logical stream formed by `bufs`
/// as host-memory runs, merging buffers that are adjacent in host memory.
/// Returns the bytes covered (short of `len` only if the buffers are).
fn chain_runs(
    bufs: &[ChainBuf],
    mut skip: usize,
    len: usize,
    out: &mut Vec<(*mut u8, usize)>,
) -> usize {
    out.clear();
    let mut covered = 0usize;
    for b in bufs {
        if covered == len {
            break;
        }
        if skip >= b.len {
            skip -= b.len;
            continue;
        }
        let p = b.ptr.wrapping_add(skip);
        let take = (b.len - skip).min(len - covered);
        skip = 0;
        match out.last_mut() {
            Some(last) if last.0.wrapping_add(last.1) == p => last.1 += take,
            _ => out.push((p, take)),
        }
        covered += take;
    }
    covered
}

fn runs_direct(runs: &[(*mut u8, usize)], total: usize) -> bool {
    runs.len() <= 1 || runs.len() * DIRECT_MIN_RUN <= total
}

/// SAFETY: every run must be valid for writes of its length.
unsafe fn scatter(runs: &[(*mut u8, usize)], mut src: &[u8]) {
    for &(p, n) in runs {
        if src.is_empty() {
            break;
        }
        let k = n.min(src.len());
        unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), p, k) };
        src = &src[k..];
    }
}

/// SAFETY: every run must be valid for reads of its length.
unsafe fn gather(runs: &[(*mut u8, usize)], dst: &mut [u8]) {
    let mut off = 0usize;
    for &(p, n) in runs {
        let k = n.min(dst.len() - off);
        unsafe { std::ptr::copy_nonoverlapping(p, dst[off..].as_mut_ptr(), k) };
        off += k;
    }
}

/// Positioned (or, with `append`, appending) write of `n` bytes at `p`.
///
/// SAFETY: `[p, p + n)` must be valid for reads until the call returns.
unsafe fn write_raw(h: HANDLE, append: bool, p: *const u8, n: usize, at: u64) -> Result<u32, u32> {
    unsafe {
        if append {
            fs::write_append_raw(h, p, n as u32)
        } else {
            fs::write_at_raw(h, p, n as u32, at)
        }
    }
}

impl VirtioDevice for P9Device {
    fn device_id(&self) -> u32 {
        DEVICE_ID_P9
    }

    fn device_features(&self) -> u64 {
        FEATURE_VERSION_1 | FEATURE_RING_EVENT_IDX | FEATURE_RING_INDIRECT_DESC | P9_F_MOUNT_TAG
    }

    fn set_driver_features(&self, acked: u64) -> bool {
        if acked & FEATURE_VERSION_1 == 0 {
            return false;
        }
        if acked & !self.device_features() != 0 {
            return false;
        }
        self.acked_features.store(acked, Ordering::Relaxed);
        true
    }

    fn queue_count(&self) -> u32 {
        1
    }

    fn queue_max(&self, idx: u32) -> u32 {
        if idx == P9_REQUEST_QUEUE {
            P9_QUEUE_MAX
        } else {
            0
        }
    }

    fn enable_queue(&self, idx: u32, desc: u64, avail: u64, used: u64, size: u16, event_idx: bool) {
        if idx != P9_REQUEST_QUEUE {
            return;
        }
        let mut q = self.queue.lock().unwrap();
        q.set_desc_gpa(desc);
        q.set_avail_gpa(avail);
        q.set_used_gpa(used);
        q.set_size(size as u32);
        q.set_event_idx_enabled(event_idx);
        q.set_ready(true);
    }

    fn disable_queue(&self, idx: u32) {
        if idx == P9_REQUEST_QUEUE {
            self.queue.lock().unwrap().set_ready(false);
        }
    }

    fn notify_queue(&self, idx: u32) {
        if idx == P9_REQUEST_QUEUE {
            self.drain();
        }
    }

    fn queue_has_work(&self, idx: u32) -> Option<bool> {
        if idx != P9_REQUEST_QUEUE {
            return None;
        }
        // A held lock is a worker pushing a reply: let the drain look properly.
        Some(self.queue.try_lock().map_or(true, |q| q.has_avail()))
    }

    fn driver_ok(&self) {
        self.driver_ok.store(true, Ordering::Relaxed);
    }

    fn reset(&self) {
        self.driver_ok.store(false, Ordering::Relaxed);
        self.acked_features.store(0, Ordering::Relaxed);
        self.negotiated_msize.store(0, Ordering::Relaxed);
        self.fids.lock().unwrap().map.clear();
    }

    // ---- save/restore ----
    fn capture_queue(&self, idx: u32) -> Option<crate::virtio::queue::QueueState> {
        if idx == P9_REQUEST_QUEUE {
            Some(self.queue.lock().unwrap().capture())
        } else {
            None
        }
    }

    fn apply_queue(&self, idx: u32, st: &crate::virtio::queue::QueueState) {
        if idx == P9_REQUEST_QUEUE {
            self.queue.lock().unwrap().apply(st);
        }
    }

    /// Encode driver_ok + negotiated features/msize + the qid allocator + the
    /// whole fid table (host path + open mode per fid). Host handles are NOT
    /// encoded; they are reopened from each fid's path on `apply_device_state`.
    fn capture_device_state(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(2u8); // format version (2 added each fid's uid)
        b.push(self.driver_ok.load(Ordering::Relaxed) as u8);
        b.extend_from_slice(&self.acked_features.load(Ordering::Relaxed).to_le_bytes());
        b.extend_from_slice(&self.negotiated_msize.load(Ordering::Relaxed).to_le_bytes());
        b.extend_from_slice(&self.next_qid_path.load(Ordering::Relaxed).to_le_bytes());
        let fids = self.fids.lock().unwrap();
        b.extend_from_slice(&(fids.map.len() as u32).to_le_bytes());
        for (id, e) in fids.map.iter() {
            b.extend_from_slice(&id.to_le_bytes());
            b.extend_from_slice(&e.qid_path.to_le_bytes());
            b.push(e.is_dir as u8);
            b.push(e.opened as u8);
            b.extend_from_slice(&e.open_flags.to_le_bytes());
            let path = if e.rel.as_os_str().is_empty() {
                self.host_root.clone()
            } else {
                self.host_root.join(&e.rel)
            };
            let path = path.to_string_lossy();
            let pb = path.as_bytes();
            b.extend_from_slice(&(pb.len() as u32).to_le_bytes());
            b.extend_from_slice(pb);
            b.extend_from_slice(&e.uid.to_le_bytes());
        }
        b
    }

    /// Rebuild the device state captured above. Reopens each previously-open
    /// fid's host handle (best effort: a since-deleted file leaves the fid
    /// unopened). A fid whose path doesn't lie under the share root is dropped.
    /// Bounds-checked: a short/corrupt blob aborts the parse rather than
    /// panicking.
    fn apply_device_state(&self, bytes: &[u8]) {
        let mut p = 0usize;
        macro_rules! take {
            ($n:expr) => {{
                if p + $n > bytes.len() {
                    return;
                }
                let s = &bytes[p..p + $n];
                p += $n;
                s
            }};
        }
        let ver = take!(1)[0];
        let drv_ok = take!(1)[0] != 0;
        let acked = u64::from_le_bytes(take!(8).try_into().unwrap());
        let msize = u32::from_le_bytes(take!(4).try_into().unwrap());
        let next_qid = u64::from_le_bytes(take!(8).try_into().unwrap());
        self.driver_ok.store(drv_ok, Ordering::Relaxed);
        self.acked_features.store(acked, Ordering::Relaxed);
        self.negotiated_msize.store(msize, Ordering::Relaxed);
        self.next_qid_path.store(next_qid, Ordering::Relaxed);

        let count = u32::from_le_bytes(take!(4).try_into().unwrap());
        let mut new_map: HashMap<u32, FidEntry> = HashMap::new();
        for _ in 0..count {
            let id = u32::from_le_bytes(take!(4).try_into().unwrap());
            let qid = u64::from_le_bytes(take!(8).try_into().unwrap());
            let is_dir = take!(1)[0] != 0;
            let opened = take!(1)[0] != 0;
            let flags = u32::from_le_bytes(take!(4).try_into().unwrap());
            let plen = u32::from_le_bytes(take!(4).try_into().unwrap()) as usize;
            let pbytes = take!(plen);
            let path = PathBuf::from(String::from_utf8_lossy(pbytes).into_owned());
            let uid = if ver >= 2 {
                u32::from_le_bytes(take!(4).try_into().unwrap())
            } else {
                self.uid
            };
            let Some(rel) = rel_below(&self.host_root, &path) else {
                eprintln!(
                    "[9p] restore: fid {id} ({}) is not below the share root; dropping it",
                    path.display()
                );
                continue;
            };
            let mut e = FidEntry::new(rel, is_dir, qid, uid);
            if opened {
                match self.reopen_fid_handle(&e.rel, is_dir, flags) {
                    Some(h) => {
                        e.handle = Some(Arc::new(h));
                        e.opened = true;
                        e.open_flags = flags;
                    }
                    None => eprintln!(
                        "[9p] restore: could not reopen fid {id} ({}); leaving it unopened",
                        path.display()
                    ),
                }
            }
            new_map.insert(id, e);
        }
        self.fids.lock().unwrap().map = new_map;
    }

    fn read_config(&self, offset: u32, size: u32) -> u32 {
        let mut v = 0u32;
        for i in 0..size {
            let o = (offset + i) as usize;
            if o < self.config_bytes.len() {
                v |= (self.config_bytes[o] as u32) << (i * 8);
            }
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create the directory junction `link` -> `target`; `mklink /J` needs no
    /// elevation. False where junctions are unavailable, and the caller skips.
    fn junction(link: &Path, target: &Path) -> bool {
        std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .is_ok_and(|o| o.status.success())
            && link.exists()
    }

    /// Links in the share are followed only to places inside it: a junction to
    /// a directory outside can't be walked into, while one to a directory
    /// inside works as that directory would, also partway along a path.
    #[test]
    fn links_are_followed_only_inside_the_share() {
        let base = std::env::temp_dir().join(format!("tinyvmm_p9_esc_{}", std::process::id()));
        let share = base.join("share");
        let sub = share.join("sub");
        let outside = base.join("outside");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(sub.join("f.txt"), b"inside").unwrap();
        std::fs::write(outside.join("secret.txt"), b"top secret").unwrap();
        if !junction(&share.join("escape"), &outside) || !junction(&share.join("link"), &sub) {
            eprintln!("[p9-test] skipping: could not create a directory junction");
            let _ = std::fs::remove_dir_all(&base);
            return;
        }

        let root = std::fs::canonicalize(&share).unwrap();
        let mem = std::sync::Arc::new(whpsys::memory::GuestMemory::new_host_only(4096).unwrap());
        let dev = P9Device::new(mem, "test".into(), root, ShareOptions::default());
        connect(&dev, 0);

        walk(&dev, 0, 1, &["sub"]);
        assert_eq!(walk_err(&dev, 0, 2, &["escape"]), E_ACCES);
        assert_eq!(walk_err(&dev, 0, 2, &["escape", "secret.txt"]), E_ACCES);
        walk(&dev, 0, 2, &["link", "f.txt"]);
        call(&dev, T_LOPEN, |t| {
            enc4(t, 2);
            enc4(t, O_RDONLY);
        });
        let r = call(&dev, T_READ, |t| {
            enc4(t, 2);
            enc8(t, 0);
            enc4(t, 64);
        });
        assert_eq!(&r[RREAD_HEADER_SIZE..], b"inside");

        drop(dev);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A directory a fid names can turn into a junction to somewhere outside
    /// the share after the walk: a host process can swap it, or the guest can
    /// rename a junction already in the share into its place. No operation
    /// through such a fid may then act outside: no delete, rename, mkdir,
    /// create or truncate, and no open.
    #[test]
    fn swapped_junction_cannot_redirect_operations() {
        let base = std::env::temp_dir().join(format!("tinyvmm_p9_swap_{}", std::process::id()));
        let share = base.join("share");
        let a = share.join("a");
        let outside = base.join("outside");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(a.join("victim.txt"), b"inside").unwrap();
        std::fs::write(outside.join("victim.txt"), b"precious").unwrap();
        std::fs::write(outside.join("secret.txt"), b"secret").unwrap();

        let root = std::fs::canonicalize(&share).unwrap();
        let mem = std::sync::Arc::new(whpsys::memory::GuestMemory::new_host_only(4096).unwrap());
        let dev = P9Device::new(mem, "t".into(), root, ShareOptions::default());
        connect(&dev, 0);
        walk(&dev, 0, 1, &["a"]);
        walk(&dev, 0, 2, &["a", "victim.txt"]);
        walk(&dev, 0, 3, &["a"]);

        std::fs::rename(&a, share.join("a_real")).unwrap();
        if !junction(&a, &outside) {
            eprintln!("[p9-test] skipping: could not create a directory junction");
            let _ = std::fs::remove_dir_all(&base);
            return;
        }

        let unlink = call_err(&dev, T_UNLINKAT, |t| {
            enc4(t, 1);
            enc_str(t, "secret.txt");
            enc4(t, 0);
        });
        let rename = call_err(&dev, T_RENAMEAT, |t| {
            enc4(t, 1);
            enc_str(t, "secret.txt");
            enc4(t, 0);
            enc_str(t, "stolen.txt");
        });
        let mkdir = call_err(&dev, T_MKDIR, |t| {
            enc4(t, 1);
            enc_str(t, "planted");
            enc4(t, 0o755);
            enc4(t, 0);
        });
        let create = call_err(&dev, T_LCREATE, |t| {
            enc4(t, 3);
            enc_str(t, "victim.txt");
            enc4(t, O_WRONLY | O_TRUNC);
            enc4(t, 0o644);
            enc4(t, 0);
        });
        let open = call_err(&dev, T_LOPEN, |t| {
            enc4(t, 2);
            enc4(t, O_WRONLY | O_TRUNC);
        });
        let getattr = call_err(&dev, T_GETATTR, |t| {
            enc4(t, 2);
            enc8(t, STATS_BASIC);
        });
        assert_eq!([unlink, rename, mkdir, create, open, getattr], [E_ACCES; 6]);
        assert_eq!(
            std::fs::read(outside.join("secret.txt")).unwrap(),
            b"secret"
        );
        assert_eq!(
            std::fs::read(outside.join("victim.txt")).unwrap(),
            b"precious"
        );
        assert!(!outside.join("planted").exists());
        assert!(!share.join("stolen.txt").exists());

        drop(dev);
        let _ = std::fs::remove_dir(&a);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Renaming over a file the guest holds open works, as on Linux, and the
    /// open fid keeps reading the file it opened. `MoveFileExW` refuses such a
    /// rename while any handle to the target is open.
    #[test]
    fn renameat_replaces_a_target_held_open() {
        let base = std::env::temp_dir().join(format!("tinyvmm_p9_replace_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("new.txt"), b"new").unwrap();
        std::fs::write(base.join("target.txt"), b"old").unwrap();
        let root = std::fs::canonicalize(&base).unwrap();
        let mem = std::sync::Arc::new(whpsys::memory::GuestMemory::new_host_only(4096).unwrap());
        let dev = P9Device::new(mem, "t".into(), root, ShareOptions::default());
        connect(&dev, 0);
        walk(&dev, 0, 1, &["target.txt"]);
        call(&dev, T_LOPEN, |t| {
            enc4(t, 1);
            enc4(t, O_RDONLY);
        });

        call(&dev, T_RENAMEAT, |t| {
            enc4(t, 0);
            enc_str(t, "new.txt");
            enc4(t, 0);
            enc_str(t, "target.txt");
        });
        let r = call(&dev, T_READ, |t| {
            enc4(t, 1);
            enc8(t, 0);
            enc4(t, 64);
        });
        assert_eq!(&r[RREAD_HEADER_SIZE..], b"old");
        call(&dev, T_CLUNK, |t| enc4(t, 1));
        assert_eq!(std::fs::read(base.join("target.txt")).unwrap(), b"new");
        assert!(!base.join("new.txt").exists());

        drop(dev);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The share root deleted and recreated on the host, as a build step does to
    /// its output folder: the share reattaches to the new directory, for fids
    /// walked before and requests after, instead of staying on the deleted one;
    /// but not to wherever a junction put in the root's place points.
    #[test]
    fn recreated_root_is_reattached() {
        let base = std::env::temp_dir().join(format!("tinyvmm_p9_reroot_{}", std::process::id()));
        let share = base.join("share");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&share).unwrap();
        std::fs::write(share.join("old.txt"), b"old").unwrap();
        let root = std::fs::canonicalize(&share).unwrap();
        let mem = std::sync::Arc::new(whpsys::memory::GuestMemory::new_host_only(4096).unwrap());
        let dev = P9Device::new(mem, "t".into(), root, ShareOptions::default());
        connect(&dev, 0);
        walk(&dev, 0, 1, &[]);

        std::fs::remove_dir_all(&share).unwrap();
        std::fs::create_dir(&share).unwrap();
        std::fs::write(share.join("new.txt"), b"new").unwrap();

        call(&dev, T_LOPEN, |t| {
            enc4(t, 1);
            enc4(t, O_RDONLY | O_DIRECTORY);
        });
        let r = call(&dev, T_READDIR, |t| {
            enc4(t, 1);
            enc8(t, 0);
            enc4(t, 4096);
        });
        assert!(r.windows(7).any(|w| w == b"new.txt"), "{r:?}");
        assert_eq!(walk_err(&dev, 0, 2, &["old.txt"]), E_NOENT);
        walk(&dev, 0, 2, &["new.txt"]);
        call(&dev, T_LOPEN, |t| {
            enc4(t, 2);
            enc4(t, O_RDONLY);
        });
        let r = call(&dev, T_READ, |t| {
            enc4(t, 2);
            enc8(t, 0);
            enc4(t, 64);
        });
        assert_eq!(&r[RREAD_HEADER_SIZE..], b"new");
        walk(&dev, 0, 3, &[]);
        lcreate(&dev, 3, "made.txt", O_WRONLY, 0o644, 0);
        assert!(share.join("made.txt").exists());

        // A junction left in the deleted root's place doesn't move the share.
        let outside = base.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::remove_dir_all(&share).unwrap();
        if junction(&share, &outside) {
            assert_eq!(walk_err(&dev, 0, 4, &["x"]), E_ACCES);
            walk(&dev, 0, 4, &[]);
            let create = call_err(&dev, T_LCREATE, |t| {
                enc4(t, 4);
                enc_str(t, "planted.txt");
                enc4(t, O_WRONLY);
                enc4(t, 0o644);
                enc4(t, 0);
            });
            assert_eq!(create, E_ACCES);
            assert!(!outside.join("planted.txt").exists());
            let _ = std::fs::remove_dir(&share);
        } else {
            eprintln!("[p9-test] skipping the junction case: could not create a junction");
        }

        drop(dev);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Capturing then re-applying the 9p device state must restore the negotiated
    /// state and the whole fid table, reopening the host handles of fids that
    /// were open at capture time, and must drop a fid whose path leaves the
    /// share, as a tampered snapshot could carry.
    #[test]
    fn device_state_roundtrip_reopens_fids() {
        let base = std::env::temp_dir().join(format!("tinyvmm_p9_snap_{}", std::process::id()));
        let share = base.join("share");
        let sub = share.join("sub");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(share.join("file.txt"), b"hello").unwrap();
        let root = std::fs::canonicalize(&share).unwrap();

        let mem = std::sync::Arc::new(whpsys::memory::GuestMemory::new_host_only(4096).unwrap());
        let dev = P9Device::new(
            mem.clone(),
            "t".into(),
            root.clone(),
            ShareOptions::default(),
        );
        dev.driver_ok.store(true, Ordering::Relaxed);
        let feats = dev.device_features();
        dev.acked_features.store(feats, Ordering::Relaxed);
        dev.negotiated_msize.store(512_000, Ordering::Relaxed);
        dev.next_qid_path.store(42, Ordering::Relaxed);
        {
            let hf = dev
                .reopen_fid_handle(Path::new("file.txt"), false, O_RDONLY)
                .unwrap();
            let hd = dev
                .reopen_fid_handle(Path::new("sub"), true, O_RDONLY)
                .unwrap();
            let mut fids = dev.fids.lock().unwrap();
            let mut ef = FidEntry::new(PathBuf::from("file.txt"), false, 7, 1000);
            ef.handle = Some(Arc::new(hf));
            ef.opened = true;
            ef.open_flags = O_RDONLY;
            fids.map.insert(1, ef);
            let mut ed = FidEntry::new(PathBuf::from("sub"), true, 8, 0);
            ed.handle = Some(Arc::new(hd));
            ed.opened = true;
            ed.open_flags = O_RDONLY;
            fids.map.insert(2, ed);
            // A walked-but-not-opened fid: path only, no handle.
            fids.map
                .insert(3, FidEntry::new(PathBuf::new(), true, 1, 1001));
            let outside = Path::new("..").join("outside");
            fids.map.insert(4, FidEntry::new(outside, true, 9, 0));
        }

        let blob = dev.capture_device_state();

        let dev2 = P9Device::new(mem, "t".into(), root, ShareOptions::default());
        dev2.apply_device_state(&blob);
        assert!(dev2.driver_ok.load(Ordering::Relaxed));
        assert_eq!(dev2.acked_features.load(Ordering::Relaxed), feats);
        assert_eq!(dev2.negotiated_msize.load(Ordering::Relaxed), 512_000);
        assert_eq!(dev2.next_qid_path.load(Ordering::Relaxed), 42);
        let fids = dev2.fids.lock().unwrap();
        assert_eq!(fids.map.len(), 3, "the fid leaving the share is dropped");
        let f1 = fids.map.get(&1).unwrap();
        assert!(!f1.is_dir && f1.opened && f1.handle.is_some() && f1.qid_path == 7);
        let f2 = fids.map.get(&2).unwrap();
        assert!(f2.is_dir && f2.opened && f2.handle.is_some() && f2.qid_path == 8);
        let f3 = fids.map.get(&3).unwrap();
        assert!(f3.is_dir && !f3.opened && f3.handle.is_none() && f3.qid_path == 1);
        assert_eq!((f1.uid, f2.uid, f3.uid), (1000, 0, 1001));
        assert_eq!(
            [&f1.rel, &f2.rel, &f3.rel],
            [Path::new("file.txt"), Path::new("sub"), Path::new("")]
        );
        drop(fids);

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Send one T-message to `dev` and return its R-message.
    fn send(dev: &P9Device, mtype: u8, body: impl Fn(&mut Vec<u8>)) -> Vec<u8> {
        let mut t = Vec::new();
        enc4(&mut t, 0);
        enc1(&mut t, mtype);
        enc2(&mut t, 1);
        body(&mut t);
        finalize(&mut t);
        let mut reply = Vec::new();
        dev.dispatch(&t, &mut reply, 8192);
        reply
    }

    /// [`send`], for a request that must succeed.
    fn call(dev: &P9Device, mtype: u8, body: impl Fn(&mut Vec<u8>)) -> Vec<u8> {
        let reply = send(dev, mtype, body);
        assert_eq!(reply[4], mtype + 1, "T-message {mtype} failed: {reply:?}");
        reply
    }

    /// [`send`], for a request that must fail: the errno of its Rlerror.
    fn call_err(dev: &P9Device, mtype: u8, body: impl Fn(&mut Vec<u8>)) -> u32 {
        let reply = send(dev, mtype, body);
        assert_eq!(reply[4], R_LERROR, "T-message {mtype} succeeded: {reply:?}");
        u32::from_le_bytes(reply[7..11].try_into().unwrap())
    }

    /// Tversion, then Tattach fid 0 to the share root as user `n_uname`.
    fn connect(dev: &P9Device, n_uname: u32) {
        call(dev, T_VERSION, |t| {
            enc4(t, 8192);
            enc_str(t, "9P2000.L");
        });
        call(dev, T_ATTACH, |t| {
            enc4(t, 0);
            enc4(t, NO_FID);
            enc_str(t, "");
            enc_str(t, "");
            enc4(t, n_uname);
        });
    }

    fn walk(dev: &P9Device, fid: u32, newfid: u32, names: &[&str]) {
        call(dev, T_WALK, |t| walk_body(t, fid, newfid, names));
    }

    /// The errno of a Twalk that must fail at its first name.
    fn walk_err(dev: &P9Device, fid: u32, newfid: u32, names: &[&str]) -> u32 {
        call_err(dev, T_WALK, |t| walk_body(t, fid, newfid, names))
    }

    fn walk_body(t: &mut Vec<u8>, fid: u32, newfid: u32, names: &[&str]) {
        enc4(t, fid);
        enc4(t, newfid);
        enc2(t, names.len() as u16);
        for name in names {
            enc_str(t, name);
        }
    }

    /// (mode, uid, gid) from Rgetattr.
    fn stat(dev: &P9Device, fid: u32) -> (u32, u32, u32) {
        let r = call(dev, T_GETATTR, |t| {
            enc4(t, fid);
            enc8(t, STATS_BASIC);
        });
        // size[4] type[1] tag[2] valid[8] qid[13] mode[4] uid[4] gid[4]
        let word = |o: usize| u32::from_le_bytes(r[o..o + 4].try_into().unwrap());
        (word(28), word(32), word(36))
    }

    fn setattr(dev: &P9Device, fid: u32, valid: u32, mode: u32, uid: u32) {
        call(dev, T_SETATTR, |t| {
            enc4(t, fid);
            enc4(t, valid);
            enc4(t, mode);
            enc4(t, uid);
            enc4(t, 0); // gid
            for _ in 0..5 {
                enc8(t, 0); // size, atime, mtime
            }
        });
    }

    /// Tlcreate with `flags`. A write-only file's handle can't read extended
    /// attributes, so getattr through it must fall back to a fresh handle.
    fn lcreate(dev: &P9Device, fid: u32, name: &str, flags: u32, mode: u32, gid: u32) {
        call(dev, T_LCREATE, |t| {
            enc4(t, fid);
            enc_str(t, name);
            enc4(t, flags);
            enc4(t, mode);
            enc4(t, gid);
        });
    }

    /// Rgetattr must report the share's configured owner for the root and for
    /// the files under it, so that guest user can write to the share.
    #[test]
    fn getattr_reports_share_owner() {
        let base = std::env::temp_dir().join(format!("tinyvmm_p9_owner_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("file.txt"), b"hello").unwrap();
        let root = std::fs::canonicalize(&base).unwrap();
        let mem = std::sync::Arc::new(whpsys::memory::GuestMemory::new_host_only(4096).unwrap());
        let opts = ShareOptions {
            uid: 1000,
            gid: 1001,
            ..Default::default()
        };
        let dev = P9Device::new(mem, "t".into(), root, opts);

        connect(&dev, 0);
        walk(&dev, 0, 1, &["file.txt"]);
        for fid in [0u32, 1] {
            let (_, uid, gid) = stat(&dev, fid);
            assert_eq!((uid, gid), (1000, 1001), "fid {fid}");
        }

        let _ = std::fs::remove_dir_all(&base);
    }

    /// qid.version of the qid starting at byte `at` of a reply.
    fn qid_version_at(r: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(r[at + 1..at + 5].try_into().unwrap())
    }

    /// Linux forces uncached I/O on any file whose qid.version is 0, so files
    /// carry a version — the same through walk, lopen and getattr — that a host
    /// change moves. Directories keep 0.
    #[test]
    fn file_qids_carry_a_version() {
        use std::io::Write;
        let base = std::env::temp_dir().join(format!("tinyvmm_p9_qv_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("f"), b"one").unwrap();
        let root = std::fs::canonicalize(&base).unwrap();
        let mem = std::sync::Arc::new(whpsys::memory::GuestMemory::new_host_only(4096).unwrap());
        let dev = P9Device::new(mem, "t".into(), root, ShareOptions::default());

        connect(&dev, 0);
        let rwalk = call(&dev, T_WALK, |t| {
            enc4(t, 0);
            enc4(t, 1);
            enc2(t, 1);
            enc_str(t, "f");
        });
        // Rwalk: size[4] type[1] tag[2] nwqid[2] qid[13]...
        let walked = qid_version_at(&rwalk, 9);
        assert_ne!(walked, 0);
        let rlopen = call(&dev, T_LOPEN, |t| {
            enc4(t, 1);
            enc4(t, O_RDONLY);
        });
        assert_eq!(qid_version_at(&rlopen, 7), walked);
        let getattr_version = |fid: u32| {
            let r = call(&dev, T_GETATTR, |t| {
                enc4(t, fid);
                enc8(t, STATS_BASIC);
            });
            qid_version_at(&r, 15)
        };
        assert_eq!(getattr_version(1), walked);
        assert_eq!(getattr_version(0), 0, "directory");

        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(base.join("f"))
            .unwrap();
        f.write_all(b"two").unwrap();
        drop(f);
        assert_ne!(
            getattr_version(1),
            walked,
            "a host change must move the version"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// The virtqueue path moves Tread/Twrite payloads between the host file and
    /// the guest's buffers either run by run or through the bounce buffer. Both
    /// must follow the chain's logical byte stream exactly, header included.
    #[test]
    fn direct_read_and_write_follow_scattered_chains() {
        let base = std::env::temp_dir().join(format!("tinyvmm_p9_rw_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let file: Vec<u8> = (0..40_000u32).map(|i| (i * 7 + i / 251) as u8).collect();
        std::fs::write(base.join("d"), &file).unwrap();
        let mut file = file;
        let root = std::fs::canonicalize(&base).unwrap();
        let mem = std::sync::Arc::new(whpsys::memory::GuestMemory::new_host_only(4096).unwrap());
        let dev = P9Device::new(mem, "t".into(), root, ShareOptions::default());
        connect(&dev, 0);
        // Room for the 9000-byte read (Tversion would also drop the fids).
        dev.negotiated_msize.store(65536, Ordering::Relaxed);
        walk(&dev, 0, 1, &["d"]);
        call(&dev, T_LOPEN, |t| {
            enc4(t, 1);
            enc4(t, O_RDWR);
        });

        // Guest-RAM stand-in. Buffers are laid out 64 bytes apart so no two of
        // them merge into one run.
        let mut ram = vec![0u8; 1 << 20];
        let ram_ptr = ram.as_mut_ptr();
        let layout = |first: usize, lens: &[usize], write: bool| {
            let mut off = 0usize;
            let mut bufs = Vec::new();
            for &len in std::iter::once(&first).chain(lens) {
                bufs.push(ChainBuf {
                    ptr: ram_ptr.wrapping_add(off),
                    len,
                    write,
                });
                off += len + 64;
            }
            bufs
        };
        let stream = |bufs: &[ChainBuf], n: usize| {
            let mut s = Vec::new();
            for b in bufs {
                b.extend_vec(0, b.len, &mut s);
            }
            s.truncate(n);
            s
        };

        // One 9000-byte run takes the per-run path; 24 runs of 512 the bounce.
        for data_lens in [vec![9000usize], vec![512; 24]] {
            let payload: usize = data_lens.iter().sum();
            for offset in [0u64, 12_345, 39_000] {
                // Tread: header buffer, then the data buffers.
                let mut slot = P9Slot::new();
                slot.wbufs = layout(RREAD_HEADER_SIZE, &data_lens, true);
                slot.cap = writable_capacity(&slot.wbufs);
                enc4(&mut slot.t_msg, 0);
                enc1(&mut slot.t_msg, T_READ);
                enc2(&mut slot.t_msg, 7);
                enc4(&mut slot.t_msg, 1);
                enc8(&mut slot.t_msg, offset);
                enc4(&mut slot.t_msg, payload as u32);
                finalize(&mut slot.t_msg);
                let n = dev.read_into_chain(&mut slot) as usize;
                let want = &file[offset as usize..(offset as usize + payload).min(file.len())];
                let r = stream(&slot.wbufs, n);
                assert_eq!(n, RREAD_HEADER_SIZE + want.len(), "{data_lens:?} @{offset}");
                assert_eq!(r[4], R_READ);
                assert_eq!(u16::from_le_bytes([r[5], r[6]]), 7);
                assert_eq!(
                    u32::from_le_bytes(r[7..11].try_into().unwrap()) as usize,
                    want.len()
                );
                assert!(r[RREAD_HEADER_SIZE..] == *want, "{data_lens:?} @{offset}");
            }

            // Twrite of `payload` new bytes at 100: header, then the data.
            let mut slot = P9Slot::new();
            slot.rbufs = layout(TWRITE_HEADER_SIZE, &data_lens, false);
            let mut hdr = Vec::new();
            enc4(&mut hdr, (TWRITE_HEADER_SIZE + payload) as u32);
            enc1(&mut hdr, T_WRITE);
            enc2(&mut hdr, 9);
            enc4(&mut hdr, 1);
            enc8(&mut hdr, 100);
            enc4(&mut hdr, payload as u32);
            let data: Vec<u8> = (0..payload).map(|i| (i % 253) as u8 ^ 0x5A).collect();
            let mut src = hdr.clone();
            src.extend_from_slice(&data);
            let mut at = 0usize;
            for b in &slot.rbufs {
                at += b.write_at(0, &src[at..at + b.len]);
            }
            slot.t_msg = hdr;
            slot.msg_len = src.len();
            let mut reply = vec![0u8; 64];
            slot.wbufs = vec![ChainBuf {
                ptr: reply.as_mut_ptr(),
                len: reply.len(),
                write: true,
            }];
            let n = dev.write_from_chain(&mut slot) as usize;
            assert_eq!(n, REPLY_HEADER_SIZE + 4);
            assert_eq!(reply[4], R_WRITE, "{data_lens:?}");
            assert_eq!(
                u32::from_le_bytes(reply[7..11].try_into().unwrap()) as usize,
                payload
            );
            let host = std::fs::read(base.join("d")).unwrap();
            assert!(host[100..100 + payload] == *data, "{data_lens:?}");
            file[100..100 + payload].copy_from_slice(&data);
        }

        drop(dev);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// On a `metadata` share, new entries record their creator, gid and mode as
    /// WSL metadata, chmod/chown update it, and it all reads back from the host:
    /// through this device, a fresh one, and NTFS's own WSL metadata decoder.
    #[test]
    fn metadata_share_keeps_owner_and_mode_in_wsl_attributes() {
        let base = std::env::temp_dir().join(format!("tinyvmm_p9_meta_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("plain.txt"), b"from the host").unwrap();
        let root = std::fs::canonicalize(&base).unwrap();
        let mem = std::sync::Arc::new(whpsys::memory::GuestMemory::new_host_only(4096).unwrap());
        let opts = ShareOptions {
            uid: 500,
            gid: 501,
            metadata: true,
            ..Default::default()
        };
        let dev = P9Device::new(mem.clone(), "t".into(), root.clone(), opts);
        connect(&dev, 1000);

        // No metadata yet: the share's defaults.
        walk(&dev, 0, 1, &["plain.txt"]);
        assert_eq!(stat(&dev, 1), (S_IFREG | 0o644, 500, 501));

        // Tlcreate turns a clone of the root fid into the new file.
        walk(&dev, 0, 2, &[]);
        lcreate(&dev, 2, "new.txt", O_WRONLY, S_IFREG | 0o640, 1001);
        assert_eq!(stat(&dev, 2), (S_IFREG | 0o640, 1000, 1001));
        call(&dev, T_MKDIR, |t| {
            enc4(t, 0);
            enc_str(t, "sub");
            enc4(t, 0o750);
            enc4(t, 7);
        });
        walk(&dev, 0, 3, &["sub"]);
        assert_eq!(stat(&dev, 3), (S_IFDIR | 0o750, 1000, 7));

        // A create that opens an existing file must not claim it.
        walk(&dev, 0, 4, &[]);
        lcreate(&dev, 4, "plain.txt", O_WRONLY, S_IFREG | 0o600, 1001);
        assert_eq!(stat(&dev, 4), (S_IFREG | 0o644, 500, 501));

        // chmod (setuid included), then chown of the uid alone.
        setattr(&dev, 2, SETATTR_MODE, S_IFREG | 0o4755, 0);
        setattr(&dev, 2, SETATTR_UID, 0, 42);
        let want = (S_IFREG | 0o4755, 42, 1001);
        assert_eq!(stat(&dev, 2), want);

        // Truncating creates and opens keep them, as on Linux.
        walk(&dev, 0, 5, &[]);
        lcreate(&dev, 5, "new.txt", O_WRONLY | O_TRUNC, S_IFREG | 0o600, 7);
        walk(&dev, 0, 6, &["new.txt"]);
        call(&dev, T_LOPEN, |t| {
            enc4(t, 6);
            enc4(t, O_WRONLY | O_TRUNC);
        });
        assert_eq!(stat(&dev, 6), want);

        let fresh = P9Device::new(mem, "t".into(), root.clone(), opts);
        connect(&fresh, 0);
        walk(&fresh, 0, 1, &["new.txt"]);
        assert_eq!(stat(&fresh, 1), want);
        let wp = to_win32_long_path(&root.join("new.txt"));
        let h = fs::create_file(&wp, FILE_READ_EA, FILE_SHARE_RWD, OPEN_EXISTING, 0).unwrap();
        let md = fs::lx_metadata(h);
        fs::close(h);
        let _ = std::fs::remove_dir_all(&base);
        assert_eq!(
            md,
            Ok(fs::LxMetadata {
                uid: Some(want.1),
                gid: Some(want.2),
                mode: Some(want.0),
            })
        );
    }
}
