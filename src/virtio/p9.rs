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
//! Names: Windows looks names up ignoring case, while Linux programs expect
//! `a.cs` and `A.cs` to be different names. So a walk finds only the entry
//! spelled exactly as asked, case included: it opens the name as Windows does,
//! then compares the last component with the name the file system reports for
//! what it opened, as its directory stores it. That name comes in the same
//! call as the attributes the walk reads anyway, so the check costs nothing.
//! For a link, the link's own name counts; an 8.3 short name still finds its
//! file when spelled as stored. A `nocase` share looks names up as Windows
//! does. Only lookups are exact: Windows can't hold two names that differ only
//! in case, and creating, renaming or deleting by name matches as it does.
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
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
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
const T_XATTRWALK: u8 = 30;
const T_XATTRCREATE: u8 = 32;
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
const E_NOMEM: u32 = 12;
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
    /// Look names up ignoring case, as Windows does. By default a name finds
    /// only the entry spelled exactly so (see the module docs).
    pub nocase: bool,
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

/// The FILETIME of a Unix time. The guest picks both numbers (Tsetattr), so
/// a time past the end of FILETIME's range is its last tick rather than an
/// overflow. That tick is `i64::MAX`: the kernel reads a FILETIME as signed,
/// and takes -1 and -2 not for times but for orders to stop and resume
/// updating the handle's timestamps.
fn unix_to_filetime(sec: u64, nsec: u64) -> u64 {
    sec.saturating_mul(10_000_000)
        .saturating_add(nsec / 100)
        .saturating_add(FILETIME_BIAS_TO_1970)
        .min(i64::MAX as u64)
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

const SEP: u16 = b'\\' as u16;
/// `\??\`: the object manager's directory of DOS device names, where the
/// target of an absolute link begins.
const NT_DOS_DEVICES: &[u16] = &[SEP, b'?' as u16, b'?' as u16, SEP];

/// The path that `parts` make up, one after another, as its components below
/// `root` (a path from `fs::final_nt_path_by_handle`): `.` is dropped and `..`
/// takes the component before it, as Windows resolves a link's target. `None`
/// if a `..` has nothing left to take, or the path that results is not `root`
/// (which gives no components) or below it. Names compare as
/// [`normalize_for_containment`] has them.
fn steps_below(root: &[u16], parts: &[&[u16]]) -> Option<Vec<Vec<u16>>> {
    const DOT: u16 = b'.' as u16;
    let mut path: Vec<&[u16]> = Vec::new();
    for name in parts.iter().flat_map(|p| p.split(|&c| c == SEP)) {
        match name {
            [] | [DOT] => {}
            [DOT, DOT] => {
                path.pop()?;
            }
            name => path.push(name),
        }
    }
    let lower = |name: &[u16]| normalize_for_containment(name);
    let mut below = path.iter();
    for name in root.split(|&c| c == SEP).filter(|name| !name.is_empty()) {
        if lower(below.next()?) != lower(name) {
            return None;
        }
    }
    Some(below.map(|name| name.to_vec()).collect())
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
    // Win32 takes a name for a DOS device by what precedes its first dot, less
    // trailing spaces (`NUL .txt` is `NUL`), and counts the superscript digits
    // as digits (`COM¹`). The share itself never parses names that way, but a
    // host program opening such a file by its Win32 path would get the device.
    let stem = comp.split('.').next().unwrap_or(comp);
    let stem = stem.trim_end_matches(' ').to_ascii_uppercase();
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "COM¹", "COM²", "COM³", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7",
        "LPT8", "LPT9", "LPT¹", "LPT²", "LPT³",
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

/// Most host memory every open directory's readdir listing may hold at once
/// (`FidEntry::dir_cache`). A guest can open up to `MAX_FIDS` fids on one big
/// directory and start a readdir on each; past this, the listings of other
/// fids are dropped, and rebuilt if their readdir carries on.
const DIR_CACHE_BUDGET: usize = 64 << 20;

/// About how much of a directory a fid's listing holds at a time. A directory
/// that takes more is listed a stretch at a time as its readdir moves along
/// (see [`P9Device::list_dir`]), so no directory, however big, takes more
/// than this of the budget per fid, or while it is being read.
const DIR_WINDOW_BYTES: usize = 1 << 20;

/// What a listing costs against [`DIR_CACHE_BUDGET`]: the memory it holds,
/// spare capacity included.
#[allow(clippy::ptr_arg)]
fn dir_cache_bytes(cache: &Vec<DirEntryCached>) -> usize {
    cache.capacity() * std::mem::size_of::<DirEntryCached>()
        + cache.iter().map(|e| e.name.capacity()).sum::<usize>()
}

/// A stretch of a directory's listing, as [`P9Device::list_dir`] read it.
struct DirWindow {
    entries: Vec<DirEntryCached>,
    /// The place of `entries[0]` in the listing.
    base: usize,
    /// The listing ends with `entries`.
    ended: bool,
    /// How many of the listing's entries the directory handle has moved past.
    cursor: usize,
}

impl DirWindow {
    /// Take the listing's next entry, kept if the stretch has reached its
    /// start.
    fn push(&mut self, entry: DirEntryCached) {
        if self.cursor >= self.base {
            self.entries.push(entry);
        }
        self.cursor += 1;
    }
}

/// Build an Rreaddir of as many of `entries` as fit in `count` bytes. `first`
/// is the place of `entries[0]` in its directory's listing; each entry
/// carries the place of the one after it, the offset a readdir carries on
/// from.
fn build_rreaddir(
    reply: &mut Vec<u8>,
    tag: u16,
    entries: &[DirEntryCached],
    first: usize,
    count: u32,
) {
    reply.clear();
    enc4(reply, 0);
    enc1(reply, R_READDIR);
    enc2(reply, tag);
    let count_off = reply.len();
    enc4(reply, 0);
    let start_payload = reply.len();
    for (i, de) in entries.iter().enumerate() {
        let need = 13 + 8 + 1 + 2 + de.name.len();
        if (reply.len() - start_payload) + need > count as usize {
            break;
        }
        enc_qid(reply, de.qid_type, de.qid_version, de.qid_path);
        enc8(reply, (first + i + 1) as u64);
        enc1(reply, de.d_type);
        enc_str(reply, &de.name);
    }
    let payload_len = (reply.len() - start_payload) as u32;
    reply[count_off..count_off + 4].copy_from_slice(&payload_len.to_le_bytes());
    finalize(reply);
}

/// The stretch of its directory's listing a fid holds. Its bytes count toward
/// the share's running total (`Fids::dir_cache_total`) for exactly as long as
/// it lives, however it goes: clunk, remove, reopen, a walk replacing the fid,
/// eviction or a reset. Checking the budget is then O(1) rather than a sum
/// over every fid, which a guest holding many fids paid on each listing.
struct DirCache {
    entries: Vec<DirEntryCached>,
    /// The place of `entries[0]` in the listing.
    base: usize,
    /// The listing ends with `entries`.
    ended: bool,
    bytes: usize,
    total: Arc<AtomicUsize>,
}

impl DirCache {
    /// `entries` as a whole listing.
    fn new(mut entries: Vec<DirEntryCached>, total: &Arc<AtomicUsize>) -> DirCache {
        entries.shrink_to_fit();
        let bytes = dir_cache_bytes(&entries);
        total.fetch_add(bytes, Ordering::Relaxed);
        DirCache {
            entries,
            base: 0,
            ended: true,
            bytes,
            total: total.clone(),
        }
    }

    /// The entries from `offset` of the listing on, if this stretch has them
    /// or knows there are none.
    fn entries_from(&self, offset: usize) -> Option<&[DirEntryCached]> {
        let at = offset.checked_sub(self.base)?;
        if at < self.entries.len() || (at == self.entries.len() && self.ended) {
            Some(&self.entries[at..])
        } else {
            None
        }
    }
}

impl Drop for DirCache {
    fn drop(&mut self) {
        self.total.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

/// Owns a host file HANDLE and closes it exactly once on drop. Stored as an
/// `Arc<OwnedHandle>` inside a `FidEntry` so a worker can clone the `Arc` under
/// the `fids` lock and then do its blocking I/O lock-free: a concurrent `Tclunk`
/// / `Tremove` / `Trename` drops the map's `Arc`, but the real `CloseHandle` is
/// deferred until the last in-flight user drops its clone. That closes the
/// use-after-close race without serialising the concurrent worker pool.
struct OwnedHandle {
    handle: HANDLE,
    /// Held while this handle, a directory's, is listed (`P9Device::list_dir`)
    /// until the fid has what was read. A handle's place in its directory is
    /// the handle's own, so it must not move between the choice to carry on
    /// from it and the note of where it then stands: two readdirs of one
    /// handle take turns. Each handle has its own lock, so different
    /// directories are listed side by side, as many at once as there are
    /// workers. Taken before `fids`.
    listing: Mutex<()>,
}

// The only access to `handle` is `get()` (a copy of the value, used while at
// least one `Arc` ref is held) and the one-shot close in `Drop`.
unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

impl OwnedHandle {
    fn new(handle: HANDLE) -> OwnedHandle {
        OwnedHandle {
            handle,
            listing: Mutex::new(()),
        }
    }

    fn get(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        fs::close(self.handle);
    }
}

/// Most bytes every fid's path may hold at once (`FidEntry::rel`). A fid costs
/// the guest one small Twalk, and its path can be as long as NTFS lets a path
/// be (32767 UTF-16 units, some 96 KiB as stored here), so `MAX_FIDS` alone
/// lets a guest pin gigabytes. Past this, a request that would make a fid a
/// new path fails with ENOMEM. Real workloads hold a few thousand fids with
/// paths of a few hundred bytes.
const FID_PATH_BUDGET: usize = 64 << 20;

/// A fid's path below the share root. Its bytes count toward the share's
/// running total (`P9Device::fid_path_bytes`) for exactly as long as it lives,
/// however it goes: clunk, remove, a walk, create or rename replacing it,
/// Tversion or a reset. Making one reserves its bytes, so the total never
/// passes the budget.
struct FidPath {
    path: PathBuf,
    bytes: usize,
    total: Arc<AtomicUsize>,
}

impl FidPath {
    /// `path` as a fid's path; `None` if the fid paths counted in `total`
    /// would then hold more than `budget` bytes.
    fn within(mut path: PathBuf, total: &Arc<AtomicUsize>, budget: usize) -> Option<FidPath> {
        path.shrink_to_fit();
        let bytes = path.capacity();
        total
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
                held.checked_add(bytes).filter(|&sum| sum <= budget)
            })
            .ok()?;
        Some(FidPath {
            path,
            bytes,
            total: total.clone(),
        })
    }
}

impl std::ops::Deref for FidPath {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<Path> for FidPath {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl Drop for FidPath {
    fn drop(&mut self) {
        self.total.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

struct FidEntry {
    /// The file's path below the share root, empty for the root itself: made of
    /// validated components only, never `.` or `..`. Fids keep a path, not a
    /// handle, because Windows refuses to rename a directory while any handle
    /// to something under it is open.
    rel: FidPath,
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
    /// The stretch of the directory's listing the last readdir read; `None`
    /// until then, and after the budget drops it.
    dir_cache: Option<DirCache>,
    /// How many of its listing's entries the directory `handle` has moved
    /// past, which is where a listing that carries on, rather than starting
    /// over, picks up. `None` until the handle has been listed.
    dir_cursor: Option<usize>,
}

impl FidEntry {
    fn new(rel: FidPath, is_dir: bool, qid_path: u64, uid: u32) -> FidEntry {
        FidEntry {
            rel,
            is_dir,
            qid_path,
            uid,
            handle: None,
            opened: false,
            open_flags: 0,
            dir_cache: None,
            dir_cursor: None,
        }
    }

    fn drop_dir_cache(&mut self) {
        self.dir_cache = None;
    }

    /// Make `h`, opened with the Tlopen/Tlcreate `flags`, the fid's handle.
    fn open(&mut self, h: OwnedHandle, flags: u32) {
        self.handle = Some(Arc::new(h));
        self.opened = true;
        self.open_flags = flags;
        // What was listed, and how far, was the previous handle's.
        self.drop_dir_cache();
        self.dir_cursor = None;
    }

    fn close_handle(&mut self) {
        // Drop our `Arc`; the real CloseHandle runs when the last in-flight user
        // (if any) releases its clone. The `Option<Arc<OwnedHandle>>` also frees
        // the handle automatically when a `FidEntry` is dropped, so there is no
        // manual `Drop for FidEntry`.
        self.handle = None;
        self.opened = false;
        self.drop_dir_cache();
        self.dir_cursor = None;
    }
}

#[derive(Default)]
struct Fids {
    map: HashMap<u32, FidEntry>,
    /// Bytes of every fid's `dir_cache`, kept by [`DirCache`].
    dir_cache_total: Arc<AtomicUsize>,
}

impl Fids {
    /// Give fid `fid` the stretch `window` of its directory's listing, read
    /// through `handle`, and note where that left the handle. Nothing happens
    /// if the fid has since been clunked or opened anew: the handle listed is
    /// then not the one it holds.
    fn set_dir_window(&mut self, fid: u32, handle: &Arc<OwnedHandle>, window: DirWindow) {
        let Some(e) = self.map.get_mut(&fid) else {
            return;
        };
        if !e.handle.as_ref().is_some_and(|h| Arc::ptr_eq(h, handle)) {
            return;
        }
        e.dir_cursor = Some(window.cursor);
        self.set_dir_cache_within(fid, window.entries, DIR_CACHE_BUDGET);
        if let Some(cache) = self.map.get_mut(&fid).and_then(|e| e.dir_cache.as_mut()) {
            cache.base = window.base;
            cache.ended = window.ended;
        }
    }

    /// Give fid `fid` the listing `cache`, first dropping other fids'
    /// listings as needed to keep them all within `budget`. A single listing
    /// bigger than the budget is still kept: its readdir needs it.
    fn set_dir_cache_within(&mut self, fid: u32, cache: Vec<DirEntryCached>, budget: usize) {
        let Some(e) = self.map.get_mut(&fid) else {
            return;
        };
        // The listing this one replaces stops counting first, and this fid
        // then holds none, so the eviction below only drops other fids'.
        e.drop_dir_cache();
        let cache = DirCache::new(cache, &self.dir_cache_total);
        let over = |total: &AtomicUsize| total.load(Ordering::Relaxed) > budget;
        if over(&self.dir_cache_total) {
            for e in self.map.values_mut() {
                if e.dir_cache.is_some() {
                    e.drop_dir_cache();
                    if !over(&self.dir_cache_total) {
                        break;
                    }
                }
            }
        }
        if let Some(e) = self.map.get_mut(&fid) {
            e.dir_cache = Some(cache);
        }
    }
}

/// The pinned share root: its handle, and its real path (normalized, NT volume
/// name) when first pinned, the only place a deleted root is replaced from.
struct Root {
    handle: OwnedHandle,
    real: Vec<u16>,
}

/// A file [`P9Device::open_rel_ex`] opened.
struct Opened {
    handle: OwnedHandle,
    /// This open created the file.
    created: bool,
    /// The path's last component is a symlink or junction, and `handle` is
    /// what it points at, not the link.
    followed: bool,
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
/// the synchronizing barrier. A Tflush that waits for the request it flushes
/// takes a detour: its worker parks the slot in [`Flights`], whose lock then
/// stands for the slot until the worker retiring that request takes it out.
/// `t_msg`/`reply`/`bounce` are reused, so steady-state request handling
/// allocates nothing.
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
    /// The device epoch the request was taken in (see `P9Device::epoch`).
    epoch: u32,
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
            epoch: 0,
        }
    }

    /// The request's tag, if the message is long enough to have one.
    fn tag(&self) -> Option<u16> {
        let tag = self.t_msg.get(5..REPLY_HEADER_SIZE)?;
        Some(u16::from_le_bytes([tag[0], tag[1]]))
    }

    /// The tag a Tflush in this slot flushes.
    fn flushed_tag(&self) -> Option<u16> {
        let oldtag = self.t_msg.get(REPLY_HEADER_SIZE..REPLY_HEADER_SIZE + 2)?;
        Some(u16::from_le_bytes([oldtag[0], oldtag[1]]))
    }
}

/// "No slot" in the lists of [`Flights`].
const NO_SLOT: u16 = u16::MAX;

/// The requests in flight, by the slot that carries each, kept so that a
/// Tflush is answered only once the request it flushes has been: 9P forbids a
/// reply to a flushed request after its Rflush, and a client frees the
/// request's buffers on that Rflush (Linux does, see `p9_virtio_cancelled`),
/// while the workers answer requests in whatever order they finish.
///
/// A request is listed here from the moment it is taken off the ring until
/// its reply is on the used ring, both changing under this lock. So a Tflush
/// that finds its target listed parks its own slot on it, to be answered
/// right after the target by the worker that retires it; one that doesn't is
/// answered at once, the target's reply (if it ever was in flight) being out
/// already.
struct Flights {
    /// The tag and device epoch of the request each slot carries.
    request: Vec<Option<(u16, u32)>>,
    /// The slot each parked Tflush slot waits for.
    parked_on: Vec<u16>,
    /// The first and last Tflush slot parked on each slot, in arrival order.
    first: Vec<u16>,
    last: Vec<u16>,
    /// The Tflush slot parked after each one, on the same slot.
    next: Vec<u16>,
}

impl Flights {
    fn new(n: usize) -> Self {
        Flights {
            request: vec![None; n],
            parked_on: vec![NO_SLOT; n],
            first: vec![NO_SLOT; n],
            last: vec![NO_SLOT; n],
            next: vec![NO_SLOT; n],
        }
    }

    /// List the request in `slot`.
    fn begin(&mut self, slot: u16, tag: u16, epoch: u32) {
        self.request[slot as usize] = Some((tag, epoch));
    }

    /// A slot other than `not` whose request, taken in `epoch`, has `tag`.
    fn find(&self, tag: u16, epoch: u32, not: u16) -> Option<u16> {
        let found = self
            .request
            .iter()
            .enumerate()
            .position(|(i, r)| *r == Some((tag, epoch)) && i != not as usize)?;
        Some(found as u16)
    }

    /// Park `flush` on `target`. False, with nothing changed, if `target`
    /// waits for `flush` itself (two Tflushes naming each other, say), as
    /// neither would ever be answered.
    fn park(&mut self, flush: u16, target: u16) -> bool {
        let mut at = target;
        while at != NO_SLOT {
            if at == flush {
                return false;
            }
            at = self.parked_on[at as usize];
        }
        self.parked_on[flush as usize] = target;
        match self.last[target as usize] {
            NO_SLOT => self.first[target as usize] = flush,
            last => self.next[last as usize] = flush,
        }
        self.last[target as usize] = flush;
        true
    }

    /// Unlist the request in `slot`, whose reply is out. Returns the first
    /// and last of the Tflush slots that were parked on it, chained by
    /// `next`, and now the caller's to answer.
    fn end(&mut self, slot: u16) -> (u16, u16) {
        let s = slot as usize;
        self.request[s] = None;
        self.parked_on[s] = NO_SLOT;
        let parked = (self.first[s], self.last[s]);
        self.first[s] = NO_SLOT;
        self.last[s] = NO_SLOT;
        parked
    }

    /// How many Tflush slots are parked.
    #[cfg(test)]
    fn parked(&self) -> usize {
        self.parked_on.iter().filter(|&&on| on != NO_SLOT).count()
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
    /// Taken on its own or before the queue lock, never inside it.
    flights: Mutex<Flights>,
}

/// How many workers a share's pool has.
fn p9_worker_count() -> usize {
    thread::available_parallelism()
        .map(|n| n.get().clamp(2, P9_MAX_WORKERS))
        .unwrap_or(4)
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
    nocase: bool,
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
    /// Bytes of every fid's path, kept by [`FidPath`].
    fid_path_bytes: Arc<AtomicUsize>,
    /// [`DIR_WINDOW_BYTES`]; a test lists a small directory in several
    /// stretches by lowering it.
    dir_window_bytes: AtomicUsize,
    irq: OnceLock<IrqFn>,
    engine: P9Engine,
    // Reused across drain calls so submit allocates nothing (see `drain`).
    drain_chain: Mutex<ChainScratch>,
    /// Requests taken off the avail ring that have not yet settled: been
    /// retired on the used ring, or dropped. Incremented under the queue
    /// lock, so a reset either precedes a pop or sees its request here.
    active: AtomicU32,
    /// Bumped by each reset, under the queue lock. A request remembers the
    /// epoch it was taken in; one from an earlier epoch is stale: if it has
    /// not started it is dropped, else it runs to its end, and either way it
    /// writes no reply, pushes no used element and raises no interrupt, as
    /// its buffers and ring belong to the driver again (and the queue may
    /// since have been re-enabled). As for virtio-blk.
    epoch: AtomicU32,
    /// Called with each request's T-message by the thread about to handle it.
    #[cfg(test)]
    before_request: OnceLock<RequestHook>,
}

#[cfg(test)]
type RequestHook = Box<dyn Fn(&[u8]) + Send + Sync>;

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
            nocase: opts.nocase,
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
            fids: Mutex::new(Fids::default()),
            fid_path_bytes: Arc::default(),
            dir_window_bytes: AtomicUsize::new(DIR_WINDOW_BYTES),
            irq: OnceLock::new(),
            engine: P9Engine {
                iocp,
                pool: SlotPool::new(P9_QUEUE_MAX as usize),
                flights: Mutex::new(Flights::new(P9_QUEUE_MAX as usize)),
            },
            drain_chain: Mutex::new(ChainScratch::default()),
            active: AtomicU32::new(0),
            epoch: AtomicU32::new(0),
            #[cfg(test)]
            before_request: OnceLock::new(),
        });
        // Precreate the worker pool. Each worker holds a strong Arc<P9Device>
        // (the device never strong-refs the workers back, so there's no cycle);
        // they run for the process lifetime — no join, the OS reclaims at exit.
        for w in 0..p9_worker_count() {
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

    /// Wait for all in-flight 9p requests to drain (every request taken has
    /// settled and the slot pool is fully free) so a snapshot captures a
    /// consistent device, or teardown can free guest RAM — no reply landing in
    /// guest RAM / the used ring afterwards.
    /// Bounded spin: the guest is already stopped, so no new requests arrive and
    /// the worker pool completes the in-flight ones promptly. Returns false if
    /// requests are still in flight when it gives up.
    pub fn quiesce(&self) -> bool {
        let total = self.engine.pool.slots.len();
        for _ in 0..5_000 {
            if self.active.load(Ordering::Acquire) == 0
                && self.engine.pool.free.lock().unwrap().len() >= total
            {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        eprintln!("[9p] WARN: quiesce timed out with requests still in flight");
        false
    }

    fn raise(&self, qidx: u32) {
        if let Some(cb) = self.irq.get() {
            cb(qidx);
        }
    }

    fn alloc_qid_path(&self) -> u64 {
        self.next_qid_path.fetch_add(1, Ordering::Relaxed)
    }

    /// `path` as a fid's path; `None` if the share's fids already hold as
    /// many path bytes as they may (see [`FID_PATH_BUDGET`]).
    fn fid_path(&self, path: PathBuf) -> Option<FidPath> {
        FidPath::within(path, &self.fid_path_bytes, FID_PATH_BUDGET)
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
        let handle = OwnedHandle::new(fs::create_file(
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
        self.open_rel_ex(rel, how).map(|o| (o.handle, o.created))
    }

    /// [`Self::open_rel`], also telling whether a link at the end of `rel` was
    /// followed.
    fn open_rel_ex(&self, rel: &Path, how: fs::Open) -> Result<Opened, u32> {
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

    fn open_below(&self, root: HANDLE, rel: &Path, how: fs::Open) -> Result<Opened, u32> {
        match fs::open_relative(root, &rel_wide(rel), how) {
            Ok((h, created)) => Ok(Opened {
                handle: OwnedHandle::new(h),
                created,
                followed: false,
            }),
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
    /// truncated or opened for data, and no error tells what a link that
    /// leads outside leads to.
    fn open_linked(&self, root: HANDLE, rel: &Path, how: fs::Open) -> Result<Opened, u32> {
        // The root itself is not reached through a link.
        let (Some(parent), Some(name)) = (rel.parent(), rel.file_name()) else {
            return Err(ERROR_ACCESS_DENIED);
        };
        let dir = match self.open_followed(root, &rel_wide(parent), fs::Kind::Directory) {
            Ok(dir) => dir,
            Err(_) => self.open_dir_by_steps(root, parent)?,
        };
        let name: Vec<u16> = name.encode_wide().collect();
        match fs::open_relative(dir.get(), &name, how) {
            Ok((h, created)) => Ok(Opened {
                handle: OwnedHandle::new(h),
                created,
                followed: false,
            }),
            // The name exists, as a link: O_EXCL and mkdir must fail.
            Err(ERROR_REPARSE_POINT_ENCOUNTERED) if how.create == fs::Create::New => {
                Err(ERROR_ALREADY_EXISTS)
            }
            Err(ERROR_REPARSE_POINT_ENCOUNTERED) => {
                let target = self.open_link(root, dir.get(), &name, how.kind)?;
                Ok(Opened {
                    handle: OwnedHandle::new(fs::reopen(target.get(), how.access)?),
                    created: false,
                    followed: true,
                })
            }
            Err(e) => Err(e),
        }
    }

    /// Open `name` below `dir` following links, with attribute access only, and
    /// keep it only if it lies inside the share. Unless it is known to lie
    /// inside, the error is ERROR_ACCESS_DENIED whatever went wrong: a link
    /// may lead anywhere, and whether what it names is missing, a file, a
    /// directory or just out of bounds would tell the guest what exists
    /// outside the share.
    fn open_followed(&self, dir: HANDLE, name: &[u16], kind: fs::Kind) -> Result<OwnedHandle, u32> {
        let any = fs::Open::existing(0).following();
        let inside = |how: fs::Open| {
            let h = OwnedHandle::new(fs::open_relative(dir, name, how).ok()?.0);
            self.handle_contained(h.get()).then_some(h)
        };
        if let Some(h) = inside(any.with_kind(kind)) {
            return Ok(h);
        }
        // It may be there, inside the share, and just not a `kind`.
        match kind {
            fs::Kind::Directory if inside(any).is_some() => Err(ERROR_DIRECTORY),
            fs::Kind::File if inside(any).is_some() => Err(ERROR_DIRECTORY_NOT_SUPPORTED),
            _ => Err(ERROR_ACCESS_DENIED),
        }
    }

    /// [`Self::open_followed`] of the link `name` in `dir`, a directory inside
    /// the share (below `root`), saying more than ERROR_ACCESS_DENIED when
    /// more is known: see [`Self::link_missing_inside`].
    fn open_link(
        &self,
        root: HANDLE,
        dir: HANDLE,
        name: &[u16],
        kind: fs::Kind,
    ) -> Result<OwnedHandle, u32> {
        self.open_followed(dir, name, kind).map_err(|e| match e {
            ERROR_ACCESS_DENIED => self
                .link_missing_inside(root, dir, name, 0)
                .unwrap_or(ERROR_ACCESS_DENIED),
            e => e,
        })
    }

    /// Why the link `name` in `dir`, a directory inside the share, can't be
    /// followed, if that is because what it points at is missing inside the
    /// share: ERROR_FILE_NOT_FOUND or ERROR_PATH_NOT_FOUND, or ERROR_DIRECTORY
    /// where its path runs through a file. `None` otherwise.
    ///
    /// [`Self::open_followed`] can't tell a link whose target is gone from one
    /// that leads out of the share: the open just fails. Both would be
    /// "permission denied" to the guest, yet a stale link inside a tree is
    /// common, and what looks for a file through one expects "no such file".
    /// So the target is read from the link and looked up one component at a
    /// time from the root, each lookup following nothing in a directory that
    /// lies inside the share (a component that is a link itself goes through
    /// `open_followed`, and then this). What such a lookup finds is the
    /// share's own contents, which the guest may see anyway. A target that
    /// leaves the share, by `..` or by its absolute path, is not looked up at
    /// all, and one that is there after all (something else went wrong)
    /// reports nothing.
    ///
    /// `..` is taken off the path as written, with the component before it,
    /// as Windows resolves a relative link. Should that ever differ from what
    /// the kernel did, the cost is an error code: nothing here opens a name
    /// outside the share.
    fn link_missing_inside(
        &self,
        root: HANDLE,
        dir: HANDLE,
        name: &[u16],
        depth: u32,
    ) -> Option<u32> {
        /// Links whose targets are failing links, followed this far.
        const DEPTH_MAX: u32 = 8;
        if depth >= DEPTH_MAX {
            return None;
        }
        let link = fs::open_relative(dir, name, fs::Open::existing(0).as_entry()).ok()?;
        let link = OwnedHandle::new(link.0);
        let target = fs::link_target(link.get()).ok()?;
        let root_path = fs::final_nt_path_by_handle(root)?;
        let steps = match &target {
            fs::LinkTarget::Relative(t) => {
                let dir_path = fs::final_nt_path_by_handle(dir)?;
                steps_below(&root_path, &[&dir_path, t])?
            }
            fs::LinkTarget::Absolute(t) => {
                // `\??\<device>\path`: the device as the object manager maps it.
                let rest = t.strip_prefix(NT_DOS_DEVICES)?;
                let cut = rest.iter().position(|&c| c == SEP).unwrap_or(rest.len());
                let device = fs::dos_device_target(&rest[..cut])?;
                steps_below(&root_path, &[&device, &rest[cut..]])?
            }
        };
        let mut at: Option<OwnedHandle> = None;
        for (i, step) in steps.iter().enumerate() {
            let here = at.as_ref().map_or(root, OwnedHandle::get);
            // Every step but the last has to be a directory.
            let kind = if i + 1 == steps.len() {
                fs::Kind::Any
            } else {
                fs::Kind::Directory
            };
            let found = match fs::open_relative(here, step, fs::Open::existing(0).with_kind(kind)) {
                Err(ERROR_REPARSE_POINT_ENCOUNTERED) => {
                    self.open_followed(here, step, kind).map_err(|e| match e {
                        ERROR_ACCESS_DENIED => {
                            self.link_missing_inside(root, here, step, depth + 1)
                        }
                        e => Some(e),
                    })
                }
                found => found.map(|(h, _)| OwnedHandle::new(h)).map_err(Some),
            };
            match found {
                Ok(h) => at = Some(h),
                Err(Some(e @ (ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND | ERROR_DIRECTORY))) => {
                    return Some(e);
                }
                Err(_) => return None,
            }
        }
        // Every step is there (or the target is the root itself).
        None
    }

    /// Open the directory `rel` below the share root as
    /// [`Self::open_followed`] does, when that failed, a component at a time:
    /// each is looked up, following nothing, in a directory known to lie
    /// inside the share, where a failure says nothing about the outside and
    /// so is reported as it is (a missing directory is still missing); a
    /// component that is a link goes through `open_followed`.
    fn open_dir_by_steps(&self, root: HANDLE, rel: &Path) -> Result<OwnedHandle, u32> {
        let mut dir: Option<OwnedHandle> = None;
        for name in rel.components() {
            let std::path::Component::Normal(name) = name else {
                return Err(ERROR_ACCESS_DENIED);
            };
            let name: Vec<u16> = name.encode_wide().collect();
            let at = dir.as_ref().map_or(root, OwnedHandle::get);
            let how = fs::Open::existing(0).with_kind(fs::Kind::Directory);
            dir = Some(match fs::open_relative(at, &name, how) {
                Ok((h, _)) => OwnedHandle::new(h),
                Err(ERROR_REPARSE_POINT_ENCOUNTERED) => {
                    self.open_link(root, at, &name, fs::Kind::Directory)?
                }
                Err(e) => return Err(e),
            });
        }
        dir.ok_or(ERROR_ACCESS_DENIED)
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
            Some(h) => fs::reopen(h.get(), access).map(OwnedHandle::new),
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
        let w = OwnedHandle::new(fs::reopen(h, GENERIC_WRITE)?);
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
                .map(OwnedHandle::new)
                .and_then(|h2| fs::lx_metadata(h2.get()))
                .unwrap_or_default(),
            Err(_) => fs::LxMetadata::default(),
        }
    }

    /// Store the `Some` fields of `md` as the WSL metadata of the file `h`
    /// refers to.
    fn set_lx_metadata(h: HANDLE, md: fs::LxMetadata) -> Result<(), u32> {
        let h = OwnedHandle::new(fs::reopen(h, FILE_WRITE_EA)?);
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

    /// Stat a path for Twalk and Tattach, keeping no handle: qid type, version
    /// and path, and whether it is a directory. Unless the share is `nocase`,
    /// the last component must be spelled exactly as the entry it opened,
    /// case included (see the module docs).
    fn stat_rel(&self, rel: &Path) -> Result<(u8, u32, u64, bool), u32> {
        let opened = self
            .open_rel_ex(rel, fs::Open::existing(0))
            .map_err(errno_from_win32)?;
        let (info, mut name) =
            fs::file_info_and_name(opened.handle.get()).map_err(errno_from_win32)?;
        if !self.nocase
            && let Some(want) = rel.file_name()
        {
            if opened.followed {
                // The link's target may have any name; the link's own counts.
                let how = fs::Open::existing(0).as_entry();
                let (link, _) = self.open_rel(rel, how).map_err(errno_from_win32)?;
                name = fs::file_info_and_name(link.get())
                    .map_err(errno_from_win32)?
                    .1;
            }
            let found = name
                .rsplit(|&c| c == u16::from(b'\\'))
                .next()
                .unwrap_or(&[]);
            if !want.encode_wide().eq(found.iter().copied()) {
                return Err(E_NOENT);
            }
        }
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
            let (more, epoch) = {
                let mut q = self.queue.lock().unwrap();
                if !q.ready() {
                    return None;
                }
                if !q.pop_into(&mut chain) {
                    return None;
                }
                self.active.fetch_add(1, Ordering::Relaxed);
                (q.has_avail(), self.epoch.load(Ordering::Relaxed))
            };
            let Some(idx) = self.engine.pool.acquire() else {
                // Pool exhausted (a driver that keeps to its ring can't have
                // more requests in flight than there are slots): retire the
                // descriptor empty so the guest isn't wedged, then stop draining.
                if self.push_used(epoch, chain.head_index, 0) {
                    self.raise(P9_REQUEST_QUEUE);
                }
                self.settle(1);
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
            slot.epoch = epoch;
            // In flight from here on, for a Tflush to find (see `Flights`).
            if let Some(tag) = slot.tag() {
                self.engine.flights.lock().unwrap().begin(idx, tag, epoch);
            }
            if inline_ok && !more && self.engine.pool.in_use.load(Ordering::Relaxed) == 1 {
                return Some(idx);
            }
            if !sock::post(self.engine.iocp, 0, idx as usize, std::ptr::null_mut()) {
                // Posting failed: complete inline so the request isn't lost.
                self.complete_slot(idx);
            }
        }
    }

    /// Whether `epoch`, the one a request was taken in, is still the
    /// device's: no reset has ended it.
    fn current(&self, epoch: u32) -> bool {
        self.epoch.load(Ordering::Relaxed) == epoch
    }

    /// Retire `head` on the used ring, unless the epoch it was taken in has
    /// ended. Returns whether the driver wants an interrupt for it.
    fn push_used(&self, epoch: u32, head: u16, used_len: u32) -> bool {
        let mut q = self.queue.lock().unwrap();
        if !self.current(epoch) {
            return false;
        }
        q.push(head, used_len);
        q.should_interrupt_driver()
    }

    /// Copy `reply` into the writable buffers `wbufs` of a request taken in
    /// `epoch`, unless that has ended: the buffers are the driver's again.
    /// Returns the bytes written.
    fn write_reply(&self, epoch: u32, wbufs: &mut [ChainBuf], reply: &[u8]) -> u32 {
        if !self.current(epoch) {
            return 0;
        }
        write_chain(wbufs, reply)
    }

    /// `n` requests taken off the ring have settled: the device will not
    /// touch their guest buffers or the used ring for them again. Must come
    /// last.
    fn settle(&self, n: u32) {
        self.active.fetch_sub(n, Ordering::Release);
    }

    /// Run one request to completion (on a worker, or inline on the pump):
    /// handle it straight into the guest's buffers, then retire it. A Tflush
    /// of a request still in flight is parked instead, for whoever retires
    /// that request to answer.
    fn complete_slot(&self, idx: u16) {
        // SAFETY: this slot was handed to us via the IOCP (or kept by the
        // drain for inline execution); we own it until it is retired or
        // parked.
        let slot = unsafe { self.engine.pool.slot(idx) };
        slot.reply.clear();
        // Taken before a reset and not yet started: dropped. The session it
        // belonged to is over.
        if !self.current(slot.epoch) {
            return self.retire(idx, 0);
        }
        #[cfg(test)]
        if let Some(hook) = self.before_request.get() {
            hook(&slot.t_msg);
        }
        let written = match slot.t_msg.get(4).copied() {
            // Parked: the slot is not this thread's any more.
            Some(T_FLUSH) if self.park_flush(idx, slot.flushed_tag(), slot.epoch) => return,
            Some(T_READ) if slot.t_msg.len() >= REPLY_HEADER_SIZE => self.read_into_chain(slot),
            Some(T_WRITE) if !slot.rbufs.is_empty() => self.write_from_chain(slot),
            _ => {
                self.dispatch(&slot.t_msg, &mut slot.reply, slot.cap);
                self.write_reply(slot.epoch, &mut slot.wbufs, &slot.reply)
            }
        };
        self.retire(idx, written);
    }

    /// Park the Tflush of `oldtag` in slot `idx`, taken in `epoch`, on the
    /// request it flushes if that one is in flight: the worker that retires
    /// it then answers the Tflush, whose slot is its own from the moment this
    /// returns true. False if the Tflush is to be answered now: the
    /// request's reply is out already, or there is no such request.
    fn park_flush(&self, idx: u16, oldtag: Option<u16>, epoch: u32) -> bool {
        let Some(oldtag) = oldtag else {
            return false;
        };
        let mut flights = self.engine.flights.lock().unwrap();
        let parked = flights
            .find(oldtag, epoch, idx)
            .is_some_and(|target| flights.park(idx, target));
        if parked {
            self.requests.fetch_add(1, Ordering::Relaxed);
        }
        parked
    }

    /// Retire the request in slot `idx`, whose reply of `written` bytes is in
    /// its buffers: put it on the used ring and take it out of [`Flights`],
    /// in one hold of that lock, then do the same for each Tflush that was
    /// parked on it, and for those parked on them in turn. A stale request
    /// (see `epoch`) is only taken out. Raises one interrupt for them all,
    /// recycles their slots and settles them.
    fn retire(&self, idx: u16, written: u32) {
        let pool = &self.engine.pool;
        let mut interrupt = false;
        let mut settled = 0;
        {
            let mut flights = self.engine.flights.lock().unwrap();
            // The slots to retire, chained by `flights.next` from `cur` to
            // `last`, and the reply length of `cur`.
            let (mut cur, mut last, mut len) = (idx, idx, written);
            loop {
                // SAFETY: `idx` is the caller's to retire; every other slot
                // here was parked, which left it to whoever takes it out of
                // `flights` under its lock.
                let slot = unsafe { pool.slot(cur) };
                interrupt |= self.push_used(slot.epoch, slot.head_index, len);
                let (first_parked, last_parked) = flights.end(cur);
                if first_parked != NO_SLOT {
                    flights.next[last as usize] = first_parked;
                    last = last_parked;
                }
                let next = std::mem::replace(&mut flights.next[cur as usize], NO_SLOT);
                if cur != idx {
                    pool.release(cur);
                }
                settled += 1;
                if next == NO_SLOT {
                    break;
                }
                cur = next;
                // SAFETY: as above.
                let slot = unsafe { pool.slot(cur) };
                let tag = slot.tag().unwrap_or(0);
                build_header_only(&mut slot.reply, R_FLUSH, tag);
                len = self.write_reply(slot.epoch, &mut slot.wbufs, &slot.reply);
            }
        }
        pool.release(idx);
        if interrupt {
            self.raise(P9_REQUEST_QUEUE);
        }
        self.settle(settled);
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
            // Of a request that isn't in flight: one that is has the Tflush
            // wait for it (see `park_flush`).
            T_FLUSH => build_header_only(reply, R_FLUSH, tag),
            T_MKDIR => self.h_mkdir(tag, body, reply),
            T_RENAME => self.h_rename(tag, body, reply),
            T_RENAMEAT => self.h_renameat(tag, body, reply),
            T_UNLINKAT => self.h_unlinkat(tag, body, reply),
            T_STATFS => self.h_statfs(tag, body, reply),
            // Shares have no extended attributes. Say so as such a filesystem
            // does: `cp -a` skips EOPNOTSUPP, but uutils' cp fails on ENOSYS.
            T_XATTRWALK | T_XATTRCREATE => build_rlerror(reply, tag, E_OPNOTSUPP),
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
        let Some(rel) = self.fid_path(PathBuf::new()) else {
            build_rlerror(reply, tag, E_NOMEM);
            return;
        };
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
            f.map.insert(fid, FidEntry::new(rel, true, qp, uid));
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
            src_rel = src.rel.to_path_buf();
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
            // The clone's path counts like any other: a fid is cheap to
            // make, its path may be long.
            let Some(rel) = self.fid_path(src_rel) else {
                build_rlerror(reply, tag, E_NOMEM);
                return;
            };
            self.fids.lock().unwrap().map.insert(
                newfid,
                FidEntry::new(rel, src_is_dir, src_qid_path, src_uid),
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
            let Some(rel) = self.fid_path(rel) else {
                build_rlerror(reply, tag, E_NOMEM);
                return;
            };
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
            rel = e.rel.to_path_buf();
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
            e.open(h, flags);
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
            parent_rel = e.rel.to_path_buf();
            creator = e.uid;
        }
        // The path the fid will have, reserved before anything is created.
        let Some(rel) = self.fid_path(parent_rel.join(&name)) else {
            build_rlerror(reply, tag, E_NOMEM);
            return;
        };
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
            e.open(h, flags);
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
        self.write_reply(slot.epoch, &mut slot.wbufs, &slot.reply)
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
                let at = offset.saturating_add(got as u64);
                match unsafe { fs::read_at_raw(h.get(), p, n as u32, at) } {
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
                Ok(k) => {
                    // After a reset the buffers are the driver's again.
                    if self.current(slot.epoch) {
                        // SAFETY: as above; the runs cover `len` >= `k` bytes.
                        unsafe { scatter(&slot.runs, &slot.bounce[..k as usize]) };
                    }
                    k as usize
                }
                Err(e) => return self.fail_slot(slot, tag, errno_from_win32(e)),
            }
        };
        let mut hdr = [0u8; RREAD_HEADER_SIZE];
        hdr[0..4].copy_from_slice(&((RREAD_HEADER_SIZE + got) as u32).to_le_bytes());
        hdr[4] = R_READ;
        hdr[5..7].copy_from_slice(&tag.to_le_bytes());
        hdr[7..11].copy_from_slice(&(got as u32).to_le_bytes());
        self.write_reply(slot.epoch, &mut slot.wbufs, &hdr);
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
                let at = offset.saturating_add(done as u64);
                match unsafe { write_raw(h.get(), append, p, n, at) } {
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
        self.write_reply(slot.epoch, &mut slot.wbufs, &rep)
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
        let max_payload = if cap as usize > RREAD_HEADER_SIZE {
            cap - RREAD_HEADER_SIZE as u32
        } else {
            0
        };
        if count > max_payload {
            count = max_payload;
        }
        // The place in the directory's listing to read on from: 0, or the
        // offset an earlier Rreaddir gave with the entry before.
        let offset = usize::try_from(req_offset).unwrap_or(usize::MAX);

        // A readdir that carries on is served from the stretch of the listing
        // the fid holds, if that reaches so far: encoded under the lock that
        // found it, so another fid's readdir can't drop it meanwhile, and
        // with no copy of it. The loop is bounded by `count` (<= msize), so
        // the lock hold is short. A readdir from the start lists the
        // directory afresh.
        let held = |e: &FidEntry, reply: &mut Vec<u8>| {
            if offset == 0 {
                return false;
            }
            let Some(entries) = e.dir_cache.as_ref().and_then(|c| c.entries_from(offset)) else {
                return false;
            };
            build_rreaddir(reply, tag, entries, offset, count);
            true
        };
        let dir_h = {
            let f = self.fids.lock().unwrap();
            let Some(e) = f.map.get(&fid) else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            if !e.is_dir {
                build_rlerror(reply, tag, E_NOTDIR);
                return;
            }
            let Some(dir_h) = e.handle.clone().filter(|_| e.opened) else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            if held(e, reply) {
                return;
            }
            dir_h
        };

        // Read the stretch from `offset` on through the fid's directory
        // handle, one listing of it at a time (see `OwnedHandle::listing`),
        // and leave it with the fid for the chunks that follow.
        let _listing = dir_h.listing.lock().unwrap();
        let carry_on = {
            let f = self.fids.lock().unwrap();
            match f.map.get(&fid) {
                Some(e) if e.handle.as_ref().is_some_and(|h| Arc::ptr_eq(h, &dir_h)) => {
                    // Another request may have read it while this one waited.
                    if held(e, reply) {
                        return;
                    }
                    // The handle stands where this stretch starts if the one
                    // before it ended there; else the directory is read from
                    // the top again (a rewind, a seek, or a stretch the
                    // budget dropped before the guest had read it all).
                    offset != 0 && e.dir_cursor == Some(offset)
                }
                // Clunked or opened anew meanwhile: `dir_h` is this request's
                // alone, and is where nobody left it.
                _ => false,
            }
        };
        let max_bytes = self.dir_window_bytes.load(Ordering::Relaxed);
        let window = self.list_dir(dir_h.get(), offset, carry_on, max_bytes);
        build_rreaddir(reply, tag, &window.entries, offset, count);
        self.fids
            .lock()
            .unwrap()
            .set_dir_window(fid, &dir_h, window);
    }

    /// Read a stretch of the listing of the directory `dir_h`: its entries
    /// from the `start`th on, about `max_bytes` worth. `carry_on` says the
    /// handle stands at `start`, where the stretch read before this one left
    /// it; otherwise the directory is read from the top and the entries
    /// before `start` are passed over. A stretch ends where a batch of
    /// entries from the file system does, as the handle's place in the
    /// directory moves a batch at a time, so it may run past `max_bytes` by
    /// one batch (some 600 entries at most).
    ///
    /// The listing is what the handle enumerates with
    /// `FileIdBothDirectoryInfo`: each entry comes back with its 64-bit
    /// file ID, so there is **no per-entry open / GetFileInformation /
    /// Close** — one buffer-full per ~500 entries instead of ~4 syscalls per
    /// entry. (Profiled on a 5 000-entry dir: ~20 K host syscalls/readdir →
    /// ~10.) It starts with `.` and `..`: the file system's own entries where
    /// it lists them first (NTFS does, below a volume's root), made up where
    /// it lists none.
    fn list_dir(&self, dir_h: HANDLE, start: usize, carry_on: bool, max_bytes: usize) -> DirWindow {
        let mut window = DirWindow {
            entries: Vec::new(),
            base: start,
            ended: false,
            cursor: if carry_on { start } else { 0 },
        };
        // Whether the listing's `.` and `..` are behind the handle.
        let (mut dot, mut dotdot) = (carry_on, carry_on);
        let made_up = |name: &str| DirEntryCached {
            qid_type: QT_DIR,
            qid_version: 0,
            qid_path: self.alloc_qid_path(),
            d_type: DT_DIR,
            name: name.into(),
        };
        let mut dir = fs::read_dir_ids_from(dir_h, !carry_on);
        loop {
            // Never an empty stretch short of the listing's end: a readdir
            // would take it for the end.
            if dir.at_batch_end()
                && !window.entries.is_empty()
                && dir_cache_bytes(&window.entries) >= max_bytes
            {
                break;
            }
            let Some(e) = dir.next() else {
                window.ended = true;
                break;
            };
            match e.name.as_str() {
                "" => continue,
                "." if dot => continue,
                ".." if dotdot => continue,
                "." => {}
                ".." => {
                    if !dot {
                        window.push(made_up("."));
                    }
                }
                _ => {
                    if !dot {
                        window.push(made_up("."));
                    }
                    if !dotdot {
                        window.push(made_up(".."));
                    }
                    dotdot = true;
                }
            }
            dot = true;
            dotdot |= e.name == "..";
            window.push(DirEntryCached {
                qid_type: if e.is_dir { QT_DIR } else { QT_FILE },
                qid_version: 0,
                qid_path: if e.file_id != 0 {
                    e.file_id
                } else {
                    self.alloc_qid_path()
                },
                d_type: if e.is_dir { DT_DIR } else { DT_REG },
                name: e.name,
            });
        }
        if window.ended {
            if !dot {
                window.push(made_up("."));
            }
            if !dotdot {
                window.push(made_up(".."));
            }
        }
        window
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
            rel = e.rel.to_path_buf();
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
            rel = e.rel.to_path_buf();
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
            rel = e.rel.to_path_buf();
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
            parent = e.rel.to_path_buf();
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
            old_rel = src.rel.to_path_buf();
            new_parent = dir.rel.to_path_buf();
        }
        // The share root can't be moved.
        if old_rel.as_os_str().is_empty() {
            build_rlerror(reply, tag, E_ACCES);
            return;
        }
        // The path the fid will have, reserved before anything is renamed.
        let Some(new_rel) = self.fid_path(new_parent.join(&name)) else {
            build_rlerror(reply, tag, E_NOMEM);
            return;
        };
        // The fid's open handle, if any, stays valid: it follows the file.
        if let Err(e) = self.rename_entry(&old_rel, &new_parent, &name) {
            build_rlerror(reply, tag, errno_from_win32(e));
            return;
        }
        if let Some(e) = self.fids.lock().unwrap().map.get_mut(&fid) {
            e.rel = new_rel;
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
            old_dir = o.rel.to_path_buf();
            new_dir = n.rel.to_path_buf();
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
            parent = e.rel.to_path_buf();
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
        // A guest-triggered reset (status write of 0) can race with requests
        // still in flight. It must not wait for them: it runs under the
        // transport `common` lock, which a retiring request's IRQ path
        // re-takes. Instead the reset completes asynchronously (see
        // `reset_pending`), as virtio-blk's does: under the queue lock, end
        // the epoch and reset the virtqueue. A request taken before this is
        // stale (see `epoch`), as the used ring and its buffers may belong to
        // a re-enabled queue by the time it is done. The slot pool and the
        // flight list are left alone: each stale request gives back its own
        // slot, exactly once, as it settles.
        {
            let mut q = self.queue.lock().unwrap();
            self.epoch.fetch_add(1, Ordering::Relaxed);
            q.reset();
        }
        self.driver_ok.store(false, Ordering::Relaxed);
        self.acked_features.store(0, Ordering::Relaxed);
        self.negotiated_msize.store(0, Ordering::Relaxed);
        self.fids.lock().unwrap().map.clear();
    }

    fn reset_pending(&self) -> bool {
        self.active.load(Ordering::Acquire) != 0
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
            let Some(rel) = self.fid_path(rel) else {
                eprintln!(
                    "[9p] restore: fid {id} ({}) is more path than the share's fids may hold; \
                     dropping it",
                    path.display()
                );
                continue;
            };
            let mut e = FidEntry::new(rel, is_dir, qid, uid);
            if opened {
                match self.reopen_fid_handle(&e.rel, is_dir, flags) {
                    Some(h) => e.open(h, flags),
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
    use std::sync::Condvar;
    use std::time::{Duration, Instant};

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

    /// `path` as a fid's path, counted on its own.
    fn rel(path: impl Into<PathBuf>) -> FidPath {
        FidPath::within(path.into(), &Arc::default(), usize::MAX).unwrap()
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

    /// A walk finds only the entry spelled exactly as asked, case included, as
    /// on Linux, though Windows opens `a.cs` for `A.cs`. For a junction, its
    /// own name counts, not its target's. A `nocase` share ignores case.
    #[test]
    fn lookups_match_case_exactly() {
        let base = std::env::temp_dir().join(format!("tinyvmm_p9_case_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("Src")).unwrap();
        std::fs::create_dir_all(base.join("deep").join("foo")).unwrap();
        std::fs::write(base.join("a.cs"), b"lower").unwrap();
        std::fs::write(base.join("Src").join("Main.cs"), b"main").unwrap();
        let root = std::fs::canonicalize(&base).unwrap();
        let mem = std::sync::Arc::new(whpsys::memory::GuestMemory::new_host_only(4096).unwrap());
        let dev = P9Device::new(
            mem.clone(),
            "t".into(),
            root.clone(),
            ShareOptions::default(),
        );
        connect(&dev, 0);

        assert_eq!(walk_err(&dev, 0, 1, &["A.cs"]), E_NOENT);
        walk(&dev, 0, 1, &["a.cs"]);
        call(&dev, T_LOPEN, |t| {
            enc4(t, 1);
            enc4(t, O_RDONLY);
        });
        let r = call(&dev, T_READ, |t| {
            enc4(t, 1);
            enc8(t, 0);
            enc4(t, 64);
        });
        assert_eq!(&r[RREAD_HEADER_SIZE..], b"lower");
        walk(&dev, 0, 2, &["Src", "Main.cs"]);
        assert_eq!(walk_err(&dev, 0, 3, &["src", "Main.cs"]), E_NOENT);
        // A later name spelled otherwise ends the walk there, as a missing one.
        let r = call(&dev, T_WALK, |t| walk_body(t, 0, 3, &["Src", "main.cs"]));
        assert_eq!(u16::from_le_bytes([r[7], r[8]]), 1, "nwqid");

        // "Foo" leads to a directory named "foo", which "foo" must not reach.
        if junction(&base.join("Lnk"), &base.join("Src"))
            && junction(&base.join("Foo"), &base.join("deep").join("foo"))
        {
            walk(&dev, 0, 3, &["Lnk", "Main.cs"]);
            assert_eq!(walk_err(&dev, 0, 4, &["lnk"]), E_NOENT);
            walk(&dev, 0, 4, &["Foo"]);
            assert_eq!(walk_err(&dev, 0, 5, &["foo"]), E_NOENT);
        } else {
            eprintln!("[p9-test] skipping the junction cases: could not create a junction");
        }
        drop(dev);

        let opts = ShareOptions {
            nocase: true,
            ..Default::default()
        };
        let dev = P9Device::new(mem, "t".into(), root, opts);
        connect(&dev, 0);
        walk(&dev, 0, 1, &["A.CS"]);
        walk(&dev, 0, 2, &["src", "MAIN.cs"]);

        drop(dev);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Extended attributes get EOPNOTSUPP, as from a filesystem without them,
    /// so copy tools skip them: uutils' cp, Ubuntu's default, fails `cp -a`
    /// out of a share on any other error. No xattr fid is created.
    #[test]
    fn extended_attributes_are_unsupported() {
        let share = std::env::temp_dir().join(format!("tinyvmm_p9_xattr_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&share);
        std::fs::create_dir_all(&share).unwrap();
        let root = std::fs::canonicalize(&share).unwrap();
        let mem = std::sync::Arc::new(whpsys::memory::GuestMemory::new_host_only(4096).unwrap());
        let dev = P9Device::new(mem, "test".into(), root, ShareOptions::default());
        connect(&dev, 0);

        // listxattr, then getxattr: Txattrwalk with an empty name, then a name.
        for name in ["", "user.mime_type"] {
            let errno = call_err(&dev, T_XATTRWALK, |t| {
                enc4(t, 0);
                enc4(t, 1);
                enc_str(t, name);
            });
            assert_eq!(errno, E_OPNOTSUPP, "Txattrwalk {name:?}");
        }
        // setxattr.
        let errno = call_err(&dev, T_XATTRCREATE, |t| {
            enc4(t, 0);
            enc_str(t, "user.mime_type");
            enc8(t, 4);
            enc4(t, 0);
        });
        assert_eq!(errno, E_OPNOTSUPP);
        assert!(!dev.fids.lock().unwrap().map.contains_key(&1));

        drop(dev);
        let _ = std::fs::remove_dir_all(&share);
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
            let mut ef = FidEntry::new(rel("file.txt"), false, 7, 1000);
            ef.handle = Some(Arc::new(hf));
            ef.opened = true;
            ef.open_flags = O_RDONLY;
            fids.map.insert(1, ef);
            let mut ed = FidEntry::new(rel("sub"), true, 8, 0);
            ed.handle = Some(Arc::new(hd));
            ed.opened = true;
            ed.open_flags = O_RDONLY;
            fids.map.insert(2, ed);
            // A walked-but-not-opened fid: path only, no handle.
            fids.map.insert(3, FidEntry::new(rel(""), true, 1, 1001));
            let outside = Path::new("..").join("outside");
            fids.map.insert(4, FidEntry::new(rel(outside), true, 9, 0));
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
            [&*f1.rel, &*f2.rel, &*f3.rel],
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

    /// Every directory fid's readdir listing shares one memory budget: a new
    /// listing drops other fids' listings as needed, never its own, and is
    /// kept even when it alone exceeds the budget.
    #[test]
    fn directory_listings_share_a_memory_budget() {
        let listing = |n: usize| -> Vec<DirEntryCached> {
            (0..n)
                .map(|i| DirEntryCached {
                    name: format!("f{i:03}"),
                    ..Default::default()
                })
                .collect()
        };
        let budget = 3 * dir_cache_bytes(&listing(10));
        let mut f = Fids::default();
        for fid in 0..4 {
            f.map
                .insert(fid, FidEntry::new(rel(""), true, u64::from(fid), 0));
        }
        let built = |f: &Fids| -> Vec<u32> {
            let mut v: Vec<u32> = f
                .map
                .iter()
                .filter(|(_, e)| e.dir_cache.is_some())
                .map(|(k, _)| *k)
                .collect();
            v.sort();
            v
        };
        // The running total is exactly what the fids' listings hold, however
        // a listing goes.
        let total = |f: &Fids| -> usize {
            let sum = f
                .map
                .values()
                .filter_map(|e| e.dir_cache.as_ref())
                .map(|c| dir_cache_bytes(&c.entries))
                .sum();
            assert_eq!(f.dir_cache_total.load(Ordering::Relaxed), sum);
            sum
        };
        for fid in 0..3 {
            f.set_dir_cache_within(fid, listing(10), budget);
        }
        assert_eq!(built(&f), [0, 1, 2]);
        f.set_dir_cache_within(3, listing(10), budget);
        let now = built(&f);
        assert_eq!(now.len(), 3, "one listing made room: {now:?}");
        assert!(now.contains(&3));
        assert!(total(&f) <= budget, "{} > {budget}", total(&f));
        f.set_dir_cache_within(3, listing(5), budget);
        total(&f);
        f.map.remove(&now[0]);
        f.map.insert(now[1], FidEntry::new(rel(""), true, 9, 0));
        assert_eq!(total(&f), dir_cache_bytes(&listing(5)));
        f.map.insert(0, FidEntry::new(rel(""), true, 0, 0));
        f.set_dir_cache_within(0, listing(100), budget);
        assert_eq!(built(&f), [0], "an oversized listing is kept, alone");
        f.map.clear();
        assert_eq!(total(&f), 0);
    }

    /// A readdir that carries on after the budget dropped its listing lists
    /// the directory again and resumes at its offset, instead of ending the
    /// listing early.
    #[test]
    fn readdir_carries_on_after_its_listing_is_dropped() {
        let base = std::env::temp_dir().join(format!("tinyvmm_p9_rd_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let mut want: Vec<String> = vec![".".into(), "..".into()];
        for i in 0..40 {
            let name = format!("file{i:02}");
            std::fs::write(base.join(&name), b"x").unwrap();
            want.push(name);
        }
        let root = std::fs::canonicalize(&base).unwrap();
        let mem = std::sync::Arc::new(whpsys::memory::GuestMemory::new_host_only(4096).unwrap());
        let dev = P9Device::new(mem, "t".into(), root, ShareOptions::default());
        connect(&dev, 0);
        walk(&dev, 0, 1, &[]);
        call(&dev, T_LOPEN, |t| {
            enc4(t, 1);
            enc4(t, O_RDONLY);
        });
        // Rreaddir: size[4] type[1] tag[2] count[4], then entries of qid[13]
        // offset[8] type[1] name[2+n].
        let readdir = |offset: u64| -> Vec<(u64, String)> {
            let r = call(&dev, T_READDIR, |t| {
                enc4(t, 1);
                enc8(t, offset);
                enc4(t, 256);
            });
            let end = 11 + u32::from_le_bytes(r[7..11].try_into().unwrap()) as usize;
            let mut out = Vec::new();
            let mut p = 11;
            while p < end {
                let off = u64::from_le_bytes(r[p + 13..p + 21].try_into().unwrap());
                let len = u16::from_le_bytes(r[p + 22..p + 24].try_into().unwrap()) as usize;
                out.push((
                    off,
                    String::from_utf8(r[p + 24..p + 24 + len].to_vec()).unwrap(),
                ));
                p += 24 + len;
            }
            out
        };
        let mut names = Vec::new();
        let mut offset = 0;
        loop {
            let chunk = readdir(offset);
            let Some(&(last, _)) = chunk.last() else {
                break;
            };
            assert!(
                chunk.len() < want.len(),
                "the listing should take several chunks"
            );
            offset = last;
            names.extend(chunk.into_iter().map(|(_, n)| n));
            // The budget drops this fid's listing between chunks.
            dev.fids
                .lock()
                .unwrap()
                .map
                .get_mut(&1)
                .unwrap()
                .drop_dir_cache();
        }
        names.sort();
        want.sort();
        assert_eq!(names, want);
        let _ = std::fs::remove_dir_all(&base);
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

    /// Win32 takes more names for DOS devices than the bare ones: any with
    /// spaces between the device name and the first dot, and COM and LPT
    /// followed by a superscript digit. The guest can't create those either.
    #[test]
    fn names_win32_takes_for_devices_are_refused() {
        for name in [
            "NUL",
            "nul.txt",
            "NUL .txt",
            "con  .log",
            "COM1 .x",
            "lpt9 .a.b",
            "COM\u{b9}",
            "com\u{b2}.txt",
            "LPT\u{b3} .x",
            "lpt\u{b9}",
        ] {
            assert!(!is_safe_name_component(name), "{name:?}");
        }
        for name in [
            "NULL",
            "console.txt",
            "COM10",
            "LPT",
            "nul_.txt",
            "a NUL",
            " nul",
            "COM\u{2074}",
        ] {
            assert!(is_safe_name_component(name), "{name:?}");
        }
    }

    /// A Tsetattr time is the guest's to pick: one past what a FILETIME holds
    /// is the last FILETIME, not an overflow, nor one of the values the
    /// kernel takes for something other than a time.
    #[test]
    fn times_past_the_end_of_filetime_saturate() {
        let last = i64::MAX as u64;
        assert_eq!(unix_to_filetime(0, 0), FILETIME_BIAS_TO_1970);
        assert_eq!(unix_to_filetime(1, 500), FILETIME_BIAS_TO_1970 + 10_000_005);
        assert_eq!(unix_to_filetime(u64::MAX, 999_999_999), last);
        assert_eq!(unix_to_filetime(u64::MAX / 10_000_000, u64::MAX), last);
        // No overflow, but past the last tick.
        assert_eq!(unix_to_filetime(1_000_000_000_000, 0), last);
    }

    /// Rgetattr's errno for `fid`.
    fn getattr_err(dev: &P9Device, fid: u32) -> u32 {
        call_err(dev, T_GETATTR, |t| {
            enc4(t, fid);
            enc8(t, STATS_BASIC);
        })
    }

    #[test]
    fn a_link_target_is_placed_below_the_root_by_its_text() {
        let w = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
        // The steps joined by `/`, or None.
        let steps = |root: &str, parts: &[&str]| {
            let parts: Vec<Vec<u16>> = parts.iter().map(|p| w(p)).collect();
            let parts: Vec<&[u16]> = parts.iter().map(Vec::as_slice).collect();
            steps_below(&w(root), &parts).map(|steps| {
                let names: Vec<String> =
                    steps.iter().map(|s| String::from_utf16_lossy(s)).collect();
                names.join("/")
            })
        };
        let some = |s: &str| Some(s.to_string());
        let root = r"\Device\HarddiskVolume3\Work\Share";
        let dir = r"\Device\HarddiskVolume3\Work\Share\a\b";

        // A relative target, from the directory its link is in.
        assert_eq!(steps(root, &[dir, r"x"]), some("a/b/x"));
        assert_eq!(steps(root, &[dir, r"..\c\.\x"]), some("a/c/x"));
        // Up to the root, which is no step at all, and no further.
        assert_eq!(steps(root, &[dir, r"..\.."]), some(""));
        assert_eq!(steps(root, &[dir, r"..\..\..\Other\x"]), None);
        assert_eq!(steps(root, &[dir, r"..\..\..\..\..\..\..\x"]), None);
        // Out of the share and back in by its own name is in.
        assert_eq!(steps(root, &[dir, r"..\..\..\SHARE\x"]), some("x"));
        // A neighbour whose name begins as the root's does is not.
        assert_eq!(steps(root, &[dir, r"..\..\..\Share2\x"]), None);

        // An absolute target: its device as mapped, then its path, in the
        // case it was written in.
        let volume = r"\Device\HarddiskVolume3";
        assert_eq!(steps(root, &[volume, r"\WORK\share\Sub\f"]), some("Sub/f"));
        assert_eq!(steps(root, &[volume, r"\Work\Share\a\..\..\x"]), None);
        assert_eq!(
            steps(root, &[r"\Device\HarddiskVolume4", r"\Work\Share\x"]),
            None
        );
        assert_eq!(
            steps(root, &[r"\Device\Mup", r"\server\Work\Share\x"]),
            None
        );
        // A whole volume shared: its path ends in a separator.
        assert_eq!(
            steps(r"\Device\HarddiskVolume3\", &[volume, r"\a\b"]),
            some("a/b")
        );
    }

    /// A link whose target is gone is missing, as any name that isn't there,
    /// when the target would lie inside the share: what looks for a file
    /// through a stale link gets "no such file". One that leads out of the
    /// share, or would, still tells nothing.
    #[test]
    fn a_stale_link_inside_the_share_is_just_missing() {
        use std::os::windows::fs::symlink_file;
        let base = std::env::temp_dir().join(format!("tinyvmm_p9_stale_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("share").join("sub").join("there")).unwrap();
        std::fs::create_dir_all(base.join("outside")).unwrap();
        // Real paths: a link's absolute target is matched with the root's by
        // its text, and the temporary directory may be named by a short name.
        let real = |p: PathBuf| {
            let p = std::fs::canonicalize(p).unwrap();
            PathBuf::from(p.to_str().unwrap().trim_start_matches(r"\\?\"))
        };
        let (share, outside) = (real(base.join("share")), real(base.join("outside")));
        let sub = share.join("sub");
        std::fs::write(sub.join("file"), b"a file").unwrap();
        for gone in [sub.join("gone"), outside.join("gone")] {
            std::fs::create_dir(gone).unwrap();
        }
        if !junction(&share.join("in_gone"), &sub.join("gone"))
            || !junction(&share.join("out_gone"), &outside.join("gone"))
            || !junction(&share.join("in_there"), &sub.join("there"))
        {
            eprintln!("[p9-test] skipping: could not create a directory junction");
            let _ = std::fs::remove_dir_all(&base);
            return;
        }
        for gone in [sub.join("gone"), outside.join("gone")] {
            std::fs::remove_dir(gone).unwrap();
        }

        let mem = std::sync::Arc::new(whpsys::memory::GuestMemory::new_host_only(4096).unwrap());
        let root = std::fs::canonicalize(&share).unwrap();
        let dev = P9Device::new(mem, "t".into(), root, ShareOptions::default());
        connect(&dev, 0);

        // A junction (its target is an absolute path) to nothing: inside the
        // share, outside it, and a name below each.
        assert_eq!(walk_err(&dev, 0, 9, &["in_gone"]), E_NOENT);
        assert_eq!(walk_err(&dev, 0, 9, &["in_gone", "x"]), E_NOENT);
        assert_eq!(walk_err(&dev, 0, 9, &["out_gone"]), E_ACCES);
        assert_eq!(walk_err(&dev, 0, 9, &["out_gone", "x"]), E_ACCES);

        // Symlinks, where this process may create them: in the root (fid 0)
        // or in `sub` (fid 1), each with its target and what a walk to it
        // must say.
        walk(&dev, 0, 1, &["sub"]);
        let mut links = vec![
            share.join("in_gone"),
            share.join("out_gone"),
            share.join("in_there"),
        ];
        let abs_gone = sub.join("nofile").to_str().unwrap().to_string();
        let cases: [(u32, &str, &str, u32); 12] = [
            // Relative targets: beside the link, below it, above it.
            (0, "rel_gone", r"sub\nofile", E_NOENT),
            (0, "rel_deep", r"sub\nodir\nofile", E_NOENT),
            (1, "up", r"..\nofile", E_NOENT),
            // Out of the share by `..`, at once or after a look inside.
            (0, "rel_out", r"..\outside\nofile", E_ACCES),
            (0, "rel_out2", r"sub\..\..\outside\nofile", E_ACCES),
            (1, "up_out", r"..\..\nofile", E_ACCES),
            // A file where the target's path needs a directory.
            (0, "through_file", r"sub\file\x", E_NOTDIR),
            // Through other links: a stale one, one that stays inside, one
            // that leads out, and two that lead to each other.
            (0, "chain", r"rel_gone", E_NOENT),
            (0, "via_in", r"in_there\nofile", E_NOENT),
            (0, "via_out", r"out_gone\x", E_ACCES),
            (0, "loop_a", r"loop_b", E_ACCES),
            // An absolute target inside the share.
            (0, "abs_gone", &abs_gone, E_NOENT),
        ];
        let dir_of = |fid: u32| if fid == 0 { share.clone() } else { sub.clone() };
        if symlink_file(r"loop_a", share.join("loop_b")).is_ok() {
            links.push(share.join("loop_b"));
            for (dir, link, target, _) in &cases {
                symlink_file(target, dir_of(*dir).join(link)).unwrap();
                links.push(dir_of(*dir).join(link));
            }
            for (dir, link, target, errno) in &cases {
                assert_eq!(
                    walk_err(&dev, *dir, 9, &[link]),
                    *errno,
                    "{link} -> {target}"
                );
            }
            // The target appears: the links lead to it.
            std::fs::write(sub.join("nofile"), b"now there").unwrap();
            for (fid, link) in ["rel_gone", "chain", "abs_gone"].iter().enumerate() {
                walk(&dev, 0, 20 + fid as u32, &[link]);
            }
        } else {
            eprintln!("[p9-test] skipping the symlink cases: no privilege to create one");
        }
        std::fs::create_dir(sub.join("gone")).unwrap();
        walk(&dev, 0, 40, &["in_gone"]);

        drop(dev);
        for link in links {
            let _ = std::fs::remove_dir(&link).or_else(|_| std::fs::remove_file(&link));
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// What a link that leads out of the share leads to stays unknown: an
    /// operation through it fails the same way whether the path beyond the
    /// link names a directory, a file or nothing at all. Inside the share,
    /// through a link or not, the errors are what they were.
    #[test]
    fn a_link_out_of_the_share_tells_nothing_of_what_is_there() {
        let base = std::env::temp_dir().join(format!("tinyvmm_p9_oracle_{}", std::process::id()));
        let (share, outside) = (base.join("share"), base.join("outside"));
        let _ = std::fs::remove_dir_all(&base);
        for dir in ["dir", "file", "none"] {
            std::fs::create_dir_all(share.join("a").join(dir)).unwrap();
            std::fs::write(share.join("a").join(dir).join("x"), b"inside").unwrap();
        }
        for dir in ["d", "e"] {
            std::fs::create_dir_all(share.join("sub").join(dir)).unwrap();
            std::fs::write(share.join("sub").join(dir).join("x"), b"inside").unwrap();
        }
        std::fs::create_dir_all(outside.join("dir")).unwrap();
        std::fs::create_dir_all(outside.join("gone")).unwrap();
        std::fs::write(outside.join("file"), b"outside").unwrap();
        if !junction(&share.join("link"), &share.join("sub"))
            || !junction(&share.join("to_dir"), &outside.join("dir"))
            || !junction(&share.join("to_gone"), &outside.join("gone"))
        {
            eprintln!("[p9-test] skipping: could not create a directory junction");
            let _ = std::fs::remove_dir_all(&base);
            return;
        }
        std::fs::remove_dir(outside.join("gone")).unwrap();

        let root = std::fs::canonicalize(&share).unwrap();
        let mem = std::sync::Arc::new(whpsys::memory::GuestMemory::new_host_only(4096).unwrap());
        let dev = P9Device::new(mem, "t".into(), root, ShareOptions::default());
        connect(&dev, 0);
        // Fids from before `a` turned into a link out of the share: beyond
        // it, their paths name a directory, a file and nothing.
        walk(&dev, 0, 1, &["a", "dir", "x"]);
        walk(&dev, 0, 2, &["a", "file", "x"]);
        walk(&dev, 0, 3, &["a", "none", "x"]);
        // And fids through a link that stays inside.
        walk(&dev, 0, 4, &["link", "d", "x"]);
        walk(&dev, 0, 5, &["link", "e", "x"]);
        walk(&dev, 0, 6, &["link"]);
        walk(&dev, 0, 7, &[]);
        std::fs::rename(share.join("a"), share.join("a_real")).unwrap();
        if !junction(&share.join("a"), &outside) {
            eprintln!("[p9-test] skipping: could not create a directory junction");
            let _ = std::fs::remove_dir_all(&base);
            return;
        }
        let create = |name: &str| {
            call_err(&dev, T_LCREATE, |t| {
                enc4(t, 7);
                enc_str(t, name);
                enc4(t, O_WRONLY);
                enc4(t, 0o644);
                enc4(t, 0);
            })
        };

        assert_eq!(
            [
                getattr_err(&dev, 1),
                getattr_err(&dev, 2),
                getattr_err(&dev, 3)
            ],
            [E_ACCES; 3]
        );
        // A link to a directory outside, and one to nothing there.
        assert_eq!(walk_err(&dev, 0, 9, &["to_dir"]), E_ACCES);
        assert_eq!(walk_err(&dev, 0, 9, &["to_gone"]), E_ACCES);
        // A file can't be created over either, as over any directory: a
        // junction is one itself, wherever it leads.
        assert_eq!([create("to_dir"), create("to_gone")], [E_ISDIR; 2]);
        assert!(!outside.join("gone").exists());

        // Inside the share: a name missing below a link, a file created over
        // a link, and a directory on a fid's path that has gone, or turned
        // into a file.
        assert_eq!(walk_err(&dev, 6, 9, &["missing"]), E_NOENT);
        assert_eq!(create("link"), E_ISDIR);
        std::fs::remove_dir_all(share.join("sub").join("d")).unwrap();
        std::fs::remove_dir_all(share.join("sub").join("e")).unwrap();
        std::fs::write(share.join("sub").join("e"), b"a file now").unwrap();
        assert_eq!(getattr_err(&dev, 4), E_NOENT);
        assert_eq!(getattr_err(&dev, 5), E_NOTDIR);

        drop(dev);
        for link in ["a", "link", "to_dir", "to_gone"] {
            let _ = std::fs::remove_dir(share.join(link));
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The bytes the fids' paths hold, checked against the share's count.
    fn fid_path_bytes(dev: &P9Device) -> usize {
        let f = dev.fids.lock().unwrap();
        let sum: usize = f.map.values().map(|e| e.rel.bytes).sum();
        assert_eq!(dev.fid_path_bytes.load(Ordering::Relaxed), sum);
        sum
    }

    /// The share's count of fid path bytes is what the fids hold, however a
    /// path comes or goes: a walk to a new fid or over its own, a clone, a
    /// rename, a create, a clunk, a remove, Tversion and a reset.
    #[test]
    fn fid_paths_are_counted_as_they_come_and_go() {
        let base = std::env::temp_dir().join(format!("tinyvmm_p9_fidbytes_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("dir").join("sub")).unwrap();
        std::fs::write(base.join("dir").join("a.txt"), b"a").unwrap();
        let root = std::fs::canonicalize(&base).unwrap();
        let mem = std::sync::Arc::new(whpsys::memory::GuestMemory::new_host_only(4096).unwrap());
        let dev = P9Device::new(mem, "t".into(), root, ShareOptions::default());
        let (dir, sub, a, b) = (
            3,
            r"dir\sub".len(),
            r"dir\a.txt".len(),
            r"dir\sub\b.txt".len(),
        );

        connect(&dev, 0);
        assert_eq!(fid_path_bytes(&dev), 0, "the root's path is empty");
        walk(&dev, 0, 1, &["dir"]);
        walk(&dev, 1, 2, &["sub"]);
        walk(&dev, 2, 3, &[]);
        walk(&dev, 0, 4, &["dir", "a.txt"]);
        assert_eq!(fid_path_bytes(&dev), dir + 2 * sub + a);
        // Fid 3 walks over itself, up to `dir`.
        walk(&dev, 3, 3, &[".."]);
        assert_eq!(fid_path_bytes(&dev), 2 * dir + sub + a);
        // Fid 4's file moves to `dir\sub\b.txt`.
        call(&dev, T_RENAME, |t| {
            enc4(t, 4);
            enc4(t, 2);
            enc_str(t, "b.txt");
        });
        assert_eq!(fid_path_bytes(&dev), 2 * dir + sub + b);
        // Fid 5, the root, becomes the file it creates.
        walk(&dev, 0, 5, &[]);
        lcreate(&dev, 5, "new.txt", O_WRONLY, 0o644, 0);
        assert_eq!(fid_path_bytes(&dev), 2 * dir + sub + b + "new.txt".len());
        call(&dev, T_CLUNK, |t| enc4(t, 2));
        call(&dev, T_REMOVE, |t| enc4(t, 5));
        assert_eq!(fid_path_bytes(&dev), 2 * dir + b);
        connect(&dev, 0);
        assert_eq!(fid_path_bytes(&dev), 0, "Tversion drops every fid");
        walk(&dev, 0, 1, &["dir"]);
        assert_eq!(fid_path_bytes(&dev), dir);
        dev.reset();
        assert_eq!(fid_path_bytes(&dev), 0, "a reset drops every fid");

        drop(dev);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A fid costs the guest one small Twalk, while its path may be tens of
    /// kilobytes, so the paths of a share's fids have a byte budget. At the
    /// budget a walk, a clone, a create and a rename that need a longer path
    /// fail with ENOMEM, before they do anything, until fids give paths back.
    #[test]
    fn fid_paths_stop_at_their_budget() {
        let base =
            std::env::temp_dir().join(format!("tinyvmm_p9_fidbudget_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let root = std::fs::canonicalize(&base).unwrap();
        // A path of some 1.9 KiB: eight directories with 240-byte names.
        let names: Vec<String> = (0..8).map(|i| format!("{i}{}", "d".repeat(239))).collect();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        let deep: PathBuf = names.iter().collect();
        std::fs::create_dir_all(root.join(&deep)).unwrap();
        std::fs::write(root.join("f"), b"f").unwrap();
        let mem = std::sync::Arc::new(whpsys::memory::GuestMemory::new_host_only(4096).unwrap());
        let dev = P9Device::new(mem, "t".into(), root.clone(), ShareOptions::default());
        let held = || dev.fid_path_bytes.load(Ordering::Relaxed);

        connect(&dev, 0);
        walk(&dev, 0, 1, &names);
        walk(&dev, 0, 2, &names[..1]);
        // Clones of the long path, then of a short one, until neither fits.
        let mut clone = 10;
        for (fid, len) in [(1, deep.as_os_str().len()), (2, names[0].len())] {
            for _ in 0..(FID_PATH_BUDGET - held()) / len {
                walk(&dev, fid, clone, &[]);
                clone += 1;
            }
            assert_eq!(walk_err(&dev, fid, clone, &[]), E_NOMEM);
            assert_eq!(walk_err(&dev, 0, clone, &names), E_NOMEM);
        }
        assert!(clone < MAX_FIDS as u32, "the fid count ran out first");
        assert!(held() <= FID_PATH_BUDGET, "{} bytes", held());
        fid_path_bytes(&dev);

        // A fid's path can't grow past it either, and nothing is created or
        // renamed for the path that didn't fit. The short ones still do.
        let long = format!("{}.txt", "n".repeat(250));
        walk(&dev, 0, 3, &[]);
        walk(&dev, 0, 4, &["f"]);
        let create = call_err(&dev, T_LCREATE, |t| {
            enc4(t, 3);
            enc_str(t, &long);
            enc4(t, O_WRONLY);
            enc4(t, 0o644);
            enc4(t, 0);
        });
        let rename = call_err(&dev, T_RENAME, |t| {
            enc4(t, 4);
            enc4(t, 0);
            enc_str(t, &long);
        });
        assert_eq!([create, rename], [E_NOMEM; 2]);
        assert!(!root.join(&long).exists() && root.join("f").exists());

        // A clunk makes room for the path it gave back.
        call(&dev, T_CLUNK, |t| enc4(t, 10));
        walk(&dev, 1, 10, &[]);
        connect(&dev, 0);
        assert_eq!(held(), 0);

        drop(dev);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The offsets and names of the entries of fid `fid`'s directory that an
    /// Rreaddir of `count` bytes holds from `offset` on.
    fn readdir(dev: &P9Device, fid: u32, offset: u64, count: u32) -> Vec<(u64, String)> {
        let r = call(dev, T_READDIR, |t| {
            enc4(t, fid);
            enc8(t, offset);
            enc4(t, count);
        });
        // Rreaddir: size[4] type[1] tag[2] count[4], then entries of qid[13]
        // offset[8] type[1] name[2+n].
        let end = 11 + u32::from_le_bytes(r[7..11].try_into().unwrap()) as usize;
        let mut out = Vec::new();
        let mut p = 11;
        while p < end {
            let off = u64::from_le_bytes(r[p + 13..p + 21].try_into().unwrap());
            let len = u16::from_le_bytes(r[p + 22..p + 24].try_into().unwrap()) as usize;
            out.push((
                off,
                String::from_utf8(r[p + 24..p + 24 + len].to_vec()).unwrap(),
            ));
            p += 24 + len;
        }
        out
    }

    /// A directory too big for one stretch of a listing is read a stretch at
    /// a time as the readdir moves through it: the fid never holds it all,
    /// yet every entry comes exactly once, at consecutive offsets, and a seek
    /// back or a rewind finds the same entries again.
    #[test]
    fn a_big_directory_is_listed_a_stretch_at_a_time() {
        let base = std::env::temp_dir().join(format!("tinyvmm_p9_bigdir_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        // Some four batches of entries from the file system.
        let mut want: Vec<String> = vec![".".into(), "..".into()];
        for i in 0..2000 {
            let name = format!("f{i:04}");
            std::fs::write(base.join(&name), b"").unwrap();
            want.push(name);
        }
        let root = std::fs::canonicalize(&base).unwrap();
        let mem = std::sync::Arc::new(whpsys::memory::GuestMemory::new_host_only(4096).unwrap());
        let dev = P9Device::new(mem, "t".into(), root, ShareOptions::default());
        // Every batch is a stretch of its own.
        dev.dir_window_bytes.store(1, Ordering::Relaxed);
        connect(&dev, 0);
        walk(&dev, 0, 1, &[]);
        call(&dev, T_LOPEN, |t| {
            enc4(t, 1);
            enc4(t, O_RDONLY);
        });

        let mut names = Vec::new();
        let mut stretches = std::collections::BTreeSet::new();
        let mut most = 0;
        let mut offset = 0;
        loop {
            let chunk = readdir(&dev, 1, offset, 4096);
            let Some(&(last, _)) = chunk.last() else {
                break;
            };
            for (i, (off, _)) in chunk.iter().enumerate() {
                assert_eq!(*off, offset + i as u64 + 1);
            }
            offset = last;
            names.extend(chunk.into_iter().map(|(_, n)| n));
            let f = dev.fids.lock().unwrap();
            let cache = f.map[&1].dir_cache.as_ref().unwrap();
            stretches.insert(cache.base);
            most = most.max(cache.entries.len());
            assert_eq!(f.dir_cache_total.load(Ordering::Relaxed), cache.bytes);
            assert_eq!(cache.bytes, dir_cache_bytes(&cache.entries));
        }
        let mut sorted = names.clone();
        sorted.sort();
        want.sort();
        assert_eq!(sorted, want);
        assert!(stretches.len() >= 3, "stretches at {stretches:?}");
        assert!(most < 1000, "the fid held {most} entries at once");

        // A seek back to a stretch the fid no longer holds, a rewind, and
        // offsets at and past the end.
        assert_eq!(readdir(&dev, 1, 5, 4096)[0], (6, names[5].clone()));
        assert_eq!(readdir(&dev, 1, 700, 4096)[0], (701, names[700].clone()));
        assert_eq!(readdir(&dev, 1, 0, 4096)[0], (1, names[0].clone()));
        assert!(readdir(&dev, 1, names.len() as u64, 4096).is_empty());
        assert!(readdir(&dev, 1, 1 << 40, 4096).is_empty());

        drop(dev);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A listing counts against the budget for the memory it holds, spare
    /// capacity included, not just for its names.
    #[test]
    fn a_listing_counts_for_the_memory_it_holds() {
        let mut name = String::with_capacity(100);
        name.push('x');
        let mut listing = Vec::with_capacity(50);
        listing.push(DirEntryCached {
            name,
            ..Default::default()
        });
        assert!(dir_cache_bytes(&listing) >= 50 * std::mem::size_of::<DirEntryCached>() + 100);
    }

    /// One directory handle is listed by one request at a time (its place in
    /// the directory is the handle's), while other directories are listed
    /// meanwhile: a listing under way holds up only readdirs of its own
    /// handle.
    #[test]
    fn a_listing_holds_up_only_its_own_directory() {
        let base = std::env::temp_dir().join(format!("tinyvmm_p9_onedir_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dirs = 2u32;
        for d in 0..dirs {
            std::fs::create_dir_all(base.join(format!("d{d}"))).unwrap();
        }
        let root = std::fs::canonicalize(&base).unwrap();
        let mem = std::sync::Arc::new(whpsys::memory::GuestMemory::new_host_only(4096).unwrap());
        let dev = P9Device::new(mem, "t".into(), root, ShareOptions::default());
        connect(&dev, 0);
        for d in 0..dirs {
            let name = format!("d{d}");
            walk(&dev, 0, 1 + d, &[name.as_str()]);
            call(&dev, T_LOPEN, |t| {
                enc4(t, 1 + d);
                enc4(t, O_RDONLY);
            });
        }
        let handle = |fid: u32| {
            let f = dev.fids.lock().unwrap();
            f.map[&fid].handle.clone().unwrap()
        };
        let (held, other) = (1, 2);

        // As if a listing of `held`'s directory were under way.
        let h = handle(held);
        let listing = h.listing.lock().unwrap();
        let read = |fid: u32| {
            let (tx, rx) = std::sync::mpsc::channel();
            let dev = dev.clone();
            let reader = thread::spawn(move || tx.send(readdir(&dev, fid, 0, 4096).len()).unwrap());
            (rx, reader)
        };
        let (other_rx, other_reader) = read(other);
        assert_eq!(
            other_rx.recv_timeout(Duration::from_secs(10)),
            Ok(2),
            "another directory waited for this one's listing"
        );
        let (held_rx, held_reader) = read(held);
        assert!(
            held_rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "a directory was read while a listing of it was under way"
        );
        drop(listing);
        assert_eq!(held_rx.recv_timeout(Duration::from_secs(10)), Ok(2));
        other_reader.join().unwrap();
        held_reader.join().unwrap();

        drop(dev);
        let _ = std::fs::remove_dir_all(&base);
    }

    // ---- requests through the virtqueue ----

    const NEXT: u16 = 1;
    const WRITE: u16 = 2;
    /// The entries of a test [`Ring`].
    const RING: u16 = P9_QUEUE_MAX as u16;

    /// A share over a fresh directory, with guest RAM for a couple of rings.
    fn ring_device(name: &str) -> (PathBuf, Arc<GuestMemory>, Arc<P9Device>) {
        let base = std::env::temp_dir().join(format!("tinyvmm_p9_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let root = std::fs::canonicalize(&base).unwrap();
        let mem = Arc::new(GuestMemory::new_host_only(2 << 20).unwrap());
        let dev = P9Device::new(mem.clone(), "t".into(), root, ShareOptions::default());
        (base, mem, dev)
    }

    /// A split virtqueue in guest RAM: the descriptor table at `self.0`, then
    /// the avail ring, the used ring and each request's two buffers (its
    /// T-message, then room for the reply), a page apart.
    #[derive(Clone, Copy)]
    struct Ring(u64);

    impl Ring {
        /// The size of a request's buffers.
        const BUF: u64 = 0x100;

        fn avail(self) -> u64 {
            self.0 + 0x1000
        }
        fn used(self) -> u64 {
            self.0 + 0x2000
        }
        fn enable(self, dev: &P9Device) {
            dev.enable_queue(
                P9_REQUEST_QUEUE,
                self.0,
                self.avail(),
                self.used(),
                RING,
                false,
            );
        }
        /// The descriptor that heads request `slot`'s chain.
        fn head(self, slot: u16) -> u16 {
            slot * 2
        }
        fn reply_gpa(self, slot: u16) -> u64 {
            self.0 + 0x3000 + u64::from(slot) * 2 * Self::BUF + Self::BUF
        }
        fn desc(self, mem: &GuestMemory, i: u16, addr: u64, len: u32, flags: u16) {
            let mut d = [0u8; 16];
            d[0..8].copy_from_slice(&addr.to_le_bytes());
            d[8..12].copy_from_slice(&len.to_le_bytes());
            d[12..14].copy_from_slice(&flags.to_le_bytes());
            d[14..16].copy_from_slice(&(i + 1).to_le_bytes());
            mem.write_at(self.0 + u64::from(i) * 16, &d).unwrap();
        }
        /// Make chain `head` the ring's `slot`th request and publish it.
        fn publish(self, mem: &GuestMemory, slot: u16, head: u16) {
            let entry = self.avail() + 4 + u64::from(slot % RING) * 2;
            mem.write_at(entry, &head.to_le_bytes()).unwrap();
            mem.write_at(self.avail() + 2, &(slot + 1).to_le_bytes())
                .unwrap();
        }
        /// Publish `t_msg` as the ring's `slot`th request, without a kick. Its
        /// reply buffer is preset to 0xEE.
        fn request(self, mem: &GuestMemory, slot: u16, t_msg: &[u8]) {
            assert!(slot < RING / 2 && t_msg.len() <= Self::BUF as usize);
            let msg = self.reply_gpa(slot) - Self::BUF;
            mem.write_at(msg, t_msg).unwrap();
            mem.write_at(self.reply_gpa(slot), &[0xEE; Self::BUF as usize])
                .unwrap();
            let head = self.head(slot);
            self.desc(mem, head, msg, t_msg.len() as u32, NEXT);
            self.desc(mem, head + 1, self.reply_gpa(slot), Self::BUF as u32, WRITE);
            self.publish(mem, slot, head);
        }
        fn used_idx(self, mem: &GuestMemory) -> u16 {
            u16::from_le_bytes(mem.read_array::<2>(self.used() + 2).unwrap())
        }
        /// The chain and the reply length of the `i`th request retired.
        fn used_elem(self, mem: &GuestMemory, i: u16) -> (u16, u32) {
            let at = self.used() + 4 + u64::from(i % RING) * 8;
            let e = mem.read_array::<8>(at).unwrap();
            (
                u32::from_le_bytes(e[0..4].try_into().unwrap()) as u16,
                u32::from_le_bytes(e[4..8].try_into().unwrap()),
            )
        }
        /// The chains retired so far, in order.
        fn retired(self, mem: &GuestMemory) -> Vec<u16> {
            (0..self.used_idx(mem))
                .map(|i| self.used_elem(mem, i).0)
                .collect()
        }
        /// The type and tag of the reply to request `slot`: (0xEE, 0xEEEE)
        /// while its buffer is untouched.
        fn reply(self, mem: &GuestMemory, slot: u16) -> (u8, u16) {
            let r = mem.read_array::<7>(self.reply_gpa(slot)).unwrap();
            (r[4], u16::from_le_bytes([r[5], r[6]]))
        }
    }

    /// A T-message of type `mtype` tagged `tag`.
    fn t_msg(mtype: u8, tag: u16, body: impl Fn(&mut Vec<u8>)) -> Vec<u8> {
        let mut t = Vec::new();
        enc4(&mut t, 0);
        enc1(&mut t, mtype);
        enc2(&mut t, tag);
        body(&mut t);
        finalize(&mut t);
        t
    }

    fn tversion(tag: u16) -> Vec<u8> {
        t_msg(T_VERSION, tag, |t| {
            enc4(t, 8192);
            enc_str(t, "9P2000.L");
        })
    }

    fn tflush(tag: u16, oldtag: u16) -> Vec<u8> {
        t_msg(T_FLUSH, tag, |t| enc2(t, oldtag))
    }

    /// Where a test holds requests on the way into their handlers.
    #[derive(Default)]
    struct Gate {
        open: Mutex<bool>,
        opened: Condvar,
        arrived: AtomicUsize,
    }

    impl Gate {
        /// How many requests have reached the gate.
        fn arrived(&self) -> usize {
            self.arrived.load(Ordering::SeqCst)
        }
        fn open(&self) {
            *self.open.lock().unwrap() = true;
            self.opened.notify_all();
        }
        fn pass(&self) {
            self.arrived.fetch_add(1, Ordering::SeqCst);
            let open = self.open.lock().unwrap();
            let _held = self
                .opened
                .wait_timeout_while(open, Duration::from_secs(30), |open| !*open)
                .unwrap();
        }
    }

    /// Have `dev` hold the requests whose tag `held` picks at a gate, each on
    /// the thread about to handle it, until the gate is opened.
    fn hold(dev: &P9Device, held: impl Fn(u16) -> bool + Send + Sync + 'static) -> Arc<Gate> {
        let gate = Arc::new(Gate::default());
        let at = gate.clone();
        let hook = move |t_msg: &[u8]| {
            if t_msg.len() >= REPLY_HEADER_SIZE && held(u16::from_le_bytes([t_msg[5], t_msg[6]])) {
                at.pass();
            }
        };
        assert!(dev.before_request.set(Box::new(hook)).is_ok());
        gate
    }

    fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn parked(dev: &P9Device) -> usize {
        dev.engine.flights.lock().unwrap().parked()
    }

    /// A Tflush is answered only after the request it flushes: its Rflush
    /// tells the client that no reply to that request will follow, and Linux
    /// then frees the request and its buffers. Meanwhile it is parked, not
    /// kept on a worker, so other requests are answered; a Tflush of the
    /// Tflush follows it in turn.
    #[test]
    fn rflush_follows_the_reply_to_the_request_it_flushes() {
        let (base, mem, dev) = ring_device("flush");
        let ring = Ring(0x1_0000);
        ring.enable(&dev);
        let gate = hold(&dev, |tag| tag == 7);
        ring.request(&mem, 0, &tversion(7));
        dev.notify_queue(P9_REQUEST_QUEUE);
        wait_until("the request to reach its handler", || gate.arrived() == 1);

        ring.request(&mem, 1, &tflush(8, 7));
        ring.request(&mem, 2, &tflush(9, 8));
        ring.request(&mem, 3, &tversion(10));
        dev.notify_queue(P9_REQUEST_QUEUE);
        wait_until(
            "the Tflushes to be parked and the bystander answered",
            || parked(&dev) == 2 && ring.used_idx(&mem) == 1,
        );
        assert_eq!(ring.retired(&mem), [ring.head(3)]);
        assert_eq!(ring.reply(&mem, 3), (R_VERSION, 10));
        for slot in 0..3 {
            assert_eq!(ring.reply(&mem, slot), (0xEE, 0xEEEE), "request {slot}");
        }

        gate.open();
        wait_until("the request and its Tflushes to be answered", || {
            ring.used_idx(&mem) == 4
        });
        assert_eq!(
            ring.retired(&mem)[1..],
            [ring.head(0), ring.head(1), ring.head(2)]
        );
        assert_eq!(ring.reply(&mem, 0), (R_VERSION, 7));
        assert_eq!(ring.reply(&mem, 1), (R_FLUSH, 8));
        assert_eq!(ring.reply(&mem, 2), (R_FLUSH, 9));
        assert_eq!(ring.used_elem(&mem, 2).1, REPLY_HEADER_SIZE as u32);
        assert!(dev.quiesce(), "a slot stayed in use");
        assert_eq!(parked(&dev), 0);

        drop(dev);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Two Tflushes that name each other, as only a hostile guest sends, can't
    /// each wait for the other: one is answered at once, the other right
    /// after it, and neither keeps its slot.
    #[test]
    fn tflushes_naming_each_other_are_both_answered() {
        let (base, mem, dev) = ring_device("flushring");
        let ring = Ring(0x1_0000);
        ring.enable(&dev);
        // Both are in flight before either is looked at.
        let gate = hold(&dev, |_| true);
        ring.request(&mem, 0, &tflush(20, 21));
        ring.request(&mem, 1, &tflush(21, 20));
        dev.notify_queue(P9_REQUEST_QUEUE);
        wait_until("both to reach their handlers", || gate.arrived() == 2);
        gate.open();
        wait_until("both to be answered", || ring.used_idx(&mem) == 2);
        assert_eq!(ring.reply(&mem, 0), (R_FLUSH, 20));
        assert_eq!(ring.reply(&mem, 1), (R_FLUSH, 21));
        assert!(dev.quiesce(), "a slot stayed in use");
        assert_eq!(parked(&dev), 0);

        drop(dev);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The flight list on its own: Tflushes parked on a request come back in
    /// the order they arrived when it ends, a tag two requests carry (which
    /// the protocol forbids) leaves nothing behind, and no slot ever waits
    /// for itself through others.
    #[test]
    fn flights_park_in_order_and_never_in_a_ring() {
        let mut f = Flights::new(8);
        f.begin(0, 5, 0);
        f.begin(1, 5, 0);
        f.begin(2, 6, 0);
        f.begin(3, 7, 0);
        f.begin(4, 8, 0);
        assert_eq!(f.find(5, 0, 2), Some(0));
        assert_eq!(f.find(5, 0, 0), Some(1), "the other request tagged 5");
        assert_eq!(f.find(5, 1, 2), None, "a request of another epoch");
        assert_eq!(f.find(6, 0, 2), None, "the Tflush itself");
        // 2 and 3 flush 0; 4 flushes 3.
        assert!(f.park(2, 0) && f.park(3, 0) && f.park(4, 3));
        assert_eq!(f.parked(), 3);
        // 0 can't then wait for any of them, nor 3 for 4.
        assert!(!f.park(0, 2) && !f.park(0, 4) && !f.park(3, 4));
        assert_eq!(f.parked(), 3);

        assert_eq!(f.end(1), (NO_SLOT, NO_SLOT));
        assert_eq!(f.end(0), (2, 3));
        assert_eq!((f.next[2], f.next[3]), (3, NO_SLOT));
        assert_eq!(f.end(2), (NO_SLOT, NO_SLOT));
        assert_eq!(f.end(3), (4, 4));
        assert_eq!(f.end(4), (NO_SLOT, NO_SLOT));
        assert_eq!(f.parked(), 0);
        assert!(f.request.iter().all(Option::is_none));
        assert!(f.first.iter().chain(&f.last).all(|&s| s == NO_SLOT));
    }

    /// A guest can publish one chain over and over and so have more requests
    /// in flight than there are slots. The one too many is retired empty;
    /// the others are all answered, and every slot comes back.
    #[test]
    fn a_request_beyond_the_slot_pool_is_retired_empty() {
        let (base, mem, dev) = ring_device("slots");
        let ring = Ring(0x1_0000);
        ring.enable(&dev);
        let gate = hold(&dev, |_| true);
        ring.request(&mem, 0, &tversion(7));
        for slot in 1..RING {
            ring.publish(&mem, slot, ring.head(0));
        }
        dev.notify_queue(P9_REQUEST_QUEUE);
        assert_eq!(
            dev.engine.pool.in_use.load(Ordering::Relaxed),
            u32::from(RING)
        );
        assert_eq!(ring.used_idx(&mem), 0);

        ring.publish(&mem, RING, ring.head(0));
        dev.notify_queue(P9_REQUEST_QUEUE);
        assert_eq!(ring.retired(&mem), [ring.head(0)]);
        assert_eq!(ring.used_elem(&mem, 0).1, 0);
        assert!(dev.reset_pending(), "requests are in flight");

        gate.open();
        wait_until("every request to settle", || !dev.reset_pending());
        assert_eq!(ring.used_idx(&mem), RING + 1);
        assert!(dev.quiesce(), "a slot stayed in use");

        drop(dev);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A reset restarts the virtqueue, as for every other device: the queue
    /// serves nothing until the driver enables it again, and then starts at
    /// the top of the driver's new ring, not where the old one had got to.
    #[test]
    fn a_reset_restarts_the_virtqueue() {
        let (base, mem, dev) = ring_device("reset");
        let (old, fresh) = (Ring(0x1_0000), Ring(0x4_0000));
        old.enable(&dev);
        for slot in 0..3 {
            old.request(&mem, slot, &tversion(slot + 1));
        }
        dev.notify_queue(P9_REQUEST_QUEUE);
        wait_until("three replies", || old.used_idx(&mem) == 3);
        wait_until("them to settle", || !dev.reset_pending());
        assert_eq!(dev.requests_handled(), 3);

        dev.reset();
        let q = dev.capture_queue(P9_REQUEST_QUEUE).unwrap();
        assert!(!q.ready, "the queue outlived the reset");
        assert_eq!((q.last_avail, q.last_used_idx), (0, 0));
        // A late doorbell, then the driver's new, still empty ring.
        dev.notify_queue(P9_REQUEST_QUEUE);
        fresh.enable(&dev);
        dev.notify_queue(P9_REQUEST_QUEUE);
        assert!(dev.quiesce());
        assert_eq!(
            dev.requests_handled(),
            3,
            "requests taken from an empty ring"
        );
        assert_eq!((old.used_idx(&mem), fresh.used_idx(&mem)), (3, 0));

        fresh.request(&mem, 0, &tversion(9));
        dev.notify_queue(P9_REQUEST_QUEUE);
        wait_until("a reply on the new ring", || fresh.used_idx(&mem) == 1);
        assert_eq!(fresh.retired(&mem), [fresh.head(0)]);
        assert_eq!(fresh.reply(&mem, 0), (R_VERSION, 9));

        drop(dev);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Reset with requests in flight, then enable a fresh queue at once (as a
    /// driver that doesn't wait for the reset might). Those a worker had
    /// started run to their end, the others are dropped, and none touches
    /// the guest: no reply in its buffers, nothing on either used ring. The
    /// reset is pending until they have all settled.
    #[test]
    fn a_reset_makes_requests_in_flight_harmless() {
        let (base, mem, dev) = ring_device("resetbusy");
        let (old, fresh) = (Ring(0x1_0000), Ring(0x4_0000));
        old.enable(&dev);
        let gate = hold(&dev, |tag| tag == 7);
        // More requests than workers: each worker holds one in its handler's
        // doorway, the rest wait for a worker.
        let workers = p9_worker_count();
        let requests = 20;
        assert!(workers < usize::from(requests));
        for slot in 0..requests {
            old.request(&mem, slot, &tversion(7));
        }
        dev.notify_queue(P9_REQUEST_QUEUE);
        wait_until("every worker to hold a request", || {
            gate.arrived() == workers
        });

        dev.reset();
        assert!(dev.reset_pending());
        fresh.enable(&dev);
        gate.open();
        wait_until("the reset to settle", || !dev.reset_pending());
        assert_eq!(
            dev.requests_handled(),
            workers as u64,
            "a request not yet started ran after the reset"
        );
        assert_eq!((old.used_idx(&mem), fresh.used_idx(&mem)), (0, 0));
        for slot in 0..requests {
            assert_eq!(old.reply(&mem, slot), (0xEE, 0xEEEE), "request {slot}");
        }
        assert!(dev.quiesce(), "a slot stayed in use");

        // The new queue works.
        fresh.request(&mem, 0, &tversion(9));
        dev.notify_queue(P9_REQUEST_QUEUE);
        wait_until("a reply on the new ring", || fresh.used_idx(&mem) == 1);
        assert_eq!(fresh.reply(&mem, 0), (R_VERSION, 9));

        drop(dev);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A Tflush parked on a request when the device is reset settles with it,
    /// as silently.
    #[test]
    fn a_reset_silences_a_parked_tflush_too() {
        let (base, mem, dev) = ring_device("resetflush");
        let (old, fresh) = (Ring(0x1_0000), Ring(0x4_0000));
        old.enable(&dev);
        let gate = hold(&dev, |tag| tag == 7);
        old.request(&mem, 0, &tversion(7));
        dev.notify_queue(P9_REQUEST_QUEUE);
        wait_until("the request to reach its handler", || gate.arrived() == 1);
        old.request(&mem, 1, &tflush(8, 7));
        dev.notify_queue(P9_REQUEST_QUEUE);
        wait_until("the Tflush to be parked", || parked(&dev) == 1);

        dev.reset();
        assert!(dev.reset_pending());
        fresh.enable(&dev);
        gate.open();
        wait_until("the reset to settle", || !dev.reset_pending());
        assert_eq!((old.used_idx(&mem), fresh.used_idx(&mem)), (0, 0));
        for slot in 0..2 {
            assert_eq!(old.reply(&mem, slot), (0xEE, 0xEEEE), "request {slot}");
        }
        assert_eq!(parked(&dev), 0);
        assert!(dev.quiesce(), "a slot stayed in use");

        drop(dev);
        let _ = std::fs::remove_dir_all(&base);
    }
}
