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
//! Security: a share root is trusted (the operator chose it). We sanitise each
//! path component (reject separators / NUL / reserved DOS names) and resolve
//! ".."/"." against the wire path so a guest cannot escape the share.

#![allow(clippy::too_many_arguments)]

use crate::virtio::device::{
    DEVICE_ID_P9, FEATURE_RING_EVENT_IDX, FEATURE_VERSION_1, VirtioDevice,
};
use crate::virtio::queue::{ChainBuf, ChainScratch, Virtqueue};
use crate::whp::GuestMemory;
use std::collections::HashMap;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use std::cell::UnsafeCell;
use std::thread;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
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
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;

const V9FS_MAGIC: u32 = 0x0102_1997;
const FILETIME_BIAS_TO_1970: u64 = 116_444_736_000_000_000;
const REPLY_HEADER_SIZE: usize = 7;
const RREAD_HEADER_SIZE: usize = 11; // 7 hdr + 4 count
const MAX_WALK_NAMES: u16 = 16;

// ---- Win32 flag / error values (defined locally to avoid import churn) ----
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_LIST_DIRECTORY: u32 = 0x0001;
const FILE_APPEND_DATA: u32 = 0x0004;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
const FILE_SHARE_RWD: u32 = 0x0000_0007; // READ | WRITE | DELETE
const OPEN_EXISTING: u32 = 3;
const CREATE_NEW: u32 = 1;
const CREATE_ALWAYS: u32 = 2;
const OPEN_ALWAYS: u32 = 4;
const TRUNCATE_EXISTING: u32 = 5;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFF_FFFF;
const MOVEFILE_REPLACE_EXISTING: u32 = 0x01;
const MOVEFILE_COPY_ALLOWED: u32 = 0x02;
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
const ERROR_OPERATION_ABORTED: u32 = 995;
const ERROR_NOT_READY: u32 = 21;
const ERROR_WRITE_PROTECT: u32 = 19;
const ERROR_NOT_SUPPORTED: u32 = 50;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_TOO_MANY_OPEN_FILES: u32 = 4;
const ERROR_NEGATIVE_SEEK: u32 = 131;

pub type IrqFn = Box<dyn Fn(u32) + Send + Sync>;

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
        ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION => E_ACCES,
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
        ERROR_DIRECTORY => E_NOTDIR,
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

/// Lexically normalise (lowercase + backslash + strip trailing) for the
/// containment prefix check. Inputs are already free of `.`/`..` (Twalk
/// resolves them), so no canonicalisation is needed.
fn normalize_for_containment(p: &Path) -> Vec<u16> {
    let mut w: Vec<u16> = p.as_os_str().encode_wide().collect();
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

fn join_child(base: &Path, child: &str) -> PathBuf {
    base.join(child)
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
    host_path: PathBuf,
    is_dir: bool,
    qid_path: u64,
    /// `None` = not open. Shared so in-flight I/O keeps the handle alive past a
    /// concurrent clunk/remove/rename (see [`OwnedHandle`]).
    handle: Option<Arc<OwnedHandle>>,
    opened: bool,
    open_flags: u32,
    dir_cache: Vec<DirEntryCached>,
    dir_cache_built: bool,
}

impl FidEntry {
    fn new(host_path: PathBuf, is_dir: bool, qid_path: u64) -> FidEntry {
        FidEntry {
            host_path,
            is_dir,
            qid_path,
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
/// the synchronizing barrier. `t_msg`/`reply` are reused, so steady-state
/// request handling allocates nothing.
struct P9Slot {
    t_msg: Vec<u8>,
    reply: Vec<u8>,
    wbufs: Vec<ChainBuf>,
    head_index: u16,
    cap: u32,
}

/// Preallocated slot pool + free-list, sized to the max ring depth so an
/// acquire can never fail (the guest cannot have more requests in flight than
/// the ring holds).
struct SlotPool {
    slots: Vec<UnsafeCell<P9Slot>>,
    free: Mutex<Vec<u16>>,
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
            slots.push(UnsafeCell::new(P9Slot {
                t_msg: Vec::new(),
                reply: Vec::new(),
                wbufs: Vec::new(),
                head_index: 0,
                cap: 0,
            }));
        }
        SlotPool {
            slots,
            free: Mutex::new((0..n as u16).rev().collect()),
        }
    }
    fn acquire(&self) -> Option<u16> {
        self.free.lock().unwrap().pop()
    }
    fn release(&self, i: u16) {
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
    readonly: bool,
    share_root_norm: Vec<u16>,
    config_bytes: Vec<u8>,
    driver_ok: AtomicBool,
    acked_features: AtomicU64,
    negotiated_msize: AtomicU32,
    next_qid_path: AtomicU64,
    requests: AtomicU64,
    rlerrors: AtomicU64,
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
        readonly: bool,
    ) -> Arc<Self> {
        let share_root_norm = normalize_for_containment(&host_root);
        let mut config_bytes = Vec::with_capacity(2 + tag.len());
        let n = tag.len().min(0xFFFF);
        config_bytes.extend_from_slice(&(n as u16).to_le_bytes());
        config_bytes.extend_from_slice(&tag.as_bytes()[..n]);
        let iocp = sock::create_iocp().expect("virtio-9p: CreateIoCompletionPort failed");
        let dev = Arc::new(P9Device {
            queue: Mutex::new(Virtqueue::new(_mem, P9_QUEUE_MAX)),
            tag,
            host_root,
            readonly,
            share_root_norm,
            config_bytes,
            driver_ok: AtomicBool::new(false),
            acked_features: AtomicU64::new(0),
            negotiated_msize: AtomicU32::new(0),
            next_qid_path: AtomicU64::new(1),
            requests: AtomicU64::new(0),
            rlerrors: AtomicU64::new(0),
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

    fn path_contained(&self, p: &Path) -> bool {
        let pn = normalize_for_containment(p);
        let root = &self.share_root_norm;
        if pn.len() < root.len() {
            return false;
        }
        if pn[..root.len()] != root[..] {
            return false;
        }
        if pn.len() == root.len() {
            return true;
        }
        pn[root.len()] == b'\\' as u16
    }

    /// Re-check containment against the *real* path of an opened handle. The
    /// lexical [`path_contained`] check runs on the guest-supplied path, but
    /// `CreateFileW` follows reparse points (symlinks / NTFS junctions). A
    /// reparse point that lives lexically inside the share but targets a
    /// directory outside it would pass the lexical check yet open an external
    /// file. `GetFinalPathNameByHandleW` resolves the handle to its true path
    /// (`\\?\C:\...`, same canonical form as the share root, which is
    /// `std::fs::canonicalize`d at construction), so re-running the prefix check
    /// on that real path closes the symlink/junction escape. Fails closed: if
    /// the path can't be resolved, treat as not contained. This restores parity
    /// with the C++ backend's `weakly_canonical`-based normalization.
    fn handle_contained(&self, h: HANDLE) -> bool {
        match fs::final_path_by_handle(h) {
            Some(real) => {
                let os = std::ffi::OsString::from_wide(&real);
                self.path_contained(Path::new(&os))
            }
            None => false,
        }
    }

    // Open a handle for attribute-only queries (works on directories too).
    //
    // NOTE: the per-call `handle_contained` (GetFinalPathNameByHandle, ≈5
    // internal QueryInfo) is the dominant cost of `Twalk`/`Tgetattr`, but it
    // CANNOT be skipped via `FILE_FLAG_OPEN_REPARSE_POINT` + last-component
    // attribute check: that flag only suppresses traversal of the *final*
    // component, so an intermediate junction retargeted by a host process
    // (the B1 TOCTOU) would still be followed and the attribute check on the
    // landed-on file wouldn't see it. The safe optimisation is relative-open
    // (`NtCreateFile` with `RootDirectory` = parent fid's validated handle +
    // `OPEN_REPARSE_POINT` on the single new component) — that's the B1 fix
    // and the perf fix in one, left as follow-up.
    fn open_for_attrs(&self, p: &Path) -> Result<HANDLE, u32> {
        let w = to_win32_long_path(p);
        let h = fs::create_file(
            &w,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_RWD,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
        )?;
        // The path was lexically contained, but the open may have traversed a
        // reparse point out of the share. Validate the resolved handle path.
        if !self.handle_contained(h) {
            fs::close(h);
            return Err(ERROR_ACCESS_DENIED);
        }
        Ok(h)
    }

    /// Reopen a fid's host handle on restore from its saved (path, is_dir,
    /// open_flags). Uses `OPEN_EXISTING` (never `TRUNCATE_EXISTING` — any
    /// truncation already happened pre-snapshot and is reflected in captured
    /// RAM/disk) and the same access derivation as `h_lopen`, then re-validates
    /// containment. Returns null on failure (the fid is left unopened; the guest
    /// just re-errors on its next use of that fid).
    fn reopen_fid_handle(&self, path: &Path, is_dir: bool, open_flags: u32) -> HANDLE {
        let acc = open_flags & O_ACCMODE;
        let want_append = open_flags & O_APPEND != 0;
        let access = if is_dir {
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES
        } else {
            match acc {
                O_RDONLY => GENERIC_READ,
                O_WRONLY => {
                    if want_append {
                        FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES
                    } else {
                        GENERIC_WRITE
                    }
                }
                O_RDWR => {
                    GENERIC_READ
                        | if want_append {
                            FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES
                        } else {
                            GENERIC_WRITE
                        }
                }
                _ => return core::ptr::null_mut(),
            }
        };
        let flags_attr = if is_dir {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            FILE_ATTRIBUTE_NORMAL
        };
        let wp = to_win32_long_path(path);
        match fs::create_file(&wp, access, FILE_SHARE_RWD, OPEN_EXISTING, flags_attr) {
            Ok(h) => {
                if self.handle_contained(h) {
                    h
                } else {
                    fs::close(h);
                    core::ptr::null_mut()
                }
            }
            Err(_) => core::ptr::null_mut(),
        }
    }

    // Stat a path (no kept handle): fill qid type/path + is_dir.
    fn stat_path_for_fid(&self, p: &Path) -> Result<(u8, u64, bool), u32> {
        let h = self.open_for_attrs(p).map_err(errno_from_win32)?;
        let info = match fs::file_info(h) {
            Ok(i) => i,
            Err(e) => {
                fs::close(h);
                return Err(errno_from_win32(e));
            }
        };
        fs::close(h);
        let is_dir = info.attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        let qt = if is_dir { QT_DIR } else { QT_FILE };
        let mut qp = info.file_index;
        if qp == 0 {
            qp = self.alloc_qid_path();
        }
        Ok((qt, qp, is_dir))
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
            0,
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
    /// Pop every available request and hand each to the worker pool. Runs on the
    /// doorbell pump thread (or the MMIO-fallback vCPU thread); never blocks on
    /// I/O and never pushes the used ring — a worker does that on completion.
    fn drain(&self) {
        // Reuse one PoppedChain across the whole drain AND across drain calls so
        // submit never allocates: each popped chain is copied into the slot's
        // reused t_msg/wbufs before the next pop. Holding `drain_chain` (instead
        // of the queue lock) serialises the rare concurrent drain without
        // extending the contended queue-lock hold time.
        let mut chain = self.drain_chain.lock().unwrap();
        loop {
            {
                let mut q = self.queue.lock().unwrap();
                if !q.ready() {
                    return;
                }
                if !q.pop_into(&mut chain) {
                    return;
                }
            }
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
                return;
            };
            // SAFETY: we just acquired `idx` and own it until we post it. The
            // writable descriptors stay valid until the worker pushes the used
            // ring, so copying them now (and writing through them later) is sound.
            let slot = unsafe { self.engine.pool.slot(idx) };
            read_chain(&chain.bufs, &mut slot.t_msg, P9_MSIZE_MAX as usize);
            slot.cap = writable_capacity(&chain.bufs);
            slot.head_index = chain.head_index;
            slot.wbufs.clear();
            slot.wbufs
                .extend(chain.bufs.iter().filter(|b| b.write).copied());
            if !sock::post(self.engine.iocp, 0, idx as usize, std::ptr::null_mut()) {
                // Posting failed: complete inline so the request isn't lost.
                self.complete_slot(idx);
            }
        }
    }

    /// Run one posted request to completion (on a worker thread): dispatch into
    /// the slot's reply buffer, write it to guest RAM, push the used ring, raise
    /// the IRQ, then recycle the slot.
    fn complete_slot(&self, idx: u16) {
        // SAFETY: this slot was handed to us via the IOCP; we own it until release.
        let slot = unsafe { self.engine.pool.slot(idx) };
        slot.reply.clear();
        self.dispatch(&slot.t_msg, &mut slot.reply, slot.cap);
        let written = write_chain(&mut slot.wbufs, &slot.reply);
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

        let neg = self.negotiated_msize.load(Ordering::Relaxed);
        // Bound the reply by the negotiated msize, or — before T_version — by the
        // protocol ceiling, so a pre-negotiation Tread/Treaddir with a multi-GB
        // writable descriptor can't drive a giant `reply.resize` (alloc failure
        // → VMM abort).
        let mut cap = writable_cap.min(P9_MSIZE_MAX);
        if neg != 0 && neg < cap {
            cap = neg;
        }

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
        let (Some(fid), Some(afid), Some(_uname), Some(aname), Some(_n_uname)) =
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
        let (qt, qp, is_dir) = match self.stat_path_for_fid(&self.host_root) {
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
            f.map
                .insert(fid, FidEntry::new(self.host_root.clone(), true, qp));
        }
        reply.clear();
        enc4(reply, 0);
        enc1(reply, R_ATTACH);
        enc2(reply, tag);
        enc_qid(reply, qt, 0, qp);
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

        let (src_path, src_is_dir, src_qid_path);
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
            src_path = src.host_path.clone();
            src_is_dir = src.is_dir;
            src_qid_path = src.qid_path;
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
            self.fids
                .lock()
                .unwrap()
                .map
                .insert(newfid, FidEntry::new(src_path, src_is_dir, src_qid_path));
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

        let mut cur = src_path;
        let mut qids: Vec<(u8, u64)> = Vec::with_capacity(nwname as usize);
        for (i, name) in wnames.iter().enumerate() {
            let next: PathBuf = if name == "." {
                cur.clone()
            } else if name == ".." {
                if normalize_for_containment(&cur) == self.share_root_norm {
                    cur.clone()
                } else {
                    let p = cur
                        .parent()
                        .map(|x| x.to_path_buf())
                        .unwrap_or_else(|| cur.clone());
                    if !self.path_contained(&p) {
                        self.host_root.clone()
                    } else {
                        p
                    }
                }
            } else {
                if !is_safe_name_component(name) {
                    if i == 0 {
                        build_rlerror(reply, tag, E_NOENT);
                        return;
                    }
                    break;
                }
                let p = join_child(&cur, name);
                if !self.path_contained(&p) {
                    if i == 0 {
                        build_rlerror(reply, tag, E_NOENT);
                        return;
                    }
                    break;
                }
                p
            };
            let (qt, qp, isd) = match self.stat_path_for_fid(&next) {
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
            qids.push((qt, qp));
            cur = next;
        }

        if qids.len() == nwname as usize {
            let (qt, qp) = *qids.last().unwrap();
            self.fids
                .lock()
                .unwrap()
                .map
                .insert(newfid, FidEntry::new(cur, qt & QT_DIR != 0, qp));
        }

        reply.clear();
        enc4(reply, 0);
        enc1(reply, R_WALK);
        enc2(reply, tag);
        enc2(reply, qids.len() as u16);
        for (qt, qp) in &qids {
            enc_qid(reply, *qt, 0, *qp);
        }
        finalize(reply);
    }

    fn h_lopen(&self, tag: u16, body: &[u8], reply: &mut Vec<u8>) {
        let mut d = Dec::new(body);
        let (Some(fid), Some(flags)) = (d.u32(), d.u32()) else {
            build_rlerror(reply, tag, E_PROTO);
            return;
        };
        let (host_path, is_dir, qid_path, already_open);
        {
            let f = self.fids.lock().unwrap();
            let Some(e) = f.map.get(&fid) else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            host_path = e.host_path.clone();
            is_dir = e.is_dir;
            qid_path = e.qid_path;
            already_open = e.opened;
        }
        if already_open {
            build_rlerror(reply, tag, E_INVAL);
            return;
        }
        let acc = flags & O_ACCMODE;
        let want_write = acc != O_RDONLY;
        let want_trunc = flags & O_TRUNC != 0;
        let want_append = flags & O_APPEND != 0;
        let want_dir = flags & O_DIRECTORY != 0;
        if want_dir && !is_dir {
            build_rlerror(reply, tag, E_NOTDIR);
            return;
        }
        if self.readonly && (want_write || want_trunc) {
            build_rlerror(reply, tag, E_ROFS);
            return;
        }
        let access = if is_dir {
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES
        } else {
            match acc {
                O_RDONLY => GENERIC_READ,
                O_WRONLY => {
                    if want_append {
                        FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES
                    } else {
                        GENERIC_WRITE
                    }
                }
                O_RDWR => {
                    GENERIC_READ
                        | if want_append {
                            FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES
                        } else {
                            GENERIC_WRITE
                        }
                }
                _ => {
                    build_rlerror(reply, tag, E_INVAL);
                    return;
                }
            }
        };
        let disposition = if want_trunc && !is_dir {
            TRUNCATE_EXISTING
        } else {
            OPEN_EXISTING
        };
        let flags_attr = if is_dir {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            FILE_ATTRIBUTE_NORMAL
        };
        let wp = to_win32_long_path(&host_path);
        let h = match fs::create_file(&wp, access, FILE_SHARE_RWD, disposition, flags_attr) {
            Ok(h) => h,
            Err(e) => {
                build_rlerror(reply, tag, errno_from_win32(e));
                return;
            }
        };
        // Re-validate against the real path: the open may have followed a
        // reparse point out of the share (the lexical walk check can't see it).
        if !self.handle_contained(h) {
            fs::close(h);
            build_rlerror(reply, tag, E_ACCES);
            return;
        }
        {
            let mut f = self.fids.lock().unwrap();
            let Some(e) = f.map.get_mut(&fid) else {
                fs::close(h);
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            if e.opened {
                fs::close(h);
                build_rlerror(reply, tag, E_INVAL);
                return;
            }
            e.handle = Some(Arc::new(OwnedHandle(h)));
            e.opened = true;
            e.open_flags = flags;
        }
        let qt = if is_dir { QT_DIR } else { QT_FILE };
        reply.clear();
        enc4(reply, 0);
        enc1(reply, R_LOPEN);
        enc2(reply, tag);
        enc_qid(reply, qt, 0, qid_path);
        enc4(reply, 0); // iounit
        finalize(reply);
    }

    fn h_lcreate(&self, tag: u16, body: &[u8], reply: &mut Vec<u8>) {
        let mut d = Dec::new(body);
        let (Some(fid), Some(name), Some(flags), Some(_mode), Some(_gid)) =
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
        let parent_path;
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
            parent_path = e.host_path.clone();
        }
        let new_path = join_child(&parent_path, &name);
        if !self.path_contained(&new_path) {
            build_rlerror(reply, tag, E_INVAL);
            return;
        }
        let acc = flags & O_ACCMODE;
        let want_append = flags & O_APPEND != 0;
        let mut access = GENERIC_WRITE | FILE_READ_ATTRIBUTES;
        if acc == O_RDWR || acc == O_RDONLY {
            access |= GENERIC_READ;
        }
        if want_append {
            access = (access & !GENERIC_WRITE) | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES;
        }
        let excl = flags & O_EXCL != 0;
        let trunc = flags & O_TRUNC != 0;
        let disposition = if excl {
            CREATE_NEW
        } else if trunc {
            CREATE_ALWAYS
        } else {
            OPEN_ALWAYS
        };
        let wp = to_win32_long_path(&new_path);
        let h = match fs::create_file(
            &wp,
            access,
            FILE_SHARE_RWD,
            disposition,
            FILE_ATTRIBUTE_NORMAL,
        ) {
            Ok(h) => h,
            Err(e) => {
                build_rlerror(reply, tag, errno_from_win32(e));
                return;
            }
        };
        // A pre-existing reparse point at this name (non-exclusive create) could
        // have been followed out of the share — validate the real handle path.
        if !self.handle_contained(h) {
            fs::close(h);
            build_rlerror(reply, tag, E_ACCES);
            return;
        }
        let mut qp = match fs::file_info(h) {
            Ok(info) => info.file_index,
            Err(e) => {
                let e = errno_from_win32(e);
                fs::close(h);
                build_rlerror(reply, tag, e);
                return;
            }
        };
        if qp == 0 {
            qp = self.alloc_qid_path();
        }
        {
            let mut f = self.fids.lock().unwrap();
            let Some(e) = f.map.get_mut(&fid) else {
                fs::close(h);
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            e.host_path = new_path;
            e.is_dir = false;
            e.qid_path = qp;
            e.handle = Some(Arc::new(OwnedHandle(h)));
            e.opened = true;
            e.open_flags = flags;
        }
        reply.clear();
        enc4(reply, 0);
        enc1(reply, R_LCREATE);
        enc2(reply, tag);
        enc_qid(reply, QT_FILE, 0, qp);
        enc4(reply, 0); // iounit
        finalize(reply);
    }

    fn h_read(&self, tag: u16, body: &[u8], reply: &mut Vec<u8>, cap: u32) {
        let mut d = Dec::new(body);
        let (Some(fid), Some(offset), Some(mut count)) = (d.u32(), d.u64(), d.u32()) else {
            build_rlerror(reply, tag, E_PROTO);
            return;
        };
        let (h, opened, is_dir);
        {
            let f = self.fids.lock().unwrap();
            let Some(e) = f.map.get(&fid) else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            h = e.handle.clone();
            opened = e.opened;
            is_dir = e.is_dir;
        }
        if !opened || h.is_none() {
            build_rlerror(reply, tag, E_BADF);
            return;
        }
        if is_dir {
            build_rlerror(reply, tag, E_ISDIR);
            return;
        }
        // Hold the Arc for the whole read so a concurrent clunk can't close it.
        let h = h.unwrap();
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
        if self.readonly {
            build_rlerror(reply, tag, E_ROFS);
            return;
        }
        let (h, opened, is_dir, open_flags);
        {
            let f = self.fids.lock().unwrap();
            let Some(e) = f.map.get(&fid) else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            h = e.handle.clone();
            opened = e.opened;
            is_dir = e.is_dir;
            open_flags = e.open_flags;
        }
        if !opened || h.is_none() {
            build_rlerror(reply, tag, E_BADF);
            return;
        }
        if is_dir {
            build_rlerror(reply, tag, E_ISDIR);
            return;
        }
        // Hold the Arc for the whole write so a concurrent clunk can't close it.
        let h = h.unwrap();
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
        let (dir_path, is_dir, opened, has_handle);
        {
            let f = self.fids.lock().unwrap();
            let Some(e) = f.map.get(&fid) else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            dir_path = e.host_path.clone();
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
            // Clone the fid's already-open (and `handle_contained`-validated)
            // directory handle and enumerate by HANDLE — no per-entry open.
            let dir_h = {
                let f = self.fids.lock().unwrap();
                f.map.get(&fid).and_then(|e| e.handle.clone())
            };
            let Some(dir_h) = dir_h else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            let cache = self.build_dir_cache(dir_h.get(), &dir_path);
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

    /// Build the readdir cache by enumerating the (already-open, already-
    /// containment-validated) directory HANDLE with `FileIdBothDirectoryInfo`.
    /// Each entry comes back with its 64-bit NTFS file-ID, so there is **no
    /// per-entry CreateFile / GetFinalPathNameByHandle / GetFileInformation /
    /// Close** — one buffer-full per ~500 entries instead of ~4 syscalls per
    /// entry. (Profiled on a 5 000-entry dir: ~20 K host syscalls/readdir → ~10.)
    ///
    /// `_dir_path` is retained for a future per-entry fallback if by-handle
    /// enumeration ever fails on a non-NTFS volume.
    fn build_dir_cache(&self, dir_h: HANDLE, _dir_path: &Path) -> Vec<DirEntryCached> {
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
        let (path, was_open, existing);
        {
            let f = self.fids.lock().unwrap();
            let Some(e) = f.map.get(&fid) else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            path = e.host_path.clone();
            was_open = e.opened;
            existing = e.handle.clone();
        }
        let mut opened_here = INVALID_HANDLE_VALUE;
        // `existing` (the Arc) stays in scope through `read_attrs_by_handle`, so a
        // concurrent clunk can't close the fid's handle under us.
        let h = match &existing {
            Some(a) if was_open => a.get(),
            _ => match self.open_for_attrs(&path) {
                Ok(nh) => {
                    opened_here = nh;
                    nh
                }
                Err(e) => {
                    build_rlerror(reply, tag, errno_from_win32(e));
                    return;
                }
            },
        };
        let attrs = self.read_attrs_by_handle(h);
        if opened_here != INVALID_HANDLE_VALUE {
            fs::close(opened_here);
        }
        let (qt, qv, qp, mode, nlink, size, blocks, atime, mtime, ctime) = match attrs {
            Ok(v) => v,
            Err(e) => {
                build_rlerror(reply, tag, e);
                return;
            }
        };
        reply.clear();
        enc4(reply, 0);
        enc1(reply, R_GETATTR);
        enc2(reply, tag);
        enc8(reply, STATS_BASIC & request_mask);
        enc_qid(reply, qt, qv, qp);
        enc4(reply, mode);
        enc4(reply, 0); // uid
        enc4(reply, 0); // gid
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
            Some(_mode),
            Some(_uid),
            Some(_gid),
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
        let (path, was_open, existing, is_dir);
        {
            let f = self.fids.lock().unwrap();
            let Some(e) = f.map.get(&fid) else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            path = e.host_path.clone();
            was_open = e.opened;
            existing = e.handle.clone();
            is_dir = e.is_dir;
        }
        let need_size = valid & SETATTR_SIZE != 0;
        let need_handle = need_size || !was_open || existing.is_none();
        let mut opened_here = INVALID_HANDLE_VALUE;
        let h = if need_handle {
            let mut access = FILE_WRITE_ATTRIBUTES;
            if need_size {
                access |= GENERIC_WRITE;
            }
            let attr = if is_dir {
                FILE_FLAG_BACKUP_SEMANTICS
            } else {
                FILE_ATTRIBUTE_NORMAL
            };
            let wp = to_win32_long_path(&path);
            let nh = match fs::create_file(&wp, access, FILE_SHARE_RWD, OPEN_EXISTING, attr) {
                Ok(nh) => nh,
                Err(e) => {
                    build_rlerror(reply, tag, errno_from_win32(e));
                    return;
                }
            };
            // Parity with h_lopen/h_lcreate/open_for_attrs: re-validate the
            // resolved handle path so a reparse point can't redirect a setattr
            // (truncate / utime) at a host file outside the share.
            if !self.handle_contained(nh) {
                fs::close(nh);
                build_rlerror(reply, tag, E_ACCES);
                return;
            }
            opened_here = nh;
            nh
        } else {
            // `existing` (the Arc) stays in scope through the set_* calls below,
            // so a concurrent clunk can't close the fid's handle under us.
            existing.as_ref().unwrap().get()
        };

        if valid & SETATTR_SIZE != 0 {
            if let Err(e) = fs::set_end_of_file(h, sz) {
                let e = errno_from_win32(e);
                if opened_here != INVALID_HANDLE_VALUE {
                    fs::close(opened_here);
                }
                build_rlerror(reply, tag, e);
                return;
            }
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
            if let Err(e) = fs::set_file_times(h, pa, pm) {
                let e = errno_from_win32(e);
                if opened_here != INVALID_HANDLE_VALUE {
                    fs::close(opened_here);
                }
                build_rlerror(reply, tag, e);
                return;
            }
        }
        if opened_here != INVALID_HANDLE_VALUE {
            fs::close(opened_here);
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
        let (path, is_dir);
        {
            let mut f = self.fids.lock().unwrap();
            let Some(mut e) = f.map.remove(&fid) else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            path = e.host_path.clone();
            is_dir = e.is_dir;
            e.close_handle(); // explicit; dropped at end of scope anyway
        }
        if self.readonly {
            build_rlerror(reply, tag, E_ROFS);
            return;
        }
        if normalize_for_containment(&path) == self.share_root_norm {
            build_rlerror(reply, tag, E_ACCES);
            return;
        }
        let wp = to_win32_long_path(&path);
        let res = if is_dir {
            fs::remove_dir(&wp)
        } else {
            fs::delete_file(&wp)
        };
        if let Err(e) = res {
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
        if let Some(a) = &h {
            if let Err(err) = fs::flush(a.get()) {
                if err != ERROR_ACCESS_DENIED && err != ERROR_INVALID_HANDLE {
                    build_rlerror(reply, tag, errno_from_win32(err));
                    return;
                }
            }
        }
        build_header_only(reply, R_FSYNC, tag);
    }

    fn h_mkdir(&self, tag: u16, body: &[u8], reply: &mut Vec<u8>) {
        let mut d = Dec::new(body);
        let (Some(dfid), Some(name), Some(_mode), Some(_gid)) =
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
        let parent;
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
            parent = e.host_path.clone();
        }
        let new_path = join_child(&parent, &name);
        if !self.path_contained(&new_path) {
            build_rlerror(reply, tag, E_INVAL);
            return;
        }
        let wp = to_win32_long_path(&new_path);
        if let Err(e) = fs::create_dir(&wp) {
            build_rlerror(reply, tag, errno_from_win32(e));
            return;
        }
        let (qt, qp, _isd) = match self.stat_path_for_fid(&new_path) {
            Ok(v) => v,
            Err(e) => {
                build_rlerror(reply, tag, e);
                return;
            }
        };
        reply.clear();
        enc4(reply, 0);
        enc1(reply, R_MKDIR);
        enc2(reply, tag);
        enc_qid(reply, qt, 0, qp);
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
        let (old_path, new_parent);
        {
            let mut f = self.fids.lock().unwrap();
            if !f.map.contains_key(&fid) || !f.map.contains_key(&dfid) {
                build_rlerror(reply, tag, E_BADF);
                return;
            }
            if !f.map.get(&dfid).unwrap().is_dir {
                build_rlerror(reply, tag, E_NOTDIR);
                return;
            }
            old_path = f.map.get(&fid).unwrap().host_path.clone();
            new_parent = f.map.get(&dfid).unwrap().host_path.clone();
            // Drop any open handle on the source so MoveFileExW can proceed.
            f.map.get_mut(&fid).unwrap().close_handle();
        }
        let new_path = join_child(&new_parent, &name);
        if !self.path_contained(&new_path) {
            build_rlerror(reply, tag, E_INVAL);
            return;
        }
        let wold = to_win32_long_path(&old_path);
        let wnew = to_win32_long_path(&new_path);
        if let Err(e) = fs::move_file(
            &wold,
            &wnew,
            MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING,
        ) {
            build_rlerror(reply, tag, errno_from_win32(e));
            return;
        }
        if let Some(e) = self.fids.lock().unwrap().map.get_mut(&fid) {
            e.host_path = new_path;
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
            old_dir = o.host_path.clone();
            new_dir = n.host_path.clone();
        }
        let old_path = join_child(&old_dir, &old_name);
        let new_path = join_child(&new_dir, &new_name);
        if !self.path_contained(&old_path) || !self.path_contained(&new_path) {
            build_rlerror(reply, tag, E_INVAL);
            return;
        }
        let wold = to_win32_long_path(&old_path);
        let wnew = to_win32_long_path(&new_path);
        if let Err(e) = fs::move_file(
            &wold,
            &wnew,
            MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING,
        ) {
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
            parent = e.host_path.clone();
        }
        let target = join_child(&parent, &name);
        if !self.path_contained(&target) {
            build_rlerror(reply, tag, E_INVAL);
            return;
        }
        let wp = to_win32_long_path(&target);
        let res = if flags & AT_REMOVEDIR != 0 {
            fs::remove_dir(&wp)
        } else {
            fs::delete_file(&wp)
        };
        if let Err(err) = res {
            // unlinkat without AT_REMOVEDIR on a directory should be EISDIR;
            // DeleteFileW returns ERROR_ACCESS_DENIED there.
            if flags & AT_REMOVEDIR == 0 && err == ERROR_ACCESS_DENIED {
                let attrs = fs::get_attributes(&wp);
                if attrs != INVALID_FILE_ATTRIBUTES && attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
                    build_rlerror(reply, tag, E_ISDIR);
                    return;
                }
            }
            build_rlerror(reply, tag, errno_from_win32(err));
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
        let path = {
            let f = self.fids.lock().unwrap();
            let Some(e) = f.map.get(&fid) else {
                build_rlerror(reply, tag, E_BADF);
                return;
            };
            e.host_path.clone()
        };
        let wp = to_win32_long_path(&path);
        const BLOCK: u64 = 4096;
        let (blocks_total, blocks_free, blocks_avail) = match fs::disk_free_space(&wp) {
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
        let s = b.as_slice();
        let take = s.len().min(max - out.len());
        out.extend_from_slice(&s[..take]);
    }
}

fn write_chain(bufs: &mut [ChainBuf], reply: &[u8]) -> u32 {
    let mut off = 0usize;
    for b in bufs.iter_mut().filter(|b| b.write) {
        if off >= reply.len() {
            break;
        }
        let n = b.len.min(reply.len() - off);
        if n > 0 {
            b.as_mut_slice()[..n].copy_from_slice(&reply[off..off + n]);
        }
        off += n;
    }
    off as u32
}

fn writable_capacity(bufs: &[ChainBuf]) -> u32 {
    let total: usize = bufs.iter().filter(|b| b.write).map(|b| b.len).sum();
    total.min(0xFFFF_FFFF) as u32
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
    /// whole fid table (path + open mode per fid). Host handles are NOT encoded;
    /// they are reopened from each fid's path on `apply_device_state`.
    fn capture_device_state(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(1u8); // format version
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
            let path = e.host_path.to_string_lossy();
            let pb = path.as_bytes();
            b.extend_from_slice(&(pb.len() as u32).to_le_bytes());
            b.extend_from_slice(pb);
        }
        b
    }

    /// Rebuild the device state captured above. Reopens each previously-open
    /// fid's host handle (best effort: a since-deleted file leaves the fid
    /// unopened). Bounds-checked: a short/corrupt blob aborts the parse rather
    /// than panicking.
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
        let _ver = take!(1)[0];
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
            let mut e = FidEntry::new(path.clone(), is_dir, qid);
            if opened {
                let h = self.reopen_fid_handle(&path, is_dir, flags);
                if h.is_null() {
                    eprintln!(
                        "[9p] restore: could not reopen fid {id} ({}); leaving it unopened",
                        path.display()
                    );
                } else {
                    e.handle = Some(Arc::new(OwnedHandle(h)));
                    e.opened = true;
                    e.open_flags = flags;
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

    /// A directory junction planted inside the share that targets a directory
    /// outside it must be rejected: the lexical path is inside the share, but
    /// the resolved handle path is not. `mklink /J` needs no elevation.
    #[test]
    fn junction_escape_is_denied() {
        let base = std::env::temp_dir().join(format!("tinyvmm_p9_esc_{}", std::process::id()));
        let share = base.join("share");
        let sub = share.join("sub");
        let outside = base.join("outside");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), b"top secret").unwrap();

        // Plant a directory junction <share>/escape -> <outside>.
        let escape = share.join("escape");
        let out = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&escape)
            .arg(&outside)
            .output();
        if out.map(|o| !o.status.success()).unwrap_or(true) || !escape.exists() {
            // Junctions unavailable in this environment; skip rather than fail.
            eprintln!("[p9-test] skipping: could not create a directory junction");
            let _ = std::fs::remove_dir_all(&base);
            return;
        }

        let canon_root = std::fs::canonicalize(&share).unwrap();
        let mem = std::sync::Arc::new(whpsys::memory::GuestMemory::new_host_only(4096).unwrap());
        let dev = P9Device::new(mem, "test".into(), canon_root, false);

        // A genuine subdir of the share opens fine.
        assert!(
            dev.open_for_attrs(&sub).is_ok(),
            "a real subdir of the share must be reachable"
        );
        // Opening through the junction resolves outside the share -> denied.
        assert_eq!(
            dev.open_for_attrs(&escape.join("secret.txt")),
            Err(ERROR_ACCESS_DENIED),
            "a file reached through a junction out of the share must be denied"
        );
        // The junction directory itself also resolves outside -> denied.
        assert_eq!(
            dev.open_for_attrs(&escape),
            Err(ERROR_ACCESS_DENIED),
            "the escaping junction directory itself must be denied"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Capturing then re-applying the 9p device state must restore the negotiated
    /// state and the whole fid table, reopening the host handles of fids that
    /// were open at capture time.
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
        let dev = P9Device::new(mem.clone(), "t".into(), root.clone(), false);
        dev.driver_ok.store(true, Ordering::Relaxed);
        let feats = dev.device_features();
        dev.acked_features.store(feats, Ordering::Relaxed);
        dev.negotiated_msize.store(512_000, Ordering::Relaxed);
        dev.next_qid_path.store(42, Ordering::Relaxed);
        {
            let file = share.join("file.txt");
            let hf = dev.reopen_fid_handle(&file, false, O_RDONLY);
            let hd = dev.reopen_fid_handle(&sub, true, O_RDONLY);
            assert!(!hf.is_null() && !hd.is_null());
            let mut fids = dev.fids.lock().unwrap();
            let mut ef = FidEntry::new(file, false, 7);
            ef.handle = Some(Arc::new(OwnedHandle(hf)));
            ef.opened = true;
            ef.open_flags = O_RDONLY;
            fids.map.insert(1, ef);
            let mut ed = FidEntry::new(sub.clone(), true, 8);
            ed.handle = Some(Arc::new(OwnedHandle(hd)));
            ed.opened = true;
            ed.open_flags = O_RDONLY;
            fids.map.insert(2, ed);
            // A walked-but-not-opened fid: path only, no handle.
            fids.map.insert(3, FidEntry::new(root.clone(), true, 1));
        }

        let blob = dev.capture_device_state();

        let dev2 = P9Device::new(mem, "t".into(), root, false);
        dev2.apply_device_state(&blob);
        assert!(dev2.driver_ok.load(Ordering::Relaxed));
        assert_eq!(dev2.acked_features.load(Ordering::Relaxed), feats);
        assert_eq!(dev2.negotiated_msize.load(Ordering::Relaxed), 512_000);
        assert_eq!(dev2.next_qid_path.load(Ordering::Relaxed), 42);
        let fids = dev2.fids.lock().unwrap();
        assert_eq!(fids.map.len(), 3);
        let f1 = fids.map.get(&1).unwrap();
        assert!(!f1.is_dir && f1.opened && f1.handle.is_some() && f1.qid_path == 7);
        let f2 = fids.map.get(&2).unwrap();
        assert!(f2.is_dir && f2.opened && f2.handle.is_some() && f2.qid_path == 8);
        let f3 = fids.map.get(&3).unwrap();
        assert!(f3.is_dir && !f3.opened && f3.handle.is_none() && f3.qid_path == 1);
        drop(fids);

        let _ = std::fs::remove_dir_all(&base);
    }
}
