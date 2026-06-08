//! Async block-file backend for virtio-blk. Port of src/host/block_file.cpp.
//!
//! Wraps a Win32 file opened with `FILE_FLAG_OVERLAPPED` and binds it to a
//! per-file IOCP. A single worker thread drains the IOCP and dispatches
//! completions through a user-supplied callback (which runs on the worker
//! thread). The caller extends [`Request`] by embedding it as the first field
//! of its own struct, so the worker can recover the surrounding request from
//! the `OVERLAPPED` pointer (the `OVERLAPPED` is the first member of
//! `Request`, so all three addresses coincide).
//!
//! We deliberately do NOT use `FILE_FLAG_NO_BUFFERING`: that requires
//! sector-aligned host buffers/lengths, which guest descriptor chains don't
//! guarantee. The OS cache is fine at our scale; a FLUSH op forces
//! `FlushFileBuffers` on the worker thread.
//!
//! This is the core read/write/flush backend; DISCARD / WRITE_ZEROES
//! (`ZeroRange`) are not ported here.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once, OnceLock};
use std::thread::JoinHandle;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_IO_PENDING, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE, FlushFileBuffers,
    GetFileSizeEx, OPEN_EXISTING, ReadFile, WriteFile,
};
use windows_sys::Win32::System::IO::{
    CreateIoCompletionPort, DeviceIoControl, GetQueuedCompletionStatus, OVERLAPPED,
    PostQueuedCompletionStatus,
};
use windows_sys::Win32::System::Ioctl::{
    FILE_SET_SPARSE_BUFFER, FILE_ZERO_DATA_INFORMATION, FSCTL_SET_SPARSE, FSCTL_SET_ZERO_DATA,
};

use super::wide;

const INFINITE: u32 = 0xFFFF_FFFF;
const SHUTDOWN_KEY: usize = 0x1;
const FLUSH_KEY: usize = 0x2;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    Read,
    Write,
    Flush,
}

/// One async op. `ovl` MUST be the first member so the worker can recover the
/// surrounding (caller-defined) request from the completion's `OVERLAPPED*`.
/// The request must stay alive (and `ovl` untouched) until the completion
/// callback fires.
#[repr(C)]
pub struct Request {
    pub ovl: OVERLAPPED,
    pub op: Op,
    pub ok: bool,
    pub file_offset: u64,
    pub buf: *mut u8,
    pub bytes: u32,
}

impl Request {
    pub fn zeroed() -> Request {
        // OVERLAPPED is a plain C struct; zero-init is the documented idle state.
        Request {
            ovl: unsafe { core::mem::zeroed() },
            op: Op::Read,
            ok: false,
            file_offset: 0,
            buf: core::ptr::null_mut(),
            bytes: 0,
        }
    }
}

type CompleteFn = Box<dyn Fn(*mut Request) + Send + Sync>;

struct Inner {
    handle: HANDLE,
    iocp: HANDLE,
    readonly: bool,
    size: u64,
    complete: OnceLock<CompleteFn>,
    submitted: AtomicU64,
    completed: AtomicU64,
    errors: AtomicU64,
    inflight: AtomicU64,
    max_inflight: AtomicU64,
    // DISCARD / WRITE_ZEROES support: mark the file sparse on first ZeroRange
    // so FSCTL_SET_ZERO_DATA deallocates clusters (not just logical zero).
    sparse_once: Once,
    sparse_ok: AtomicBool,
}

// The handles are valid for the whole lifetime of the (Arc-shared) Inner; the
// worker thread and the submitting thread coordinate via the IOCP, exactly as
// the C++ backend does with the same raw HANDLEs.
unsafe impl Send for Inner {}
unsafe impl Sync for Inner {}

impl Drop for Inner {
    fn drop(&mut self) {
        unsafe {
            if !self.iocp.is_null() {
                CloseHandle(self.iocp);
            }
            if self.handle != INVALID_HANDLE_VALUE && !self.handle.is_null() {
                CloseHandle(self.handle);
            }
        }
    }
}

pub struct BlockFile {
    inner: Arc<Inner>,
    worker: Mutex<Option<JoinHandle<()>>>,
    open_err: u32,
}

impl BlockFile {
    /// Open `path` (must already exist). On failure `open()` returns false and
    /// `open_err()` carries the Win32 error.
    pub fn new(path: &str, readonly: bool) -> BlockFile {
        let closed = |err: u32| BlockFile {
            inner: Arc::new(Inner {
                handle: INVALID_HANDLE_VALUE,
                iocp: core::ptr::null_mut(),
                readonly,
                size: 0,
                complete: OnceLock::new(),
                submitted: AtomicU64::new(0),
                completed: AtomicU64::new(0),
                errors: AtomicU64::new(0),
                inflight: AtomicU64::new(0),
                max_inflight: AtomicU64::new(0),
                sparse_once: Once::new(),
                sparse_ok: AtomicBool::new(false),
            }),
            worker: Mutex::new(None),
            open_err: err,
        };

        let wpath = wide(path);
        let access = if readonly {
            GENERIC_READ
        } else {
            GENERIC_READ | GENERIC_WRITE
        };
        let share = if readonly {
            FILE_SHARE_READ
        } else {
            FILE_SHARE_READ | FILE_SHARE_WRITE
        };
        let handle = unsafe {
            CreateFileW(
                wpath.as_ptr(),
                access,
                share,
                core::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                core::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return closed(unsafe { GetLastError() });
        }
        let mut li: i64 = 0;
        if unsafe { GetFileSizeEx(handle, &mut li) } == 0 {
            let err = unsafe { GetLastError() };
            unsafe { CloseHandle(handle) };
            return closed(err);
        }
        let iocp = unsafe { CreateIoCompletionPort(handle, core::ptr::null_mut(), 0, 1) };
        if iocp.is_null() {
            let err = unsafe { GetLastError() };
            unsafe { CloseHandle(handle) };
            return closed(err);
        }
        BlockFile {
            inner: Arc::new(Inner {
                handle,
                iocp,
                readonly,
                size: li as u64,
                complete: OnceLock::new(),
                submitted: AtomicU64::new(0),
                completed: AtomicU64::new(0),
                errors: AtomicU64::new(0),
                inflight: AtomicU64::new(0),
                max_inflight: AtomicU64::new(0),
                sparse_once: Once::new(),
                sparse_ok: AtomicBool::new(false),
            }),
            worker: Mutex::new(None),
            open_err: 0,
        }
    }

    pub fn open(&self) -> bool {
        self.inner.handle != INVALID_HANDLE_VALUE && !self.inner.handle.is_null()
    }
    pub fn open_err(&self) -> u32 {
        self.open_err
    }
    pub fn size(&self) -> u64 {
        self.inner.size
    }
    pub fn readonly(&self) -> bool {
        self.inner.readonly
    }

    pub fn submitted(&self) -> u64 {
        self.inner.submitted.load(Ordering::Relaxed)
    }
    pub fn completed(&self) -> u64 {
        self.inner.completed.load(Ordering::Relaxed)
    }
    pub fn errors(&self) -> u64 {
        self.inner.errors.load(Ordering::Relaxed)
    }
    pub fn max_inflight(&self) -> u64 {
        self.inner.max_inflight.load(Ordering::Relaxed)
    }
    pub fn inflight(&self) -> u64 {
        self.inner.inflight.load(Ordering::Relaxed)
    }

    /// Install the completion callback. Must be called before `start()`.
    pub fn set_completion_callback(&self, f: CompleteFn) {
        let _ = self.inner.complete.set(f);
    }

    /// Synchronously zero (and, on a sparse NTFS file, deallocate) a byte range.
    /// Backs virtio-blk DISCARD / WRITE_ZEROES. On first call marks the file
    /// sparse via `FSCTL_SET_SPARSE`; then issues `FSCTL_SET_ZERO_DATA`. Returns
    /// false on a read-only file or on failure. Thread-safe.
    pub fn zero_range(&self, offset: u64, length: u64) -> bool {
        let inner = &self.inner;
        if inner.readonly || !self.open() {
            return false;
        }
        if length == 0 {
            return true;
        }
        if offset > inner.size || length > inner.size - offset {
            return false;
        }
        // Mark sparse once so SET_ZERO_DATA deallocates clusters. On a non-NTFS
        // volume SET_SPARSE fails (ERROR_INVALID_FUNCTION); treat as soft —
        // SET_ZERO_DATA still zeroes the bytes, it just won't deallocate.
        inner.sparse_once.call_once(|| {
            let sb = FILE_SET_SPARSE_BUFFER { SetSparse: true };
            let mut ret: u32 = 0;
            let ok = unsafe {
                DeviceIoControl(
                    inner.handle,
                    FSCTL_SET_SPARSE,
                    &sb as *const _ as *const core::ffi::c_void,
                    core::mem::size_of::<FILE_SET_SPARSE_BUFFER>() as u32,
                    core::ptr::null_mut(),
                    0,
                    &mut ret,
                    core::ptr::null_mut(),
                )
            };
            inner.sparse_ok.store(ok != 0, Ordering::Release);
        });

        let zd = FILE_ZERO_DATA_INFORMATION {
            FileOffset: offset as i64,
            BeyondFinalZero: (offset + length) as i64,
        };
        let mut ret: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                inner.handle,
                FSCTL_SET_ZERO_DATA,
                &zd as *const _ as *const core::ffi::c_void,
                core::mem::size_of::<FILE_ZERO_DATA_INFORMATION>() as u32,
                core::ptr::null_mut(),
                0,
                &mut ret,
                core::ptr::null_mut(),
            )
        };
        ok != 0
    }

    /// Spin up the IOCP worker. Must be called before `submit`.
    pub fn start(&self) {
        let mut w = self.worker.lock().unwrap();
        if w.is_some() || !self.open() {
            return;
        }
        let inner = self.inner.clone();
        *w = Some(std::thread::spawn(move || worker_loop(inner)));
    }

    /// Stop the IOCP worker (signals + joins). In-flight ops are NOT cancelled;
    /// the caller must quiesce the device first.
    pub fn stop(&self) {
        let handle = self.worker.lock().unwrap().take();
        if let Some(h) = handle {
            unsafe {
                PostQueuedCompletionStatus(self.inner.iocp, 0, SHUTDOWN_KEY, core::ptr::null());
            }
            let _ = h.join();
        }
    }

    /// Submit one async op. `req` must remain alive (and `ovl` untouched) until
    /// the completion callback fires. Returns false on synchronous failure.
    ///
    /// # Safety
    /// `req` must point to a live [`Request`] embedded in a caller-owned
    /// allocation that outlives the completion.
    pub unsafe fn submit(&self, req: *mut Request) -> bool {
        unsafe {
            let inner = &self.inner;
            inner.submitted.fetch_add(1, Ordering::Relaxed);
            (*req).ok = false;

            // High-water mark of outstanding requests (queue depth actually
            // reached). The blk-test asserts this exceeds 1.
            let cur = inner.inflight.fetch_add(1, Ordering::Relaxed) + 1;
            let mut prev = inner.max_inflight.load(Ordering::Relaxed);
            while cur > prev {
                match inner.max_inflight.compare_exchange_weak(
                    prev,
                    cur,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(p) => prev = p,
                }
            }

            let op = (*req).op;
            if op == Op::Flush {
                // Defer the (sync) FlushFileBuffers to the worker so the vCPU
                // thread doesn't stall; FLUSH_KEY lets the worker recognise it.
                core::ptr::write_bytes(&mut (*req).ovl as *mut OVERLAPPED, 0, 1);
                if PostQueuedCompletionStatus(inner.iocp, 0, FLUSH_KEY, &(*req).ovl) == 0 {
                    inner.inflight.fetch_sub(1, Ordering::Relaxed);
                    inner.errors.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
                return true;
            }

            core::ptr::write_bytes(&mut (*req).ovl as *mut OVERLAPPED, 0, 1);
            (*req).ovl.Anonymous.Anonymous.Offset = ((*req).file_offset & 0xFFFF_FFFF) as u32;
            (*req).ovl.Anonymous.Anonymous.OffsetHigh = ((*req).file_offset >> 32) as u32;

            let started = if op == Op::Read {
                ReadFile(
                    inner.handle,
                    (*req).buf,
                    (*req).bytes,
                    core::ptr::null_mut(),
                    &mut (*req).ovl,
                )
            } else {
                if inner.readonly {
                    inner.inflight.fetch_sub(1, Ordering::Relaxed);
                    inner.errors.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
                WriteFile(
                    inner.handle,
                    (*req).buf,
                    (*req).bytes,
                    core::ptr::null_mut(),
                    &mut (*req).ovl,
                )
            };
            if started == 0 {
                let err = GetLastError();
                if err != ERROR_IO_PENDING {
                    inner.inflight.fetch_sub(1, Ordering::Relaxed);
                    inner.errors.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
            }
            true
        }
    }
}

impl Drop for BlockFile {
    fn drop(&mut self) {
        self.stop();
    }
}

fn worker_loop(inner: Arc<Inner>) {
    loop {
        let mut bytes: u32 = 0;
        let mut key: usize = 0;
        let mut ovl: *mut OVERLAPPED = core::ptr::null_mut();
        let ok = unsafe {
            GetQueuedCompletionStatus(inner.iocp, &mut bytes, &mut key, &mut ovl, INFINITE)
        };
        if key == SHUTDOWN_KEY {
            return;
        }
        if ovl.is_null() {
            continue;
        }
        // `ovl` is the first member of Request, so the addresses coincide.
        let req = ovl as *mut Request;
        unsafe {
            if key == FLUSH_KEY || (*req).op == Op::Flush {
                (*req).ok = FlushFileBuffers(inner.handle) != 0;
            } else {
                (*req).ok = ok != 0 && bytes == (*req).bytes;
            }
            if !(*req).ok {
                inner.errors.fetch_add(1, Ordering::Relaxed);
            }
            inner.completed.fetch_add(1, Ordering::Relaxed);
            inner.inflight.fetch_sub(1, Ordering::Relaxed);
            if let Some(cb) = inner.complete.get() {
                cb(req);
            }
        }
    }
}
