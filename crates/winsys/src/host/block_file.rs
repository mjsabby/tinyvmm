//! Async block-file backend for virtio-blk. Port of src/host/block_file.cpp.
//!
//! Wraps a Win32 file opened with `FILE_FLAG_OVERLAPPED` and binds it to a
//! per-file IOCP. A single worker thread drains the IOCP and dispatches
//! completions through a user-supplied callback (which runs on the worker
//! thread). An op that completes synchronously — a read or write served by the
//! host page cache — posts no packet (`FILE_SKIP_COMPLETION_PORT_ON_SUCCESS`)
//! and its callback runs on the submitting thread instead, saving the hand-off
//! to the worker. The caller extends [`Request`] by embedding it as the first field
//! of its own struct, so the worker can recover the surrounding request from
//! the `OVERLAPPED` pointer (the `OVERLAPPED` is the first member of
//! `Request`, so all three addresses coincide).
//!
//! We deliberately do NOT use `FILE_FLAG_NO_BUFFERING`: that requires
//! sector-aligned host buffers/lengths, which guest descriptor chains don't
//! guarantee. The OS cache is fine at our scale; a FLUSH op forces
//! `FlushFileBuffers` on the worker thread.
//!
//! Ops are accepted only between `start` and `stop`, so every op has a worker
//! to complete it, and `stop` returns only once every op it let in has
//! completed and its callback has returned.
//!
//! Disks use VHDMP's VM-only VHDX handle. The separate read-only ISO
//! constructor exposes installation media as bytes, never as a writable disk.
//! DISCARD uses native SCSI UNMAP.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_IO_PENDING, GENERIC_READ, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FlushFileBuffers, GetFileSizeEx,
    OPEN_EXISTING, ReadFile, SetFileCompletionNotificationModes, WriteFile,
};
use windows_sys::Win32::System::IO::{
    CreateIoCompletionPort, GetOverlappedResult, GetQueuedCompletionStatus, OVERLAPPED,
    PostQueuedCompletionStatus,
};
use windows_sys::Win32::System::Threading::CreateEventW;

use super::vhdx::VirtualDisk;
use super::wide;

const INFINITE: u32 = 0xFFFF_FFFF;
const SHUTDOWN_KEY: usize = 0x1;
const FLUSH_KEY: usize = 0x2;
// SetFileCompletionNotificationModes flag (WindowsProgramming in windows-sys).
const FILE_SKIP_COMPLETION_PORT_ON_SUCCESS: u8 = 1;

/// Manual-reset event a thread waits on in `submit_sync` for VHDX I/O.
struct SyncEvent(HANDLE);

impl Drop for SyncEvent {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

thread_local! {
    static SYNC_EVENT: SyncEvent =
        SyncEvent(unsafe { CreateEventW(core::ptr::null(), 1, 0, core::ptr::null()) });
}

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
    virtual_disk: Option<VirtualDisk>,
    /// A second, non-overlapped handle to the ISO for `submit_sync`:
    /// Windows completes even page-cache hits on the overlapped handle
    /// asynchronously, through a system worker and the IOCP. Null for a VHDX
    /// (VHDMP allows a single open), whose `submit_sync` waits on overlapped
    /// I/O instead, and if the second open failed (`submit` then serves it).
    sync_handle: HANDLE,
    iocp: HANDLE,
    readonly: bool,
    /// A read/write that completes synchronously posts no completion packet,
    /// so `submit` finishes it inline (Windows does this for some writes,
    /// e.g. cached writes on ReFS).
    skip_on_success: bool,
    size: u64,
    complete: OnceLock<CompleteFn>,
    /// Set unless the worker is running: new ops are refused, so none is left
    /// without a thread to complete it.
    closed: AtomicBool,
    submitted: AtomicU64,
    completed: AtomicU64,
    errors: AtomicU64,
    /// Ops started whose completion callback has not yet returned.
    inflight: AtomicU64,
    max_inflight: AtomicU64,
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
            if !self.sync_handle.is_null() {
                CloseHandle(self.sync_handle);
            }
            if self.virtual_disk.is_none()
                && self.handle != INVALID_HANDLE_VALUE
                && !self.handle.is_null()
            {
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
    /// Open an existing VHDX (regardless of filename extension).
    /// On failure `open()` returns false and
    /// `open_err()` carries the Win32 error.
    pub fn new(path: &str, readonly: bool) -> BlockFile {
        Self::new_impl(path, readonly, false)
    }

    /// Open installation ISO bytes read-only. This does not enable raw disks.
    pub fn new_iso(path: &str) -> BlockFile {
        Self::new_impl(path, true, true)
    }

    fn new_impl(path: &str, readonly: bool, iso: bool) -> BlockFile {
        let closed = |err: u32| BlockFile {
            inner: Arc::new(Inner {
                handle: INVALID_HANDLE_VALUE,
                virtual_disk: None,
                sync_handle: core::ptr::null_mut(),
                iocp: core::ptr::null_mut(),
                readonly,
                skip_on_success: false,
                size: 0,
                complete: OnceLock::new(),
                closed: AtomicBool::new(true),
                submitted: AtomicU64::new(0),
                completed: AtomicU64::new(0),
                errors: AtomicU64::new(0),
                inflight: AtomicU64::new(0),
                max_inflight: AtomicU64::new(0),
            }),
            worker: Mutex::new(None),
            open_err: err,
        };

        let wpath = wide(path);
        let virtual_disk = if !iso {
            match VirtualDisk::open(path, readonly) {
                Ok(disk) => Some(disk),
                Err(err) => return closed(err),
            }
        } else {
            None
        };
        let handle = if let Some(disk) = &virtual_disk {
            disk.handle()
        } else {
            unsafe {
                CreateFileW(
                    wpath.as_ptr(),
                    GENERIC_READ,
                    FILE_SHARE_READ,
                    core::ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    core::ptr::null_mut(),
                )
            }
        };
        if handle == INVALID_HANDLE_VALUE {
            return closed(unsafe { GetLastError() });
        }
        let mut li: i64 = 0;
        if let Some(disk) = &virtual_disk {
            li = disk.size as i64;
        } else if unsafe { GetFileSizeEx(handle, &mut li) } == 0 {
            let err = unsafe { GetLastError() };
            unsafe { CloseHandle(handle) };
            return closed(err);
        }
        let iocp = unsafe { CreateIoCompletionPort(handle, core::ptr::null_mut(), 0, 1) };
        if iocp.is_null() {
            let err = unsafe { GetLastError() };
            if virtual_disk.is_none() {
                unsafe { CloseHandle(handle) };
            }
            return closed(err);
        }
        let skip_on_success = unsafe {
            SetFileCompletionNotificationModes(handle, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS)
        } != 0;
        let sync_handle = if virtual_disk.is_some() {
            core::ptr::null_mut()
        } else {
            unsafe {
                CreateFileW(
                    wpath.as_ptr(),
                    GENERIC_READ,
                    FILE_SHARE_READ,
                    core::ptr::null(),
                    OPEN_EXISTING,
                    0,
                    core::ptr::null_mut(),
                )
            }
        };
        let sync_handle = if sync_handle == INVALID_HANDLE_VALUE {
            core::ptr::null_mut()
        } else {
            sync_handle
        };
        BlockFile {
            inner: Arc::new(Inner {
                handle,
                virtual_disk,
                sync_handle,
                iocp,
                readonly,
                skip_on_success,
                size: li as u64,
                complete: OnceLock::new(),
                closed: AtomicBool::new(true),
                submitted: AtomicU64::new(0),
                completed: AtomicU64::new(0),
                errors: AtomicU64::new(0),
                inflight: AtomicU64::new(0),
                max_inflight: AtomicU64::new(0),
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

    /// Discard guest sectors, without promising that subsequent reads are zero.
    /// Uses SCSI UNMAP when supported.
    pub fn discard_range(&self, offset: u64, length: u64) -> bool {
        if let Some(disk) = &self.inner.virtual_disk {
            if self.inner.readonly || offset > self.inner.size || length > self.inner.size - offset
            {
                return false;
            }
            disk.discard_range(offset, length)
        } else {
            false
        }
    }

    /// Spin up the IOCP worker and start accepting ops; `submit` refuses
    /// them before this.
    pub fn start(&self) {
        let mut w = self.worker.lock().unwrap();
        if w.is_some() || !self.open() {
            return;
        }
        let inner = self.inner.clone();
        *w = Some(std::thread::spawn(move || worker_loop(inner)));
        self.inner.closed.store(false, Ordering::SeqCst);
    }

    /// Refuse new ops, wait until every op already started has completed and
    /// its completion callback has returned, then signal and join the worker.
    /// Nothing the backend started is still running afterwards. Callers stop
    /// issuing ops first: one refused here fails like any `submit` failure.
    pub fn stop(&self) {
        let mut w = self.worker.lock().unwrap();
        let Some(h) = w.take() else {
            return;
        };
        self.inner.closed.store(true, Ordering::SeqCst);
        // The worker keeps completing ops meanwhile.
        while self.inner.inflight.load(Ordering::SeqCst) != 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
        unsafe {
            PostQueuedCompletionStatus(self.inner.iocp, 0, SHUTDOWN_KEY, core::ptr::null());
        }
        let _ = h.join();
    }

    /// Submit one async op. `req` must remain alive (and `ovl` untouched) until
    /// the completion callback fires. Returns false on synchronous failure,
    /// including when the backend is not started.
    ///
    /// # Safety
    /// `req` must point to a live [`Request`] embedded in a caller-owned
    /// allocation that outlives the completion.
    pub unsafe fn submit(&self, req: *mut Request) -> bool {
        unsafe {
            let inner = &self.inner;
            if !begin(inner, req) {
                return false;
            }

            let op = (*req).op;
            if op == Op::Flush {
                // Defer the (sync) FlushFileBuffers to the worker so the vCPU
                // thread doesn't stall; FLUSH_KEY lets the worker recognise it.
                core::ptr::write_bytes(&mut (*req).ovl as *mut OVERLAPPED, 0, 1);
                if PostQueuedCompletionStatus(inner.iocp, 0, FLUSH_KEY, &(*req).ovl) == 0 {
                    fail(inner);
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
                    fail(inner);
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
                    fail(inner);
                    return false;
                }
            } else if inner.skip_on_success {
                // Completed synchronously and no packet was queued: finish it
                // here. `InternalHigh` is the byte count GetOverlappedResult
                // would report.
                let bytes = (*req).ovl.InternalHigh as u32;
                finish(inner, req, bytes == (*req).bytes);
            }
            true
        }
    }

    /// Run a read or write to completion on the calling thread, then fire the
    /// completion callback here. Worth it for a request the guest is waiting
    /// on alone: a page-cache hit costs one copy instead of two thread
    /// hand-offs. An ISO goes through its non-overlapped second handle. A VHDX
    /// has only its overlapped handle, so the I/O sets the low bit of `hEvent`,
    /// which keeps its completion off the IOCP, and is waited for here. A miss
    /// blocks the caller for the device's latency, so callers keep concurrent
    /// requests on [`Self::submit`]. Flushes, and everything when neither path
    /// is available, go through `submit`. Returns false on failure to start
    /// (as `submit`).
    ///
    /// # Safety
    /// As [`Self::submit`].
    pub unsafe fn submit_sync(&self, req: *mut Request) -> bool {
        unsafe {
            let inner = &self.inner;
            let op = (*req).op;
            if op == Op::Flush || (op == Op::Write && inner.readonly) {
                return self.submit(req);
            }
            let waited = inner.sync_handle.is_null();
            let event = if waited && inner.virtual_disk.is_some() {
                SYNC_EVENT.with(|event| event.0)
            } else {
                core::ptr::null_mut()
            };
            if waited && event.is_null() {
                return self.submit(req);
            }
            if !begin(inner, req) {
                return false;
            }
            // Positioned I/O: the OVERLAPPED carries the offset.
            core::ptr::write_bytes(&mut (*req).ovl as *mut OVERLAPPED, 0, 1);
            (*req).ovl.Anonymous.Anonymous.Offset = ((*req).file_offset & 0xFFFF_FFFF) as u32;
            (*req).ovl.Anonymous.Anonymous.OffsetHigh = ((*req).file_offset >> 32) as u32;
            let mut done: u32 = 0;
            let (handle, done_ptr): (HANDLE, *mut u32) = if waited {
                (*req).ovl.hEvent = event.map_addr(|addr| addr | 1);
                (inner.handle, core::ptr::null_mut())
            } else {
                (inner.sync_handle, &mut done)
            };
            let mut ok = if op == Op::Read {
                ReadFile(handle, (*req).buf, (*req).bytes, done_ptr, &mut (*req).ovl)
            } else {
                WriteFile(handle, (*req).buf, (*req).bytes, done_ptr, &mut (*req).ovl)
            };
            if waited && (ok != 0 || GetLastError() == ERROR_IO_PENDING) {
                ok = GetOverlappedResult(handle, &(*req).ovl, &mut done, 1);
            }
            finish(inner, req, ok != 0 && done == (*req).bytes);
            true
        }
    }
}

/// Account a newly started op, or refuse it (false) unless the worker is
/// running.
///
/// # Safety
/// `req` must point to a live [`Request`].
unsafe fn begin(inner: &Inner, req: *mut Request) -> bool {
    inner.submitted.fetch_add(1, Ordering::Relaxed);
    unsafe {
        (*req).ok = false;
    }
    // Count the op before checking `closed`. `stop` sets `closed` before it
    // waits for the count to drain, so (SeqCst on both sides) either it waits
    // for this op or this op sees `closed`.
    let cur = inner.inflight.fetch_add(1, Ordering::SeqCst) + 1;
    if inner.closed.load(Ordering::SeqCst) {
        fail(inner);
        return false;
    }
    // High-water mark of ops outstanding at once.
    inner.max_inflight.fetch_max(cur, Ordering::Relaxed);
    true
}

/// Account an op that failed to start after `begin` counted it.
fn fail(inner: &Inner) {
    inner.errors.fetch_add(1, Ordering::Relaxed);
    inner.inflight.fetch_sub(1, Ordering::Release);
}

impl Drop for BlockFile {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Record a finished op and hand it to the completion callback. Runs on the IOCP
/// worker, or on the submitting thread for a synchronous completion.
///
/// # Safety
/// `req` must be the live request of a just-finished op.
unsafe fn finish(inner: &Inner, req: *mut Request, ok: bool) {
    unsafe {
        (*req).ok = ok;
    }
    if !ok {
        inner.errors.fetch_add(1, Ordering::Relaxed);
    }
    inner.completed.fetch_add(1, Ordering::Relaxed);
    if let Some(cb) = inner.complete.get() {
        cb(req);
    }
    // Only after the callback: `stop` reads a zero count as "every callback
    // has returned".
    inner.inflight.fetch_sub(1, Ordering::Release);
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
            let ok = if key == FLUSH_KEY || (*req).op == Op::Flush {
                FlushFileBuffers(inner.handle) != 0
            } else {
                ok != 0 && bytes == (*req).bytes
            };
            finish(&inner, req, ok);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    struct TestImage(std::path::PathBuf);

    impl TestImage {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            Self(std::env::temp_dir().join(format!(
                "tinyvmm-vhdx-{}-{}.vhdx",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )))
        }
        fn path(&self) -> &str {
            self.0.to_str().unwrap()
        }
    }

    impl Drop for TestImage {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn completion(backend: &BlockFile) -> mpsc::Receiver<(usize, bool)> {
        let (tx, rx) = mpsc::channel();
        backend.set_completion_callback(Box::new(move |request| {
            // The submit contract keeps the request alive until this callback.
            tx.send((request as usize, unsafe { (*request).ok }))
                .unwrap();
        }));
        backend.start();
        rx
    }

    /// An op counts as in flight until its callback has returned.
    fn wait_idle(backend: &BlockFile) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while backend.inflight() != 0 {
            assert!(std::time::Instant::now() < deadline, "ops still in flight");
            std::thread::yield_now();
        }
    }

    fn transfer(
        backend: &BlockFile,
        rx: &mpsc::Receiver<(usize, bool)>,
        op: Op,
        offset: u64,
        data: &mut [u8],
    ) {
        let mut request = Request::zeroed();
        request.op = op;
        request.file_offset = offset;
        request.buf = data.as_mut_ptr();
        request.bytes = data.len() as u32;
        assert!(unsafe { backend.submit_sync(&mut request) });
        // Reads and writes finish before submit_sync returns; flushes go to the worker.
        let (address, ok) = if op == Op::Flush {
            let done = rx.recv_timeout(Duration::from_secs(10)).unwrap();
            wait_idle(backend);
            done
        } else {
            rx.try_recv().unwrap()
        };
        assert_eq!(address, &request as *const _ as usize);
        assert!(ok);
    }

    #[test]
    fn stop_waits_for_in_flight_ops() {
        let image = TestImage::new();
        super::super::vhdx::create(image.path(), 256 << 20).unwrap();
        let backend = BlockFile::new(image.path(), false);
        assert!(backend.open(), "error {}", backend.open_err());
        let rx = completion(&backend);
        // Large enough to be still in flight when stop() is called.
        let mut data = vec![0x5a; 64 << 20];
        let mut request = Box::new(Request::zeroed());
        request.op = Op::Write;
        request.buf = data.as_mut_ptr();
        request.bytes = data.len() as u32;
        assert!(unsafe { backend.submit(&mut *request) });
        backend.stop();
        assert_eq!(backend.inflight(), 0);
        assert_eq!(
            rx.try_recv().unwrap(),
            (&*request as *const Request as usize, true)
        );
    }

    #[test]
    fn ops_need_a_running_worker() {
        let image = TestImage::new();
        super::super::vhdx::create(image.path(), 64 << 20).unwrap();
        let backend = BlockFile::new(image.path(), false);
        assert!(backend.open(), "error {}", backend.open_err());
        let (tx, rx) = mpsc::channel();
        backend.set_completion_callback(Box::new(move |request| {
            tx.send(request as usize).unwrap();
        }));
        let mut request = Request::zeroed();
        request.op = Op::Flush;
        let address = &request as *const Request as usize;
        assert!(!unsafe { backend.submit(&mut request) });
        backend.start();
        assert!(unsafe { backend.submit(&mut request) });
        assert_eq!(rx.recv_timeout(Duration::from_secs(10)).unwrap(), address);
        backend.stop();
        assert!(!unsafe { backend.submit(&mut request) });
        request.op = Op::Read;
        let mut data = [0; 4096];
        request.buf = data.as_mut_ptr();
        request.bytes = data.len() as u32;
        assert!(!unsafe { backend.submit_sync(&mut request) });
        assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());
        assert_eq!((backend.inflight(), backend.errors()), (0, 3));
    }

    #[test]
    fn native_vhdx_io_lifecycle() {
        let image = TestImage::new();
        let size = 64 * 1024 * 1024;
        super::super::vhdx::create(image.path(), size).unwrap();
        assert!(std::fs::metadata(&image.0).unwrap().len() < size);
        assert!(super::super::vhdx::create(image.path(), size).is_err());
        {
            let backend = BlockFile::new(image.path(), false);
            assert!(backend.open(), "error {}", backend.open_err());
            assert_eq!(backend.size(), size);
            assert!(!BlockFile::new(image.path(), false).open());
            let rx = completion(&backend);
            let mut slots: Vec<_> = (0..16)
                .map(|i| {
                    let mut bytes = vec![i as u8 + 1; 4096].into_boxed_slice();
                    let mut request = Box::new(Request::zeroed());
                    request.op = Op::Write;
                    // The first request crosses a 2 MiB allocation boundary.
                    request.file_offset = 2 * 1024 * 1024 - 512 + i * 4096;
                    request.buf = bytes.as_mut_ptr();
                    request.bytes = bytes.len() as u32;
                    (request, bytes)
                })
                .collect();
            for (request, _) in &mut slots {
                assert!(unsafe { backend.submit(&mut **request) });
            }
            let mut completed = std::collections::HashSet::new();
            for _ in &slots {
                let (address, ok) = rx.recv_timeout(Duration::from_secs(10)).unwrap();
                assert!(ok);
                assert!(completed.insert(address));
            }
            for (request, _) in &slots {
                assert!(completed.contains(&(&**request as *const _ as usize)));
            }
            transfer(&backend, &rx, Op::Flush, 0, &mut []);
            assert_eq!(backend.inflight(), 0);
            assert!(!backend.discard_range(size - 512, 1024));
            assert!(!backend.discard_range(1, 512));
            transfer(&backend, &rx, Op::Write, 4 * 1024 * 1024, &mut [0x5a; 4096]);
            assert!(backend.discard_range(4 * 1024 * 1024, 2 * 1024 * 1024));
            transfer(&backend, &rx, Op::Write, 2 * 1024 * 1024, &mut [0; 512]);
            transfer(&backend, &rx, Op::Flush, 0, &mut []);
            assert_eq!(backend.inflight(), 0);
        }
        {
            let backend = BlockFile::new(image.path(), true);
            assert!(backend.open(), "error {}", backend.open_err());
            let rx = completion(&backend);
            let mut data = vec![0; 4096];
            transfer(&backend, &rx, Op::Read, 2 * 1024 * 1024 - 512, &mut data);
            assert_eq!(&data[..512], &[1; 512]);
            assert_eq!(&data[512..1024], &[0; 512]);
            assert_eq!(&data[1024..], &[1; 3072]);
            transfer(&backend, &rx, Op::Read, 8 * 1024 * 1024, &mut data);
            assert_eq!(data, vec![0; 4096]);
            assert!(!backend.discard_range(0, 512));
            let mut request = Request::zeroed();
            request.op = Op::Write;
            request.buf = data.as_mut_ptr();
            request.bytes = data.len() as u32;
            assert!(!unsafe { backend.submit(&mut request) });
            assert_eq!(backend.inflight(), 0);
        }
        // All virtual handles must be closed before the image can be reopened
        // for writing or deleted (attachment lifetime follows those handles).
        assert!(BlockFile::new(image.path(), false).open());
        std::fs::remove_file(&image.0).unwrap();
    }

    #[test]
    fn native_vhdx_rejects_invalid_container() {
        let image = TestImage::new();
        for extension in ["vhdx", "img", "iso"] {
            let path = image.0.with_extension(extension);
            std::fs::write(&path, [0; 4096]).unwrap();
            for readonly in [false, true] {
                let backend = BlockFile::new(path.to_str().unwrap(), readonly);
                assert!(!backend.open());
                assert_ne!(backend.open_err(), 0);
            }
            assert_eq!(std::fs::read(&path).unwrap(), vec![0; 4096]);
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn installation_iso_is_explicit_and_read_only() {
        let image = TestImage::new();
        std::fs::write(&image.0, [0x42; 4096]).unwrap();
        let backend = BlockFile::new_iso(image.path());
        assert!(backend.open());
        assert!(backend.readonly());
        let rx = completion(&backend);
        let mut data = [0; 4096];
        transfer(&backend, &rx, Op::Read, 0, &mut data);
        assert_eq!(data, [0x42; 4096]);
        assert!(!backend.discard_range(0, 512));
        let mut request = Request::zeroed();
        request.op = Op::Write;
        request.buf = data.as_mut_ptr();
        request.bytes = data.len() as u32;
        assert!(!unsafe { backend.submit(&mut request) });
    }
}
