//! gVisor's netstack, loaded at run time from `tinyvmm_gvisor.dll` (built
//! from `gvisor/` by `gvisor/build.ps1`). All of the FFI is here: the
//! exports' signatures and the trampoline its send callback lands in.
//!
//! The DLL runs the Go runtime; its goroutines call [`GvisorHost::send`]
//! concurrently, from threads tinyvmm doesn't own, until [`Gvisor::close`].

use core::ffi::{c_char, c_void};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock, RwLock};
use windows_sys::Win32::Foundation::{GetLastError, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
    LoadLibraryExW, LoadLibraryW,
};

const DLL: &str = "tinyvmm_gvisor.dll";

type SendFn = unsafe extern "C" fn(*mut c_void, *const u8, i32, i32, i32, i32, i32);
type NewFn = unsafe extern "C" fn(
    *const u8,
    i32,
    *const u8,
    i32,
    SendFn,
    *mut c_void,
    *mut c_char,
    i32,
) -> usize;
type InputFn = unsafe extern "C" fn(usize, *const u8, i32);
type PortFwdFn =
    unsafe extern "C" fn(usize, *const u8, i32, *const u8, i32, *mut c_char, i32) -> i32;
type StatsFn = unsafe extern "C" fn(usize, *mut u64, i32);
type CloseFn = unsafe extern "C" fn(usize);
type VersionFn = unsafe extern "C" fn(*mut c_char, i32);

struct Api {
    new: NewFn,
    input: InputFn,
    add_portfwd: PortFwdFn,
    stats: StatsFn,
    close: CloseFn,
    version: VersionFn,
}

/// Load the DLL once: from `TINYVMM_GVISOR` (a path to it), else next to the
/// running executable, else from the DLL search path.
fn api() -> Result<&'static Api, String> {
    static API: OnceLock<Result<Api, String>> = OnceLock::new();
    API.get_or_init(load).as_ref().map_err(Clone::clone)
}

fn load() -> Result<Api, String> {
    let wide = |s: &std::ffi::OsStr| -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        s.encode_wide().chain([0]).collect()
    };
    let mut paths: Vec<PathBuf> = Vec::new();
    if let Some(p) = std::env::var_os("TINYVMM_GVISOR") {
        paths.push(p.into());
    }
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(PathBuf::from))
    {
        paths.push(dir.join(DLL));
    }
    let mut module: HMODULE = std::ptr::null_mut();
    for p in paths.iter().filter(|p| p.is_file()) {
        let w = wide(p.as_os_str());
        module = unsafe {
            LoadLibraryExW(
                w.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
            )
        };
        if !module.is_null() {
            break;
        }
    }
    if module.is_null() {
        module = unsafe { LoadLibraryW(wide(DLL.as_ref()).as_ptr()) };
    }
    if module.is_null() {
        return Err(format!(
            "could not load {DLL} (err={}); build it with gvisor\\build.ps1, which puts it next \
             to tinyvmm.exe, or set TINYVMM_GVISOR to its path",
            unsafe { GetLastError() }
        ));
    }
    let sym = |name: &str| -> Result<*const (), String> {
        let c: Vec<u8> = name.bytes().chain([0]).collect();
        match unsafe { GetProcAddress(module, c.as_ptr()) } {
            Some(f) => Ok(f as *const ()),
            None => Err(format!("{DLL} has no export {name}")),
        }
    };
    // SAFETY: each export has the signature gvisor/main.go declares for it.
    unsafe {
        Ok(Api {
            new: core::mem::transmute::<*const (), NewFn>(sym("tvg_new")?),
            input: core::mem::transmute::<*const (), InputFn>(sym("tvg_input")?),
            add_portfwd: core::mem::transmute::<*const (), PortFwdFn>(sym("tvg_add_portfwd")?),
            stats: core::mem::transmute::<*const (), StatsFn>(sym("tvg_stats")?),
            close: core::mem::transmute::<*const (), CloseFn>(sym("tvg_close")?),
            version: core::mem::transmute::<*const (), VersionFn>(sym("tvg_version")?),
        })
    }
}

fn message(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// The DLL's gVisor version (loading it if need be).
pub fn version() -> Result<String, String> {
    let api = api()?;
    let mut buf = [0u8; 256];
    // SAFETY: the buffer and its length.
    unsafe { (api.version)(buf.as_mut_ptr().cast(), buf.len() as i32) };
    Ok(message(&buf))
}

/// How a frame for the guest was offloaded.
#[derive(Clone, Copy, Debug, Default)]
pub struct Offload {
    /// A TCPv4 GSO frame of segments of this many payload bytes (0: one
    /// segment).
    pub gso_mss: u16,
    /// The TCP checksum holds only the pseudo-header sum.
    pub needs_csum: bool,
    /// The IP header's length (where the L4 header starts after Ethernet).
    pub l3_len: u16,
}

/// Where the stack's frames for the guest go.
pub trait GvisorHost: Send + Sync + 'static {
    /// A frame for the guest; `more`: another of the same batch follows.
    fn send(&self, frame: &[u8], offload: Offload, more: bool);
}

/// The stack's counters (see `tvg_stats`).
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub segs_sent: u64,
    pub segs_received: u64,
    pub retransmits: u64,
    pub fast_retransmits: u64,
    pub rtos: u64,
    pub dsacked: u64,
    pub input_drops: u64,
    pub tcp_flows: u64,
    pub tcp_refused: u64,
    pub udp_flows: u64,
}

/// A gVisor stack whose frames for the guest go to `H`.
pub struct Gvisor<H: GvisorHost> {
    api: &'static Api,
    /// The Go handle; None once closed. Input holds it for reading, so no
    /// input races `tvg_close`.
    handle: RwLock<Option<usize>>,
    /// What the send trampoline's context points at; freed after close.
    host: *const H,
}

// SAFETY: the handle is used under its lock, and `host` is an `Arc<H>` with
// `H: Send + Sync`.
unsafe impl<H: GvisorHost> Send for Gvisor<H> {}
unsafe impl<H: GvisorHost> Sync for Gvisor<H> {}

impl<H: GvisorHost> Gvisor<H> {
    /// A stack owning `gateway` on a `/prefix` network, its NIC with MAC
    /// `mac` and an MTU of `mtu`.
    pub fn new(
        gateway: [u8; 4],
        prefix: u8,
        mac: [u8; 6],
        mtu: u16,
        host: Arc<H>,
    ) -> Result<Self, String> {
        let api = api()?;
        let ctx = Arc::into_raw(host);
        let mut err = [0u8; 512];
        // SAFETY: the inputs are read during the call; `ctx` stays valid
        // until after `tvg_close` (see `close`).
        let h = unsafe {
            (api.new)(
                gateway.as_ptr(),
                i32::from(prefix),
                mac.as_ptr(),
                i32::from(mtu),
                send_tramp::<H>,
                ctx as *mut c_void,
                err.as_mut_ptr().cast(),
                err.len() as i32,
            )
        };
        if h == 0 {
            // SAFETY: from `Arc::into_raw` above; the stack never started.
            drop(unsafe { Arc::from_raw(ctx) });
            return Err(message(&err));
        }
        Ok(Gvisor {
            api,
            handle: RwLock::new(Some(h)),
            host: ctx,
        })
    }

    /// Hand the stack a frame from the guest (whose L4 checksum it doesn't
    /// check: the guest leaves those of offloaded frames to the host).
    /// Dropped once closed.
    pub fn input(&self, frame: &[u8]) {
        let Ok(len) = i32::try_from(frame.len()) else {
            return;
        };
        if let Some(h) = *self.handle.read().unwrap() {
            // SAFETY: the stack copies the frame during the call.
            unsafe { (self.api.input)(h, frame.as_ptr(), len) };
        }
    }

    /// Forward host TCP `host_addr:host_port` to the guest's
    /// `guest_addr:guest_port`.
    pub fn add_port_forward(
        &self,
        host_addr: [u8; 4],
        host_port: u16,
        guest_addr: [u8; 4],
        guest_port: u16,
    ) -> Result<(), String> {
        let Some(h) = *self.handle.read().unwrap() else {
            return Err("closed".into());
        };
        let mut err = [0u8; 512];
        // SAFETY: the inputs are read during the call.
        let rc = unsafe {
            (self.api.add_portfwd)(
                h,
                host_addr.as_ptr(),
                i32::from(host_port),
                guest_addr.as_ptr(),
                i32::from(guest_port),
                err.as_mut_ptr().cast(),
                err.len() as i32,
            )
        };
        if rc == 0 { Ok(()) } else { Err(message(&err)) }
    }

    pub fn stats(&self) -> Stats {
        let mut v = [0u64; 10];
        if let Some(h) = *self.handle.read().unwrap() {
            // SAFETY: the buffer and its length.
            unsafe { (self.api.stats)(h, v.as_mut_ptr(), v.len() as i32) };
        }
        Stats {
            segs_sent: v[0],
            segs_received: v[1],
            retransmits: v[2],
            fast_retransmits: v[3],
            rtos: v[4],
            dsacked: v[5],
            input_drops: v[6],
            tcp_flows: v[7],
            tcp_refused: v[8],
            udp_flows: v[9],
        }
    }

    /// Stop the stack. Once this returns no send callback runs.
    pub fn close(&self) {
        if let Some(h) = self.handle.write().unwrap().take() {
            // SAFETY: a live handle, closed once.
            unsafe { (self.api.close)(h) };
        }
    }
}

impl<H: GvisorHost> Drop for Gvisor<H> {
    fn drop(&mut self) {
        self.close();
        // SAFETY: from `Arc::into_raw` in `new`; after `close` the stack no
        // longer calls back with it.
        drop(unsafe { Arc::from_raw(self.host) });
    }
}

unsafe extern "C" fn send_tramp<H: GvisorHost>(
    ctx: *mut c_void,
    frame: *const u8,
    len: i32,
    gso_mss: i32,
    needs_csum: i32,
    l3_len: i32,
    more: i32,
) {
    let Ok(len) = usize::try_from(len) else {
        return;
    };
    // SAFETY: `ctx` is the `Arc<H>` given to `tvg_new`, alive until after
    // `tvg_close`; the frame is valid for the call.
    let (host, frame) = unsafe { (&*(ctx as *const H), std::slice::from_raw_parts(frame, len)) };
    let offload = Offload {
        gso_mss: u16::try_from(gso_mss).unwrap_or(0),
        needs_csum: needs_csum != 0,
        l3_len: u16::try_from(l3_len).unwrap_or(0),
    };
    host.send(frame, offload, more != 0);
}
