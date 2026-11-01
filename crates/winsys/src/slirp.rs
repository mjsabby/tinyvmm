//! libslirp (QEMU's user-mode network stack), loaded at run time from
//! `libslirp-0.dll` — MSYS2's build, which `tools/fetch_libslirp.py` fetches
//! with the GLib DLLs it needs. All of the FFI is here: the C structs, the
//! callback trampolines and the poll loop's `WSAPoll`.
//!
//! libslirp is single-threaded: every call on a [`Slirp`] (and every callback
//! it makes into its [`SlirpHost`]) happens on the thread that drives it.

use core::ffi::{c_char, c_int, c_void};
use std::path::PathBuf;
use std::ptr::NonNull;
use std::sync::OnceLock;
use std::time::Instant;
use windows_sys::Win32::Foundation::{GetLastError, HMODULE};
use windows_sys::Win32::Networking::WinSock::{
    POLLERR, POLLHUP, POLLNVAL, POLLRDBAND, POLLRDNORM, POLLWRNORM, SOCKET, WSAPOLLFD, WSAPoll,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
    LoadLibraryExW, LoadLibraryW,
};

const DLL: &str = "libslirp-0.dll";

const POLL_IN: c_int = 1 << 0;
const POLL_OUT: c_int = 1 << 1;
const POLL_PRI: c_int = 1 << 2;
const POLL_ERR: c_int = 1 << 3;
const POLL_HUP: c_int = 1 << 4;

/// `struct in_addr` (4-byte aligned, network order in memory).
#[repr(C)]
#[derive(Clone, Copy)]
struct InAddr(u32);

impl InAddr {
    fn of(a: [u8; 4]) -> Self {
        InAddr(u32::from_ne_bytes(a))
    }
}

/// `struct in6_addr` (2-byte aligned).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct In6Addr([u16; 8]);

/// `SlirpConfig`, version 4 (libslirp 4.1+). Field order and C types match
/// libslirp.h; later versions only append fields.
#[repr(C)]
struct RawConfig {
    version: u32,
    restricted: c_int,
    in_enabled: bool,
    vnetwork: InAddr,
    vnetmask: InAddr,
    vhost: InAddr,
    in6_enabled: bool,
    vprefix_addr6: In6Addr,
    vprefix_len: u8,
    vhost6: In6Addr,
    vhostname: *const c_char,
    tftp_server_name: *const c_char,
    tftp_path: *const c_char,
    bootfile: *const c_char,
    vdhcp_start: InAddr,
    vnameserver: InAddr,
    vnameserver6: In6Addr,
    vdnssearch: *const *const c_char,
    vdomainname: *const c_char,
    if_mtu: usize,
    if_mru: usize,
    disable_host_loopback: bool,
    enable_emu: bool,
    // version 2
    outbound_addr: *const c_void,
    outbound_addr6: *const c_void,
    // version 3
    disable_dns: bool,
    // version 4
    disable_dhcp: bool,
}

// The offsets libslirp.h gives these fields on Windows x64.
const _: () = {
    assert!(core::mem::offset_of!(RawConfig, vnetwork) == 12);
    assert!(core::mem::offset_of!(RawConfig, vprefix_addr6) == 26);
    assert!(core::mem::offset_of!(RawConfig, vhost6) == 44);
    assert!(core::mem::offset_of!(RawConfig, vhostname) == 64);
    assert!(core::mem::offset_of!(RawConfig, vdhcp_start) == 96);
    assert!(core::mem::offset_of!(RawConfig, vnameserver6) == 104);
    assert!(core::mem::offset_of!(RawConfig, if_mtu) == 136);
    assert!(core::mem::offset_of!(RawConfig, disable_host_loopback) == 152);
    assert!(core::mem::offset_of!(RawConfig, outbound_addr) == 160);
    assert!(core::mem::offset_of!(RawConfig, disable_dhcp) == 177);
};

type TimerCb = unsafe extern "C" fn(*mut c_void);

/// `SlirpCb`: what libslirp calls back. It keeps a pointer to it, so it
/// must outlive the instance.
#[repr(C)]
struct RawCallbacks {
    send_packet: unsafe extern "C" fn(*const c_void, usize, *mut c_void) -> isize,
    guest_error: unsafe extern "C" fn(*const c_char, *mut c_void),
    clock_get_ns: unsafe extern "C" fn(*mut c_void) -> i64,
    timer_new: Option<unsafe extern "C" fn(TimerCb, *mut c_void, *mut c_void) -> *mut c_void>,
    timer_free: unsafe extern "C" fn(*mut c_void, *mut c_void),
    timer_mod: unsafe extern "C" fn(*mut c_void, i64, *mut c_void),
    register_poll_fd: unsafe extern "C" fn(c_int, *mut c_void),
    unregister_poll_fd: unsafe extern "C" fn(c_int, *mut c_void),
    notify: unsafe extern "C" fn(*mut c_void),
    // version 4
    init_completed: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    timer_new_opaque: unsafe extern "C" fn(c_int, *mut c_void, *mut c_void) -> *mut c_void,
}

type NewFn =
    unsafe extern "C" fn(*const RawConfig, *const RawCallbacks, *mut c_void) -> *mut c_void;
type CleanupFn = unsafe extern "C" fn(*mut c_void);
type AddPollCb = unsafe extern "C" fn(SOCKET, c_int, *mut c_void) -> c_int;
type FillFn = unsafe extern "C" fn(*mut c_void, *mut u32, AddPollCb, *mut c_void);
type GetReventsCb = unsafe extern "C" fn(c_int, *mut c_void) -> c_int;
type PollFn = unsafe extern "C" fn(*mut c_void, c_int, GetReventsCb, *mut c_void);
type InputFn = unsafe extern "C" fn(*mut c_void, *const u8, c_int);
type HandleTimerFn = unsafe extern "C" fn(*mut c_void, c_int, *mut c_void);
type AddHostfwdFn = unsafe extern "C" fn(*mut c_void, c_int, InAddr, c_int, InAddr, c_int) -> c_int;
type VersionFn = unsafe extern "C" fn() -> *const c_char;

/// The libslirp exports tinyvmm uses.
struct Api {
    new: NewFn,
    cleanup: CleanupFn,
    pollfds_fill_socket: FillFn,
    pollfds_poll: PollFn,
    input: InputFn,
    handle_timer: HandleTimerFn,
    add_hostfwd: AddHostfwdFn,
    version: VersionFn,
}

/// Load libslirp once: from `TINYVMM_LIBSLIRP` (a path to the DLL), else
/// next to the running executable, else from the DLL search path. Its own
/// dependencies (GLib, ...) load from the directory it is in.
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
    if let Some(p) = std::env::var_os("TINYVMM_LIBSLIRP") {
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
            "could not load {DLL} (err={}); run tools\\fetch_libslirp.py, which puts it and the \
             DLLs it needs next to tinyvmm.exe, or set TINYVMM_LIBSLIRP to its path",
            unsafe { GetLastError() }
        ));
    }
    let sym = |name: &str| -> Result<*const (), String> {
        let c: Vec<u8> = name.bytes().chain([0]).collect();
        match unsafe { GetProcAddress(module, c.as_ptr()) } {
            Some(f) => Ok(f as *const ()),
            None => Err(format!("{DLL} has no export {name} (libslirp 4.7+ needed)")),
        }
    };
    // SAFETY: each export has the C signature libslirp.h declares for it.
    unsafe {
        Ok(Api {
            new: core::mem::transmute::<*const (), NewFn>(sym("slirp_new")?),
            cleanup: core::mem::transmute::<*const (), CleanupFn>(sym("slirp_cleanup")?),
            pollfds_fill_socket: core::mem::transmute::<*const (), FillFn>(sym(
                "slirp_pollfds_fill_socket",
            )?),
            pollfds_poll: core::mem::transmute::<*const (), PollFn>(sym("slirp_pollfds_poll")?),
            input: core::mem::transmute::<*const (), InputFn>(sym("slirp_input")?),
            handle_timer: core::mem::transmute::<*const (), HandleTimerFn>(sym(
                "slirp_handle_timer",
            )?),
            add_hostfwd: core::mem::transmute::<*const (), AddHostfwdFn>(sym("slirp_add_hostfwd")?),
            version: core::mem::transmute::<*const (), VersionFn>(sym("slirp_version_string")?),
        })
    }
}

/// The loaded libslirp's version string (loading it if need be).
pub fn version() -> Result<String, String> {
    let api = api()?;
    // SAFETY: a static NUL-terminated string.
    let s = unsafe { std::ffi::CStr::from_ptr((api.version)()) };
    Ok(s.to_string_lossy().into_owned())
}

/// The guest network a [`Slirp`] emulates (IPv4 only).
pub struct SlirpConfig {
    pub network: [u8; 4],
    pub netmask: [u8; 4],
    /// The gateway; connections to it reach the host's loopback.
    pub host: [u8; 4],
    /// The address DHCP hands the guest.
    pub dhcp_start: [u8; 4],
    /// libslirp's DNS forwarder (offered by DHCP).
    pub nameserver: [u8; 4],
    /// MTU and MRU of the guest link.
    pub mtu: usize,
}

/// What a [`Slirp`] calls back into, on its driving thread.
pub trait SlirpHost {
    /// An Ethernet frame for the guest.
    fn send_packet(&mut self, frame: &[u8]);
    /// libslirp's complaint about something the guest sent.
    fn guest_error(&mut self, msg: &str);
}

/// A libslirp timer (`timer_new_opaque`): libslirp's own, fired through
/// `slirp_handle_timer`.
struct Timer {
    /// The opaque handle libslirp knows it by (never dereferenced).
    handle: usize,
    id: c_int,
    cb_opaque: *mut c_void,
    expire_ms: Option<i64>,
}

/// What the callbacks reach through libslirp's opaque pointer.
struct CbState<H> {
    host: H,
    start: Instant,
    timers: Vec<Timer>,
    /// The last timer handle given out (0 is never one).
    last_timer: usize,
}

/// One libslirp instance with host `H`.
pub struct Slirp<H: SlirpHost> {
    api: &'static Api,
    raw: NonNull<c_void>,
    // Both outlive `raw` (dropped after `slirp_cleanup` in `drop`).
    state: Box<CbState<H>>,
    _cb: Box<RawCallbacks>,
    pollfds: Vec<WSAPOLLFD>,
}

/// What [`Slirp::poll`] saw on the caller's extra sockets.
pub struct Polled {
    /// Bit i set: `extra[i]` is readable (or closed / in error).
    pub readable: u64,
}

impl<H: SlirpHost> Slirp<H> {
    /// A new instance for `cfg`, calling back into `host`.
    pub fn new(cfg: &SlirpConfig, host: H) -> Result<Self, String> {
        let api = api()?;
        let cb = Box::new(RawCallbacks {
            send_packet: send_packet::<H>,
            guest_error: guest_error::<H>,
            clock_get_ns: clock_get_ns::<H>,
            timer_new: None,
            timer_free: timer_free::<H>,
            timer_mod: timer_mod::<H>,
            register_poll_fd: noop_fd,
            unregister_poll_fd: noop_fd,
            notify: noop,
            init_completed: None,
            timer_new_opaque: timer_new_opaque::<H>,
        });
        let mtu = cfg.mtu;
        let raw_cfg = RawConfig {
            version: 4,
            restricted: 0,
            in_enabled: true,
            vnetwork: InAddr::of(cfg.network),
            vnetmask: InAddr::of(cfg.netmask),
            vhost: InAddr::of(cfg.host),
            in6_enabled: false,
            vprefix_addr6: In6Addr::default(),
            vprefix_len: 0,
            vhost6: In6Addr::default(),
            vhostname: std::ptr::null(),
            tftp_server_name: std::ptr::null(),
            tftp_path: std::ptr::null(),
            bootfile: std::ptr::null(),
            vdhcp_start: InAddr::of(cfg.dhcp_start),
            vnameserver: InAddr::of(cfg.nameserver),
            vnameserver6: In6Addr::default(),
            vdnssearch: std::ptr::null(),
            vdomainname: std::ptr::null(),
            if_mtu: mtu,
            if_mru: mtu,
            disable_host_loopback: false,
            enable_emu: false,
            outbound_addr: std::ptr::null(),
            outbound_addr6: std::ptr::null(),
            disable_dns: false,
            disable_dhcp: false,
        };
        let mut state = Box::new(CbState {
            host,
            start: Instant::now(),
            timers: Vec::new(),
            last_timer: 0,
        });
        let opaque = &mut *state as *mut CbState<H> as *mut c_void;
        // SAFETY: the config is read during the call; `cb` and `state` are
        // boxed (stable) and outlive the instance.
        let raw = unsafe { (api.new)(&raw_cfg, &*cb, opaque) };
        let raw = NonNull::new(raw).ok_or("slirp_new failed (bad network configuration?)")?;
        Ok(Slirp {
            api,
            raw,
            state,
            _cb: cb,
            pollfds: Vec::new(),
        })
    }

    pub fn host(&mut self) -> &mut H {
        &mut self.state.host
    }

    /// Hand libslirp an Ethernet frame from the guest.
    pub fn input(&mut self, frame: &[u8]) {
        let Ok(len) = c_int::try_from(frame.len()) else {
            return;
        };
        // SAFETY: the frame is read during the call; callbacks it makes
        // reach `state` alone.
        unsafe { (self.api.input)(self.raw.as_ptr(), frame.as_ptr(), len) };
    }

    /// Forward host TCP (or UDP) `host_addr:host_port` to the guest's
    /// `guest_addr:guest_port`. False if libslirp refused (e.g. port in use).
    pub fn add_hostfwd(
        &mut self,
        udp: bool,
        host_addr: [u8; 4],
        host_port: u16,
        guest_addr: [u8; 4],
        guest_port: u16,
    ) -> bool {
        // SAFETY: plain values.
        unsafe {
            (self.api.add_hostfwd)(
                self.raw.as_ptr(),
                c_int::from(udp),
                InAddr::of(host_addr),
                c_int::from(host_port),
                InAddr::of(guest_addr),
                c_int::from(guest_port),
            ) == 0
        }
    }

    /// One turn of libslirp's loop: wait (up to `max_ms`, or less if a
    /// timer is due sooner) for its sockets or one of `extra` to be ready,
    /// let it handle its sockets and timers, and report which of `extra`
    /// (at most 64) became readable.
    pub fn poll(&mut self, max_ms: u32, extra: &[SOCKET]) -> Polled {
        let mut timeout = max_ms;
        self.pollfds.clear();
        let fds = &mut self.pollfds as *mut Vec<WSAPOLLFD> as *mut c_void;
        // SAFETY: `add_poll` only pushes onto `pollfds`, which nothing else
        // borrows during the call.
        unsafe { (self.api.pollfds_fill_socket)(self.raw.as_ptr(), &mut timeout, add_poll, fds) };
        let now = self.now_ms();
        if let Some(t) = self.state.timers.iter().filter_map(|t| t.expire_ms).min() {
            timeout = timeout.min(u32::try_from((t - now).max(0)).unwrap_or(u32::MAX));
        }
        let base = self.pollfds.len();
        self.pollfds
            .extend(extra.iter().take(64).map(|&fd| WSAPOLLFD {
                fd,
                events: POLLRDNORM,
                revents: 0,
            }));
        let wait = i32::try_from(timeout).unwrap_or(i32::MAX);
        // SAFETY: a valid array of `len` entries.
        let n = unsafe { WSAPoll(self.pollfds.as_mut_ptr(), self.pollfds.len() as u32, wait) };
        let fds = &self.pollfds as *const Vec<WSAPOLLFD> as *mut c_void;
        // SAFETY: `get_revents` only reads `pollfds`.
        unsafe { (self.api.pollfds_poll)(self.raw.as_ptr(), c_int::from(n < 0), get_revents, fds) };
        let readable = self.pollfds[base..]
            .iter()
            .enumerate()
            .filter(|(_, p)| p.revents != 0)
            .fold(0u64, |m, (i, _)| m | 1 << i);
        self.fire_timers();
        Polled { readable }
    }

    fn now_ms(&self) -> i64 {
        self.state.start.elapsed().as_millis() as i64
    }

    fn fire_timers(&mut self) {
        let now = self.now_ms();
        let due: Vec<(c_int, *mut c_void)> = self
            .state
            .timers
            .iter_mut()
            .filter(|t| t.expire_ms.is_some_and(|e| e <= now))
            .map(|t| {
                t.expire_ms = None;
                (t.id, t.cb_opaque)
            })
            .collect();
        for (id, cb_opaque) in due {
            // SAFETY: the id and opaque libslirp gave `timer_new_opaque`.
            unsafe { (self.api.handle_timer)(self.raw.as_ptr(), id, cb_opaque) };
        }
    }
}

impl<H: SlirpHost> Drop for Slirp<H> {
    fn drop(&mut self) {
        // SAFETY: the instance is not used again; `state` and the callbacks
        // are freed after this returns.
        unsafe { (self.api.cleanup)(self.raw.as_ptr()) };
    }
}

/// # Safety (all callbacks)
/// `opaque` is the `CbState<H>` given to `slirp_new`, and libslirp calls
/// back only from within a call made on the driving thread, while nothing
/// else borrows that state.
unsafe fn state<'a, H>(opaque: *mut c_void) -> &'a mut CbState<H> {
    unsafe { &mut *(opaque as *mut CbState<H>) }
}

unsafe extern "C" fn send_packet<H: SlirpHost>(
    buf: *const c_void,
    len: usize,
    opaque: *mut c_void,
) -> isize {
    let frame = unsafe { std::slice::from_raw_parts(buf as *const u8, len) };
    unsafe { state::<H>(opaque) }.host.send_packet(frame);
    len as isize
}

unsafe extern "C" fn guest_error<H: SlirpHost>(msg: *const c_char, opaque: *mut c_void) {
    let msg = unsafe { std::ffi::CStr::from_ptr(msg) }.to_string_lossy();
    unsafe { state::<H>(opaque) }.host.guest_error(&msg);
}

unsafe extern "C" fn clock_get_ns<H>(opaque: *mut c_void) -> i64 {
    unsafe { state::<H>(opaque) }.start.elapsed().as_nanos() as i64
}

unsafe extern "C" fn timer_new_opaque<H>(
    id: c_int,
    cb_opaque: *mut c_void,
    opaque: *mut c_void,
) -> *mut c_void {
    let s = unsafe { state::<H>(opaque) };
    s.last_timer += 1;
    s.timers.push(Timer {
        handle: s.last_timer,
        id,
        cb_opaque,
        expire_ms: None,
    });
    s.last_timer as *mut c_void
}

unsafe extern "C" fn timer_free<H>(timer: *mut c_void, opaque: *mut c_void) {
    unsafe { state::<H>(opaque) }
        .timers
        .retain(|t| t.handle != timer as usize);
}

unsafe extern "C" fn timer_mod<H>(timer: *mut c_void, expire_ms: i64, opaque: *mut c_void) {
    if let Some(t) = unsafe { state::<H>(opaque) }
        .timers
        .iter_mut()
        .find(|t| t.handle == timer as usize)
    {
        t.expire_ms = Some(expire_ms);
    }
}

unsafe extern "C" fn noop_fd(_: c_int, _: *mut c_void) {}
unsafe extern "C" fn noop(_: *mut c_void) {}

unsafe extern "C" fn add_poll(fd: SOCKET, events: c_int, opaque: *mut c_void) -> c_int {
    // SAFETY: `opaque` is the poll array `Slirp::poll` passed.
    let fds = unsafe { &mut *(opaque as *mut Vec<WSAPOLLFD>) };
    let mut ev = 0;
    if events & (POLL_IN | POLL_PRI) != 0 {
        ev |= POLLRDNORM;
    }
    if events & POLL_OUT != 0 {
        ev |= POLLWRNORM;
    }
    fds.push(WSAPOLLFD {
        fd,
        events: ev,
        revents: 0,
    });
    (fds.len() - 1) as c_int
}

unsafe extern "C" fn get_revents(idx: c_int, opaque: *mut c_void) -> c_int {
    // SAFETY: `opaque` is the poll array `Slirp::poll` passed.
    let fds = unsafe { &*(opaque as *const Vec<WSAPOLLFD>) };
    let Some(p) = usize::try_from(idx).ok().and_then(|i| fds.get(i)) else {
        return 0;
    };
    let r = p.revents;
    let mut out = 0;
    if r & (POLLRDNORM | POLLRDBAND) != 0 {
        out |= POLL_IN;
    }
    if r & POLLWRNORM != 0 {
        out |= POLL_OUT;
    }
    if r & (POLLERR | POLLNVAL) != 0 {
        out |= POLL_ERR;
    }
    if r & POLLHUP != 0 {
        out |= POLL_HUP;
    }
    out
}
