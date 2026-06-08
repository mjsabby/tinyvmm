//! Safe wrapper over `wintun.dll` (loaded at runtime via LoadLibrary) plus the
//! IP Helper call that assigns the host adapter address. All of the
//! LoadLibrary/GetProcAddress/`transmute` and fn-pointer-invocation `unsafe` is
//! concentrated here; callers use the safe methods below.
//!
//! The raw `*mut u8` buffers returned by [`WintunApi::receive_packet`] and
//! [`WintunApi::allocate_send_packet`] are intentionally left raw — they point
//! into the WinTun ring and the caller copies the frame bytes itself (a
//! domain-side operation, mirroring guest-buffer access).

use core::ffi::c_void;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{GetLastError, HANDLE, HMODULE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateUnicastIpAddressEntry, InitializeUnicastIpAddressEntry, MIB_UNICASTIPADDRESS_ROW,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, IN_ADDR, IN_ADDR_0, SOCKADDR_IN};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

/// Opaque WinTun adapter handle (WINTUN_ADAPTER_HANDLE).
pub type AdapterHandle = *mut c_void;
/// Opaque WinTun session handle (WINTUN_SESSION_HANDLE).
pub type SessionHandle = *mut c_void;

// WINAPI == extern "system" on x64.
type CreateAdapterFn =
    unsafe extern "system" fn(*const u16, *const u16, *const GUID) -> AdapterHandle;
type CloseAdapterFn = unsafe extern "system" fn(AdapterHandle);
type GetAdapterLuidFn = unsafe extern "system" fn(AdapterHandle, *mut u64);
type StartSessionFn = unsafe extern "system" fn(AdapterHandle, u32) -> SessionHandle;
type EndSessionFn = unsafe extern "system" fn(SessionHandle);
type GetReadWaitEventFn = unsafe extern "system" fn(SessionHandle) -> HANDLE;
type ReceivePacketFn = unsafe extern "system" fn(SessionHandle, *mut u32) -> *mut u8;
type ReleaseReceiveFn = unsafe extern "system" fn(SessionHandle, *const u8);
type AllocateSendFn = unsafe extern "system" fn(SessionHandle, u32) -> *mut u8;
type SendPacketFn = unsafe extern "system" fn(SessionHandle, *const u8);

/// The subset of wintun.dll exports tinyvmm uses, resolved once at load time.
pub struct WintunApi {
    create_adapter: CreateAdapterFn,
    close_adapter: CloseAdapterFn,
    get_adapter_luid: GetAdapterLuidFn,
    start_session: StartSessionFn,
    end_session: EndSessionFn,
    get_read_wait_event: GetReadWaitEventFn,
    receive_packet: ReceivePacketFn,
    release_receive_packet: ReleaseReceiveFn,
    allocate_send_packet: AllocateSendFn,
    send_packet: SendPacketFn,
}

impl WintunApi {
    /// Load wintun.dll and resolve the exports. Returns a descriptive error if
    /// the DLL can't be found or is missing an export.
    pub fn load() -> Result<WintunApi, String> {
        let wide: Vec<u16> = "wintun.dll".encode_utf16().chain([0]).collect();
        let module: HMODULE = unsafe { LoadLibraryW(wide.as_ptr()) };
        if module.is_null() {
            return Err(format!(
                "LoadLibraryW(wintun.dll) failed (err={}); place wintun.dll next to tinyvmm.exe \
                 or on PATH",
                unsafe { GetLastError() }
            ));
        }
        unsafe fn sym(m: HMODULE, name: &str) -> Result<*const (), String> {
            let c: Vec<u8> = name.bytes().chain([0]).collect();
            match GetProcAddress(m, c.as_ptr()) {
                Some(f) => Ok(f as *const ()),
                None => Err(format!("wintun.dll missing export {name}")),
            }
        }
        unsafe {
            Ok(WintunApi {
                create_adapter: core::mem::transmute::<*const (), CreateAdapterFn>(sym(
                    module,
                    "WintunCreateAdapter",
                )?),
                close_adapter: core::mem::transmute::<*const (), CloseAdapterFn>(sym(
                    module,
                    "WintunCloseAdapter",
                )?),
                get_adapter_luid: core::mem::transmute::<*const (), GetAdapterLuidFn>(sym(
                    module,
                    "WintunGetAdapterLUID",
                )?),
                start_session: core::mem::transmute::<*const (), StartSessionFn>(sym(
                    module,
                    "WintunStartSession",
                )?),
                end_session: core::mem::transmute::<*const (), EndSessionFn>(sym(
                    module,
                    "WintunEndSession",
                )?),
                get_read_wait_event: core::mem::transmute::<*const (), GetReadWaitEventFn>(sym(
                    module,
                    "WintunGetReadWaitEvent",
                )?),
                receive_packet: core::mem::transmute::<*const (), ReceivePacketFn>(sym(
                    module,
                    "WintunReceivePacket",
                )?),
                release_receive_packet: core::mem::transmute::<*const (), ReleaseReceiveFn>(sym(
                    module,
                    "WintunReleaseReceivePacket",
                )?),
                allocate_send_packet: core::mem::transmute::<*const (), AllocateSendFn>(sym(
                    module,
                    "WintunAllocateSendPacket",
                )?),
                send_packet: core::mem::transmute::<*const (), SendPacketFn>(sym(
                    module,
                    "WintunSendPacket",
                )?),
            })
        }
    }

    /// Create a WinTun adapter (requires administrator). `name`/`tunnel_type`
    /// are NUL-terminated UTF-16. Returns a null handle on failure (see
    /// [`last_error`]).
    pub fn create_adapter(&self, name: &[u16], tunnel_type: &[u16]) -> AdapterHandle {
        unsafe { (self.create_adapter)(name.as_ptr(), tunnel_type.as_ptr(), core::ptr::null()) }
    }

    /// Close (delete) an adapter created by [`create_adapter`](Self::create_adapter).
    pub fn close_adapter(&self, adapter: AdapterHandle) {
        unsafe { (self.close_adapter)(adapter) }
    }

    /// Return the adapter's NET_LUID as a raw u64 (for IP Helper calls).
    pub fn adapter_luid(&self, adapter: AdapterHandle) -> u64 {
        let mut luid: u64 = 0;
        unsafe { (self.get_adapter_luid)(adapter, &mut luid) };
        luid
    }

    /// Start a ring session of `capacity` bytes. Null handle on failure.
    pub fn start_session(&self, adapter: AdapterHandle, capacity: u32) -> SessionHandle {
        unsafe { (self.start_session)(adapter, capacity) }
    }

    /// End a session started by [`start_session`](Self::start_session).
    pub fn end_session(&self, session: SessionHandle) {
        unsafe { (self.end_session)(session) }
    }

    /// The manual-reset event signaled when the read ring becomes non-empty.
    pub fn read_wait_event(&self, session: SessionHandle) -> HANDLE {
        unsafe { (self.get_read_wait_event)(session) }
    }

    /// Pop the next received packet from the ring, writing its length to `size`.
    /// Returns null when the ring is empty. The caller must copy the bytes and
    /// then call [`release_receive_packet`](Self::release_receive_packet).
    pub fn receive_packet(&self, session: SessionHandle, size: &mut u32) -> *mut u8 {
        unsafe { (self.receive_packet)(session, size as *mut u32) }
    }

    /// Release a packet returned by [`receive_packet`](Self::receive_packet).
    pub fn release_receive_packet(&self, session: SessionHandle, packet: *const u8) {
        unsafe { (self.release_receive_packet)(session, packet) }
    }

    /// Allocate a `size`-byte send slot in the ring. Null on a full ring. The
    /// caller fills it then calls [`send_packet`](Self::send_packet).
    pub fn allocate_send_packet(&self, session: SessionHandle, size: u32) -> *mut u8 {
        unsafe { (self.allocate_send_packet)(session, size) }
    }

    /// Commit a packet previously allocated by
    /// [`allocate_send_packet`](Self::allocate_send_packet).
    pub fn send_packet(&self, session: SessionHandle, packet: *const u8) {
        unsafe { (self.send_packet)(session, packet) }
    }
}

/// Thin wrapper over `GetLastError` for callers reporting WinTun failures.
pub fn last_error() -> u32 {
    unsafe { GetLastError() }
}

/// Assign `ip_be` (network byte order) / `prefix` to the adapter identified by
/// `luid` via the IP Helper API. `ERROR_OBJECT_ALREADY_EXISTS` (5010) on adapter
/// reuse is treated as success.
pub fn assign_unicast_ipv4(luid: u64, ip_be: u32, prefix: u8) -> Result<(), String> {
    unsafe {
        let mut row: MIB_UNICASTIPADDRESS_ROW = core::mem::zeroed();
        InitializeUnicastIpAddressEntry(&mut row);
        // InterfaceLuid is a NET_LUID_LH (a u64-sized union); write the raw value.
        core::ptr::write(&mut row.InterfaceLuid as *mut _ as *mut u64, luid);
        row.Address.Ipv4 = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 { S_addr: ip_be },
            },
            sin_zero: [0; 8],
        };
        row.OnLinkPrefixLength = prefix;
        let rc = CreateUnicastIpAddressEntry(&row);
        if rc != 0 && rc != 5010 {
            return Err(format!("CreateUnicastIpAddressEntry failed (rc={rc})"));
        }
    }
    Ok(())
}
