//! Thin wrappers over the Winsock + IOCP FFI used by the NAT backend. Kept
//! small and explicit; all the unsafe is funnelled here.

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY,
};
use windows_sys::Win32::Networking::WinSock::{
    accept, bind, closesocket, connect, listen, setsockopt, shutdown, socket, WSAGetLastError,
    WSAIoctl, WSARecv, WSASend, WSAStartup, AF_INET, INVALID_SOCKET, IN_ADDR, IN_ADDR_0,
    IPPROTO_TCP, IPPROTO_UDP, SD_SEND, SOCKADDR, SOCKADDR_IN, SOCKET, SOCK_DGRAM, SOCK_STREAM,
    SOL_SOCKET, WSABUF, WSADATA, WSA_IO_PENDING,
};
use windows_sys::Win32::System::IO::{
    CreateIoCompletionPort, GetQueuedCompletionStatus, PostQueuedCompletionStatus, OVERLAPPED,
};

use core::ffi::c_void;
use std::sync::{Once, OnceLock};

const SIO_GET_EXTENSION_FUNCTION_POINTER: u32 = 0xC800_0006;
const SO_UPDATE_CONNECT_CONTEXT: i32 = 0x7010;

/// Initialise Winsock 2.2 once for the process.
pub fn wsa_startup() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let mut data: WSADATA = unsafe { core::mem::zeroed() };
        let rc = unsafe { WSAStartup(0x0202, &mut data) };
        if rc != 0 {
            eprintln!("[nat] WSAStartup failed: {rc}");
        }
    });
}

/// Copyable, thread-shareable IOCP handle.
#[derive(Clone, Copy)]
pub struct Iocp(pub HANDLE);
// SAFETY: an I/O completion port handle is explicitly designed for concurrent
// use from multiple threads (PostQueuedCompletionStatus / GetQueuedCompletion
// Status are thread-safe); sharing the handle is the intended usage.
unsafe impl Send for Iocp {}
unsafe impl Sync for Iocp {}

pub fn create_iocp() -> Option<Iocp> {
    let h = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, std::ptr::null_mut(), 0, 0) };
    if h.is_null() {
        None
    } else {
        Some(Iocp(h))
    }
}

pub fn associate(iocp: Iocp, sock: SOCKET, key: usize) -> bool {
    let h = unsafe { CreateIoCompletionPort(sock as HANDLE, iocp.0, key, 0) };
    !h.is_null()
}

pub fn post(iocp: Iocp, bytes: u32, key: usize, ov: *mut OVERLAPPED) -> bool {
    unsafe { PostQueuedCompletionStatus(iocp.0, bytes, key, ov) != 0 }
}

/// Block for the next completion. Returns (success, bytes, key, overlapped).
pub fn get(iocp: Iocp) -> (bool, u32, usize, *mut OVERLAPPED) {
    get_ms(iocp, u32::MAX)
}

/// Like `get` but with a millisecond timeout. On timeout returns
/// `(false, 0, 0, null)`.
pub fn get_ms(iocp: Iocp, ms: u32) -> (bool, u32, usize, *mut OVERLAPPED) {
    let mut bytes = 0u32;
    let mut key = 0usize;
    let mut ov: *mut OVERLAPPED = std::ptr::null_mut();
    let ok = unsafe { GetQueuedCompletionStatus(iocp.0, &mut bytes, &mut key, &mut ov, ms) };
    (ok != 0, bytes, key, ov)
}

pub fn sockaddr_in(ip: [u8; 4], port: u16) -> SOCKADDR_IN {
    SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: port.to_be(),
        sin_addr: IN_ADDR {
            // Network-order octets land in memory as-is via from_ne_bytes.
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes(ip),
            },
        },
        sin_zero: [0; 8],
    }
}

pub fn new_udp_socket() -> Option<SOCKET> {
    let s = unsafe { socket(AF_INET as i32, SOCK_DGRAM, IPPROTO_UDP) };
    if s == INVALID_SOCKET {
        None
    } else {
        Some(s)
    }
}

pub fn new_tcp_socket() -> Option<SOCKET> {
    let s = unsafe { socket(AF_INET as i32, SOCK_STREAM, IPPROTO_TCP) };
    if s == INVALID_SOCKET {
        None
    } else {
        Some(s)
    }
}

/// Set the default peer for a (UDP or connected-TCP) socket.
pub fn connect_sock(s: SOCKET, ip: [u8; 4], port: u16) -> bool {
    let sa = sockaddr_in(ip, port);
    let rc = unsafe {
        connect(
            s,
            &sa as *const SOCKADDR_IN as *const SOCKADDR,
            core::mem::size_of::<SOCKADDR_IN>() as i32,
        )
    };
    rc == 0
}

pub fn close_sock(s: SOCKET) {
    unsafe {
        closesocket(s);
    }
}

/// Post an overlapped receive. `wsabuf`/`ov` must outlive the operation.
///
/// # Safety
/// `wsabuf` must point to a valid `WSABUF` whose buffer, and `ov` (an
/// `OVERLAPPED`), both remain alive and pinned until the IOCP completion for
/// this receive is dequeued.
pub unsafe fn wsa_recv(s: SOCKET, wsabuf: *const WSABUF, ov: *mut OVERLAPPED) -> i32 {
    let mut flags = 0u32;
    let mut recvd = 0u32;
    unsafe { WSARecv(s, wsabuf, 1, &mut recvd, &mut flags, ov, None) }
}

/// Synchronous send (no overlapped -> no IOCP completion). Used only for UDP,
/// where a datagram send can't block on peer flow-control (no windowing): a
/// connected UDP socket's send completes into the local buffer immediately, so
/// it can't stall the worker the way a backpressured TCP send can.
pub fn wsa_send(s: SOCKET, data: &[u8]) -> i32 {
    let wb = WSABUF {
        len: data.len() as u32,
        buf: data.as_ptr() as *mut u8,
    };
    let mut sent = 0u32;
    unsafe { WSASend(s, &wb, 1, &mut sent, 0, std::ptr::null_mut(), None) }
}

/// Post an overlapped send. `wsabuf`/`ov` must outlive the operation. Returns
/// true if a completion will be delivered (an inline success still queues one),
/// false if the send failed synchronously (no completion will arrive).
///
/// # Safety
/// `wsabuf` must point to a valid `WSABUF` whose buffer, and `ov` (an
/// `OVERLAPPED`), both remain alive and pinned until the IOCP completion for
/// this send is dequeued.
pub unsafe fn wsa_send_ov(s: SOCKET, wsabuf: *const WSABUF, ov: *mut OVERLAPPED) -> bool {
    let mut sent = 0u32;
    let r = unsafe { WSASend(s, wsabuf, 1, &mut sent, 0, ov, None) };
    r == 0 || unsafe { WSAGetLastError() } == WSA_IO_PENDING
}

pub fn wsabuf(ptr: *mut u8, len: usize) -> WSABUF {
    WSABUF {
        len: len as u32,
        buf: ptr,
    }
}

/// Bind a socket to 0.0.0.0:0 (required before ConnectEx).
pub fn bind_any(s: SOCKET) -> bool {
    let sa = sockaddr_in([0, 0, 0, 0], 0);
    unsafe {
        bind(
            s,
            &sa as *const SOCKADDR_IN as *const SOCKADDR,
            core::mem::size_of::<SOCKADDR_IN>() as i32,
        ) == 0
    }
}

/// Create a listening TCP socket bound to `addr:port` (for port-forwarding).
pub fn new_tcp_listener(addr: [u8; 4], port: u16) -> Option<SOCKET> {
    let s = unsafe { socket(AF_INET as i32, SOCK_STREAM, IPPROTO_TCP) };
    if s == INVALID_SOCKET {
        return None;
    }
    let sa = sockaddr_in(addr, port);
    let bound = unsafe {
        bind(
            s,
            &sa as *const SOCKADDR_IN as *const SOCKADDR,
            core::mem::size_of::<SOCKADDR_IN>() as i32,
        )
    };
    if bound != 0 || unsafe { listen(s, 64) } != 0 {
        unsafe {
            closesocket(s);
        }
        return None;
    }
    Some(s)
}

/// Block until a client connects (or the listener is closed). Returns
/// INVALID_SOCKET when the listener has been closed for shutdown.
pub fn accept_one(listener: SOCKET) -> SOCKET {
    unsafe { accept(listener, std::ptr::null_mut(), std::ptr::null_mut()) }
}

pub fn update_connect_ctx(s: SOCKET) {
    unsafe {
        setsockopt(
            s,
            SOL_SOCKET,
            SO_UPDATE_CONNECT_CONTEXT,
            std::ptr::null(),
            0,
        );
    }
}

pub fn shutdown_send(s: SOCKET) {
    unsafe {
        shutdown(s, SD_SEND);
    }
}

type ConnectExFn = unsafe extern "system" fn(
    SOCKET,
    *const SOCKADDR,
    i32,
    *const c_void,
    u32,
    *mut u32,
    *mut OVERLAPPED,
) -> i32;

fn connect_ex_ptr() -> Option<ConnectExFn> {
    static PTR: OnceLock<usize> = OnceLock::new();
    let p = *PTR.get_or_init(|| {
        let s = unsafe { socket(AF_INET as i32, SOCK_STREAM, IPPROTO_TCP) };
        if s == INVALID_SOCKET {
            return 0;
        }
        let guid = GUID {
            data1: 0x25a2_07b9,
            data2: 0xddf3,
            data3: 0x4660,
            data4: [0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e],
        };
        let mut func: usize = 0;
        let mut bytes = 0u32;
        let rc = unsafe {
            WSAIoctl(
                s,
                SIO_GET_EXTENSION_FUNCTION_POINTER,
                &guid as *const GUID as *const c_void,
                core::mem::size_of::<GUID>() as u32,
                &mut func as *mut usize as *mut c_void,
                core::mem::size_of::<usize>() as u32,
                &mut bytes,
                std::ptr::null_mut(),
                None,
            )
        };
        unsafe {
            closesocket(s);
        }
        if rc != 0 {
            0
        } else {
            func
        }
    });
    if p == 0 {
        None
    } else {
        Some(unsafe { core::mem::transmute::<usize, ConnectExFn>(p) })
    }
}

/// Start an overlapped connect. `ov` must outlive the operation. Returns true
/// if the connect is in progress (or completed immediately).
///
/// # Safety
/// `ov` must point to an `OVERLAPPED` that remains alive and pinned until the
/// IOCP completion for this connect is dequeued.
pub unsafe fn connect_ex(s: SOCKET, ip: [u8; 4], port: u16, ov: *mut OVERLAPPED) -> bool {
    let Some(f) = connect_ex_ptr() else {
        return false;
    };
    let sa = sockaddr_in(ip, port);
    let mut sent = 0u32;
    let r = unsafe {
        f(
            s,
            &sa as *const SOCKADDR_IN as *const SOCKADDR,
            core::mem::size_of::<SOCKADDR_IN>() as i32,
            std::ptr::null(),
            0,
            &mut sent,
            ov,
        )
    };
    r != 0 || unsafe { WSAGetLastError() } == WSA_IO_PENDING
}

// ---------------------------------------------------------------------------
// ICMP echo (iphlpapi) -- used to proxy guest pings to real remote hosts.
// IcmpSendEcho is synchronous/blocking, so it runs on a dedicated worker pool.
// ---------------------------------------------------------------------------

/// Open an ICMP request handle (one per worker thread). Returns
/// INVALID_HANDLE_VALUE on failure.
pub fn icmp_create() -> HANDLE {
    unsafe { IcmpCreateFile() }
}

pub fn icmp_close(h: HANDLE) {
    if h != INVALID_HANDLE_VALUE && !h.is_null() {
        unsafe {
            IcmpCloseHandle(h);
        }
    }
}

/// Ping `dst` with `data` as the echo payload; returns true if a reply arrived
/// within `timeout_ms`. Blocking — call from a dedicated thread.
pub fn icmp_echo(h: HANDLE, dst: [u8; 4], data: &[u8], timeout_ms: u32) -> bool {
    let addr = u32::from_ne_bytes(dst);
    let req = if data.len() > 1024 {
        &data[..1024]
    } else {
        data
    };
    let reply_len = core::mem::size_of::<ICMP_ECHO_REPLY>() + req.len() + 8;
    let mut reply = vec![0u8; reply_len.max(64)];
    let n = unsafe {
        IcmpSendEcho(
            h,
            addr,
            req.as_ptr() as *const c_void,
            req.len() as u16,
            std::ptr::null(),
            reply.as_mut_ptr() as *mut c_void,
            reply.len() as u32,
            timeout_ms,
        )
    };
    n > 0
}
