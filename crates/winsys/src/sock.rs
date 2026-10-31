//! Thin wrappers over the Winsock + IOCP FFI used by the NAT backend. Kept
//! small and explicit; all the unsafe is funnelled here.

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FIXED_INFO_W2KSP1, GetNetworkParams, ICMP_ECHO_REPLY, IP_ADDR_STRING, IcmpCloseHandle,
    IcmpCreateFile, IcmpSendEcho,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, FIONBIO, IN_ADDR, IN_ADDR_0, INVALID_SOCKET, IPPROTO_TCP, IPPROTO_UDP, SD_SEND,
    SO_PROTOCOL_INFOW, SO_RCVBUF, SOCK_DGRAM, SOCK_STREAM, SOCKADDR, SOCKADDR_IN, SOCKET,
    SOL_SOCKET, WSA_IO_PENDING, WSABUF, WSADATA, WSAGetLastError, WSAIoctl, WSAPROTOCOL_INFOW,
    WSARecv, WSASend, WSAStartup, XP1_IFS_HANDLES, accept, bind, closesocket, connect, getpeername,
    getsockname, getsockopt, ioctlsocket, listen, setsockopt, shutdown, socket,
};
use windows_sys::Win32::Storage::FileSystem::SetFileCompletionNotificationModes;
use windows_sys::Win32::System::IO::{
    CreateIoCompletionPort, GetQueuedCompletionStatus, GetQueuedCompletionStatusEx, OVERLAPPED,
    OVERLAPPED_ENTRY, PostQueuedCompletionStatus,
};
use windows_sys::core::GUID;

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
    if h.is_null() { None } else { Some(Iocp(h)) }
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

/// One dequeued completion: (success, bytes, key, overlapped), as `get_ms`
/// would return it.
pub type Completion = (bool, u32, usize, *mut OVERLAPPED);

/// Dequeue up to `out.len()` completions in one call, waiting up to `ms` for
/// the first. Returns how many were stored (0 on timeout).
pub fn get_many(iocp: Iocp, out: &mut [Completion], ms: u32) -> usize {
    const MAX: usize = 64;
    let mut raw: [OVERLAPPED_ENTRY; MAX] = unsafe { core::mem::zeroed() };
    let want = out.len().min(MAX) as u32;
    let mut n = 0u32;
    let ok = unsafe { GetQueuedCompletionStatusEx(iocp.0, raw.as_mut_ptr(), want, &mut n, ms, 0) };
    if ok == 0 {
        return 0;
    }
    for (o, e) in out.iter_mut().zip(&raw[..n as usize]) {
        // `Internal` is the I/O's NTSTATUS: GetQueuedCompletionStatus reports
        // failure exactly when it is not NT_SUCCESS (negative as i32).
        let ok = (e.Internal as i32) >= 0;
        *o = (
            ok,
            e.dwNumberOfBytesTransferred,
            e.lpCompletionKey,
            e.lpOverlapped,
        );
    }
    n as usize
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
        return None;
    }
    // Non-blocking so the single NAT worker's connected-UDP sends can never block
    // on a full send buffer (a hostile UDP flood would otherwise stall the worker,
    // starving all TCP/timer/ICMP/accept work). A full buffer drops the datagram
    // (WSAEWOULDBLOCK) — fine for UDP. Overlapped receives ignore the blocking mode.
    let mut nb: u32 = 1;
    unsafe { ioctlsocket(s, FIONBIO, &mut nb) };
    Some(s)
}

pub fn new_tcp_socket() -> Option<SOCKET> {
    let s = unsafe { socket(AF_INET as i32, SOCK_STREAM, IPPROTO_TCP) };
    if s == INVALID_SOCKET { None } else { Some(s) }
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

/// Post an overlapped receive into `count` buffers (scatter, filled in order).
/// `wsabufs`/`ov` must outlive the operation. Returns
/// true if a completion will be delivered (an inline success still queues one),
/// false if the receive failed synchronously (no completion will arrive — the
/// caller must NOT mark the op pending, or it will wedge its reap gate forever).
///
/// # Safety
/// `wsabufs` must point to `count` valid `WSABUF`s whose buffers, and `ov` (an
/// `OVERLAPPED`), all remain alive and pinned until the IOCP completion for
/// this receive is dequeued.
pub unsafe fn wsa_recv(s: SOCKET, wsabufs: *const WSABUF, count: u32, ov: *mut OVERLAPPED) -> bool {
    let mut flags = 0u32;
    let mut recvd = 0u32;
    let r = unsafe { WSARecv(s, wsabufs, count, &mut recvd, &mut flags, ov, None) };
    r == 0 || unsafe { WSAGetLastError() } == WSA_IO_PENDING
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

/// What posting an overlapped receive with [`wsa_recv_inline`] did.
pub enum RecvPost {
    /// It completed at once, with this many bytes. On a socket in
    /// [`skip_iocp_on_success`] mode no completion is queued for it; on any
    /// other socket one still is.
    Done(usize),
    /// It is pending: its completion will be queued.
    Pending,
    /// It failed at once (e.g. WSAECONNRESET after an ICMP port unreachable):
    /// no completion will be queued.
    Failed,
}

/// Stop queueing completions for overlapped operations on `s` that complete
/// at once (`FILE_SKIP_COMPLETION_PORT_ON_SUCCESS`): [`wsa_recv_inline`]
/// reports those and the caller handles them inline. Only done when the
/// socket's provider is IFS, as a layered (LSP) provider may queue them
/// anyway; returns whether the mode is on.
pub fn skip_iocp_on_success(s: SOCKET) -> bool {
    const FILE_SKIP_COMPLETION_PORT_ON_SUCCESS: u8 = 1;
    const FILE_SKIP_SET_EVENT_ON_HANDLE: u8 = 2;
    let mut info: WSAPROTOCOL_INFOW = unsafe { core::mem::zeroed() };
    let mut len = core::mem::size_of::<WSAPROTOCOL_INFOW>() as i32;
    let rc = unsafe {
        getsockopt(
            s,
            SOL_SOCKET,
            SO_PROTOCOL_INFOW,
            (&mut info as *mut WSAPROTOCOL_INFOW).cast(),
            &mut len,
        )
    };
    if rc != 0 || info.dwServiceFlags1 & XP1_IFS_HANDLES == 0 {
        return false;
    }
    let flags = FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE;
    unsafe { SetFileCompletionNotificationModes(s as HANDLE, flags) != 0 }
}

/// [`wsa_recv`] that tells a receive which completed at once apart from a
/// pending one, with its size (read from the `OVERLAPPED`, which the system
/// fills in for an immediate completion).
///
/// # Safety
/// As for [`wsa_recv`].
pub unsafe fn wsa_recv_inline(
    s: SOCKET,
    wsabufs: *const WSABUF,
    count: u32,
    ov: *mut OVERLAPPED,
) -> RecvPost {
    let mut flags = 0u32;
    let r = unsafe {
        WSARecv(
            s,
            wsabufs,
            count,
            std::ptr::null_mut(),
            &mut flags,
            ov,
            None,
        )
    };
    if r == 0 {
        RecvPost::Done(unsafe { (*ov).InternalHigh })
    } else if unsafe { WSAGetLastError() } == WSA_IO_PENDING {
        RecvPost::Pending
    } else {
        RecvPost::Failed
    }
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

/// True if a connected IPv4 socket's peer is this host: a loopback address,
/// or the very address the socket is bound to (a connection to one of the
/// host's own interface addresses). ConnectEx sockets need
/// [`update_connect_ctx`] first.
pub fn peer_is_local(s: SOCKET) -> bool {
    let mut local: SOCKADDR_IN = unsafe { core::mem::zeroed() };
    let mut peer: SOCKADDR_IN = unsafe { core::mem::zeroed() };
    let mut local_len = core::mem::size_of::<SOCKADDR_IN>() as i32;
    let mut peer_len = local_len;
    let ok = unsafe {
        getsockname(
            s,
            &mut local as *mut SOCKADDR_IN as *mut SOCKADDR,
            &mut local_len,
        ) == 0
            && getpeername(
                s,
                &mut peer as *mut SOCKADDR_IN as *mut SOCKADDR,
                &mut peer_len,
            ) == 0
    };
    if !ok || local.sin_family != AF_INET || peer.sin_family != AF_INET {
        return false;
    }
    // SAFETY: every bit pattern is a valid `S_addr`; octets are in network order.
    let (l, p) = unsafe { (local.sin_addr.S_un.S_addr, peer.sin_addr.S_un.S_addr) };
    p.to_ne_bytes()[0] == 127 || p == l
}

/// Fix the socket's receive buffer, and so its advertised TCP window, at
/// `bytes`. This replaces Windows' receive-window autotuning for the socket.
pub fn set_rcvbuf(s: SOCKET, bytes: i32) -> bool {
    unsafe {
        setsockopt(
            s,
            SOL_SOCKET,
            SO_RCVBUF,
            &bytes as *const i32 as *const u8,
            core::mem::size_of::<i32>() as i32,
        ) == 0
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
        if rc != 0 { 0 } else { func }
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

// ---------------------------------------------------------------------------
// Host DNS configuration (iphlpapi) -- what the NAT's DHCP hands the guest.
// ---------------------------------------------------------------------------

/// The host's IPv4 DNS servers in preference order; empty if unavailable.
pub fn dns_servers() -> Vec<[u8; 4]> {
    const MAX_SERVERS: usize = 16;
    let mut len: u32 = 0;
    // Sizing call: fails with ERROR_BUFFER_OVERFLOW and sets `len`.
    // SAFETY: a null buffer with a zero length is the documented sizing form.
    unsafe { GetNetworkParams(std::ptr::null_mut(), &mut len) };
    if (len as usize) < core::mem::size_of::<FIXED_INFO_W2KSP1>() {
        return Vec::new();
    }
    // u64 backing keeps the FIXED_INFO and its list nodes pointer-aligned.
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    let info = buf.as_mut_ptr() as *mut FIXED_INFO_W2KSP1;
    // SAFETY: `buf` holds at least `len` bytes, as the call requires.
    if unsafe { GetNetworkParams(info, &mut len) } != ERROR_SUCCESS {
        return Vec::new();
    }
    let mut out = Vec::new();
    // SAFETY: on success `buf` holds a FIXED_INFO whose DnsServerList chain is
    // null-terminated and lives inside `buf`, which outlives this walk.
    let mut node: *const IP_ADDR_STRING = unsafe { &(*info).DnsServerList };
    while !node.is_null() && out.len() < MAX_SERVERS {
        let raw = unsafe { (*node).IpAddress.String };
        let text: Vec<u8> = raw
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        if let Some(ip) = std::str::from_utf8(&text)
            .ok()
            .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
        {
            out.push(ip.octets());
        }
        node = unsafe { (*node).Next };
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::windows::io::AsRawSocket;
    use std::time::Duration;

    /// In skip mode a receive that finds a datagram queued completes inline
    /// and queues no completion (one would be handled twice), while one that
    /// waits still completes through the port.
    #[test]
    fn skip_mode_completes_queued_receives_inline_only() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.connect(rx.local_addr().unwrap()).unwrap();
        rx.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let s = rx.as_raw_socket() as SOCKET;
        let iocp = create_iocp().unwrap();
        assert!(associate(iocp, s, 7));
        assert!(skip_iocp_on_success(s));
        let mut buf = [0u8; 64];
        let wb = wsabuf(buf.as_mut_ptr(), buf.len());
        let mut ov: OVERLAPPED = unsafe { core::mem::zeroed() };
        let mut done = [(false, 0, 0, std::ptr::null_mut()); 4];

        tx.send(b"hello").unwrap();
        rx.peek(&mut [0u8; 8]).unwrap();
        let r = unsafe { wsa_recv_inline(s, &wb, 1, &mut ov) };
        assert!(matches!(r, RecvPost::Done(5)));
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(get_many(iocp, &mut done, 0), 0, "nothing queued for it");

        let r = unsafe { wsa_recv_inline(s, &wb, 1, &mut ov) };
        assert!(matches!(r, RecvPost::Pending));
        tx.send(b"world!").unwrap();
        assert_eq!(get_many(iocp, &mut done, 5000), 1);
        let (ok, bytes, key, _) = done[0];
        assert!(ok && bytes == 6 && key == 7);
        assert_eq!(&buf[..6], b"world!");
    }
}
