//! DLL-based WinTun backend (port of src/virtio/net_wintun.cpp + the DLL path of
//! wintun_loader/wintun_adapter_mgr). Bridges the guest's virtio-net L2 frames
//! to a WinTun L3 TUN adapter on the host, so guest IP traffic reaches the real
//! Windows network stack.
//!
//! Unlike the C++ (which used a vendored clean-room ring), this uses wintun.dll's
//! documented API directly for both adapter management AND the session ring; the
//! datapath behavior is identical.
//!
//! Layering: WinTun is layer-3 (IP). The guest speaks layer-2 (Ethernet), so the
//! backend strips the Ethernet header on TX (guest -> wintun) and synthesizes one
//! on RX (wintun -> guest), and answers the guest's ARP-for-the-gateway locally
//! with a synthetic backend MAC. Only IPv4 crosses, in either direction: WinTun
//! gives the host's stack whatever it is handed and tells IPv4 from IPv6 by the
//! first nibble, so TX forwards well-formed IPv4 packets only (`ipv4_packet`).
//!
//! Requires admin: creating a WinTun adapter needs elevation.

use crate::virtio::net::{NetBackend, NetDevice};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::thread::JoinHandle;
use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent, WaitForMultipleObjects};
use winsys::wintun::{AdapterHandle, SessionHandle, WintunApi, assign_unicast_ipv4, last_error};

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETH_HDR: usize = 14;
const ARP_LEN: usize = 28;
const IPV4_MIN_HDR: usize = 20;
const RX_FRAME_CAP: usize = 2048;

/// Per-NIC WinTun configuration recorded in the snapshot header so restore can
/// recreate the adapter.
#[derive(Clone)]
pub struct WintunOptions {
    pub adapter_name: String,
    pub host_ipv4: [u8; 4],
    pub prefix_len: u8,
    pub backend_mac: [u8; 6],
    pub ring_capacity: u32,
}

impl Default for WintunOptions {
    fn default() -> Self {
        WintunOptions {
            adapter_name: "tinyvmm".to_string(),
            host_ipv4: crate::net::GATEWAY_IP,
            prefix_len: crate::net::PREFIX_LEN,
            backend_mac: [0x02, 0x53, 0x54, 0x00, 0x00, 0x01],
            ring_capacity: 4 * 1024 * 1024,
        }
    }
}

/// The WinTun handles, shared with the RX worker thread.
struct Handles {
    api: WintunApi,
    adapter: AdapterHandle,
    session: SessionHandle,
    read_wait: HANDLE,
}
// SAFETY: a WinTun session may be used from several threads at once (one
// receiving while others send: its API takes its own locks), and the session
// and adapter handles stay valid until `WintunBackend::stop` ends them. `stop`
// does that last, once nothing can call into the session any more: by then it
// has joined the RX worker and shut the TX gate (`session_open`).
unsafe impl Send for Handles {}
unsafe impl Sync for Handles {}

/// Wraps a raw `HANDLE` so it can be moved into the worker thread.
struct SendHandle(HANDLE);
// SAFETY: the wrapped HANDLE is a manual-reset event used only for cross-thread
// signalling (SetEvent/WaitForMultipleObjects), which is OS-thread-safe.
unsafe impl Send for SendHandle {}

pub struct WintunBackend {
    handles: Arc<Handles>,
    /// The TX gate: true while the session may be used. A send holds it for
    /// reading around its calls into the session; `stop` takes it for writing
    /// before it ends the session, which waits for a send in flight and turns
    /// every later one away. (The RX worker needs no gate: `stop` joins it.)
    session_open: RwLock<bool>,
    net: Weak<NetDevice>,
    backend_mac: [u8; 6],
    guest_mac: [u8; 6],
    host_ip_be: u32,
    running: Arc<AtomicBool>,
    stop_evt: HANDLE,
    worker: Mutex<Option<JoinHandle<()>>>,
    tx_packets: AtomicU64,
    /// Guest frames of ethertype IPv4 that didn't hold a well-formed IPv4
    /// packet (see `ipv4_packet`): dropped.
    tx_invalid: AtomicU64,
    rx_packets: AtomicU64,
    arp_replies: AtomicU64,
}

// SAFETY: the only raw field is `stop_evt`, an OS event HANDLE used solely for
// cross-thread signalling; all other fields are Send+Sync. `stop` closes it
// once the worker, the only thread that waits on it, is done with it.
unsafe impl Send for WintunBackend {}
unsafe impl Sync for WintunBackend {}

impl WintunBackend {
    pub fn new(net: &Arc<NetDevice>, opts: &WintunOptions) -> Result<Arc<WintunBackend>, String> {
        let api = WintunApi::load()?;

        // Create the adapter (needs admin).
        let name_w: Vec<u16> = opts.adapter_name.encode_utf16().chain([0]).collect();
        let type_w: Vec<u16> = "tinyvmm".encode_utf16().chain([0]).collect();
        let adapter = api.create_adapter(&name_w, &type_w);
        if adapter.is_null() {
            return Err(format!(
                "WintunCreateAdapter('{}') failed (err={}); WinTun needs administrator rights",
                opts.adapter_name,
                last_error()
            ));
        }

        // Assign the host-side IPv4 (gateway) address to the adapter.
        let host_ip_be = u32::from_ne_bytes(opts.host_ipv4);
        if let Err(e) = assign_unicast_ipv4(api.adapter_luid(adapter), host_ip_be, opts.prefix_len)
        {
            api.close_adapter(adapter);
            return Err(e);
        }

        // Start the ring session.
        let session = api.start_session(adapter, opts.ring_capacity);
        if session.is_null() {
            let e = format!("WintunStartSession failed (err={})", last_error());
            api.close_adapter(adapter);
            return Err(e);
        }
        let read_wait = api.read_wait_event(session);

        let stop_evt = unsafe { CreateEventW(core::ptr::null(), 1, 0, core::ptr::null()) };
        let handles = Arc::new(Handles {
            api,
            adapter,
            session,
            read_wait,
        });
        let running = Arc::new(AtomicBool::new(true));

        let backend = Arc::new(WintunBackend {
            handles: handles.clone(),
            session_open: RwLock::new(true),
            net: Arc::downgrade(net),
            backend_mac: opts.backend_mac,
            guest_mac: net.mac(),
            host_ip_be,
            running: running.clone(),
            stop_evt,
            worker: Mutex::new(None),
            tx_packets: AtomicU64::new(0),
            tx_invalid: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            arp_replies: AtomicU64::new(0),
        });

        // Spawn the RX worker: drain WinTun's read ring, frame to L2, inject.
        let weak = Arc::downgrade(&backend);
        let stop = SendHandle(stop_evt);
        let h = std::thread::Builder::new()
            .name(format!("wintun-{}", opts.adapter_name))
            .spawn(move || rx_worker(weak, handles, running, stop))
            .map_err(|e| format!("spawn wintun worker: {e}"))?;
        *backend.worker.lock().unwrap() = Some(h);

        Ok(backend)
    }

    /// TX: the IPv4 packet in a guest frame's payload (Eth header stripped) ->
    /// WinTun. A payload that isn't a well-formed IPv4 packet is dropped and
    /// counted.
    fn send_ip(&self, payload: &[u8]) {
        let Some(ip) = ipv4_packet(payload) else {
            self.tx_invalid.fetch_add(1, Ordering::Relaxed);
            return;
        };
        // Hold the gate across the calls into the session, so `stop` can't end
        // it under them. This runs on a doorbell pump or vCPU thread, which
        // may still be draining the guest's TX queue when `stop` is called (a
        // snapshot quiesces the backends while the pumps run).
        let open = self.session_open.read().unwrap();
        if !*open {
            return; // stopped: the session is gone
        }
        // `ip.len()` is an IPv4 total length: at most 0xFFFF, WinTun's limit.
        let buf = self
            .handles
            .api
            .allocate_send_packet(self.handles.session, ip.len() as u32);
        if buf.is_null() {
            return; // ring full or EOF; drop (lossy like a real NIC under pressure)
        }
        // SAFETY: the gate is held, so the session is open, and `buf` is a
        // valid `ip.len()`-byte slot of its ring; copy the IP packet in then
        // hand it back to WinTun to transmit.
        unsafe {
            core::ptr::copy_nonoverlapping(ip.as_ptr(), buf, ip.len());
        }
        self.handles.api.send_packet(self.handles.session, buf);
        drop(open);
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
    }

    /// Answer a guest ARP-for-the-gateway with our synthetic backend MAC so the
    /// guest can resolve the next hop (WinTun is L3 and never sees ARP).
    fn handle_arp(&self, eth: &[u8]) {
        if eth.len() < ETH_HDR + ARP_LEN {
            return;
        }
        let a = &eth[ETH_HDR..ETH_HDR + ARP_LEN];
        let htype = u16::from_be_bytes([a[0], a[1]]);
        let ptype = u16::from_be_bytes([a[2], a[3]]);
        let hlen = a[4];
        let plen = a[5];
        let opcode = u16::from_be_bytes([a[6], a[7]]);
        if htype != 1 || ptype != ETHERTYPE_IPV4 || hlen != 6 || plen != 4 || opcode != 1 {
            return;
        }
        let sha = &a[8..14]; // sender hw (guest MAC)
        let spa = &a[14..18]; // sender proto (guest IP)
        let tpa = &a[24..28]; // target proto (the IP being resolved)
        if u32::from_ne_bytes([tpa[0], tpa[1], tpa[2], tpa[3]]) != self.host_ip_be {
            return; // not asking for our gateway
        }

        let mut frame = [0u8; ETH_HDR + ARP_LEN];
        // Ethernet header: dst = guest, src = backend, type = ARP.
        frame[0..6].copy_from_slice(sha);
        frame[6..12].copy_from_slice(&self.backend_mac);
        frame[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        // ARP reply.
        let r = &mut frame[ETH_HDR..];
        r[0..2].copy_from_slice(&1u16.to_be_bytes()); // htype = Ethernet
        r[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes()); // ptype = IPv4
        r[4] = 6;
        r[5] = 4;
        r[6..8].copy_from_slice(&2u16.to_be_bytes()); // opcode = reply
        r[8..14].copy_from_slice(&self.backend_mac); // sha = us
        r[14..18].copy_from_slice(&self.host_ip_be.to_ne_bytes()); // spa = gateway IP
        r[18..24].copy_from_slice(sha); // tha = guest MAC
        r[24..28].copy_from_slice(spa); // tpa = guest IP

        if let Some(net) = self.net.upgrade() {
            net.inject_rx(&frame);
            self.arp_replies.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The IPv4 packet at the start of an Ethernet payload: its total-length
/// bytes, without whatever follows them (padding). `None` unless the payload
/// starts with a well-formed IPv4 header: version 4, a header length of at
/// least 20 bytes that the payload holds, and a total length that covers the
/// header and that the payload holds too.
///
/// WinTun gives the host's network stack whatever it is handed, and tells
/// IPv4 from IPv6 by the first nibble alone. Unchecked, a guest could put
/// IPv6 packets (router advertisements, say) to the host through an adapter
/// that bridges only IPv4 back, by sending them with the IPv4 ethertype.
fn ipv4_packet(payload: &[u8]) -> Option<&[u8]> {
    let first = *payload.first()?;
    let ihl = usize::from(first & 0x0F) * 4;
    if first >> 4 != 4 || ihl < IPV4_MIN_HDR || payload.len() < ihl {
        return None;
    }
    let total = usize::from(u16::from_be_bytes([payload[2], payload[3]]));
    if total < ihl || total > payload.len() {
        return None;
    }
    Some(&payload[..total])
}

/// RX worker: block on the WinTun read-wait event, drain the read ring, prepend
/// an Ethernet header to each IPv4 packet, and inject toward the guest.
///
/// It is the only thread that receives from the session, and it leaves once
/// `running` clears or the stop event is set. `stop` waits for that before it
/// ends the session, so the session is open for every call made here. Each
/// packet is copied out and released before it is injected, so nothing of the
/// session is in use across the call into the device.
fn rx_worker(
    weak: Weak<WintunBackend>,
    handles: Arc<Handles>,
    running: Arc<AtomicBool>,
    stop: SendHandle,
) {
    let mut frame = vec![0u8; RX_FRAME_CAP];
    while running.load(Ordering::Acquire) {
        // Drain everything currently available.
        loop {
            if !running.load(Ordering::Acquire) {
                return;
            }
            let mut size: u32 = 0;
            let p = handles.api.receive_packet(handles.session, &mut size);
            if p.is_null() {
                break; // ERROR_NO_MORE_ITEMS (or EOF) -> wait below
            }
            let sz = size as usize;
            // WinTun hands us an L3 packet; only IPv4 is bridged (v6 dropped).
            let version = if sz > 0 { (unsafe { *p }) >> 4 } else { 0 };
            let bridged = version == 4 && sz + ETH_HDR <= RX_FRAME_CAP;
            if bridged {
                // SAFETY: `p` is `sz` readable bytes of the session's ring
                // until the release below, and `frame` has room for them
                // after the Ethernet header (checked just above).
                unsafe { core::ptr::copy_nonoverlapping(p, frame.as_mut_ptr().add(ETH_HDR), sz) };
            }
            handles.api.release_receive_packet(handles.session, p);
            if bridged && let Some(b) = weak.upgrade() {
                frame[0..6].copy_from_slice(&b.guest_mac);
                frame[6..12].copy_from_slice(&b.backend_mac);
                frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
                if let Some(net) = b.net.upgrade() {
                    net.inject_rx(&frame[..ETH_HDR + sz]);
                    b.rx_packets.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        // Wait for the next read or a stop request.
        let objs = [stop.0, handles.read_wait];
        let w = unsafe { WaitForMultipleObjects(2, objs.as_ptr(), FALSE, 250) };
        if w == WAIT_OBJECT_0 {
            return; // stop signaled
        }
    }
}

impl NetBackend for WintunBackend {
    fn on_guest_frame(&self, frame: &[u8]) {
        if frame.len() < ETH_HDR {
            return;
        }
        let etype = u16::from_be_bytes([frame[12], frame[13]]);
        match etype {
            ETHERTYPE_IPV4 => self.send_ip(&frame[ETH_HDR..]),
            ETHERTYPE_ARP => self.handle_arp(frame),
            _ => {}
        }
    }

    fn diag_summary(&self) -> Option<String> {
        let ld = |a: &AtomicU64| a.load(Ordering::Relaxed);
        Some(format!(
            "wintun: tx_packets={} tx_invalid={} rx_packets={} arp_replies={}",
            ld(&self.tx_packets),
            ld(&self.tx_invalid),
            ld(&self.rx_packets),
            ld(&self.arp_replies),
        ))
    }

    /// Stop using the session, then end it. WinTun frees a session's rings and
    /// state at once when it is ended, whoever is still in a call on it, so
    /// the order is: every user out first.
    fn stop(&self) {
        if !self.running.swap(false, Ordering::AcqRel) {
            return; // already stopped
        }
        // 1. The RX worker. It sleeps on [stop, read_wait] for at most 250 ms
        //    and checks `running` before every receive, so the flag and the
        //    event are all it needs to leave: wait until it has. (Should this
        //    be the worker itself, dropping the last reference to the backend,
        //    there is nothing to join: it holds no packet at that point, and
        //    returns at its next `running` check without touching the session.)
        unsafe { SetEvent(self.stop_evt) };
        let worker = self.worker.lock().unwrap().take();
        if let Some(h) = worker
            && h.thread().id() != std::thread::current().id()
        {
            let _ = h.join();
        }
        // 2. The TX path. Taking the gate for writing waits for a send in
        //    flight, and every later one finds it shut. With no user left,
        //    the session can end.
        let mut open = self.session_open.write().unwrap();
        *open = false;
        self.handles.api.end_session(self.handles.session);
        drop(open);
        // 3. The adapter, which nothing but the session used.
        self.handles.api.close_adapter(self.handles.adapter);
        unsafe {
            CloseHandle(self.stop_evt);
        }
    }
}

impl Drop for WintunBackend {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::wire::build_ipv4;

    /// A payload of `len` bytes that starts like an IPv4 header of `ihl`
    /// 32-bit words whose total-length field says `total`.
    fn payload(ihl: u8, total: u16, len: usize) -> Vec<u8> {
        let mut p = vec![0xEE; len];
        if let Some(first) = p.first_mut() {
            *first = 0x40 | ihl;
        }
        if len >= 4 {
            p[2..4].copy_from_slice(&total.to_be_bytes());
        }
        p
    }

    /// TX forwards a guest frame's payload only if it is a well-formed IPv4
    /// packet, and then exactly that packet.
    #[test]
    fn tx_forwards_only_well_formed_ipv4() {
        // A real datagram.
        let udp = build_ipv4([172, 29, 255, 2], [1, 1, 1, 1], 17, &[7u8; 12]);
        assert_eq!(ipv4_packet(&udp), Some(&udp[..]));

        let sent = |ihl, total, len| ipv4_packet(&payload(ihl, total, len)).map(<[u8]>::len);
        // A bare header, headers with options, an MTU's worth, the largest.
        assert_eq!(sent(5, 20, 20), Some(20));
        assert_eq!(sent(6, 24, 24), Some(24));
        assert_eq!(sent(15, 60, 60), Some(60));
        assert_eq!(sent(5, 1500, 1500), Some(1500));
        assert_eq!(sent(5, 0xFFFF, 0xFFFF), Some(0xFFFF));
        // What follows the datagram (Ethernet padding, or a tail a hostile
        // guest appended) is not sent.
        let padded = payload(5, 28, 46);
        assert_eq!(ipv4_packet(&padded), Some(&padded[..28]));
        assert_eq!(sent(5, 20, 0xFFFF + 4), Some(20));

        // Not IPv4: nothing at all, or another version. 6 is the one WinTun
        // would hand to the host's IPv6 stack.
        assert_eq!(ipv4_packet(&[]), None);
        for version in [0u8, 1, 3, 5, 6, 7, 15] {
            let mut p = payload(5, 60, 60);
            p[0] = (version << 4) | 5;
            assert_eq!(ipv4_packet(&p), None, "version {version}");
        }
        // A header length under 20 bytes, or longer than the payload.
        assert_eq!(sent(0, 20, 20), None);
        assert_eq!(sent(4, 20, 20), None);
        assert_eq!(sent(5, 20, 1), None);
        assert_eq!(sent(5, 20, 19), None);
        assert_eq!(sent(15, 60, 59), None);
        // A total length short of the header, or longer than the payload.
        assert_eq!(sent(5, 0, 20), None);
        assert_eq!(sent(5, 19, 40), None);
        assert_eq!(sent(6, 20, 40), None);
        assert_eq!(sent(5, 41, 40), None);
        assert_eq!(sent(5, 0xFFFF, 1500), None);
    }
}
