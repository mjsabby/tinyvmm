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
//! with a synthetic backend MAC.
//!
//! Requires admin: creating a WinTun adapter needs elevation.

use crate::virtio::net::{NetBackend, NetDevice};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::thread::JoinHandle;
use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent, WaitForMultipleObjects};
use winsys::wintun::{assign_unicast_ipv4, last_error, AdapterHandle, SessionHandle, WintunApi};

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETH_HDR: usize = 14;
const ARP_LEN: usize = 28;
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
            host_ipv4: [10, 0, 0, 1],
            prefix_len: 24,
            backend_mac: [0x02, 0x53, 0x54, 0x00, 0x00, 0x01],
            ring_capacity: 4 * 1024 * 1024,
        }
    }
}

/// Wraps the WinTun handles so they can cross into the worker thread. WinTun's
/// session API is documented thread-safe (concurrent send + receive); the
/// adapter/session are only torn down in stop()/drop after the worker joins.
struct Handles {
    api: WintunApi,
    adapter: AdapterHandle,
    session: SessionHandle,
    read_wait: HANDLE,
}
// SAFETY: the WinTun adapter/session handles are documented thread-safe (the
// session API permits concurrent send + receive); the adapter + session are
// only torn down in stop()/drop AFTER the worker thread joins.
unsafe impl Send for Handles {}
unsafe impl Sync for Handles {}

/// Wraps a raw `HANDLE` so it can be moved into the worker thread.
struct SendHandle(HANDLE);
// SAFETY: the wrapped HANDLE is a manual-reset event used only for cross-thread
// signalling (SetEvent/WaitForMultipleObjects), which is OS-thread-safe.
unsafe impl Send for SendHandle {}

pub struct WintunBackend {
    handles: Arc<Handles>,
    net: Weak<NetDevice>,
    backend_mac: [u8; 6],
    guest_mac: [u8; 6],
    host_ip_be: u32,
    running: Arc<AtomicBool>,
    stop_evt: HANDLE,
    worker: Mutex<Option<JoinHandle<()>>>,
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    arp_replies: AtomicU64,
}

// SAFETY: the only raw field is `stop_evt`, an OS event HANDLE used solely for
// cross-thread signalling; all other fields are Send+Sync. The handle is closed
// in stop()/drop after the worker joins.
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
        if let Err(e) = assign_unicast_ipv4(api.adapter_luid(adapter), host_ip_be, opts.prefix_len) {
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
            net: Arc::downgrade(net),
            backend_mac: opts.backend_mac,
            guest_mac: net.mac(),
            host_ip_be,
            running: running.clone(),
            stop_evt,
            worker: Mutex::new(None),
            tx_packets: AtomicU64::new(0),
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

    /// TX: a guest IPv4 frame -> strip Eth header -> push the IP packet to WinTun.
    fn send_ip(&self, ip: &[u8]) {
        if ip.is_empty() || ip.len() > 0xFFFF {
            return;
        }
        let buf = self
            .handles
            .api
            .allocate_send_packet(self.handles.session, ip.len() as u32);
        if buf.is_null() {
            return; // ring full or EOF; drop (lossy like a real NIC under pressure)
        }
        // SAFETY: `buf` is a valid `ip.len()`-byte WinTun ring slot; copy the IP
        // packet in then hand it back to WinTun to transmit.
        unsafe {
            core::ptr::copy_nonoverlapping(ip.as_ptr(), buf, ip.len());
        }
        self.handles.api.send_packet(self.handles.session, buf);
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

/// RX worker: block on the WinTun read-wait event, drain the read ring, prepend
/// an Ethernet header to each IPv4 packet, and inject toward the guest.
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
            if version == 4 && sz + ETH_HDR <= RX_FRAME_CAP {
                if let Some(b) = weak.upgrade() {
                    frame[0..6].copy_from_slice(&b.guest_mac);
                    frame[6..12].copy_from_slice(&b.backend_mac);
                    frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
                    unsafe {
                        core::ptr::copy_nonoverlapping(p, frame.as_mut_ptr().add(ETH_HDR), sz)
                    };
                    if let Some(net) = b.net.upgrade() {
                        net.inject_rx(&frame[..ETH_HDR + sz]);
                        b.rx_packets.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            handles.api.release_receive_packet(handles.session, p);
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

    fn stop(&self) {
        if !self.running.swap(false, Ordering::AcqRel) {
            return; // already stopped
        }
        unsafe { SetEvent(self.stop_evt) };
        // End the session first so a blocked ReceivePacket returns; then join.
        self.handles.api.end_session(self.handles.session);
        if let Some(h) = self.worker.lock().unwrap().take() {
            let _ = h.join();
        }
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
