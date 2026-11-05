//! A minimal VMBus host: the channel protocol Hyper-V guests find and talk to
//! synthetic devices over, with just enough of it for Linux's vmbus driver.
//! Its one device is the time-sync integration component ([`timesync`]),
//! which keeps the guest's clock on the host's as WSL's is kept.
//!
//! The guest finds the bus through the ACPI device `\_SB.VMBS`, and reaches it
//! through the SynIC the hypervisor already implements for it
//! (`whp::hv`); tinyvmm supplies only the host's end.
//! - Control messages. The guest posts them with HvPostMessage, which WHP hands
//!   tinyvmm as a hypercall exit ([`Host::hypercall`]). The answers go to the
//!   guest's SynIC message page on SINT 2, posted one at a time by the run loop
//!   of the vCPU the guest takes them on ([`Host::flush`]). tinyvmm speaks
//!   protocol versions 5.0 to 5.3 and the messages Linux sends: requesting
//!   offers, GPADLs (the guest pages a channel uses), opening, closing and
//!   retargeting channels, and unloading. It always answers, since Linux
//!   waits for most answers without a timeout.
//! - Channels. Each device gets one: a pair of ring buffers ([`ring`]) in a
//!   GPADL. The guest signals a channel with HvSignalEvent, which WHP passes on
//!   as a hypercall exit too (its unknown-SynIC-connection exit), and tinyvmm
//!   signals the guest by setting the channel's flag in its SynIC event page.
//!
//! A snapshot holds the bus's state; a restored device starts its own protocol
//! over on the channel it finds open.

mod ic;
mod protocol;
mod ring;
pub mod timesync;

use crate::error::{Error, Result};
use crate::whp::hv::feature;
use crate::whp::partition::{
    exits, extended_exits_supported, synthetic_processor_features_supported,
};
use crate::whp::synic::{self, MESSAGE_SIZE};
use crate::whp::{GuestMemory, Vcpu};
use protocol as p;
use protocol::{u16_at, u32_at};
use ring::Ring;
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use windows_sys::Win32::System::Hypervisor::WHV_PARTITION_HANDLE;

/// The WHP extended exits the host runs on.
pub const EXITS: u64 = exits::HYPERCALL | exits::UNKNOWN_SYNIC_CONNECTION;

const HVCALL_POST_MESSAGE: u64 = 0x005c;
const HVCALL_SIGNAL_EVENT: u64 = 0x005d;
const HYPERCALL_FAST: u64 = 1 << 16;
/// `HV_STATUS_*`, returned in RAX.
const HV_STATUS_SUCCESS: u64 = 0;
pub const HV_STATUS_INVALID_HYPERCALL_CODE: u64 = 2;
const HV_STATUS_INVALID_HYPERCALL_INPUT: u64 = 3;
const HV_STATUS_INVALID_ALIGNMENT: u64 = 4;
const HV_STATUS_INVALID_PARAMETER: u64 = 5;
const HV_STATUS_INVALID_CONNECTION_ID: u64 = 0x12;
const HV_STATUS_INSUFFICIENT_BUFFERS: u64 = 0x13;

/// Bounds on what a guest can make the host hold.
const MAX_OUTBOX: usize = 64;
const MAX_GPADLS: usize = 64;
const MAX_GPADL_PAGES: usize = 8192;
/// A channel's connection ID, which the guest signals it on: its relid on SINT
/// 2, as OpenVMM numbers them.
const CHANNEL_CONNECTION_BASE: u32 = 0x2000;
const SAVE_FORMAT: u32 = 1;

/// Whether this host's WHP can run the bus: it must hand tinyvmm the guest's
/// HvPostMessage and HvSignalEvent, and its hypervisor implement the SynIC.
pub fn supported() -> bool {
    let synic = feature::ACCESS_SYNIC_REGS | feature::ACCESS_HYPERCALL_REGS;
    extended_exits_supported().is_ok_and(|e| e & EXITS == EXITS)
        && synthetic_processor_features_supported().is_ok_and(|f| f & synic == synic)
}

/// A device on the bus.
pub trait Device: Send + Sync {
    /// The device class its offer names (Linux matches drivers on it).
    fn interface(&self) -> [u8; 16];
    fn instance(&self) -> [u8; 16];
    /// The guest opened the channel, or a restore found it open: start over
    /// on it.
    fn open(&self, channel: Channel);
    /// The guest closed it, or reset the bus.
    fn close(&self);
    /// The guest signaled the channel.
    fn signal(&self);
    /// Stop for good, before guest memory goes away.
    fn stop(&self);
}

/// An open channel, as its device uses it.
#[derive(Clone)]
pub struct Channel {
    mem: Arc<GuestMemory>,
    part: WHV_PARTITION_HANDLE,
    relid: u32,
    target_vp: Arc<AtomicU32>,
    /// Written by the guest.
    incoming: Ring,
    /// Read by the guest.
    outgoing: Ring,
}

impl Channel {
    /// Send `payload` as one in-band packet. False if it doesn't fit, or the
    /// ring is broken.
    pub fn send(&self, payload: &[u8]) -> bool {
        match self.outgoing.write(&self.mem, payload) {
            Ok(signal) => {
                if signal {
                    let vp = self.target_vp.load(Ordering::Relaxed);
                    let _ = synic::signal_event(self.part, vp, p::SINT, self.relid as u16);
                }
                true
            }
            Err(_) => false,
        }
    }

    /// Read the guest's next in-band packet (at most `max` bytes) into `buf`.
    /// Ok(false) if there is none.
    pub fn recv(&self, buf: &mut Vec<u8>, max: usize) -> std::result::Result<bool, ring::Error> {
        loop {
            match self.incoming.read(&self.mem, buf, max)? {
                None => return Ok(false),
                Some(ring::PACKET_INBAND) => return Ok(true),
                Some(_) => {}
            }
        }
    }

    /// Signal the guest whether or not the ring says it needs it: for a
    /// device that suspects a signal went missing.
    pub fn notify(&self) {
        let vp = self.target_vp.load(Ordering::Relaxed);
        let _ = synic::signal_event(self.part, vp, p::SINT, self.relid as u16);
    }
}

struct Gpadl {
    relid: u32,
    pages: usize,
    pfns: Vec<u64>,
}

/// An open channel, as the host keeps it.
struct Open {
    gpadl: u32,
    target_vp: Arc<AtomicU32>,
    /// The page in the GPADL where the guest's receive ring starts.
    downstream: u32,
}

#[derive(Default)]
struct State {
    /// The protocol version the guest connected with; 0 until it does.
    version: u32,
    /// The vCPU the guest takes messages on.
    target_vp: u32,
    outbox: VecDeque<[u8; MESSAGE_SIZE]>,
    /// A post found the message slot still full: wait for the guest to free it.
    slot_busy: bool,
    gpadls: BTreeMap<u32, Gpadl>,
    /// Per device (relid = index + 1).
    open: Vec<Option<Open>>,
}

pub struct Host {
    part: WHV_PARTITION_HANDLE,
    mem: Arc<GuestMemory>,
    vcpu_count: u32,
    /// Interrupts a vCPU's `WHvRunVirtualProcessor`, so it posts the outbox.
    kick: Box<dyn Fn(u32) + Send + Sync>,
    devices: Vec<Arc<dyn Device>>,
    state: Mutex<State>,
    /// The outbox has messages to post: checked on every exit, lock-free.
    outbox_ready: AtomicBool,
    stopped: AtomicBool,
    /// A hypercall nothing serves was logged.
    unknown_hypercall: AtomicBool,
}

impl Host {
    pub fn new(
        part: WHV_PARTITION_HANDLE,
        mem: Arc<GuestMemory>,
        vcpus: &[Arc<Vcpu>],
        devices: Vec<Arc<dyn Device>>,
    ) -> Arc<Self> {
        let count = vcpus.len() as u32;
        let vcpus = vcpus.to_vec();
        let kick = Box::new(move |vp: u32| {
            if let Some(v) = vcpus.get(vp as usize) {
                let _ = v.cancel();
            }
        });
        Self::build(part, mem, count, kick, devices)
    }

    fn build(
        part: WHV_PARTITION_HANDLE,
        mem: Arc<GuestMemory>,
        vcpu_count: u32,
        kick: Box<dyn Fn(u32) + Send + Sync>,
        devices: Vec<Arc<dyn Device>>,
    ) -> Arc<Self> {
        let state = State {
            open: devices.iter().map(|_| None).collect(),
            ..State::default()
        };
        Arc::new(Host {
            part,
            mem,
            vcpu_count,
            kick,
            devices,
            state: Mutex::new(state),
            outbox_ready: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            unknown_hypercall: AtomicBool::new(false),
        })
    }

    /// Serve a hypercall WHP left to tinyvmm: returns the status for RAX.
    pub fn hypercall(&self, vp: u32, control: u64, input: u64) -> u64 {
        let code = control & 0xffff;
        if code != HVCALL_POST_MESSAGE && code != HVCALL_SIGNAL_EVENT {
            if !self.unknown_hypercall.swap(true, Ordering::Relaxed) {
                eprintln!("[vmbus] the guest made hypercall 0x{code:x}, which nothing serves");
            }
            return HV_STATUS_INVALID_HYPERCALL_CODE;
        }
        // Neither takes a rep count or a variable header.
        if control >> 17 != 0 {
            return HV_STATUS_INVALID_HYPERCALL_INPUT;
        }
        let fast = control & HYPERCALL_FAST != 0;
        if code == HVCALL_POST_MESSAGE {
            return if fast {
                HV_STATUS_INVALID_HYPERCALL_INPUT
            } else {
                self.post_message(vp, input)
            };
        }
        // HV_INPUT_SIGNAL_EVENT: the connection ID, then the flag number.
        let arg = if fast {
            input
        } else if !input.is_multiple_of(8) {
            return HV_STATUS_INVALID_ALIGNMENT;
        } else {
            match self.mem.read_u64(input) {
                Some(v) => v,
                None => return HV_STATUS_INVALID_PARAMETER,
            }
        };
        self.signal_event(arg as u32 & 0xff_ffff)
    }

    /// HvPostMessage: the input page holds the connection ID, a reserved word,
    /// the message type, the payload size and the payload.
    fn post_message(&self, vp: u32, gpa: u64) -> u64 {
        if !gpa.is_multiple_of(8) {
            return HV_STATUS_INVALID_ALIGNMENT;
        }
        let Some(head) = self.mem.read_array::<16>(gpa) else {
            return HV_STATUS_INVALID_PARAMETER;
        };
        let connection = u32_at(&head, 0).unwrap() & 0xff_ffff;
        let kind = u32_at(&head, 8).unwrap();
        let size = u32_at(&head, 12).unwrap() as usize;
        if kind == 0 || kind & 0x8000_0000 != 0 || size > p::MAX_PAYLOAD {
            return HV_STATUS_INVALID_PARAMETER;
        }
        if gpa % 4096 + 16 + size as u64 > 4096 {
            return HV_STATUS_INVALID_ALIGNMENT;
        }
        if connection != p::MESSAGE_CONNECTION_ID && connection != p::MESSAGE_CONNECTION_ID_4 {
            return HV_STATUS_INVALID_CONNECTION_ID;
        }
        let mut payload = vec![0u8; size];
        if !self.mem.read_into(gpa + 16, &mut payload) {
            return HV_STATUS_INVALID_PARAMETER;
        }
        let mut st = self.state.lock().unwrap();
        if st.outbox.len() >= MAX_OUTBOX {
            // Linux backs off and posts again.
            return HV_STATUS_INSUFFICIENT_BUFFERS;
        }
        self.handle(&mut st, &payload);
        let target = st.target_vp;
        drop(st);
        if target != vp && self.outbox_ready.load(Ordering::Acquire) {
            (self.kick)(target);
        }
        HV_STATUS_SUCCESS
    }

    fn signal_event(&self, connection: u32) -> u64 {
        let st = self.state.lock().unwrap();
        let open = connection
            .checked_sub(CHANNEL_CONNECTION_BASE)
            .and_then(|relid| self.channel_index(relid))
            .filter(|&i| st.open[i].is_some());
        match open {
            Some(i) => {
                self.devices[i].signal();
                HV_STATUS_SUCCESS
            }
            None => HV_STATUS_INVALID_CONNECTION_ID,
        }
    }

    fn channel_index(&self, relid: u32) -> Option<usize> {
        let i = relid.checked_sub(1)? as usize;
        (i < self.devices.len()).then_some(i)
    }

    fn queue(&self, st: &mut State, message: [u8; MESSAGE_SIZE]) {
        st.outbox.push_back(message);
        if !st.slot_busy {
            self.outbox_ready.store(true, Ordering::Release);
        }
    }

    /// Handle a message the guest posted.
    fn handle(&self, st: &mut State, m: &[u8]) {
        let Some(kind) = u32_at(m, 0) else {
            return;
        };
        let connected = st.version != 0;
        match kind {
            p::INITIATE_CONTACT => self.initiate_contact(st, m),
            p::REQUESTOFFERS if connected => {
                for (i, d) in self.devices.iter().enumerate() {
                    let relid = i as u32 + 1;
                    let offer = p::Offer {
                        interface: d.interface(),
                        instance: d.instance(),
                        relid,
                        connection_id: CHANNEL_CONNECTION_BASE + relid,
                    };
                    self.queue(st, p::offer(&offer));
                }
                self.queue(st, p::all_offers_delivered());
            }
            p::GPADL_HEADER if connected => self.gpadl_header(st, m),
            p::GPADL_BODY if connected => self.gpadl_body(st, m),
            p::OPENCHANNEL if connected => self.open_channel(st, m),
            p::CLOSECHANNEL => {
                if let Some(i) = u32_at(m, 8).and_then(|r| self.channel_index(r))
                    && st.open[i].take().is_some()
                {
                    self.devices[i].close();
                }
            }
            p::GPADL_TEARDOWN => {
                let Some(gpadl) = u32_at(m, 12) else {
                    return;
                };
                // Linux closes the channel first; if it didn't, stop using the
                // pages it is taking back.
                for (i, open) in st.open.iter_mut().enumerate() {
                    if open.as_ref().is_some_and(|o| o.gpadl == gpadl) {
                        *open = None;
                        self.devices[i].close();
                    }
                }
                st.gpadls.remove(&gpadl);
                self.queue(st, p::gpadl_torndown(gpadl));
            }
            p::MODIFYCHANNEL => self.modify_channel(st, m),
            p::UNLOAD => {
                self.reset(st);
                self.queue(st, p::unload_response());
            }
            // RELID_RELEASED answers a rescind, which tinyvmm never sends;
            // Linux sends nothing else.
            _ => {}
        }
    }

    fn initiate_contact(&self, st: &mut State, m: &[u8]) {
        let (Some(version), Some(target)) = (u32_at(m, 8), u32_at(m, 12)) else {
            return;
        };
        if st.version != 0 {
            // A kernel starting over without unloading the bus (kexec).
            self.reset(st);
        }
        if target < self.vcpu_count {
            st.target_vp = target;
        }
        // From 5.0 the guest names its message SINT; Linux names SINT 2.
        let ok = (p::VERSION_5_0..=p::VERSION_5_3).contains(&version)
            && target < self.vcpu_count
            && m.get(16) == Some(&p::SINT);
        if ok {
            st.version = version;
            println!(
                "[vmbus] guest connected (protocol {}.{})",
                version >> 16,
                version & 0xffff
            );
        }
        self.queue(st, p::version_response(ok));
    }

    /// Close every channel and forget the connection: the guest unloaded the
    /// bus, or a new kernel is connecting.
    fn reset(&self, st: &mut State) {
        for (i, open) in st.open.iter_mut().enumerate() {
            if open.take().is_some() {
                self.devices[i].close();
            }
        }
        st.gpadls.clear();
        st.version = 0;
        st.outbox.clear();
    }

    fn gpadl_header(&self, st: &mut State, m: &[u8]) {
        let fields = (
            u32_at(m, 8),
            u32_at(m, 12),
            u16_at(m, 18),
            u32_at(m, 20),
            u32_at(m, 24),
        );
        let (Some(relid), Some(id), Some(ranges), Some(bytes), Some(offset)) = fields else {
            return;
        };
        let pages = (u64::from(offset) + u64::from(bytes)).div_ceil(4096) as usize;
        let ok = ranges == 1
            && (1..=MAX_GPADL_PAGES).contains(&pages)
            && st.gpadls.len() < MAX_GPADLS
            && !st.gpadls.contains_key(&id);
        if !ok {
            self.queue(st, p::gpadl_created(relid, id, false));
            return;
        }
        let pfns = p::pfns(m, p::GPADL_HEADER_PFNS, pages);
        let complete = pfns.len() == pages;
        st.gpadls.insert(id, Gpadl { relid, pages, pfns });
        if complete {
            self.queue(st, p::gpadl_created(relid, id, true));
        }
    }

    /// The PFNs that didn't fit in the GPADL's header message.
    fn gpadl_body(&self, st: &mut State, m: &[u8]) {
        let Some(id) = u32_at(m, 12) else {
            return;
        };
        let Some(g) = st.gpadls.get_mut(&id) else {
            return;
        };
        let missing = g.pages - g.pfns.len();
        if missing == 0 {
            return;
        }
        g.pfns.extend(p::pfns(m, p::GPADL_BODY_PFNS, missing));
        if g.pfns.len() == g.pages {
            let relid = g.relid;
            self.queue(st, p::gpadl_created(relid, id, true));
        }
    }

    fn open_channel(&self, st: &mut State, m: &[u8]) {
        let fields = (
            u32_at(m, 8),
            u32_at(m, 12),
            u32_at(m, 16),
            u32_at(m, 20),
            u32_at(m, 24),
        );
        let (Some(relid), Some(openid), Some(gpadl), Some(target), Some(downstream)) = fields
        else {
            return;
        };
        let rings = self
            .channel_index(relid)
            .filter(|&i| st.open[i].is_none() && target < self.vcpu_count)
            .and_then(|i| {
                let (incoming, outgoing) = self.rings(st.gpadls.get(&gpadl)?, downstream)?;
                Some((i, incoming, outgoing))
            });
        self.queue(st, p::open_result(relid, openid, rings.is_some()));
        if let Some((i, incoming, outgoing)) = rings {
            let target_vp = Arc::new(AtomicU32::new(target));
            st.open[i] = Some(Open {
                gpadl,
                target_vp: target_vp.clone(),
                downstream,
            });
            self.devices[i].open(Channel {
                mem: self.mem.clone(),
                part: self.part,
                relid,
                target_vp,
                incoming,
                outgoing,
            });
        }
    }

    /// The rings in a complete GPADL: the guest's send ring, then from page
    /// `downstream` on its receive ring.
    fn rings(&self, g: &Gpadl, downstream: u32) -> Option<(Ring, Ring)> {
        if g.pfns.len() != g.pages {
            return None;
        }
        let (send, receive) = g.pfns.split_at_checked(downstream as usize)?;
        Some((Ring::new(send)?, Ring::new(receive)?))
    }

    /// Retarget a channel's interrupts to another vCPU.
    fn modify_channel(&self, st: &mut State, m: &[u8]) {
        let (Some(relid), Some(target)) = (u32_at(m, 8), u32_at(m, 12)) else {
            return;
        };
        let open = self.channel_index(relid).and_then(|i| st.open[i].as_ref());
        let ok = match open {
            Some(o) if target < self.vcpu_count => {
                o.target_vp.store(target, Ordering::Relaxed);
                true
            }
            _ => false,
        };
        // Only 5.3 answers.
        if st.version >= p::VERSION_5_3 {
            self.queue(st, p::modify_channel_response(relid, ok));
        }
    }

    /// Post the outbox, if `vcpu` is the one the guest takes messages on. The
    /// run loop calls this before entering the guest, so posting is done on
    /// the target's own thread, which alone may ask for deliverability
    /// notifications.
    pub fn flush(&self, vcpu: &Vcpu) {
        if !self.outbox_ready.load(Ordering::Acquire) {
            return;
        }
        let mut st = self.state.lock().unwrap();
        if vcpu.index() != st.target_vp || st.slot_busy {
            return;
        }
        while let Some(m) = st.outbox.front() {
            if synic::post_message(self.part, st.target_vp, p::SINT, m).is_err() {
                // The guest hasn't taken the last message yet. Have WHP say
                // when it has (`sints_deliverable`).
                st.slot_busy = true;
                if let Err(e) = vcpu.request_sint_deliverable(1 << p::SINT) {
                    eprintln!("[vmbus] asking for SINT deliverability failed: {e}");
                }
                break;
            }
            st.outbox.pop_front();
        }
        self.outbox_ready.store(false, Ordering::Release);
    }

    /// `vcpu` exited because the SINTs in `sints` can take messages again.
    pub fn sints_deliverable(&self, vcpu: &Vcpu, sints: u16) {
        if sints & (1 << p::SINT) == 0 {
            return;
        }
        let mut st = self.state.lock().unwrap();
        if vcpu.index() == st.target_vp && st.slot_busy {
            st.slot_busy = false;
            self.outbox_ready
                .store(!st.outbox.is_empty(), Ordering::Release);
        }
    }

    /// Stop the devices for good: call once the vCPUs are, before guest
    /// memory goes away.
    pub fn stop(&self) {
        if !self.stopped.swap(true, Ordering::AcqRel) {
            for d in &self.devices {
                d.stop();
            }
        }
    }

    /// The bus's state, for a snapshot taken with the vCPUs stopped.
    pub fn save(&self) -> Vec<u8> {
        let st = self.state.lock().unwrap();
        let mut w = Vec::new();
        let mut put = |v: u32| w.extend(v.to_le_bytes());
        put(SAVE_FORMAT);
        put(st.version);
        put(st.target_vp);
        put(st.outbox.len() as u32);
        put(st.gpadls.len() as u32);
        put(st.open.len() as u32);
        for m in &st.outbox {
            w.extend(m);
        }
        for (&id, g) in &st.gpadls {
            for v in [id, g.relid, g.pages as u32, g.pfns.len() as u32] {
                w.extend(v.to_le_bytes());
            }
            for pfn in &g.pfns {
                w.extend(pfn.to_le_bytes());
            }
        }
        for open in &st.open {
            let (flag, gpadl, target, downstream) = match open {
                Some(o) => (
                    1,
                    o.gpadl,
                    o.target_vp.load(Ordering::Relaxed),
                    o.downstream,
                ),
                None => (0, 0, 0, 0),
            };
            for v in [flag, gpadl, target, downstream] {
                w.extend(v.to_le_bytes());
            }
        }
        w
    }

    /// Put back [`Self::save`]'s state, and reopen its open channels. Call with
    /// the vCPUs' state, the SynIC's included, already restored.
    pub fn restore(&self, bytes: &[u8]) -> Result<()> {
        let bad = || Error::msg("VMBus snapshot section is malformed");
        let mut r = Reader(bytes);
        if r.u32().ok_or_else(bad)? != SAVE_FORMAT {
            return Err(Error::msg("VMBus snapshot section has an unknown format"));
        }
        let mut st = State {
            version: r.u32().ok_or_else(bad)?,
            target_vp: r.u32().ok_or_else(bad)?,
            ..State::default()
        };
        let (outbox, gpadls, devices) = (r.count(MAX_OUTBOX), r.count(MAX_GPADLS), r.u32());
        let (Some(outbox), Some(gpadls), Some(devices)) = (outbox, gpadls, devices) else {
            return Err(bad());
        };
        if devices as usize != self.devices.len() {
            return Err(Error::msg(format!(
                "the snapshot's VMBus has {devices} devices; this tinyvmm offers {}",
                self.devices.len()
            )));
        }
        if st.target_vp >= self.vcpu_count {
            return Err(bad());
        }
        for _ in 0..outbox {
            st.outbox
                .push_back(r.bytes(MESSAGE_SIZE).ok_or_else(bad)?.try_into().unwrap());
        }
        for _ in 0..gpadls {
            let (id, relid) = (r.u32().ok_or_else(bad)?, r.u32().ok_or_else(bad)?);
            let pages = r.count(MAX_GPADL_PAGES).ok_or_else(bad)?;
            let n = r.count(pages).ok_or_else(bad)?;
            let pfns = (0..n)
                .map(|_| r.u64())
                .collect::<Option<_>>()
                .ok_or_else(bad)?;
            st.gpadls.insert(id, Gpadl { relid, pages, pfns });
        }
        let mut reopen = Vec::new();
        for i in 0..self.devices.len() {
            let fields = [r.u32(), r.u32(), r.u32(), r.u32()];
            let [Some(flag), Some(gpadl), Some(target), Some(downstream)] = fields else {
                return Err(bad());
            };
            if flag == 0 {
                st.open.push(None);
                continue;
            }
            let (incoming, outgoing) = st
                .gpadls
                .get(&gpadl)
                .and_then(|g| self.rings(g, downstream))
                .filter(|_| target < self.vcpu_count)
                .ok_or_else(bad)?;
            let target_vp = Arc::new(AtomicU32::new(target));
            st.open.push(Some(Open {
                gpadl,
                target_vp: target_vp.clone(),
                downstream,
            }));
            reopen.push((i, incoming, outgoing, target_vp));
        }
        let mut cur = self.state.lock().unwrap();
        *cur = st;
        self.outbox_ready
            .store(!cur.outbox.is_empty(), Ordering::Release);
        for (i, incoming, outgoing, target_vp) in reopen {
            self.devices[i].open(Channel {
                mem: self.mem.clone(),
                part: self.part,
                relid: i as u32 + 1,
                target_vp,
                incoming,
                outgoing,
            });
        }
        Ok(())
    }
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn bytes(&mut self, n: usize) -> Option<&[u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.bytes(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.bytes(8)?.try_into().ok()?))
    }

    /// A count no larger than `max`.
    fn count(&mut self, max: usize) -> Option<usize> {
        Some(self.u32()? as usize).filter(|&n| n <= max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Fake {
        events: Mutex<Vec<String>>,
        channel: Mutex<Option<Channel>>,
    }

    impl Device for Fake {
        fn interface(&self) -> [u8; 16] {
            [0x11; 16]
        }
        fn instance(&self) -> [u8; 16] {
            [0x22; 16]
        }
        fn open(&self, channel: Channel) {
            self.events
                .lock()
                .unwrap()
                .push(format!("open {}", channel.relid));
            *self.channel.lock().unwrap() = Some(channel);
        }
        fn close(&self) {
            self.events.lock().unwrap().push("close".into());
        }
        fn signal(&self) {
            self.events.lock().unwrap().push("signal".into());
        }
        fn stop(&self) {}
    }

    /// The guest's hypercall input page.
    const INPUT: u64 = 0x1000;

    struct Bus {
        host: Arc<Host>,
        mem: Arc<GuestMemory>,
        dev: Arc<Fake>,
    }

    fn bus() -> Bus {
        let mem = Arc::new(GuestMemory::new_host_only(64 * 4096).unwrap());
        let dev = Arc::new(Fake::default());
        let host = Host::build(0, mem.clone(), 2, Box::new(|_| {}), vec![dev.clone()]);
        Bus { host, mem, dev }
    }

    fn words(values: &[u32]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    impl Bus {
        /// HvPostMessage the VMBus message `kind` with `body`, on connection 4.
        fn post(&self, kind: u32, body: &[u8]) -> u64 {
            let mut input = words(&[4, 0, 1, 8 + body.len() as u32, kind, 0]);
            input.extend(body);
            assert!(self.mem.write_bytes(INPUT, &input));
            let status = self.host.hypercall(0, HVCALL_POST_MESSAGE, INPUT);
            assert_eq!(status, HV_STATUS_SUCCESS, "posting message {kind}");
            status
        }

        /// The messages queued for the guest: their types and bodies.
        fn sent(&self) -> Vec<(u32, Vec<u8>)> {
            let mut st = self.host.state.lock().unwrap();
            let sent = st.outbox.drain(..);
            sent.map(|m| (u32_at(&m, 16).unwrap(), m[24..16 + m[4] as usize].to_vec()))
                .collect()
        }

        fn events(&self) -> Vec<String> {
            std::mem::take(&mut self.dev.events.lock().unwrap())
        }

        fn signal(&self, connection: u64) -> u64 {
            self.host
                .hypercall(1, HVCALL_SIGNAL_EVENT | HYPERCALL_FAST, connection)
        }
    }

    /// INITIATE_CONTACT for `version`, answered on vCPU 0 and SINT 2.
    fn contact(version: u32) -> Vec<u8> {
        let mut body = words(&[version, 0]);
        body.extend([p::SINT, 0, 0, 0, 0, 0, 0, 0]);
        body.extend([0; 16]); // monitor pages
        body
    }

    /// GPADL_HEADER for a GPADL of `pages` pages, carrying the first `pfns`.
    fn gpadl_header(id: u32, pages: usize, pfns: &[u64]) -> Vec<u8> {
        let mut body = words(&[1, id]);
        body.extend((8 + 8 * pages as u16).to_le_bytes()); // range_buflen
        body.extend(1u16.to_le_bytes()); // rangecount
        body.extend(words(&[pages as u32 * 4096, 0]));
        body.extend(pfns.iter().flat_map(|p| p.to_le_bytes()));
        body
    }

    /// OPENCHANNEL for relid 1 on `gpadl`, targeting vCPU 1.
    fn open(gpadl: u32, downstream: u32) -> Vec<u8> {
        let mut body = words(&[1, 99, gpadl, 1, downstream]);
        body.extend([0; 120]);
        body
    }

    fn connect() -> Bus {
        let b = bus();
        assert_eq!(b.post(p::INITIATE_CONTACT, &contact(p::VERSION_5_3)), 0);
        b.post(p::REQUESTOFFERS, &[]);
        b.sent();
        b
    }

    /// A connected bus whose channel is open on GPADL 7, pages 0x10 to 0x13.
    fn opened() -> Bus {
        let b = connect();
        b.post(
            p::GPADL_HEADER,
            &gpadl_header(7, 4, &[0x10, 0x11, 0x12, 0x13]),
        );
        b.post(p::OPENCHANNEL, &open(7, 2));
        b.sent();
        b.events();
        b
    }

    #[test]
    fn the_guest_connects_at_5_3_and_is_offered_the_device() {
        let b = bus();
        assert_eq!(b.post(p::INITIATE_CONTACT, &contact(p::version(6, 0))), 0);
        assert_eq!(
            b.sent(),
            [(p::VERSION_RESPONSE, vec![0, 0, 0, 0, 1, 0, 0, 0])]
        );
        b.post(p::REQUESTOFFERS, &[]);
        assert!(b.sent().is_empty(), "no offers before a version is agreed");

        b.post(p::INITIATE_CONTACT, &contact(p::VERSION_5_3));
        assert_eq!(
            b.sent(),
            [(p::VERSION_RESPONSE, vec![1, 0, 0, 0, 1, 0, 0, 0])]
        );
        b.post(p::REQUESTOFFERS, &[]);
        let sent = b.sent();
        assert_eq!(sent.len(), 2);
        let (kind, offer) = &sent[0];
        assert_eq!(*kind, p::OFFERCHANNEL);
        assert_eq!(&offer[..32], &[[0x11; 16], [0x22; 16]].concat());
        assert_eq!(u32_at(offer, 176), Some(1), "relid");
        assert_eq!(u32_at(offer, 184), Some(0x2001), "connection");
        assert_eq!(sent[1], (p::ALLOFFERS_DELIVERED, vec![]));
    }

    #[test]
    fn a_channel_opens_on_its_gpadl_and_takes_signals() {
        let b = connect();
        // 30 pages: 26 fit in the header, 4 come in a body.
        let pfns: Vec<u64> = (0x10..0x10 + 30).collect();
        b.post(p::GPADL_HEADER, &gpadl_header(7, 30, &pfns[..26]));
        assert!(b.sent().is_empty(), "not created until every PFN is in");
        let mut body = words(&[0, 7]);
        body.extend(pfns[26..].iter().flat_map(|p| p.to_le_bytes()));
        b.post(p::GPADL_BODY, &body);
        assert_eq!(b.sent(), [(p::GPADL_CREATED, words(&[1, 7, 0]))]);

        // The guest's send ring is pages 0 to 9, its receive ring 10 to 29.
        b.post(p::OPENCHANNEL, &open(7, 10));
        assert_eq!(b.sent(), [(p::OPENCHANNEL_RESULT, words(&[1, 99, 0]))]);
        assert_eq!(b.events(), ["open 1"]);
        let channel = b.dev.channel.lock().unwrap().clone().unwrap();
        assert_eq!(channel.target_vp.load(Ordering::Relaxed), 1);
        // What the guest writes in its send ring, the device reads.
        let guest_send = Ring::new(&pfns[..10]).unwrap();
        guest_send.write(&b.mem, b"from the guest").unwrap();
        let mut buf = Vec::new();
        assert_eq!(channel.recv(&mut buf, 64), Ok(true));
        assert_eq!(&buf[..14], b"from the guest");

        assert_eq!(b.signal(0x2001), HV_STATUS_SUCCESS);
        assert_eq!(b.events(), ["signal"]);
        assert_eq!(b.signal(0x2002), HV_STATUS_INVALID_CONNECTION_ID);

        // Retarget it: 5.3 answers.
        b.post(p::MODIFYCHANNEL, &words(&[1, 0]));
        assert_eq!(b.sent(), [(p::MODIFYCHANNEL_RESPONSE, words(&[1, 0]))]);
        assert_eq!(channel.target_vp.load(Ordering::Relaxed), 0);

        b.post(p::CLOSECHANNEL, &words(&[1]));
        assert_eq!(b.events(), ["close"]);
        assert_eq!(b.signal(0x2001), HV_STATUS_INVALID_CONNECTION_ID);
        b.post(p::GPADL_TEARDOWN, &words(&[1, 7]));
        assert_eq!(b.sent(), [(p::GPADL_TORNDOWN, words(&[7]))]);
    }

    #[test]
    fn a_bad_open_is_refused() {
        let b = connect();
        b.post(p::OPENCHANNEL, &open(7, 2));
        assert_eq!(
            b.sent(),
            [(p::OPENCHANNEL_RESULT, words(&[1, 99, 1]))],
            "no GPADL"
        );
        b.post(
            p::GPADL_HEADER,
            &gpadl_header(7, 4, &[0x10, 0x11, 0x12, 0x13]),
        );
        b.sent();
        b.post(p::OPENCHANNEL, &open(7, 3));
        assert_eq!(
            b.sent(),
            [(p::OPENCHANNEL_RESULT, words(&[1, 99, 1]))],
            "1-page ring"
        );
        assert!(b.events().is_empty());
    }

    #[test]
    fn unloading_closes_everything_and_answers() {
        let b = opened();
        b.post(p::UNLOAD, &[]);
        assert_eq!(b.events(), ["close"]);
        assert_eq!(b.sent(), [(p::UNLOAD_RESPONSE, vec![])]);
        b.post(p::REQUESTOFFERS, &[]);
        assert!(b.sent().is_empty(), "disconnected");
    }

    #[test]
    fn a_restored_bus_reopens_its_channel() {
        let b = opened();
        // An answer the guest has yet to take.
        b.post(p::GPADL_TEARDOWN, &words(&[1, 42]));
        let saved = b.host.save();

        let c = bus();
        c.host.restore(&saved).unwrap();
        assert_eq!(c.events(), ["open 1"]);
        assert_eq!(c.sent(), [(p::GPADL_TORNDOWN, words(&[42]))]);
        assert_eq!(c.signal(0x2001), HV_STATUS_SUCCESS);
        c.post(p::REQUESTOFFERS, &[]);
        assert_eq!(c.sent().len(), 2, "still connected");

        let mut other = saved.clone();
        other[20] = 2; // the device count
        assert!(c.host.restore(&other).is_err());
        assert!(c.host.restore(&saved[..30]).is_err());
    }

    #[test]
    fn malformed_hypercalls_fail_and_change_nothing() {
        let b = bus();
        let post = |control: u64, gpa: u64| b.host.hypercall(0, control, gpa);
        assert_eq!(post(0x0002, INPUT), HV_STATUS_INVALID_HYPERCALL_CODE);
        assert_eq!(
            post(HVCALL_POST_MESSAGE | HYPERCALL_FAST, INPUT),
            HV_STATUS_INVALID_HYPERCALL_INPUT
        );
        assert_eq!(
            post(HVCALL_POST_MESSAGE | 1 << 32, INPUT),
            HV_STATUS_INVALID_HYPERCALL_INPUT,
            "a rep count"
        );
        assert_eq!(
            post(HVCALL_POST_MESSAGE, INPUT + 4),
            HV_STATUS_INVALID_ALIGNMENT
        );
        let write = |conn: u32, size: u32, at: u64| {
            assert!(
                b.mem
                    .write_bytes(at, &words(&[conn, 0, 1, size, p::INITIATE_CONTACT]))
            );
        };
        write(3, 8, INPUT);
        assert_eq!(
            post(HVCALL_POST_MESSAGE, INPUT),
            HV_STATUS_INVALID_CONNECTION_ID
        );
        write(4, 241, INPUT);
        assert_eq!(
            post(HVCALL_POST_MESSAGE, INPUT),
            HV_STATUS_INVALID_PARAMETER
        );
        write(4, 8, INPUT + 4096 - 16);
        assert_eq!(
            post(HVCALL_POST_MESSAGE, INPUT + 4096 - 16),
            HV_STATUS_INVALID_ALIGNMENT,
            "input crossing a page"
        );
        assert_eq!(
            post(HVCALL_POST_MESSAGE, 1 << 40),
            HV_STATUS_INVALID_PARAMETER
        );
        assert!(b.sent().is_empty());
    }
}
