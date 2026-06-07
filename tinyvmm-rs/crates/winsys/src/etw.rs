//! Manifest-free ETW TraceLogging for tinyvmm, hand-rolled over the raw
//! `windows-sys` ETW APIs (no external crate). Mirrors the C++ `diag/etw.h`:
//! same provider name/GUID, the same keyword categories, and the same
//! self-describing TraceLogging wire format (channel 11) so existing capture
//! tooling works unchanged.
//!
//! Capture, e.g.:
//! ```text
//! logman start tinyvmm -p "{0fb6c4d5-9b9b-4e1f-9d5a-7a6d8a9b3c4d}" 0xFFFF 5 -ets -o trace.etl
//! ... run tinyvmm ...
//! logman stop tinyvmm -ets
//! tracerpt trace.etl -of csv -o trace.csv -y
//! ```
//! or open `trace.etl` in WPA / PerfView.
//!
//! Usage:
//! ```ignore
//! etw::register();
//! etw::Event::new("VmStart", etw::INFO, etw::kw::LIFECYCLE)
//!     .str("kernel", path).u64("ram_mb", ram).write();
//! // Hot path: gate on `enabled` so the event isn't built when nobody listens.
//! if etw::enabled(etw::VERBOSE, etw::kw::NET) {
//!     etw::Event::new("NetTx", etw::VERBOSE, etw::kw::NET).u32("len", n).write();
//! }
//! ```

#![allow(dead_code)]

use std::sync::atomic::{AtomicI64, AtomicU64, AtomicU8, Ordering};
use std::sync::OnceLock;
use windows_sys::core::GUID;
use windows_sys::Win32::System::Diagnostics::Etw::{
    EventRegister, EventSetInformation, EventUnregister, EventWriteTransfer, EventProviderSetTraits,
    EVENT_DATA_DESCRIPTOR, EVENT_DATA_DESCRIPTOR_0, EVENT_DATA_DESCRIPTOR_0_0,
    EVENT_DATA_DESCRIPTOR_TYPE_EVENT_METADATA, EVENT_DATA_DESCRIPTOR_TYPE_PROVIDER_METADATA,
    EVENT_DESCRIPTOR, EVENT_FILTER_DESCRIPTOR,
};

// Provider: "Tinyvmm-Core" / {0fb6c4d5-9b9b-4e1f-9d5a-7a6d8a9b3c4d} (matches C++).
const PROVIDER_NAME: &str = "Tinyvmm-Core";
const PROVIDER_GUID: GUID = GUID {
    data1: 0x0fb6_c4d5,
    data2: 0x9b9b,
    data3: 0x4e1f,
    data4: [0x9d, 0x5a, 0x7a, 0x6d, 0x8a, 0x9b, 0x3c, 0x4d],
};

// ETW levels.
pub const CRITICAL: u8 = 1;
pub const ERROR: u8 = 2;
pub const WARN: u8 = 3;
pub const INFO: u8 = 4;
pub const VERBOSE: u8 = 5;

/// Keyword categories (bitmask) — capture sessions filter on these. Mirrors the
/// C++ `kw` table.
pub mod kw {
    pub const VMEXIT: u64 = 0x0000_0001;
    pub const DOORBELL: u64 = 0x0000_0002;
    pub const VIRTIO: u64 = 0x0000_0004;
    pub const NET: u64 = 0x0000_0008;
    pub const MMIO: u64 = 0x0000_0010;
    pub const IO: u64 = 0x0000_0020;
    pub const BOOT: u64 = 0x0000_0040;
    pub const LIFECYCLE: u64 = 0x0000_0080;
    pub const BLOCK: u64 = 0x0000_0100;
    pub const CPUID: u64 = 0x0000_0200;
    pub const MSI: u64 = 0x0000_0400;
}

// TraceLogging field in-types (_TlgIn*).
const TLG_ANSISTRING: u8 = 2;
const TLG_UINT32: u8 = 8;
const TLG_UINT64: u8 = 10;
const TLG_FLOAT64: u8 = 12;
const TLG_HEXINT64: u8 = 21;

const CHANNEL_TRACELOGGING: u8 = 11;

// REGHANDLE (i64); 0 = unregistered.
static REG: AtomicI64 = AtomicI64::new(0);
// Cached enablement, updated by the ETW enable callback so the hot-path gate is
// a pure atomic check (no per-event API call). 0 level = nobody listening.
static EN_LEVEL: AtomicU8 = AtomicU8::new(0);
static EN_KW: AtomicU64 = AtomicU64::new(0);
// Provider-traits blob (kept alive for the descriptor pointer across all writes).
static PROVIDER_META: OnceLock<Vec<u8>> = OnceLock::new();

/// ETW enable/disable callback: caches the session's level + keyword mask.
unsafe extern "system" fn enable_callback(
    _source: *const GUID,
    is_enabled: u32,
    level: u8,
    match_any_keyword: u64,
    _match_all_keyword: u64,
    _filter: *const EVENT_FILTER_DESCRIPTOR,
    _context: *mut core::ffi::c_void,
) {
    // 0 = DISABLE_PROVIDER, 1 = ENABLE_PROVIDER, 2 = CAPTURE_STATE.
    if is_enabled == 0 {
        EN_LEVEL.store(0, Ordering::Relaxed);
        EN_KW.store(0, Ordering::Relaxed);
    } else if is_enabled == 1 {
        // level 0 = "all levels"; keyword 0 = "all keywords".
        EN_LEVEL.store(if level == 0 { 0xFF } else { level }, Ordering::Relaxed);
        EN_KW.store(
            if match_any_keyword == 0 {
                u64::MAX
            } else {
                match_any_keyword
            },
            Ordering::Relaxed,
        );
    }
}

/// Register the provider. Idempotent.
pub fn register() {
    if REG.load(Ordering::Acquire) != 0 {
        return;
    }
    // Provider traits blob: u16 total-size (LE, incl. itself) + name + NUL.
    let name = PROVIDER_NAME.as_bytes();
    let mut meta = Vec::with_capacity(2 + name.len() + 1);
    let total = (2 + name.len() + 1) as u16;
    meta.extend_from_slice(&total.to_le_bytes());
    meta.extend_from_slice(name);
    meta.push(0);
    let meta = PROVIDER_META.get_or_init(|| meta);

    let mut handle: i64 = 0;
    let rc = unsafe {
        EventRegister(
            &PROVIDER_GUID,
            Some(enable_callback),
            std::ptr::null(),
            &mut handle,
        )
    };
    if rc != 0 || handle == 0 {
        return;
    }
    unsafe {
        EventSetInformation(
            handle,
            EventProviderSetTraits,
            meta.as_ptr() as *const core::ffi::c_void,
            meta.len() as u32,
        );
    }
    REG.store(handle, Ordering::Release);
}

pub fn unregister() {
    let h = REG.swap(0, Ordering::AcqRel);
    if h != 0 {
        EN_LEVEL.store(0, Ordering::Relaxed);
        EN_KW.store(0, Ordering::Relaxed);
        unsafe {
            EventUnregister(h);
        }
    }
}

/// Cheap inline "is anyone listening at this level with one of these keywords?"
/// check (pure atomic loads). Gate hot-path events with this.
#[inline]
pub fn enabled(level: u8, keyword: u64) -> bool {
    let lvl = EN_LEVEL.load(Ordering::Relaxed);
    lvl != 0 && level <= lvl && (keyword & EN_KW.load(Ordering::Relaxed)) != 0
}

const MAX_FIELDS: usize = 12;
const META_CAP: usize = 256;
const VALS_CAP: usize = 512;

/// A TraceLogging event under construction. Stack-only (no heap); build fields
/// then `write()`. Field methods chain via `&mut self`.
pub struct Event {
    level: u8,
    keyword: u64,
    meta: [u8; META_CAP], // event metadata blob (size + name + field decls)
    meta_len: usize,
    vals: [u8; VALS_CAP], // packed field values
    vals_len: usize,
    foff: [usize; MAX_FIELDS], // each field value's offset/len into `vals`
    flen: [usize; MAX_FIELDS],
    nfields: usize,
    ok: bool, // false if a buffer overflowed (event is dropped)
}

impl Event {
    pub fn new(name: &str, level: u8, keyword: u64) -> Event {
        let mut e = Event {
            level,
            keyword,
            meta: [0u8; META_CAP],
            meta_len: 2, // reserve the u16 size prefix
            vals: [0u8; VALS_CAP],
            vals_len: 0,
            foff: [0; MAX_FIELDS],
            flen: [0; MAX_FIELDS],
            nfields: 0,
            ok: true,
        };
        e.push_meta(&[0]); // event-tags: none (single 0x00 before the name)
        e.push_meta(name.as_bytes());
        e.push_meta(&[0]); // NUL-terminate the event name
        e
    }

    fn push_meta(&mut self, b: &[u8]) {
        if self.meta_len + b.len() > META_CAP {
            self.ok = false;
            return;
        }
        self.meta[self.meta_len..self.meta_len + b.len()].copy_from_slice(b);
        self.meta_len += b.len();
    }

    fn push_val(&mut self, b: &[u8]) -> bool {
        if !self.ok || self.nfields >= MAX_FIELDS || self.vals_len + b.len() > VALS_CAP {
            self.ok = false;
            return false;
        }
        let off = self.vals_len;
        self.vals[off..off + b.len()].copy_from_slice(b);
        self.vals_len += b.len();
        self.foff[self.nfields] = off;
        self.flen[self.nfields] = b.len();
        self.nfields += 1;
        true
    }

    fn field(&mut self, name: &str, intype: u8) {
        self.push_meta(name.as_bytes());
        self.push_meta(&[0, intype]); // NUL + in-type byte
    }

    pub fn u32(&mut self, name: &str, v: u32) -> &mut Self {
        self.field(name, TLG_UINT32);
        self.push_val(&v.to_le_bytes());
        self
    }

    pub fn u64(&mut self, name: &str, v: u64) -> &mut Self {
        self.field(name, TLG_UINT64);
        self.push_val(&v.to_le_bytes());
        self
    }

    /// A u64 displayed in hex (addresses, RIP, GPA).
    pub fn hex64(&mut self, name: &str, v: u64) -> &mut Self {
        self.field(name, TLG_HEXINT64);
        self.push_val(&v.to_le_bytes());
        self
    }

    pub fn f64(&mut self, name: &str, v: f64) -> &mut Self {
        self.field(name, TLG_FLOAT64);
        self.push_val(&v.to_le_bytes());
        self
    }

    pub fn str(&mut self, name: &str, v: &str) -> &mut Self {
        self.field(name, TLG_ANSISTRING);
        // ANSISTRING value is the bytes followed by a NUL terminator.
        let b = v.as_bytes();
        if !self.ok || self.nfields >= MAX_FIELDS || self.vals_len + b.len() + 1 > VALS_CAP {
            self.ok = false;
            return self;
        }
        let off = self.vals_len;
        self.vals[off..off + b.len()].copy_from_slice(b);
        self.vals[off + b.len()] = 0;
        self.vals_len += b.len() + 1;
        self.foff[self.nfields] = off;
        self.flen[self.nfields] = b.len() + 1;
        self.nfields += 1;
        self
    }

    pub fn write(&mut self) {
        let h = REG.load(Ordering::Relaxed);
        if h == 0 || !self.ok || !enabled(self.level, self.keyword) {
            return;
        }
        // Patch the metadata size prefix (total length incl. the 2 size bytes).
        let mlen = self.meta_len as u16;
        self.meta[0..2].copy_from_slice(&mlen.to_le_bytes());

        let meta = PROVIDER_META.get();
        let Some(meta) = meta else {
            return;
        };

        let mut desc: [EVENT_DATA_DESCRIPTOR; MAX_FIELDS + 2] =
            unsafe { core::mem::zeroed() };
        desc[0] = data_desc(
            meta.as_ptr(),
            meta.len() as u32,
            EVENT_DATA_DESCRIPTOR_TYPE_PROVIDER_METADATA as u8,
        );
        desc[1] = data_desc(
            self.meta.as_ptr(),
            self.meta_len as u32,
            EVENT_DATA_DESCRIPTOR_TYPE_EVENT_METADATA as u8,
        );
        for i in 0..self.nfields {
            desc[2 + i] = data_desc(
                unsafe { self.vals.as_ptr().add(self.foff[i]) },
                self.flen[i] as u32,
                0,
            );
        }

        let ev = EVENT_DESCRIPTOR {
            Id: 0,
            Version: 0,
            Channel: CHANNEL_TRACELOGGING,
            Level: self.level,
            Opcode: 0,
            Task: 0,
            Keyword: self.keyword,
        };
        unsafe {
            EventWriteTransfer(
                h,
                &ev,
                std::ptr::null(),
                std::ptr::null(),
                (2 + self.nfields) as u32,
                desc.as_ptr(),
            );
        }
    }
}

fn data_desc(ptr: *const u8, size: u32, ty: u8) -> EVENT_DATA_DESCRIPTOR {
    EVENT_DATA_DESCRIPTOR {
        Ptr: ptr as u64,
        Size: size,
        Anonymous: EVENT_DATA_DESCRIPTOR_0 {
            Anonymous: EVENT_DATA_DESCRIPTOR_0_0 {
                Type: ty,
                Reserved1: 0,
                Reserved2: 0,
            },
        },
    }
}
