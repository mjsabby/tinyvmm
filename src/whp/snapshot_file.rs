//! Save/restore file-format primitives. Port of src/whp/snapshot_file.cpp.
//!
//! File layout (all integers little-endian):
//!   [FileHeader 24B]: magic "TVMMSAVE" (8) | version u32 | reserved u32 |
//!                     header_json_size u64
//!   [Header JSON]    : UTF-8 flat object (string keys; int/bool/string values)
//!   [Sections]*      : type u32 | reserved u32 | length u64 | payload[length]
//!   [Trailer]        : crc32 u32 over every preceding byte
//!
//! CRC-32 is IEEE-802.3 (poly 0xEDB88320 reflected, init/xorout 0xFFFFFFFF).
//! Snapshots are self-consistent within this Rust binary (device-state payloads
//! differ from the C++ port), but the container/section IDs match the C++.

#![allow(dead_code)]

use crate::error::{Error, Result};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::OnceLock;

pub const MAGIC: [u8; 8] = *b"TVMMSAVE";
pub const VERSION: u32 = 1;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum SectionType {
    RamRaw = 0x0001,
    VcpuRegs = 0x0010,
    VcpuXsave = 0x0011,
    VcpuApic = 0x0012,
    VcpuIntrCtl = 0x0013,
    VcpuTiming = 0x0014,
    VcpuSupMsr = 0x0015,
    HvEnlightenment = 0x0020,
    PciDevice = 0x0030,
    VirtioPciTransport = 0x0031,
    MsixState = 0x0032,
    Virtqueue = 0x0040,
    VirtioRngState = 0x0050,
    VirtioConsoleState = 0x0051,
    VirtioBlkState = 0x0052,
    LegacySerial8250 = 0x0060,
    LegacyPic8259 = 0x0061,
    LegacyPit8254 = 0x0062,
    LegacyPciBus = 0x0063,
    LegacyIsaStubs = 0x0064,
}

impl SectionType {
    pub fn from_u32(v: u32) -> Option<SectionType> {
        use SectionType::*;
        Some(match v {
            0x0001 => RamRaw,
            0x0010 => VcpuRegs,
            0x0011 => VcpuXsave,
            0x0012 => VcpuApic,
            0x0013 => VcpuIntrCtl,
            0x0014 => VcpuTiming,
            0x0015 => VcpuSupMsr,
            0x0020 => HvEnlightenment,
            0x0030 => PciDevice,
            0x0031 => VirtioPciTransport,
            0x0032 => MsixState,
            0x0040 => Virtqueue,
            0x0050 => VirtioRngState,
            0x0051 => VirtioConsoleState,
            0x0052 => VirtioBlkState,
            0x0060 => LegacySerial8250,
            0x0061 => LegacyPic8259,
            0x0062 => LegacyPit8254,
            0x0063 => LegacyPciBus,
            0x0064 => LegacyIsaStubs,
            _ => return None,
        })
    }
}

// ---------------- CRC-32 IEEE 802.3 (poly 0xEDB88320, reflected) ----------
fn crc_table() -> &'static [u32; 256] {
    static TBL: OnceLock<[u32; 256]> = OnceLock::new();
    TBL.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *slot = c;
        }
        t
    })
}

pub fn crc32_update(crc: u32, data: &[u8]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    if data.len() >= 128
        && std::arch::is_x86_feature_detected!("pclmulqdq")
        && std::arch::is_x86_feature_detected!("sse4.1")
    {
        // SAFETY: the CPU supports both features (checked just above).
        return unsafe { crc32_pclmul(crc, data) };
    }
    crc32_table(crc, data)
}

fn crc32_table(crc: u32, data: &[u8]) -> u32 {
    let tbl = crc_table();
    let mut c = crc;
    for &b in data {
        c = tbl[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    c
}

/// a(x)·b(x) mod P(x), bit-reflected (zlib's `multmodp`). `a` must not be 0.
fn multmodp(a: u32, mut b: u32) -> u32 {
    let mut m = 1u32 << 31;
    let mut p = 0u32;
    loop {
        if a & m != 0 {
            p ^= b;
            if a & (m - 1) == 0 {
                return p;
            }
        }
        m >>= 1;
        b = if b & 1 != 0 {
            (b >> 1) ^ 0xEDB8_8320
        } else {
            b >> 1
        };
    }
}

/// x^(8·len) mod P(x): what appending `len` bytes does to a CRC register.
fn x8nmodp(mut len: u64) -> u32 {
    let mut p = 1u32 << 31; // x^0
    let mut xk = 1u32 << 23; // x^8
    while len != 0 {
        if len & 1 != 0 {
            p = multmodp(xk, p);
        }
        len >>= 1;
        xk = multmodp(xk, xk);
    }
    p
}

/// The finalized CRC-32 of A‖B from those of A and B and B's length (zlib's
/// `crc32_combine`), so chunks can be checksummed independently.
fn crc32_combine(crc_a: u32, crc_b: u32, len_b: u64) -> u32 {
    multmodp(x8nmodp(len_b), crc_a) ^ crc_b
}

/// The finalized CRC-32 of `data`, computed on several threads for big inputs.
pub fn crc32_parallel(data: &[u8]) -> u32 {
    const CHUNK: usize = 32 << 20;
    const MAX_THREADS: usize = 8;
    let threads = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .min(MAX_THREADS)
        .min(data.len().div_ceil(CHUNK));
    if threads <= 1 {
        return crc32_update(0xFFFF_FFFF, data) ^ 0xFFFF_FFFF;
    }
    let chunk = data.len().div_ceil(threads);
    let parts: Vec<(u32, u64)> = std::thread::scope(|scope| {
        let handles: Vec<_> = data
            .chunks(chunk)
            .map(|c| {
                scope.spawn(move || (crc32_update(0xFFFF_FFFF, c) ^ 0xFFFF_FFFF, c.len() as u64))
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    parts[1..]
        .iter()
        .fold(parts[0].0, |crc, &(c, len)| crc32_combine(crc, c, len))
}

/// CRC-32 by carry-less multiplication: the folding method of Intel's "Fast CRC
/// Computation for Generic Polynomials Using PCLMULQDQ Instruction" (Gopal et
/// al., 2009) for the reflected IEEE polynomial, as Linux and zlib implement it.
/// Four 128-bit accumulators fold 64 bytes per step, then fold into one, reduce
/// to 64 and 32 bits, and finish with a Barrett reduction. The byte table
/// handles the tail. Snapshot RAM sections are gigabytes: a byte at a time this
/// ran at ~0.4 GB/s and dominated save and restore. Needs `data.len() >= 64`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "pclmulqdq,sse4.1")]
fn crc32_pclmul(crc: u32, data: &[u8]) -> u32 {
    use std::arch::x86_64::*;

    // Folding constants x^n mod P (bit-reflected, shifted), and P' / mu for
    // the Barrett step.
    let k1k2 = _mm_set_epi64x(0x1_c6e4_1596, 0x1_5444_2bd4);
    let k3k4 = _mm_set_epi64x(0x0_ccaa_009e, 0x1_7519_97d0);
    let k5 = _mm_set_epi64x(0, 0x1_63cd_6124);
    let poly_mu = _mm_set_epi64x(0x1_f701_1641, 0x1_db71_0641);
    let mask32 = _mm_set_epi32(0, 0, 0, -1);

    #[inline]
    #[target_feature(enable = "pclmulqdq,sse4.1")]
    fn fold(x: __m128i, k: __m128i) -> __m128i {
        _mm_xor_si128(
            _mm_clmulepi64_si128(x, k, 0x00),
            _mm_clmulepi64_si128(x, k, 0x11),
        )
    }
    #[inline]
    #[target_feature(enable = "sse2")]
    fn load(block: &[u8]) -> __m128i {
        assert!(block.len() >= 16);
        // SAFETY: `block` has at least 16 readable bytes; the load is unaligned.
        unsafe { _mm_loadu_si128(block.as_ptr().cast()) }
    }

    let (body, tail) = data.split_at(data.len() & !15);
    let mut x1 = _mm_xor_si128(load(&body[0..]), _mm_cvtsi32_si128(crc as i32));
    let mut x2 = load(&body[16..]);
    let mut x3 = load(&body[32..]);
    let mut x4 = load(&body[48..]);
    let mut rest = &body[64..];
    while rest.len() >= 64 {
        x1 = _mm_xor_si128(fold(x1, k1k2), load(&rest[0..]));
        x2 = _mm_xor_si128(fold(x2, k1k2), load(&rest[16..]));
        x3 = _mm_xor_si128(fold(x3, k1k2), load(&rest[32..]));
        x4 = _mm_xor_si128(fold(x4, k1k2), load(&rest[48..]));
        rest = &rest[64..];
    }
    x1 = _mm_xor_si128(fold(x1, k3k4), x2);
    x1 = _mm_xor_si128(fold(x1, k3k4), x3);
    x1 = _mm_xor_si128(fold(x1, k3k4), x4);
    while rest.len() >= 16 {
        x1 = _mm_xor_si128(fold(x1, k3k4), load(rest));
        rest = &rest[16..];
    }
    // 128 -> 64 bits.
    x1 = _mm_xor_si128(_mm_srli_si128(x1, 8), _mm_clmulepi64_si128(k3k4, x1, 0x01));
    // 64 -> 32 bits.
    let hi = _mm_srli_si128(x1, 4);
    x1 = _mm_xor_si128(
        _mm_clmulepi64_si128(_mm_and_si128(x1, mask32), k5, 0x00),
        hi,
    );
    // Barrett reduction.
    let t = _mm_clmulepi64_si128(_mm_and_si128(x1, mask32), poly_mu, 0x10);
    let t = _mm_clmulepi64_si128(_mm_and_si128(t, mask32), poly_mu, 0x00);
    let crc = _mm_extract_epi32(_mm_xor_si128(t, x1), 1) as u32;
    crc32_table(crc, tail)
}

// ============================================================
// Minimal flat-JSON header (string keys; u64 / bool / string values)
// ============================================================
#[derive(Default)]
pub struct JsonWriter {
    entries: Vec<String>,
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

impl JsonWriter {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn u64(&mut self, key: &str, v: u64) -> &mut Self {
        self.entries.push(format!("{}:{}", escape_json(key), v));
        self
    }
    pub fn bool(&mut self, key: &str, v: bool) -> &mut Self {
        self.entries.push(format!("{}:{}", escape_json(key), v));
        self
    }
    pub fn str(&mut self, key: &str, v: &str) -> &mut Self {
        self.entries
            .push(format!("{}:{}", escape_json(key), escape_json(v)));
        self
    }
    pub fn finish(&self) -> String {
        format!("{{{}}}", self.entries.join(","))
    }
}

/// Parsed flat JSON object. Tolerant of the canonical compact form this module
/// writes (and only that — string-aware so paths with `:` `,` `\` round-trip).
pub struct JsonReader {
    kv: HashMap<String, String>,
}

impl JsonReader {
    pub fn parse(json: &str) -> Result<JsonReader> {
        let b = json.as_bytes();
        let mut i = 0usize;
        let n = b.len();
        let skip_ws = |i: &mut usize| {
            while *i < n && (b[*i] as char).is_whitespace() {
                *i += 1;
            }
        };
        let parse_string = |i: &mut usize| -> Result<String> {
            if *i >= n || b[*i] != b'"' {
                return Err(Error::msg("json: expected string"));
            }
            *i += 1;
            let mut out = String::new();
            while *i < n {
                let c = b[*i];
                if c == b'"' {
                    *i += 1;
                    return Ok(out);
                }
                if c == b'\\' {
                    *i += 1;
                    if *i >= n {
                        return Err(Error::msg("json: dangling backslash"));
                    }
                    match b[*i] {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            if *i + 4 >= n {
                                return Err(Error::msg("json: truncated \\u"));
                            }
                            let mut code = 0u32;
                            for _ in 0..4 {
                                *i += 1;
                                let h = b[*i];
                                let d = match h {
                                    b'0'..=b'9' => (h - b'0') as u32,
                                    b'a'..=b'f' => 10 + (h - b'a') as u32,
                                    b'A'..=b'F' => 10 + (h - b'A') as u32,
                                    _ => return Err(Error::msg("json: bad hex")),
                                };
                                code = (code << 4) | d;
                            }
                            out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                        }
                        _ => return Err(Error::msg("json: unknown escape")),
                    }
                    *i += 1;
                } else {
                    // Push the raw UTF-8 byte run for this char.
                    let start = *i;
                    *i += 1;
                    while *i < n && (b[*i] & 0xC0) == 0x80 {
                        *i += 1;
                    }
                    out.push_str(std::str::from_utf8(&b[start..*i]).unwrap_or("\u{fffd}"));
                }
            }
            Err(Error::msg("json: unterminated string"))
        };

        let mut kv = HashMap::new();
        skip_ws(&mut i);
        if i >= n || b[i] != b'{' {
            return Err(Error::msg("json: expected '{'"));
        }
        i += 1;
        skip_ws(&mut i);
        if i < n && b[i] == b'}' {
            return Ok(JsonReader { kv });
        }
        loop {
            skip_ws(&mut i);
            let key = parse_string(&mut i)?;
            skip_ws(&mut i);
            if i >= n || b[i] != b':' {
                return Err(Error::msg("json: expected ':'"));
            }
            i += 1;
            skip_ws(&mut i);
            let val = if i < n && b[i] == b'"' {
                parse_string(&mut i)?
            } else {
                // number or bool/true/false: read until , or }
                let start = i;
                while i < n && b[i] != b',' && b[i] != b'}' {
                    i += 1;
                }
                json[start..i].trim().to_string()
            };
            kv.insert(key, val);
            skip_ws(&mut i);
            if i < n && b[i] == b',' {
                i += 1;
                continue;
            }
            if i < n && b[i] == b'}' {
                break;
            }
            return Err(Error::msg("json: expected ',' or '}'"));
        }
        Ok(JsonReader { kv })
    }

    pub fn has(&self, key: &str) -> bool {
        self.kv.contains_key(key)
    }
    pub fn get_u64(&self, key: &str) -> Result<u64> {
        self.kv
            .get(key)
            .ok_or_else(|| Error::msg(format!("json: missing key '{key}'")))?
            .parse()
            .map_err(|_| Error::msg(format!("json: key '{key}' not an integer")))
    }
    pub fn get_bool(&self, key: &str) -> Result<bool> {
        match self
            .kv
            .get(key)
            .ok_or_else(|| Error::msg(format!("json: missing key '{key}'")))?
            .as_str()
        {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(Error::msg(format!("json: key '{key}' not a bool"))),
        }
    }
    pub fn get_str(&self, key: &str) -> Result<String> {
        self.kv
            .get(key)
            .cloned()
            .ok_or_else(|| Error::msg(format!("json: missing key '{key}'")))
    }
}

// ============================================================
// Writer
// ============================================================
pub struct SnapshotWriter {
    path: String,
    out: BufWriter<File>,
    crc: u32,
    bytes: u64,
    header_written: bool,
    finalized: bool,
}

impl SnapshotWriter {
    pub fn create(path: &str) -> Result<SnapshotWriter> {
        let f =
            File::create(path).map_err(|e| Error::msg(format!("snapshot: create {path}: {e}")))?;
        Ok(SnapshotWriter {
            path: path.to_string(),
            out: BufWriter::new(f),
            crc: 0xFFFF_FFFF,
            bytes: 0,
            header_written: false,
            finalized: false,
        })
    }

    fn write_raw(&mut self, data: &[u8]) -> Result<()> {
        self.out
            .write_all(data)
            .map_err(|e| Error::msg(format!("snapshot: write {}: {e}", self.path)))?;
        self.crc = crc32_update(self.crc, data);
        self.bytes += data.len() as u64;
        Ok(())
    }

    pub fn write_header(&mut self, json: &str) -> Result<()> {
        assert!(!self.header_written, "write_header called twice");
        let jb = json.as_bytes();
        let mut hdr = [0u8; 24];
        hdr[0..8].copy_from_slice(&MAGIC);
        hdr[8..12].copy_from_slice(&VERSION.to_le_bytes());
        // [12..16] reserved = 0
        hdr[16..24].copy_from_slice(&(jb.len() as u64).to_le_bytes());
        self.write_raw(&hdr)?;
        self.write_raw(jb)?;
        self.header_written = true;
        Ok(())
    }

    pub fn write_section(&mut self, ty: SectionType, data: &[u8]) -> Result<()> {
        let mut hdr = [0u8; 16];
        hdr[0..4].copy_from_slice(&(ty as u32).to_le_bytes());
        // [4..8] reserved = 0
        hdr[8..16].copy_from_slice(&(data.len() as u64).to_le_bytes());
        self.write_raw(&hdr)?;
        // RAM payloads can be hundreds of MiB; write in 1 MiB chunks.
        const CHUNK: usize = 1 << 20;
        let mut off = 0;
        while off < data.len() {
            let end = (off + CHUNK).min(data.len());
            self.write_raw(&data[off..end])?;
            off = end;
        }
        Ok(())
    }

    pub fn finalize(mut self) -> Result<u64> {
        let crc = self.crc ^ 0xFFFF_FFFF;
        self.out
            .write_all(&crc.to_le_bytes())
            .map_err(|e| Error::msg(format!("snapshot: write trailer: {e}")))?;
        self.bytes += 4;
        self.out
            .flush()
            .map_err(|e| Error::msg(format!("snapshot: flush: {e}")))?;
        self.out
            .get_ref()
            .sync_all()
            .map_err(|e| Error::msg(format!("snapshot: sync: {e}")))?;
        self.finalized = true;
        Ok(self.bytes)
    }
}

impl Drop for SnapshotWriter {
    fn drop(&mut self) {
        if !self.finalized {
            // Partial file: best-effort remove so a crashed save leaves nothing.
            let _ = std::fs::remove_file(&self.path);
            eprintln!("[snapshot] WARN: writer dropped without finalize; removed partial file");
        }
    }
}

// ============================================================
// Reader
// ============================================================
/// Reads a snapshot through a read-only mapping of the file: no heap copy of a
/// gigabyte-sized RAM section, and its pages come straight from the file cache.
/// Writers are locked out while it's open, so the bytes `verify_trailer`
/// checked are the ones restored.
pub struct SnapshotReader {
    map: crate::host::mapped_file::MappedFile,
    pos: usize,
    header_read: bool,
}

pub struct SectionRef<'a> {
    pub ty: SectionType,
    pub payload: &'a [u8],
}

impl SnapshotReader {
    pub fn open(path: &str) -> Result<SnapshotReader> {
        let map = crate::host::mapped_file::MappedFile::open_no_writers(path)
            .map_err(|e| Error::msg(format!("snapshot: read {path}: {e}")))?;
        if map.size() < 24 + 4 {
            return Err(Error::msg("snapshot: file too small"));
        }
        Ok(SnapshotReader {
            map,
            pos: 0,
            header_read: false,
        })
    }

    fn buf(&self) -> &[u8] {
        self.map.bytes()
    }

    pub fn read_header(&mut self) -> Result<String> {
        let buf = self.map.bytes();
        if buf[0..8] != MAGIC {
            return Err(Error::msg("snapshot: bad magic"));
        }
        let ver = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        if ver != VERSION {
            return Err(Error::msg(format!("snapshot: version {ver} != {VERSION}")));
        }
        let jsz = u64::from_le_bytes(buf[16..24].try_into().unwrap()) as usize;
        if jsz > buf.len().saturating_sub(24 + 4) {
            return Err(Error::msg("snapshot: header_json_size out of range"));
        }
        let json = std::str::from_utf8(&buf[24..24 + jsz])
            .map_err(|_| Error::msg("snapshot: header JSON not UTF-8"))?
            .to_string();
        self.pos = 24 + jsz;
        self.header_read = true;
        Ok(json)
    }

    /// Returns the next section, or None when only the 4-byte trailer remains.
    pub fn next_section(&mut self) -> Result<Option<SectionRef<'_>>> {
        let buf = self.map.bytes();
        let end = buf.len() - 4; // trailer
        if self.pos == end {
            return Ok(None);
        }
        if self.pos + 16 > end {
            return Err(Error::msg("snapshot: truncated section header"));
        }
        let ty_raw = u32::from_le_bytes(buf[self.pos..self.pos + 4].try_into().unwrap());
        let reserved = u32::from_le_bytes(buf[self.pos + 4..self.pos + 8].try_into().unwrap());
        if reserved != 0 {
            return Err(Error::msg("snapshot: section reserved != 0"));
        }
        let len = u64::from_le_bytes(buf[self.pos + 8..self.pos + 16].try_into().unwrap()) as usize;
        let body = self.pos + 16;
        // `body <= end` here (checked just above), so `end - body` can't
        // underflow; written as subtraction to avoid `body + len` overflowing for
        // a crafted near-u64::MAX length (which would bypass the guard and then
        // panic on the slice below).
        if len > end - body {
            return Err(Error::msg("snapshot: section length out of range"));
        }
        let ty = SectionType::from_u32(ty_raw)
            .ok_or_else(|| Error::msg(format!("snapshot: unknown section type {ty_raw:#x}")))?;
        self.pos = body + len;
        Ok(Some(SectionRef {
            ty,
            payload: &buf[body..body + len],
        }))
    }

    pub fn verify_trailer(&self) -> Result<()> {
        let buf = self.buf();
        let n = buf.len();
        let saved = u32::from_le_bytes(buf[n - 4..n].try_into().unwrap());
        let crc = crc32_parallel(&buf[..n - 4]);
        if crc != saved {
            return Err(Error::msg(format!(
                "snapshot: CRC mismatch (file {saved:#010x} != computed {crc:#010x})"
            )));
        }
        Ok(())
    }

    pub fn file_size(&self) -> u64 {
        self.map.size() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The carry-less-multiply CRC must match the byte table for every length
    /// (the fold paths change at 64- and 16-byte steps) and alignment, and the
    /// IEEE check value; snapshots written before it must still verify.
    #[test]
    fn crc32_fast_path_matches_table() {
        let full = |data: &[u8]| crc32_update(0xFFFF_FFFF, data) ^ 0xFFFF_FFFF;
        assert_eq!(full(b"123456789"), 0xCBF4_3926);
        let mut seed = 0x9E37_79B9u32;
        let buf: Vec<u8> = (0..4096 + 64)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                seed as u8
            })
            .collect();
        for align in 0..16 {
            for len in (0..300).chain([1000, 4095, 4096]) {
                let d = &buf[align..align + len];
                for init in [0xFFFF_FFFFu32, 0x1234_5678] {
                    assert_eq!(
                        crc32_update(init, d),
                        crc32_table(init, d),
                        "len {len} align {align}"
                    );
                }
            }
        }
        // Chunked updates compose like one pass.
        let (a, b) = buf.split_at(777);
        assert_eq!(
            crc32_update(crc32_update(0xFFFF_FFFF, a), b),
            crc32_update(0xFFFF_FFFF, &buf)
        );
    }

    /// Independently checksummed chunks combine into the CRC of the whole, so
    /// restore can verify a multi-GiB snapshot on several threads.
    #[test]
    fn crc32_combines_chunks() {
        let data: Vec<u8> = (0..(80u32 << 20) + 12_345)
            .map(|i| (i ^ (i >> 9)) as u8)
            .collect();
        let whole = crc32_update(0xFFFF_FFFF, &data) ^ 0xFFFF_FFFF;
        assert_eq!(crc32_parallel(&data), whole);
        for cut in [0usize, 1, 4096, 1_000_001] {
            let (a, b) = data.split_at(cut);
            let ca = crc32_update(0xFFFF_FFFF, a) ^ 0xFFFF_FFFF;
            let cb = crc32_update(0xFFFF_FFFF, b) ^ 0xFFFF_FFFF;
            assert_eq!(crc32_combine(ca, cb, b.len() as u64), whole, "cut {cut}");
        }
    }

    #[test]
    fn roundtrip() {
        let path = std::env::temp_dir().join("tv_snap_fmt_test.bin");
        let p = path.to_str().unwrap();
        let mut jw = JsonWriter::new();
        jw.u64("ram", 268435456)
            .u64("vcpus", 4)
            .bool("net", false)
            .str("drive", r#"C:\path,with"comma\and quote"#);
        let json = jw.finish();
        {
            let mut w = SnapshotWriter::create(p).unwrap();
            w.write_header(&json).unwrap();
            w.write_section(SectionType::RamRaw, &[1u8, 2, 3, 4, 5])
                .unwrap();
            w.write_section(SectionType::VcpuRegs, &vec![0xABu8; 100])
                .unwrap();
            w.finalize().unwrap();
        }
        let mut r = SnapshotReader::open(p).unwrap();
        let jr_str = r.read_header().unwrap();
        let jr = JsonReader::parse(&jr_str).unwrap();
        assert_eq!(jr.get_u64("ram").unwrap(), 268435456);
        assert_eq!(jr.get_u64("vcpus").unwrap(), 4);
        assert!(!jr.get_bool("net").unwrap());
        assert_eq!(
            jr.get_str("drive").unwrap(),
            r#"C:\path,with"comma\and quote"#
        );
        let s0 = r.next_section().unwrap().unwrap();
        assert_eq!(s0.ty, SectionType::RamRaw);
        assert_eq!(s0.payload, &[1, 2, 3, 4, 5]);
        let s1 = r.next_section().unwrap().unwrap();
        assert_eq!(s1.ty, SectionType::VcpuRegs);
        assert_eq!(s1.payload.len(), 100);
        assert!(r.next_section().unwrap().is_none());
        r.verify_trailer().unwrap();
        let _ = std::fs::remove_file(p);
    }
}
