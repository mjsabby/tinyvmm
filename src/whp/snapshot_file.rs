//! Save/restore file-format primitives. Port of src/whp/snapshot_file.cpp.
//!
//! File layout (all integers little-endian):
//!   [FileHeader 24B]: magic "TVMMSAVE" (8) | version u32 | reserved u32 |
//!                     header_json_size u64
//!   [Header JSON]    : UTF-8 flat object (string keys; int/bool/string values)
//!   [Sections]*      : type u32 | reserved u32 | length u64 | payload[length]
//!   [Trailer]        : crc32 u32 over every preceding byte
//!
//! Guest RAM is one `RamSparse` section: chunk_size u32 | reserved u32 |
//! image_len u64 | a bitmap of the image's chunks (bit i of byte i/8: chunk i
//! is stored) | the stored chunks in order, the last one short if image_len
//! ends mid-chunk. Chunks that are all zero are left out and come back as zero.
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

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::__m128i;

pub const MAGIC: [u8; 8] = *b"TVMMSAVE";
/// 2: guest RAM is stored sparse. Version 1 (RAM stored whole, section type
/// 0x0001) is not read.
pub const VERSION: u32 = 2;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum SectionType {
    RamSparse = 0x0002,
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
            0x0002 => RamSparse,
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
        if data.len() >= 256
            && std::arch::is_x86_feature_detected!("avx2")
            && std::arch::is_x86_feature_detected!("vpclmulqdq")
        {
            // SAFETY: the CPU supports all four features (checked just above).
            return unsafe { crc32_vpclmul(crc, data) };
        }
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

    // Folding constants: x^n mod P(x) bit-reflected and shifted left once, for
    // n = 4*128 + 32 and 4*128 - 32 (across 512 bits), and 128 + 32 and 128 - 32.
    let k1k2 = _mm_set_epi64x(0x1_c6e4_1596, 0x1_5444_2bd4);
    let k3k4 = _mm_set_epi64x(0x0_ccaa_009e, 0x1_7519_97d0);

    let (body, tail) = data.split_at(data.len() & !15);
    let mut x1 = _mm_xor_si128(load16(&body[0..]), _mm_cvtsi32_si128(crc as i32));
    let mut x2 = load16(&body[16..]);
    let mut x3 = load16(&body[32..]);
    let mut x4 = load16(&body[48..]);
    let mut rest = &body[64..];
    while rest.len() >= 64 {
        x1 = _mm_xor_si128(clmul_fold(x1, k1k2), load16(&rest[0..]));
        x2 = _mm_xor_si128(clmul_fold(x2, k1k2), load16(&rest[16..]));
        x3 = _mm_xor_si128(clmul_fold(x3, k1k2), load16(&rest[32..]));
        x4 = _mm_xor_si128(clmul_fold(x4, k1k2), load16(&rest[48..]));
        rest = &rest[64..];
    }
    x1 = _mm_xor_si128(clmul_fold(x1, k3k4), x2);
    x1 = _mm_xor_si128(clmul_fold(x1, k3k4), x3);
    x1 = _mm_xor_si128(clmul_fold(x1, k3k4), x4);
    crc32_clmul_finish(x1, rest, tail)
}

/// [`crc32_pclmul`] with 256-bit carry-less multiplies (VPCLMULQDQ, which recent
/// x86 CPUs have alongside AVX2): four accumulators fold 128 bytes per step,
/// each 128-bit lane across 1024 bits, then fold into one 128-bit accumulator
/// that finishes the same way. Twice the speed of the 128-bit loop on a block in
/// cache (~49 vs ~25 GB/s for 64 KiB on the reference host); restoring a guest
/// with 2 GiB of RAM stored, it cut the CRC's CPU time by about a quarter, as
/// the pieces just read are only partly still in cache. Needs
/// `data.len() >= 128`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,vpclmulqdq,pclmulqdq,sse4.1")]
fn crc32_vpclmul(crc: u32, data: &[u8]) -> u32 {
    use std::arch::x86_64::*;

    // As in crc32_pclmul, for n = 8*128 +/- 32 (across 1024 bits) and
    // 2*128 +/- 32 (256 bits), in both 128-bit lanes.
    let pair = |lo: i64, hi: i64| _mm256_set_epi64x(hi, lo, hi, lo);
    let k1024 = pair(0x1_e88e_f372, 0x1_4a7f_e880);
    let k256 = pair(0x0_f1da_05aa, 0x1_5a54_6366);
    let k3k4 = _mm_set_epi64x(0x0_ccaa_009e, 0x1_7519_97d0);
    let fold = |x, k| {
        _mm256_xor_si256(
            _mm256_clmulepi64_epi128::<0x00>(x, k),
            _mm256_clmulepi64_epi128::<0x11>(x, k),
        )
    };
    let load = |block: &[u8]| {
        assert!(block.len() >= 32);
        // SAFETY: `block` has at least 32 readable bytes; the load is unaligned.
        unsafe { _mm256_loadu_si256(block.as_ptr().cast()) }
    };

    let (body, tail) = data.split_at(data.len() & !15);
    let init = _mm256_setr_epi32(crc as i32, 0, 0, 0, 0, 0, 0, 0);
    let mut y1 = _mm256_xor_si256(load(&body[0..]), init);
    let mut y2 = load(&body[32..]);
    let mut y3 = load(&body[64..]);
    let mut y4 = load(&body[96..]);
    let mut rest = &body[128..];
    while rest.len() >= 128 {
        y1 = _mm256_xor_si256(fold(y1, k1024), load(&rest[0..]));
        y2 = _mm256_xor_si256(fold(y2, k1024), load(&rest[32..]));
        y3 = _mm256_xor_si256(fold(y3, k1024), load(&rest[64..]));
        y4 = _mm256_xor_si256(fold(y4, k1024), load(&rest[96..]));
        rest = &rest[128..];
    }
    y1 = _mm256_xor_si256(fold(y1, k256), y2);
    y1 = _mm256_xor_si256(fold(y1, k256), y3);
    y1 = _mm256_xor_si256(fold(y1, k256), y4);
    let x1 = _mm_xor_si128(
        clmul_fold(_mm256_castsi256_si128(y1), k3k4),
        _mm256_extracti128_si256::<1>(y1),
    );
    crc32_clmul_finish(x1, rest, tail)
}

/// Fold the 16-byte blocks of `rest` into the accumulator `x1`, reduce it to
/// 64 and 32 bits, finish with a Barrett reduction, and run the byte table
/// over `tail`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "pclmulqdq,sse4.1")]
fn crc32_clmul_finish(mut x1: __m128i, mut rest: &[u8], tail: &[u8]) -> u32 {
    use std::arch::x86_64::*;

    // k3/k4 as in crc32_pclmul, x^64 mod P for 64 -> 32 bits, and P' / mu for
    // the Barrett step.
    let k3k4 = _mm_set_epi64x(0x0_ccaa_009e, 0x1_7519_97d0);
    let k5 = _mm_set_epi64x(0, 0x1_63cd_6124);
    let poly_mu = _mm_set_epi64x(0x1_f701_1641, 0x1_db71_0641);
    let mask32 = _mm_set_epi32(0, 0, 0, -1);
    while rest.len() >= 16 {
        x1 = _mm_xor_si128(clmul_fold(x1, k3k4), load16(rest));
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

/// Carry-less multiply `x`'s low half by `k`'s and its high half by `k`'s, and
/// add (xor) the products: one folding step.
#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "pclmulqdq,sse4.1")]
fn clmul_fold(x: __m128i, k: __m128i) -> __m128i {
    use std::arch::x86_64::*;
    _mm_xor_si128(
        _mm_clmulepi64_si128(x, k, 0x00),
        _mm_clmulepi64_si128(x, k, 0x11),
    )
}

#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "sse2")]
fn load16(block: &[u8]) -> __m128i {
    assert!(block.len() >= 16);
    // SAFETY: `block` has at least 16 readable bytes; the load is unaligned.
    unsafe { std::arch::x86_64::_mm_loadu_si128(block.as_ptr().cast()) }
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
// Sparse RAM
// ============================================================
/// Granularity of a sparse RAM image: the writer leaves out all-zero chunks.
pub const SPARSE_CHUNK: usize = 64 * 1024;

fn is_zero(b: &[u8]) -> bool {
    // SAFETY: every bit pattern is a valid u64.
    let (head, words, tail) = unsafe { b.align_to::<u64>() };
    head.iter().all(|&x| x == 0)
        && tail.iter().all(|&x| x == 0)
        && words
            .chunks(32)
            .all(|c| c.iter().fold(0, |a, &x| a | x) == 0)
}

/// Which [`SPARSE_CHUNK`]s of the `len`-byte image `read` copies out hold a
/// non-zero byte, scanned on up to eight threads.
fn stored_chunks(len: usize, read: &(impl Fn(usize, &mut [u8]) + Sync)) -> Vec<bool> {
    let n = len.div_ceil(SPARSE_CHUNK);
    let mut stored = vec![false; n];
    let threads = std::thread::available_parallelism()
        .map_or(1, |t| t.get())
        .clamp(1, 8)
        .min(n.max(1));
    let per = n.div_ceil(threads).max(1);
    std::thread::scope(|scope| {
        for (t, out) in stored.chunks_mut(per).enumerate() {
            scope.spawn(move || {
                let mut chunk = vec![0u8; SPARSE_CHUNK];
                for (j, s) in out.iter_mut().enumerate() {
                    let at = (t * per + j) * SPARSE_CHUNK;
                    let c = &mut chunk[..SPARSE_CHUNK.min(len - at)];
                    read(at, c);
                    *s = !is_zero(c);
                }
            });
        }
    });
    stored
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
        self.write_raw(data)
    }

    /// Write a guest RAM image as a [`SectionType::RamSparse`] section, leaving
    /// out every all-zero [`SPARSE_CHUNK`]. A booted guest's RAM is mostly
    /// zero (about 95% of a 1 GiB guest at a shell prompt), so this writes, and
    /// a restore later reads, a small fraction of it. The image is `len` bytes
    /// that `read(off, dst)` copies out a piece at a time; guest RAM is never
    /// borrowed, since a device thread may still write it. Returns the bytes of
    /// RAM stored.
    pub fn write_ram_sparse(
        &mut self,
        len: usize,
        read: impl Fn(usize, &mut [u8]) + Sync,
    ) -> Result<u64> {
        let stored = stored_chunks(len, &read);
        let chunk_len = |i: usize| SPARSE_CHUNK.min(len - i * SPARSE_CHUNK);
        let mut bitmap = vec![0u8; stored.len().div_ceil(8)];
        let mut data_len = 0u64;
        for (i, _) in stored.iter().enumerate().filter(|(_, s)| **s) {
            bitmap[i / 8] |= 1 << (i % 8);
            data_len += chunk_len(i) as u64;
        }
        let mut hdr = [0u8; 32];
        hdr[0..4].copy_from_slice(&(SectionType::RamSparse as u32).to_le_bytes());
        let section_len = 16 + bitmap.len() as u64 + data_len;
        hdr[8..16].copy_from_slice(&section_len.to_le_bytes());
        hdr[16..20].copy_from_slice(&(SPARSE_CHUNK as u32).to_le_bytes());
        hdr[24..32].copy_from_slice(&(len as u64).to_le_bytes());
        self.write_raw(&hdr)?;
        self.write_raw(&bitmap)?;
        // Runs of stored chunks go out as single writes of up to 1 MiB.
        const RUN: usize = (1 << 20) / SPARSE_CHUNK;
        let mut run = vec![0u8; RUN * SPARSE_CHUNK];
        let mut i = 0;
        while i < stored.len() {
            if !stored[i] {
                i += 1;
                continue;
            }
            let start = i;
            while i < stored.len() && stored[i] && i - start < RUN {
                i += 1;
            }
            let begin = start * SPARSE_CHUNK;
            let bytes = &mut run[..(i * SPARSE_CHUNK).min(len) - begin];
            read(begin, bytes);
            self.write_raw(bytes)?;
        }
        Ok(data_len)
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
/// Reads a snapshot without ever holding its RAM section in host memory: `open`
/// reads everything else (header, the small sections) with positioned reads,
/// and [`Self::load_ram_and_verify`] reads the RAM payload straight into guest
/// memory on several threads, checksumming each chunk as it lands, then checks
/// the whole file's CRC. Writers are locked out while it's open.
pub struct SnapshotReader {
    path: String,
    _file: File,
    /// Every byte before the trailer except the RAM payload.
    meta: Vec<u8>,
    ram: Option<RamSpan>,
    trailer: u32,
    pos: usize,
    header_read: bool,
}

/// Where the RAM section's parts sit: its sub-header and chunk bitmap stay in
/// `meta`, its stored chunks in the file.
#[derive(Clone, Copy)]
struct RamSpan {
    /// Where the section's body starts in `meta`.
    body_at: usize,
    /// Where the stored chunks were cut out of `meta` (after the sub-header
    /// and bitmap).
    meta_at: usize,
    /// The stored chunks, in the file.
    file_off: u64,
    len: u64,
    chunk: usize,
    image_len: u64,
    /// The chunk bitmap, in `meta`.
    bitmap_at: usize,
}

impl RamSpan {
    fn chunks(&self) -> usize {
        self.image_len.div_ceil(self.chunk as u64) as usize
    }
    fn stored(&self, meta: &[u8], i: usize) -> bool {
        meta[self.bitmap_at + i / 8] >> (i % 8) & 1 != 0
    }
    fn chunk_len(&self, i: usize) -> u64 {
        (self.chunk as u64).min(self.image_len - (i * self.chunk) as u64)
    }
}

pub struct SectionRef<'a> {
    pub ty: SectionType,
    pub payload: &'a [u8],
}

/// Open for reading, denying writers so the file can't change under a restore.
fn open_no_writers(path: &str) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 1;
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
}

fn read_exact_at(f: &File, mut buf: &mut [u8], mut off: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = f.seek_read(buf, off)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf = &mut buf[n..];
        off += n as u64;
    }
    Ok(())
}

/// Finalized CRC-32 of `data`.
fn crc32(data: &[u8]) -> u32 {
    crc32_update(0xFFFF_FFFF, data) ^ 0xFFFF_FFFF
}

impl SnapshotReader {
    pub fn open(path: &str) -> Result<SnapshotReader> {
        let io = |e: std::io::Error| Error::msg(format!("snapshot: read {path}: {e}"));
        let file = open_no_writers(path).map_err(io)?;
        let size = file.metadata().map_err(io)?.len();
        if size < 24 + 4 {
            return Err(Error::msg("snapshot: file too small"));
        }
        let end = size - 4;
        let mut trailer = [0u8; 4];
        read_exact_at(&file, &mut trailer, end).map_err(io)?;
        let mut meta = vec![0u8; 24];
        read_exact_at(&file, &mut meta, 0).map_err(io)?;
        let jsz = u64::from_le_bytes(meta[16..24].try_into().unwrap());
        if jsz > end - 24 {
            return Err(Error::msg("snapshot: header_json_size out of range"));
        }
        meta.resize(24 + jsz as usize, 0);
        read_exact_at(&file, &mut meta[24..], 24).map_err(io)?;
        // Walk the section headers, reading every payload but the RAM image's.
        // `next_section` validates types and reserved fields as it hands them out.
        let mut pos = 24 + jsz;
        let mut ram = None;
        while pos < end {
            if end - pos < 16 {
                return Err(Error::msg("snapshot: truncated section header"));
            }
            let at = meta.len();
            meta.resize(at + 16, 0);
            read_exact_at(&file, &mut meta[at..], pos).map_err(io)?;
            let ty = u32::from_le_bytes(meta[at..at + 4].try_into().unwrap());
            let len = u64::from_le_bytes(meta[at + 8..at + 16].try_into().unwrap());
            pos += 16;
            if len > end - pos {
                return Err(Error::msg("snapshot: section length out of range"));
            }
            if ty == SectionType::RamSparse as u32 && ram.is_none() {
                // The sub-header and bitmap stay with the metadata; only the
                // stored chunks are cut out.
                let bad = |what: &str| Error::msg(format!("snapshot: RAM section {what}"));
                if len < 16 {
                    return Err(bad("too short"));
                }
                let body_at = meta.len();
                meta.resize(body_at + 16, 0);
                read_exact_at(&file, &mut meta[body_at..], pos).map_err(io)?;
                let sub = &meta[body_at..];
                let chunk = u32::from_le_bytes(sub[0..4].try_into().unwrap()) as usize;
                let reserved = u32::from_le_bytes(sub[4..8].try_into().unwrap());
                let image_len = u64::from_le_bytes(sub[8..16].try_into().unwrap());
                if !chunk.is_power_of_two() || !(4096..=16 << 20).contains(&chunk) {
                    return Err(bad("chunk size invalid"));
                }
                if reserved != 0 {
                    return Err(bad("reserved != 0"));
                }
                let bitmap_len = image_len.div_ceil(chunk as u64).div_ceil(8);
                if bitmap_len > len - 16 {
                    return Err(bad("bitmap past the section"));
                }
                let mut span = RamSpan {
                    body_at,
                    meta_at: 0,
                    file_off: pos + 16 + bitmap_len,
                    len: 0,
                    chunk,
                    image_len,
                    bitmap_at: body_at + 16,
                };
                meta.resize(span.bitmap_at + bitmap_len as usize, 0);
                read_exact_at(&file, &mut meta[span.bitmap_at..], pos + 16).map_err(io)?;
                let chunks = span.chunks();
                if !chunks.is_multiple_of(8) && meta[meta.len() - 1] >> (chunks % 8) != 0 {
                    return Err(bad("bitmap marks chunks past the image"));
                }
                span.len = (0..chunks)
                    .filter(|&i| span.stored(&meta, i))
                    .map(|i| span.chunk_len(i))
                    .sum();
                if 16 + bitmap_len + span.len != len {
                    return Err(bad("length does not match its bitmap"));
                }
                span.meta_at = meta.len();
                ram = Some(span);
            } else {
                let at = meta.len();
                meta.resize(at + len as usize, 0);
                read_exact_at(&file, &mut meta[at..], pos).map_err(io)?;
            }
            pos += len;
        }
        Ok(SnapshotReader {
            path: path.to_string(),
            _file: file,
            meta,
            ram,
            trailer: u32::from_le_bytes(trailer),
            pos: 0,
            header_read: false,
        })
    }

    pub fn read_header(&mut self) -> Result<String> {
        let buf = &self.meta;
        if buf[0..8] != MAGIC {
            return Err(Error::msg("snapshot: bad magic"));
        }
        let ver = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        if ver != VERSION {
            return Err(Error::msg(format!("snapshot: version {ver} != {VERSION}")));
        }
        // `open` read exactly the declared JSON after the fixed header.
        let jsz = u64::from_le_bytes(buf[16..24].try_into().unwrap()) as usize;
        let json = std::str::from_utf8(&buf[24..24 + jsz])
            .map_err(|_| Error::msg("snapshot: header JSON not UTF-8"))?
            .to_string();
        self.pos = 24 + jsz;
        self.header_read = true;
        Ok(json)
    }

    /// Returns the next section, or None at the trailer. The RAM section comes
    /// back with an empty payload: [`Self::load_ram_and_verify`] reads it.
    pub fn next_section(&mut self) -> Result<Option<SectionRef<'_>>> {
        let buf = &self.meta;
        if self.pos == buf.len() {
            return Ok(None);
        }
        if buf.len() - self.pos < 16 {
            return Err(Error::msg("snapshot: truncated section header"));
        }
        let ty_raw = u32::from_le_bytes(buf[self.pos..self.pos + 4].try_into().unwrap());
        let reserved = u32::from_le_bytes(buf[self.pos + 4..self.pos + 8].try_into().unwrap());
        if reserved != 0 {
            return Err(Error::msg("snapshot: section reserved != 0"));
        }
        let len = u64::from_le_bytes(buf[self.pos + 8..self.pos + 16].try_into().unwrap()) as usize;
        let ty = SectionType::from_u32(ty_raw)
            .ok_or_else(|| Error::msg(format!("snapshot: unknown section type {ty_raw:#x}")))?;
        let body = self.pos + 16;
        if let Some(r) = self.ram.filter(|r| r.body_at == body) {
            self.pos = r.meta_at;
            return Ok(Some(SectionRef { ty, payload: &[] }));
        }
        // `open` read every other payload in full.
        self.pos = body + len;
        Ok(Some(SectionRef {
            ty,
            payload: &buf[body..body + len],
        }))
    }

    /// Read the RAM section into guest RAM (laid out as `GuestMemory::load_image`
    /// takes it), on several threads with a handle each, then verify the CRC of
    /// the whole file. Until this returns Ok, nothing parsed from the file may
    /// be applied to the machine. Chunks the file leaves out are not written:
    /// `ram` must still be the zero-filled allocation.
    pub fn load_ram_and_verify(&self, ram: &crate::whp::GuestMemory) -> Result<()> {
        let io = |e: std::io::Error| Error::msg(format!("snapshot: read {}: {e}", self.path));
        let crc = match self.ram {
            None => crc32(&self.meta),
            Some(span) => {
                // CRC of the stored chunks, in file order: first those that
                // land in guest RAM, then any past its end.
                let (mut ram_crc, mut done) = (0u32, 0u64);
                let n = (span.image_len as usize).min(ram.size());
                for c in self.fill_ram(ram, span, n) {
                    let (c, len) = c.map_err(io)?;
                    ram_crc = crc32_combine(ram_crc, c, len);
                    done += len;
                }
                // A payload longer than this RAM (an allocation aligned
                // differently at save time) is still part of the checksum.
                let mut scratch = Vec::new();
                while done < span.len {
                    scratch.resize(((span.len - done) as usize).min(16 << 20), 0);
                    read_exact_at(&self._file, &mut scratch, span.file_off + done).map_err(io)?;
                    ram_crc = crc32_combine(ram_crc, crc32(&scratch), scratch.len() as u64);
                    done += scratch.len() as u64;
                }
                let (before, after) = self.meta.split_at(span.meta_at);
                let crc = crc32_combine(crc32(before), ram_crc, span.len);
                crc32_combine(crc, crc32(after), after.len() as u64)
            }
        };
        if crc != self.trailer {
            return Err(Error::msg(format!(
                "snapshot: CRC mismatch (file {:#010x} != computed {crc:#010x})",
                self.trailer
            )));
        }
        Ok(())
    }

    /// Read the stored chunks for the first `n` bytes of the image into guest
    /// RAM, in parallel slices. Returns each slice's (CRC, bytes read), in
    /// image order, which is also the order the chunks sit in the file.
    fn fill_ram(
        &self,
        ram: &crate::whp::GuestMemory,
        span: RamSpan,
        n: usize,
    ) -> Vec<std::io::Result<(u32, u64)>> {
        // Checksum each piece right after reading it, while it's still in
        // cache.
        const PIECE: usize = 1 << 20;
        let read = |f: &File, dst: &mut [u8], file_off: u64, reg: &mut u32| {
            for (i, piece) in dst.chunks_mut(PIECE).enumerate() {
                read_exact_at(f, piece, file_off + (i * PIECE) as u64)?;
                *reg = crc32_update(*reg, piece);
            }
            Ok::<_, std::io::Error>(())
        };
        // Where each chunk's bytes start among the stored bytes (for the
        // chunks that land in guest RAM; the rest are read as the tail).
        let needed = n.div_ceil(span.chunk);
        let mut at = Vec::with_capacity(needed);
        let mut sum = 0u64;
        for i in 0..needed {
            at.push(sum);
            if span.stored(&self.meta, i) {
                sum += span.chunk_len(i);
            }
        }
        ram.fill_image(n, |off, slice| {
            // `fill_image` slices start on chunk boundaries (chunks are powers
            // of two of at most its slice size); only the image's end can cut
            // a chunk short.
            let f = open_no_writers(&self.path)?;
            let mut reg = 0xFFFF_FFFFu32;
            let mut got = 0u64;
            let end = off + slice.len();
            let mut i = off / span.chunk;
            while i * span.chunk < end {
                if !span.stored(&self.meta, i) {
                    i += 1;
                    continue;
                }
                let first = i;
                while i * span.chunk < end && span.stored(&self.meta, i) {
                    i += 1;
                }
                let run = first * span.chunk - off..(i * span.chunk).min(end) - off;
                got += run.len() as u64;
                read(&f, &mut slice[run], span.file_off + at[first], &mut reg)?;
            }
            Ok((reg ^ 0xFFFF_FFFF, got))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `write_ram_sparse`'s reader for an image held in a slice.
    fn from_slice(image: &[u8]) -> impl Fn(usize, &mut [u8]) + Sync + '_ {
        move |off, dst| dst.copy_from_slice(&image[off..off + dst.len()])
    }

    /// The carry-less-multiply CRCs must match the byte table for every length
    /// (the fold paths change at 128-, 64- and 16-byte steps) and alignment, and
    /// the IEEE check value. Each kernel the CPU supports is tried directly, as
    /// the dispatch picks only one per length.
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
        #[cfg(target_arch = "x86_64")]
        let (pclmul, vpclmul) = {
            use std::arch::is_x86_feature_detected as has;
            let pclmul = has!("pclmulqdq") && has!("sse4.1");
            (pclmul, pclmul && has!("avx2") && has!("vpclmulqdq"))
        };
        for align in 0..16 {
            for len in (0..300).chain([1000, 4095, 4096]) {
                let d = &buf[align..align + len];
                for init in [0xFFFF_FFFFu32, 0x1234_5678] {
                    let want = crc32_table(init, d);
                    assert_eq!(crc32_update(init, d), want, "len {len} align {align}");
                    #[cfg(target_arch = "x86_64")]
                    if pclmul && len >= 64 {
                        // SAFETY: the CPU supports the features (checked above).
                        assert_eq!(unsafe { crc32_pclmul(init, d) }, want, "len {len}");
                    }
                    #[cfg(target_arch = "x86_64")]
                    if vpclmul && len >= 128 {
                        // SAFETY: the CPU supports the features (checked above).
                        assert_eq!(unsafe { crc32_vpclmul(init, d) }, want, "len {len}");
                    }
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
    /// restore can verify the RAM image chunk by chunk on several threads.
    #[test]
    fn crc32_combines_chunks() {
        let data: Vec<u8> = (0..(3u32 << 20) + 12_345)
            .map(|i| (i ^ (i >> 9)) as u8)
            .collect();
        let whole = crc32(&data);
        for cut in [0usize, 1, 4096, 1_000_001, data.len()] {
            let (a, b) = data.split_at(cut);
            assert_eq!(
                crc32_combine(crc32(a), crc32(b), b.len() as u64),
                whole,
                "cut {cut}"
            );
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
            w.write_ram_sparse(5, from_slice(&[1u8, 2, 3, 4, 5]))
                .unwrap();
            w.write_section(SectionType::VcpuRegs, &[0xABu8; 100])
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
        assert_eq!(s0.ty, SectionType::RamSparse);
        assert!(s0.payload.is_empty(), "RAM is read by load_ram_and_verify");
        let s1 = r.next_section().unwrap().unwrap();
        assert_eq!(s1.ty, SectionType::VcpuRegs);
        assert_eq!(s1.payload.len(), 100);
        assert!(r.next_section().unwrap().is_none());
        let ram = crate::whp::GuestMemory::new_host_only(4096).unwrap();
        r.load_ram_and_verify(&ram).unwrap();
        let mut got = [0u8; 5];
        assert!(ram.read_into(0, &mut got));
        assert_eq!(got, [1, 2, 3, 4, 5]);
        drop(r);

        // A flipped bit anywhere, the RAM image included, fails verification:
        // here in the JSON header and in the RAM payload, which ends where the
        // 116-byte VcpuRegs section and the 4-byte trailer begin.
        let mut bytes = std::fs::read(p).unwrap();
        for at in [30usize, bytes.len() - 4 - 116 - 2] {
            bytes[at] ^= 1;
            std::fs::write(p, &bytes).unwrap();
            let mut r = SnapshotReader::open(p).unwrap();
            let _ = r.read_header();
            while let Ok(Some(_)) = r.next_section() {}
            assert!(r.load_ram_and_verify(&ram).is_err(), "flip at {at}");
            bytes[at] ^= 1;
        }
        let _ = std::fs::remove_file(p);
    }

    /// RAM goes out sparse: all-zero chunks are left out of the file and the
    /// rest come back in place, into RAM the image's size, larger (the rest
    /// stays zero) or smaller (ending inside a stored chunk, whose remainder
    /// is still checksummed). Moving a stored chunk in the bitmap or flipping
    /// a stored bit fails the load.
    #[test]
    fn sparse_ram_roundtrip() {
        const C: usize = SPARSE_CHUNK;
        let mut image = vec![0u8; 5 * C + 1000];
        image[C + 7] = 1;
        for (i, b) in image[3 * C..5 * C].iter_mut().enumerate() {
            *b = (i % 251) as u8 + 1;
        }
        image[5 * C + 999] = 9;
        let stored = 3 * C + 1000;
        let path = std::env::temp_dir().join("tv_snap_sparse_test.bin");
        let p = path.to_str().unwrap();
        {
            let mut w = SnapshotWriter::create(p).unwrap();
            w.write_header("{}").unwrap();
            w.write_section(SectionType::VcpuRegs, &[7u8; 10]).unwrap();
            assert_eq!(
                w.write_ram_sparse(image.len(), from_slice(&image)).unwrap(),
                stored as u64
            );
            w.finalize().unwrap();
        }
        let file_len = std::fs::metadata(p).unwrap().len() as usize;
        assert_eq!(file_len, 24 + 2 + 26 + 16 + 16 + 1 + stored + 4);
        let load = |ram_size: usize| -> Result<Vec<u8>> {
            let mut r = SnapshotReader::open(p)?;
            r.read_header()?;
            let s = r.next_section()?.unwrap();
            assert_eq!((s.ty, s.payload.len()), (SectionType::VcpuRegs, 10));
            let s = r.next_section()?.unwrap();
            assert_eq!((s.ty, s.payload.len()), (SectionType::RamSparse, 0));
            assert!(r.next_section()?.is_none());
            let ram = crate::whp::GuestMemory::new_host_only(ram_size).unwrap();
            r.load_ram_and_verify(&ram)?;
            let mut got = vec![0u8; ram_size];
            assert!(ram.read_into(0, &mut got));
            Ok(got)
        };
        for size in [image.len(), image.len() + 3 * C, 3 * C + 4096] {
            let got = load(size).unwrap();
            let n = size.min(image.len());
            assert!(got[..n] == image[..n], "ram size {size}");
            assert!(got[n..].iter().all(|&b| b == 0), "ram size {size}");
        }
        // The one-byte bitmap sits right before the stored chunks.
        let bitmap = file_len - 4 - stored - 1;
        let mut bytes = std::fs::read(p).unwrap();
        for (at, flip) in [(bitmap, 0b11u8), (bitmap, 0b100), (file_len - 4 - 500, 1)] {
            bytes[at] ^= flip;
            std::fs::write(p, &bytes).unwrap();
            assert!(load(image.len()).is_err(), "flip {flip:#b} at {at}");
            bytes[at] ^= flip;
        }
        let _ = std::fs::remove_file(p);
    }
}
