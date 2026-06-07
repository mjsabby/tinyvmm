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
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            *slot = c;
        }
        t
    })
}

pub fn crc32_update(crc: u32, data: &[u8]) -> u32 {
    let tbl = crc_table();
    let mut c = crc;
    for &b in data {
        c = tbl[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    c
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
        let f = File::create(path)
            .map_err(|e| Error::msg(format!("snapshot: create {path}: {e}")))?;
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
pub struct SnapshotReader {
    buf: Vec<u8>,
    pos: usize,
    header_read: bool,
}

pub struct SectionRef<'a> {
    pub ty: SectionType,
    pub payload: &'a [u8],
}

impl SnapshotReader {
    pub fn open(path: &str) -> Result<SnapshotReader> {
        let buf =
            std::fs::read(path).map_err(|e| Error::msg(format!("snapshot: read {path}: {e}")))?;
        if buf.len() < 24 + 4 {
            return Err(Error::msg("snapshot: file too small"));
        }
        Ok(SnapshotReader {
            buf,
            pos: 0,
            header_read: false,
        })
    }

    pub fn read_header(&mut self) -> Result<String> {
        if self.buf[0..8] != MAGIC {
            return Err(Error::msg("snapshot: bad magic"));
        }
        let ver = u32::from_le_bytes(self.buf[8..12].try_into().unwrap());
        if ver != VERSION {
            return Err(Error::msg(format!(
                "snapshot: version {ver} != {VERSION}"
            )));
        }
        let jsz = u64::from_le_bytes(self.buf[16..24].try_into().unwrap()) as usize;
        if jsz > self.buf.len().saturating_sub(24 + 4) {
            return Err(Error::msg("snapshot: header_json_size out of range"));
        }
        let json = std::str::from_utf8(&self.buf[24..24 + jsz])
            .map_err(|_| Error::msg("snapshot: header JSON not UTF-8"))?
            .to_string();
        self.pos = 24 + jsz;
        self.header_read = true;
        Ok(json)
    }

    /// Returns the next section, or None when only the 4-byte trailer remains.
    pub fn next_section(&mut self) -> Result<Option<SectionRef<'_>>> {
        let end = self.buf.len() - 4; // trailer
        if self.pos == end {
            return Ok(None);
        }
        if self.pos + 16 > end {
            return Err(Error::msg("snapshot: truncated section header"));
        }
        let ty_raw = u32::from_le_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        let reserved = u32::from_le_bytes(self.buf[self.pos + 4..self.pos + 8].try_into().unwrap());
        if reserved != 0 {
            return Err(Error::msg("snapshot: section reserved != 0"));
        }
        let len = u64::from_le_bytes(self.buf[self.pos + 8..self.pos + 16].try_into().unwrap())
            as usize;
        let body = self.pos + 16;
        if body + len > end {
            return Err(Error::msg("snapshot: section length out of range"));
        }
        let ty = SectionType::from_u32(ty_raw)
            .ok_or_else(|| Error::msg(format!("snapshot: unknown section type {ty_raw:#x}")))?;
        self.pos = body + len;
        Ok(Some(SectionRef {
            ty,
            payload: &self.buf[body..body + len],
        }))
    }

    pub fn verify_trailer(&self) -> Result<()> {
        let n = self.buf.len();
        let saved = u32::from_le_bytes(self.buf[n - 4..n].try_into().unwrap());
        let crc = crc32_update(0xFFFF_FFFF, &self.buf[..n - 4]) ^ 0xFFFF_FFFF;
        if crc != saved {
            return Err(Error::msg(format!(
                "snapshot: CRC mismatch (file {saved:#010x} != computed {crc:#010x})"
            )));
        }
        Ok(())
    }

    pub fn file_size(&self) -> u64 {
        self.buf.len() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            w.write_section(SectionType::RamRaw, &[1u8, 2, 3, 4, 5]).unwrap();
            w.write_section(SectionType::VcpuRegs, &vec![0xABu8; 100]).unwrap();
            w.finalize().unwrap();
        }
        let mut r = SnapshotReader::open(p).unwrap();
        let jr_str = r.read_header().unwrap();
        let jr = JsonReader::parse(&jr_str).unwrap();
        assert_eq!(jr.get_u64("ram").unwrap(), 268435456);
        assert_eq!(jr.get_u64("vcpus").unwrap(), 4);
        assert!(!jr.get_bool("net").unwrap());
        assert_eq!(jr.get_str("drive").unwrap(), r#"C:\path,with"comma\and quote"#);
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
