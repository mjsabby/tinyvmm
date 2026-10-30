//! Read-only ISO 9660 reader with just enough to fetch a file by path, using
//! Rock Ridge names when the image has them. Every field read from the image
//! is bounds-checked; a malformed image yields an error, not a panic.

use crate::error::{Error, Result};

const SECTOR: u64 = 2048;
const FIRST_DESCRIPTOR: u64 = 16;
const MAX_DESCRIPTORS: u64 = 64;
const PRIMARY: u8 = 1;
const TERMINATOR: u8 = 255;
const ROOT_RECORD: usize = 156;
/// Directory record: fixed part before the name.
const RECORD_FIXED: usize = 33;
const FLAG_DIRECTORY: u8 = 1 << 1;
const FLAG_MULTI_EXTENT: u8 = 1 << 7;
/// Caps on what a crafted image can make us allocate.
const MAX_DIR_BYTES: u32 = 16 << 20;
const MAX_FILE_BYTES: u32 = 1 << 30;
const MAX_DEPTH: usize = 32;

/// Positioned reads from the image.
pub trait ReadAt {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()>;
}

impl ReadAt for std::fs::File {
    fn read_exact_at(&self, mut offset: u64, mut buf: &mut [u8]) -> std::io::Result<()> {
        use std::os::windows::fs::FileExt;
        while !buf.is_empty() {
            match self.seek_read(buf, offset)? {
                0 => return Err(std::io::ErrorKind::UnexpectedEof.into()),
                n => {
                    offset += n as u64;
                    buf = &mut buf[n..];
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
impl ReadAt for Vec<u8> {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        let src = usize::try_from(offset)
            .ok()
            .and_then(|start| self.get(start..start.checked_add(buf.len())?))
            .ok_or(std::io::ErrorKind::UnexpectedEof)?;
        buf.copy_from_slice(src);
        Ok(())
    }
}

/// A file or directory: its extent on the image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub lba: u32,
    pub size: u32,
    pub dir: bool,
}

struct Record {
    entry: Entry,
    multi_extent: bool,
    /// The ISO 9660 identifier without its `;version` and a trailing '.'.
    iso_name: String,
    /// The Rock Ridge (`NM`) name, if any.
    rr_name: Option<String>,
}

impl Record {
    fn loosely_named(&self, name: &str) -> bool {
        self.rr_name
            .as_deref()
            .is_some_and(|rr| rr.eq_ignore_ascii_case(name))
            || self.iso_name.eq_ignore_ascii_case(name)
    }
}

pub struct Iso9660<R: ReadAt> {
    src: R,
    root: Entry,
}

impl Iso9660<std::fs::File> {
    pub fn open(path: &str) -> Result<Self> {
        let file =
            std::fs::File::open(path).map_err(|e| Error::msg(format!("open ISO {path}: {e}")))?;
        Self::new(file).map_err(|e| Error::msg(format!("{path}: {e}")))
    }
}

impl<R: ReadAt> Iso9660<R> {
    /// Find the primary volume descriptor and its root directory.
    pub fn new(src: R) -> Result<Self> {
        let mut desc = vec![0u8; SECTOR as usize];
        for i in 0..MAX_DESCRIPTORS {
            read(&src, (FIRST_DESCRIPTOR + i) * SECTOR, &mut desc)?;
            if &desc[1..6] != b"CD001" {
                return Err(Error::msg("not an ISO 9660 image"));
            }
            match desc[0] {
                PRIMARY => {
                    let block = u16::from_le_bytes([desc[128], desc[129]]);
                    if u64::from(block) != SECTOR {
                        return Err(Error::msg(format!(
                            "ISO 9660: unsupported {block}-byte logical blocks"
                        )));
                    }
                    let root = parse_record(&desc[ROOT_RECORD..])
                        .filter(|r| r.entry.dir)
                        .ok_or_else(|| Error::msg("ISO 9660: bad root directory record"))?;
                    return Ok(Iso9660 {
                        src,
                        root: root.entry,
                    });
                }
                TERMINATOR => break,
                _ => {}
            }
        }
        Err(Error::msg("ISO 9660: no primary volume descriptor"))
    }

    /// Look up a `/`-separated path. Each component matches a Rock Ridge name
    /// exactly, or else a Rock Ridge or ISO 9660 name ignoring ASCII case.
    pub fn lookup(&self, path: &str) -> Result<Option<Entry>> {
        let mut cur = self.root;
        for (depth, part) in path.split('/').filter(|p| !p.is_empty()).enumerate() {
            if !cur.dir || depth >= MAX_DEPTH {
                return Ok(None);
            }
            let records = self.read_dir(cur)?;
            let found = records
                .iter()
                .find(|r| r.rr_name.as_deref() == Some(part))
                .or_else(|| records.iter().find(|r| r.loosely_named(part)));
            match found {
                Some(r) if r.multi_extent => {
                    return Err(Error::msg(format!(
                        "ISO 9660: {path} spans several extents (unsupported)"
                    )));
                }
                Some(r) => cur = r.entry,
                None => return Ok(None),
            }
        }
        Ok(Some(cur))
    }

    /// Read a whole file.
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let entry = self
            .lookup(path)?
            .filter(|e| !e.dir)
            .ok_or_else(|| Error::msg(format!("ISO 9660: no file {path}")))?;
        if entry.size > MAX_FILE_BYTES {
            return Err(Error::msg(format!("ISO 9660: {path} is too large")));
        }
        let mut buf = vec![0u8; entry.size as usize];
        read(&self.src, u64::from(entry.lba) * SECTOR, &mut buf)?;
        Ok(buf)
    }

    fn read_dir(&self, dir: Entry) -> Result<Vec<Record>> {
        if dir.size > MAX_DIR_BYTES {
            return Err(Error::msg("ISO 9660: directory too large"));
        }
        let mut buf = vec![0u8; dir.size as usize];
        read(&self.src, u64::from(dir.lba) * SECTOR, &mut buf)?;
        let mut records = Vec::new();
        let mut off = 0usize;
        while off < buf.len() {
            let len = buf[off] as usize;
            if len == 0 {
                // Records never straddle sectors; the rest of this one is padding.
                off = (off / SECTOR as usize + 1) * SECTOR as usize;
                continue;
            }
            let Some(raw) = buf.get(off..off + len) else {
                break;
            };
            off += len;
            if !is_dot_entry(raw)
                && let Some(r) = parse_record(raw)
            {
                records.push(r);
            }
        }
        Ok(records)
    }
}

fn read<R: ReadAt>(src: &R, offset: u64, buf: &mut [u8]) -> Result<()> {
    src.read_exact_at(offset, buf)
        .map_err(|e| Error::msg(format!("ISO 9660: read at 0x{offset:x}: {e}")))
}

/// Whether a directory record is the `.` or `..` entry (identifier 0x00 or
/// 0x01).
fn is_dot_entry(raw: &[u8]) -> bool {
    raw.get(32) == Some(&1) && matches!(raw.get(RECORD_FIXED), Some(0 | 1))
}

/// Parse one directory record; `None` if it is malformed.
fn parse_record(raw: &[u8]) -> Option<Record> {
    let len = *raw.first()? as usize;
    let rec = raw.get(..len)?;
    let name_len = *rec.get(32)? as usize;
    let name = rec.get(RECORD_FIXED..RECORD_FIXED + name_len)?;
    if name.is_empty() {
        return None;
    }
    let lba = u32::from_le_bytes(rec.get(2..6)?.try_into().ok()?);
    let size = u32::from_le_bytes(rec.get(10..14)?.try_into().ok()?);
    let flags = *rec.get(25)?;
    // The System Use area starts after the name, padded to an even offset.
    let su_start = RECORD_FIXED + name_len + (1 - name_len % 2);
    let rr_name = rec.get(su_start..).and_then(rock_ridge_name);
    let iso_name = String::from_utf8_lossy(name);
    let iso_name = iso_name.split(';').next().unwrap_or_default();
    Some(Record {
        entry: Entry {
            lba,
            size,
            dir: flags & FLAG_DIRECTORY != 0,
        },
        multi_extent: flags & FLAG_MULTI_EXTENT != 0,
        iso_name: iso_name.strip_suffix('.').unwrap_or(iso_name).to_string(),
        rr_name,
    })
}

/// The Rock Ridge alternate name from a record's System Use entries: the
/// concatenated `NM` components, skipping the "." and ".." markers.
fn rock_ridge_name(su: &[u8]) -> Option<String> {
    const NM_CURRENT: u8 = 1 << 1;
    const NM_PARENT: u8 = 1 << 2;
    let mut name = Vec::new();
    let mut pos = 0usize;
    while let Some(head) = su.get(pos..pos + 4) {
        let len = head[2] as usize;
        let Some(body) = su.get(pos + 4..pos + len.max(4)) else {
            break;
        };
        match &head[..2] {
            b"NM" if !body.is_empty() && body[0] & (NM_CURRENT | NM_PARENT) == 0 => {
                name.extend_from_slice(&body[1..]);
            }
            b"ST" => break,
            _ => {}
        }
        if len < 4 {
            break;
        }
        pos += len;
    }
    (!name.is_empty()).then(|| String::from_utf8_lossy(&name).into_owned())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A directory tree for [`build`].
    pub(crate) enum Node<'a> {
        Dir(&'a str, Vec<Node<'a>>),
        File(&'a str, &'a [u8]),
    }

    /// Build a small ISO 9660 image whose root holds `nodes`. Names are stored
    /// as Rock Ridge names (split over two `NM` entries) and upper-cased as ISO
    /// 9660 names, with a file's '.' turned into '_' ("grub.cfg" is stored as
    /// "GRUB_CFG.;1").
    pub(crate) fn build(nodes: Vec<Node>) -> Vec<u8> {
        let mut sectors = vec![vec![0u8; SECTOR as usize]; FIRST_DESCRIPTOR as usize + 2];
        let root_lba = dir(&mut sectors, &nodes);
        let pvd = &mut sectors[FIRST_DESCRIPTOR as usize];
        pvd[0] = PRIMARY;
        pvd[1..6].copy_from_slice(b"CD001");
        pvd[128..130].copy_from_slice(&(SECTOR as u16).to_le_bytes());
        let root = record(&[0], None, root_lba, SECTOR as u32, true);
        pvd[ROOT_RECORD..ROOT_RECORD + root.len()].copy_from_slice(&root);
        let term = &mut sectors[FIRST_DESCRIPTOR as usize + 1];
        term[0] = TERMINATOR;
        term[1..6].copy_from_slice(b"CD001");
        sectors.concat()
    }

    fn record(iso_name: &[u8], rr: Option<&str>, lba: u32, size: u32, dir: bool) -> Vec<u8> {
        let mut r = vec![0u8; RECORD_FIXED];
        r[2..6].copy_from_slice(&lba.to_le_bytes());
        r[10..14].copy_from_slice(&size.to_le_bytes());
        r[25] = if dir { FLAG_DIRECTORY } else { 0 };
        r[32] = iso_name.len() as u8;
        r.extend_from_slice(iso_name);
        if iso_name.len().is_multiple_of(2) {
            r.push(0);
        }
        if let Some(rr) = rr {
            let (a, b) = rr.split_at(rr.len() / 2);
            for (part, flags) in [(a, 1u8), (b, 0u8)] {
                r.extend_from_slice(b"NM");
                r.extend_from_slice(&[5 + part.len() as u8, 1, flags]);
                r.extend_from_slice(part.as_bytes());
            }
        }
        r[0] = r.len() as u8;
        r
    }

    fn alloc(sectors: &mut Vec<Vec<u8>>, data: &[u8]) -> u32 {
        let lba = sectors.len() as u32;
        for chunk in data.chunks(SECTOR as usize) {
            let mut s = chunk.to_vec();
            s.resize(SECTOR as usize, 0);
            sectors.push(s);
        }
        if data.is_empty() {
            sectors.push(vec![0u8; SECTOR as usize]);
        }
        lba
    }

    fn dir(sectors: &mut Vec<Vec<u8>>, nodes: &[Node]) -> u32 {
        let mut body = record(&[0], None, 0, SECTOR as u32, true);
        body.extend(record(&[1], None, 0, SECTOR as u32, true));
        for node in nodes {
            body.extend(match node {
                Node::Dir(name, children) => {
                    let lba = dir(sectors, children);
                    let iso = name.to_ascii_uppercase();
                    record(iso.as_bytes(), Some(name), lba, SECTOR as u32, true)
                }
                Node::File(name, data) => {
                    let lba = alloc(sectors, data);
                    let iso = format!("{}.;1", name.to_ascii_uppercase().replace('.', "_"));
                    record(iso.as_bytes(), Some(name), lba, data.len() as u32, false)
                }
            });
        }
        assert!(body.len() <= SECTOR as usize);
        alloc(sectors, &body)
    }

    #[test]
    fn finds_files_by_rock_ridge_and_iso_names() {
        let image = build(vec![
            Node::Dir("casper", vec![Node::File("vmlinuz", b"kernel bytes")]),
            Node::Dir(
                "boot",
                vec![Node::Dir("grub", vec![Node::File("grub.cfg", b"cfg")])],
            ),
        ]);
        let iso = Iso9660::new(image).unwrap();
        assert_eq!(iso.read_file("/casper/vmlinuz").unwrap(), b"kernel bytes");
        assert_eq!(iso.read_file("boot/grub/grub.cfg").unwrap(), b"cfg");
        // The ISO 9660 names, ignoring case.
        assert_eq!(iso.read_file("BOOT/GRUB/grub_cfg").unwrap(), b"cfg");
        assert!(iso.lookup("casper/initrd").unwrap().is_none());
        assert!(iso.lookup("casper/vmlinuz/x").unwrap().is_none());
        assert!(iso.lookup("casper").unwrap().unwrap().dir);
        assert!(iso.read_file("casper").is_err());
    }

    #[test]
    fn rejects_non_iso_and_truncated_images() {
        assert!(Iso9660::new(vec![0u8; 64 * 1024]).is_err());
        let image = build(vec![Node::File("a", b"x")]);
        assert!(Iso9660::new(image[..10 * SECTOR as usize].to_vec()).is_err());
        // The root directory (sector 19) lies past this truncated image:
        // looking inside it is an error, not a panic.
        let iso = Iso9660::new(image[..19 * SECTOR as usize].to_vec()).unwrap();
        assert!(iso.read_file("a").is_err());
    }
}
