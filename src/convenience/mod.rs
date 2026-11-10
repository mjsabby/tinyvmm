//! Conveniences layered on the VMM. Nothing here is needed to run a VM; these
//! turn inputs that would otherwise need preparation by hand (such as a
//! distribution's ISO, or the Linux installed on a disk) into what the boot
//! path takes.

pub mod disk_boot;
pub mod ext4;
pub mod grub_cfg;
pub mod iso9660;
pub mod iso_boot;
pub mod partition;

use crate::error::{Error, Result};

/// The largest kernel read for a boot entry, and the most its initrds hold
/// together: the bzImage loader puts initrds below 2 GiB (the boot protocol's
/// `initrd_addr_max`), so a larger total could not boot.
const MAX_KERNEL_BYTES: u64 = 1 << 30;
const MAX_INITRD_BYTES: u64 = 2 << 30;

/// Positioned reads from an image.
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

/// `len` bytes of an image from `start`, such as a partition of a disk, read
/// as an image of their own.
pub struct Region<'a, R: ReadAt> {
    src: &'a R,
    start: u64,
    len: u64,
}

impl<'a, R: ReadAt> Region<'a, R> {
    pub fn new(src: &'a R, start: u64, len: u64) -> Self {
        Region { src, start, len }
    }
}

impl<R: ReadAt> ReadAt for Region<'_, R> {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        let at = offset
            .checked_add(buf.len() as u64)
            .filter(|&end| end <= self.len)
            .and_then(|_| self.start.checked_add(offset))
            .ok_or(std::io::ErrorKind::UnexpectedEof)?;
        self.src.read_exact_at(at, buf)
    }
}

/// A boot entry's kernel and initrds, read into memory.
pub struct LoadedEntry {
    pub title: String,
    pub kernel_path: String,
    pub kernel: Vec<u8>,
    pub initrd_paths: Vec<String>,
    /// The initrds back to back, each padded to 4 bytes as GRUB loads them;
    /// `None` if the entry has none.
    pub initrd: Option<Vec<u8>>,
    pub args: String,
}

impl LoadedEntry {
    /// Read `entry`'s kernel and initrds with `read`, which takes a path and
    /// the most bytes the file may hold, and fails on a larger file before
    /// reading it. The image sizes the files, and a guest may have written
    /// the image: an entry naming one sparse gigabyte many times over must
    /// not have us allocate them all.
    pub fn load(
        entry: grub_cfg::BootEntry,
        read: impl Fn(&str, u64) -> Result<Vec<u8>>,
    ) -> Result<LoadedEntry> {
        if entry.initrds.len() > grub_cfg::MAX_INITRDS {
            return Err(Error::msg(format!(
                "a boot entry with {} initrds is too large (at most {})",
                entry.initrds.len(),
                grub_cfg::MAX_INITRDS
            )));
        }
        let kernel = read(&entry.kernel, MAX_KERNEL_BYTES)?;
        let mut initrd: Option<Vec<u8>> = None;
        for path in &entry.initrds {
            let buf = initrd.get_or_insert_with(Vec::new);
            // What the initrds before this one left of their total.
            let room = MAX_INITRD_BYTES.saturating_sub(buf.len() as u64);
            let mut bytes = read(path, room)?;
            // Sized exactly, as the Vec's usual doubling would commit up to
            // twice the total; the usual single initrd isn't copied at all.
            let padded = bytes.len().next_multiple_of(4);
            if buf.is_empty() {
                bytes.reserve_exact(padded - bytes.len());
                *buf = bytes;
            } else {
                buf.reserve_exact(padded);
                buf.extend_from_slice(&bytes);
            }
            buf.resize(buf.len().next_multiple_of(4), 0);
        }
        Ok(LoadedEntry {
            title: entry.title,
            kernel_path: entry.kernel,
            kernel,
            initrd_paths: entry.initrds,
            initrd,
            args: entry.args,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn entry(initrds: &[&str]) -> grub_cfg::BootEntry {
        grub_cfg::BootEntry {
            title: "t".into(),
            kernel: "/k".into(),
            initrds: initrds.iter().map(|path| path.to_string()).collect(),
            args: String::new(),
        }
    }

    #[test]
    fn each_initrd_may_hold_what_those_before_it_left_of_their_total() {
        // What the reader is asked for: each path, and the most it may hold.
        let asked = RefCell::new(Vec::new());
        let read = |path: &str, max: u64| {
            asked.borrow_mut().push((path.to_string(), max));
            match path {
                "/k" => Ok(b"kernel".to_vec()),
                "/a" => Ok(vec![1; 5]),
                "/b" => Ok(vec![2; 6]),
                // As a reader does for a file over `max`.
                _ => Err(Error::msg(format!("{path} is too large"))),
            }
        };
        let loaded = LoadedEntry::load(entry(&["/a", "/b", "/b"]), read).unwrap();
        assert_eq!(loaded.kernel, b"kernel");
        // Each padded to 4 bytes, as GRUB loads them.
        let (a, b) = ([1, 1, 1, 1, 1, 0, 0, 0], [2, 2, 2, 2, 2, 2, 0, 0]);
        assert_eq!(loaded.initrd, Some([a, b, b].concat()));
        let asked_for = |path: &str, max| (path.to_string(), max);
        assert_eq!(
            asked.take(),
            [
                asked_for("/k", MAX_KERNEL_BYTES),
                asked_for("/a", MAX_INITRD_BYTES),
                asked_for("/b", MAX_INITRD_BYTES - 8),
                asked_for("/b", MAX_INITRD_BYTES - 16),
            ]
        );

        // A file the reader refuses ends the load: nothing after it is read.
        let error = LoadedEntry::load(entry(&["/a", "/big", "/b"]), read).err();
        assert_eq!(error.unwrap().to_string(), "/big is too large");
        assert_eq!(asked.take().len(), 3);

        // More initrds than an entry may name aren't read at all.
        let many = vec!["/a"; grub_cfg::MAX_INITRDS + 1];
        let error = LoadedEntry::load(entry(&many), read).err().unwrap();
        assert!(error.to_string().contains("9 initrds"), "{error}");
        assert!(asked.take().is_empty());
        assert!(LoadedEntry::load(entry(&many[1..]), read).is_ok());
        assert!(
            LoadedEntry::load(entry(&[]), read)
                .unwrap()
                .initrd
                .is_none()
        );
    }
}
