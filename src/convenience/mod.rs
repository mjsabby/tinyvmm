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

use crate::error::Result;

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
    /// Read `entry`'s kernel and initrds with `read`.
    pub fn load(
        entry: grub_cfg::BootEntry,
        read: impl Fn(&str) -> Result<Vec<u8>>,
    ) -> Result<LoadedEntry> {
        let kernel = read(&entry.kernel)?;
        let mut initrd: Option<Vec<u8>> = None;
        for path in &entry.initrds {
            let buf = initrd.get_or_insert_with(Vec::new);
            buf.extend_from_slice(&read(path)?);
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
