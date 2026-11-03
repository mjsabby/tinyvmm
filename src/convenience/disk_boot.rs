//! Booting the Linux installed on a `--drive`, given no kernel and no `--iso`.
//! The kernel, initrd(s) and kernel arguments come from the default entry of
//! the installation's GRUB configuration, read from its ext2/3/4 filesystem
//! before the VM starts. A kernel the guest installs (whose package rewrites
//! `grub.cfg`) is thus what boots next time, as with GRUB itself.

use crate::convenience::ext4::{Ext4, Kind};
use crate::convenience::{LoadedEntry, ReadAt, Region, grub_cfg, partition};
use crate::error::{Error, Result};
use winsys::host::vhdx::ReadOnlyDisk;

/// Where an installation keeps its GRUB configuration: in its root
/// filesystem, or at the top of a separate `/boot` filesystem.
const GRUB_CONFIGS: &[&str] = &[
    "boot/grub/grub.cfg",
    "boot/grub2/grub.cfg",
    "grub/grub.cfg",
    "grub2/grub.cfg",
];
/// Smaller partitions (such as a BIOS boot partition) hold no filesystem.
const MIN_FILESYSTEM: u64 = 64 << 10;

pub struct DiskBoot {
    pub drive: String,
    /// The partition's number, as Linux numbers it (0: the whole disk).
    pub partition: u32,
    pub config: &'static str,
    /// Blocks read from the filesystem's journal: it wasn't cleanly unmounted.
    pub journal_blocks: usize,
    pub entry: LoadedEntry,
}

/// Find the first of `drives` (VHDX paths) with a GRUB configuration naming a
/// Linux kernel, and load its default entry.
pub fn resolve(drives: &[&str]) -> Result<DiskBoot> {
    for &drive in drives {
        // Closed again before the VM opens the drive: VHDMP refuses a
        // writable open while this one is open.
        let disk = ReadOnlyDisk::open(drive).map_err(|e| {
            Error::msg(format!(
                "--drive {drive}: open: {}",
                std::io::Error::from_raw_os_error(e as i32)
            ))
        })?;
        let found = resolve_from(&Vhdx(&disk), disk.size())
            .map_err(|e| Error::msg(format!("--drive {drive}: {e}")))?;
        if let Some((partition, config, journal_blocks, entry)) = found {
            return Ok(DiskBoot {
                drive: drive.to_string(),
                partition,
                config,
                journal_blocks,
                entry,
            });
        }
    }
    Err(Error::msg(format!(
        "no --drive holds a Linux installation to boot: no ext2/3/4 filesystem with a GRUB \
         configuration naming a kernel (looked for {}). Give a kernel path or --iso to boot \
         something else",
        GRUB_CONFIGS.join(", ")
    )))
}

type Found = (u32, &'static str, usize, LoadedEntry);

fn resolve_from<R: ReadAt>(disk: &R, size: u64) -> Result<Option<Found>> {
    for part in partition::partitions(disk, size)? {
        if part.len < MIN_FILESYSTEM {
            continue;
        }
        let Some(fs) = Ext4::probe(Region::new(disk, part.start, part.len))
            .map_err(|e| Error::msg(format!("partition {}: {e}", part.number)))?
        else {
            continue;
        };
        for &config in GRUB_CONFIGS {
            if fs.lookup(config)? != Some(Kind::File) {
                continue;
            }
            let text = fs.read_file(config)?;
            let Some(entry) = grub_cfg::first_linux_entry(&String::from_utf8_lossy(&text)) else {
                continue;
            };
            // The entry's paths are on the filesystem holding the configuration.
            let entry = LoadedEntry::load(entry, |path| fs.read_file(path))
                .map_err(|e| Error::msg(format!("partition {} ({config}): {e}", part.number)))?;
            return Ok(Some((part.number, config, fs.journal_blocks(), entry)));
        }
    }
    Ok(None)
}

/// A VHDX read through VHDMP, in whole sectors as it requires.
struct Vhdx<'a>(&'a ReadOnlyDisk);

impl ReadAt for Vhdx<'_> {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        const SECTOR: u64 = 512;
        let os = |e: u32| std::io::Error::from_raw_os_error(e as i32);
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(std::io::ErrorKind::InvalidInput)?;
        if offset.is_multiple_of(SECTOR) && end.is_multiple_of(SECTOR) {
            return self.0.read_exact_at(offset, buf).map_err(os);
        }
        let start = offset / SECTOR * SECTOR;
        let mut aligned = vec![0u8; (end.next_multiple_of(SECTOR) - start) as usize];
        self.0.read_exact_at(start, &mut aligned).map_err(os)?;
        let skip = (offset - start) as usize;
        buf.copy_from_slice(&aligned[skip..skip + buf.len()]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convenience::ext4::tests::{Image, Node, SMALL, pattern};
    use crate::convenience::partition::tests::gpt_disk;

    /// A GPT disk: a 1 MiB BIOS boot partition, then each filesystem.
    fn disk(filesystems: &[&[u8]]) -> Vec<u8> {
        let bios = vec![0x11u8; 1 << 20];
        let mut parts: Vec<(u64, &[u8])> = vec![(2048, &bios)];
        let mut first = 4096;
        for fs in filesystems {
            parts.push((first, fs));
            first += (fs.len() as u64).div_ceil(512) + 2048;
        }
        gpt_disk((first * 512) as usize, &parts)
    }

    const UBUNTU_CFG: &[u8] = b"set default=\"0\"\n\
        menuentry 'Ubuntu' --class ubuntu $menuentry_id_option 'gnulinux-simple-x' {\n\
        \trecordfail\n\
        \tsearch --no-floppy --fs-uuid --set=root 0123\n\
        \tlinux\t/boot/vmlinuz-7.0.0-15-generic root=UUID=0123 ro  quiet splash $vt_handoff\n\
        \tinitrd\t/boot/initrd.img-7.0.0-15-generic\n\
        }\n";

    #[test]
    fn boots_the_default_entry_of_the_installed_grub_configuration() {
        let kernel = pattern(5000, 1);
        let initrd = pattern(3001, 2);
        let root = Image::new(
            SMALL,
            vec![Node::Dir(
                "boot",
                vec![
                    Node::Dir("grub", vec![Node::File("grub.cfg", UBUNTU_CFG)]),
                    Node::File("vmlinuz-7.0.0-15-generic", &kernel),
                    Node::File("initrd.img-7.0.0-15-generic", &initrd),
                ],
            )],
        );
        let disk = disk(&[&root.bytes]);
        let (partition, config, journal_blocks, entry) =
            resolve_from(&disk, disk.len() as u64).unwrap().unwrap();
        assert_eq!(
            (partition, config, journal_blocks),
            (2, "boot/grub/grub.cfg", 0)
        );
        assert_eq!(entry.title, "Ubuntu");
        assert_eq!(entry.args, "root=UUID=0123 ro quiet splash");
        assert_eq!(entry.kernel, kernel);
        // Padded to 4 bytes, as GRUB loads initrds.
        let mut padded = initrd.clone();
        padded.resize(3004, 0);
        assert_eq!(entry.initrd.as_deref(), Some(&padded[..]));
    }

    #[test]
    fn finds_a_separate_boot_filesystem_and_skips_others() {
        let kernel = pattern(4096, 3);
        let cfg = b"menuentry 'Debian' {\n linux /vmlinuz-6 root=/dev/vda3 ro\n}\n";
        let other = Image::new(SMALL, vec![Node::File("hello", b"not a boot filesystem")]);
        let boot = Image::new(
            SMALL,
            vec![
                Node::Dir("grub", vec![Node::File("grub.cfg", cfg)]),
                Node::File("vmlinuz-6", &kernel),
            ],
        );
        let disk = disk(&[&other.bytes, &boot.bytes]);
        let (partition, config, _, entry) =
            resolve_from(&disk, disk.len() as u64).unwrap().unwrap();
        assert_eq!((partition, config), (3, "grub/grub.cfg"));
        assert_eq!(entry.kernel, kernel);
        assert!(entry.initrd.is_none());
        // Nothing to boot: no configuration, or one without a Linux entry.
        let empty = Image::new(
            SMALL,
            vec![Node::Dir("boot", vec![Node::Dir("grub", vec![])])],
        );
        let disk = self::disk(&[&empty.bytes]);
        assert!(resolve_from(&disk, disk.len() as u64).unwrap().is_none());
        let chain = Image::new(
            SMALL,
            vec![Node::Dir(
                "boot",
                vec![Node::Dir(
                    "grub",
                    vec![Node::File("grub.cfg", b"configfile /x\n")],
                )],
            )],
        );
        let disk = self::disk(&[&chain.bytes]);
        assert!(resolve_from(&disk, disk.len() as u64).unwrap().is_none());
    }
}
