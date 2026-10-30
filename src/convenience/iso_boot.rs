//! `--iso`: boot a distribution's live or install ISO with no extraction step.
//! The kernel, initrd(s) and kernel arguments come from the default entry of
//! the ISO's GRUB configuration, read into memory; the caller attaches the ISO
//! itself as a read-only disk, where the initrd finds the live system.

use crate::convenience::grub_cfg;
use crate::convenience::iso9660::{Iso9660, ReadAt};
use crate::error::{Error, Result};

/// Where live ISOs keep the GRUB configuration that boots them.
const GRUB_CONFIGS: &[&str] = &[
    "boot/grub/grub.cfg",
    "boot/grub2/grub.cfg",
    "EFI/BOOT/grub.cfg",
    "boot/grub/loopback.cfg",
];

pub struct IsoBoot {
    pub config: &'static str,
    pub title: String,
    pub kernel_path: String,
    pub kernel: Vec<u8>,
    pub initrd_paths: Vec<String>,
    /// The initrds back to back, each padded to 4 bytes as GRUB loads them;
    /// `None` if the entry has none.
    pub initrd: Option<Vec<u8>>,
    pub args: String,
}

/// Open the ISO at `path` and load its default boot entry.
pub fn resolve(path: &str) -> Result<IsoBoot> {
    resolve_from(&Iso9660::open(path)?).map_err(|e| Error::msg(format!("--iso {path}: {e}")))
}

fn resolve_from<R: ReadAt>(iso: &Iso9660<R>) -> Result<IsoBoot> {
    for &config in GRUB_CONFIGS {
        if !iso.lookup(config)?.is_some_and(|e| !e.dir) {
            continue;
        }
        let text = iso.read_file(config)?;
        let Some(entry) = grub_cfg::first_linux_entry(&String::from_utf8_lossy(&text)) else {
            continue;
        };
        let kernel = iso.read_file(&entry.kernel)?;
        let mut initrd: Option<Vec<u8>> = None;
        for path in &entry.initrds {
            let buf = initrd.get_or_insert_with(Vec::new);
            buf.extend_from_slice(&iso.read_file(path)?);
            buf.resize(buf.len().next_multiple_of(4), 0);
        }
        return Ok(IsoBoot {
            config,
            title: entry.title,
            kernel_path: entry.kernel,
            kernel,
            initrd_paths: entry.initrds,
            initrd,
            args: entry.args,
        });
    }
    Err(Error::msg(format!(
        "no GRUB configuration with a Linux entry (looked for {})",
        GRUB_CONFIGS.join(", ")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convenience::iso9660::tests::{Node, build};

    #[test]
    fn loads_the_default_entry_from_the_image() {
        let cfg = b"menuentry 'Live' {\n linux /live/vmlinuz boot=live quiet\n initrd /live/a /live/b\n}\n";
        let image = build(vec![
            Node::Dir(
                "boot",
                vec![Node::Dir("grub2", vec![Node::File("grub.cfg", cfg)])],
            ),
            Node::Dir(
                "live",
                vec![
                    Node::File("vmlinuz", b"bzImage"),
                    Node::File("a", b"cpio1"),
                    Node::File("b", b"cpio2"),
                ],
            ),
        ]);
        let boot = resolve_from(&Iso9660::new(image).unwrap()).unwrap();
        assert_eq!(boot.config, "boot/grub2/grub.cfg");
        assert_eq!(boot.title, "Live");
        assert_eq!(boot.kernel, b"bzImage");
        assert_eq!(boot.initrd.as_deref(), Some(&b"cpio1\0\0\0cpio2\0\0\0"[..]));
        assert_eq!(boot.args, "boot=live quiet");
    }

    #[test]
    fn reports_missing_configuration_and_files() {
        let image = build(vec![Node::File("readme", b"hi")]);
        assert!(resolve_from(&Iso9660::new(image).unwrap()).is_err());
        let cfg = b"menuentry 'x' {\n linux /vmlinuz\n}\n";
        let image = build(vec![Node::Dir(
            "boot",
            vec![Node::Dir("grub", vec![Node::File("grub.cfg", cfg)])],
        )]);
        assert!(resolve_from(&Iso9660::new(image).unwrap()).is_err());
    }
}
