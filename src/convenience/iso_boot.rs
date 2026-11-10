//! `--iso`: boot a distribution's live or install ISO with no extraction step.
//! The kernel, initrd(s) and kernel arguments come from the default entry of
//! the ISO's GRUB configuration, read into memory; the caller attaches the ISO
//! itself as a read-only disk, where the initrd finds the live system.

use crate::convenience::iso9660::Iso9660;
use crate::convenience::{LoadedEntry, ReadAt, grub_cfg};
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
    pub entry: LoadedEntry,
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
        // No more of a configuration is read than the parser takes.
        let text = iso.read_file_capped(config, grub_cfg::MAX_CONFIG_BYTES as u64)?;
        let entry =
            grub_cfg::first_linux_entry(&text).map_err(|e| Error::msg(format!("{config}: {e}")))?;
        let Some(entry) = entry else {
            continue;
        };
        return Ok(IsoBoot {
            config,
            entry: LoadedEntry::load(entry, |path, max| iso.read_file_capped(path, max))?,
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
        assert_eq!(boot.entry.title, "Live");
        assert_eq!(boot.entry.kernel, b"bzImage");
        assert_eq!(
            boot.entry.initrd.as_deref(),
            Some(&b"cpio1\0\0\0cpio2\0\0\0"[..])
        );
        assert_eq!(boot.entry.args, "boot=live quiet");
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

    #[test]
    fn a_configuration_over_the_caps_is_an_error_naming_it() {
        // What booting an image with this configuration comes to: the length
        // of the initrds it loads (`/z`, 6 bytes), or the error.
        let booting = |cfg: &str| {
            let image = build(vec![
                Node::Dir(
                    "boot",
                    vec![Node::Dir(
                        "grub",
                        vec![Node::File("grub.cfg", cfg.as_bytes())],
                    )],
                ),
                Node::File("k", b"kernel"),
                Node::File("z", b"initrd"),
            ]);
            match resolve_from(&Iso9660::new(image).unwrap()) {
                Ok(boot) => Ok(boot.entry.initrd.map_or(0, |initrd| initrd.len())),
                Err(e) => Err(e.to_string()),
            }
        };
        let entry = |initrds: usize| {
            format!(
                "menuentry x {{\n linux /k\n initrd{}\n}}\n",
                " /z".repeat(initrds)
            )
        };
        assert_eq!(booting(&entry(8)), Ok(64));
        assert_eq!(
            booting(&entry(9)).unwrap_err(),
            "boot/grub/grub.cfg: grub.cfg: an entry with 9 initrds is too large (at most 8)"
        );
        // A variable that multiplies itself: this one asked for 16 TiB.
        let grow = format!("set a={}\n", "$a".repeat(16)).repeat(10);
        let error = booting(&format!("set a={}\n{grow}{}", "A".repeat(16), entry(1)));
        let line = "boot/grub/grub.cfg: grub.cfg: line 4 with its variables";
        assert!(error.clone().unwrap_err().starts_with(line), "{error:?}");
        // No more than a megabyte of configuration is read.
        let padded = "# padding\n".repeat(110_000) + &entry(1);
        assert_eq!(
            booting(&padded).unwrap_err(),
            "ISO 9660: boot/grub/grub.cfg is too large (1100037 bytes; at most 1048576 here)"
        );
    }
}
