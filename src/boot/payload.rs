#[cfg(not(any(feature = "embedded-init", feature = "embedded-dotnet")))]
use crate::error::Error;
use crate::{error::Result, host::mapped_file::MappedFile};

pub const BUNDLED: bool = cfg!(any(feature = "embedded-init", feature = "embedded-dotnet"));

pub enum Image {
    File(MappedFile),
    /// Read into memory, e.g. from inside an ISO (`--iso`).
    Owned(Vec<u8>),
    #[cfg(any(feature = "embedded-init", feature = "embedded-dotnet"))]
    Embedded(&'static [u8]),
}

impl Image {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::File(file) => file.bytes(),
            Self::Owned(bytes) => bytes,
            #[cfg(any(feature = "embedded-init", feature = "embedded-dotnet"))]
            Self::Embedded(bytes) => bytes,
        }
    }
}

pub fn kernel(path: Option<&str>) -> Result<Image> {
    if let Some(path) = path {
        return MappedFile::open(path).map(Image::File);
    }
    #[cfg(any(feature = "embedded-init", feature = "embedded-dotnet"))]
    return Ok(Image::Embedded(include_bytes!(env!("TINYVMM_KERNEL"))));
    #[cfg(not(any(feature = "embedded-init", feature = "embedded-dotnet")))]
    Err(Error::msg("--pvh-run: expected path to vmlinux"))
}

pub fn initrd(path: Option<&str>) -> Result<Option<Image>> {
    if let Some(path) = path {
        return MappedFile::open(path).map(Image::File).map(Some);
    }
    #[cfg(any(feature = "embedded-init", feature = "embedded-dotnet"))]
    return Ok(Some(Image::Embedded(include_bytes!(env!(
        "TINYVMM_INITRD"
    )))));
    #[cfg(not(any(feature = "embedded-init", feature = "embedded-dotnet")))]
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_pvh_args;

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    #[test]
    fn kernel_is_optional_only_for_embedded_builds() {
        let result = parse_pvh_args(&args(&["tinyvmm", "--pvh-run", "--", "console=hvc0"]));
        if BUNDLED {
            let config = result.unwrap();
            assert!(config.vmlinux.is_none());
            assert_eq!(config.ram_mb, 1024);
        } else {
            assert!(result.is_err());
        }
    }

    #[test]
    fn explicit_boot_assets_override_embedded_defaults() {
        let config = parse_pvh_args(&args(&[
            "tinyvmm",
            "--pvh-run",
            "--initrd",
            "custom.cpio",
            "custom-vmlinux",
            "--",
            "console=hvc0",
            "quiet",
        ]))
        .unwrap();
        assert_eq!(config.vmlinux.as_deref(), Some("custom-vmlinux"));
        assert_eq!(config.initrd.as_deref(), Some("custom.cpio"));
        // The arguments follow the defaults, which a bundled build ends with
        // idle=halt.
        let defaults = if BUNDLED {
            "console=hvc0 pci=conf1,nocrs,lastbus=0 nofb nomodeset idle=halt"
        } else {
            "console=hvc0 pci=conf1,nocrs,lastbus=0 nofb nomodeset"
        };
        assert_eq!(config.cmdline, format!("{defaults} console=hvc0 quiet"));
    }

    #[test]
    fn no_default_cmdline_makes_the_arguments_the_whole_cmdline() {
        let parse = |extra: &[&str]| {
            let mut parts = vec!["tinyvmm", "--pvh-run"];
            parts.extend_from_slice(extra);
            parse_pvh_args(&args(&parts)).unwrap()
        };
        let config = parse(&[
            "--no-default-cmdline",
            "vmlinux",
            "--",
            "console=ttyS0",
            "x=1",
        ]);
        assert_eq!(config.cmdline, "console=ttyS0 x=1");
        // --gpu and --debug-boot shape the defaults, given or not.
        let config = parse(&["--gpu", "--debug-boot", "vmlinux", "--", "x=1"]);
        assert!(
            config
                .cmdline
                .starts_with("earlyprintk=ttyS0,115200 console=hvc0 pci=conf1,nocrs,lastbus=0 ")
        );
        assert!(!config.cmdline.contains("nomodeset"));
        assert!(config.cmdline.split_whitespace().any(|arg| arg == "x=1"));
    }

    #[test]
    fn flags_may_follow_the_kernel_path() {
        // As when an @file ends with the kernel path and more flags follow it.
        let config = parse_pvh_args(&args(&[
            "tinyvmm",
            "--pvh-run",
            "--vcpus",
            "2",
            "vmlinux",
            "--watchdog-secs",
            "3",
            "--",
            "quiet",
        ]))
        .unwrap();
        assert_eq!(config.vmlinux.as_deref(), Some("vmlinux"));
        assert_eq!((config.vcpus, config.watchdog_secs), (2, 3));
        assert!(config.cmdline.ends_with(" quiet"));
        // A second path is a mistake (kernel arguments belong after --), not
        // something to drop silently.
        let err = parse_pvh_args(&args(&["tinyvmm", "--pvh-run", "vmlinux", "quiet"]));
        assert!(err.is_err());
    }

    #[test]
    fn large_pages_default_to_plain_builds_and_can_be_selected() {
        let parse = |extra: &[&str]| {
            let mut parts = vec!["tinyvmm", "--pvh-run"];
            parts.extend_from_slice(extra);
            parts.push("vmlinux");
            parse_pvh_args(&args(&parts)).unwrap().large_pages
        };
        assert_eq!(parse(&[]), !BUNDLED);
        assert!(parse(&["--large-pages"]));
        assert!(!parse(&["--no-large-pages"]));
    }

    #[test]
    fn iso_supplies_kernel_and_first_drive_and_appends_args() {
        let config = parse_pvh_args(&args(&[
            "tinyvmm",
            "--pvh-run",
            "--drive",
            "disk.vhdx",
            "--iso",
            "live.iso",
            "--",
            "debug",
            "x=1",
        ]))
        .unwrap();
        assert_eq!(config.iso.as_deref(), Some("live.iso"));
        assert!(config.vmlinux.is_none());
        let drives: Vec<_> = config
            .drives
            .iter()
            .map(|d| (d.path.as_str(), d.readonly))
            .collect();
        assert_eq!(drives, [("live.iso", true), ("disk.vhdx", false)]);
        assert!(config.drives[0].iso);
        assert!(!config.drives[1].iso);
        assert!(!config.disk_boot);
        assert_eq!(config.extra_args, "debug x=1");
        assert!(config.cmdline.starts_with("console=hvc0 "));

        for conflicting in [
            &["--iso", "a.iso", "vmlinux"][..],
            &["--iso", "a.iso", "--initrd", "i"],
        ] {
            let mut parts = vec!["tinyvmm", "--pvh-run"];
            parts.extend_from_slice(conflicting);
            assert!(parse_pvh_args(&args(&parts)).is_err(), "{conflicting:?}");
        }
    }

    #[test]
    fn a_drive_without_a_kernel_boots_the_installed_system() {
        let parse = |extra: &[&str]| {
            let mut parts = vec!["tinyvmm", "--pvh-run", "--drive", "disk.vhdx"];
            parts.extend_from_slice(extra);
            parse_pvh_args(&args(&parts))
        };
        let config = parse(&["--", "quiet", "x=1"]).unwrap();
        assert!(config.vmlinux.is_none());
        // Appliance builds boot their embedded kernel instead.
        assert_eq!(config.disk_boot, !BUNDLED);
        if !BUNDLED {
            assert_eq!(config.extra_args, "quiet x=1");
            assert!(config.cmdline.starts_with("console=hvc0 "));
            assert!(parse(&["--initrd", "i.cpio"]).is_err());
        }
        // A kernel path still boots that kernel, its arguments after the
        // defaults.
        let config = parse(&["vmlinux", "--", "console=hvc0", "quiet"]).unwrap();
        assert!(!config.disk_boot);
        assert!(
            config
                .cmdline
                .starts_with("console=hvc0 pci=conf1,nocrs,lastbus=0 ")
        );
        assert!(config.cmdline.ends_with(" console=hvc0 quiet"));
    }
}
