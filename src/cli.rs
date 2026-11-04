//! Command-line conveniences: argument files (`@file`) and disk sizes with
//! units.

use crate::error::{Error, Result};

/// Expand each `@file` argument (after the program name) into the arguments
/// the file holds; see [`split_arg_file`]. Arguments read from a file are not
/// expanded again. A file's kernel arguments (after its `--`) move to the end,
/// ahead of those after the command line's own `--`, so options can still
/// follow the `@file`. Nothing after the command line's `--` is expanded.
pub fn expand_arg_files(args: Vec<String>) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(args.len());
    let mut kernel: Option<Vec<String>> = None;
    let mut args = args.into_iter();
    out.extend(args.next()); // the program name
    while let Some(arg) = args.next() {
        if arg == "--" {
            kernel.get_or_insert_with(Vec::new).extend(args.by_ref());
            break;
        }
        match arg.strip_prefix('@') {
            Some(path) if !path.is_empty() => {
                let text = std::fs::read_to_string(path)
                    .map_err(|e| Error::msg(format!("@{path}: {e}")))?;
                let mut file_args =
                    split_arg_file(&text).map_err(|e| Error::msg(format!("@{path}: {e}")))?;
                if let Some(at) = file_args.iter().position(|a| a == "--") {
                    let file_kernel = file_args.drain(at..).skip(1);
                    kernel.get_or_insert_with(Vec::new).extend(file_kernel);
                }
                out.extend(file_args);
            }
            _ => out.push(arg),
        }
    }
    if let Some(kernel) = kernel {
        out.push("--".to_string());
        out.extend(kernel);
    }
    Ok(out)
}

/// The arguments in an argument file: each line is split at whitespace, a
/// double-quoted part keeps its spaces (quotes are removed, nothing is
/// escaped, so Windows paths stay as typed), and blank lines and lines
/// starting with `#` are skipped.
fn split_arg_file(text: &str) -> std::result::Result<Vec<String>, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut args = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut arg = String::new();
        let (mut quoted, mut started) = (false, false);
        for c in line.chars() {
            match c {
                '"' => (quoted, started) = (!quoted, true),
                c if c.is_whitespace() && !quoted => {
                    if started {
                        args.push(std::mem::take(&mut arg));
                        started = false;
                    }
                }
                c => {
                    arg.push(c);
                    started = true;
                }
            }
        }
        if quoted {
            return Err(format!("line {}: unterminated quote", n + 1));
        }
        if started {
            args.push(arg);
        }
    }
    Ok(args)
}

/// A disk size in bytes: a number of MiB, or a number with a binary unit (`K`,
/// `M`, `G` or `T`, optionally followed by `B` or `iB`; any case). `None` if
/// it isn't one, or overflows.
pub fn parse_disk_size(s: &str) -> Option<u64> {
    let digits = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (number, unit) = s.split_at(digits);
    let number: u64 = number.parse().ok()?;
    let unit = unit.to_ascii_uppercase();
    let unit = unit
        .strip_suffix("IB")
        .or_else(|| unit.strip_suffix('B'))
        .filter(|prefix| !prefix.is_empty())
        .unwrap_or(&unit);
    let scale: u64 = match unit {
        "" | "M" => 1 << 20,
        "K" => 1 << 10,
        "G" => 1 << 30,
        "T" => 1 << 40,
        _ => return None,
    };
    number.checked_mul(scale)
}

/// `bytes` in the largest binary unit that divides it exactly, e.g. "256 GiB".
pub fn format_size(bytes: u64) -> String {
    const UNITS: [(u64, &str); 4] = [
        (1 << 40, "TiB"),
        (1 << 30, "GiB"),
        (1 << 20, "MiB"),
        (1 << 10, "KiB"),
    ];
    UNITS
        .iter()
        .find(|(scale, _)| bytes >= *scale && bytes.is_multiple_of(*scale))
        .map_or_else(
            || format!("{bytes} bytes"),
            |(scale, unit)| format!("{} {unit}", bytes / scale),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn disk_sizes_take_binary_units_and_default_to_mib() {
        const GIB: u64 = 1 << 30;
        assert_eq!(parse_disk_size("262144"), Some(256 * GIB));
        for s in ["256G", "256g", "256GB", "256GiB", "256gib"] {
            assert_eq!(parse_disk_size(s), Some(256 * GIB), "{s}");
        }
        assert_eq!(parse_disk_size("1T"), Some(1 << 40));
        assert_eq!(parse_disk_size("512M"), Some(512 << 20));
        assert_eq!(parse_disk_size("4096K"), Some(4 << 20));
        for s in [
            "",
            "G",
            "1.5G",
            "10X",
            "256 G",
            "512B",
            "-1",
            "99999999999T",
        ] {
            assert_eq!(parse_disk_size(s), None, "{s}");
        }
        assert_eq!(format_size(256 * GIB), "256 GiB");
        assert_eq!(format_size(1536 << 20), "1536 MiB");
        assert_eq!(format_size(4097 << 10), "4097 KiB");
    }

    #[test]
    fn argument_files_split_lines_and_keep_windows_paths() {
        let text = "\u{feff}# Ubuntu desktop\r\n--pvh-run\r\n\
                    --drive D:\\vms\\ubuntu.vhdx   --vcpus 8\r\n\
                    \r\n   # indented comment\n\
                    --virtio-9p-share \"host=C:\\My Files\\share\",ro\n\
                    -- quiet splash\n";
        assert_eq!(
            split_arg_file(text).unwrap(),
            strings(&[
                "--pvh-run",
                "--drive",
                "D:\\vms\\ubuntu.vhdx",
                "--vcpus",
                "8",
                "--virtio-9p-share",
                "host=C:\\My Files\\share,ro",
                "--",
                "quiet",
                "splash",
            ])
        );
        assert_eq!(split_arg_file("\"\" x").unwrap(), strings(&["", "x"]));
        assert!(split_arg_file("--drive \"D:\\vms").is_err());
    }

    #[test]
    fn argument_files_expand_in_place() {
        let dir = std::env::temp_dir().join(format!("tinyvmm-args-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("vm.args");
        std::fs::write(&file, "--vcpus 8\n@nested.args\n").unwrap();
        let at_file = format!("@{}", file.display());
        let args = strings(&["tinyvmm", "--pvh-run", &at_file, "--sound"]);
        assert_eq!(
            expand_arg_files(args).unwrap(),
            strings(&[
                "tinyvmm",
                "--pvh-run",
                "--vcpus",
                "8",
                "@nested.args",
                "--sound"
            ])
        );

        // A file's kernel arguments go last, before the command line's; an
        // option after the file stays an option, and nothing after the
        // command line's "--" is expanded.
        std::fs::write(&file, "--pvh-run --vcpus 8 -- quiet splash\n").unwrap();
        let args = strings(&["tinyvmm", &at_file, "--sound", "--", "@x", "nosmt"]);
        assert_eq!(
            expand_arg_files(args).unwrap(),
            strings(&[
                "tinyvmm",
                "--pvh-run",
                "--vcpus",
                "8",
                "--sound",
                "--",
                "quiet",
                "splash",
                "@x",
                "nosmt",
            ])
        );

        // The program name is never a file, a bare "@" is kept, and a missing
        // file is an error naming it.
        let kept = strings(&["@x", "@"]);
        assert_eq!(expand_arg_files(kept.clone()).unwrap(), kept);
        let missing = format!("@{}", dir.join("none.args").display());
        let err = expand_arg_files(strings(&["tinyvmm", &missing])).unwrap_err();
        assert!(err.to_string().contains("none.args"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
