//! Picks a Linux boot entry out of a GRUB configuration, the way a live ISO's
//! `grub.cfg` boots by default: the first `menuentry` that loads a kernel.
//!
//! The configuration comes from an image a guest may have written, so what it
//! can make us allocate or walk is capped. Going over a cap is an error, not a
//! truncation, which would silently change what boots.

use std::collections::HashMap;

use crate::error::{Error, Result};

/// The largest configuration parsed; real ones are tens of kilobytes.
pub const MAX_CONFIG_BYTES: usize = 1 << 20;
/// The longest line after variable substitution, and so the longest value a
/// variable takes: without it, `set a=$a$a` doubles `a` line after line.
const MAX_LINE_BYTES: usize = 64 << 10;
/// All lines together after substitution, which bounds the time a
/// configuration takes however often it repeats its longest variable.
const MAX_EXPANDED_BYTES: usize = 4 << 20;
/// The variables, and the bytes of their names and values together.
const MAX_VARS: usize = 1024;
const MAX_VAR_BYTES: usize = 1 << 20;
/// The most initrds an entry loads, and its longest kernel or initrd path
/// (Linux's `PATH_MAX`).
pub const MAX_INITRDS: usize = 8;
pub const MAX_PATH_BYTES: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
pub struct BootEntry {
    pub title: String,
    /// Kernel path on the boot medium, without a `(device)` prefix.
    pub kernel: String,
    pub initrds: Vec<String>,
    /// The kernel arguments, joined by single spaces.
    pub args: String,
}

/// The first `menuentry` in file order (submenus included) with a `linux`
/// command; `None` if there is none. `set name=value` assignments seen before
/// it are substituted for `$name` and `${name}`; unknown variables expand to
/// nothing, as in GRUB. A configuration, or an entry, beyond the caps above
/// is an error.
pub fn first_linux_entry(cfg: &[u8]) -> Result<Option<BootEntry>> {
    let too_large = |what: String| Error::msg(format!("grub.cfg: {what} is too large"));
    if cfg.len() > MAX_CONFIG_BYTES {
        return Err(too_large(format!(
            "a {}-byte configuration (over {MAX_CONFIG_BYTES})",
            cfg.len()
        )));
    }
    let cfg = String::from_utf8_lossy(cfg);
    let mut vars: HashMap<String, String> = HashMap::new();
    let (mut var_bytes, mut expanded) = (0usize, 0usize);
    let mut open: Option<BootEntry> = None;
    for (number, raw) in (1..).zip(cfg.lines()) {
        let line = raw.trim();
        if line.starts_with('}') {
            if let Some(entry) = open.take()
                && !entry.kernel.is_empty()
            {
                return bounded(entry).map(Some);
            }
            continue;
        }
        // A comment has nothing to substitute, however long it is.
        if line.starts_with('#') {
            continue;
        }
        let line = expand_vars(line, &vars).ok_or_else(|| {
            too_large(format!(
                "line {number} with its variables substituted (over {MAX_LINE_BYTES} bytes)"
            ))
        })?;
        expanded += line.len();
        if expanded > MAX_EXPANDED_BYTES {
            return Err(too_large(format!(
                "the configuration up to line {number} with its variables substituted (over \
                 {MAX_EXPANDED_BYTES} bytes)"
            )));
        }
        let words = split_words(&line);
        let Some((cmd, rest)) = words.split_first() else {
            continue;
        };
        match (cmd.as_str(), open.as_mut()) {
            ("menuentry", _) => {
                open = Some(BootEntry {
                    title: rest.first().cloned().unwrap_or_default(),
                    kernel: String::new(),
                    initrds: Vec::new(),
                    args: String::new(),
                });
            }
            ("set", _) => {
                if let Some((name, value)) = rest.first().and_then(|w| w.split_once('=')) {
                    var_bytes += name.len() + value.len();
                    if let Some(old) = vars.insert(name.to_string(), value.to_string()) {
                        var_bytes -= name.len() + old.len();
                    }
                    if vars.len() > MAX_VARS || var_bytes > MAX_VAR_BYTES {
                        return Err(too_large(format!(
                            "the set of variables at line {number} (over {MAX_VARS} of them, or \
                             {MAX_VAR_BYTES} bytes)"
                        )));
                    }
                }
            }
            ("linux" | "linuxefi" | "linux16", Some(entry)) => {
                if let Some((kernel, args)) = rest.split_first() {
                    entry.kernel = strip_device(kernel).to_string();
                    entry.args = args.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" ");
                }
            }
            ("initrd" | "initrdefi" | "initrd16", Some(entry)) => {
                entry.initrds = rest.iter().map(|p| strip_device(p).to_string()).collect();
            }
            _ => {}
        }
    }
    open.filter(|entry| !entry.kernel.is_empty())
        .map(bounded)
        .transpose()
}

/// The entry to boot, unless it names more initrds or longer paths than the
/// caps allow. Checked here rather than line by line: only the entry that
/// boots has to pass.
fn bounded(entry: BootEntry) -> Result<BootEntry> {
    if entry.initrds.len() > MAX_INITRDS {
        return Err(Error::msg(format!(
            "grub.cfg: an entry with {} initrds is too large (at most {MAX_INITRDS})",
            entry.initrds.len()
        )));
    }
    let mut paths = std::iter::once(&entry.kernel).chain(&entry.initrds);
    if let Some(path) = paths.find(|path| path.len() > MAX_PATH_BYTES) {
        return Err(Error::msg(format!(
            "grub.cfg: a {}-byte kernel or initrd path is too large (over {MAX_PATH_BYTES})",
            path.len()
        )));
    }
    Ok(entry)
}

/// Drop a GRUB device prefix such as `($root)` or `(hd0,gpt2)` from a path.
fn strip_device(path: &str) -> &str {
    match path.strip_prefix('(').and_then(|p| p.split_once(')')) {
        Some((_, rest)) => rest,
        None => path,
    }
}

/// Re-quote an argument that contains whitespace (it was quoted in the file).
fn quote(arg: &str) -> String {
    if arg.contains(char::is_whitespace) {
        format!("\"{arg}\"")
    } else {
        arg.to_string()
    }
}

/// Substitute `$name` / `${name}` outside single quotes; `None` if the line
/// grows past `MAX_LINE_BYTES`.
fn expand_vars(line: &str, vars: &HashMap<String, String>) -> Option<String> {
    let mut out = String::with_capacity(line.len().min(MAX_LINE_BYTES));
    let mut chars = line.chars().peekable();
    let mut single = false;
    while let Some(c) = chars.next() {
        // A step adds a character or a value, itself a part of such a line.
        if out.len() > MAX_LINE_BYTES {
            return None;
        }
        match c {
            '\'' => {
                single = !single;
                out.push(c);
            }
            '\\' if !single => {
                out.push(c);
                if let Some(next) = chars.next() {
                    out.push(next);
                }
            }
            '$' if !single => {
                let mut name = String::new();
                if chars.next_if_eq(&'{').is_some() {
                    for c in chars.by_ref() {
                        if c == '}' {
                            break;
                        }
                        name.push(c);
                    }
                } else {
                    while let Some(c) = chars.next_if(|c| c.is_ascii_alphanumeric() || *c == '_') {
                        name.push(c);
                    }
                }
                if name.is_empty() {
                    out.push('$');
                } else if let Some(value) = vars.get(&name) {
                    out.push_str(value);
                }
            }
            _ => out.push(c),
        }
    }
    (out.len() <= MAX_LINE_BYTES).then_some(out)
}

/// Split a line into words like GRUB's script parser: whitespace separates
/// words, quotes group (and are removed), a backslash escapes the next
/// character, and an unquoted `#` starts a comment.
fn split_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            '#' if !in_word => break,
            '\'' | '"' => {
                in_word = true;
                for q in chars.by_ref() {
                    if q == c {
                        break;
                    }
                    cur.push(q);
                }
            }
            '\\' => {
                in_word = true;
                if let Some(next) = chars.next() {
                    cur.push(next);
                }
            }
            c => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ubuntu_live_iso() {
        let cfg = r#"set timeout=30

loadfont unicode

menuentry "Try or Install Ubuntu" {
    set gfxpayload=keep
    linux  /casper/vmlinuz  --- quiet splash
    initrd /casper/initrd
}
menuentry "Ubuntu (safe graphics)" {
    set gfxpayload=keep
    linux  /casper/vmlinuz nomodeset  --- quiet splash
    initrd /casper/initrd
}
"#;
        assert_eq!(
            first_linux_entry(cfg.as_bytes()).unwrap(),
            Some(BootEntry {
                title: "Try or Install Ubuntu".into(),
                kernel: "/casper/vmlinuz".into(),
                initrds: vec!["/casper/initrd".into()],
                args: "--- quiet splash".into(),
            })
        );
    }

    #[test]
    fn fedora_live_iso_with_device_prefix_variables_and_submenu() {
        let cfg = r#"set default="1"
function load_video {
  insmod all_video
}
if [ "$grub_platform" == "efi" ]; then
	set basicgfx="nomodeset"
fi
menuentry 'Start Fedora-Workstation-Live' --class fedora --class os {
	linux ($root)/boot/x86_64/loader/linux quiet rhgb  root=live:CDLABEL=Fedora-WS-Live-43 rd.live.image
	initrd ($root)/boot/x86_64/loader/initrd
}
submenu 'Troubleshooting -->' {
	menuentry 'Start in basic graphics mode' {
		linux ($root)/boot/x86_64/loader/linux ${basicgfx} quiet
	}
}
"#;
        let entry = first_linux_entry(cfg.as_bytes()).unwrap().unwrap();
        assert_eq!(entry.title, "Start Fedora-Workstation-Live");
        assert_eq!(entry.kernel, "/boot/x86_64/loader/linux");
        assert_eq!(entry.initrds, ["/boot/x86_64/loader/initrd"]);
        assert_eq!(
            entry.args,
            "quiet rhgb root=live:CDLABEL=Fedora-WS-Live-43 rd.live.image"
        );
    }

    #[test]
    fn variables_quotes_and_multiple_initrds() {
        let cfg = r#"set iso="/live" # where the files are
menuentry "Install" {
    echo "no kernel here"
}
menuentry "Live ($iso)" {
    linux ${iso}/vmlinuz boot=live 'label=My Disk' $unset x=\$y
    initrd $iso/initrd.img (hd0,gpt2)/extra.cpio
}"#;
        assert_eq!(
            first_linux_entry(cfg.as_bytes()).unwrap(),
            Some(BootEntry {
                title: "Live (/live)".into(),
                kernel: "/live/vmlinuz".into(),
                initrds: vec!["/live/initrd.img".into(), "/extra.cpio".into()],
                args: "boot=live \"label=My Disk\" x=$y".into(),
            })
        );
        assert_eq!(first_linux_entry(b"menuentry 'x' {\n}\n").unwrap(), None);
    }

    /// The error a configuration over one of the caps gives.
    fn too_large(cfg: &str) -> String {
        let error = first_linux_entry(cfg.as_bytes()).unwrap_err().to_string();
        assert!(
            error.starts_with("grub.cfg: ") && error.contains("too large"),
            "{error}"
        );
        error
    }

    #[test]
    fn a_variable_that_multiplies_itself_is_an_error_not_an_allocation() {
        // Each line makes `a` sixteen times longer: 16 TiB by the eleventh,
        // had the fourth not been refused (16^4 bytes = 64 KiB, and "set a=").
        let grow = format!("set a={}\n", "$a".repeat(16));
        let cfg = format!("set a={}\n{}", "A".repeat(16), grow.repeat(10));
        assert!(too_large(&cfg).contains("line 4 "));
        // `${a}`, and a variable that grows through another, are no different.
        let grow = "set b=${a}${a}\nset a=$b$b\n".repeat(20);
        too_large(&format!("set a={}\n{grow}", "A".repeat(16)));
        // Nor are lines that set nothing: a 60 KiB value fits a line, but a
        // hundred such lines don't fit the 4 MiB all lines may come to.
        let cfg = format!(
            "set a={}\n{}",
            "A".repeat(60 << 10),
            "echo $a\n".repeat(100)
        );
        assert!(too_large(&cfg).contains("up to line 69 "));
        // A value below the caps still substitutes as before.
        let cfg = format!(
            "set a={}\nset b=$a$a\nmenuentry x {{\n linux /k $b\n}}\n",
            "A".repeat(1000)
        );
        let entry = first_linux_entry(cfg.as_bytes()).unwrap().unwrap();
        assert_eq!(entry.args, "A".repeat(2000));
    }

    #[test]
    fn configurations_and_variable_tables_over_the_caps_are_errors() {
        // A megabyte of configuration parses; a byte more does not.
        let entry = "menuentry x {\n linux /k\n}\n";
        let padding = "# a comment\n".repeat(MAX_CONFIG_BYTES / 12);
        let mut cfg = format!("{padding}{entry}");
        cfg.truncate(MAX_CONFIG_BYTES);
        assert!(first_linux_entry(cfg.as_bytes()).is_ok());
        cfg.push('\n');
        assert!(too_large(&cfg).contains("1048577-byte configuration"));
        // A long comment is no line to substitute; a long command is.
        let long = "x".repeat(MAX_LINE_BYTES + 1);
        let cfg = format!("# {long}\n{entry}");
        assert!(first_linux_entry(cfg.as_bytes()).unwrap().is_some());
        assert!(too_large(&format!("echo {long}\n{entry}")).contains("line 1 "));
        // Variables: a thousand are fine, setting them again too.
        let sets = |n: usize| (0..n).map(|i| format!("set v{i}=x\n")).collect::<String>();
        let cfg = format!("{}{}{entry}", sets(MAX_VARS), sets(MAX_VARS));
        assert!(first_linux_entry(cfg.as_bytes()).unwrap().is_some());
        assert!(too_large(&sets(MAX_VARS + 1)).contains("line 1025 "));
        // And their bytes together: the eighteenth 60 KiB value is the one
        // that takes them over a megabyte.
        let value = "A".repeat(60 << 10);
        let copies: String = (0..20).map(|i| format!("set v{i}=$a\n")).collect();
        assert!(too_large(&format!("set a={value}\n{copies}")).contains("line 18 "));
        // Setting one variable over and over holds only its last value.
        let cfg = format!("set v={value}\n").repeat(16) + entry;
        assert!(first_linux_entry(cfg.as_bytes()).unwrap().is_some());
    }

    #[test]
    fn an_entry_over_the_initrd_and_path_caps_is_an_error() {
        let entry = |kernel: &str, initrds: usize| {
            format!(
                "menuentry x {{\n linux {kernel}\n initrd{}\n}}\n",
                " /z".repeat(initrds)
            )
        };
        let eight = first_linux_entry(entry("/k", MAX_INITRDS).as_bytes()).unwrap();
        assert_eq!(eight.unwrap().initrds.len(), MAX_INITRDS);
        assert!(too_large(&entry("/k", MAX_INITRDS + 1)).contains("9 initrds"));
        // Only the entry that boots has to pass: one without a kernel doesn't.
        let cfg = format!(
            "menuentry skipped {{\n initrd{}\n}}\n{}",
            " /z".repeat(100),
            entry("/k", 1)
        );
        let booted = first_linux_entry(cfg.as_bytes()).unwrap().unwrap();
        assert_eq!((booted.kernel.as_str(), booted.initrds.len()), ("/k", 1));
        // Paths: 4096 bytes is the longest.
        let path = format!("/{}", "k".repeat(MAX_PATH_BYTES - 1));
        assert!(first_linux_entry(entry(&path, 1).as_bytes()).is_ok());
        assert!(too_large(&entry(&format!("{path}k"), 1)).contains("4097-byte"));
        let cfg = format!("menuentry x {{\n linux /k\n initrd /z {path}k\n}}");
        assert!(too_large(&cfg).contains("4097-byte"));
    }
}
