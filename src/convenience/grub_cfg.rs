//! Picks a Linux boot entry out of a GRUB configuration, the way a live ISO's
//! `grub.cfg` boots by default: the first `menuentry` that loads a kernel.

use std::collections::HashMap;

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
/// command. `set name=value` assignments seen before it are substituted for
/// `$name` and `${name}`; unknown variables expand to nothing, as in GRUB.
pub fn first_linux_entry(cfg: &str) -> Option<BootEntry> {
    let mut vars: HashMap<String, String> = HashMap::new();
    let mut open: Option<BootEntry> = None;
    for raw in cfg.lines() {
        let line = raw.trim();
        if line.starts_with('}') {
            if let Some(entry) = open.take()
                && !entry.kernel.is_empty()
            {
                return Some(entry);
            }
            continue;
        }
        let words = split_words(&expand_vars(line, &vars));
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
                    vars.insert(name.to_string(), value.to_string());
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

/// Substitute `$name` / `${name}` outside single quotes.
fn expand_vars(line: &str, vars: &HashMap<String, String>) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    let mut single = false;
    while let Some(c) = chars.next() {
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
    out
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
            first_linux_entry(cfg),
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
        let entry = first_linux_entry(cfg).unwrap();
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
            first_linux_entry(cfg),
            Some(BootEntry {
                title: "Live (/live)".into(),
                kernel: "/live/vmlinuz".into(),
                initrds: vec!["/live/initrd.img".into(), "/extra.cpio".into()],
                args: "boot=live \"label=My Disk\" x=$y".into(),
            })
        );
        assert_eq!(first_linux_entry("menuentry 'x' {\n}\n"), None);
    }
}
