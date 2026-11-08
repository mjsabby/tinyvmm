use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    applets();
    if env::var_os("CARGO_FEATURE_EMBEDDED_ROOTFS").is_none() {
        return;
    }
    println!("cargo:rerun-if-changed=rootfs.lock.json");
    println!("cargo:rerun-if-changed=fetch-rootfs.py");
    let status = Command::new("python")
        .arg("fetch-rootfs.py")
        .status()
        .expect("Python 3.14+ is required to fetch the embedded rootfs");
    assert!(
        status.success(),
        "failed to prepare embedded ASP.NET rootfs"
    );
    let archive = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("out")
        .join("rootfs-cache")
        .join("rootfs.tar.zst");
    println!("cargo:rerun-if-changed={}", archive.display());
    println!("cargo:rustc-env=TINYINIT_ROOTFS={}", archive.display());
}

/// Writes the coreutils applet table, sorted by name: one entry for each
/// `uu_*` crate in Cargo.toml's `[dependencies]`, named without the prefix;
/// `uu_test` also answers to `[`.
fn applets() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("Cargo.toml");
    println!("cargo:rerun-if-changed={}", manifest.display());
    let mut section = "";
    let mut applets = Vec::new();
    for line in fs::read_to_string(&manifest).unwrap().lines() {
        let line = line.trim();
        if line.starts_with('[') {
            section = line;
        } else if section == "[dependencies]"
            && let Some((key, _)) = line.split_once('=')
            && let Some(name) = key.trim().strip_prefix("uu_")
        {
            let krate = format!("uu_{name}");
            if name == "test" {
                applets.push(("[".to_owned(), krate.clone()));
            }
            applets.push((name.to_owned(), krate));
        }
    }
    applets.sort();
    let mut table = String::from("pub static APPLETS: &[(&str, Main)] = &[\n");
    for (name, krate) in &applets {
        table += &format!("    ({name:?}, {krate}::uumain),\n");
    }
    table += "];\n";
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("applets.rs");
    fs::write(out, table).unwrap();
}
