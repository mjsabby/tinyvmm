use std::{env, path::PathBuf, process::Command};

fn main() {
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
