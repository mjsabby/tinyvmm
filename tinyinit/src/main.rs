mod boot;
mod config;
mod coreutils;
mod rootfs;
mod shell;
mod ssh;
mod unix;

use anyhow::{Result, bail};
use std::{ffi::OsString, path::Path};

fn main() {
    let pid1 = std::process::id() == 1;
    let result = run();
    if let Err(error) = result {
        eprintln!("tinyinit: {error:#}");
        if pid1 {
            boot::shutdown();
        }
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args: Vec<OsString> = std::env::args_os().collect();
    let name = Path::new(&args[0])
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    if coreutils::APPLETS.contains(&name.as_str()) {
        std::process::exit(coreutils::run(&name, args)?);
    }
    if matches!(name.as_str(), "sh" | "brush") {
        return shell::run(&args[1..]);
    }
    if name == "poweroff" {
        anyhow::ensure!(std::process::id() != 1, "use the init shutdown path");
        unix::check(unsafe { libc::kill(1, libc::SIGTERM) })?;
        return Ok(());
    }
    let mode = if std::process::id() == 1 {
        "init".to_owned()
    } else {
        args.get(1)
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default()
    };
    match mode.as_str() {
        "init" => boot::run(),
        "sshd" => {
            let path = args
                .get(2)
                .and_then(|s| s.to_str())
                .unwrap_or("/run/tinyinit.json");
            let config = config::Config::read(path)?;
            tokio::runtime::Runtime::new()?.block_on(ssh::run(config))
        }
        "shell" => shell::run(&args[2..]),
        "coreutils" => {
            anyhow::ensure!(
                args.len() >= 3,
                "usage: tinyinit coreutils APPLET [ARGS...]"
            );
            let name = args[2].to_string_lossy().into_owned();
            args.drain(..2);
            std::process::exit(coreutils::run(&name, args)?);
        }
        "--help" | "-h" | "" => {
            println!(
                "tinyinit: init | sshd [CONFIG] | shell [-c COMMAND | SCRIPT [ARGS...]]\n\
                 tinyinit coreutils APPLET [ARGS...]\n\
                 Boot as /init with tinyinit.config=/etc/init.json or a bootstrap 9p share.\n\
                 Coreutils: {}",
                coreutils::APPLETS.join(" ")
            );
            Ok(())
        }
        _ => bail!("unknown mode {mode:?}; use --help"),
    }
}
