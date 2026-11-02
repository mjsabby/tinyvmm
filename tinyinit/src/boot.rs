use crate::{
    config::{Config, Limits, Share},
    coreutils, unix,
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    net::Ipv4Addr,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::symlink,
    },
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub fn run() -> Result<()> {
    ensure!(
        std::process::id() == 1,
        "init mode is only allowed as guest PID 1"
    );
    unsafe {
        libc::umask(0o022);
    }
    let mut log = BootLog::new();
    log.record(&format!(
        "event=begin kernel_uptime_ms={:.3}",
        unix::uptime_ms()?
    ));
    // Leave initramfs rootfs behind; plain chroot would break new user/mount namespaces.
    let cmdline = log.step("boot-arguments", || {
        fs::create_dir_all("/proc")?;
        unix::mount("proc", "/proc", "proc", libc::MS_NOSUID, "")?;
        let contents = fs::read_to_string("/proc/cmdline");
        unix::check(unsafe { libc::umount2(c"/proc".as_ptr(), 0) })?;
        Ok(contents?)
    })?;
    switch_root(&mut log, &cmdline)?;
    for (path, kind, options) in [
        ("/proc", "proc", ""),
        ("/sys", "sysfs", ""),
        ("/dev", "devtmpfs", ""),
        ("/run", "tmpfs", "mode=0755"),
        ("/tmp", "tmpfs", "mode=1777"),
        ("/dev/pts", "devpts", "newinstance,ptmxmode=0666,mode=0620"),
        ("/dev/shm", "tmpfs", "mode=1777"),
    ] {
        log.record(&format!(
            "mount target={path} type={kind} options={options:?}"
        ));
        log.step(&format!("mount:{path}"), || {
            fs::create_dir_all(path)?;
            unix::mount(kind, path, kind, libc::MS_NOSUID, options)
        })?;
    }
    log.step("console-and-device-links", || {
        let console = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/console")?;
        for fd in 0..=2 {
            unix::check(unsafe { libc::dup2(console.as_raw_fd(), fd) })?;
        }
        for (link, target) in [
            ("/dev/ptmx", "pts/ptmx"),
            ("/dev/fd", "/proc/self/fd"),
            ("/dev/stdin", "/proc/self/fd/0"),
            ("/dev/stdout", "/proc/self/fd/1"),
            ("/dev/stderr", "/proc/self/fd/2"),
        ] {
            if fs::symlink_metadata(link).is_ok() {
                fs::remove_file(link)?;
            }
            symlink(target, link)?;
        }
        for dir in [
            "/etc",
            "/root",
            "/home",
            "/mnt",
            "/run/log",
            "/sys/fs/cgroup",
        ] {
            fs::create_dir_all(dir)?;
        }
        Ok(())
    })?;
    log.persist("/run/log/boot.log")?;
    log.step("cgroup2", || {
        unix::mount(
            "cgroup2",
            "/sys/fs/cgroup",
            "cgroup2",
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            "",
        )?;
        unix::write(
            "/sys/fs/cgroup/cgroup.subtree_control",
            "+cpu +memory +pids",
            0o644,
        )
    })?;
    log.step("applet-links", || {
        for applet in coreutils::APPLETS
            .iter()
            .copied()
            .chain(["sh", "brush", "poweroff"])
        {
            let path = format!("/bin/{applet}");
            if fs::symlink_metadata(&path).is_ok() {
                fs::remove_file(&path)?;
            }
            symlink("tinyinit", path)?;
        }
        Ok(())
    })?;

    log.step("clock", || {
        if let Some(epoch) = argument(&cmdline, "tinyinit.epoch") {
            let epoch: i64 = epoch.parse().context("invalid tinyinit.epoch")?;
            ensure!(epoch > 0, "tinyinit.epoch must be positive");
            let time = libc::timespec {
                tv_sec: epoch,
                tv_nsec: 0,
            };
            unix::check(unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &time) })?;
        }
        Ok(())
    })?;
    let path = argument(&cmdline, "tinyinit.config").unwrap_or("/mnt/bootstrap/init.json");
    if path.starts_with("/mnt/bootstrap/") {
        let share = Share {
            tag: argument(&cmdline, "tinyinit.bootstrap")
                .unwrap_or("bootstrap")
                .into(),
            target: "/mnt/bootstrap".into(),
            readonly: true,
            cache: None,
        };
        log.record(&format!(
            "share tag={} target={} readonly=true",
            share.tag, share.target
        ));
        log.step("bootstrap-share", || mount_share(&share))?;
    }
    log.record(&format!("config path={path}"));
    let mut config = log.step("config-read", || Config::read(path))?;
    for (target, size) in &config.tmpfs {
        log.record(&format!("tmpfs target={target} size={size}"));
    }
    log.step("tmpfs-limits", || {
        for (target, size) in &config.tmpfs {
            // Remount must restate per-mount flags; tmpfs changes only `size`.
            let flags = if target == "/" { 0 } else { libc::MS_NOSUID };
            unix::mount(
                "tmpfs",
                target,
                "tmpfs",
                libc::MS_REMOUNT | flags,
                &format!("size={size}"),
            )?;
        }
        Ok(())
    })?;
    for (name, value) in &config.sysctls {
        log.record(&format!("sysctl {name}={value}"));
    }
    log.step("sysctls", || {
        for (name, value) in &config.sysctls {
            fs::write(
                format!("/proc/sys/{}", name.replace('.', "/")),
                value.to_string(),
            )
            .with_context(|| format!("set sysctl {name}"))?;
        }
        Ok(())
    })?;
    // Mount parents before children, such as /srv before /srv/data.
    let mut shares: Vec<&Share> = config.mounts.iter().collect();
    shares.sort_by_key(|share| share.target.matches('/').count());
    for share in shares {
        log.record(&format!(
            "share tag={} target={} readonly={} cache={}",
            share.tag,
            share.target,
            share.readonly,
            share.cache_mode()
        ));
        log.step(&format!("share:{}", share.tag), || {
            fs::create_dir_all(&share.target)?;
            // An image symlink such as /var/run -> /run must not redirect a
            // share onto a path tinyinit manages.
            let real = fs::canonicalize(&share.target)?;
            ensure!(
                !crate::config::reserved(&real.to_string_lossy()),
                "share target {} resolves to {}",
                share.target,
                real.display()
            );
            mount_share(share)
        })?;
    }
    log.step("ssh-authorization", || {
        for login in &mut config.ssh.logins {
            if let Some(path) = login.public_keys_file.take() {
                for line in fs::read_to_string(&path)
                    .with_context(|| format!("read public keys {path}"))?
                    .lines()
                {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        login.public_keys.push(line.into());
                    }
                }
            }
        }
        crate::ssh::validate_keys(&config)
    })?;
    log.step("identities", || identity(&config))?;
    log.step("network", || network(config.network.as_ref()))?;
    log.step("config-save", || {
        unix::write(
            "/run/tinyinit.json",
            serde_json::to_vec_pretty(&config)?,
            0o600,
        )
    })?;
    log.record(&format!(
        "mountinfo\n{}",
        fs::read_to_string("/proc/self/mountinfo")?
    ));

    let mut signals: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        unix::check(libc::sigemptyset(&mut signals))?;
        for signal in [libc::SIGCHLD, libc::SIGTERM, libc::SIGINT, libc::SIGPWR] {
            unix::check(libc::sigaddset(&mut signals, signal))?;
        }
        unix::check(libc::sigprocmask(
            libc::SIG_BLOCK,
            &signals,
            std::ptr::null_mut(),
        ))?;
    }
    let mut services = HashMap::new();
    for app in &config.apps {
        let user = config.user(&app.user)?;
        let argv = script_argv(&app.argv)?;
        let spawn = unix::Spawn {
            groups: app.groups.clone(),
            umask: app.umask_bits()?,
            capabilities: app.capability_mask()?,
            rlimits: config.app_rlimits(app)?,
        };
        let script = (argv[0] != app.argv[0]).then(|| format!(" script={:?}", app.argv[0]));
        log.record(&format!(
            "service={} uid={} gid={} groups={:?} umask={} capabilities={:?} executable={:?}{} cwd={:?} log=/run/log/{}.log",
            app.name,
            user.uid,
            user.gid,
            app.groups,
            app.umask.as_deref().unwrap_or("0022"),
            app.capabilities,
            argv[0],
            script.unwrap_or_default(),
            app.cwd,
            app.name
        ));
        log.step(&format!("service:{}", app.name), || {
            let mut command = unix::command(&user, &argv[0], &app.cwd, &config.env);
            command.args(&argv[1..]).envs(&app.env);
            unix::child_setup(
                &mut command,
                &user,
                Some(cgroup(&app.name, &app.limits)?),
                false,
                true,
                spawn,
            );
            let path = app
                .env
                .get("PATH")
                .or(config.env.get("PATH"))
                .map_or(unix::DEFAULT_PATH, String::as_str);
            start(
                &app.name,
                &mut command,
                &mut services,
                config.logs.max_bytes,
            )
            .with_context(|| format!("executable {:?} with PATH={path}", argv[0]))
        })?;
    }
    log.step("service:sshd", || {
        let root = config.user("root")?;
        let mut command = unix::command(&root, "/bin/tinyinit", "/", &config.env);
        command.args(["sshd", "/run/tinyinit.json"]);
        // Login sessions inherit these limits from sshd.
        let spawn = unix::Spawn {
            rlimits: crate::config::rlimits(&config.rlimits)?,
            ..Default::default()
        };
        unix::child_setup(
            &mut command,
            &root,
            Some(cgroup("sshd", &Limits::default())?),
            false,
            false,
            spawn,
        );
        start("sshd", &mut command, &mut services, config.logs.max_bytes)
    })?;
    log.record(&format!(
        "event=supervisor-ready kernel_uptime_ms={:.3}",
        unix::uptime_ms()?
    ));
    println!(
        "tinyinit: ready; {} essential services; no restarts",
        services.len()
    );
    loop {
        loop {
            let mut status = 0;
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if pid <= 0 {
                break;
            }
            if let Some(Service { name, log }) = services.get(&pid) {
                eprintln!(
                    "tinyinit: essential service {name} exited (wait status {status}); shutting down"
                );
                // Let the pump drain output written just before the exit. A
                // surviving descendant can hold the pipe open, so wait briefly.
                let deadline = Instant::now() + Duration::from_secs(1);
                while !log.is_finished() && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(5));
                }
                use std::io::{Read, Seek, SeekFrom};
                if let Ok(mut file) = File::open(format!("/run/log/{name}.log")) {
                    let length = file.metadata().map_or(0, |metadata| metadata.len());
                    let mut tail = Vec::new();
                    if file
                        .seek(SeekFrom::Start(length.saturating_sub(4096)))
                        .is_ok()
                        && file.read_to_end(&mut tail).is_ok()
                    {
                        eprintln!("{}", String::from_utf8_lossy(&tail));
                    }
                }
                shutdown();
            }
        }
        let signal = unsafe { libc::sigwaitinfo(&signals, std::ptr::null_mut()) };
        if matches!(signal, libc::SIGTERM | libc::SIGINT | libc::SIGPWR) {
            shutdown();
        }
        if signal < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error().into());
        }
    }
}

struct BootLog {
    started: Instant,
    buffered: String,
    file: Option<File>,
}

impl BootLog {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            buffered: String::new(),
            file: None,
        }
    }

    fn record(&mut self, message: &str) {
        let line = format!(
            "tinyinit boot: elapsed_ms={:.3} {message}\n",
            self.started.elapsed().as_secs_f64() * 1000.0
        );
        eprint!("{line}");
        if let Some(file) = &mut self.file {
            if let Err(error) = file.write_all(line.as_bytes()) {
                eprintln!("tinyinit boot: cannot append boot log: {error}");
            }
        } else {
            self.buffered.push_str(&line);
        }
    }

    fn step<T>(&mut self, name: &str, action: impl FnOnce() -> Result<T>) -> Result<T> {
        self.record(&format!("stage={name} event=begin"));
        let started = Instant::now();
        let result = action().with_context(|| format!("boot stage {name}"));
        let duration = started.elapsed().as_secs_f64() * 1000.0;
        match &result {
            Ok(_) => self.record(&format!(
                "stage={name} event=complete duration_ms={duration:.3}"
            )),
            Err(error) => self.record(&format!(
                "stage={name} event=failed duration_ms={duration:.3} error={error:#}"
            )),
        }
        result
    }

    fn persist(&mut self, path: &str) -> Result<()> {
        let mut file = File::create(path)?;
        file.write_all(self.buffered.as_bytes())?;
        self.buffered.clear();
        self.file = Some(file);
        Ok(())
    }
}

fn switch_root(log: &mut BootLog, cmdline: &str) -> Result<()> {
    log.step("root-mount", || {
        fs::create_dir_all("/newroot")?;
        unix::mount("tmpfs", "/newroot", "tmpfs", 0, "mode=0755")
    })?;
    if let Some(source) = argument(cmdline, "tinyinit.rootfs") {
        let tag = source
            .strip_prefix("9p:")
            .context("tinyinit.rootfs expects 9p:TAG")?;
        ensure!(
            !tag.is_empty()
                && tag
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "invalid external rootfs share tag"
        );
        log.step("rootfs-share", || {
            mount_share(&Share {
                tag: tag.into(),
                target: "/rootfs-source".into(),
                readonly: true,
                cache: None,
            })
        })?;
        let source = ["rootfs.tar.zst", "rootfs.tar.gz"]
            .into_iter()
            .map(|name| std::path::Path::new("/rootfs-source").join(name))
            .find(|path| path.exists())
            .context("external rootfs share needs rootfs.tar.zst or rootfs.tar.gz")?;
        log.record(&format!(
            "rootfs source=9p:{tag}/{}",
            source.file_name().unwrap_or_default().to_string_lossy()
        ));
        let report = log.step("root-unpack", || {
            if source
                .extension()
                .is_some_and(|extension| extension == "zst")
            {
                // Packs need random access for parallel frames; the copy is
                // released as soon as extraction finishes.
                let archive = fs::read(&source)?;
                crate::rootfs::unpack_bytes(&archive, std::path::Path::new("/newroot"))
            } else {
                crate::rootfs::unpack(File::open(&source)?, std::path::Path::new("/newroot"))?;
                Ok(crate::rootfs::Unpacked {
                    format: "streamed",
                    frames: 1,
                    threads: 1,
                })
            }
        })?;
        record_unpack(log, &report);
        log.step("rootfs-share-unmount", || {
            Ok(unix::check(unsafe {
                libc::umount2(c"/rootfs-source".as_ptr(), 0)
            })?)
        })?;
    } else {
        #[cfg(feature = "embedded-rootfs")]
        {
            let archive = include_bytes!(env!("TINYINIT_ROOTFS"));
            log.record(&format!(
                "rootfs source=embedded compressed_bytes={}",
                archive.len()
            ));
            let report = log.step("root-unpack", || {
                crate::rootfs::unpack_bytes(archive.as_slice(), std::path::Path::new("/newroot"))
            })?;
            record_unpack(log, &report);
        }
        #[cfg(not(feature = "embedded-rootfs"))]
        log.record("stage=root-unpack event=skipped source=empty");
    }
    if std::path::Path::new("/rootfs-payload").exists() {
        log.step("root-overlay", || {
            crate::rootfs::unpack(
                File::open("/rootfs-payload")?,
                std::path::Path::new("/newroot"),
            )
        })?;
    } else {
        log.record("stage=root-overlay event=skipped");
    }
    log.step("root-bind-init", || {
        fs::create_dir_all("/newroot/usr/bin")?;
        if fs::symlink_metadata("/newroot/bin").is_err() {
            symlink("usr/bin", "/newroot/bin")?;
        }
        if fs::symlink_metadata("/newroot/bin/tinyinit").is_ok() {
            fs::remove_file("/newroot/bin/tinyinit")?;
        }
        File::create("/newroot/bin/tinyinit")?;
        unix::mount("/init", "/newroot/bin/tinyinit", "", libc::MS_BIND, "")?;
        unix::mount(
            "",
            "/newroot/bin/tinyinit",
            "",
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID,
            "",
        )
    })?;
    log.step("root-switch", || {
        std::env::set_current_dir("/newroot")?;
        unix::mount(".", "/", "", libc::MS_MOVE, "")?;
        unix::check(unsafe { libc::chroot(c".".as_ptr()) })?;
        std::env::set_current_dir("/")?;
        Ok(())
    })
}

fn argument<'a>(cmdline: &'a str, key: &str) -> Option<&'a str> {
    cmdline
        .split_whitespace()
        .find_map(|s| s.strip_prefix(key)?.strip_prefix('='))
}

fn record_unpack(log: &mut BootLog, report: &crate::rootfs::Unpacked) {
    log.record(&format!(
        "rootfs format={} frames={} threads={}",
        report.format, report.frames, report.threads
    ));
}

fn mount_share(share: &Share) -> Result<()> {
    fs::create_dir_all(&share.target)?;
    let flags = libc::MS_NOSUID | libc::MS_NODEV | if share.readonly { libc::MS_RDONLY } else { 0 };
    // Read-only shares cache file data (`readahead`): reads go through the page
    // cache in msize-sized Treads instead of one 4 KiB round trip per page, and
    // since lookups of files not held open still go to the host, a file the
    // host replaces is seen when next opened. `"cache": "loose"` caches names
    // and attributes too, for trees the host leaves alone while the VM runs.
    // Writable shares stay uncached, so the guest always reads what the host
    // last wrote.
    let options = format!(
        "trans=virtio,version=9p2000.L,msize=512000,cache={}",
        share.cache_mode()
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match unix::mount(&share.tag, &share.target, "9p", flags, &options) {
            Ok(()) => return Ok(()),
            Err(error) if Instant::now() >= deadline => return Err(error),
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
}

fn identity(config: &Config) -> Result<()> {
    unix::check(unsafe {
        libc::sethostname(config.hostname.as_ptr().cast(), config.hostname.len())
    })?;
    // Like Docker, leave the image's /etc/passwd, group and shadow alone:
    // processes only need numeric IDs, and init resolves names itself.
    for user in std::iter::once(config.user("root")?).chain(config.users.clone()) {
        fs::create_dir_all(&user.home)?;
        unix::own(&user.home, &user, 0o700)?;
    }
    unix::write(
        "/etc/nsswitch.conf",
        "passwd: files\ngroup: files\nhosts: files dns\n",
        0o644,
    )?;
    unix::write(
        "/etc/hosts",
        format!("127.0.0.1 localhost {}\n::1 localhost\n", config.hostname),
        0o644,
    )?;
    Ok(())
}

fn cgroup(name: &str, limits: &Limits) -> Result<File> {
    let dir = format!("/sys/fs/cgroup/{name}");
    fs::create_dir(&dir)?;
    if let Some(bytes) = limits.memory_max {
        fs::write(format!("{dir}/memory.max"), bytes.to_string())?;
    }
    if let Some(count) = limits.pids_max {
        fs::write(format!("{dir}/pids.max"), count.to_string())?;
    }
    if let Some(percent) = limits.cpu_percent {
        fs::write(
            format!("{dir}/cpu.max"),
            format!("{} 100000", u64::from(percent) * 1000),
        )?;
    }
    Ok(OpenOptions::new()
        .write(true)
        .open(format!("{dir}/cgroup.procs"))?)
}

struct Service {
    name: String,
    /// Copies output to the service log until every writer closes the pipe.
    log: thread::JoinHandle<()>,
}

/// Run a `#!` script that lacks an execute bit the way the kernel would if
/// it had one: 9p shows Windows files without one, and the guest can't chmod.
fn script_argv(argv: &[String]) -> Result<Vec<String>> {
    use std::{io::Read, os::unix::fs::PermissionsExt};
    let unchanged = || Ok(argv.to_vec());
    let program = &argv[0];
    if !program.starts_with('/') {
        return unchanged();
    }
    match fs::metadata(program) {
        Ok(metadata) if metadata.is_file() && metadata.permissions().mode() & 0o111 == 0 => {}
        _ => return unchanged(),
    }
    // Linux reads at most 256 bytes for the #! line.
    let mut head = Vec::with_capacity(256);
    File::open(program)?.take(256).read_to_end(&mut head)?;
    let Some(line) = head.strip_prefix(b"#!") else {
        return unchanged();
    };
    let line = line.split(|&byte| byte == b'\n').next().unwrap_or_default();
    let line = std::str::from_utf8(line)
        .with_context(|| format!("{program}: #! line is not UTF-8"))?
        .trim();
    let (interpreter, argument) = line.split_once([' ', '\t']).unwrap_or((line, ""));
    ensure!(!interpreter.is_empty(), "{program}: empty #! line");
    let mut rewritten = vec![interpreter.to_owned()];
    // Like Linux, everything after the interpreter is a single argument.
    let argument = argument.trim();
    if !argument.is_empty() {
        rewritten.push(argument.to_owned());
    }
    rewritten.extend(argv.iter().cloned());
    Ok(rewritten)
}

fn start(
    name: &str,
    command: &mut Command,
    services: &mut HashMap<i32, Service>,
    max_bytes: u64,
) -> Result<()> {
    let (reader, writer) = unix::pipe()?;
    command
        .stdin(Stdio::null())
        .stdout(writer.try_clone()?)
        .stderr(writer);
    let child = command.spawn().with_context(|| format!("start {name}"))?;
    let path = format!("/run/log/{name}.log");
    let log = thread::Builder::new()
        .name(format!("log-{name}"))
        .spawn(move || pump_log(reader, &path, max_bytes))?;
    services.insert(
        child.id() as i32,
        Service {
            name: name.into(),
            log,
        },
    );
    println!("tinyinit: started {name} pid={}", child.id());
    Ok(())
}

/// Copy a service's output into `path`, rotating to `path.1` so each file
/// stays within `max_bytes`. Reading never stops while the service runs, even
/// if tmpfs is full, so the service cannot block on its output pipe.
fn pump_log(mut reader: impl io::Read, path: &str, max_bytes: u64) {
    let rotated = format!("{path}.1");
    let mut file = File::create(path).ok();
    let mut size = 0;
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => return,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };
        let mut chunk = &buffer[..read];
        while !chunk.is_empty() {
            if size >= max_bytes {
                let _ = fs::rename(path, &rotated);
                file = File::create(path).ok();
                size = 0;
            }
            let take = chunk.len().min((max_bytes - size) as usize);
            if let Some(file) = &mut file {
                let _ = file.write_all(&chunk[..take]);
            }
            size += take as u64;
            chunk = &chunk[take..];
        }
    }
}

pub fn shutdown() -> ! {
    if std::process::id() != 1 {
        std::process::exit(1);
    }
    unsafe {
        libc::kill(-1, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        while unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } > 0 {}
        thread::sleep(Duration::from_millis(50));
    }
    unsafe {
        libc::kill(-1, libc::SIGKILL);
        libc::sync();
    }
    // tinyvmm recognizes this on its virtio console; no ACPI power button is needed.
    println!("=== tinyvmm shutdown requested ===");
    unsafe {
        libc::reboot(libc::RB_POWER_OFF);
    }
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

fn network(config: Option<&crate::config::Network>) -> Result<()> {
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    ensure!(
        socket >= 0,
        "network socket: {}",
        io::Error::last_os_error()
    );
    let socket = unsafe { File::from_raw_fd(socket) };
    link_up(socket.as_raw_fd(), "lo")?;
    let Some(net) = config else {
        return Ok(());
    };
    ensure!(
        net.interface.len() < 16 && !net.interface.contains('\0'),
        "invalid interface name"
    );
    let (address, prefix) = net
        .address
        .split_once('/')
        .context("network address needs /prefix")?;
    let address: Ipv4Addr = address.parse()?;
    let prefix: u32 = prefix.parse()?;
    ensure!(prefix <= 32, "invalid IPv4 prefix");
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&format!("/sys/class/net/{}", net.interface)).exists() {
        ensure!(
            Instant::now() < deadline,
            "network interface did not appear"
        );
        thread::sleep(Duration::from_millis(100));
    }
    for (op, addr) in [
        (libc::SIOCSIFADDR, address),
        (libc::SIOCSIFNETMASK, Ipv4Addr::from(mask)),
    ] {
        let mut req = ifreq(&net.interface)?;
        req[16..18].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        req[20..24].copy_from_slice(&addr.octets());
        unix::check(unsafe { libc::ioctl(socket.as_raw_fd(), op as _, req.as_mut_ptr()) })?;
    }
    link_up(socket.as_raw_fd(), &net.interface)?;
    let mut route: libc::rtentry = unsafe { std::mem::zeroed() };
    route.rt_dst.sa_family = libc::AF_INET as u16;
    route.rt_genmask.sa_family = libc::AF_INET as u16;
    route.rt_gateway.sa_family = libc::AF_INET as u16;
    let gateway: Ipv4Addr = net.gateway.parse()?;
    for (dst, src) in route.rt_gateway.sa_data[2..6]
        .iter_mut()
        .zip(gateway.octets())
    {
        *dst = src as libc::c_char;
    }
    route.rt_flags = libc::RTF_UP | libc::RTF_GATEWAY;
    unix::check(unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCADDRT as _, &route) })?;
    let mut dns = String::new();
    for ip in &net.dns {
        let _: std::net::IpAddr = ip.parse()?;
        dns += &format!("nameserver {ip}\n");
    }
    unix::write("/etc/resolv.conf", dns, 0o644)?;
    Ok(())
}

fn ifreq(name: &str) -> Result<[u8; 40]> {
    ensure!(name.len() < 16, "interface name too long");
    let mut req = [0; 40];
    req[..name.len()].copy_from_slice(name.as_bytes());
    Ok(req)
}

fn link_up(socket: i32, name: &str) -> Result<()> {
    let mut req = ifreq(name)?;
    unix::check(unsafe { libc::ioctl(socket, libc::SIOCGIFFLAGS as _, req.as_mut_ptr()) })?;
    let flags = u16::from_ne_bytes([req[16], req[17]]) | libc::IFF_UP as u16;
    req[16..18].copy_from_slice(&flags.to_ne_bytes());
    unix::check(unsafe { libc::ioctl(socket, libc::SIOCSIFFLAGS as _, req.as_mut_ptr()) })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_logs_rotate_within_the_cap() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("tinyinit-log-{}", std::process::id()));
        fs::create_dir(&dir)?;
        let path = dir.join("app.log").to_string_lossy().into_owned();
        let output: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        pump_log(output.as_slice(), &path, 4096);
        let current = fs::read(&path)?;
        let previous = fs::read(format!("{path}.1"))?;
        fs::remove_dir_all(&dir)?;
        assert_eq!(current, output[8192..]);
        assert_eq!(previous, output[4096..8192]);
        Ok(())
    }

    #[test]
    fn non_executable_scripts_run_through_their_interpreter() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("tinyinit-script-{}", std::process::id()));
        fs::create_dir(&dir)?;
        let script = dir.join("start.sh").to_string_lossy().into_owned();
        let argv = vec![script.clone(), "one".into()];
        let mode = |bits| fs::set_permissions(&script, fs::Permissions::from_mode(bits));
        // Windows line endings are trimmed from the #! line.
        fs::write(&script, "#!/bin/sh  -e x \r\necho hi\n")?;
        mode(0o644)?;
        assert_eq!(
            script_argv(&argv)?,
            ["/bin/sh", "-e x", script.as_str(), "one"]
        );
        // Executable scripts and plain files are left to the kernel.
        mode(0o755)?;
        assert_eq!(script_argv(&argv)?, argv);
        fs::write(&script, "echo no interpreter\n")?;
        mode(0o644)?;
        assert_eq!(script_argv(&argv)?, argv);
        assert_eq!(script_argv(&["sleep".into()])?, ["sleep"]);
        fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
