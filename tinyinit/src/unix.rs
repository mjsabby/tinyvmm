use crate::config::User;
use anyhow::{Context, Result};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
    },
    process::Command,
};

pub fn check(result: libc::c_int) -> io::Result<()> {
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn uptime_ms() -> io::Result<f64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    check(unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) })?;
    Ok(time.tv_sec as f64 * 1000.0 + time.tv_nsec as f64 / 1_000_000.0)
}

pub fn mount(
    source: &str,
    target: &str,
    kind: &str,
    flags: libc::c_ulong,
    options: &str,
) -> Result<()> {
    let (source, target_c, kind, options) = (
        CString::new(source)?,
        CString::new(target)?,
        CString::new(kind)?,
        CString::new(options)?,
    );
    check(unsafe {
        libc::mount(
            source.as_ptr(),
            target_c.as_ptr(),
            kind.as_ptr(),
            flags,
            options.as_ptr().cast(),
        )
    })
    .with_context(|| format!("mount {target}"))
}

pub fn write(path: &str, contents: impl AsRef<[u8]>, mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.write_all(contents.as_ref())?;
    Ok(())
}

pub fn own(path: &str, user: &User, mode: u32) -> Result<()> {
    let p = CString::new(path)?;
    check(unsafe { libc::chown(p.as_ptr(), user.uid, user.gid) })?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// PATH for apps and SSH sessions unless init.json `env` sets one.
pub const DEFAULT_PATH: &str = "/bin:/usr/bin";

pub fn command(
    user: &User,
    executable: &str,
    cwd: &str,
    env: &BTreeMap<String, String>,
) -> Command {
    let mut cmd = Command::new(executable);
    cmd.current_dir(cwd)
        .env_clear()
        .envs([
            ("PATH", DEFAULT_PATH),
            ("HOME", &user.home),
            ("USER", &user.name),
            ("LOGNAME", &user.name),
            ("SHELL", "/bin/sh"),
        ])
        .envs(env);
    cmd
}

pub fn pipe() -> io::Result<(File, File)> {
    let mut fds = [0; 2];
    check(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) })?;
    Ok(unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) })
}

/// Per-process settings applied in the child before it drops root.
#[derive(Default)]
pub struct Spawn {
    pub groups: Vec<libc::gid_t>,
    pub umask: Option<libc::mode_t>,
    /// Capability bits kept as ambient capabilities across the UID change.
    pub capabilities: u64,
    /// `(resource, soft, hard)`.
    pub rlimits: Vec<(u32, u64, u64)>,
}

pub fn child_setup(
    cmd: &mut Command,
    user: &User,
    cgroup: Option<File>,
    tty: bool,
    no_new_privs: bool,
    spawn: Spawn,
) {
    let uid = user.uid;
    let gid = user.gid;
    unsafe {
        cmd.pre_exec(move || {
            let mut mask: libc::sigset_t = std::mem::zeroed();
            check(libc::sigemptyset(&mut mask))?;
            check(libc::sigprocmask(
                libc::SIG_SETMASK,
                &mask,
                std::ptr::null_mut(),
            ))?;
            check(libc::setsid())?;
            if tty {
                check(libc::ioctl(0, libc::TIOCSCTTY, 0))?;
            }
            if let Some(ref file) = cgroup
                && libc::write(file.as_raw_fd(), b"0".as_ptr().cast(), 1) != 1
            {
                return Err(io::Error::last_os_error());
            }
            for &(resource, soft, hard) in &spawn.rlimits {
                let limit = libc::rlimit {
                    rlim_cur: soft,
                    rlim_max: hard,
                };
                check(libc::setrlimit(resource as _, &limit))?;
            }
            if let Some(mask) = spawn.umask {
                libc::umask(mask);
            }
            if spawn.capabilities != 0 {
                check(libc::prctl(
                    libc::PR_SET_KEEPCAPS,
                    1 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                ))?;
            }
            check(libc::setgroups(spawn.groups.len(), spawn.groups.as_ptr()))?;
            check(libc::setgid(gid))?;
            check(libc::setuid(uid))?;
            if spawn.capabilities != 0 {
                ambient(spawn.capabilities)?;
            }
            if no_new_privs {
                check(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))?;
            }
            Ok(())
        });
    }
}

/// Make `capabilities` permitted, inheritable, effective and ambient, so they
/// survive exec of an ordinary program after the switch to a non-root UID.
fn ambient(capabilities: u64) -> io::Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const VERSION_3: u32 = 0x2008_0522;
    let set = |bits: u32| Data {
        effective: bits,
        permitted: bits,
        inheritable: bits,
    };
    let header = Header {
        version: VERSION_3,
        pid: 0,
    };
    let data = [set(capabilities as u32), set((capabilities >> 32) as u32)];
    if unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    for bit in (0..64).filter(|bit| capabilities & 1 << bit != 0) {
        check(unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_RAISE as libc::c_ulong,
                bit as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        })?;
    }
    Ok(())
}
