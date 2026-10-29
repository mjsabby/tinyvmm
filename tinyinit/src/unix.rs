use crate::config::User;
use anyhow::{Context, Result};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::{
        fd::AsRawFd,
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

pub fn command(user: &User, executable: &str, cwd: &str) -> Command {
    let mut cmd = Command::new(executable);
    cmd.current_dir(cwd).env_clear().envs([
        ("PATH", "/bin:/usr/bin"),
        ("HOME", &user.home),
        ("USER", &user.name),
        ("LOGNAME", &user.name),
        ("SHELL", "/bin/sh"),
        ("LANG", "C.UTF-8"),
        ("DOTNET_ROOT", "/usr/share/dotnet"),
        ("ASPNETCORE_HTTP_PORTS", "8080"),
    ]);
    cmd
}

pub fn child_setup(
    cmd: &mut Command,
    user: &User,
    cgroup: Option<File>,
    tty: bool,
    no_new_privs: bool,
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
            check(libc::setgroups(0, std::ptr::null()))?;
            check(libc::setgid(gid))?;
            check(libc::setuid(uid))?;
            if no_new_privs {
                check(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))?;
            }
            Ok(())
        });
    }
}
