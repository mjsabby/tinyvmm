use crate::{
    config::{Config, User},
    unix,
};
use anyhow::{Context, Result, ensure};
use russh::{
    Channel, ChannelId, Pty,
    keys::{Algorithm, HashAlg, PrivateKey, PublicKey},
    server::{self, Auth, ChannelOpenHandle, Msg, Server as _, Session, VerifiedPublicKey},
};
use std::{
    collections::HashMap,
    fs::File,
    io,
    net::SocketAddr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, unix::AsyncFd},
    process::Child,
    sync::watch,
};

struct Authorized {
    user: User,
    keys: Vec<PublicKey>,
}

fn authorized(config: &Config) -> Result<Vec<Authorized>> {
    config.ssh.logins.iter().map(|login| {
        ensure!(!login.public_keys.is_empty(), "no keys for SSH user {}", login.user);
        let keys = login.public_keys.iter().map(|key| {
            PublicKey::from_openssh(key).context("invalid SSH public key (use plain OpenSSH public keys, without authorized_keys options)")
        }).collect::<Result<_>>()?;
        Ok(Authorized { user: config.user(&login.user)?, keys })
    }).collect()
}

pub fn validate_keys(config: &Config) -> Result<()> {
    authorized(config).map(|_| ())
}

pub async fn run(config: Config) -> Result<()> {
    let started = Instant::now();
    let users = Arc::new(authorized(&config)?);
    eprintln!(
        "tinyinit sshd: stage=authorization elapsed_ms={:.3}",
        started.elapsed().as_secs_f64() * 1000.0
    );
    let key_started = Instant::now();
    let host_key = match config.ssh.host_key {
        Some(path) => russh::keys::load_secret_key(&path, None)
            .with_context(|| format!("load host key {path}"))?,
        None => {
            eprintln!("tinyinit sshd: using an ephemeral host key (changes on every boot)");
            PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?
        }
    };
    eprintln!(
        "tinyinit sshd: host key {} duration_ms={:.3}",
        host_key.public_key().fingerprint(HashAlg::Sha256),
        key_started.elapsed().as_secs_f64() * 1000.0
    );
    let server_config = Arc::new(server::Config {
        keys: vec![host_key],
        inactivity_timeout: None,
        nodelay: true,
        // Clients probe with "none" before offering keys. Rejecting that probe
        // immediately reveals nothing; failed key attempts keep the default delay.
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..Default::default()
    });
    eprintln!(
        "tinyinit sshd: auth_rejection_time_ms={} initial_auth_rejection_time_ms={}",
        server_config.auth_rejection_time.as_millis(),
        server_config
            .auth_rejection_time_initial
            .unwrap_or(server_config.auth_rejection_time)
            .as_millis()
    );
    let socket = tokio::net::TcpListener::bind(&config.ssh.listen).await?;
    eprintln!(
        "tinyinit sshd: listening on {} event=listener-ready startup_ms={:.3} kernel_uptime_ms={:.3}",
        config.ssh.listen,
        started.elapsed().as_secs_f64() * 1000.0,
        unix::uptime_ms()?
    );
    SshServer { users }
        .run_on_socket(server_config, &socket)
        .await?;
    Ok(())
}

struct SshServer {
    users: Arc<Vec<Authorized>>,
}

impl server::Server for SshServer {
    type Handler = Connection;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Connection {
        Connection {
            users: self.users.clone(),
            user: None,
            channels: HashMap::new(),
        }
    }

    fn handle_session_error(&mut self, error: anyhow::Error) {
        eprintln!("tinyinit sshd: connection: {error:#}");
    }
}

struct Connection {
    users: Arc<Vec<Authorized>>,
    user: Option<User>,
    channels: HashMap<ChannelId, ChannelState>,
}

#[derive(Default)]
struct ChannelState {
    channel: Option<Channel<Msg>>,
    pty: Option<Terminal>,
    cancel: Option<watch::Sender<bool>>,
}

impl Drop for ChannelState {
    fn drop(&mut self) {
        if let Some(cancel) = &self.cancel {
            let _ = cancel.send(true);
        }
    }
}

struct Terminal {
    master: Arc<AsyncFd<OwnedFd>>,
    slave: Option<File>,
    term: String,
}

impl Connection {
    fn start(&mut self, id: ChannelId, command: Option<&str>, session: &mut Session) -> Result<()> {
        let user = self.user.as_ref().context("not authenticated")?;
        let state = self.channels.get_mut(&id).context("unknown channel")?;
        let Some(channel) = state.channel.take() else {
            session.channel_failure(id)?;
            return Ok(());
        };
        let mut cmd = unix::command(user, "/bin/tinyinit", &user.home);
        cmd.arg("shell");
        if let Some(command) = command {
            cmd.args(["-c", command]);
        }
        let master = state.pty.as_ref().map(|p| p.master.clone());
        if let Some(pty) = &state.pty {
            let slave = pty.slave.as_ref().context("missing PTY slave")?;
            cmd.env("TERM", &pty.term);
            cmd.stdin(slave.try_clone()?)
                .stdout(slave.try_clone()?)
                .stderr(slave.try_clone()?);
        } else {
            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
        }
        unix::child_setup(&mut cmd, user, None, master.is_some(), user.uid != 0);
        let mut cmd = tokio::process::Command::from(cmd);
        cmd.kill_on_drop(true);
        let child = cmd.spawn()?;
        // Only the child should hold the slave; otherwise the master never reaches EOF.
        if let Some(pty) = &mut state.pty {
            pty.slave.take();
        }
        let (cancel, receiver) = watch::channel(false);
        state.cancel = Some(cancel);
        let handle = session.handle();
        session.channel_success(id)?;
        tokio::spawn(async move {
            if let Err(error) =
                serve_process(child, master, channel, handle.clone(), id, receiver).await
            {
                eprintln!("tinyinit sshd: session: {error:#}");
                let _ = handle.exit_status_request(id, 1).await;
                let _ = handle.close(id).await;
            }
        });
        Ok(())
    }
}

impl server::Handler for Connection {
    type Error = anyhow::Error;

    async fn auth_publickey(&mut self, name: &str, key: VerifiedPublicKey<'_>) -> Result<Auth> {
        self.user = self
            .users
            .iter()
            .find(|u| {
                u.user.name == name
                    && u.keys
                        .iter()
                        .any(|k| k.key_data() == key.public_key.key_data())
            })
            .map(|u| u.user.clone());
        Ok(if self.user.is_some() {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<()> {
        if self.user.is_some() && self.channels.len() < 16 {
            self.channels.insert(
                channel.id(),
                ChannelState {
                    channel: Some(channel),
                    pty: None,
                    cancel: None,
                },
            );
            reply.accept().await;
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        cols: u32,
        rows: u32,
        _: u32,
        _: u32,
        _: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<()> {
        let state = self.channels.get_mut(&channel).context("unknown channel")?;
        if state.channel.is_none() || state.pty.is_some() || term.contains('\0') || term.len() > 128
        {
            session.channel_failure(channel)?;
            return Ok(());
        }
        let mut master = -1;
        let mut slave = -1;
        let size = window_size(cols, rows);
        unix::check(unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                &size,
            )
        })?;
        let master = unsafe { OwnedFd::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        for fd in [master.as_raw_fd(), slave.as_raw_fd()] {
            unix::check(unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) })?;
        }
        unix::check(unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) })?;
        let user = self.user.as_ref().context("not authenticated")?;
        unix::check(unsafe { libc::fchown(slave.as_raw_fd(), user.uid, user.gid) })?;
        // The owned descriptor stays open and unchanged for the registration's lifetime.
        let master = unsafe { AsyncFd::register(master)? };
        state.pty = Some(Terminal {
            master: Arc::new(master),
            slave: Some(slave),
            term: term.into(),
        });
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<()> {
        self.start(channel, None, session)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<()> {
        self.start(channel, Some(std::str::from_utf8(data)?), session)
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        cols: u32,
        rows: u32,
        _: u32,
        _: u32,
        _: &mut Session,
    ) -> Result<()> {
        if let Some(pty) = self.channels.get(&channel).and_then(|s| s.pty.as_ref()) {
            unix::check(unsafe {
                libc::ioctl(
                    pty.master.as_raw_fd(),
                    libc::TIOCSWINSZ,
                    &window_size(cols, rows),
                )
            })?;
        }
        Ok(())
    }

    async fn channel_close(&mut self, channel: ChannelId, _: &mut Session) -> Result<()> {
        self.channels.remove(&channel);
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _: &str,
        session: &mut Session,
    ) -> Result<()> {
        session.channel_failure(channel)?;
        Ok(())
    }
}

fn window_size(cols: u32, rows: u32) -> libc::winsize {
    libc::winsize {
        ws_col: cols.min(u16::MAX as u32) as u16,
        ws_row: rows.min(u16::MAX as u32) as u16,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

// Killing the session's original process group also cleans up ordinary shell children.
struct ProcessGroup(u32);
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        unsafe {
            libc::kill(-(self.0 as i32), libc::SIGKILL);
        }
    }
}

async fn serve_process(
    mut child: Child,
    master: Option<Arc<AsyncFd<OwnedFd>>>,
    channel: Channel<Msg>,
    handle: server::Handle,
    id: ChannelId,
    mut cancel: watch::Receiver<bool>,
) -> Result<()> {
    let group = ProcessGroup(child.id().context("missing shell pid")?);
    // into_stream() closes on drop, which can race the exit-status message.
    let (mut incoming_channel, outgoing_channel) = channel.split();
    let mut outgoing = outgoing_channel.make_writer();
    let input;
    let output;
    let error_output;
    if let Some(master) = master {
        let writer = master.clone();
        input = tokio::spawn(async move {
            let mut incoming = incoming_channel.make_reader();
            let mut buffer = [0; 8192];
            while let Ok(n) = incoming.read(&mut buffer).await {
                if n == 0 {
                    let _ = fd_write(&writer, b"\x04").await;
                    break;
                }
                if fd_write(&writer, &buffer[..n]).await.is_err() {
                    break;
                }
            }
        });
        output = tokio::spawn(async move {
            let mut buffer = [0; 8192];
            loop {
                let n = fd_read(&master, &mut buffer).await?;
                if n == 0 {
                    break;
                }
                outgoing.write_all(&buffer[..n]).await?;
            }
            Ok::<_, io::Error>(())
        });
        error_output = None;
    } else {
        let mut stdin = child.stdin.take().context("missing stdin")?;
        let mut stdout = child.stdout.take().context("missing stdout")?;
        let mut stderr = child.stderr.take().context("missing stderr")?;
        input = tokio::spawn(async move {
            let mut incoming = incoming_channel.make_reader();
            let _ = tokio::io::copy(&mut incoming, &mut stdin).await;
        });
        output = tokio::spawn(async move {
            tokio::io::copy(&mut stdout, &mut outgoing)
                .await
                .map(|_| ())
        });
        let handle = handle.clone();
        error_output = Some(tokio::spawn(async move {
            forward_stderr(&mut stderr, handle, id).await
        }));
    }
    let status = tokio::select! {
        status = child.wait() => status?,
        _ = cancel.changed() => {
            drop(group);
            child.wait().await?
        }
    };
    input.abort();
    // Background jobs can retain stdout after their shell exits: don't wait forever.
    let mut output = output;
    let _ = tokio::time::timeout(Duration::from_secs(2), &mut output).await;
    output.abort();
    if let Some(mut errors) = error_output {
        let _ = tokio::time::timeout(Duration::from_secs(2), &mut errors).await;
        errors.abort();
    }
    use std::os::unix::process::ExitStatusExt;
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)) as u32;
    let _ = handle.exit_status_request(id, code).await;
    let _ = handle.eof(id).await;
    let _ = handle.close(id).await;
    Ok(())
}

async fn forward_stderr(
    reader: &mut (impl AsyncRead + Unpin),
    handle: server::Handle,
    id: ChannelId,
) -> Result<()> {
    let mut buffer = [0; 8192];
    loop {
        let n = reader.read(&mut buffer).await?;
        if n == 0 {
            return Ok(());
        }
        if handle
            .extended_data(id, 1, buffer[..n].to_vec())
            .await
            .is_err()
        {
            return Ok(());
        }
    }
}

async fn fd_read(fd: &AsyncFd<OwnedFd>, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        let mut ready = fd.readable().await?;
        match ready.try_io(|fd| {
            let n = unsafe { libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
            if n < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EIO) {
                    Ok(0)
                } else {
                    Err(error)
                }
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(result) => return result,
            Err(_) => continue,
        }
    }
}

async fn fd_write(fd: &AsyncFd<OwnedFd>, mut buffer: &[u8]) -> io::Result<()> {
    while !buffer.is_empty() {
        let mut ready = fd.writable().await?;
        match ready.try_io(|fd| {
            let n = unsafe { libc::write(fd.as_raw_fd(), buffer.as_ptr().cast(), buffer.len()) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(result) => buffer = &buffer[result?..],
            Err(_) => continue,
        }
    }
    Ok(())
}
