//! The SSH server: tinyssh, with init.json's logins, accounts and environment.

use crate::{
    config::{Config, User},
    unix,
};
use anyhow::{Context, Result, bail, ensure};
use data_encoding::{BASE64, BASE64_NOPAD};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, ffi::OsStr, fs, io, os::unix::ffi::OsStrExt, time::Instant};
use tinyssh::{HostKey, Launch, Launcher, PublicKey, SpawnRequest};

const ED25519: &[u8] = b"ssh-ed25519";

struct Authorized {
    user: User,
    keys: Vec<PublicKey>,
}

fn authorized(config: &Config) -> Result<Vec<Authorized>> {
    config
        .ssh
        .logins
        .iter()
        .map(|login| {
            ensure!(
                !login.public_keys.is_empty(),
                "no keys for SSH user {}",
                login.user
            );
            let keys = login
                .public_keys
                .iter()
                .map(|key| {
                    public_key(key).context(
                        "invalid SSH public key (use plain OpenSSH ssh-ed25519 public keys, \
                         without authorized_keys options)",
                    )
                })
                .collect::<Result<_>>()?;
            Ok(Authorized {
                user: config.user(&login.user)?,
                keys,
            })
        })
        .collect()
}

pub fn validate_keys(config: &Config) -> Result<()> {
    authorized(config).map(|_| ())
}

pub async fn run(config: Config) -> Result<()> {
    let started = Instant::now();
    let logins: &'static [Authorized] = Box::leak(authorized(&config)?.into_boxed_slice());
    eprintln!(
        "tinyinit sshd: stage=authorization elapsed_ms={:.3}",
        started.elapsed().as_secs_f64() * 1000.0
    );
    let key_started = Instant::now();
    let host_key = match &config.ssh.host_key {
        Some(path) => {
            host_key(&fs::read_to_string(path).with_context(|| format!("read host key {path}"))?)
                .with_context(|| format!("load host key {path}"))?
        }
        None => {
            eprintln!("tinyinit sshd: using an ephemeral host key (changes on every boot)");
            HostKey::generate().context("generate host key")?
        }
    };
    eprintln!(
        "tinyinit sshd: host key {} duration_ms={:.3}",
        fingerprint(&host_key.public_key()),
        key_started.elapsed().as_secs_f64() * 1000.0
    );
    let mut server = tinyssh::Config::new(host_key, move |name: &str, key: &PublicKey| {
        logins
            .iter()
            .any(|login| login.user.name == name && login.keys.contains(key))
    });
    server.launcher = Some(Box::new(Sessions {
        logins,
        env: config.env,
    }));
    eprintln!(
        "tinyinit sshd: max_auth_attempts={} login_timeout_ms={} max_connections={}",
        server.max_auth_attempts,
        server.login_timeout.as_millis(),
        server.max_connections
    );
    let server: &'static tinyssh::Config = Box::leak(Box::new(server));
    let listener = tokio::net::TcpListener::bind(&config.ssh.listen).await?;
    eprintln!(
        "tinyinit sshd: listening on {} event=listener-ready startup_ms={:.3} kernel_uptime_ms={:.3}",
        config.ssh.listen,
        started.elapsed().as_secs_f64() * 1000.0,
        unix::uptime_ms()?
    );
    tinyssh::serve(listener, server).await
}

/// Starts SSH sessions as init.json resolves the login's account, with its
/// environment, rather than as the image's /etc/passwd says.
struct Sessions {
    logins: &'static [Authorized],
    env: BTreeMap<String, String>,
}

impl Launcher for Sessions {
    fn launch(&self, request: &SpawnRequest<'_>) -> io::Result<Launch> {
        let user = &self
            .logins
            .iter()
            .find(|login| login.user.name == request.user)
            .ok_or_else(|| io::Error::other("unknown user"))?
            .user;
        let mut command = unix::command(user, "/bin/tinyinit", &user.home, &self.env);
        command.arg("shell");
        if let Some(line) = request.command {
            command.arg("-c").arg(OsStr::from_bytes(line));
        }
        // No new session here: tinyssh makes the shell a session leader, with
        // its terminal, after these steps.
        unix::child_setup(
            &mut command,
            user,
            None,
            false,
            user.uid != 0,
            unix::Spawn::default(),
        );
        Ok(Launch {
            command,
            terminal_owner: Some(user.uid),
        })
    }
}

/// An OpenSSH public key line: `ssh-ed25519 BASE64 [COMMENT]`.
fn public_key(line: &str) -> Result<PublicKey> {
    let mut fields = line.split_whitespace();
    ensure!(
        fields.next().map(str::as_bytes) == Some(ED25519),
        "only ssh-ed25519 keys are supported"
    );
    let blob = BASE64
        .decode(fields.next().unwrap_or_default().as_bytes())
        .context("key is not base64")?;
    let mut blob = Wire(&blob);
    let key = ed25519(&mut blob)?;
    ensure!(blob.0.is_empty(), "trailing data after the key");
    Ok(key)
}

/// An unencrypted OpenSSH Ed25519 private key file, as `ssh-keygen -t
/// ed25519 -N ''` writes it.
fn host_key(text: &str) -> Result<HostKey> {
    let body: String = text
        .trim()
        .strip_prefix("-----BEGIN OPENSSH PRIVATE KEY-----")
        .and_then(|rest| rest.strip_suffix("-----END OPENSSH PRIVATE KEY-----"))
        .context("not an OpenSSH private key; create one with ssh-keygen -t ed25519 -N ''")?
        .split_whitespace()
        .collect();
    let data = BASE64
        .decode(body.as_bytes())
        .context("key is not base64")?;
    let mut file = Wire(
        data.strip_prefix(b"openssh-key-v1\0")
            .context("not an OpenSSH private key")?,
    );
    let (cipher, kdf) = (file.string()?, file.string()?);
    ensure!(
        cipher == b"none" && kdf == b"none",
        "encrypted host keys are not supported"
    );
    file.string()?;
    ensure!(file.u32()? == 1, "expected exactly one key");
    let public = ed25519(&mut Wire(file.string()?))?;
    let mut private = Wire(file.string()?);
    ensure!(private.u32()? == private.u32()?, "corrupt private key");
    let inner = ed25519(&mut private)?;
    // The secret key is the 32-byte seed followed by the public key.
    let secret = private.string()?;
    let (Some(seed), Some(tail)) = (secret.first_chunk::<32>(), secret.get(32..)) else {
        bail!("corrupt private key");
    };
    let key = HostKey::from_seed(seed);
    // The file holds the public key three times; each must be the seed's.
    ensure!(
        key.public_key() == public && inner == public && tail == public.as_bytes(),
        "corrupt private key: its public keys do not match"
    );
    Ok(key)
}

/// Reads an `ssh-ed25519` public key in SSH wire encoding.
fn ed25519(wire: &mut Wire) -> Result<PublicKey> {
    ensure!(
        wire.string()? == ED25519,
        "only ssh-ed25519 keys are supported"
    );
    let key = wire.string()?;
    Ok(PublicKey::from_bytes(
        key.try_into().context("an Ed25519 key has 32 bytes")?,
    ))
}

/// The SSH wire encoding of `key`.
fn blob(key: &PublicKey) -> Vec<u8> {
    let mut blob = Vec::new();
    for part in [ED25519, key.as_bytes()] {
        blob.extend_from_slice(&(part.len() as u32).to_be_bytes());
        blob.extend_from_slice(part);
    }
    blob
}

/// The fingerprint `ssh-keygen -l` shows.
fn fingerprint(key: &PublicKey) -> String {
    format!("SHA256:{}", BASE64_NOPAD.encode(&Sha256::digest(blob(key))))
}

/// Reads SSH wire-format fields (RFC 4251).
struct Wire<'a>(&'a [u8]);

impl<'a> Wire<'a> {
    fn bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        ensure!(self.0.len() >= len, "truncated key");
        let (head, tail) = self.0.split_at(len);
        self.0 = tail;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.bytes(4)?.try_into()?))
    }

    fn string(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.bytes(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    // From `ssh-keygen -t ed25519 -C test@tinyinit` and `ssh-keygen -l`.
    const PUBLIC: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINWauYHquFmI4/Nk2jTnrxpRmSHg0CSdccNP7oBsFkQt test@tinyinit";
    const FINGERPRINT: &str = "SHA256:dezTwKPZjsHOOzqmzXluxK3sflao6WKhRcUS+/iqVaI";

    #[test]
    fn public_keys_are_plain_openssh_ed25519_lines() {
        let key = public_key(PUBLIC).unwrap();
        assert_eq!(fingerprint(&key), FINGERPRINT);
        assert_eq!(
            BASE64.encode(&blob(&key)),
            PUBLIC.split(' ').nth(1).unwrap()
        );
        let bare = PUBLIC.rsplit_once(' ').unwrap().0;
        assert_eq!(public_key(bare).unwrap(), key);
        for bad in [
            "not a valid key",
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDS5vVS rsa",
            // An RSA key labelled as Ed25519.
            "ssh-ed25519 AAAAB3NzaC1yc2EAAAADAQABAAABAQDS5vVS",
            &format!("from=\"10.0.0.1\" {PUBLIC}"),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINWauYHquFmI4/Nk2jTnrxpRmSHg0CSdccNP7oBs",
            "ssh-ed25519 !!!!",
            "ssh-ed25519",
        ] {
            assert!(public_key(bad).is_err(), "{bad}");
        }
    }

    /// Host keys load from the files `ssh-keygen` writes, and match the
    /// public key and fingerprint it reports. Skipped without `ssh-keygen`.
    #[test]
    fn host_keys_load_from_ssh_keygen_files() {
        let dir = std::env::temp_dir().join(format!("tinyinit-hostkey-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let keygen = |name: &str, passphrase: &str| {
            Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", passphrase, "-C", "", "-f"])
                .arg(dir.join(name))
                .status()
        };
        match keygen("plain", "") {
            Ok(status) => assert!(status.success()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                eprintln!("skipped: no ssh-keygen");
                return;
            }
            Err(error) => panic!("{error}"),
        }
        assert!(keygen("encrypted", "secret").unwrap().success());
        let read = |name: &str| fs::read_to_string(dir.join(name)).unwrap();
        let (plain, public, encrypted) = (read("plain"), read("plain.pub"), read("encrypted"));
        let listed = Command::new("ssh-keygen")
            .arg("-lf")
            .arg(dir.join("plain.pub"))
            .output()
            .unwrap();
        fs::remove_dir_all(&dir).unwrap();
        let key = host_key(&plain).unwrap();
        assert_eq!(key.public_key(), public_key(&public).unwrap());
        let listed = String::from_utf8(listed.stdout).unwrap();
        assert_eq!(
            listed.split(' ').nth(1),
            Some(fingerprint(&key.public_key()).as_str())
        );
        assert!(host_key(&encrypted).is_err());
        assert!(host_key(PUBLIC).is_err());
    }
}
