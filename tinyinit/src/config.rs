use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    path::{Component, Path},
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "hostname")]
    pub hostname: String,
    /// Environment defaults for applications and SSH sessions; app `env` wins.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Resource limits for every process init starts; app `rlimits` win.
    #[serde(default)]
    pub rlimits: BTreeMap<String, Rlimit>,
    #[serde(default)]
    pub sysctls: BTreeMap<String, SysctlValue>,
    /// tmpfs `size=` limits keyed by mountpoint.
    #[serde(default)]
    pub tmpfs: BTreeMap<String, String>,
    #[serde(default)]
    pub logs: Logs,
    #[serde(default)]
    pub mounts: Vec<Share>,
    #[serde(default)]
    pub users: Vec<User>,
    pub apps: Vec<App>,
    pub ssh: Ssh,
    #[serde(default)]
    pub network: Option<Network>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Share {
    pub tag: String,
    pub target: String,
    #[serde(default = "yes")]
    pub readonly: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct App {
    pub name: String,
    pub user: String,
    pub argv: Vec<String>,
    #[serde(default = "root_dir")]
    pub cwd: String,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Supplementary group IDs.
    #[serde(default)]
    pub groups: Vec<u32>,
    /// Octal file-creation mask such as "0027"; init's default is 0022.
    #[serde(default)]
    pub umask: Option<String>,
    /// Capabilities granted as ambient capabilities, such as CAP_NET_BIND_SERVICE.
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub rlimits: BTreeMap<String, Rlimit>,
    #[serde(default)]
    pub limits: Limits,
}

/// A number or "unlimited" sets both limits; `{"soft": .., "hard": ..}` sets each.
#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Rlimit {
    Both(RlimitValue),
    Split(RlimitPair),
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RlimitPair {
    pub soft: RlimitValue,
    pub hard: RlimitValue,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum RlimitValue {
    Number(u64),
    Text(String),
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SysctlValue {
    Integer(i64),
    Text(String),
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Logs {
    /// Per-file cap; each stream also keeps one rotated `.1` file.
    #[serde(default = "log_max_bytes")]
    pub max_bytes: u64,
}

impl Default for Logs {
    fn default() -> Self {
        Self {
            max_bytes: log_max_bytes(),
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub memory_max: Option<u64>,
    pub pids_max: Option<u32>,
    pub cpu_percent: Option<u32>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ssh {
    #[serde(default = "listen")]
    pub listen: String,
    #[serde(default)]
    pub host_key: Option<String>,
    pub logins: Vec<Login>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Login {
    pub user: String,
    #[serde(default)]
    pub public_keys: Vec<String>,
    #[serde(default)]
    pub public_keys_file: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub interface: String,
    pub address: String,
    pub gateway: String,
    #[serde(default)]
    pub dns: Vec<String>,
}

fn hostname() -> String {
    "tinyvm".into()
}
fn log_max_bytes() -> u64 {
    8 << 20
}

/// Linux resource names, as used by `ulimit` and Docker's `--ulimit`.
const RLIMITS: [(&str, u32); 16] = [
    ("cpu", libc::RLIMIT_CPU as u32),
    ("fsize", libc::RLIMIT_FSIZE as u32),
    ("data", libc::RLIMIT_DATA as u32),
    ("stack", libc::RLIMIT_STACK as u32),
    ("core", libc::RLIMIT_CORE as u32),
    ("rss", libc::RLIMIT_RSS as u32),
    ("nproc", libc::RLIMIT_NPROC as u32),
    ("nofile", libc::RLIMIT_NOFILE as u32),
    ("memlock", libc::RLIMIT_MEMLOCK as u32),
    ("as", libc::RLIMIT_AS as u32),
    ("locks", libc::RLIMIT_LOCKS as u32),
    ("sigpending", libc::RLIMIT_SIGPENDING as u32),
    ("msgqueue", libc::RLIMIT_MSGQUEUE as u32),
    ("nice", libc::RLIMIT_NICE as u32),
    ("rtprio", libc::RLIMIT_RTPRIO as u32),
    ("rttime", libc::RLIMIT_RTTIME as u32),
];

/// Linux capability names in bit order.
const CAPABILITIES: [&str; 41] = [
    "chown",
    "dac_override",
    "dac_read_search",
    "fowner",
    "fsetid",
    "kill",
    "setgid",
    "setuid",
    "setpcap",
    "linux_immutable",
    "net_bind_service",
    "net_broadcast",
    "net_admin",
    "net_raw",
    "ipc_lock",
    "ipc_owner",
    "sys_module",
    "sys_rawio",
    "sys_chroot",
    "sys_ptrace",
    "sys_pacct",
    "sys_admin",
    "sys_boot",
    "sys_nice",
    "sys_resource",
    "sys_time",
    "sys_tty_config",
    "mknod",
    "lease",
    "audit_write",
    "audit_control",
    "setfcap",
    "mac_override",
    "mac_admin",
    "syslog",
    "wake_alarm",
    "block_suspend",
    "audit_read",
    "perfmon",
    "bpf",
    "checkpoint_restore",
];

pub const TMPFS_MOUNTS: [&str; 4] = ["/", "/run", "/tmp", "/dev/shm"];

impl RlimitValue {
    fn get(&self) -> Result<u64> {
        match self {
            Self::Number(value) => Ok(*value),
            Self::Text(text) if text == "unlimited" => Ok(libc::RLIM_INFINITY),
            Self::Text(text) => bail!("invalid rlimit value {text:?}"),
        }
    }
}

/// Resolve named limits to `(resource, soft, hard)`.
pub fn rlimits<'a>(
    entries: impl IntoIterator<Item = (&'a String, &'a Rlimit)>,
) -> Result<Vec<(u32, u64, u64)>> {
    entries
        .into_iter()
        .map(|(name, limit)| {
            let resource = RLIMITS
                .iter()
                .find(|(known, _)| known == name)
                .map(|(_, resource)| *resource)
                .with_context(|| format!("unknown rlimit {name:?}"))?;
            let (soft, hard) = match limit {
                Rlimit::Both(value) => (value.get()?, value.get()?),
                Rlimit::Split(pair) => (pair.soft.get()?, pair.hard.get()?),
            };
            ensure!(soft <= hard, "rlimit {name} soft value exceeds hard value");
            Ok((resource, soft, hard))
        })
        .collect()
}

impl App {
    pub fn umask_bits(&self) -> Result<Option<u32>> {
        self.umask
            .as_deref()
            .map(|text| {
                ensure!(
                    !text.is_empty()
                        && text.len() <= 4
                        && text.bytes().all(|b| (b'0'..=b'7').contains(&b)),
                    "umask must be octal, such as \"0027\""
                );
                let mask = u32::from_str_radix(text, 8)?;
                ensure!(mask <= 0o777, "umask must be at most 0777");
                Ok(mask)
            })
            .transpose()
    }

    pub fn capability_mask(&self) -> Result<u64> {
        self.capabilities.iter().try_fold(0, |mask, name| {
            let lower = name.to_ascii_lowercase();
            let short = lower.strip_prefix("cap_").unwrap_or(&lower);
            let bit = CAPABILITIES
                .iter()
                .position(|known| *known == short)
                .with_context(|| format!("unknown capability {name:?}"))?;
            Ok(mask | 1 << bit)
        })
    }
}

impl std::fmt::Display for SysctlValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Integer(value) => write!(f, "{value}"),
            Self::Text(value) => f.write_str(value),
        }
    }
}

fn sysctl_name_ok(name: &str) -> bool {
    name.contains('.')
        && name.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        })
}

fn tmpfs_size_ok(size: &str) -> bool {
    let split = size
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(size.len());
    let (digits, suffix) = size.split_at(split);
    let Ok(value) = digits.parse::<u64>() else {
        return false;
    };
    value > 0
        && match suffix {
            "" | "k" | "K" | "m" | "M" | "g" | "G" => true,
            "%" => value <= 100,
            _ => false,
        }
}
fn listen() -> String {
    "0.0.0.0:22".into()
}
fn root_dir() -> String {
    "/".into()
}
fn yes() -> bool {
    true
}

pub fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
}

fn absolute(path: &str) -> bool {
    Path::new(path).is_absolute()
        && !path.contains(['\0', '\n', ':'])
        && !Path::new(path)
            .components()
            .any(|c| c == Component::ParentDir)
}

impl Config {
    pub fn read(path: &str) -> Result<Self> {
        let config: Self =
            serde_json::from_slice(&fs::read(path).with_context(|| format!("read {path}"))?)
                .with_context(|| format!("parse {path}"))?;
        config.validate()?;
        Ok(config)
    }

    pub fn user(&self, name: &str) -> Result<User> {
        if name == "root" {
            return Ok(User {
                name: "root".into(),
                uid: 0,
                gid: 0,
                home: "/root".into(),
            });
        }
        self.users
            .iter()
            .find(|u| u.name == name)
            .cloned()
            .with_context(|| format!("unknown user {name:?}"))
    }

    /// Global rlimits, with this app's entries replacing the same resources.
    pub fn app_rlimits(&self, app: &App) -> Result<Vec<(u32, u64, u64)>> {
        let mut merged = self.rlimits.clone();
        merged.extend(app.rlimits.clone());
        rlimits(&merged)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(name_ok(&self.hostname), "invalid hostname");
        for (key, value) in self
            .env
            .iter()
            .chain(self.apps.iter().flat_map(|app| &app.env))
        {
            ensure!(
                !key.is_empty() && !key.contains(['=', '\0']) && !value.contains('\0'),
                "invalid environment variable {key:?}"
            );
        }
        rlimits(&self.rlimits)?;
        for (name, value) in &self.sysctls {
            ensure!(
                sysctl_name_ok(name) && !value.to_string().contains(['\0', '\n']),
                "invalid sysctl {name:?}"
            );
        }
        for (target, size) in &self.tmpfs {
            ensure!(
                TMPFS_MOUNTS.contains(&target.as_str()),
                "tmpfs limits apply only to {}",
                TMPFS_MOUNTS.join(", ")
            );
            ensure!(
                tmpfs_size_ok(size),
                "invalid tmpfs size {size:?} for {target}"
            );
        }
        ensure!(
            self.logs.max_bytes >= 4096,
            "logs.max_bytes must be at least 4096"
        );
        let mut names = HashSet::new();
        let mut uids = HashSet::new();
        for u in &self.users {
            ensure!(
                name_ok(&u.name) && u.name != "root" && u.uid != 0 && u.gid != 0,
                "invalid unprivileged user"
            );
            ensure!(
                names.insert(&u.name) && uids.insert(u.uid),
                "duplicate user name or uid"
            );
            ensure!(
                absolute(&u.home) && u.home.starts_with("/home/"),
                "user home must be under /home"
            );
        }
        names.clear();
        for app in &self.apps {
            ensure!(
                name_ok(&app.name) && app.name != "sshd" && names.insert(&app.name),
                "invalid or duplicate app name"
            );
            ensure!(
                self.user(&app.user)?.uid != 0,
                "apps must run as non-root users"
            );
            ensure!(
                !app.argv.is_empty() && absolute(&app.argv[0]),
                "app argv must start with an absolute executable"
            );
            ensure!(absolute(&app.cwd), "app cwd must be absolute");
            ensure!(
                app.limits.cpu_percent != Some(0) && app.limits.pids_max != Some(0),
                "invalid zero limit"
            );
            let context = || format!("app {}", app.name);
            self.app_rlimits(app).with_context(context)?;
            app.umask_bits().with_context(context)?;
            app.capability_mask().with_context(context)?;
            let mut groups = HashSet::new();
            ensure!(
                app.groups.len() <= 64
                    && app
                        .groups
                        .iter()
                        .all(|gid| *gid != 0 && groups.insert(*gid)),
                "app {} groups must be unique non-root GIDs (at most 64)",
                app.name
            );
        }
        ensure!(!self.apps.is_empty(), "at least one app is required");
        let mut targets = HashSet::new();
        for share in &self.mounts {
            ensure!(
                !share.tag.is_empty() && !share.tag.contains(['\0', ',']),
                "invalid share tag"
            );
            ensure!(
                absolute(&share.target)
                    && share.target.starts_with("/mnt/")
                    && targets.insert(&share.target),
                "share target must be unique and under /mnt"
            );
        }
        ensure!(
            !self.ssh.logins.is_empty(),
            "at least one SSH login is required"
        );
        names.clear();
        for login in &self.ssh.logins {
            self.user(&login.user)?;
            ensure!(names.insert(&login.user), "duplicate SSH login");
            ensure!(
                !login.public_keys.is_empty() || login.public_keys_file.is_some(),
                "SSH login needs a public key"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        serde_json::from_str(
            r#"{
          "users":[{"name":"app","uid":1000,"gid":1000,"home":"/home/app"}],
          "apps":[{"name":"a","user":"app","argv":["/bin/sleep","100"]}],
          "ssh":{"logins":[{"user":"root","public_keys":["key"]}]}
        }"#,
        )
        .unwrap()
    }

    #[test]
    fn root_login_does_not_make_apps_root() {
        let mut c = config();
        c.validate().unwrap();
        c.apps[0].user = "root".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_colliding_services_and_escaping_mounts() {
        let mut c = config();
        c.apps.push(c.apps[0].clone());
        assert!(c.validate().is_err());
        c.apps.pop();
        c.mounts.push(Share {
            tag: "x".into(),
            target: "/mnt/../etc".into(),
            readonly: true,
        });
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_unknown_users_and_missing_keys() {
        let mut c = config();
        c.ssh.logins[0].user = "missing".into();
        assert!(c.validate().is_err());
        c.ssh.logins[0].user = "root".into();
        c.ssh.logins[0].public_keys.clear();
        assert!(c.validate().is_err());
    }

    #[test]
    fn process_settings_validate_merge_and_round_trip() {
        let c: Config = serde_json::from_str(
            r#"{
          "env":{"LANG":"C.UTF-8"},
          "rlimits":{"nofile":1048576,"core":"unlimited"},
          "sysctls":{"net.core.somaxconn":1024,"net.ipv4.ip_local_port_range":"1024 65000"},
          "tmpfs":{"/":"75%","/run":"64m"},
          "users":[{"name":"app","uid":1000,"gid":1000,"home":"/home/app"}],
          "apps":[{"name":"a","user":"app","argv":["/bin/sleep","100"],"groups":[2000],
            "umask":"0027","capabilities":["CAP_NET_BIND_SERVICE","sys_nice"],
            "rlimits":{"nofile":{"soft":4096,"hard":8192}}}],
          "ssh":{"logins":[{"user":"root","public_keys":["key"]}]}
        }"#,
        )
        .unwrap();
        c.validate().unwrap();
        let app = &c.apps[0];
        assert_eq!(
            c.app_rlimits(app).unwrap(),
            [
                (
                    libc::RLIMIT_CORE as u32,
                    libc::RLIM_INFINITY,
                    libc::RLIM_INFINITY
                ),
                (libc::RLIMIT_NOFILE as u32, 4096, 8192),
            ]
        );
        assert_eq!(app.umask_bits().unwrap(), Some(0o027));
        assert_eq!(app.capability_mask().unwrap(), 1 << 10 | 1 << 23);
        // sshd re-reads the config that PID 1 saves.
        let saved: Config = serde_json::from_slice(&serde_json::to_vec(&c).unwrap()).unwrap();
        saved.validate().unwrap();

        let broken: [fn(&mut Config); 7] = [
            |c| c.apps[0].capabilities.push("CAP_NOT_REAL".into()),
            |c| c.apps[0].umask = Some("0999".into()),
            |c| c.apps[0].groups.push(0),
            |c| {
                c.rlimits.insert(
                    "nofile".into(),
                    Rlimit::Split(RlimitPair {
                        soft: RlimitValue::Number(10),
                        hard: RlimitValue::Number(5),
                    }),
                );
            },
            |c| {
                c.tmpfs.insert("/var".into(), "1m".into());
            },
            |c| {
                c.tmpfs.insert("/run".into(), "0".into());
            },
            |c| {
                c.sysctls
                    .insert("../etc".into(), SysctlValue::Text("1".into()));
            },
        ];
        for change in broken {
            let mut bad = c.clone();
            change(&mut bad);
            assert!(bad.validate().is_err());
        }
    }
}
