use anyhow::{Context, Result, ensure};
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
    #[serde(default)]
    pub limits: Limits,
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

    pub fn validate(&self) -> Result<()> {
        ensure!(name_ok(&self.hostname), "invalid hostname");
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
}
