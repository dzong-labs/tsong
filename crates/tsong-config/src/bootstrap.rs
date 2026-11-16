//! The bootstrap file: where the config comes from, and the admin listener.
//! It is deployed with Tsong, because the settings that say where the
//! config lives can't live in that config.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ipnet::IpNet;
use serde::Deserialize;

use crate::{Problems, duration};

/// A whole bootstrap file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    pub source: Source,
    /// The admin listener, which serves the status endpoint. Unset, there
    /// is none.
    pub admin: Option<Admin>,
    /// The Git host's push webhook, on its own listener. Unset, only
    /// polling reloads.
    pub webhook: Option<Webhook>,
}

/// Where the config comes from.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "store", rename_all = "lowercase", deny_unknown_fields)]
pub enum Source {
    /// A TOML file on disk, relative to the bootstrap file. It is read once.
    File { path: PathBuf },
    /// A file on a Git branch, reloaded when the branch moves.
    Git(GitSource),
}

/// A config file on a Git branch.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitSource {
    /// The repository, such as `ssh://git@github.com/example/config.git`.
    pub url: String,
    /// The branch to watch.
    pub branch: String,
    /// The folder within the repository that holds the config, as
    /// `CONFIG_FILE`. Empty for the repository's root.
    pub folder: String,
    /// Where Tsong keeps its bare clone.
    pub checkout: PathBuf,
    /// The deploy key SSH authenticates with.
    pub ssh_key: Option<PathBuf>,
    /// The host keys SSH accepts. Set with `ssh_key`.
    pub known_hosts: Option<PathBuf>,
    /// How often the branch is fetched when no webhook arrives.
    #[serde(default = "default_poll", with = "duration")]
    pub poll: Duration,
}

/// How a Git source's url is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    /// `ssh://`, or scp-like `user@host:path`: authenticated by the deploy
    /// key against pinned host keys.
    Ssh,
    /// A path or `file://` url on this machine.
    Local,
    /// Anything else, such as `http://` or `git://`, which nothing
    /// authenticates.
    Other,
}

fn transport(url: &str) -> Transport {
    if url.starts_with("ssh://") {
        return Transport::Ssh;
    }
    if url.starts_with("file://") {
        return Transport::Local;
    }
    if url.contains("://") {
        return Transport::Other;
    }
    // scp-like syntax: a colon before any slash, after something that
    // isn't a Windows drive letter.
    match url.split_once(':') {
        Some((host, _)) if host.len() > 1 && !host.contains('/') => Transport::Ssh,
        _ => Transport::Local,
    }
}

/// The config file's name within a Git source's folder.
pub const CONFIG_FILE: &str = "tsong.toml";

fn default_poll() -> Duration {
    Duration::from_secs(5 * 60)
}

/// The admin listener. It admits the clients in the served config's
/// `gateway.allow`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admin {
    pub listen: SocketAddr,
}

/// A Git host's push webhook, on its own listener.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Webhook {
    pub listen: SocketAddr,
    /// The addresses the Git host delivers from. Each connection's peer
    /// address must be in it; no `X-Forwarded-For` is read, since nothing
    /// should proxy this listener.
    pub allow: Vec<IpNet>,
    pub host: GitHost,
    /// The environment variable holding the webhook secret.
    pub secret_env: String,
}

/// A Git host, which decides how webhooks are verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GitHost {
    /// Signs each delivery with HMAC-SHA256 in `X-Hub-Signature-256`.
    GitHub,
    /// Sends the shared secret in `X-Gitlab-Token`.
    GitLab,
}

/// Why a bootstrap file didn't load.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("reading {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parsing the bootstrap file: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid bootstrap file:\n{0}")]
    Invalid(Problems),
}

impl Bootstrap {
    /// Parses and validates a bootstrap document.
    pub fn from_toml(text: &str) -> Result<Self, BootstrapError> {
        let bootstrap: Self = toml::from_str(text)?;
        bootstrap.validate().map_err(BootstrapError::Invalid)?;
        Ok(bootstrap)
    }

    /// Reads a bootstrap file. A file source's path is taken from the
    /// bootstrap file's directory.
    pub fn load(path: &Path) -> Result<Self, BootstrapError> {
        let text = std::fs::read_to_string(path).map_err(|source| BootstrapError::Read {
            path: path.to_owned(),
            source,
        })?;
        let mut bootstrap = Self::from_toml(&text)?;
        let dir = path.parent().unwrap_or(Path::new(""));
        match &mut bootstrap.source {
            Source::File { path: file } => *file = dir.join(&*file),
            Source::Git(git) => {
                git.checkout = dir.join(&git.checkout);
                for file in [&mut git.ssh_key, &mut git.known_hosts]
                    .into_iter()
                    .flatten()
                {
                    *file = dir.join(&*file);
                }
                let local = transport(&git.url) == Transport::Local;
                if local && !git.url.starts_with("file://") && Path::new(&git.url).is_relative() {
                    git.url = dir.join(&git.url).display().to_string();
                }
            }
        }
        Ok(bootstrap)
    }

    fn validate(&self) -> Result<(), Problems> {
        let mut problems = Vec::new();
        if let Source::Git(GitSource {
            url,
            branch,
            folder,
            ssh_key,
            known_hosts,
            poll,
            ..
        }) = &self.source
        {
            for (field, value) in [("url", url), ("branch", branch)] {
                if value.is_empty() {
                    problems.push(format!("source.{field} is empty"));
                }
            }
            if folder.starts_with('/') || folder.split('/').any(|part| part == "..") {
                problems.push("source.folder must be within the repository".into());
            }
            match transport(url) {
                _ if url.is_empty() => {}
                Transport::Ssh => {
                    if ssh_key.is_none() || known_hosts.is_none() {
                        problems.push(
                            "source.ssh_key and source.known_hosts are required for an ssh url"
                                .into(),
                        );
                    }
                }
                Transport::Local => {
                    if ssh_key.is_some() || known_hosts.is_some() {
                        problems.push(
                            "source.ssh_key and source.known_hosts are for an ssh url".into(),
                        );
                    }
                }
                Transport::Other => problems.push(
                    "source.url must be an ssh url or a local path; other transports are not supported"
                        .into(),
                ),
            }
            if poll.is_zero() {
                problems.push("source.poll must be above zero".into());
            }
        }
        if let Some(webhook) = &self.webhook {
            if !matches!(self.source, Source::Git(_)) {
                problems.push("webhook needs a git source".into());
            }
            if webhook.allow.is_empty() {
                problems.push("webhook.allow is empty, so no delivery can arrive".into());
            }
            if webhook.secret_env.is_empty() {
                problems.push("webhook.secret_env is empty".into());
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(Problems(problems))
        }
    }
}
