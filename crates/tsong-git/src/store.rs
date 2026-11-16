//! A config store that reads `tsong.toml` from a folder on a Git branch.

use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use gix::config::tree::Core;
use gix::remote::Direction;
use tsong_config::{
    CONFIG_FILE, Config, ConfigError, ConfigStore, GitSource, LoadFuture, Problems, Snapshot,
};

/// The longest a fetch may take before it is abandoned.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(120);

/// Reads the config from a branch of a Git repository. It keeps a bare
/// clone, fetches only the branch, and reads the file from the fetched
/// commit without checking anything out.
#[derive(Debug, Clone)]
pub struct GitStore {
    url: String,
    branch: String,
    folder: String,
    checkout: PathBuf,
    ssh_command: Option<String>,
    timeout: Duration,
}

/// What a fetch found: the commit, its author, and the config file's blob
/// ID and text.
struct Fetched {
    commit: String,
    author: Option<String>,
    blob: String,
    text: String,
}

/// Sets its flag when dropped, so a fetch abandoned by a timeout or a
/// shutdown is told to stop.
pub struct Interrupt(pub Arc<AtomicBool>);

impl Drop for Interrupt {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

impl GitStore {
    /// The store for a git source.
    pub fn new(source: &GitSource) -> Self {
        let ssh_command = match (&source.ssh_key, &source.known_hosts) {
            (Some(key), Some(hosts)) => Some(ssh_command(key, hosts)),
            _ => None,
        };
        Self {
            url: source.url.clone(),
            branch: source.branch.clone(),
            folder: source.folder.clone(),
            checkout: source.checkout.clone(),
            ssh_command,
            timeout: FETCH_TIMEOUT,
        }
    }

    /// This store with fetches abandoned after `timeout`.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The config file's path within the repository.
    fn file(&self) -> String {
        match self.folder.trim_matches('/') {
            "" => CONFIG_FILE.to_owned(),
            folder => format!("{folder}/{CONFIG_FILE}"),
        }
    }

    /// Opens the clone, creating it when there is none yet or its directory
    /// is empty. A clone that exists but can't be opened is an error, not a
    /// reason to start over.
    fn repository(&self) -> Result<gix::Repository, String> {
        let empty = std::fs::read_dir(&self.checkout)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(false);
        if self.checkout.exists() && !empty {
            return gix::open(&self.checkout).map_err(failed("opening the clone"));
        }
        std::fs::create_dir_all(&self.checkout).map_err(failed("creating the clone"))?;
        gix::init_bare(&self.checkout).map_err(failed("creating the clone"))
    }

    /// Fetches the branch and reads the config file from its tip. Blocking;
    /// it stops early once `interrupt` is set.
    fn fetch(&self, interrupt: &AtomicBool) -> Result<Fetched, String> {
        let mut repo = self.repository()?;
        if let Some(command) = &self.ssh_command {
            let mut config = repo.config_snapshot_mut();
            config
                .set_value(&Core::SSH_COMMAND, command.as_str())
                .map_err(failed("setting the ssh command"))?;
            config.commit().map_err(failed("setting the ssh command"))?;
        }
        let tracking = format!("refs/remotes/origin/{}", self.branch);
        let refspec = format!("+refs/heads/{}:{tracking}", self.branch);
        repo.remote_at(self.url.as_str())
            .map_err(failed("reading the url"))?
            .with_refspecs(Some(refspec.as_str()), Direction::Fetch)
            .map_err(failed("setting the refspec"))?
            .connect(Direction::Fetch)
            .map_err(failed("connecting"))?
            .prepare_fetch(gix::progress::Discard, Default::default())
            .map_err(failed("fetching"))?
            .receive(gix::progress::Discard, interrupt)
            .map_err(failed("fetching"))?;

        let commit = repo
            .find_reference(tracking.as_str())
            .map_err(failed("finding the branch"))?
            .peel_to_commit()
            .map_err(failed("reading the branch's commit"))?;
        let author = commit
            .author()
            .ok()
            .map(|author| format!("{} <{}>", author.name, author.email));
        let file = self.file();
        let entry = commit
            .tree()
            .map_err(failed("reading the commit's tree"))?
            .lookup_entry_by_path(file.as_str())
            .map_err(failed("finding the config"))?
            .ok_or_else(|| format!("{file} is not on {}", self.branch))?;
        let blob = entry.object().map_err(failed("reading the config"))?;
        let text =
            String::from_utf8(blob.data.clone()).map_err(|_| format!("{file} is not UTF-8"))?;
        Ok(Fetched {
            commit: commit.id.to_string(),
            author,
            blob: blob.id.to_string(),
            text,
        })
    }
}

impl ConfigStore for GitStore {
    fn load(&self) -> LoadFuture<'_> {
        let store = self.clone();
        Box::pin(async move {
            let flag = Arc::new(AtomicBool::new(false));
            let interrupt = Interrupt(flag.clone());
            let timeout = store.timeout;
            let fetching = tokio::task::spawn_blocking(move || store.fetch(&flag));
            let fetched = tokio::time::timeout(timeout, fetching)
                .await
                .map_err(|_| ConfigError::Store(format!("fetching: timed out after {timeout:?}")))?
                .map_err(|error| ConfigError::Store(format!("fetching: {error}")))?
                .map_err(ConfigError::Store)?;
            drop(interrupt);
            let at_revision = |source: ConfigError| ConfigError::AtRevision {
                revision: fetched.commit.clone(),
                content: fetched.blob.clone(),
                author: fetched.author.clone(),
                source: Box::new(source),
            };
            let config = Config::from_toml(&fetched.text).map_err(at_revision)?;
            let relative = config.relative_key_paths();
            if !relative.is_empty() {
                let problems = relative
                    .into_iter()
                    .map(|kid| {
                        format!(
                            "issuer.signing.keys {kid:?} path must be absolute in a config from Git"
                        )
                    })
                    .collect();
                return Err(at_revision(ConfigError::Invalid(Problems(problems))));
            }
            Ok(Snapshot {
                config,
                revision: fetched.commit,
                content: fetched.blob,
                author: fetched.author,
            })
        })
    }
}

/// The `ssh` command line that authenticates with `key` and accepts only
/// the hosts in `known_hosts`, never prompting. It reads no `ssh_config`
/// and no system-wide known hosts, so nothing on the machine can loosen
/// host-key checking, and it gives up on a dead connection.
pub fn ssh_command(key: &Path, known_hosts: &Path) -> String {
    format!(
        "ssh -F /dev/null -i {} -o IdentitiesOnly=yes -o BatchMode=yes \
         -o StrictHostKeyChecking=yes -o UserKnownHostsFile={} \
         -o GlobalKnownHostsFile=/dev/null -o ConnectTimeout=15 \
         -o ServerAliveInterval=15 -o ServerAliveCountMax=3",
        quote(key),
        quote(known_hosts),
    )
}

/// `path` quoted for a POSIX shell.
fn quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', r"'\''"))
}

/// An error mapper that names the step that failed.
fn failed<E: Display>(step: &'static str) -> impl Fn(E) -> String {
    move |error| format!("{step}: {error}")
}
