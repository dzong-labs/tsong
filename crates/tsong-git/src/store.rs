//! A config store that reads `tsong.toml` from a folder on a Git branch.

use std::fmt::Display;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use gix::config::tree::Core;
use gix::remote::Direction;
use tsong_config::{CONFIG_FILE, ConfigError, ConfigStore, Fetched, GitSource, LoadFuture};

/// The longest a fetch may take before it is abandoned.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(120);

/// Reads the config from a branch of a Git repository. It keeps a bare
/// clone, fetches only the branch, and reads the file from the fetched
/// commit without checking anything out.
#[derive(Debug, Clone)]
pub struct GitStore {
    source: GitSource,
    ssh_command: Option<String>,
    timeout: Duration,
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
            source: source.clone(),
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
        match self.source.folder.trim_matches('/') {
            "" => CONFIG_FILE.to_owned(),
            folder => format!("{folder}/{CONFIG_FILE}"),
        }
    }

    /// Opens the clone, creating it when there is none yet or its directory
    /// is empty. A clone that exists but can't be opened is an error, not a
    /// reason to start over.
    fn repository(&self) -> Result<gix::Repository, String> {
        let checkout = &self.source.checkout;
        let empty = std::fs::read_dir(checkout)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(false);
        if checkout.exists() && !empty {
            return gix::open(checkout).map_err(failed("opening the clone"));
        }
        std::fs::create_dir_all(checkout).map_err(failed("creating the clone"))?;
        gix::init_bare(checkout).map_err(failed("creating the clone"))
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
        let branch = &self.source.branch;
        let tracking = format!("refs/remotes/origin/{branch}");
        let refspec = format!("+refs/heads/{branch}:{tracking}");
        repo.remote_at(self.source.url.as_str())
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
            .ok_or_else(|| format!("{file} is not on {branch}"))?;
        let mut blob = entry.object().map_err(failed("reading the config"))?;
        let content = blob.id.to_string();
        let text = String::from_utf8(std::mem::take(&mut blob.data))
            .map_err(|_| format!("{file} is not UTF-8"))?;
        Ok(Fetched {
            text,
            revision: commit.id.to_string(),
            content,
            author,
            base_dir: None,
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
            Ok(fetched)
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
