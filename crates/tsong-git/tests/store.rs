use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;

use tsong_config::{ConfigError, ConfigStore, GitSource};
use tsong_git::{GitStore, ssh_command};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// Runs `git` in `dir` and returns its trimmed output, or a test failure.
fn git(dir: &Path, args: &[&str]) -> TestResult<String> {
    let output = Command::new("git")
        .args(["-c", "user.name=Ada", "-c", "user.email=ada@example.test"])
        .args([
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .current_dir(dir)
        .output()?;
    if !output.status.success() {
        return Err(format!("git {args:?}: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

/// A valid config whose key path is absolute, with `max_entries`.
fn config(max_entries: u32) -> String {
    let key = std::env::temp_dir().join("k1.pem");
    format!(
        r#"
[issuer]
url = "https://tsong.example.com"
listen = "127.0.0.1:8444"
token_lifetime = "15m"
clock_skew = "30s"

[issuer.signing]
provider = "file"
algorithm = "ES256"

[[issuer.signing.keys]]
kid = "k1"
path = '{}'
state = "active"

[gateway]
listen = "127.0.0.1:8443"
allow = ["10.0.0.0/8"]

[gateway.cache]
max_entries = {max_entries}
"#,
        key.display()
    )
}

/// A repository with a `main` branch, and a scratch directory for clones.
struct Fixture {
    _dir: tempfile::TempDir,
    origin: PathBuf,
    clones: PathBuf,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let origin = dir.path().join("origin");
        let clones = dir.path().join("clones");
        std::fs::create_dir_all(&origin)?;
        git(&origin, &["init", "-q"])?;
        Ok(Self {
            _dir: dir,
            origin,
            clones,
        })
    }

    /// Writes `text` to `file` in the repository and commits it on the
    /// current branch, returning the commit ID.
    fn commit(&self, file: &str, text: &str) -> TestResult<String> {
        let path = self.origin.join(file);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, text)?;
        git(&self.origin, &["add", "-A"])?;
        git(&self.origin, &["commit", "-q", "-m", file])?;
        git(&self.origin, &["rev-parse", "HEAD"])
    }

    /// A git source on `branch` and `folder`, cloning into `clone`.
    fn source(&self, branch: &str, folder: &str, clone: &str) -> GitSource {
        GitSource {
            url: self.origin.display().to_string(),
            branch: branch.into(),
            folder: folder.into(),
            checkout: self.clones.join(clone),
            ssh_key: None,
            known_hosts: None,
            poll: std::time::Duration::from_secs(60),
        }
    }

    fn store(&self, branch: &str, folder: &str) -> TestResult<GitStore> {
        Ok(GitStore::new(&self.source(branch, folder, "clone.git")))
    }
}

/// The store error a load must fail with.
async fn store_error(store: &GitStore) -> TestResult<String> {
    match store.load().await {
        Err(ConfigError::Store(message)) => Ok(message),
        other => Err(format!("expected a store error, got {other:?}").into()),
    }
}

#[tokio::test]
async fn the_config_is_read_from_the_folder_at_the_branch_tip() -> TestResult {
    let f = Fixture::new()?;
    let first = f.commit("tsong/tsong.toml", &config(10))?;
    let store = f.store("main", "tsong")?;
    let snapshot = store.load().await?;
    assert_eq!(snapshot.revision, first);
    assert_eq!(snapshot.config.gateway.cache.max_entries, 10);
    assert_eq!(snapshot.author.as_deref(), Some("Ada <ada@example.test>"));

    assert_eq!(store.load().await?.revision, first);

    let second = f.commit("tsong/tsong.toml", &config(20))?;
    let snapshot = store.load().await?;
    assert_eq!(snapshot.revision, second);
    assert_eq!(snapshot.config.gateway.cache.max_entries, 20);
    Ok(())
}

#[tokio::test]
async fn an_existing_clone_is_reused() -> TestResult {
    let f = Fixture::new()?;
    let commit = f.commit("tsong/tsong.toml", &config(10))?;
    f.store("main", "tsong/")?.load().await?;
    let again = f.store("main", "/tsong")?.load().await?;
    assert_eq!(again.revision, commit);
    Ok(())
}

#[tokio::test]
async fn an_empty_folder_is_the_repository_root() -> TestResult {
    let f = Fixture::new()?;
    f.commit("tsong.toml", &config(7))?;
    let snapshot = f.store("main", "")?.load().await?;
    assert_eq!(snapshot.config.gateway.cache.max_entries, 7);
    Ok(())
}

#[tokio::test]
async fn only_the_watched_branch_is_read() -> TestResult {
    let f = Fixture::new()?;
    f.commit("tsong/tsong.toml", &config(10))?;
    git(&f.origin, &["checkout", "-q", "-b", "next"])?;
    let next = f.commit("tsong/tsong.toml", &config(30))?;
    let snapshot = f.store("next", "tsong")?.load().await?;
    assert_eq!(snapshot.revision, next);
    assert_eq!(snapshot.config.gateway.cache.max_entries, 30);
    let main = GitStore::new(&f.source("main", "tsong", "main.git"));
    assert_eq!(main.load().await?.config.gateway.cache.max_entries, 10);
    Ok(())
}

#[tokio::test]
async fn a_missing_branch_or_file_is_a_store_error() -> TestResult {
    let f = Fixture::new()?;
    f.commit("tsong/tsong.toml", &config(10))?;
    let missing_file = store_error(&f.store("main", "elsewhere")?).await?;
    assert_eq!(missing_file, "elsewhere/tsong.toml is not on main");
    let missing_branch = GitStore::new(&f.source("gone", "tsong", "gone.git"));
    assert!(!store_error(&missing_branch).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn an_unreachable_repository_is_a_store_error() -> TestResult {
    let f = Fixture::new()?;
    let source = GitSource {
        url: f.origin.join("nothing-here").display().to_string(),
        branch: "main".into(),
        folder: String::new(),
        checkout: f.clones.join("x.git"),
        ssh_key: None,
        known_hosts: None,
        poll: std::time::Duration::from_secs(60),
    };
    let store = GitStore::new(&source);
    assert!(store_error(&store).await?.starts_with("connecting: "));
    Ok(())
}

#[tokio::test]
async fn a_checkout_that_is_not_a_directory_is_a_store_error() -> TestResult {
    let f = Fixture::new()?;
    f.commit("tsong.toml", &config(10))?;
    std::fs::create_dir_all(&f.clones)?;
    std::fs::write(f.clones.join("clone.git"), "not a repository")?;
    let error = store_error(&f.store("main", "")?).await?;
    assert!(error.starts_with("creating the clone: "), "{error}");
    Ok(())
}

#[tokio::test]
async fn a_config_that_is_not_utf8_is_a_store_error() -> TestResult {
    let f = Fixture::new()?;
    std::fs::write(f.origin.join("tsong.toml"), [0xff, 0xfe])?;
    git(&f.origin, &["add", "-A"])?;
    git(&f.origin, &["commit", "-q", "-m", "binary"])?;
    assert_eq!(
        store_error(&f.store("main", "")?).await?,
        "tsong.toml is not UTF-8"
    );
    Ok(())
}

#[tokio::test]
async fn an_invalid_config_fails_validation() -> TestResult {
    let f = Fixture::new()?;
    f.commit("tsong.toml", &config(0))?;
    assert!(matches!(
        f.store("main", "")?.load().await,
        Err(ConfigError::Invalid(_))
    ));
    f.commit("tsong.toml", "not toml [")?;
    assert!(matches!(
        f.store("main", "")?.load().await,
        Err(ConfigError::Parse(_))
    ));
    Ok(())
}

#[tokio::test]
async fn key_paths_in_a_config_from_git_are_absolute() -> TestResult {
    let f = Fixture::new()?;
    let key = std::env::temp_dir().join("k1.pem").display().to_string();
    let relative = config(10).replace(&format!("'{key}'"), "\"k1.pem\"");
    f.commit("tsong.toml", &relative)?;
    match f.store("main", "")?.load().await {
        Err(ConfigError::Invalid(problems)) => assert_eq!(
            problems.0,
            [r#"issuer.signing.keys "k1" path must be absolute in a config from Git"#]
        ),
        other => return Err(format!("expected invalid, got {other:?}").into()),
    }
    Ok(())
}

#[tokio::test]
async fn a_deploy_key_sets_the_ssh_command() -> TestResult {
    let f = Fixture::new()?;
    let commit = f.commit("tsong.toml", &config(10))?;
    let GitSource {
        url,
        branch,
        folder,
        checkout,
        poll,
        ..
    } = f.source("main", "", "keyed.git");
    let source = GitSource {
        url,
        branch,
        folder,
        checkout: checkout.clone(),
        ssh_key: Some("/etc/tsong/deploy_key".into()),
        known_hosts: Some("/etc/tsong/known_hosts".into()),
        poll,
    };
    let store = GitStore::new(&source);
    assert_eq!(store.load().await?.revision, commit);
    let repo_config = std::fs::read_to_string(checkout.join("config"))?;
    assert!(
        !repo_config.contains("sshCommand"),
        "the command is set in memory, not written to the clone"
    );
    Ok(())
}

#[test]
fn the_ssh_command_pins_the_key_and_hosts() {
    assert_eq!(
        ssh_command(
            Path::new("/etc/tsong/deploy key"),
            Path::new("/etc/tsong/it's/known_hosts")
        ),
        "ssh -i '/etc/tsong/deploy key' -o IdentitiesOnly=yes -o BatchMode=yes \
         -o StrictHostKeyChecking=yes -o UserKnownHostsFile='/etc/tsong/it'\\''s/known_hosts'"
    );
}
