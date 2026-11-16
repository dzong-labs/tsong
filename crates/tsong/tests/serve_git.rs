//! `tsong serve` with a git source: the config reloads when the branch
//! moves.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use common::*;
use serde_json::Value;

/// Runs `git` in `dir` and returns its trimmed output.
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

/// A scratch directory with a signing key and an empty origin repository.
struct Origin {
    dir: tempfile::TempDir,
    key: PathBuf,
    repo: PathBuf,
}

impl Origin {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let key = write_key(dir.path())?;
        let repo = dir.path().join("origin");
        std::fs::create_dir_all(&repo)?;
        git(&repo, &["init", "-q"])?;
        Ok(Self { dir, key, repo })
    }

    /// Commits a config issuing as `issuer` on `port` as
    /// `config/tsong.toml`, returning the commit.
    fn commit(&self, issuer: &str, port: u16) -> TestResult<String> {
        let folder = self.repo.join("config");
        std::fs::create_dir_all(&folder)?;
        std::fs::write(
            folder.join("tsong.toml"),
            config_text(&self.key, issuer, port, ""),
        )?;
        git(&self.repo, &["add", "-A"])?;
        git(&self.repo, &["commit", "-q", "-m", "config"])?;
        git(&self.repo, &["rev-parse", "HEAD"])
    }

    /// A bootstrap file for the origin's `main`, polled every `poll`, with
    /// the admin listener on `admin` and `extra` appended.
    fn bootstrap(&self, poll: &str, admin: u16, extra: &str) -> TestResult<PathBuf> {
        let path = self.dir.path().join("bootstrap.toml");
        std::fs::write(
            &path,
            format!(
                r#"
[source]
store = "git"
url = '{}'
branch = "main"
folder = "config"
checkout = '{}'
poll = "{poll}"

[admin]
listen = "127.0.0.1:{admin}"
{extra}"#,
                self.repo.display(),
                self.dir.path().join("clone.git").display()
            ),
        )?;
        Ok(path)
    }
}

/// A `[webhook]` section listening on `port` for GitHub, with the secret
/// in the environment variable `secret_env`.
fn webhook(port: u16, secret_env: &str) -> String {
    format!(
        "\n[webhook]\nlisten = \"127.0.0.1:{port}\"\nallow = [\"127.0.0.0/8\"]\nhost = \"github\"\nsecret_env = \"{secret_env}\"\n"
    )
}

/// GETs `url` as JSON once it answers.
async fn get_json(url: &str) -> TestResult<Value> {
    let mut last = String::new();
    for _ in 0..100 {
        match reqwest::get(url).await {
            Ok(response) => return Ok(response.json().await?),
            Err(error) => last = error.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Err(format!("{url} never answered: {last}").into())
}

/// Waits until the admin listener on `admin` reports `revision`.
async fn serving(admin: u16, revision: &str) -> TestResult<Value> {
    let url = format!("http://127.0.0.1:{admin}/status");
    for _ in 0..200 {
        let status = get_json(&url).await?;
        if status.get("revision").and_then(Value::as_str) == Some(revision) {
            return Ok(status);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Err(format!("never served {revision}").into())
}

type Server = tokio::task::JoinHandle<Result<(), tsong::Error>>;

/// Serves the bootstrap file at `path` until the returned sender is used.
fn serve(path: PathBuf) -> (tokio::sync::oneshot::Sender<()>, Server) {
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        tsong::serve_until(&path, async {
            let _ = stopped.await;
        })
        .await
    });
    (stop, server)
}

#[tokio::test(flavor = "multi_thread")]
async fn serve_reloads_when_the_branch_moves() -> TestResult {
    let origin = Origin::new()?;
    let port = free_port()?;
    let admin = free_port()?;
    let health = free_port()?;
    let first = origin.commit("https://one.test", port)?;
    let checks = format!(
        "
[health]
listen = \"127.0.0.1:{health}\"
allow = [\"127.0.0.0/8\"]
drain = \"1s\"
"
    );
    let (stop, server) = serve(origin.bootstrap("50ms", admin, &checks)?);

    let status = serving(admin, &first).await?;
    assert_eq!(status.get("reloads"), Some(&Value::from(1)));
    let discovery = format!("http://127.0.0.1:{port}/.well-known/openid-configuration");
    let issuer = get_json(&discovery).await?;
    assert_eq!(
        issuer.get("issuer").and_then(Value::as_str),
        Some("https://one.test")
    );

    let ready = get_json(&format!("http://127.0.0.1:{health}/health/ready")).await?;
    assert_eq!(ready.get("ready"), Some(&Value::Bool(true)));
    let live = get_json(&format!("http://127.0.0.1:{health}/health/live")).await?;
    assert_eq!(live.get("live"), Some(&Value::Bool(true)));

    let second = origin.commit("https://two.test", port)?;
    let status = serving(admin, &second).await?;
    assert_eq!(status.get("reloads"), Some(&Value::from(2)));
    let metrics = reqwest::get(format!("http://127.0.0.1:{admin}/metrics"))
        .await?
        .text()
        .await?;
    assert!(
        metrics.contains(r#"tsong_config_reloads_total{outcome="applied"} 1"#),
        "{metrics}"
    );
    let issuer = get_json(&discovery).await?;
    assert_eq!(
        issuer.get("issuer").and_then(Value::as_str),
        Some("https://two.test")
    );

    // On shutdown, readiness fails while the listeners stay open to drain.
    stop.send(()).map_err(|()| "the server stopped early")?;
    let ready = format!("http://127.0.0.1:{health}/health/ready");
    let mut status = 200;
    for _ in 0..50 {
        status = reqwest::get(&ready).await?.status().as_u16();
        if status != 200 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(status, 503);
    assert!(
        !server.is_finished(),
        "the listeners closed before the drain"
    );
    tokio::time::timeout(Duration::from_secs(10), server).await???;
    Ok(())
}

#[tokio::test]
async fn a_webhook_secret_must_be_in_the_environment() -> TestResult {
    let origin = Origin::new()?;
    origin.commit("https://one.test", 0)?;
    let unset = "TSONG_TEST_SECRET_THAT_IS_NEVER_SET";
    let path = origin.bootstrap("50ms", 0, &webhook(0, unset))?;
    match tsong::serve_until(&path, async {}).await {
        Err(tsong::Error::Secret(name)) => assert_eq!(name, unset),
        other => return Err(format!("expected a missing secret, got {other:?}").into()),
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_signed_webhook_reloads_without_waiting_for_the_poll() -> TestResult {
    let origin = Origin::new()?;
    let port = free_port()?;
    let admin = free_port()?;
    let hooks = free_port()?;
    let first = origin.commit("https://one.test", port)?;
    // PATH is always set, so it stands in for the secret's variable.
    let (stop, server) = serve(origin.bootstrap("1h", admin, &webhook(hooks, "PATH"))?);
    serving(admin, &first).await?;

    let second = origin.commit("https://two.test", port)?;
    let body = r#"{"ref":"refs/heads/main"}"#;
    let signature = github_signature(&std::env::var("PATH")?, body)?;
    let client = reqwest::Client::new();
    let on_admin = client
        .post(format!("http://127.0.0.1:{admin}/hooks/config"))
        .header("x-hub-signature-256", signature.clone())
        .body(body)
        .send()
        .await?;
    assert_eq!(
        on_admin.status().as_u16(),
        404,
        "the webhook has its own listener"
    );
    let delivered = client
        .post(format!("http://127.0.0.1:{hooks}/hooks/config"))
        .header("x-hub-signature-256", signature)
        .body(body)
        .send()
        .await?;
    assert_eq!(delivered.status().as_u16(), 202);
    serving(admin, &second).await?;

    stop.send(()).map_err(|()| "the server stopped early")?;
    tokio::time::timeout(Duration::from_secs(10), server).await???;
    Ok(())
}
