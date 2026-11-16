//! `tsong serve` with a git source: the config reloads when the branch
//! moves.

mod common;

use std::path::Path;
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

/// Commits `text` as `config/tsong.toml` in `origin`, returning the commit.
fn commit(origin: &Path, text: &str) -> TestResult<String> {
    std::fs::create_dir_all(origin.join("config"))?;
    std::fs::write(origin.join("config").join("tsong.toml"), text)?;
    git(origin, &["add", "-A"])?;
    git(origin, &["commit", "-q", "-m", "config"])?;
    git(origin, &["rev-parse", "HEAD"])
}

fn free_port() -> TestResult<u16> {
    let free = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(free.local_addr()?.port())
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

/// A bootstrap file for `origin`'s `main`, polled every 50ms, with the
/// admin listener on `admin` and `extra` appended.
fn bootstrap(dir: &Path, origin: &Path, admin: u16, extra: &str) -> TestResult<std::path::PathBuf> {
    let path = dir.join("bootstrap.toml");
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
poll = "50ms"

[admin]
listen = "127.0.0.1:{admin}"
{extra}"#,
            origin.display(),
            dir.join("clone.git").display()
        ),
    )?;
    Ok(path)
}

#[tokio::test(flavor = "multi_thread")]
async fn serve_reloads_when_the_branch_moves() -> TestResult {
    let dir = tempfile::tempdir()?;
    let key = write_key(dir.path())?;
    let origin = dir.path().join("origin");
    std::fs::create_dir_all(&origin)?;
    git(&origin, &["init", "-q"])?;
    let port = free_port()?;
    let admin = free_port()?;
    let first = commit(&origin, &config_text(&key, "https://one.test", port, ""))?;
    let path = bootstrap(dir.path(), &origin, admin, "")?;

    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        tsong::serve_until(&path, async {
            let _ = stopped.await;
        })
        .await
    });

    let status = serving(admin, &first).await?;
    assert_eq!(status.get("reloads"), Some(&Value::from(1)));
    let discovery = format!("http://127.0.0.1:{port}/.well-known/openid-configuration");
    let issuer = get_json(&discovery).await?;
    assert_eq!(
        issuer.get("issuer").and_then(Value::as_str),
        Some("https://one.test")
    );

    let second = commit(&origin, &config_text(&key, "https://two.test", port, ""))?;
    let status = serving(admin, &second).await?;
    assert_eq!(status.get("reloads"), Some(&Value::from(2)));
    let issuer = get_json(&discovery).await?;
    assert_eq!(
        issuer.get("issuer").and_then(Value::as_str),
        Some("https://two.test")
    );

    stop.send(()).map_err(|()| "the server stopped early")?;
    tokio::time::timeout(Duration::from_secs(10), server).await???;
    Ok(())
}

#[tokio::test]
async fn a_webhook_secret_must_be_in_the_environment() -> TestResult {
    let dir = tempfile::tempdir()?;
    let key = write_key(dir.path())?;
    let origin = dir.path().join("origin");
    std::fs::create_dir_all(&origin)?;
    git(&origin, &["init", "-q"])?;
    commit(&origin, &config_text(&key, "https://one.test", 0, ""))?;
    let unset = "TSONG_TEST_SECRET_THAT_IS_NEVER_SET";
    let webhook = format!(
        "\n[webhook]\nlisten = \"127.0.0.1:0\"\nallow = [\"127.0.0.0/8\"]\nhost = \"github\"\nsecret_env = \"{unset}\"\n"
    );
    let path = bootstrap(dir.path(), &origin, 0, &webhook)?;
    match tsong::serve_until(&path, async {}).await {
        Err(tsong::Error::Secret(name)) => assert_eq!(name, unset),
        other => return Err(format!("expected a missing secret, got {other:?}").into()),
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_signed_webhook_reloads_without_waiting_for_the_poll() -> TestResult {
    use hmac::{Hmac, KeyInit, Mac};

    let dir = tempfile::tempdir()?;
    let key = write_key(dir.path())?;
    let origin = dir.path().join("origin");
    std::fs::create_dir_all(&origin)?;
    git(&origin, &["init", "-q"])?;
    let port = free_port()?;
    let admin = free_port()?;
    let hooks = free_port()?;
    let first = commit(&origin, &config_text(&key, "https://one.test", port, ""))?;
    // PATH is always set, so it stands in for the secret's variable.
    let webhook = format!(
        "\n[webhook]\nlisten = \"127.0.0.1:{hooks}\"\nallow = [\"127.0.0.0/8\"]\nhost = \"github\"\nsecret_env = \"PATH\"\n"
    );
    let path = bootstrap(dir.path(), &origin, admin, &webhook)?;
    let text = std::fs::read_to_string(&path)?.replace(r#"poll = "50ms""#, r#"poll = "1h""#);
    std::fs::write(&path, text)?;

    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        tsong::serve_until(&path, async {
            let _ = stopped.await;
        })
        .await
    });
    serving(admin, &first).await?;

    let second = commit(&origin, &config_text(&key, "https://two.test", port, ""))?;
    let body = r#"{"ref":"refs/heads/main"}"#;
    let secret = std::env::var("PATH")?;
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes())?;
    mac.update(body.as_bytes());
    let signature = format!("sha256={}", tsong_config::hex(&mac.finalize().into_bytes()));
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
