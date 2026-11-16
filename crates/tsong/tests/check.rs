use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use p256::ecdsa::SigningKey;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

/// A config in `dir` with the issuer on `port`, with its key file unless
/// `with_key` is false.
fn write_config(dir: &Path, port: u16, with_key: bool) -> TestResult<PathBuf> {
    write_config_with(dir, port, 0, with_key, "")
}

/// A config in `dir` with the issuer on `port`, the gateway on
/// `gateway_port`, and `extra` appended.
fn write_config_with(
    dir: &Path,
    port: u16,
    gateway_port: u16,
    with_key: bool,
    extra: &str,
) -> TestResult<PathBuf> {
    if with_key {
        let pem = SigningKey::from_slice(&[7; 32])?.to_pkcs8_pem(LineEnding::LF)?;
        std::fs::write(dir.join("k1.pem"), pem.as_bytes())?;
    }
    let config = format!(
        r#"
[issuer]
url = "https://tsong.example.com"
listen = "127.0.0.1:{port}"
token_lifetime = "15m"
clock_skew = "30s"

[issuer.signing]
provider = "file"
algorithm = "ES256"

[[issuer.signing.keys]]
kid = "k1"
path = "k1.pem"
state = "active"

[gateway]
listen = "127.0.0.1:{gateway_port}"
allow = ["127.0.0.0/8"]

[gateway.cache]
max_entries = 10
{extra}"#
    );
    let path = dir.join("tsong.toml");
    std::fs::write(&path, config)?;
    Ok(path)
}

fn args(command: &str, path: &Path) -> Vec<String> {
    vec![command.into(), path.display().to_string()]
}

/// The error `result` holds, or a test failure when it holds a value.
fn failure<T: std::fmt::Debug>(result: Result<T, tsong::Error>) -> TestResult<tsong::Error> {
    match result {
        Ok(value) => Err(format!("expected an error, got {value:?}").into()),
        Err(error) => Ok(error),
    }
}

/// A port nothing listens on, at the moment it is chosen.
fn free_port() -> TestResult<u16> {
    let free = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(free.local_addr()?.port())
}

/// The issuer's discovery document on `port`, once it answers.
async fn discovery(port: u16) -> TestResult<Value> {
    let url = format!("http://127.0.0.1:{port}/.well-known/openid-configuration");
    for _ in 0..50 {
        if let Ok(response) = reqwest::get(&url).await {
            return Ok(response.json().await?);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Err(format!("the issuer never answered on port {port}").into())
}

#[tokio::test]
async fn check_reports_a_good_config() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = write_config(dir.path(), 0, true)?;
    assert_eq!(
        tsong::run(args("check", &path)).await?,
        format!("{}: ok, signing with k1", path.display())
    );
    Ok(())
}

const WARNED_ROUTE: &str = r#"
[[routes]]
name = "orders"
host = "orders.example.com"
downstream = "https://orders-lb.example.com"
append_audience = ""
allowed_audiences = ["*"]
allowed_scopes = []
"#;

#[tokio::test]
async fn check_reports_warnings_and_passes() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = write_config_with(dir.path(), 0, 0, true, WARNED_ROUTE)?;
    assert_eq!(
        tsong::run(args("check", &path)).await?,
        format!(
            "warning: route \"orders\": allowed_audiences has \"*\"; any value is accepted\n\
             warning: route \"orders\": allowed_scopes is empty; every request will be denied\n\
             {}: ok, signing with k1",
            path.display()
        )
    );
    Ok(())
}

#[tokio::test]
async fn deny_warnings_fails_a_check_with_warnings() -> TestResult {
    let dir = tempfile::tempdir()?;
    let warned = write_config_with(dir.path(), 0, 0, true, WARNED_ROUTE)?;
    let deny = |path: &Path| {
        vec![
            "check".to_owned(),
            tsong::DENY_WARNINGS.to_owned(),
            path.display().to_string(),
        ]
    };
    let error = failure(tsong::run(deny(&warned)).await)?;
    assert!(matches!(error, tsong::Error::Warnings(_)));
    assert!(
        error
            .to_string()
            .ends_with("every request will be denied\nwarnings are denied")
    );

    let clean = write_config(dir.path(), 0, true)?;
    assert_eq!(
        tsong::run(deny(&clean)).await?,
        format!("{}: ok, signing with k1", clean.display())
    );
    Ok(())
}

#[tokio::test]
async fn check_reports_a_missing_key() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = write_config(dir.path(), 0, false)?;
    let error = failure(tsong::run(args("check", &path)).await)?;
    assert!(matches!(error, tsong::Error::Key(_)));
    Ok(())
}

#[tokio::test]
async fn check_and_serve_report_a_bad_config() -> TestResult {
    for command in ["check", "serve"] {
        let error = failure(tsong::run(args(command, Path::new("no-such-file.toml"))).await)?;
        assert!(matches!(error, tsong::Error::Config(_)), "{command}");
    }
    Ok(())
}

#[tokio::test]
async fn serve_reports_a_missing_key() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = write_config(dir.path(), 0, false)?;
    let error = failure(tsong::serve_until(&path, async {}).await)?;
    assert!(matches!(error, tsong::Error::Key(_)));
    Ok(())
}

#[tokio::test]
async fn serve_reports_an_address_in_use() -> TestResult {
    let taken = std::net::TcpListener::bind("127.0.0.1:0")?;
    let dir = tempfile::tempdir()?;
    let path = write_config(dir.path(), taken.local_addr()?.port(), true)?;
    let error = failure(tsong::serve_until(&path, async {}).await)?;
    assert!(error.to_string().starts_with("serving: "), "{error}");
    let gateway = write_config_with(dir.path(), 0, taken.local_addr()?.port(), true, "")?;
    let error = failure(tsong::serve_until(&gateway, async {}).await)?;
    assert!(error.to_string().starts_with("serving: "), "{error}");
    Ok(())
}

#[tokio::test]
async fn anything_else_is_a_usage_error() -> TestResult {
    for args in [
        vec![],
        vec!["check".to_string()],
        vec!["launch".into(), "x".into()],
        vec!["check".into(), "--allow-warnings".into(), "x".into()],
        vec!["serve".into(), tsong::DENY_WARNINGS.into(), "x".into()],
    ] {
        let error = failure(tsong::run(args).await)?;
        assert_eq!(error.to_string(), tsong::USAGE);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn serve_keeps_running_until_signalled() -> TestResult {
    let port = free_port()?;
    let dir = tempfile::tempdir()?;
    let path = write_config(dir.path(), port, true)?;
    let server = tokio::spawn(tsong::run(args("serve", &path)));
    let answered = discovery(port).await;
    let still_running = !server.is_finished();
    server.abort();
    answered?;
    assert!(still_running);
    Ok(())
}

/// The gateway's answer on `port` for a host with no route, once it
/// answers.
async fn gateway_status(port: u16) -> TestResult<u16> {
    let url = format!("http://127.0.0.1:{port}/");
    for _ in 0..50 {
        if let Ok(response) = reqwest::get(&url).await {
            return Ok(response.status().as_u16());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Err(format!("the gateway never answered on port {port}").into())
}

#[tokio::test(flavor = "multi_thread")]
async fn serve_runs_the_issuer_and_gateway_until_shut_down() -> TestResult {
    let port = free_port()?;
    let gateway_port = free_port()?;
    let dir = tempfile::tempdir()?;
    let path = write_config_with(dir.path(), port, gateway_port, true, "")?;
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        tsong::serve_until(&path, async {
            let _ = stopped.await;
        })
        .await
    });

    let discovery = discovery(port).await?;
    assert_eq!(
        discovery.get("issuer"),
        Some(&json!("https://tsong.example.com"))
    );
    assert_eq!(gateway_status(gateway_port).await?, 404);
    let token = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/token"))
        .form(&[("grant_type", "password")])
        .send()
        .await?;
    assert_eq!(token.status().as_u16(), 400);
    let body: Value = token.json().await?;
    assert_eq!(body.get("error"), Some(&json!("unsupported_grant_type")));

    stop.send(()).map_err(|()| "the server stopped early")?;
    server.await??;
    Ok(())
}

#[test]
fn the_binary_exits_by_outcome() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = write_config(dir.path(), 0, true)?;
    let good = Command::new(env!("CARGO_BIN_EXE_tsong"))
        .args(args("check", &path))
        .output()?;
    assert!(good.status.success());
    assert!(String::from_utf8(good.stdout)?.ends_with("signing with k1\n"));

    let bad = Command::new(env!("CARGO_BIN_EXE_tsong")).output()?;
    assert!(!bad.status.success());
    assert_eq!(String::from_utf8(bad.stderr)?.trim_end(), tsong::USAGE);
    Ok(())
}
