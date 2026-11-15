use std::path::{Path, PathBuf};
use std::process::Command;

use p256::ecdsa::SigningKey;
use p256::pkcs8::{EncodePrivateKey, LineEnding};

/// A config in `dir` listening on `port`, with its key file unless
/// `with_key` is false.
fn write_config(dir: &Path, port: u16, with_key: bool) -> PathBuf {
    if with_key {
        let pem = SigningKey::from_slice(&[7; 32])
            .unwrap()
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap();
        std::fs::write(dir.join("k1.pem"), pem.as_bytes()).unwrap();
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
listen = "127.0.0.1:0"

[gateway.cache]
max_entries = 10
"#
    );
    let path = dir.join("tsong.toml");
    std::fs::write(&path, config).unwrap();
    path
}

fn args(command: &str, path: &Path) -> Vec<String> {
    vec![command.into(), path.display().to_string()]
}

#[tokio::test]
async fn check_reports_a_good_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), 0, true);
    assert_eq!(
        tsong::run(args("check", &path)).await.unwrap(),
        format!("{}: ok, signing with k1", path.display())
    );
}

#[tokio::test]
async fn check_reports_a_missing_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), 0, false);
    let error = tsong::run(args("check", &path)).await.unwrap_err();
    assert!(matches!(error, tsong::Error::Key(_)));
}

#[tokio::test]
async fn check_and_serve_report_a_bad_config() {
    for command in ["check", "serve"] {
        let error = tsong::run(args(command, Path::new("no-such-file.toml")))
            .await
            .unwrap_err();
        assert!(matches!(error, tsong::Error::Config(_)), "{command}");
    }
}

#[tokio::test]
async fn serve_reports_a_missing_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), 0, false);
    let error = tsong::serve_until(&path, async {}).await.unwrap_err();
    assert!(matches!(error, tsong::Error::Key(_)));
}

#[tokio::test]
async fn serve_reports_an_address_in_use() {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), taken.local_addr().unwrap().port(), true);
    let error = tsong::serve_until(&path, async {}).await.unwrap_err();
    assert!(error.to_string().starts_with("serving: "), "{error}");
}

#[tokio::test]
async fn anything_else_is_a_usage_error() {
    for args in [
        vec![],
        vec!["check".to_string()],
        vec!["launch".into(), "x".into()],
    ] {
        let error = tsong::run(args).await.unwrap_err();
        assert_eq!(error.to_string(), tsong::USAGE);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn serve_runs_the_issuer_until_shut_down() {
    let port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), port, true);
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        tsong::serve_until(&path, async {
            let _ = stopped.await;
        })
        .await
    });

    let discovery = discovery(port).await.expect("the issuer answers");
    assert_eq!(discovery["issuer"], "https://tsong.example.com");

    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}

/// The issuer's discovery document on `port`, once it answers.
async fn discovery(port: u16) -> Option<serde_json::Value> {
    let url = format!("http://127.0.0.1:{port}/.well-known/openid-configuration");
    for _ in 0..50 {
        if let Ok(response) = reqwest::get(&url).await {
            return Some(response.json().await.unwrap());
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    None
}

fn free_port() -> u16 {
    let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    free.local_addr().unwrap().port()
}

#[tokio::test(flavor = "multi_thread")]
async fn serve_keeps_running_until_signalled() {
    let port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), port, true);
    let server = tokio::spawn(tsong::run(args("serve", &path)));
    assert!(discovery(port).await.is_some(), "the issuer answers");
    assert!(!server.is_finished());
    server.abort();
}

#[test]
fn the_binary_exits_by_outcome() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), 0, true);
    let good = Command::new(env!("CARGO_BIN_EXE_tsong"))
        .args(args("check", &path))
        .output()
        .unwrap();
    assert!(good.status.success());
    assert!(
        String::from_utf8(good.stdout)
            .unwrap()
            .ends_with("signing with k1\n")
    );

    let bad = Command::new(env!("CARGO_BIN_EXE_tsong")).output().unwrap();
    assert!(!bad.status.success());
    assert_eq!(
        String::from_utf8(bad.stderr).unwrap().trim_end(),
        tsong::USAGE
    );
}
