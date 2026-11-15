use std::path::{Path, PathBuf};
use std::process::Command;

use p256::ecdsa::SigningKey;
use p256::pkcs8::{EncodePrivateKey, LineEnding};

const CONFIG: &str = r#"
[issuer]
url = "https://tsong.example.com"
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
listen = "127.0.0.1:8443"

[gateway.cache]
max_entries = 10
"#;

/// A config in `dir`, with its key file unless `with_key` is false.
fn write_config(dir: &Path, with_key: bool) -> PathBuf {
    if with_key {
        let pem = SigningKey::from_slice(&[7; 32])
            .unwrap()
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap();
        std::fs::write(dir.join("k1.pem"), pem.as_bytes()).unwrap();
    }
    let path = dir.join("tsong.toml");
    std::fs::write(&path, CONFIG).unwrap();
    path
}

fn args(path: &Path) -> Vec<String> {
    vec!["check".into(), path.display().to_string()]
}

#[test]
fn check_reports_a_good_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), true);
    assert_eq!(
        tsong::run(args(&path)).unwrap(),
        format!(
            "{}: ok, 0 routes, 0 trusted issuers, signing with k1",
            path.display()
        )
    );
}

#[test]
fn check_reports_a_missing_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), false);
    let error = tsong::run(args(&path)).unwrap_err();
    assert!(matches!(error, tsong::Error::Key(_)));
}

#[test]
fn check_reports_a_bad_config() {
    let error = tsong::run(args(Path::new("no-such-file.toml"))).unwrap_err();
    assert!(matches!(error, tsong::Error::Config(_)));
}

#[test]
fn anything_else_is_a_usage_error() {
    for args in [
        vec![],
        vec!["check".to_string()],
        vec!["serve".into(), "x".into()],
    ] {
        let error = tsong::run(args).unwrap_err();
        assert_eq!(error.to_string(), tsong::USAGE);
    }
}

#[test]
fn the_binary_exits_by_outcome() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), true);
    let good = Command::new(env!("CARGO_BIN_EXE_tsong"))
        .args(args(&path))
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
