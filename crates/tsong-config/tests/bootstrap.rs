use std::error::Error;

use tsong_config::{Bootstrap, BootstrapError, Source};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const FILE: &str = r#"
[source]
store = "file"
path = "tsong.toml"

[admin]
listen = "127.0.0.1:8445"
"#;

/// The problems validation finds in `text`, or a test failure.
fn problems(text: &str) -> TestResult<Vec<String>> {
    match Bootstrap::from_toml(text) {
        Err(BootstrapError::Invalid(problems)) => Ok(problems.0),
        other => Err(format!("expected an invalid bootstrap, got {other:?}").into()),
    }
}

/// The parse error for `text`, or a test failure.
fn parse_error(text: &str) -> TestResult<String> {
    match Bootstrap::from_toml(text) {
        Err(BootstrapError::Parse(error)) => Ok(error.to_string()),
        other => Err(format!("expected a parse error, got {other:?}").into()),
    }
}

#[test]
fn a_file_bootstrap_loads() -> TestResult {
    let bootstrap = Bootstrap::from_toml(FILE)?;
    assert_eq!(
        bootstrap.source,
        Source::File {
            path: "tsong.toml".into()
        }
    );
    let admin = bootstrap.admin.ok_or("no admin")?;
    assert_eq!(admin.listen.port(), 8445);
    assert!(bootstrap.health.is_none());
    Ok(())
}

#[test]
fn a_file_bootstrap_takes_its_path_from_its_own_directory() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("bootstrap.toml");
    std::fs::write(&path, "[source]\nstore = \"file\"\npath = \"tsong.toml\"\n")?;
    let bootstrap = Bootstrap::load(&path)?;
    assert_eq!(
        bootstrap.source,
        Source::File {
            path: dir.path().join("tsong.toml")
        }
    );
    assert!(bootstrap.admin.is_none());
    assert!(matches!(
        Bootstrap::load(&dir.path().join("missing.toml")),
        Err(BootstrapError::Read { .. })
    ));
    Ok(())
}

#[test]
fn unknown_fields_and_stores_are_rejected() -> TestResult {
    assert!(parse_error(&FILE.replace("path =", "paht ="))?.contains("paht"));
    assert!(parse_error(&FILE.replace(r#"store = "file""#, r#"store = "s3""#))?.contains("s3"));
    assert!(parse_error(&FILE.replace("[admin]", "[admn]"))?.contains("admn"));
    Ok(())
}

#[test]
fn a_git_source_is_refused() -> TestResult {
    let git = r#"
[source]
store = "git"
url = "ssh://git@github.com/example/config.git"
branch = "main"
folder = ""
checkout = "/var/lib/tsong/config.git"
"#;
    let error = parse_error(git)?;
    assert!(error.contains("unknown variant `git`"), "{error}");
    assert!(error.contains("expected `file`"), "{error}");
    Ok(())
}

#[test]
fn a_webhook_table_is_refused() -> TestResult {
    let text = format!(
        "{FILE}\n[webhook]\nlisten = \"127.0.0.1:8446\"\nallow = [\"10.0.0.0/8\"]\nhost = \"github\"\nsecret = {{ env = \"TSONG_WEBHOOK_SECRET\" }}\n"
    );
    let error = parse_error(&text)?;
    assert!(error.contains("unknown field `webhook`"), "{error}");
    Ok(())
}

#[test]
fn the_sample_bootstrap_loads() -> TestResult {
    let sample = include_str!("../../../examples/bootstrap.toml");
    let bootstrap = Bootstrap::from_toml(sample)?;
    assert!(matches!(bootstrap.source, Source::File { .. }));
    Ok(())
}

#[test]
fn health_checks_have_their_own_listener_and_allow_list() -> TestResult {
    let text =
        format!("{FILE}\n[health]\nlisten = \"127.0.0.1:8447\"\nallow = [\"10.20.0.0/16\"]\n");
    let health = Bootstrap::from_toml(&text)?.health.ok_or("no health")?;
    assert_eq!(health.listen.port(), 8447);
    assert_eq!(health.allow.len(), 1);
    assert!(Bootstrap::from_toml(FILE)?.health.is_none());
    let closed = text.replace(r#"allow = ["10.20.0.0/16"]"#, "allow = []");
    assert_eq!(
        problems(&closed)?,
        ["health.allow is empty, so no health check can arrive"]
    );
    let message = Bootstrap::from_toml(&closed).map_err(|error| error.to_string());
    assert_eq!(
        message.err().as_deref(),
        Some("invalid bootstrap file:\n- health.allow is empty, so no health check can arrive\n")
    );
    let unknown = text.replace("[health]", "[health]\npath = \"/up\"");
    assert!(parse_error(&unknown)?.contains("path"));
    Ok(())
}

#[test]
fn the_drain_defaults_to_five_seconds_and_may_be_zero() -> TestResult {
    let text =
        format!("{FILE}\n[health]\nlisten = \"127.0.0.1:8447\"\nallow = [\"10.20.0.0/16\"]\n");
    let health = Bootstrap::from_toml(&text)?.health.ok_or("no health")?;
    assert_eq!(health.drain, std::time::Duration::from_secs(5));
    for (drain, seconds) in [("00:00:30", 30), ("00:00:00", 0)] {
        let set = text.replace("[health]", &format!("[health]\ndrain = \"{drain}\""));
        let health = Bootstrap::from_toml(&set)?.health.ok_or("no health")?;
        assert_eq!(health.drain, std::time::Duration::from_secs(seconds));
    }
    Ok(())
}
