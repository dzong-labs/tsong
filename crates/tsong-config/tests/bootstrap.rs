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
fn the_sample_bootstrap_loads() -> TestResult {
    let sample = include_str!("../../../examples/bootstrap.toml");
    let bootstrap = Bootstrap::from_toml(sample)?;
    assert!(matches!(bootstrap.source, Source::File { .. }));
    Ok(())
}

/// `FILE` with a health listener.
fn with_health() -> String {
    format!("{FILE}\n[health]\nlisten = \"127.0.0.1:8447\"\nallow = [\"10.20.0.0/16\"]\n")
}

#[test]
fn health_checks_have_their_own_listener_and_allow_list() -> TestResult {
    let text = with_health();
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
    let text = with_health();
    let health = Bootstrap::from_toml(&text)?.health.ok_or("no health")?;
    assert_eq!(health.drain, std::time::Duration::from_secs(5));
    for (drain, seconds) in [("00:00:30", 30), ("00:00:00", 0)] {
        let set = text.replace("[health]", &format!("[health]\ndrain = \"{drain}\""));
        let health = Bootstrap::from_toml(&set)?.health.ok_or("no health")?;
        assert_eq!(health.drain, std::time::Duration::from_secs(seconds));
    }
    Ok(())
}

#[test]
fn the_audit_writer_defaults_and_may_be_set() -> TestResult {
    let defaults = Bootstrap::from_toml(FILE)?.audit;
    assert_eq!(defaults.queue, 65_536);
    assert_eq!(defaults.shutdown, std::time::Duration::from_secs(5));
    let text = format!("{FILE}\n[audit]\nqueue = 1048576\nshutdown = \"00:01:00\"\n");
    let set = Bootstrap::from_toml(&text)?.audit;
    assert_eq!(set.queue, 1_048_576);
    assert_eq!(set.shutdown, std::time::Duration::from_secs(60));
    Ok(())
}

#[test]
fn an_audit_writer_with_no_room_or_no_deadline_or_absurd_ones_is_refused() -> TestResult {
    for (audit, problem) in [
        ("queue = 0", "audit.queue must be 1 to 1048576 lines"),
        ("queue = 1048577", "audit.queue must be 1 to 1048576 lines"),
        (
            "shutdown = \"00:00:00\"",
            "audit.shutdown must be above zero and at most 00:01:00",
        ),
        (
            "shutdown = \"00:01:00.0000001\"",
            "audit.shutdown must be above zero and at most 00:01:00",
        ),
    ] {
        let text = format!("{FILE}\n[audit]\n{audit}\n");
        assert_eq!(problems(&text)?, [problem], "{audit}");
    }
    parse_error(&format!("{FILE}\n[audit]\nqueue = -1\n"))?;
    assert!(parse_error(&format!("{FILE}\n[audit]\nlines = 5\n"))?.contains("lines"));
    Ok(())
}
