use std::error::Error;
use std::path::PathBuf;
use std::time::Duration;

use tsong_config::{Bootstrap, BootstrapError, CONFIG_FILE, GitHost, GitSource, Source};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const GIT: &str = r#"
[source]
store = "git"
url = "ssh://git@github.com/example/config.git"
branch = "main"
folder = "tsong"
checkout = "/var/lib/tsong/config.git"
ssh_key = "/etc/tsong/deploy_key"
known_hosts = "/etc/tsong/known_hosts"

[admin]
listen = "127.0.0.1:8445"

[admin.webhook]
host = "github"
secret_env = "TSONG_WEBHOOK_SECRET"
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
fn a_git_bootstrap_loads() -> TestResult {
    let bootstrap = Bootstrap::from_toml(GIT)?;
    let Source::Git(GitSource {
        url,
        branch,
        folder,
        checkout,
        ssh_key,
        known_hosts,
        poll,
    }) = &bootstrap.source
    else {
        return Err("expected a git source".into());
    };
    assert_eq!(url, "ssh://git@github.com/example/config.git");
    assert_eq!(branch, "main");
    assert_eq!(folder, "tsong");
    assert_eq!(checkout, &PathBuf::from("/var/lib/tsong/config.git"));
    assert_eq!(ssh_key, &Some(PathBuf::from("/etc/tsong/deploy_key")));
    assert_eq!(known_hosts, &Some(PathBuf::from("/etc/tsong/known_hosts")));
    assert_eq!(*poll, Duration::from_secs(300));
    let admin = bootstrap.admin.ok_or("no admin")?;
    assert_eq!(admin.listen.port(), 8445);
    let webhook = admin.webhook.ok_or("no webhook")?;
    assert_eq!(webhook.host, GitHost::GitHub);
    assert_eq!(webhook.secret_env, "TSONG_WEBHOOK_SECRET");
    assert_eq!(CONFIG_FILE, "tsong.toml");
    Ok(())
}

#[test]
fn the_poll_and_host_are_configurable() -> TestResult {
    let text = GIT
        .replace(r#"host = "github""#, r#"host = "gitlab""#)
        .replace("[admin]", "poll = \"30s\"\n\n[admin]");
    let bootstrap = Bootstrap::from_toml(&text)?;
    let Source::Git(GitSource { poll, .. }) = bootstrap.source else {
        return Err("expected a git source".into());
    };
    assert_eq!(poll, Duration::from_secs(30));
    let host = bootstrap
        .admin
        .and_then(|admin| admin.webhook)
        .map(|webhook| webhook.host);
    assert_eq!(host, Some(GitHost::GitLab));
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
    let git = dir.path().join("git.toml");
    std::fs::write(&git, GIT)?;
    let Source::Git(GitSource { checkout, .. }) = Bootstrap::load(&git)?.source else {
        return Err("expected a git source".into());
    };
    assert_eq!(checkout, PathBuf::from("/var/lib/tsong/config.git"));
    assert!(matches!(
        Bootstrap::load(&dir.path().join("missing.toml")),
        Err(BootstrapError::Read { .. })
    ));
    Ok(())
}

#[test]
fn unknown_fields_and_stores_are_rejected() -> TestResult {
    assert!(parse_error(&GIT.replace("branch =", "brnach ="))?.contains("brnach"));
    assert!(parse_error(&GIT.replace(r#"store = "git""#, r#"store = "s3""#))?.contains("s3"));
    assert!(
        parse_error(&GIT.replace(r#"host = "github""#, r#"host = "gitea""#))?.contains("gitea")
    );
    assert!(parse_error(&GIT.replace("[admin.webhook]", "[admin.hook]"))?.contains("hook"));
    Ok(())
}

#[test]
fn git_sources_need_a_url_and_branch_inside_the_repository() -> TestResult {
    let text = GIT
        .replace(
            r#"url = "ssh://git@github.com/example/config.git""#,
            r#"url = """#,
        )
        .replace(r#"branch = "main""#, r#"branch = """#)
        .replace(r#"folder = "tsong""#, r#"folder = "../tsong""#);
    assert_eq!(
        problems(&text)?,
        [
            "source.url is empty",
            "source.branch is empty",
            "source.folder must be within the repository",
        ]
    );
    let absolute = GIT.replace(r#"folder = "tsong""#, r#"folder = "/tsong""#);
    assert_eq!(
        problems(&absolute)?,
        ["source.folder must be within the repository"]
    );
    for folder in ["", "config/tsong", "a..b"] {
        let text = GIT.replace(r#"folder = "tsong""#, &format!("folder = {folder:?}"));
        Bootstrap::from_toml(&text).map_err(|error| format!("{folder}: {error}"))?;
    }
    Ok(())
}

#[test]
fn the_ssh_key_and_known_hosts_go_together() -> TestResult {
    let key_only = GIT.replace("known_hosts = \"/etc/tsong/known_hosts\"\n", "");
    assert_eq!(
        problems(&key_only)?,
        ["source.ssh_key and source.known_hosts are set together"]
    );
    let hosts_only = GIT.replace("ssh_key = \"/etc/tsong/deploy_key\"\n", "");
    assert_eq!(
        problems(&hosts_only)?,
        ["source.ssh_key and source.known_hosts are set together"]
    );
    let neither = hosts_only.replace("known_hosts = \"/etc/tsong/known_hosts\"\n", "");
    Bootstrap::from_toml(&neither)?;
    Ok(())
}

#[test]
fn the_poll_is_above_zero() -> TestResult {
    let text = GIT.replace("[admin]", "poll = \"0s\"\n\n[admin]");
    assert_eq!(problems(&text)?, ["source.poll must be above zero"]);
    Ok(())
}

#[test]
fn a_webhook_needs_a_git_source_and_a_secret() -> TestResult {
    let text = r#"
[source]
store = "file"
path = "tsong.toml"

[admin]
listen = "127.0.0.1:8445"

[admin.webhook]
host = "gitlab"
secret_env = ""
"#;
    assert_eq!(
        problems(text)?,
        [
            "admin.webhook needs a git source",
            "admin.webhook.secret_env is empty",
        ]
    );
    let message = Bootstrap::from_toml(text).map_err(|error| error.to_string());
    assert_eq!(
        message.err().as_deref(),
        Some(
            "invalid bootstrap file:\n- admin.webhook needs a git source\n- admin.webhook.secret_env is empty\n"
        )
    );
    let without = text.replace(
        "\n[admin.webhook]\nhost = \"gitlab\"\nsecret_env = \"\"\n",
        "",
    );
    Bootstrap::from_toml(&without)?;
    Ok(())
}

#[test]
fn the_sample_bootstrap_loads() -> TestResult {
    let sample = include_str!("../../../examples/bootstrap.toml");
    let bootstrap = Bootstrap::from_toml(sample)?;
    assert!(matches!(bootstrap.source, Source::Git(_)));
    let host = bootstrap
        .admin
        .and_then(|admin| admin.webhook)
        .map(|webhook| webhook.host);
    assert_eq!(host, Some(GitHost::GitHub));
    Ok(())
}
