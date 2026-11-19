use std::error::Error;
use std::path::PathBuf;
use std::time::Duration;

use tsong_config::{
    Bootstrap, BootstrapError, CONFIG_FILE, GitHost, GitSource, Scheme, SecretRef, Source,
};

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

[webhook]
listen = "127.0.0.1:8446"
allow = ["192.30.252.0/22", "2a0a:a440::/29"]
host = "github"
secret = { env = "TSONG_WEBHOOK_SECRET" }
"#;

/// The webhook secret reference in [`GIT`].
const HOOK_SECRET: &str = r#"{ env = "TSONG_WEBHOOK_SECRET" }"#;

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
    let webhook = bootstrap.webhook.ok_or("no webhook")?;
    assert_eq!(webhook.listen.port(), 8446);
    assert_eq!(webhook.allow.len(), 2);
    assert_eq!(webhook.host, GitHost::GitHub);
    assert_eq!(webhook.secret.to_string(), HOOK_SECRET);
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
    let host = bootstrap.webhook.map(|webhook| webhook.host);
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
    // An absolute path stays as written; the join is a no-op wherever "/" is
    // absolute, which is every platform Tsong runs on.
    let absolute = PathBuf::from("/var/lib/tsong/config.git");
    assert_eq!(checkout, dir.path().join(&absolute));
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
    assert!(parse_error(&GIT.replace("[webhook]", "[hook]"))?.contains("hook"));
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
fn an_ssh_url_needs_a_deploy_key_and_pinned_host_keys() -> TestResult {
    const REQUIRED: &str = "source.ssh_key and source.known_hosts are required for an ssh url";
    let without_hosts = GIT.replace("known_hosts = \"/etc/tsong/known_hosts\"\n", "");
    assert_eq!(problems(&without_hosts)?, [REQUIRED]);
    let without_key = GIT.replace("ssh_key = \"/etc/tsong/deploy_key\"\n", "");
    assert_eq!(problems(&without_key)?, [REQUIRED]);
    let neither = without_key.replace("known_hosts = \"/etc/tsong/known_hosts\"\n", "");
    assert_eq!(problems(&neither)?, [REQUIRED]);
    let scp_like = neither.replace(
        "ssh://git@github.com/example/config.git",
        "git@github.com:example/config.git",
    );
    assert_eq!(problems(&scp_like)?, [REQUIRED]);
    let keyed_scp = GIT.replace(
        "ssh://git@github.com/example/config.git",
        "git@github.com:example/config.git",
    );
    Bootstrap::from_toml(&keyed_scp)?;
    Ok(())
}

#[test]
fn a_local_url_needs_no_keys() -> TestResult {
    const KEYS: &str =
        "ssh_key = \"/etc/tsong/deploy_key\"\nknown_hosts = \"/etc/tsong/known_hosts\"\n";
    for local in [
        "/srv/git/config.git",
        "file:///srv/git/config.git",
        "C:/git/config.git",
        "C:\\\\git\\\\config.git",
        "../config.git",
    ] {
        let with_keys = GIT.replace("ssh://git@github.com/example/config.git", local);
        assert_eq!(
            problems(&with_keys)?,
            ["source.ssh_key and source.known_hosts are for an ssh url"],
            "{local}"
        );
        let text = with_keys.replace(KEYS, "");
        Bootstrap::from_toml(&text).map_err(|error| format!("{local}: {error}"))?;
    }
    Ok(())
}

#[test]
fn unauthenticated_transports_are_refused() -> TestResult {
    for url in [
        "http://git.example.com/config.git",
        "https://github.com/example/config.git",
        "git://git.example.com/config.git",
    ] {
        let text = GIT.replace("ssh://git@github.com/example/config.git", url);
        assert_eq!(
            problems(&text)?,
            ["source.url must be an ssh url or a local path; other transports are not supported"],
            "{url}"
        );
    }
    Ok(())
}

#[test]
fn the_poll_is_above_zero() -> TestResult {
    let text = GIT.replace("[admin]", "poll = \"0s\"\n\n[admin]");
    assert_eq!(problems(&text)?, ["source.poll must be above zero"]);
    Ok(())
}

#[test]
fn a_webhook_needs_a_git_source_and_an_allow_list() -> TestResult {
    let text = r#"
[source]
store = "file"
path = "tsong.toml"

[admin]
listen = "127.0.0.1:8445"

[webhook]
listen = "127.0.0.1:8446"
allow = []
host = "gitlab"
secret = { env = "TSONG_WEBHOOK_SECRET" }
"#;
    assert_eq!(
        problems(text)?,
        [
            "webhook needs a git source",
            "webhook.allow is empty, so no delivery can arrive",
        ]
    );
    let message = Bootstrap::from_toml(text).map_err(|error| error.to_string());
    assert_eq!(
        message.err().as_deref(),
        Some(
            "invalid bootstrap file:\n- webhook needs a git source\n- webhook.allow is empty, so no delivery can arrive\n"
        )
    );
    let without = text.replace(
        "\n[webhook]\nlisten = \"127.0.0.1:8446\"\nallow = []\nhost = \"gitlab\"\nsecret = { env = \"TSONG_WEBHOOK_SECRET\" }\n",
        "",
    );
    Bootstrap::from_toml(&without)?;
    Ok(())
}

#[test]
fn the_webhook_and_admin_listeners_are_independent() -> TestResult {
    let no_admin = GIT.replace("[admin]\nlisten = \"127.0.0.1:8445\"\n", "");
    let bootstrap = Bootstrap::from_toml(&no_admin)?;
    assert!(bootstrap.admin.is_none());
    assert!(bootstrap.webhook.is_some());
    let no_webhook = GIT.replace(
        "[webhook]\nlisten = \"127.0.0.1:8446\"\nallow = [\"192.30.252.0/22\", \"2a0a:a440::/29\"]\nhost = \"github\"\nsecret = { env = \"TSONG_WEBHOOK_SECRET\" }\n",
        "",
    );
    let bootstrap = Bootstrap::from_toml(&no_webhook)?;
    assert!(bootstrap.admin.is_some());
    assert!(bootstrap.webhook.is_none());
    Ok(())
}

#[test]
fn the_sample_bootstrap_loads() -> TestResult {
    let sample = include_str!("../../../examples/bootstrap.toml");
    let bootstrap = Bootstrap::from_toml(sample)?;
    assert!(matches!(bootstrap.source, Source::Git(_)));
    let host = bootstrap.webhook.map(|webhook| webhook.host);
    assert_eq!(host, Some(GitHost::GitHub));
    Ok(())
}

#[test]
fn a_local_url_takes_neither_key_alone() -> TestResult {
    let local = GIT.replace(
        "ssh://git@github.com/example/config.git",
        "/srv/git/config.git",
    );
    for (field, line) in [
        ("ssh_key", "known_hosts = \"/etc/tsong/known_hosts\"\n"),
        ("known_hosts", "ssh_key = \"/etc/tsong/deploy_key\"\n"),
    ] {
        assert_eq!(
            problems(&local.replace(line, ""))?,
            ["source.ssh_key and source.known_hosts are for an ssh url"],
            "{field} alone"
        );
    }
    Ok(())
}

#[test]
fn a_git_source_takes_relative_paths_from_the_bootstrap_directory() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("bootstrap.toml");
    let relative = GIT
        .replace(
            "ssh://git@github.com/example/config.git",
            "repos/config.git",
        )
        .replace("/var/lib/tsong/config.git", "clone.git")
        .replace(
            "ssh_key = \"/etc/tsong/deploy_key\"
known_hosts = \"/etc/tsong/known_hosts\"
",
            "",
        );
    std::fs::write(&path, &relative)?;
    let Source::Git(git) = Bootstrap::load(&path)?.source else {
        return Err("expected a git source".into());
    };
    assert_eq!(git.checkout, dir.path().join("clone.git"));
    assert_eq!(
        git.url,
        dir.path().join("repos/config.git").display().to_string()
    );

    let keyed = GIT
        .replace("/etc/tsong/deploy_key", "keys/deploy_key")
        .replace("/etc/tsong/known_hosts", "keys/known_hosts");
    std::fs::write(&path, &keyed)?;
    let Source::Git(git) = Bootstrap::load(&path)?.source else {
        return Err("expected a git source".into());
    };
    assert_eq!(git.ssh_key, Some(dir.path().join("keys/deploy_key")));
    assert_eq!(git.known_hosts, Some(dir.path().join("keys/known_hosts")));
    assert_eq!(git.url, "ssh://git@github.com/example/config.git");

    for url in ["file:///srv/config.git", "file://relative/config.git"] {
        let file_url = relative.replace("url = \"repos/config.git\"", &format!("url = {url:?}"));
        std::fs::write(&path, &file_url)?;
        let Source::Git(git) = Bootstrap::load(&path)?.source else {
            return Err("expected a git source".into());
        };
        assert_eq!(git.url, url, "a file url is left as written");
    }
    Ok(())
}

#[test]
fn health_checks_have_their_own_listener_and_allow_list() -> TestResult {
    let text =
        format!("{GIT}\n[health]\nlisten = \"127.0.0.1:8447\"\nallow = [\"10.20.0.0/16\"]\n");
    let health = Bootstrap::from_toml(&text)?.health.ok_or("no health")?;
    assert_eq!(health.listen.port(), 8447);
    assert_eq!(health.allow.len(), 1);
    assert!(Bootstrap::from_toml(GIT)?.health.is_none());
    let closed = text.replace(r#"allow = ["10.20.0.0/16"]"#, "allow = []");
    assert_eq!(
        problems(&closed)?,
        ["health.allow is empty, so no health check can arrive"]
    );
    let unknown = text.replace("[health]", "[health]\npath = \"/up\"");
    assert!(parse_error(&unknown)?.contains("path"));
    Ok(())
}

#[test]
fn the_drain_defaults_to_five_seconds_and_may_be_zero() -> TestResult {
    let text =
        format!("{GIT}\n[health]\nlisten = \"127.0.0.1:8447\"\nallow = [\"10.20.0.0/16\"]\n");
    let health = Bootstrap::from_toml(&text)?.health.ok_or("no health")?;
    assert_eq!(health.drain, std::time::Duration::from_secs(5));
    for (drain, seconds) in [("30s", 30), ("0s", 0)] {
        let set = text.replace("[health]", &format!("[health]\ndrain = \"{drain}\""));
        let health = Bootstrap::from_toml(&set)?.health.ok_or("no health")?;
        assert_eq!(health.drain, std::time::Duration::from_secs(seconds));
    }
    Ok(())
}

#[test]
fn the_webhook_secret_is_a_reference() -> TestResult {
    for (secret, expected) in [
        (r#""TSONG_WEBHOOK_SECRET""#, "a secret must be a reference"),
        (
            r#"{ vault = "tsong" }"#,
            "a secret reference's key must be env or file",
        ),
        (
            r#"{ env = "" }"#,
            "a secret reference's id must not be empty",
        ),
    ] {
        let text = GIT.replace(HOOK_SECRET, secret);
        let error = Bootstrap::from_toml(&text)
            .err()
            .ok_or("a bad reference was accepted")?
            .to_string();
        assert!(error.contains(expected), "{error}");
    }
    Ok(())
}

#[test]
fn the_retired_secret_env_field_is_refused() {
    let text = GIT.replace(
        r#"secret = { env = "TSONG_WEBHOOK_SECRET" }"#,
        r#"secret_env = "TSONG_WEBHOOK_SECRET""#,
    );
    assert!(Bootstrap::from_toml(&text).is_err());
}

#[test]
fn load_takes_a_relative_webhook_secret_file_from_the_bootstrap_directory() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("bootstrap.toml");
    let file = SecretRef::new(
        Scheme::File,
        dir.path().join("hook.secret").display().to_string(),
    )?;
    for (written, expected) in [
        (r#"{ file = "hook.secret" }"#.to_owned(), file.to_string()),
        (
            r#"{ env = "HOOK" }"#.to_owned(),
            r#"{ env = "HOOK" }"#.to_owned(),
        ),
    ] {
        std::fs::write(&path, GIT.replace(HOOK_SECRET, &written))?;
        let webhook = Bootstrap::load(&path)?.webhook.ok_or("no webhook")?;
        assert_eq!(webhook.secret.to_string(), expected);
    }
    Ok(())
}

#[test]
fn a_webhook_secret_written_in_by_mistake_is_never_quoted() -> TestResult {
    let text = GIT.replace(HOOK_SECRET, "\"hunter2\"");
    let error = Bootstrap::from_toml(&text)
        .err()
        .ok_or("a raw secret was accepted")?
        .to_string();
    assert!(!error.contains("hunter2"), "{error}");
    assert!(error.contains("a secret must be a reference"), "{error}");
    Ok(())
}
