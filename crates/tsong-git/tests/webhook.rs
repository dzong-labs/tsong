use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tsong_config::{GitHost, hex};
use tsong_git::webhook::{GITHUB_SIGNATURE, GITLAB_TOKEN, pushed_branch, signature_header, verify};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const SECRET: &[u8] = b"It's a Secret to Everybody";
const BODY: &[u8] = b"Hello, World!";

/// GitHub's signature header for `body` under `secret`.
fn github_signature(secret: &[u8], body: &[u8]) -> TestResult<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)?;
    mac.update(body);
    Ok(format!("sha256={}", hex(&mac.finalize().into_bytes())))
}

#[test]
fn github_deliveries_are_verified_by_hmac() -> TestResult {
    // GitHub's documented example delivery.
    let documented = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
    assert_eq!(github_signature(SECRET, BODY)?, documented);
    let verify_github =
        |signature: &[u8], body: &[u8]| verify(GitHost::GitHub, SECRET, Some(signature), body);
    assert!(verify_github(documented.as_bytes(), BODY));
    assert!(verify_github(
        documented
            .to_uppercase()
            .replace("SHA256=", "sha256=")
            .as_bytes(),
        BODY
    ));
    assert!(!verify_github(documented.as_bytes(), b"Hello, World?"));
    let other = github_signature(b"another secret", BODY)?;
    assert!(!verify_github(other.as_bytes(), BODY));
    for malformed in [
        &documented["sha256=".len()..],
        "sha1=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
        "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e1",
        "sha256=zz7107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
        "sha256=",
    ] {
        assert!(!verify_github(malformed.as_bytes(), BODY), "{malformed}");
    }
    assert!(!verify_github("sha256=\u{e9}\u{e9}".as_bytes(), BODY));
    Ok(())
}

#[test]
fn gitlab_deliveries_carry_the_secret() {
    let verify_gitlab = |token: &[u8]| verify(GitHost::GitLab, SECRET, Some(token), BODY);
    assert!(verify_gitlab(SECRET));
    assert!(!verify_gitlab(b"It's a Secret to Everybodx"));
    // Two differences whose bits would cancel under XOR.
    assert!(!verify_gitlab(b"It's a Secret to Everbyody"));
    assert!(!verify_gitlab(b"It's a Secret to Everybody!"));
    assert!(!verify_gitlab(b""));
}

#[test]
fn a_missing_header_or_secret_fails() {
    for host in [GitHost::GitHub, GitHost::GitLab] {
        assert!(!verify(host, SECRET, None, BODY));
        assert!(!verify(host, b"", Some(b""), BODY));
    }
}

#[test]
fn each_host_has_its_header() {
    assert_eq!(signature_header(GitHost::GitHub), GITHUB_SIGNATURE);
    assert_eq!(signature_header(GitHost::GitLab), GITLAB_TOKEN);
    assert_eq!(GITHUB_SIGNATURE, "x-hub-signature-256");
    assert_eq!(GITLAB_TOKEN, "x-gitlab-token");
}

#[test]
fn a_push_names_its_branch() {
    assert_eq!(
        pushed_branch(br#"{"ref":"refs/heads/main","after":"abc"}"#).as_deref(),
        Some("main")
    );
    assert_eq!(
        pushed_branch(br#"{"ref":"refs/heads/release/1.0"}"#).as_deref(),
        Some("release/1.0")
    );
    for body in [
        &br#"{"ref":"refs/tags/v1"}"#[..],
        br#"{"zen":"ping"}"#,
        br#"{"ref":7}"#,
        b"not json",
    ] {
        assert_eq!(pushed_branch(body), None);
    }
}
