use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tsong_config::{GitHost, hex};
use tsong_git::webhook::{GITHUB_SIGNATURE, GITLAB_TOKEN, pushed_branch, signature_header, verify};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const BODY: &[u8] = b"Hello, World!";

/// A fresh secret: 32 random bytes as hex text, as a Git host would hold it.
fn secret() -> TestResult<Vec<u8>> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| error.to_string())?;
    Ok(hex(&bytes).into_bytes())
}

/// GitHub's signature header for `body` under `secret`.
fn github_signature(secret: &[u8], body: &[u8]) -> TestResult<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)?;
    mac.update(body);
    Ok(format!("sha256={}", hex(&mac.finalize().into_bytes())))
}

#[test]
fn github_deliveries_are_verified_by_hmac() -> TestResult {
    let secret = secret()?;
    let signed = github_signature(&secret, BODY)?;
    let verify_github =
        |signature: &[u8], body: &[u8]| verify(GitHost::GitHub, &secret, Some(signature), body);
    assert!(verify_github(signed.as_bytes(), BODY));
    let digest = signed.strip_prefix("sha256=").ok_or("no prefix")?;
    let shouted = format!("sha256={}", digest.to_uppercase());
    assert!(verify_github(shouted.as_bytes(), BODY));
    assert!(!verify_github(signed.as_bytes(), b"Hello, World?"));
    let other = github_signature(&self::secret()?, BODY)?;
    assert!(!verify_github(other.as_bytes(), BODY));
    let short = digest.get(1..).ok_or("short digest")?;
    let tail = digest.get(2..).ok_or("short digest")?;
    for malformed in [
        digest.to_owned(),
        format!("sha1={digest}"),
        format!("sha256={short}"),
        format!("sha256=zz{tail}"),
        "sha256=".to_owned(),
    ] {
        assert!(!verify_github(malformed.as_bytes(), BODY), "{malformed}");
    }
    assert!(!verify_github("sha256=\u{e9}\u{e9}".as_bytes(), BODY));
    Ok(())
}

#[test]
fn gitlab_deliveries_carry_the_secret() -> TestResult {
    let secret = secret()?;
    let verify_gitlab = |token: &[u8]| verify(GitHost::GitLab, &secret, Some(token), BODY);
    assert!(verify_gitlab(&secret));
    let mut changed = secret.clone();
    if let Some(last) = changed.last_mut() {
        *last = if *last == b'0' { b'1' } else { b'0' };
    }
    assert!(!verify_gitlab(&changed));
    // Two differences whose bits would cancel under XOR: two unequal
    // neighbours swapped.
    let mut swapped = secret.clone();
    let at = swapped
        .windows(2)
        .position(|pair| pair.first() != pair.get(1))
        .ok_or("the secret repeats one character")?;
    swapped.swap(at, at + 1);
    assert!(!verify_gitlab(&swapped));
    let mut longer = secret.clone();
    longer.push(b'0');
    assert!(!verify_gitlab(&longer));
    assert!(!verify_gitlab(b""));
    Ok(())
}

#[test]
fn a_missing_header_or_secret_fails() -> TestResult {
    let secret = secret()?;
    // An empty secret, emptied from a generated one.
    let mut empty = self::secret()?;
    empty.clear();
    for host in [GitHost::GitHub, GitHost::GitLab] {
        assert!(!verify(host, &secret, None, BODY));
        assert!(!verify(host, &empty, Some(&empty), BODY));
    }
    Ok(())
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

#[test]
fn a_form_encoded_push_names_its_branch() {
    let form = b"payload=%7B%22ref%22%3A%22refs%2Fheads%2Fmain%22%7D";
    assert_eq!(pushed_branch(form).as_deref(), Some("main"));
    let other_field = b"other=%7B%22ref%22%3A%22refs%2Fheads%2Fmain%22%7D";
    assert_eq!(pushed_branch(other_field), None);
    let not_json = b"payload=not+json";
    assert_eq!(pushed_branch(not_json), None);
}
