//! Verifying a Git host's push webhook, and reading which branch it moved.

use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::Sha256;
use tsong_config::GitHost;

/// The header GitHub signs deliveries in.
pub const GITHUB_SIGNATURE: &str = "x-hub-signature-256";
/// The header GitLab sends the shared secret in.
pub const GITLAB_TOKEN: &str = "x-gitlab-token";

/// Whether a delivery came from the Git host that knows `secret`.
/// `signature` is the host's header: [`GITHUB_SIGNATURE`] or
/// [`GITLAB_TOKEN`]. Comparisons take the same time whatever the input.
pub fn verify(host: GitHost, secret: &[u8], signature: Option<&[u8]>, body: &[u8]) -> bool {
    let Some(signature) = signature else {
        return false;
    };
    if secret.is_empty() {
        return false;
    }
    match host {
        GitHost::GitHub => verify_github(secret, signature, body),
        GitHost::GitLab => constant_eq(secret, signature),
    }
}

/// The header that carries `host`'s signature.
pub fn signature_header(host: GitHost) -> &'static str {
    match host {
        GitHost::GitHub => GITHUB_SIGNATURE,
        GitHost::GitLab => GITLAB_TOKEN,
    }
}

/// GitHub's `sha256=<hex>`: an HMAC-SHA256 of the body.
fn verify_github(secret: &[u8], signature: &[u8], body: &[u8]) -> bool {
    let Some(expected) = signature.strip_prefix(b"sha256=").and_then(unhex) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

/// The branch a push delivery moved, from its `ref`, such as `main` for
/// `refs/heads/main`. `None` for anything else, such as a tag push or a
/// ping. The delivery is JSON, or GitHub's default form encoding with the
/// JSON in a `payload` field.
pub fn pushed_branch(body: &[u8]) -> Option<String> {
    let push: Push = match serde_json::from_slice(body) {
        Ok(push) => push,
        Err(_) => {
            let (_, payload) =
                url::form_urlencoded::parse(body).find(|(name, _)| name == "payload")?;
            serde_json::from_str(&payload).ok()?
        }
    };
    Some(push.reference.strip_prefix("refs/heads/")?.to_owned())
}

/// The one field of a push delivery Tsong reads; the rest, such as the
/// commits, is skipped without being built.
#[derive(Deserialize)]
struct Push {
    #[serde(rename = "ref")]
    reference: String,
}

/// Hexadecimal text, in either case, as bytes.
fn unhex(text: &[u8]) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.chunks(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(digits, 16).ok()
        })
        .collect()
}

/// Whether `a` and `b` are equal, in time that depends only on their
/// lengths.
fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}
