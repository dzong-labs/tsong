use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, SigningKey as EcKey, VerifyingKey};
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use serde_json::Value;
use tsong_config::{KeyEntry, KeyProvider, KeyState, Signing};
use tsong_keys::{FileKey, KeyError, KeySet, SigningAlgorithm, SigningKey};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// The error `result` holds, or a test failure when it holds a value.
fn failure<T, E>(result: Result<T, E>) -> TestResult<E> {
    match result {
        Ok(_) => Err("expected an error, got a value".into()),
        Err(error) => Ok(error),
    }
}

/// A PEM for a fixed scalar, so tests need no randomness.
fn pem(seed: u8) -> TestResult<String> {
    let key = EcKey::from_slice(&[seed; 32])?;
    Ok(key.to_pkcs8_pem(LineEnding::LF)?.to_string())
}

fn key(kid: &str, seed: u8) -> TestResult<Arc<dyn SigningKey>> {
    Ok(Arc::new(FileKey::from_pem(kid, &pem(seed)?)?))
}

/// The verifying key a JWK describes.
fn verifier(jwk: &Value) -> TestResult<VerifyingKey> {
    let mut sec1 = vec![4];
    for coordinate in ["x", "y"] {
        let encoded = jwk
            .get(coordinate)
            .and_then(Value::as_str)
            .ok_or(format!("the JWK has no {coordinate}"))?;
        sec1.extend(URL_SAFE_NO_PAD.decode(encoded)?);
    }
    Ok(VerifyingKey::from_sec1_bytes(&sec1)?)
}

#[tokio::test]
async fn a_file_key_signs_what_its_jwk_verifies() -> TestResult {
    let key = FileKey::from_pem("k1", &pem(7)?)?;
    let message = b"header.payload";
    let signature = key.sign(message).await?;
    assert_eq!(signature.len(), 64);
    let signature = Signature::from_slice(&signature)?;
    let verifier = verifier(&key.public_jwk())?;
    assert!(verifier.verify(message, &signature).is_ok());
    assert!(verifier.verify(b"tampered", &signature).is_err());
    Ok(())
}

#[test]
fn a_file_key_describes_itself() -> TestResult {
    let key = FileKey::from_pem("k1", &pem(7)?)?;
    assert_eq!(key.kid(), "k1");
    assert_eq!(key.algorithm(), SigningAlgorithm::ES256);
    let jwk = key.public_jwk();
    for (field, value) in [
        ("kty", "EC"),
        ("crv", "P-256"),
        ("kid", "k1"),
        ("use", "sig"),
        ("alg", "ES256"),
    ] {
        assert_eq!(
            jwk.get(field).and_then(Value::as_str),
            Some(value),
            "{field}"
        );
    }
    assert_eq!(jwk.as_object().map(serde_json::Map::len), Some(7));
    assert!(jwk.get("d").is_none());
    Ok(())
}

#[test]
fn a_file_key_hides_its_secret_when_debugged() -> TestResult {
    let key = FileKey::from_pem("k1", &pem(7)?)?;
    assert_eq!(format!("{key:?}"), r#"FileKey { kid: "k1", .. }"#);
    Ok(())
}

#[test]
fn a_file_key_must_be_pkcs8_p256() -> TestResult {
    let error = failure(FileKey::from_pem("k1", "not a key"))?;
    assert!(matches!(error, KeyError::Decode { .. }));
    assert_eq!(
        error.to_string(),
        r#"key "k1" is not a PKCS#8 PEM P-256 private key"#
    );
    Ok(())
}

#[test]
fn a_file_key_loads_from_disk() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("k1.pem");
    std::fs::write(&path, pem(7)?)?;
    let key = FileKey::load("k1", &path)?;
    assert_eq!(
        key.public_jwk(),
        FileKey::from_pem("k1", &pem(7)?)?.public_jwk()
    );
    Ok(())
}

#[test]
fn a_missing_key_file_is_reported() -> TestResult {
    let error = failure(FileKey::load("k1", &PathBuf::from("no-such-key.pem")))?;
    assert!(matches!(error, KeyError::Read { .. }));
    assert!(error.to_string().starts_with(r#"reading key "k1": "#));
    Ok(())
}

#[test]
fn a_key_set_publishes_every_key_active_first() -> TestResult {
    let set = KeySet::new(key("new", 1)?, vec![key("old", 2)?, key("older", 3)?])?;
    assert_eq!(set.active().kid(), "new");
    let kids: Vec<_> = set.keys().map(SigningKey::kid).collect();
    assert_eq!(kids, ["new", "old", "older"]);
    let jwks = set.jwks();
    let published: Vec<_> = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or("the JWKS has no keys")?
        .iter()
        .map(|jwk| jwk.get("kid").and_then(Value::as_str))
        .collect();
    assert_eq!(published, [Some("new"), Some("old"), Some("older")]);
    Ok(())
}

#[test]
fn a_key_set_rejects_repeated_kids() -> TestResult {
    let error = failure(KeySet::new(
        key("k1", 1)?,
        vec![key("k2", 2)?, key("k1", 3)?],
    ))?;
    assert_eq!(error.to_string(), r#"kid "k1" appears more than once"#);
    Ok(())
}

/// A file-provider signing config, with a key file in `dir` for each key.
fn signing(dir: &Path, keys: &[(&str, KeyState)]) -> TestResult<Signing> {
    let mut entries = Vec::new();
    for (seed, (kid, state)) in (1..).zip(keys) {
        let path = dir.join(format!("{kid}.pem"));
        std::fs::write(&path, pem(seed)?)?;
        entries.push(KeyEntry {
            kid: (*kid).into(),
            state: *state,
            path: Some(path),
        });
    }
    Ok(Signing {
        provider: KeyProvider::File,
        algorithm: SigningAlgorithm::ES256,
        keys: entries,
    })
}

#[test]
fn a_key_set_loads_from_config() -> TestResult {
    let dir = tempfile::tempdir()?;
    let signing = signing(
        dir.path(),
        &[("old", KeyState::Retiring), ("new", KeyState::Active)],
    )?;
    let set = KeySet::from_config(&signing)?;
    let kids: Vec<_> = set.keys().map(SigningKey::kid).collect();
    assert_eq!(kids, ["new", "old"]);
    Ok(())
}

#[test]
fn a_key_set_needs_exactly_one_active_key() -> TestResult {
    let dir = tempfile::tempdir()?;
    let none = signing(dir.path(), &[("old", KeyState::Retiring)])?;
    let error = failure(KeySet::from_config(&none))?;
    assert_eq!(error.to_string(), "no key is active");
    let two = signing(
        dir.path(),
        &[("a", KeyState::Active), ("b", KeyState::Active)],
    )?;
    let error = failure(KeySet::from_config(&two))?;
    assert_eq!(error.to_string(), "more than one key is active");
    Ok(())
}

#[test]
fn a_file_key_entry_needs_a_path() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut signing = signing(dir.path(), &[("k1", KeyState::Active)])?;
    for key in &mut signing.keys {
        key.path = None;
    }
    let error = failure(KeySet::from_config(&signing))?;
    assert_eq!(error.to_string(), r#"key "k1" has no path"#);
    Ok(())
}
