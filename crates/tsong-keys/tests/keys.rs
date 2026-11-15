use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, SigningKey as EcKey, VerifyingKey};
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use tsong_config::{KeyEntry, KeyProvider, KeyState, Signing};
use tsong_keys::{FileKey, KeyError, KeySet, SigningAlgorithm, SigningKey};

/// A PEM for a fixed scalar, so tests need no randomness.
fn pem(seed: u8) -> String {
    EcKey::from_slice(&[seed; 32])
        .unwrap()
        .to_pkcs8_pem(LineEnding::LF)
        .unwrap()
        .to_string()
}

fn key(kid: &str, seed: u8) -> Arc<dyn SigningKey> {
    Arc::new(FileKey::from_pem(kid, &pem(seed)).unwrap())
}

/// The verifying key a JWK describes.
fn verifier(jwk: &serde_json::Value) -> VerifyingKey {
    let mut sec1 = vec![4];
    for coordinate in ["x", "y"] {
        sec1.extend(
            URL_SAFE_NO_PAD
                .decode(jwk[coordinate].as_str().unwrap())
                .unwrap(),
        );
    }
    VerifyingKey::from_sec1_bytes(&sec1).unwrap()
}

#[tokio::test]
async fn a_file_key_signs_what_its_jwk_verifies() {
    let key = FileKey::from_pem("k1", &pem(7)).unwrap();
    let message = b"header.payload";
    let signature = key.sign(message).await.unwrap();
    assert_eq!(signature.len(), 64);
    let signature = Signature::from_slice(&signature).unwrap();
    let verifier = verifier(&key.public_jwk());
    verifier.verify(message, &signature).unwrap();
    assert!(verifier.verify(b"tampered", &signature).is_err());
}

#[test]
fn a_file_key_describes_itself() {
    let key = FileKey::from_pem("k1", &pem(7)).unwrap();
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
        assert_eq!(jwk[field], value, "{field}");
    }
    assert_eq!(jwk.as_object().unwrap().len(), 7);
    assert!(jwk.get("d").is_none());
}

#[test]
fn a_file_key_hides_its_secret_when_debugged() {
    let key = FileKey::from_pem("k1", &pem(7)).unwrap();
    assert_eq!(format!("{key:?}"), r#"FileKey { kid: "k1", .. }"#);
}

#[test]
fn a_file_key_must_be_pkcs8_p256() {
    let error = FileKey::from_pem("k1", "not a key").unwrap_err();
    assert!(matches!(error, KeyError::Decode { .. }));
    assert_eq!(
        error.to_string(),
        r#"key "k1" is not a PKCS#8 PEM P-256 private key"#
    );
}

#[test]
fn a_file_key_loads_from_disk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("k1.pem");
    std::fs::write(&path, pem(7)).unwrap();
    let key = FileKey::load("k1", &path).unwrap();
    assert_eq!(
        key.public_jwk(),
        FileKey::from_pem("k1", &pem(7)).unwrap().public_jwk()
    );
}

#[test]
fn a_missing_key_file_is_reported() {
    let error = FileKey::load("k1", &PathBuf::from("no-such-key.pem")).unwrap_err();
    assert!(matches!(error, KeyError::Read { .. }));
    assert!(error.to_string().starts_with(r#"reading key "k1": "#));
}

#[test]
fn a_key_set_publishes_every_key_active_first() {
    let set = KeySet::new(key("new", 1), vec![key("old", 2), key("older", 3)]).unwrap();
    assert_eq!(set.active().kid(), "new");
    let kids: Vec<_> = set.keys().map(SigningKey::kid).collect();
    assert_eq!(kids, ["new", "old", "older"]);
    let jwks = set.jwks();
    let published: Vec<_> = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|jwk| jwk["kid"].as_str().unwrap())
        .collect();
    assert_eq!(published, ["new", "old", "older"]);
}

#[test]
fn a_key_set_rejects_repeated_kids() {
    let error = KeySet::new(key("k1", 1), vec![key("k2", 2), key("k1", 3)])
        .err()
        .unwrap();
    assert_eq!(error.to_string(), r#"kid "k1" appears more than once"#);
}

fn signing(dir: &std::path::Path, keys: &[(&str, KeyState)]) -> Signing {
    Signing {
        provider: KeyProvider::File,
        algorithm: SigningAlgorithm::ES256,
        keys: keys
            .iter()
            .enumerate()
            .map(|(i, (kid, state))| {
                let path = dir.join(format!("{kid}.pem"));
                std::fs::write(&path, pem(i as u8 + 1)).unwrap();
                KeyEntry {
                    kid: (*kid).into(),
                    state: *state,
                    path: Some(path),
                }
            })
            .collect(),
    }
}

#[test]
fn a_key_set_loads_from_config() {
    let dir = tempfile::tempdir().unwrap();
    let signing = signing(
        dir.path(),
        &[("old", KeyState::Retiring), ("new", KeyState::Active)],
    );
    let set = KeySet::from_config(&signing).unwrap();
    let kids: Vec<_> = set.keys().map(SigningKey::kid).collect();
    assert_eq!(kids, ["new", "old"]);
}

#[test]
fn a_key_set_needs_exactly_one_active_key() {
    let dir = tempfile::tempdir().unwrap();
    let none = signing(dir.path(), &[("old", KeyState::Retiring)]);
    let error = KeySet::from_config(&none).err().unwrap();
    assert_eq!(error.to_string(), "no key is active");
    let two = signing(
        dir.path(),
        &[("a", KeyState::Active), ("b", KeyState::Active)],
    );
    let error = KeySet::from_config(&two).err().unwrap();
    assert_eq!(error.to_string(), "more than one key is active");
}

#[test]
fn a_file_key_entry_needs_a_path() {
    let dir = tempfile::tempdir().unwrap();
    let mut signing = signing(dir.path(), &[("k1", KeyState::Active)]);
    signing.keys[0].path = None;
    let error = KeySet::from_config(&signing).err().unwrap();
    assert_eq!(error.to_string(), r#"key "k1" has no path"#);
}
