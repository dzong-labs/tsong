use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey};
use p256::ecdsa::SigningKey as EcKey;
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

/// A P-256 PEM for a fixed scalar.
fn pem(seed: u8) -> TestResult<String> {
    let key = EcKey::from_slice(&[seed; 32])?;
    Ok(key.to_pkcs8_pem(LineEnding::LF)?.to_string())
}

fn private_key_pem(der: &[u8]) -> String {
    pem::encode(&pem::Pem::new("PRIVATE KEY", der))
}

fn p384_pem() -> TestResult<String> {
    let der = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &SystemRandom::new())
        .map_err(|_| "generating a P-384 key")?;
    Ok(private_key_pem(der.as_ref()))
}

fn ed25519_pem() -> TestResult<String> {
    let der = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| "generating an Ed25519 key")?;
    Ok(private_key_pem(der.as_ref()))
}

fn rsa_pem() -> TestResult<String> {
    let pair = RsaKeyPair::generate(KeySize::Rsa2048).map_err(|_| "generating an RSA key")?;
    let der = pair.as_der().map_err(|_| "encoding an RSA key")?;
    Ok(private_key_pem(der.as_ref()))
}

fn key(kid: &str, seed: u8) -> TestResult<Arc<dyn SigningKey>> {
    Ok(Arc::new(FileKey::from_pem(
        kid,
        SigningAlgorithm::ES256,
        &pem(seed)?,
    )?))
}

/// Whether `signature` over `message` verifies against `jwk`, checked by
/// jsonwebtoken, an implementation apart from the one that signed.
fn verifies(
    jwk: &Value,
    algorithm: Algorithm,
    message: &[u8],
    signature: &[u8],
) -> TestResult<bool> {
    let jwk: Jwk = serde_json::from_value(jwk.clone())?;
    let key = DecodingKey::from_jwk(&jwk)?;
    let signature = URL_SAFE_NO_PAD.encode(signature);
    Ok(jsonwebtoken::crypto::verify(&signature, message, &key, algorithm).unwrap_or(false))
}

#[tokio::test]
async fn each_algorithm_signs_what_its_jwk_verifies() -> TestResult {
    let rsa = rsa_pem()?;
    let cases = [
        (SigningAlgorithm::ES256, Algorithm::ES256, pem(7)?, 64),
        (SigningAlgorithm::ES384, Algorithm::ES384, p384_pem()?, 96),
        (
            SigningAlgorithm::EdDSA,
            Algorithm::EdDSA,
            ed25519_pem()?,
            64,
        ),
        (SigningAlgorithm::RS256, Algorithm::RS256, rsa.clone(), 256),
        (SigningAlgorithm::RS384, Algorithm::RS384, rsa.clone(), 256),
        (SigningAlgorithm::RS512, Algorithm::RS512, rsa.clone(), 256),
        (SigningAlgorithm::PS256, Algorithm::PS256, rsa.clone(), 256),
        (SigningAlgorithm::PS384, Algorithm::PS384, rsa.clone(), 256),
        (SigningAlgorithm::PS512, Algorithm::PS512, rsa, 256),
    ];
    let message = b"header.payload";
    for (algorithm, jws, pem, length) in cases {
        let key = FileKey::from_pem("k1", algorithm, &pem)?;
        assert_eq!(key.algorithm(), algorithm);
        let signature = key.sign(message).await?;
        assert_eq!(signature.len(), length, "{algorithm}");
        let jwk = key.public_jwk();
        assert_eq!(
            jwk.get("alg").and_then(Value::as_str),
            Some(algorithm.name())
        );
        assert!(verifies(&jwk, jws, message, &signature)?, "{algorithm}");
        assert!(
            !verifies(&jwk, jws, b"tampered", &signature)?,
            "{algorithm}"
        );
        // A verifier that expects another algorithm on the same key refuses it.
        let other = match jws {
            Algorithm::RS256 => Algorithm::PS256,
            Algorithm::PS256 => Algorithm::RS256,
            Algorithm::RS384 => Algorithm::RS512,
            Algorithm::RS512 => Algorithm::RS384,
            Algorithm::PS384 => Algorithm::PS512,
            Algorithm::PS512 => Algorithm::PS384,
            _ => continue,
        };
        assert!(!verifies(&jwk, other, message, &signature)?, "{algorithm}");
    }
    Ok(())
}

/// The JWK fields other than `kid`, `use` and `alg`, which every key
/// shares.
fn shape(jwk: &Value) -> Vec<(String, Option<String>)> {
    let mut fields: Vec<_> = jwk
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(name, _)| !["kid", "use", "alg"].contains(&name.as_str()))
        .map(|(name, value)| {
            let text = match name.as_str() {
                "kty" | "crv" => value.as_str().map(str::to_owned),
                _ => None,
            };
            (name.clone(), text)
        })
        .collect();
    fields.sort();
    fields
}

fn field(name: &str, value: Option<&str>) -> (String, Option<String>) {
    (name.into(), value.map(str::to_owned))
}

#[test]
fn each_key_type_publishes_its_jwk_shape() -> TestResult {
    let ec = |crv| {
        vec![
            field("crv", Some(crv)),
            field("kty", Some("EC")),
            field("x", None),
            field("y", None),
        ]
    };
    let cases = [
        (SigningAlgorithm::ES256, pem(7)?, ec("P-256")),
        (SigningAlgorithm::ES384, p384_pem()?, ec("P-384")),
        (
            SigningAlgorithm::EdDSA,
            ed25519_pem()?,
            vec![
                field("crv", Some("Ed25519")),
                field("kty", Some("OKP")),
                field("x", None),
            ],
        ),
        (
            SigningAlgorithm::PS256,
            rsa_pem()?,
            vec![
                field("e", None),
                field("kty", Some("RSA")),
                field("n", None),
            ],
        ),
    ];
    for (algorithm, pem, expected) in cases {
        let jwk = FileKey::from_pem("k1", algorithm, &pem)?.public_jwk();
        assert_eq!(shape(&jwk), expected, "{algorithm}");
        for (name, value) in [("kid", "k1"), ("use", "sig"), ("alg", algorithm.name())] {
            assert_eq!(jwk.get(name).and_then(Value::as_str), Some(value), "{name}");
        }
    }
    Ok(())
}

#[test]
fn a_p256_jwk_carries_the_public_point() -> TestResult {
    let jwk = FileKey::from_pem("k1", SigningAlgorithm::ES256, &pem(7)?)?.public_jwk();
    let point = EcKey::from_slice(&[7; 32])?
        .verifying_key()
        .to_sec1_point(false);
    let coordinate = |name| jwk.get(name).and_then(Value::as_str).map(str::to_owned);
    assert_eq!(
        coordinate("x"),
        point.x().map(|x| URL_SAFE_NO_PAD.encode(x))
    );
    assert_eq!(
        coordinate("y"),
        point.y().map(|y| URL_SAFE_NO_PAD.encode(y))
    );
    Ok(())
}

#[test]
fn a_file_key_hides_its_secret_when_debugged() -> TestResult {
    let key = FileKey::from_pem("k1", SigningAlgorithm::ES256, &pem(7)?)?;
    assert_eq!(
        format!("{key:?}"),
        r#"FileKey { kid: "k1", algorithm: ES256, .. }"#
    );
    Ok(())
}

#[test]
fn a_file_key_must_suit_its_algorithm() -> TestResult {
    let p256 = pem(7)?;
    let rsa = rsa_pem()?;
    let ed25519 = ed25519_pem()?;
    let cases = [
        (SigningAlgorithm::ES256, "not a key".to_owned(), "P-256"),
        (SigningAlgorithm::ES256, p384_pem()?, "P-256"),
        (SigningAlgorithm::ES384, p256.clone(), "P-384"),
        (SigningAlgorithm::EdDSA, p256.clone(), "Ed25519"),
        (SigningAlgorithm::ES256, ed25519.clone(), "P-256"),
        (
            SigningAlgorithm::RS256,
            p256.clone(),
            "RSA (2048 to 8192 bits)",
        ),
        (SigningAlgorithm::PS512, ed25519, "RSA (2048 to 8192 bits)"),
        (SigningAlgorithm::ES256, rsa.clone(), "P-256"),
        (SigningAlgorithm::EdDSA, rsa, "Ed25519"),
    ];
    for (algorithm, pem, expected) in cases {
        let error = failure(FileKey::from_pem("k1", algorithm, &pem))?;
        assert!(matches!(error, KeyError::Decode { .. }));
        assert_eq!(
            error.to_string(),
            format!(r#"key "k1" is not a PKCS#8 PEM {expected} private key"#),
            "{algorithm}"
        );
    }
    Ok(())
}

#[test]
fn a_file_key_loads_from_disk() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("k1.pem");
    std::fs::write(&path, pem(7)?)?;
    let key = FileKey::load("k1", SigningAlgorithm::ES256, &path)?;
    assert_eq!(
        key.public_jwk(),
        FileKey::from_pem("k1", SigningAlgorithm::ES256, &pem(7)?)?.public_jwk()
    );
    Ok(())
}

#[test]
fn a_missing_key_file_is_reported() -> TestResult {
    let error = failure(FileKey::load(
        "k1",
        SigningAlgorithm::ES256,
        &PathBuf::from("no-such-key.pem"),
    ))?;
    assert!(matches!(error, KeyError::Read { .. }));
    assert!(error.to_string().starts_with(r#"reading key "k1": "#));
    Ok(())
}

#[test]
fn a_key_set_publishes_every_key_active_first() -> TestResult {
    let rsa: Arc<dyn SigningKey> = Arc::new(FileKey::from_pem(
        "rsa",
        SigningAlgorithm::RS256,
        &rsa_pem()?,
    )?);
    let set = KeySet::new(
        vec![key("new", 1)?, rsa],
        vec![key("old", 2)?, key("older", 3)?],
    )?;
    assert_eq!(
        set.active(SigningAlgorithm::ES256).map(SigningKey::kid),
        Some("new")
    );
    assert_eq!(
        set.active(SigningAlgorithm::RS256).map(SigningKey::kid),
        Some("rsa")
    );
    assert!(set.active(SigningAlgorithm::PS256).is_none());
    let active: Vec<_> = set.active_keys().map(SigningKey::kid).collect();
    assert_eq!(active, ["rsa", "new"], "ordered by algorithm");
    let kids: Vec<_> = set.keys().map(SigningKey::kid).collect();
    assert_eq!(kids, ["rsa", "new", "old", "older"]);
    let jwks = set.jwks();
    let published: Vec<_> = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or("the JWKS has no keys")?
        .iter()
        .map(|jwk| jwk.get("kid").and_then(Value::as_str))
        .collect();
    assert_eq!(
        published,
        [Some("rsa"), Some("new"), Some("old"), Some("older")]
    );
    Ok(())
}

#[test]
fn a_key_set_rejects_repeated_kids() -> TestResult {
    let error = failure(KeySet::new(
        vec![key("k1", 1)?],
        vec![key("k2", 2)?, key("k1", 3)?],
    ))?;
    assert_eq!(error.to_string(), r#"kid "k1" appears more than once"#);
    Ok(())
}

#[test]
fn a_key_set_needs_one_active_key_per_algorithm() -> TestResult {
    let error = failure(KeySet::new(vec![], vec![key("old", 1)?]))?;
    assert_eq!(error.to_string(), "no key is active");
    let error = failure(KeySet::new(vec![key("a", 1)?, key("b", 2)?], vec![]))?;
    assert_eq!(error.to_string(), "more than one ES256 key is active");
    Ok(())
}

/// A file-provider signing config, with a P-256 key file in `dir` for
/// each key.
fn signing(dir: &Path, keys: &[(&str, KeyState)]) -> TestResult<Signing> {
    let mut entries = Vec::new();
    for (seed, (kid, state)) in (1..).zip(keys) {
        let path = dir.join(format!("{kid}.pem"));
        std::fs::write(&path, pem(seed)?)?;
        entries.push(KeyEntry {
            kid: (*kid).into(),
            algorithm: SigningAlgorithm::ES256,
            state: *state,
            path: Some(path),
        });
    }
    Ok(Signing {
        provider: KeyProvider::File,
        keys: entries,
    })
}

#[test]
fn a_key_set_loads_from_config() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut signing = signing(
        dir.path(),
        &[("old", KeyState::Retiring), ("new", KeyState::Active)],
    )?;
    let path = dir.path().join("rsa.pem");
    std::fs::write(&path, rsa_pem()?)?;
    signing.keys.push(KeyEntry {
        kid: "rsa".into(),
        algorithm: SigningAlgorithm::PS384,
        state: KeyState::Active,
        path: Some(path),
    });
    let set = KeySet::from_config(&signing)?;
    let kids: Vec<_> = set.keys().map(SigningKey::kid).collect();
    assert_eq!(kids, ["rsa", "new", "old"]);
    assert_eq!(
        set.active(SigningAlgorithm::PS384)
            .map(SigningKey::algorithm),
        Some(SigningAlgorithm::PS384)
    );
    Ok(())
}

#[test]
fn a_key_set_from_config_needs_an_active_key_per_algorithm() -> TestResult {
    let dir = tempfile::tempdir()?;
    let none = signing(dir.path(), &[("old", KeyState::Retiring)])?;
    let error = failure(KeySet::from_config(&none))?;
    assert_eq!(error.to_string(), "no key is active");
    let two = signing(
        dir.path(),
        &[("a", KeyState::Active), ("b", KeyState::Active)],
    )?;
    let error = failure(KeySet::from_config(&two))?;
    assert_eq!(error.to_string(), "more than one ES256 key is active");
    Ok(())
}

#[test]
fn a_config_key_must_suit_its_algorithm() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut signing = signing(dir.path(), &[("k1", KeyState::Active)])?;
    for key in &mut signing.keys {
        key.algorithm = SigningAlgorithm::RS256;
    }
    let error = failure(KeySet::from_config(&signing))?;
    assert_eq!(
        error.to_string(),
        r#"key "k1" is not a PKCS#8 PEM RSA (2048 to 8192 bits) private key"#
    );
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
