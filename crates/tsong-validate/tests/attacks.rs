//! Known attacks on JWT validation, each built by hand and refused. Tokens
//! are assembled from raw header and payload JSON and signed with the raw
//! signing function, so a header can carry anything an attacker writes.

use std::error::Error;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, EncodingKey};
use serde_json::{Value, json};
use tsong_clock::ManualClock;
use tsong_config::Config;
use tsong_config::TrustedIssuer;
use tsong_validate::testkit::TestKey;
use tsong_validate::{FetchError, FetchFuture, JwksFetcher, ValidateError, Validator};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const NOW: u64 = 1_000_000;
const ISSUER: &str = "https://issuer.test";
const OTHER: &str = "https://other.test";

const CONFIG: &str = r#"
[issuer]
url = "https://tsong.test"
listen = "127.0.0.1:0"
token_lifetime = "00:15:00"
clock_skew = "00:00:30"

[issuer.signing]
provider = "file"

[[issuer.signing.keys]]
kid = "k1"
private_key = { file = "/k1.pem" }
state = "active"

[gateway]
listen = "127.0.0.1:0"
allow = ["127.0.0.0/8"]

[gateway.cache]
max_entries = 10

[trusted_issuers.test]
sub_prefix = "test"
issuer = "https://issuer.test"
audiences = ["tsong"]
algorithms = ["ES256"]

[trusted_issuers.other]
sub_prefix = "other"
issuer = "https://other.test"
audiences = ["tsong"]
algorithms = ["ES256"]
"#;

/// The trusted issuer's key, k1; the other trusted issuer's key, k2; and
/// an attacker's key under the name k1, which no JWKS holds.
struct Keys {
    issuer: TestKey,
    other: TestKey,
    attacker: TestKey,
}

fn keys() -> TestResult<Keys> {
    Ok(Keys {
        issuer: TestKey::new("k1", 1)?,
        other: TestKey::new("k2", 2)?,
        attacker: TestKey::new("k1", 9)?,
    })
}

/// Serves each trusted issuer its own JWKS.
struct PerIssuer {
    issuer: JwkSet,
    other: JwkSet,
}

impl JwksFetcher for PerIssuer {
    fn fetch<'a>(&'a self, trusted: &'a TrustedIssuer) -> FetchFuture<'a> {
        let set = match trusted.issuer.as_str() {
            ISSUER => Ok(self.issuer.clone()),
            OTHER => Ok(self.other.clone()),
            other => Err(FetchError::Discovery(format!("no JWKS for {other}"))),
        };
        Box::pin(async move { set })
    }
}

fn validator(keys: &Keys) -> TestResult<Validator> {
    let set = |key: &TestKey| serde_json::from_value::<JwkSet>(json!({ "keys": [key.jwk()] }));
    let fetcher = Arc::new(PerIssuer {
        issuer: set(&keys.issuer)?,
        other: set(&keys.other)?,
    });
    let config = Config::from_toml(CONFIG)?;
    Ok(Validator::new(
        &config,
        fetcher,
        Arc::new(ManualClock::at(NOW)),
    ))
}

fn claims() -> Value {
    json!({
        "iss": ISSUER,
        "sub": "alice",
        "aud": "tsong",
        "exp": NOW + 600,
        "nbf": NOW - 10,
    })
}

/// `value`'s JSON, base64url without padding.
fn encode(value: &Value) -> String {
    URL_SAFE_NO_PAD.encode(value.to_string())
}

/// A token of `header` and `payload`, signed as ES256 with `key`.
fn signed(header: &Value, payload: &Value, key: &EncodingKey) -> TestResult<String> {
    let message = format!("{}.{}", encode(header), encode(payload));
    let signature = jsonwebtoken::crypto::sign(message.as_bytes(), key, Algorithm::ES256)?;
    Ok(format!("{message}.{signature}"))
}

/// The ES256 header naming `kid`.
fn header(kid: &str) -> Value {
    json!({ "alg": "ES256", "typ": "JWT", "kid": kid })
}

/// `value` with `changes` applied: a null removes the field.
fn with(value: Value, changes: Value) -> TestResult<Value> {
    let (Value::Object(mut fields), Value::Object(changes)) = (value, changes) else {
        return Err("expected JSON objects".into());
    };
    for (name, value) in changes {
        if value.is_null() {
            fields.remove(&name);
        } else {
            fields.insert(name, value);
        }
    }
    Ok(Value::Object(fields))
}

/// One attack: what it is, the token, and the refusal it must get.
struct Attack {
    name: &'static str,
    token: String,
    refused: fn(&ValidateError) -> bool,
}

fn attacks(keys: &Keys) -> TestResult<Vec<Attack>> {
    let k1 = keys.issuer.encoding();
    let attacker = keys.attacker.encoding();
    let good = signed(&header("k1"), &claims(), k1)?;
    let mut parts = good.split('.');
    let (Some(head), Some(body), Some(signature)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err("a signed token has three parts".into());
    };
    let signature_bytes = URL_SAFE_NO_PAD.decode(signature)?;
    let malformed = |e: &ValidateError| matches!(e, ValidateError::Malformed);
    let bad_signature = |e: &ValidateError| matches!(e, ValidateError::Signature);
    Ok(vec![
        // Algorithms.
        Attack {
            name: "alg none, unsigned",
            token: format!("{}.{body}.", encode(&json!({ "alg": "none", "kid": "k1" }))),
            refused: malformed,
        },
        Attack {
            name: "alg none, with the real signature",
            token: format!(
                "{}.{body}.{signature}",
                encode(&json!({ "alg": "none", "kid": "k1" }))
            ),
            refused: malformed,
        },
        Attack {
            name: "alg None in another case",
            token: format!("{}.{body}.", encode(&json!({ "alg": "None", "kid": "k1" }))),
            refused: malformed,
        },
        Attack {
            name: "HS256 keyed with the issuer's public key",
            token: {
                let secret = keys.issuer.jwk().to_string();
                let message = format!("{}.{body}", encode(&json!({ "alg": "HS256", "kid": "k1" })));
                let signature = jsonwebtoken::crypto::sign(
                    message.as_bytes(),
                    &EncodingKey::from_secret(secret.as_bytes())?,
                    Algorithm::HS256,
                )?;
                format!("{message}.{signature}")
            },
            refused: |e| matches!(e, ValidateError::Algorithm(_)),
        },
        Attack {
            name: "an algorithm the issuer doesn't allow, with a valid signature",
            token: signed(&json!({ "alg": "ES384", "kid": "k1" }), &claims(), k1)?,
            refused: |e| matches!(e, ValidateError::Algorithm(_)),
        },
        Attack {
            name: "no alg",
            token: signed(&json!({ "kid": "k1" }), &claims(), k1)?,
            refused: malformed,
        },
        // Keys the token brings with it.
        Attack {
            name: "an embedded jwk of the attacker's key",
            token: signed(
                &with(header("k1"), json!({ "jwk": keys.attacker.jwk() }))?,
                &claims(),
                attacker,
            )?,
            refused: bad_signature,
        },
        Attack {
            name: "a jku pointing at the attacker's JWKS",
            token: signed(
                &with(header("k1"), json!({ "jku": "https://attacker.test/jwks" }))?,
                &claims(),
                attacker,
            )?,
            refused: bad_signature,
        },
        Attack {
            name: "an x5u pointing at the attacker's certificate",
            token: signed(
                &with(header("k1"), json!({ "x5u": "https://attacker.test/cert" }))?,
                &claims(),
                attacker,
            )?,
            refused: bad_signature,
        },
        // Critical headers, which jsonwebtoken refuses when it verifies
        // the signature, as RFC 7515 section 4.1.11 requires.
        Attack {
            name: "a critical header Tsong doesn't understand",
            token: signed(
                &with(header("k1"), json!({ "crit": ["exp"] }))?,
                &claims(),
                k1,
            )?,
            refused: bad_signature,
        },
        Attack {
            name: "an empty critical header",
            token: signed(&with(header("k1"), json!({ "crit": [] }))?, &claims(), k1)?,
            refused: bad_signature,
        },
        Attack {
            name: "an unencoded payload, b64 false",
            token: signed(
                &with(header("k1"), json!({ "crit": ["b64"], "b64": false }))?,
                &claims(),
                k1,
            )?,
            refused: bad_signature,
        },
        // Key IDs.
        Attack {
            name: "no kid",
            token: signed(&json!({ "alg": "ES256" }), &claims(), k1)?,
            refused: |e| matches!(e, ValidateError::MissingKid),
        },
        Attack {
            name: "an empty kid",
            token: signed(&header(""), &claims(), k1)?,
            refused: |e| matches!(e, ValidateError::UnknownKey(_)),
        },
        Attack {
            name: "a kid that is a path",
            token: signed(&header("../../../../etc/passwd"), &claims(), k1)?,
            refused: |e| matches!(e, ValidateError::UnknownKey(_)),
        },
        Attack {
            name: "a kid that is SQL",
            token: signed(&header("k1' OR '1'='1"), &claims(), k1)?,
            refused: |e| matches!(e, ValidateError::UnknownKey(_)),
        },
        Attack {
            name: "a kid that is a number",
            token: signed(&json!({ "alg": "ES256", "kid": 1 }), &claims(), k1)?,
            refused: malformed,
        },
        Attack {
            name: "the issuer's kid on the attacker's key",
            token: signed(&header("k1"), &claims(), attacker)?,
            refused: bad_signature,
        },
        Attack {
            name: "another trusted issuer's key, claiming to be this issuer",
            token: keys.other.sign(&claims())?,
            refused: |e| matches!(e, ValidateError::UnknownKey(_)),
        },
        // Signatures.
        Attack {
            name: "no signature",
            token: format!("{head}.{body}."),
            refused: bad_signature,
        },
        Attack {
            name: "two parts",
            token: format!("{head}.{body}"),
            refused: malformed,
        },
        Attack {
            name: "a truncated signature",
            token: format!(
                "{head}.{body}.{}",
                URL_SAFE_NO_PAD.encode(signature_bytes.get(..32).unwrap_or_default())
            ),
            refused: bad_signature,
        },
        Attack {
            name: "a signature of zeros, r = s = 0",
            token: format!("{head}.{body}.{}", URL_SAFE_NO_PAD.encode([0u8; 64])),
            refused: bad_signature,
        },
        Attack {
            name: "a signature that isn't base64url",
            token: format!("{head}.{body}.{signature}!"),
            refused: bad_signature,
        },
        Attack {
            name: "a signature with padding",
            token: format!("{head}.{body}.{signature}=="),
            refused: bad_signature,
        },
        Attack {
            name: "a fourth part",
            token: format!("{good}.{signature}"),
            refused: malformed,
        },
        Attack {
            name: "the payload swapped under a valid signature",
            token: format!(
                "{head}.{}.{signature}",
                encode(&with(claims(), json!({ "sub": "admin" }))?)
            ),
            refused: bad_signature,
        },
        Attack {
            name: "the header swapped under a valid signature",
            token: format!(
                "{}.{body}.{signature}",
                encode(&with(header("k1"), json!({ "typ": "at+jwt" }))?)
            ),
            refused: bad_signature,
        },
        // Payloads.
        Attack {
            name: "a payload that isn't an object",
            token: signed(&header("k1"), &json!(["iss", ISSUER]), k1)?,
            refused: malformed,
        },
        Attack {
            name: "a payload that isn't JSON",
            token: {
                let message = format!("{head}.{}", URL_SAFE_NO_PAD.encode("not json"));
                let signature =
                    jsonwebtoken::crypto::sign(message.as_bytes(), k1, Algorithm::ES256)?;
                format!("{message}.{signature}")
            },
            refused: malformed,
        },
        Attack {
            name: "an issuer with a trailing slash",
            token: signed(
                &header("k1"),
                &with(claims(), json!({ "iss": format!("{ISSUER}/") }))?,
                k1,
            )?,
            refused: |e| matches!(e, ValidateError::UntrustedIssuer(_)),
        },
        Attack {
            name: "an issuer in another case",
            token: signed(
                &header("k1"),
                &with(claims(), json!({ "iss": ISSUER.to_uppercase() }))?,
                k1,
            )?,
            refused: |e| matches!(e, ValidateError::UntrustedIssuer(_)),
        },
        Attack {
            name: "an issuer that is an array",
            token: signed(
                &header("k1"),
                &with(claims(), json!({ "iss": [ISSUER] }))?,
                k1,
            )?,
            refused: |e| matches!(e, ValidateError::InvalidClaim("iss")),
        },
        Attack {
            name: "the other trusted issuer's iss, signed with this issuer's key",
            token: signed(&header("k1"), &with(claims(), json!({ "iss": OTHER }))?, k1)?,
            refused: |e| matches!(e, ValidateError::UnknownKey(_)),
        },
        // Audiences.
        Attack {
            name: "an empty audience list",
            token: signed(&header("k1"), &with(claims(), json!({ "aud": [] }))?, k1)?,
            refused: |e| matches!(e, ValidateError::Audience),
        },
        Attack {
            name: "an audience that is a number",
            token: signed(&header("k1"), &with(claims(), json!({ "aud": 1 }))?, k1)?,
            refused: |e| matches!(e, ValidateError::InvalidClaim("aud")),
        },
        Attack {
            name: "an audience list holding a non-string",
            token: signed(
                &header("k1"),
                &with(claims(), json!({ "aud": ["tsong", 1] }))?,
                k1,
            )?,
            refused: |e| matches!(e, ValidateError::InvalidClaim("aud")),
        },
        Attack {
            name: "an audience that only contains the accepted one",
            token: signed(
                &header("k1"),
                &with(claims(), json!({ "aud": "tsong-evil" }))?,
                k1,
            )?,
            refused: |e| matches!(e, ValidateError::Audience),
        },
        // Times.
        Attack {
            name: "an expiry that is a string",
            token: signed(
                &header("k1"),
                &with(claims(), json!({ "exp": (NOW + 600).to_string() }))?,
                k1,
            )?,
            refused: |e| matches!(e, ValidateError::InvalidClaim("exp")),
        },
        Attack {
            name: "a negative expiry",
            token: signed(&header("k1"), &with(claims(), json!({ "exp": -1 }))?, k1)?,
            refused: |e| matches!(e, ValidateError::InvalidClaim("exp")),
        },
        Attack {
            name: "an expiry of zero",
            token: signed(&header("k1"), &with(claims(), json!({ "exp": 0 }))?, k1)?,
            refused: |e| matches!(e, ValidateError::Expired),
        },
        Attack {
            name: "no expiry",
            token: signed(&header("k1"), &with(claims(), json!({ "exp": null }))?, k1)?,
            refused: |e| matches!(e, ValidateError::MissingClaim("exp")),
        },
        Attack {
            name: "a not-before that is a string",
            token: signed(&header("k1"), &with(claims(), json!({ "nbf": "0" }))?, k1)?,
            refused: |e| matches!(e, ValidateError::InvalidClaim("nbf")),
        },
        Attack {
            name: "a not-before far in the future",
            token: signed(
                &header("k1"),
                &with(claims(), json!({ "nbf": u64::MAX }))?,
                k1,
            )?,
            refused: |e| matches!(e, ValidateError::NotYetValid),
        },
    ])
}

#[tokio::test]
async fn every_known_attack_is_refused() -> TestResult {
    let keys = keys()?;
    let validator = validator(&keys)?;
    // The control: the same claims, signed properly, pass.
    validator
        .validate(&signed(&header("k1"), &claims(), keys.issuer.encoding())?)
        .await?;
    let mut failures = Vec::new();
    for attack in attacks(&keys)? {
        match validator.validate(&attack.token).await {
            Ok(_) => failures.push(format!("{}: accepted", attack.name)),
            Err(error) if !(attack.refused)(&error) => {
                failures.push(format!("{}: refused as {error:?}", attack.name));
            }
            Err(_) => {}
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}
