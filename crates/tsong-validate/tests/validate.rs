use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use tsong_clock::ManualClock;
use tsong_config::Config;
use tsong_validate::testkit::{FakeFetcher, TestKey};
use tsong_validate::{ValidateError, Validator, scopes};

const NOW: u64 = 1_000_000;
const SKEW: u64 = 30;
const ISSUER: &str = "https://issuer.test";

const CONFIG: &str = r#"
[issuer]
url = "https://tsong.test"
listen = "127.0.0.1:0"
token_lifetime = "15m"
clock_skew = "30s"

[issuer.signing]
provider = "file"
algorithm = "ES256"

[[issuer.signing.keys]]
kid = "k1"
path = "k1.pem"
state = "active"

[gateway]
listen = "127.0.0.1:0"

[gateway.cache]
max_entries = 10

[trusted_issuers.test]
issuer = "https://issuer.test"
audiences = ["tsong", "tsong-alt"]
algorithms = ["ES256", "ES384"]
jwks_refetch = "60s"
"#;

const INTROSPECTED: &str = r#"
[trusted_issuers.gitlab]
issuer = "https://gitlab.test"
audiences = ["tsong"]
validation = "introspection"
introspection_url = "https://gitlab.test/introspect"
client_id = "tsong"
client_secret_env = "SECRET"
"#;

struct Harness {
    validator: Validator,
    fetcher: Arc<FakeFetcher>,
    clock: Arc<ManualClock>,
    key: TestKey,
}

fn harness_with(extra: &str) -> Harness {
    let key = TestKey::new("k1", 1);
    let fetcher = Arc::new(FakeFetcher::with(vec![key.jwk()]));
    let clock = Arc::new(ManualClock::at(NOW));
    let config = Config::from_toml(&format!("{CONFIG}{extra}")).unwrap();
    let validator = Validator::new(&config, fetcher.clone(), clock.clone());
    Harness {
        validator,
        fetcher,
        clock,
        key,
    }
}

fn harness() -> Harness {
    harness_with("")
}

fn claims() -> Value {
    json!({
        "iss": ISSUER,
        "sub": "alice",
        "aud": "tsong",
        "exp": NOW + 600,
        "nbf": NOW - 10,
        "scope": "orders.read orders.write",
    })
}

fn with(changes: Value) -> Value {
    let mut claims = claims();
    for (name, value) in changes.as_object().unwrap() {
        if value.is_null() {
            claims.as_object_mut().unwrap().remove(name);
        } else {
            claims[name] = value.clone();
        }
    }
    claims
}

async fn refused(harness: &Harness, token: &str) -> ValidateError {
    harness.validator.validate(token).await.unwrap_err()
}

#[tokio::test]
async fn a_good_token_is_accepted() {
    let h = harness();
    let validated = h.validator.validate(&h.key.sign(&claims())).await.unwrap();
    assert_eq!(validated.issuer(), "test");
    assert_eq!(validated.subject(), Some("alice"));
    assert_eq!(validated.expires_at(), Some(NOW + 600));
    assert_eq!(validated.claims()["scope"], "orders.read orders.write");
}

#[tokio::test]
async fn something_that_is_not_a_jwt_is_malformed() {
    let h = harness();
    for token in ["opaque-token", "a.b.c", ""] {
        assert!(matches!(refused(&h, token).await, ValidateError::Malformed));
    }
    let good = h.key.sign(&claims());
    let mut parts: Vec<_> = good.split('.').collect();
    parts[1] = "not-base64!";
    assert!(matches!(
        refused(&h, &parts.join(".")).await,
        ValidateError::Malformed
    ));
    parts[1] = "bm90IGpzb24"; // "not json"
    assert!(matches!(
        refused(&h, &parts.join(".")).await,
        ValidateError::Malformed
    ));
}

#[tokio::test]
async fn an_opaque_token_needs_introspection_when_an_issuer_uses_it() {
    let h = harness_with(INTROSPECTED);
    let error = refused(&h, "opaque-token").await;
    assert!(matches!(error, ValidateError::Unsupported("introspection")));
    assert_eq!(error.to_string(), "introspection is not supported yet");
}

#[tokio::test]
async fn a_jwt_from_an_introspected_issuer_is_unsupported() {
    let h = harness_with(INTROSPECTED);
    let token = h.key.sign(&with(json!({ "iss": "https://gitlab.test" })));
    assert!(matches!(
        refused(&h, &token).await,
        ValidateError::Unsupported("introspection")
    ));
}

#[tokio::test]
async fn the_issuer_must_be_present_trusted_and_exact() {
    let h = harness();
    let missing = h.key.sign(&with(json!({ "iss": null })));
    assert!(matches!(
        refused(&h, &missing).await,
        ValidateError::MissingClaim("iss")
    ));
    let number = h.key.sign(&with(json!({ "iss": 7 })));
    assert!(matches!(
        refused(&h, &number).await,
        ValidateError::InvalidClaim("iss")
    ));
    for iss in ["https://evil.test", "https://issuer.test/"] {
        let token = h.key.sign(&with(json!({ "iss": iss })));
        match refused(&h, &token).await {
            ValidateError::UntrustedIssuer(refused) => assert_eq!(refused, iss),
            other => panic!("{other:?}"),
        }
    }
}

#[tokio::test]
async fn only_allowed_algorithms_are_accepted() {
    let h = harness();
    let hmac = jsonwebtoken::encode(
        &Header {
            kid: Some("k1".into()),
            ..Header::new(Algorithm::HS256)
        },
        &claims(),
        &EncodingKey::from_secret(b"guessable").unwrap(),
    )
    .unwrap();
    let error = refused(&h, &hmac).await;
    assert!(matches!(error, ValidateError::Algorithm(_)));
    assert_eq!(
        error.to_string(),
        "algorithm HS256 is not allowed for this issuer"
    );
    assert_eq!(h.fetcher.fetches(), 0);
}

#[tokio::test]
async fn the_header_algorithm_must_match_the_key() {
    let h = harness();
    let mut jwk = h.key.jwk();
    jwk["alg"] = json!("ES384");
    h.fetcher.set_keys(vec![jwk]);
    assert!(matches!(
        refused(&h, &h.key.sign(&claims())).await,
        ValidateError::Algorithm(_)
    ));
}

#[tokio::test]
async fn a_key_without_an_algorithm_is_used_for_the_header_algorithm() {
    let h = harness();
    let mut jwk = h.key.jwk();
    jwk.as_object_mut().unwrap().remove("alg");
    h.fetcher.set_keys(vec![jwk]);
    h.validator.validate(&h.key.sign(&claims())).await.unwrap();
}

#[tokio::test]
async fn the_token_must_name_its_key() {
    let h = harness();
    let token =
        jsonwebtoken::encode(&Header::new(Algorithm::ES256), &claims(), h.key.encoding()).unwrap();
    assert!(matches!(
        refused(&h, &token).await,
        ValidateError::MissingKid
    ));
}

#[tokio::test]
async fn keys_are_cached_and_refetched_for_an_unknown_kid_no_sooner_than_allowed() {
    let h = harness();
    h.validator.validate(&h.key.sign(&claims())).await.unwrap();
    h.validator.validate(&h.key.sign(&claims())).await.unwrap();
    assert_eq!(h.fetcher.fetches(), 1);

    // The issuer rotates to k2.
    let rotated = TestKey::new("k2", 2);
    h.fetcher.set_keys(vec![rotated.jwk()]);
    let token = rotated.sign(&claims());
    match refused(&h, &token).await {
        ValidateError::UnknownKey(kid) => assert_eq!(kid, "k2"),
        other => panic!("{other:?}"),
    }
    assert_eq!(h.fetcher.fetches(), 1, "refetched too soon");

    h.clock.advance(Duration::from_secs(59));
    refused(&h, &token).await;
    assert_eq!(h.fetcher.fetches(), 1, "refetched too soon");

    h.clock.advance(Duration::from_secs(1));
    h.validator.validate(&token).await.unwrap();
    assert_eq!(h.fetcher.fetches(), 2);
}

#[tokio::test]
async fn a_failed_fetch_fails_closed_and_is_retried() {
    let h = harness();
    h.fetcher.fail(true);
    let token = h.key.sign(&claims());
    let error = refused(&h, &token).await;
    assert!(matches!(error, ValidateError::Jwks(_)));
    assert_eq!(
        error.to_string(),
        "fetching the issuer's JWKS: discovery document: down"
    );
    h.fetcher.fail(false);
    h.validator.validate(&token).await.unwrap();
    assert_eq!(h.fetcher.fetches(), 2);
}

#[tokio::test]
async fn keys_for_encryption_or_without_a_kid_are_ignored() {
    let h = harness();
    let mut encryption = h.key.jwk();
    encryption["use"] = json!("enc");
    let mut nameless = h.key.jwk();
    nameless.as_object_mut().unwrap().remove("kid");
    h.fetcher.set_keys(vec![encryption, nameless]);
    assert!(matches!(
        refused(&h, &h.key.sign(&claims())).await,
        ValidateError::UnknownKey(_)
    ));
}

#[tokio::test]
async fn a_key_without_a_use_is_a_signing_key() {
    let h = harness();
    let mut jwk = h.key.jwk();
    jwk.as_object_mut().unwrap().remove("use");
    h.fetcher.set_keys(vec![jwk]);
    h.validator.validate(&h.key.sign(&claims())).await.unwrap();
}

#[tokio::test]
async fn a_forged_signature_is_refused() {
    let h = harness();
    let forger = TestKey::new("k1", 9);
    assert!(matches!(
        refused(&h, &forger.sign(&claims())).await,
        ValidateError::Signature
    ));
}

#[tokio::test]
async fn a_key_that_does_not_decode_is_a_bad_signature() {
    let h = harness();
    let mut jwk = h.key.jwk();
    jwk["x"] = json!("AAAA");
    h.fetcher.set_keys(vec![jwk]);
    assert!(matches!(
        refused(&h, &h.key.sign(&claims())).await,
        ValidateError::Signature
    ));
}

#[tokio::test]
async fn the_audience_must_be_accepted() {
    let h = harness();
    for aud in [json!("tsong-alt"), json!(["other", "tsong"])] {
        let token = h.key.sign(&with(json!({ "aud": aud })));
        h.validator.validate(&token).await.unwrap();
    }
    for (aud, expected) in [
        (json!("other"), "no audience in the token is accepted"),
        (
            json!(["other", "else"]),
            "no audience in the token is accepted",
        ),
        (json!([]), "no audience in the token is accepted"),
        (json!(null), "the token has no aud claim"),
        (json!(7), "the token's aud claim is not valid"),
        (json!(["tsong", 7]), "the token's aud claim is not valid"),
    ] {
        let token = h.key.sign(&with(json!({ "aud": aud })));
        assert_eq!(refused(&h, &token).await.to_string(), expected, "{aud}");
    }
}

#[tokio::test]
async fn expiry_allows_the_clock_skew_and_no_more() {
    let h = harness();
    let token = h.key.sign(&with(json!({ "exp": NOW - SKEW + 1 })));
    h.validator.validate(&token).await.unwrap();
    let token = h.key.sign(&with(json!({ "exp": NOW - SKEW })));
    assert!(matches!(refused(&h, &token).await, ValidateError::Expired));
}

#[tokio::test]
async fn expiry_is_required_and_numeric() {
    let h = harness();
    let missing = h.key.sign(&with(json!({ "exp": null })));
    assert!(matches!(
        refused(&h, &missing).await,
        ValidateError::MissingClaim("exp")
    ));
    for bad in [json!("soon"), json!(-5.0)] {
        let token = h.key.sign(&with(json!({ "exp": bad })));
        assert!(matches!(
            refused(&h, &token).await,
            ValidateError::InvalidClaim("exp")
        ));
    }
    let fractional = h
        .key
        .sign(&with(json!({ "exp": (NOW + 600) as f64 + 0.5 })));
    let validated = h.validator.validate(&fractional).await.unwrap();
    assert_eq!(validated.expires_at(), Some(NOW + 600));
}

#[tokio::test]
async fn not_before_allows_the_clock_skew_and_no_more() {
    let h = harness();
    let token = h.key.sign(&with(json!({ "nbf": NOW + SKEW })));
    h.validator.validate(&token).await.unwrap();
    let token = h.key.sign(&with(json!({ "nbf": NOW + SKEW + 1 })));
    assert!(matches!(
        refused(&h, &token).await,
        ValidateError::NotYetValid
    ));
    let token = h.key.sign(&with(json!({ "nbf": null })));
    h.validator.validate(&token).await.unwrap();
    let token = h.key.sign(&with(json!({ "nbf": "later" })));
    assert!(matches!(
        refused(&h, &token).await,
        ValidateError::InvalidClaim("nbf")
    ));
}

#[test]
fn scopes_come_from_scope_and_scp() {
    let claims = json!({ "scope": "a b", "scp": ["c", 7, "a"] });
    let found: Vec<_> = scopes(claims.as_object().unwrap()).into_iter().collect();
    assert_eq!(found, ["a", "b", "c"]);
    let entra = json!({ "scp": "d  e" });
    let found: Vec<_> = scopes(entra.as_object().unwrap()).into_iter().collect();
    assert_eq!(found, ["d", "e"]);
    let none = json!({ "scope": 7 });
    assert!(scopes(none.as_object().unwrap()).is_empty());
}
