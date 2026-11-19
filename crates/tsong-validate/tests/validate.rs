use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Map, Value, json};
use tsong_clock::ManualClock;
use tsong_config::Config;
use tsong_validate::testkit::{FakeFetcher, TestKey};
use tsong_validate::{ValidateError, Validator, scopes};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

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

[[issuer.signing.keys]]
kid = "k1"
private_key = { file = "k1.pem" }
state = "active"

[gateway]
listen = "127.0.0.1:0"
allow = ["127.0.0.0/8"]

[gateway.cache]
max_entries = 10

[trusted_issuers.test]
sub_prefix = "test"
issuer = "https://issuer.test"
audiences = ["tsong", "tsong-alt"]
algorithms = ["ES256", "ES384"]
jwks_refetch = "60s"
"#;

const INTROSPECTED: &str = r#"
[trusted_issuers.gitlab]
sub_prefix = "gitlab"
issuer = "https://gitlab.test"
audiences = ["tsong"]
validation = "introspection"
introspection_url = "https://gitlab.test/introspect"
client_id = "tsong"
client_secret = { env = "SECRET" }
"#;

struct Harness {
    validator: Validator,
    fetcher: Arc<FakeFetcher>,
    clock: Arc<ManualClock>,
    key: TestKey,
}

fn harness_with(extra: &str) -> TestResult<Harness> {
    let key = TestKey::new("k1", 1)?;
    let fetcher = Arc::new(FakeFetcher::with(vec![key.jwk()]));
    let clock = Arc::new(ManualClock::at(NOW));
    let config = Config::from_toml(&format!("{CONFIG}{extra}"))?;
    let validator = Validator::new(&config, fetcher.clone(), clock.clone());
    Ok(Harness {
        validator,
        fetcher,
        clock,
        key,
    })
}

fn harness() -> TestResult<Harness> {
    harness_with("")
}

/// The fields of a JSON object, or a test failure for anything else.
fn object(value: Value) -> TestResult<Map<String, Value>> {
    match value {
        Value::Object(fields) => Ok(fields),
        other => Err(format!("expected a JSON object, got {other}").into()),
    }
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

/// `value` with `changes` applied: a null removes the field.
fn changed(value: Value, changes: Value) -> TestResult<Value> {
    let mut fields = object(value)?;
    for (name, value) in object(changes)? {
        if value.is_null() {
            fields.remove(&name);
        } else {
            fields.insert(name, value);
        }
    }
    Ok(Value::Object(fields))
}

/// The test claims with `changes` applied.
fn with(changes: Value) -> TestResult<Value> {
    changed(claims(), changes)
}

/// The test claims, expiring after a day: past any key expiry the tests
/// wait for.
fn lasting() -> TestResult<Value> {
    with(json!({ "exp": NOW + 86_400 }))
}

/// Why `token` was refused, or a test failure when it was accepted.
async fn refused(harness: &Harness, token: &str) -> TestResult<ValidateError> {
    match harness.validator.validate(token).await {
        Ok(validated) => Err(format!("expected a refusal, got {validated:?}").into()),
        Err(error) => Ok(error),
    }
}

#[tokio::test]
async fn a_good_token_is_accepted() -> TestResult {
    let h = harness()?;
    let validated = h.validator.validate(&h.key.sign(&claims())?).await?;
    assert_eq!(validated.issuer(), "test");
    assert_eq!(validated.subject(), Some("alice"));
    assert_eq!(validated.expires_at(), Some(NOW + 600));
    assert_eq!(
        validated.claims().get("scope"),
        Some(&json!("orders.read orders.write"))
    );
    Ok(())
}

#[tokio::test]
async fn something_that_is_not_a_jwt_is_malformed() -> TestResult {
    let h = harness()?;
    for token in ["opaque-token", "a.b.c", ""] {
        assert!(matches!(
            refused(&h, token).await?,
            ValidateError::Malformed
        ));
    }
    let good = h.key.sign(&claims())?;
    let (header, rest) = good.split_once('.').ok_or("no payload")?;
    let (_, signature) = rest.split_once('.').ok_or("no signature")?;
    // Not base64, then "not json" in base64.
    for payload in ["not-base64!", "bm90IGpzb24"] {
        let token = format!("{header}.{payload}.{signature}");
        assert!(matches!(
            refused(&h, &token).await?,
            ValidateError::Malformed
        ));
    }
    Ok(())
}

#[tokio::test]
async fn an_opaque_token_needs_introspection_when_an_issuer_uses_it() -> TestResult {
    let h = harness_with(INTROSPECTED)?;
    let error = refused(&h, "opaque-token").await?;
    assert!(matches!(error, ValidateError::Unsupported("introspection")));
    assert_eq!(error.to_string(), "introspection is not supported yet");
    Ok(())
}

#[tokio::test]
async fn a_jwt_from_an_introspected_issuer_is_unsupported() -> TestResult {
    let h = harness_with(INTROSPECTED)?;
    let token = h
        .key
        .sign(&with(json!({ "iss": "https://gitlab.test" }))?)?;
    assert!(matches!(
        refused(&h, &token).await?,
        ValidateError::Unsupported("introspection")
    ));
    Ok(())
}

#[tokio::test]
async fn the_issuer_must_be_present_trusted_and_exact() -> TestResult {
    let h = harness()?;
    let missing = h.key.sign(&with(json!({ "iss": null }))?)?;
    assert!(matches!(
        refused(&h, &missing).await?,
        ValidateError::MissingClaim("iss")
    ));
    let number = h.key.sign(&with(json!({ "iss": 7 }))?)?;
    assert!(matches!(
        refused(&h, &number).await?,
        ValidateError::InvalidClaim("iss")
    ));
    for iss in ["https://evil.test", "https://issuer.test/"] {
        let token = h.key.sign(&with(json!({ "iss": iss }))?)?;
        let error = refused(&h, &token).await?;
        assert!(
            matches!(&error, ValidateError::UntrustedIssuer(refused) if refused == iss),
            "{error:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn only_allowed_algorithms_are_accepted() -> TestResult {
    let h = harness()?;
    let hmac = jsonwebtoken::encode(
        &Header {
            kid: Some("k1".into()),
            ..Header::new(Algorithm::HS256)
        },
        &claims(),
        &EncodingKey::from_secret(b"guessable")?,
    )?;
    let error = refused(&h, &hmac).await?;
    assert!(matches!(error, ValidateError::Algorithm(_)));
    assert_eq!(
        error.to_string(),
        "algorithm HS256 is not allowed for this issuer"
    );
    assert_eq!(h.fetcher.fetches(), 0);
    Ok(())
}

#[tokio::test]
async fn the_header_algorithm_must_match_the_key() -> TestResult {
    let h = harness()?;
    h.fetcher
        .set_keys(vec![changed(h.key.jwk(), json!({ "alg": "ES384" }))?]);
    assert!(matches!(
        refused(&h, &h.key.sign(&claims())?).await?,
        ValidateError::Algorithm(_)
    ));
    Ok(())
}

#[tokio::test]
async fn a_key_without_an_algorithm_is_used_for_the_header_algorithm() -> TestResult {
    let h = harness()?;
    h.fetcher
        .set_keys(vec![changed(h.key.jwk(), json!({ "alg": null }))?]);
    h.validator.validate(&h.key.sign(&claims())?).await?;
    Ok(())
}

#[tokio::test]
async fn the_token_must_name_its_key() -> TestResult {
    let h = harness()?;
    let token = jsonwebtoken::encode(&Header::new(Algorithm::ES256), &claims(), h.key.encoding())?;
    assert!(matches!(
        refused(&h, &token).await?,
        ValidateError::MissingKid
    ));
    Ok(())
}

#[tokio::test]
async fn keys_are_cached_and_refetched_for_an_unknown_kid_no_sooner_than_allowed() -> TestResult {
    let h = harness()?;
    h.validator.validate(&h.key.sign(&claims())?).await?;
    h.validator.validate(&h.key.sign(&claims())?).await?;
    assert_eq!(h.fetcher.fetches(), 1);

    // The issuer rotates to k2.
    let rotated = TestKey::new("k2", 2)?;
    h.fetcher.set_keys(vec![rotated.jwk()]);
    let token = rotated.sign(&claims())?;
    let error = refused(&h, &token).await?;
    assert!(
        matches!(&error, ValidateError::UnknownKey(kid) if kid == "k2"),
        "{error:?}"
    );
    assert_eq!(h.fetcher.fetches(), 1, "refetched too soon");

    h.clock.advance(Duration::from_secs(59));
    refused(&h, &token).await?;
    assert_eq!(h.fetcher.fetches(), 1, "refetched too soon");

    h.clock.advance(Duration::from_secs(1));
    h.validator.validate(&token).await?;
    assert_eq!(h.fetcher.fetches(), 2);
    Ok(())
}

#[tokio::test]
async fn a_failed_fetch_fails_closed_and_is_retried() -> TestResult {
    let h = harness()?;
    h.fetcher.fail(true);
    let token = h.key.sign(&claims())?;
    let error = refused(&h, &token).await?;
    assert!(matches!(error, ValidateError::Jwks(_)));
    assert_eq!(
        error.to_string(),
        "fetching the issuer's JWKS: discovery document: down"
    );
    h.fetcher.fail(false);
    h.clock.advance(Duration::from_secs(9));
    assert!(matches!(
        refused(&h, &token).await?,
        ValidateError::KeysExpired
    ));
    assert_eq!(h.fetcher.fetches(), 1, "retried too soon");
    h.clock.advance(Duration::from_secs(1));
    h.validator.validate(&token).await?;
    assert_eq!(h.fetcher.fetches(), 2);
    Ok(())
}

#[tokio::test]
async fn keys_expire_and_a_withdrawn_key_is_refused() -> TestResult {
    let h = harness()?;
    let token = h.key.sign(&lasting()?)?;
    h.validator.validate(&token).await?;

    // The issuer withdraws k1; until the keys expire it stays trusted.
    let replacement = TestKey::new("k2", 2)?;
    h.fetcher.set_keys(vec![replacement.jwk()]);
    h.clock.advance(Duration::from_secs(3599));
    h.validator.validate(&token).await?;
    assert_eq!(h.fetcher.fetches(), 1);

    h.clock.advance(Duration::from_secs(1));
    let error = refused(&h, &token).await?;
    assert!(
        matches!(&error, ValidateError::UnknownKey(kid) if kid == "k1"),
        "{error:?}"
    );
    assert_eq!(h.fetcher.fetches(), 2);
    h.validator
        .validate(&replacement.sign(&lasting()?)?)
        .await?;
    Ok(())
}

#[tokio::test]
async fn expired_keys_that_cannot_be_refetched_fail_closed_until_a_retry_succeeds() -> TestResult {
    let h = harness()?;
    let token = h.key.sign(&lasting()?)?;
    h.validator.validate(&token).await?;
    h.fetcher.fail(true);
    h.clock.advance(Duration::from_secs(3600));
    assert!(matches!(refused(&h, &token).await?, ValidateError::Jwks(_)));
    assert!(matches!(
        refused(&h, &token).await?,
        ValidateError::KeysExpired
    ));
    assert_eq!(
        ValidateError::KeysExpired.to_string(),
        "the issuer's keys are missing or expired, and no fetch has succeeded since"
    );
    h.clock.advance(Duration::from_secs(10));
    assert!(matches!(refused(&h, &token).await?, ValidateError::Jwks(_)));
    assert_eq!(h.fetcher.fetches(), 3);
    h.fetcher.fail(false);
    h.clock.advance(Duration::from_secs(10));
    h.validator.validate(&token).await?;
    assert_eq!(h.fetcher.fetches(), 4);
    Ok(())
}

#[tokio::test]
async fn a_key_replaced_under_the_same_kid_is_refetched_no_sooner_than_allowed() -> TestResult {
    let h = harness()?;
    h.validator.validate(&h.key.sign(&claims())?).await?;

    // The issuer replaces k1 with a new key that keeps the kid.
    let replaced = TestKey::new("k1", 7)?;
    h.fetcher.set_keys(vec![replaced.jwk()]);
    let token = replaced.sign(&claims())?;
    assert!(matches!(
        refused(&h, &token).await?,
        ValidateError::Signature
    ));
    assert_eq!(h.fetcher.fetches(), 1, "refetched too soon");

    h.clock.advance(Duration::from_secs(60));
    h.validator.validate(&token).await?;
    assert_eq!(h.fetcher.fetches(), 2);

    // A forgery refetches once, then not again until jwks_refetch passes.
    let forger = TestKey::new("k1", 9)?;
    let forged = forger.sign(&claims())?;
    h.clock.advance(Duration::from_secs(60));
    assert!(matches!(
        refused(&h, &forged).await?,
        ValidateError::Signature
    ));
    assert!(matches!(
        refused(&h, &forged).await?,
        ValidateError::Signature
    ));
    assert_eq!(h.fetcher.fetches(), 3);
    Ok(())
}

#[tokio::test]
async fn refresh_due_fetches_missing_keys_and_renews_keys_before_they_expire() -> TestResult {
    let h = harness_with(INTROSPECTED)?;
    assert_eq!(h.validator.key_ages().await, [(ISSUER.to_owned(), None)]);
    h.validator.refresh_due().await;
    assert_eq!(h.fetcher.fetches(), 1, "the introspected issuer is skipped");
    assert_eq!(
        h.validator.key_ages().await,
        [(ISSUER.to_owned(), Some(Duration::ZERO))]
    );

    // Keys are renewed three quarters of the way through their hour.
    h.clock.advance(Duration::from_secs(2699));
    h.validator.refresh_due().await;
    assert_eq!(h.fetcher.fetches(), 1);
    assert_eq!(
        h.validator.key_ages().await,
        [(ISSUER.to_owned(), Some(Duration::from_secs(2699)))]
    );

    // A renewal that fails leaves the unexpired keys in use, and is retried
    // every jwks_retry.
    h.clock.advance(Duration::from_secs(1));
    h.fetcher.fail(true);
    h.validator.refresh_due().await;
    assert_eq!(h.fetcher.fetches(), 2);
    let token = h.key.sign(&lasting()?)?;
    h.validator.validate(&token).await?;
    h.clock.advance(Duration::from_secs(9));
    h.validator.refresh_due().await;
    assert_eq!(h.fetcher.fetches(), 2, "retried too soon");
    h.fetcher.fail(false);
    h.clock.advance(Duration::from_secs(1));
    h.validator.refresh_due().await;
    assert_eq!(h.fetcher.fetches(), 3);
    h.validator.validate(&token).await?;
    assert_eq!(h.fetcher.fetches(), 3);
    assert_eq!(
        h.validator.key_ages().await,
        [(ISSUER.to_owned(), Some(Duration::ZERO))]
    );
    Ok(())
}

#[tokio::test]
async fn a_forgery_stays_a_bad_signature_while_the_issuer_is_down() -> TestResult {
    let h = harness()?;
    h.validator.validate(&h.key.sign(&claims())?).await?;
    h.fetcher.fail(true);
    h.clock.advance(Duration::from_secs(60));
    let forged = TestKey::new("k1", 9)?.sign(&claims())?;
    assert!(matches!(
        refused(&h, &forged).await?,
        ValidateError::Signature
    ));
    assert_eq!(h.fetcher.fetches(), 2, "the forgery tried one refetch");
    h.validator.validate(&h.key.sign(&claims())?).await?;
    Ok(())
}

#[tokio::test]
async fn keys_for_encryption_or_without_a_kid_are_ignored() -> TestResult {
    let h = harness()?;
    let encryption = changed(h.key.jwk(), json!({ "use": "enc" }))?;
    let nameless = changed(h.key.jwk(), json!({ "kid": null }))?;
    h.fetcher.set_keys(vec![encryption, nameless]);
    assert!(matches!(
        refused(&h, &h.key.sign(&claims())?).await?,
        ValidateError::UnknownKey(_)
    ));
    Ok(())
}

#[tokio::test]
async fn a_key_without_a_use_is_a_signing_key() -> TestResult {
    let h = harness()?;
    h.fetcher
        .set_keys(vec![changed(h.key.jwk(), json!({ "use": null }))?]);
    h.validator.validate(&h.key.sign(&claims())?).await?;
    Ok(())
}

#[tokio::test]
async fn a_forged_signature_is_refused() -> TestResult {
    let h = harness()?;
    let forger = TestKey::new("k1", 9)?;
    assert!(matches!(
        refused(&h, &forger.sign(&claims())?).await?,
        ValidateError::Signature
    ));
    Ok(())
}

#[tokio::test]
async fn a_key_that_does_not_decode_is_a_bad_signature() -> TestResult {
    let h = harness()?;
    h.fetcher
        .set_keys(vec![changed(h.key.jwk(), json!({ "x": "AAAA" }))?]);
    assert!(matches!(
        refused(&h, &h.key.sign(&claims())?).await?,
        ValidateError::Signature
    ));
    Ok(())
}

#[tokio::test]
async fn the_audience_must_be_accepted() -> TestResult {
    let h = harness()?;
    for aud in [json!("tsong-alt"), json!(["other", "tsong"])] {
        let token = h.key.sign(&with(json!({ "aud": aud }))?)?;
        h.validator.validate(&token).await?;
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
        let token = h.key.sign(&with(json!({ "aud": aud }))?)?;
        assert_eq!(refused(&h, &token).await?.to_string(), expected, "{aud}");
    }
    Ok(())
}

#[tokio::test]
async fn expiry_allows_the_clock_skew_and_no_more() -> TestResult {
    let h = harness()?;
    let token = h.key.sign(&with(json!({ "exp": NOW - SKEW + 1 }))?)?;
    h.validator.validate(&token).await?;
    let token = h.key.sign(&with(json!({ "exp": NOW - SKEW }))?)?;
    assert!(matches!(refused(&h, &token).await?, ValidateError::Expired));
    Ok(())
}

#[tokio::test]
async fn expiry_is_required_and_numeric() -> TestResult {
    let h = harness()?;
    let missing = h.key.sign(&with(json!({ "exp": null }))?)?;
    assert!(matches!(
        refused(&h, &missing).await?,
        ValidateError::MissingClaim("exp")
    ));
    for bad in [json!("soon"), json!(-5.0)] {
        let token = h.key.sign(&with(json!({ "exp": bad }))?)?;
        assert!(matches!(
            refused(&h, &token).await?,
            ValidateError::InvalidClaim("exp")
        ));
    }
    let fractional = h
        .key
        .sign(&with(json!({ "exp": (NOW + 600) as f64 + 0.5 }))?)?;
    let validated = h.validator.validate(&fractional).await?;
    assert_eq!(validated.expires_at(), Some(NOW + 600));
    Ok(())
}

#[tokio::test]
async fn not_before_allows_the_clock_skew_and_no_more() -> TestResult {
    let h = harness()?;
    let token = h.key.sign(&with(json!({ "nbf": NOW + SKEW }))?)?;
    h.validator.validate(&token).await?;
    let token = h.key.sign(&with(json!({ "nbf": NOW + SKEW + 1 }))?)?;
    assert!(matches!(
        refused(&h, &token).await?,
        ValidateError::NotYetValid
    ));
    let token = h.key.sign(&with(json!({ "nbf": null }))?)?;
    h.validator.validate(&token).await?;
    let token = h.key.sign(&with(json!({ "nbf": "later" }))?)?;
    assert!(matches!(
        refused(&h, &token).await?,
        ValidateError::InvalidClaim("nbf")
    ));
    Ok(())
}

#[test]
fn scopes_come_from_scope_and_scp() -> TestResult {
    let claims = object(json!({ "scope": "a b", "scp": ["c", 7, "a"] }))?;
    let found: Vec<_> = scopes(&claims).into_iter().collect();
    assert_eq!(found, ["a", "b", "c"]);
    let entra = object(json!({ "scp": "d  e" }))?;
    let found: Vec<_> = scopes(&entra).into_iter().collect();
    assert_eq!(found, ["d", "e"]);
    let none = object(json!({ "scope": 7 }))?;
    assert!(scopes(&none).is_empty());
    Ok(())
}

#[tokio::test]
async fn keys_younger_than_the_retry_interval_still_expire_on_time() -> TestResult {
    let key = TestKey::new("k1", 1)?;
    let fetcher = Arc::new(FakeFetcher::with(vec![key.jwk()]));
    let clock = Arc::new(ManualClock::at(NOW));
    let text = CONFIG.replace(
        "jwks_refetch = \"60s\"",
        "jwks_refetch = \"60s\"\njwks_max_age = \"5s\"",
    );
    let validator = Validator::new(&Config::from_toml(&text)?, fetcher.clone(), clock.clone());
    let token = key.sign(&claims())?;
    validator.validate(&token).await?;
    clock.advance(Duration::from_secs(5));
    validator.refresh_due().await;
    assert_eq!(fetcher.fetches(), 2);
    clock.advance(Duration::from_secs(5));
    validator.validate(&token).await?;
    assert_eq!(fetcher.fetches(), 3);
    Ok(())
}
