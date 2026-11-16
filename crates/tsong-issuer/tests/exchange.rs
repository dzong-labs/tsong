mod common;

use std::sync::Arc;

use common::*;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey, Header};
use serde_json::{Map, Value, json};
use tsong_issuer::{ACCESS_TOKEN, ExchangeError, JWT, TOKEN_EXCHANGE, TokenRequest, TokenResponse};
use tsong_keys::{KeyError, KeySet, SignFuture, SigningAlgorithm, SigningKey};
use tsong_validate::ValidateError;

/// The header and claims of a token Tsong minted, after verifying it
/// against the first key in Tsong's own JWKS.
fn verified(h: &Harness, token: &str) -> TestResult<(Header, Map<String, Value>)> {
    let first = h
        .issuer
        .jwks()
        .get("keys")
        .and_then(|keys| keys.get(0))
        .cloned()
        .ok_or("the JWKS has no keys")?;
    let jwk: Jwk = serde_json::from_value(first)?;
    let key = DecodingKey::from_jwk(&jwk)?;
    let mut validation = jsonwebtoken::Validation::new(Algorithm::ES256);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    let data = jsonwebtoken::decode::<Map<String, Value>>(token, &key, &validation)?;
    Ok((data.header, data.claims))
}

/// The response to an exchange that must succeed, and its token's claims.
async fn exchanged(
    h: &Harness,
    request: TestResult<TokenRequest>,
) -> TestResult<(TokenResponse, Map<String, Value>)> {
    let response = h.issuer.exchange(request?).await?;
    let (_, claims) = verified(h, &response.access_token)?;
    Ok((response, claims))
}

/// The error an exchange that must fail returns.
async fn failure(h: &Harness, request: TestResult<TokenRequest>) -> TestResult<ExchangeError> {
    match h.issuer.exchange(request?).await {
        Ok(response) => Err(format!("expected a refusal, got {response:?}").into()),
        Err(error) => Ok(error),
    }
}

/// The OAuth error code and description of an exchange that must fail.
async fn refused(
    h: &Harness,
    request: TestResult<TokenRequest>,
) -> TestResult<(&'static str, String)> {
    let error = failure(h, request).await?;
    Ok((error.code(), error.to_string()))
}

/// `request` with `change` applied.
fn changed(
    request: TestResult<TokenRequest>,
    change: impl FnOnce(&mut TokenRequest),
) -> TestResult<TokenRequest> {
    let mut request = request?;
    change(&mut request);
    Ok(request)
}

#[tokio::test]
async fn a_subject_token_is_exchanged_for_the_route() -> TestResult {
    let h = harness()?;
    let response = h
        .issuer
        .exchange(request(&h, "orders.test", subject(json!({})))?)
        .await?;
    assert_eq!(response.issued_token_type, ACCESS_TOKEN);
    assert_eq!(response.token_type, "Bearer");
    assert_eq!(response.expires_in, 900);
    assert_eq!(response.scope.as_deref(), Some("orders.read orders.write"));

    let (header, claims) = verified(&h, &response.access_token)?;
    assert_eq!(header.kid.as_deref(), Some("tsong-1"));
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
    for (name, value) in [
        ("iss", json!("https://tsong.test")),
        ("sub", json!("alice")),
        ("aud", json!(["tsong", "orders.test"])),
        ("iat", json!(NOW)),
        ("exp", json!(NOW + 900)),
        ("scope", json!("orders.read orders.write")),
        ("email", json!("alice@example.test")),
        ("groups", json!(["admins"])),
        ("user", json!("a-1")),
    ] {
        assert_eq!(claims.get(name), Some(&value), "{name}");
    }
    for absent in ["secret", "uid", "act"] {
        assert!(!claims.contains_key(absent), "{absent}");
    }
    assert_eq!(
        claims.get("jti").and_then(Value::as_str).map(str::len),
        Some(22)
    );
    assert_eq!(claims.len(), 10);
    Ok(())
}

#[tokio::test]
async fn each_token_gets_its_own_id() -> TestResult {
    let h = harness()?;
    let (_, first) = exchanged(&h, request(&h, "orders.test", subject(json!({})))).await?;
    let (_, second) = exchanged(&h, request(&h, "orders.test", subject(json!({})))).await?;
    assert!(first.contains_key("jti"));
    assert_ne!(first.get("jti"), second.get("jti"));
    Ok(())
}

#[tokio::test]
async fn a_token_lives_no_longer_than_its_subject() -> TestResult {
    let h = harness()?;
    let (response, claims) = exchanged(
        &h,
        request(&h, "orders.test", subject(json!({ "exp": NOW + 60 }))),
    )
    .await?;
    assert_eq!(response.expires_in, 60);
    assert_eq!(claims.get("exp"), Some(&json!(NOW + 60)));
    let (response, _) = exchanged(
        &h,
        request(&h, "orders.test", subject(json!({ "exp": NOW + 1 }))),
    )
    .await?;
    assert_eq!(response.expires_in, 1);
    Ok(())
}

#[tokio::test]
async fn a_subject_inside_its_skew_but_expired_is_refused() -> TestResult {
    let h = harness()?;
    for exp in [NOW, NOW - 10] {
        assert_eq!(
            refused(
                &h,
                request(&h, "orders.test", subject(json!({ "exp": exp })))
            )
            .await?,
            ("invalid_grant", "the subject token has expired".into())
        );
    }
    Ok(())
}

#[tokio::test]
async fn requested_scopes_narrow_the_subjects() -> TestResult {
    let h = harness()?;
    let narrowed = changed(request(&h, "orders.test", subject(json!({}))), |r| {
        r.scope = Some("orders.write orders.read orders.write".into());
    });
    let (response, claims) = exchanged(&h, narrowed).await?;
    assert_eq!(response.scope.as_deref(), Some("orders.read orders.write"));
    assert_eq!(
        claims.get("scope"),
        Some(&json!("orders.read orders.write"))
    );

    let one = changed(request(&h, "orders.test", subject(json!({}))), |r| {
        r.scope = Some("orders.write".into());
    });
    let (response, _) = exchanged(&h, one).await?;
    assert_eq!(response.scope.as_deref(), Some("orders.write"));

    let widened = changed(
        request(
            &h,
            "orders.test",
            subject(json!({ "scope": "orders.read" })),
        ),
        |r| r.scope = Some("orders.read orders.write".into()),
    );
    assert_eq!(
        refused(&h, widened).await?,
        (
            "invalid_scope",
            r#"the subject token lacks scope "orders.write""#.into()
        )
    );
    Ok(())
}

#[tokio::test]
async fn a_subject_without_scopes_gets_none() -> TestResult {
    let h = harness()?;
    let claims = subject(json!({ "scope": null }));
    let (response, claims) = exchanged(&h, request(&h, "orders.test", claims)).await?;
    assert_eq!(response.scope, None);
    assert!(!claims.contains_key("scope"));
    Ok(())
}

#[tokio::test]
async fn the_route_refuses_scopes_it_does_not_allow() -> TestResult {
    let h = harness()?;
    let claims = subject(json!({ "scope": "orders.read admin" }));
    assert_eq!(
        refused(&h, request(&h, "orders.test", claims)).await?,
        (
            "invalid_scope",
            r#"scope "admin" is not allowed for route "orders""#.into()
        )
    );
    let entra = subject(json!({ "scope": null, "scp": ["orders.read"] }));
    let (response, _) = exchanged(&h, request(&h, "orders.test", entra)).await?;
    assert_eq!(response.scope.as_deref(), Some("orders.read"));
    Ok(())
}

#[tokio::test]
async fn a_route_with_no_allowed_scopes_refuses_every_subject() -> TestResult {
    let h = harness()?;
    for scope in [json!("orders.read"), json!(null)] {
        let claims = subject(json!({ "scope": scope }));
        assert_eq!(
            refused(&h, request(&h, "closed.test", claims)).await?,
            ("invalid_scope", r#"route "closed" allows no scopes"#.into())
        );
    }
    Ok(())
}

#[tokio::test]
async fn the_subject_must_carry_an_audience_the_route_allows() -> TestResult {
    let h = harness()?;
    let claims = subject(json!({ "aud": "api" }));
    assert_eq!(
        refused(&h, request(&h, "orders.test", claims)).await?,
        (
            "invalid_target",
            r#"the subject token's audience is not allowed for "orders.test""#.into()
        )
    );
    let claims = subject(json!({ "aud": ["api", "tsong"] }));
    let (_, claims) = exchanged(&h, request(&h, "orders.test", claims)).await?;
    assert_eq!(
        claims.get("aud"),
        Some(&json!(["api", "tsong", "orders.test"]))
    );
    Ok(())
}

#[tokio::test]
async fn the_appended_audience_is_not_repeated() -> TestResult {
    let h = harness()?;
    let claims = subject(json!({ "aud": ["orders.test", "tsong"] }));
    let (_, claims) = exchanged(&h, request(&h, "orders.test", claims)).await?;
    assert_eq!(claims.get("aud"), Some(&json!(["orders.test", "tsong"])));
    Ok(())
}

#[tokio::test]
async fn a_star_route_accepts_any_audience_and_scope_and_appends_nothing() -> TestResult {
    let h = harness()?;
    let claims = subject(json!({ "aud": "api", "scope": "admin root" }));
    let (response, claims) = exchanged(&h, request(&h, "open.test", claims)).await?;
    assert_eq!(response.scope.as_deref(), Some("admin root"));
    assert_eq!(claims.get("aud"), Some(&json!(["api"])));
    Ok(())
}

#[tokio::test]
async fn the_audience_names_a_route_host_without_regard_to_case() -> TestResult {
    let h = harness()?;
    exchanged(&h, request(&h, "ORDERS.test", subject(json!({})))).await?;
    assert_eq!(
        refused(&h, request(&h, "nowhere", subject(json!({})))).await?,
        ("invalid_target", r#"no route has host "nowhere""#.into())
    );
    Ok(())
}

#[tokio::test]
async fn every_trusted_issuer_may_exchange_for_every_route() -> TestResult {
    let h = harness()?;
    let other = subject(json!({ "iss": "https://other.test" }));
    let (_, claims) = exchanged(&h, request(&h, "orders.test", other)).await?;
    assert_eq!(claims.get("aud"), Some(&json!(["tsong", "orders.test"])));
    Ok(())
}

#[tokio::test]
async fn a_renamed_claim_can_supply_the_subject() -> TestResult {
    let h = harness()?;
    for (changes, sub) in [
        (json!({ "oid": "object-7" }), "object-7"),
        (json!({ "oid": 7 }), "alice"),
        (json!({ "oid": "object-7", "sub": null }), "object-7"),
    ] {
        let (_, claims) = exchanged(&h, request(&h, "orders.test", subject(changes))).await?;
        assert_eq!(claims.get("sub"), Some(&json!(sub)));
    }
    Ok(())
}

#[tokio::test]
async fn renames_apply_only_to_their_issuer() -> TestResult {
    let h = harness()?;
    let claims = subject(json!({ "iss": "https://other.test", "oid": "object-7" }));
    let (_, claims) = exchanged(&h, request(&h, "orders.test", claims)).await?;
    assert_eq!(claims.get("sub"), Some(&json!("alice")));
    assert!(!claims.contains_key("user"));
    assert_eq!(claims.get("aud"), Some(&json!(["tsong", "orders.test"])));
    Ok(())
}

#[tokio::test]
async fn a_subject_is_required() -> TestResult {
    let h = harness()?;
    assert_eq!(
        refused(
            &h,
            request(&h, "orders.test", subject(json!({ "sub": null })))
        )
        .await?,
        ("invalid_grant", "the subject token has no sub".into())
    );
    Ok(())
}

#[tokio::test]
async fn the_request_must_be_a_token_exchange() -> TestResult {
    let h = harness()?;
    for grant_type in [None, Some("client_credentials".to_string())] {
        let request = changed(request(&h, "orders.test", subject(json!({}))), |r| {
            r.grant_type = grant_type;
        });
        assert_eq!(
            refused(&h, request).await?,
            (
                "unsupported_grant_type",
                "only token exchange is supported".into()
            )
        );
    }
    Ok(())
}

/// A change that makes a request malformed.
type Change = fn(&mut TokenRequest);

#[tokio::test]
async fn malformed_requests_are_invalid() -> TestResult {
    let h = harness()?;
    let cases: Vec<(Change, &str)> = vec![
        (
            |r| r.actor_token = Some("actor".into()),
            "actor tokens are not supported yet",
        ),
        (
            |r| r.actor_token_type = Some(JWT.into()),
            "actor tokens are not supported yet",
        ),
        (
            |r| r.resource = Some("https://orders.internal.test".into()),
            "resource is not supported; name the audience",
        ),
        (|r| r.subject_token = None, "subject_token is required"),
        (
            |r| r.subject_token_type = None,
            "subject_token_type is required",
        ),
        (
            |r| r.subject_token_type = Some("urn:ietf:params:oauth:token-type:id_token".into()),
            "subject_token_type must be an access token or a JWT",
        ),
        (
            |r| r.requested_token_type = Some("urn:ietf:params:oauth:token-type:saml2".into()),
            "requested_token_type must be an access token or a JWT",
        ),
        (|r| r.audience = None, "audience is required"),
    ];
    for (change, expected) in cases {
        let request = changed(request(&h, "orders.test", subject(json!({}))), change);
        assert_eq!(
            refused(&h, request).await?,
            ("invalid_request", expected.into())
        );
    }
    Ok(())
}

#[tokio::test]
async fn jwt_token_types_are_accepted() -> TestResult {
    let h = harness()?;
    let jwt = changed(request(&h, "orders.test", subject(json!({}))), |r| {
        r.subject_token_type = Some(JWT.into());
        r.requested_token_type = Some(JWT.into());
    });
    exchanged(&h, jwt).await?;
    let access = changed(request(&h, "orders.test", subject(json!({}))), |r| {
        r.requested_token_type = Some(ACCESS_TOKEN.into());
    });
    exchanged(&h, access).await?;
    Ok(())
}

#[tokio::test]
async fn validation_failures_map_to_oauth_errors() -> TestResult {
    let h = harness()?;
    let expired = subject(json!({ "exp": NOW - 3600 }));
    assert_eq!(
        refused(&h, request(&h, "orders.test", expired)).await?,
        ("invalid_grant", "the token has expired".into())
    );

    let opaque = changed(request(&h, "orders.test", subject(json!({}))), |r| {
        r.subject_token = Some("opaque".into());
    });
    assert_eq!(refused(&h, opaque).await?.0, "invalid_grant");

    // A fresh issuer, with no keys cached yet.
    let h = harness()?;
    h.fetcher.fail(true);
    let error = failure(&h, request(&h, "orders.test", subject(json!({})))).await?;
    assert_eq!(error.code(), "temporarily_unavailable");
    assert_eq!(error.status(), 503);
    Ok(())
}

/// A key whose signer is down.
struct BrokenKey;

impl SigningKey for BrokenKey {
    fn kid(&self) -> &str {
        "broken"
    }
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::ES256
    }
    fn public_jwk(&self) -> Value {
        json!({ "kid": "broken" })
    }
    fn sign<'a>(&'a self, _: &'a [u8]) -> SignFuture<'a> {
        Box::pin(async { Err(KeyError::NoActiveKey) })
    }
}

#[tokio::test]
async fn a_signing_failure_is_a_server_error() -> TestResult {
    let h = harness_with_keys(KeySet::new(Arc::new(BrokenKey), vec![])?)?;
    let error = failure(&h, request(&h, "orders.test", subject(json!({})))).await?;
    assert!(matches!(error, ExchangeError::Server(_)));
    assert_eq!(error.code(), "server_error");
    assert_eq!(error.status(), 500);
    assert_eq!(error.to_string(), "signing: no key is active");
    Ok(())
}

#[test]
fn unsupported_validation_is_an_invalid_request() {
    let error = ExchangeError::from(ValidateError::Unsupported("introspection"));
    assert_eq!(error.code(), "invalid_request");
    assert_eq!(error.to_string(), "introspection is not supported yet");
}

#[test]
fn error_codes_and_statuses() {
    for (error, code, status) in [
        (
            ExchangeError::UnsupportedGrantType,
            "unsupported_grant_type",
            400,
        ),
        (
            ExchangeError::InvalidRequest(String::new()),
            "invalid_request",
            400,
        ),
        (
            ExchangeError::InvalidGrant(String::new()),
            "invalid_grant",
            400,
        ),
        (
            ExchangeError::InvalidTarget(String::new()),
            "invalid_target",
            400,
        ),
        (
            ExchangeError::InvalidScope(String::new()),
            "invalid_scope",
            400,
        ),
        (
            ExchangeError::Unavailable(String::new()),
            "temporarily_unavailable",
            503,
        ),
        (ExchangeError::Server(String::new()), "server_error", 500),
    ] {
        assert_eq!((error.code(), error.status()), (code, status));
    }
}

#[test]
fn discovery_names_the_endpoints() -> TestResult {
    let h = harness()?;
    assert_eq!(
        h.issuer.discovery(),
        json!({
            "issuer": "https://tsong.test",
            "jwks_uri": "https://tsong.test/jwks.json",
            "token_endpoint": "https://tsong.test/token",
            "grant_types_supported": [TOKEN_EXCHANGE],
        })
    );
    let kid = h
        .issuer
        .jwks()
        .get("keys")
        .and_then(|keys| keys.get(0))
        .and_then(|key| key.get("kid"))
        .cloned();
    assert_eq!(kid, Some(json!("tsong-1")));
    Ok(())
}
