mod common;

use std::sync::Arc;

use common::*;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde_json::{Map, Value, json};
use tsong_issuer::{ACCESS_TOKEN, ExchangeError, JWT, TOKEN_EXCHANGE, TokenRequest, TokenResponse};
use tsong_keys::{KeyError, KeySet, SignFuture, SigningAlgorithm, SigningKey};

/// The header and claims of a token Tsong minted, after verifying it
/// against Tsong's own JWKS.
fn verified(h: &Harness, token: &str) -> (jsonwebtoken::Header, Map<String, Value>) {
    let jwk: Jwk = serde_json::from_value(h.issuer.jwks()["keys"][0].clone()).unwrap();
    let key = DecodingKey::from_jwk(&jwk).unwrap();
    let mut validation = jsonwebtoken::Validation::new(Algorithm::ES256);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    let data = jsonwebtoken::decode::<Map<String, Value>>(token, &key, &validation).unwrap();
    (data.header, data.claims)
}

async fn exchanged(h: &Harness, request: TokenRequest) -> (TokenResponse, Map<String, Value>) {
    let response = h.issuer.exchange(request).await.unwrap();
    let (_, claims) = verified(h, &response.access_token);
    (response, claims)
}

async fn refused(h: &Harness, request: TokenRequest) -> (&'static str, String) {
    let error = h.issuer.exchange(request).await.unwrap_err();
    (error.code(), error.to_string())
}

#[tokio::test]
async fn a_subject_token_is_exchanged_for_the_route() {
    let h = harness();
    let response = h
        .issuer
        .exchange(request(&h, "orders-api", subject(json!({}))))
        .await
        .unwrap();
    assert_eq!(response.issued_token_type, ACCESS_TOKEN);
    assert_eq!(response.token_type, "Bearer");
    assert_eq!(response.expires_in, 900);
    assert_eq!(response.scope.as_deref(), Some("orders.read orders.write"));

    let (header, claims) = verified(&h, &response.access_token);
    assert_eq!(header.kid.as_deref(), Some("tsong-1"));
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
    assert_eq!(claims["iss"], "https://tsong.test");
    assert_eq!(claims["sub"], "alice");
    assert_eq!(claims["aud"], json!(["orders-api", "orders.internal.test"]));
    assert_eq!(claims["iat"], NOW);
    assert_eq!(claims["exp"], NOW + 900);
    assert_eq!(claims["scope"], "orders.read orders.write");
    assert_eq!(claims["email"], "alice@example.test");
    assert_eq!(claims["groups"], json!(["admins"]));
    assert_eq!(claims["user"], "a-1");
    assert!(!claims.contains_key("secret"));
    assert!(!claims.contains_key("uid"));
    assert!(!claims.contains_key("act"));
    assert_eq!(claims["jti"].as_str().unwrap().len(), 22);
    assert_eq!(claims.len(), 10);
}

#[tokio::test]
async fn each_token_gets_its_own_id() {
    let h = harness();
    let (_, first) = exchanged(&h, request(&h, "orders-api", subject(json!({})))).await;
    let (_, second) = exchanged(&h, request(&h, "orders-api", subject(json!({})))).await;
    assert_ne!(first["jti"], second["jti"]);
}

#[tokio::test]
async fn a_token_lives_no_longer_than_its_subject() {
    let h = harness();
    let (response, claims) = exchanged(
        &h,
        request(&h, "orders-api", subject(json!({ "exp": NOW + 60 }))),
    )
    .await;
    assert_eq!(response.expires_in, 60);
    assert_eq!(claims["exp"], NOW + 60);
    let (response, _) = exchanged(
        &h,
        request(&h, "orders-api", subject(json!({ "exp": NOW + 1 }))),
    )
    .await;
    assert_eq!(response.expires_in, 1);
}

#[tokio::test]
async fn a_subject_inside_its_skew_but_expired_is_refused() {
    let h = harness();
    for exp in [NOW, NOW - 10] {
        let (code, message) = refused(
            &h,
            request(&h, "orders-api", subject(json!({ "exp": exp }))),
        )
        .await;
        assert_eq!(code, "invalid_grant");
        assert_eq!(message, "the subject token has expired");
    }
}

#[tokio::test]
async fn requested_scopes_must_be_the_routes() {
    let h = harness();
    let mut narrowed = request(&h, "orders-api", subject(json!({})));
    narrowed.scope = Some("orders.read".into());
    let (response, claims) = exchanged(&h, narrowed).await;
    assert_eq!(response.scope.as_deref(), Some("orders.read"));
    assert_eq!(claims["scope"], "orders.read");

    let mut widened = request(&h, "orders-api", subject(json!({})));
    widened.scope = Some("orders.read orders.delete".into());
    assert_eq!(
        refused(&h, widened).await,
        (
            "invalid_scope",
            r#"scope "orders.delete" is not allowed for audience "orders-api""#.into()
        )
    );
}

#[tokio::test]
async fn a_route_without_scopes_grants_none() {
    let h = harness();
    let (response, claims) = exchanged(&h, request(&h, "plain.test", subject(json!({})))).await;
    assert_eq!(response.scope, None);
    assert!(!claims.contains_key("scope"));
    assert_eq!(claims["aud"], json!(["plain.test"]));
}

#[tokio::test]
async fn the_subject_must_hold_the_required_scopes() {
    let h = harness();
    for scope in [json!("orders.read"), json!(null)] {
        let claims = subject(json!({ "scope": scope }));
        assert_eq!(
            refused(&h, request(&h, "orders-api", claims)).await,
            (
                "invalid_grant",
                r#"the subject token lacks scope "orders""#.into()
            )
        );
    }
    let entra = subject(json!({ "scope": null, "scp": "orders other" }));
    exchanged(&h, request(&h, "orders-api", entra)).await;
}

#[tokio::test]
async fn the_audience_picks_a_route_that_trusts_the_issuer() {
    let h = harness();
    let (response, claims) = exchanged(&h, request(&h, "shared", subject(json!({})))).await;
    assert_eq!(response.scope.as_deref(), Some("b"));
    assert_eq!(claims["aud"], json!(["shared", "b.test"]));
}

#[tokio::test]
async fn the_issuer_must_be_trusted_on_the_audience_route() {
    let h = harness();
    let other = subject(json!({ "iss": "https://other.test" }));
    assert_eq!(
        refused(&h, request(&h, "orders-api", other)).await,
        (
            "invalid_target",
            r#"issuer "other" may not exchange for audience "orders-api""#.into()
        )
    );
    assert_eq!(
        refused(&h, request(&h, "nowhere", subject(json!({})))).await,
        (
            "invalid_target",
            r#"no route has audience "nowhere""#.into()
        )
    );
}

#[tokio::test]
async fn a_renamed_claim_can_supply_the_subject() {
    let h = harness();
    let (_, claims) = exchanged(
        &h,
        request(&h, "orders-api", subject(json!({ "oid": "object-7" }))),
    )
    .await;
    assert_eq!(claims["sub"], "object-7");
    let (_, claims) = exchanged(&h, request(&h, "orders-api", subject(json!({ "oid": 7 })))).await;
    assert_eq!(claims["sub"], "alice");
    let (_, claims) = exchanged(
        &h,
        request(
            &h,
            "orders-api",
            subject(json!({ "oid": "object-7", "sub": null })),
        ),
    )
    .await;
    assert_eq!(claims["sub"], "object-7");
}

#[tokio::test]
async fn renames_apply_only_to_their_issuer() {
    let h = harness();
    let claims = subject(json!({ "iss": "https://other.test", "oid": "object-7" }));
    let (_, claims) = exchanged(&h, request(&h, "shared", claims)).await;
    assert_eq!(claims["sub"], "alice");
    assert!(!claims.contains_key("user"));
    assert_eq!(claims["aud"], json!(["shared", "a.test"]));
}

#[tokio::test]
async fn a_subject_is_required() {
    let h = harness();
    assert_eq!(
        refused(
            &h,
            request(&h, "orders-api", subject(json!({ "sub": null })))
        )
        .await,
        ("invalid_grant", "the subject token has no sub".into())
    );
}

#[tokio::test]
async fn the_request_must_be_a_token_exchange() {
    let h = harness();
    for grant_type in [None, Some("client_credentials".to_string())] {
        let mut request = request(&h, "orders-api", subject(json!({})));
        request.grant_type = grant_type;
        assert_eq!(
            refused(&h, request).await,
            (
                "unsupported_grant_type",
                "only token exchange is supported".into()
            )
        );
    }
}

/// A change that makes a request malformed.
type Change = fn(&mut TokenRequest);

#[tokio::test]
async fn malformed_requests_are_invalid() {
    let h = harness();
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
        let mut request = request(&h, "orders-api", subject(json!({})));
        change(&mut request);
        assert_eq!(
            refused(&h, request).await,
            ("invalid_request", expected.into())
        );
    }
}

#[tokio::test]
async fn jwt_token_types_are_accepted() {
    let h = harness();
    let mut request = request(&h, "orders-api", subject(json!({})));
    request.subject_token_type = Some(JWT.into());
    request.requested_token_type = Some(JWT.into());
    exchanged(&h, request).await;
    let mut request2 = self::request(&h, "orders-api", subject(json!({})));
    request2.requested_token_type = Some(ACCESS_TOKEN.into());
    exchanged(&h, request2).await;
}

#[tokio::test]
async fn validation_failures_map_to_oauth_errors() {
    let h = harness();
    let expired = subject(json!({ "exp": NOW - 3600 }));
    assert_eq!(
        refused(&h, request(&h, "orders-api", expired)).await,
        ("invalid_grant", "the token has expired".into())
    );

    let mut opaque = request(&h, "orders-api", subject(json!({})));
    opaque.subject_token = Some("opaque".into());
    assert_eq!(refused(&h, opaque).await.0, "invalid_grant");

    // A fresh issuer, with no keys cached yet.
    let h = harness();
    h.fetcher.fail(true);
    let error = h
        .issuer
        .exchange(request(&h, "orders-api", subject(json!({}))))
        .await
        .unwrap_err();
    assert_eq!(error.code(), "temporarily_unavailable");
    assert_eq!(error.status(), 503);
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
async fn a_signing_failure_is_a_server_error() {
    let h = harness_with_keys(KeySet::new(Arc::new(BrokenKey), vec![]).unwrap());
    let error = h
        .issuer
        .exchange(request(&h, "orders-api", subject(json!({}))))
        .await
        .unwrap_err();
    assert!(matches!(error, ExchangeError::Server(_)));
    assert_eq!(error.code(), "server_error");
    assert_eq!(error.status(), 500);
    assert_eq!(error.to_string(), "signing: no key is active");
}

#[test]
fn unsupported_validation_is_an_invalid_request() {
    let error = ExchangeError::from(tsong_validate::ValidateError::Unsupported("introspection"));
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
fn discovery_names_the_endpoints() {
    let h = harness();
    assert_eq!(
        h.issuer.discovery(),
        json!({
            "issuer": "https://tsong.test",
            "jwks_uri": "https://tsong.test/jwks.json",
            "token_endpoint": "https://tsong.test/token",
            "grant_types_supported": [TOKEN_EXCHANGE],
        })
    );
    let keys = h.issuer.jwks();
    assert_eq!(keys["keys"][0]["kid"], "tsong-1");
}
