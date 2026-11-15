use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use serde_json::{Value, json};
use tsong_config::{TrustedIssuer, Validation};
use tsong_validate::{FetchError, HttpFetcher, JwksFetcher};

const JWK: &str = r#"{"kty":"EC","crv":"P-256","kid":"k1","x":"WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis","y":"y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"}"#;

/// Serves `router` on a local port and returns its base URL.
async fn serve(router: impl FnOnce(String) -> Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = router(base.clone());
    tokio::spawn(async move { axum::serve(listener, app).await });
    base
}

fn jwks() -> Value {
    json!({ "keys": [serde_json::from_str::<Value>(JWK).unwrap()] })
}

/// An issuer whose discovery document says `discovery` and whose JWKS is at
/// /jwks.
async fn issuer(discovery: impl Fn(&str) -> Value + Send + 'static) -> String {
    serve(move |base| {
        let document = discovery(&base);
        Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || async move { axum::Json(document) }),
            )
            .route("/jwks", get(|| async { axum::Json(jwks()) }))
    })
    .await
}

fn trusted(issuer: &str, jwks_url: Option<&str>) -> TrustedIssuer {
    TrustedIssuer {
        issuer: issuer.into(),
        audiences: vec!["tsong".into()],
        validation: Validation::Jwt,
        algorithms: vec![],
        jwks_url: jwks_url.map(|url| url.parse().unwrap()),
        jwks_refetch: std::time::Duration::from_secs(30),
        introspection_url: None,
        client_id: None,
        client_secret_env: None,
    }
}

async fn fetch(trusted: &TrustedIssuer) -> Result<Vec<String>, FetchError> {
    let set = HttpFetcher::default().fetch(trusted).await?;
    Ok(set
        .keys
        .into_iter()
        .map(|jwk| jwk.common.key_id.unwrap())
        .collect())
}

#[tokio::test]
async fn keys_are_found_through_discovery() {
    let base = issuer(|base| json!({ "issuer": base, "jwks_uri": format!("{base}/jwks") })).await;
    assert_eq!(fetch(&trusted(&base, None)).await.unwrap(), ["k1"]);
    let slashed = format!("{base}/");
    let error = fetch(&trusted(&slashed, None)).await.unwrap_err();
    assert!(error.to_string().contains("names issuer"), "{error}");
}

#[tokio::test]
async fn a_configured_jwks_url_skips_discovery() {
    let base = serve(|_| Router::new().route("/keys", get(|| async { axum::Json(jwks()) }))).await;
    let url = format!("{base}/keys");
    assert_eq!(
        fetch(&trusted("https://unreachable.test", Some(&url)))
            .await
            .unwrap(),
        ["k1"]
    );
}

#[tokio::test]
async fn discovery_must_name_the_same_issuer() {
    let base = issuer(
        |base| json!({ "issuer": "https://other.test", "jwks_uri": format!("{base}/jwks") }),
    )
    .await;
    let error = fetch(&trusted(&base, None)).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(r#"discovery document: names issuer "https://other.test", not "{base}""#)
    );
}

#[tokio::test]
async fn the_jwks_must_be_on_the_issuer_scheme() {
    let base = issuer(|base| json!({ "issuer": base, "jwks_uri": "https://keys.test/jwks" })).await;
    let error = fetch(&trusted(&base, None)).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "discovery document: jwks_uri https://keys.test/jwks is not on the issuer's scheme"
    );
}

#[tokio::test]
async fn the_jwks_uri_must_parse() {
    let base = issuer(|base| json!({ "issuer": base, "jwks_uri": "not a url" })).await;
    let error = fetch(&trusted(&base, None)).await.unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("discovery document: jwks_uri: "),
        "{error}"
    );
}

#[tokio::test]
async fn http_failures_are_reported() {
    let base = serve(|_| {
        Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
            )
            .route("/jwks", get(|| async { StatusCode::NOT_FOUND }))
            .route("/garbage", get(|| async { "not json" }))
    })
    .await;
    for trusted in [
        trusted(&base, None),
        trusted("https://x.test", Some(&format!("{base}/jwks"))),
        trusted("https://x.test", Some(&format!("{base}/garbage"))),
    ] {
        assert!(matches!(fetch(&trusted).await, Err(FetchError::Http(_))));
    }
}

#[tokio::test]
async fn a_fetcher_takes_its_client() {
    let base = issuer(|base| json!({ "issuer": base, "jwks_uri": format!("{base}/jwks") })).await;
    let fetcher = HttpFetcher::new(reqwest::Client::new());
    let set = fetcher.fetch(&trusted(&base, None)).await.unwrap();
    assert_eq!(set.keys.len(), 1);
}
