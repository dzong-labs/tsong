use std::error::Error;
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use serde_json::{Value, json};
use tsong_config::{TokenType, TrustedIssuer, Validation};
use tsong_validate::{FetchError, HttpFetcher, JwksFetcher};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

fn jwks() -> Value {
    json!({ "keys": [{
        "kty": "EC",
        "crv": "P-256",
        "kid": "k1",
        "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
        "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
    }] })
}

/// Serves `router` on a local port and returns its base URL.
async fn serve(router: impl FnOnce(String) -> Router) -> TestResult<String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let base = format!("http://{}", listener.local_addr()?);
    let app = router(base.clone());
    tokio::spawn(async move { axum::serve(listener, app).await });
    Ok(base)
}

/// An issuer whose discovery document says `discovery` and whose JWKS is at
/// /jwks.
async fn issuer(discovery: impl Fn(&str) -> Value + Send + 'static) -> TestResult<String> {
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

fn trusted(issuer: &str, jwks_url: Option<&str>) -> TestResult<TrustedIssuer> {
    Ok(TrustedIssuer {
        issuer: issuer.into(),
        sub_prefix: "test".into(),
        audiences: vec!["tsong".into()],
        validation: Validation::Jwt,
        algorithms: vec![],
        token_types: vec![TokenType::try_from("at+jwt".to_owned())?],
        require_token_type: true,
        discovery_url: None,
        jwks_url: jwks_url.map(str::parse).transpose()?,
        jwks_max_age: Duration::from_secs(3600),
        jwks_retry: Duration::from_secs(10),
        jwks_refetch: Duration::from_secs(30),
        jwks_timeout: Duration::from_secs(10),
        introspection_url: None,
        client_id: None,
        client_secret: None,
    })
}

/// The key IDs of the JWKS fetched for `trusted`.
async fn fetch(trusted: &TrustedIssuer) -> Result<Vec<Option<String>>, FetchError> {
    let set = HttpFetcher::default().fetch(trusted).await?;
    Ok(set.keys.into_iter().map(|jwk| jwk.common.key_id).collect())
}

/// The error a fetch for `trusted` failed with, or a test failure when it
/// succeeded.
async fn fetch_error(trusted: &TrustedIssuer) -> TestResult<FetchError> {
    match fetch(trusted).await {
        Ok(kids) => Err(format!("expected a failed fetch, got {kids:?}").into()),
        Err(error) => Ok(error),
    }
}

const K1: [Option<&str>; 1] = [Some("k1")];

fn kids(kids: &[Option<String>]) -> Vec<Option<&str>> {
    kids.iter().map(Option::as_deref).collect()
}

#[tokio::test]
async fn keys_are_found_through_discovery() -> TestResult {
    let base = issuer(|base| json!({ "issuer": base, "jwks_uri": format!("{base}/jwks") })).await?;
    assert_eq!(kids(&fetch(&trusted(&base, None)?).await?), K1);
    let slashed = format!("{base}/");
    let error = fetch_error(&trusted(&slashed, None)?).await?;
    assert!(error.to_string().contains("names issuer"), "{error}");
    Ok(())
}

#[tokio::test]
async fn a_configured_discovery_url_replaces_the_well_known_path() -> TestResult {
    let base = serve(|base| {
        let document = json!({ "issuer": base, "jwks_uri": format!("{base}/jwks") });
        Router::new()
            .route(
                "/tenant/v2.0/.well-known/openid-configuration",
                get(move || async move { axum::Json(document) }),
            )
            .route("/jwks", get(|| async { axum::Json(jwks()) }))
    })
    .await?;
    let mut trusted = trusted(&base, None)?;
    assert!(matches!(fetch_error(&trusted).await?, FetchError::Http(_)));
    trusted.discovery_url =
        Some(format!("{base}/tenant/v2.0/.well-known/openid-configuration").parse()?);
    assert_eq!(kids(&fetch(&trusted).await?), K1);
    Ok(())
}

#[tokio::test]
async fn a_fetch_gives_up_after_its_timeout() -> TestResult {
    let base = serve(|base| {
        let document = json!({ "issuer": base, "jwks_uri": format!("{base}/jwks") });
        Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || async move { axum::Json(document) }),
            )
            .route(
                "/slow-discovery/.well-known/openid-configuration",
                get(|| async {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    axum::Json(json!({}))
                }),
            )
            .route(
                "/jwks",
                get(|| async {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    axum::Json(jwks())
                }),
            )
    })
    .await?;
    let mut slow_jwks = trusted(&base, None)?;
    slow_jwks.jwks_timeout = Duration::from_millis(200);
    let mut slow_discovery = slow_jwks.clone();
    slow_discovery.discovery_url =
        Some(format!("{base}/slow-discovery/.well-known/openid-configuration").parse()?);
    for trusted in [slow_jwks, slow_discovery] {
        let started = std::time::Instant::now();
        let error = fetch_error(&trusted).await?;
        assert!(
            matches!(&error, FetchError::Http(error) if error.is_timeout()),
            "{error:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(4));
    }
    Ok(())
}

#[tokio::test]
async fn a_configured_jwks_url_skips_discovery() -> TestResult {
    let base =
        serve(|_| Router::new().route("/keys", get(|| async { axum::Json(jwks()) }))).await?;
    let url = format!("{base}/keys");
    let fetched = fetch(&trusted("https://unreachable.test", Some(&url))?).await?;
    assert_eq!(kids(&fetched), K1);
    Ok(())
}

#[tokio::test]
async fn discovery_must_name_the_same_issuer() -> TestResult {
    let base = issuer(
        |base| json!({ "issuer": "https://other.test", "jwks_uri": format!("{base}/jwks") }),
    )
    .await?;
    let error = fetch_error(&trusted(&base, None)?).await?;
    assert_eq!(
        error.to_string(),
        format!(r#"discovery document: names issuer "https://other.test", not "{base}""#)
    );
    Ok(())
}

#[tokio::test]
async fn the_jwks_must_be_on_the_issuer_scheme() -> TestResult {
    let base =
        issuer(|base| json!({ "issuer": base, "jwks_uri": "https://keys.test/jwks" })).await?;
    let error = fetch_error(&trusted(&base, None)?).await?;
    assert_eq!(
        error.to_string(),
        "discovery document: jwks_uri https://keys.test/jwks is not on the issuer's scheme"
    );
    Ok(())
}

#[tokio::test]
async fn the_jwks_uri_must_parse() -> TestResult {
    let base = issuer(|base| json!({ "issuer": base, "jwks_uri": "not a url" })).await?;
    let error = fetch_error(&trusted(&base, None)?).await?;
    assert!(
        error
            .to_string()
            .starts_with("discovery document: jwks_uri: "),
        "{error}"
    );
    Ok(())
}

#[tokio::test]
async fn http_failures_are_reported() -> TestResult {
    let base = serve(|_| {
        Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
            )
            .route("/jwks", get(|| async { StatusCode::NOT_FOUND }))
            .route("/garbage", get(|| async { "not json" }))
    })
    .await?;
    for trusted in [
        trusted(&base, None)?,
        trusted("https://x.test", Some(&format!("{base}/jwks")))?,
        trusted("https://x.test", Some(&format!("{base}/garbage")))?,
    ] {
        assert!(matches!(fetch_error(&trusted).await?, FetchError::Http(_)));
    }
    Ok(())
}

#[tokio::test]
async fn a_fetcher_takes_its_client() -> TestResult {
    let base = issuer(|base| json!({ "issuer": base, "jwks_uri": format!("{base}/jwks") })).await?;
    let fetcher = HttpFetcher::new(reqwest::Client::new());
    let set = fetcher.fetch(&trusted(&base, None)?).await?;
    assert_eq!(set.keys.len(), 1);
    Ok(())
}
