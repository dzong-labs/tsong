mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use common::*;
use serde_json::json;

#[tokio::test]
async fn a_request_is_forwarded_with_the_exchanged_token() -> TestResult {
    let h = harness().await?;
    let request = from(
        CLIENT,
        Request::post("/orders/42?expand=lines&x=%2F")
            .header("host", "orders.test")
            .header("authorization", "Bearer alice")
            .header("content-type", "application/json")
            .header("x-request-id", "r-1")
            .body(Body::from(r#"{"qty":2}"#))?,
    )?;
    let answer = send(&h, request).await?;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    assert_eq!(answer.header("x-echo"), Some("yes"));

    let echoed = answer.echoed()?;
    assert_eq!(echoed.get("method"), Some(&json!("POST")));
    assert_eq!(
        echoed.get("path"),
        Some(&json!("/orders/42?expand=lines&x=%2F"))
    );
    assert_eq!(echoed.get("body"), Some(&json!(r#"{"qty":2}"#)));
    assert_eq!(
        answer.received_one("authorization")?,
        format!("Bearer {}", minted("alice@orders.test", NOW + 900)?)
    );
    assert_eq!(answer.received_one("host")?, h.downstream.to_string());
    assert_eq!(answer.received_one("x-forwarded-host")?, "orders.test");
    assert_eq!(answer.received_one("x-forwarded-for")?, "10.1.2.3");
    assert_eq!(answer.received_one("x-forwarded-proto")?, "http");
    assert_eq!(answer.received_one("content-type")?, "application/json");
    assert_eq!(answer.received_one("x-request-id")?, "r-1");
    assert_eq!(
        h.exchanger.calls(),
        [("alice".to_owned(), "orders.test".to_owned())]
    );
    Ok(())
}

#[tokio::test]
async fn the_downstream_status_and_body_pass_back() -> TestResult {
    let h = harness().await?;
    let answer = send(&h, get("orders.test", "/teapot", Some("alice"))?).await?;
    assert_eq!(answer.status, StatusCode::IM_A_TEAPOT);
    assert_eq!(answer.header("x-kind"), Some("teapot"));
    assert_eq!(answer.body, "short and stout");
    Ok(())
}

#[tokio::test]
async fn hop_by_hop_and_forwarding_headers_do_not_pass() -> TestResult {
    let h = harness().await?;
    let request = from(
        CLIENT,
        Request::get("/")
            .header("host", "orders.test")
            .header("authorization", "Bearer alice")
            .header("connection", "x-secret, keep-alive")
            .header("x-secret", "1")
            .header("keep-alive", "timeout=5")
            .header("proxy-authorization", "Basic cHJveHk=")
            .header("te", "trailers")
            .header("forwarded", "for=192.0.2.1")
            .header("x-forwarded-for", "192.0.2.1")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-host", "evil.test")
            .body(Body::empty())?,
    )?;
    let answer = send(&h, request).await?;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    for name in [
        "x-secret",
        "keep-alive",
        "proxy-authorization",
        "te",
        "forwarded",
    ] {
        assert_eq!(answer.received(name)?, Vec::<String>::new(), "{name}");
    }
    assert_eq!(answer.received_one("x-forwarded-for")?, "10.1.2.3");
    assert_eq!(answer.received_one("x-forwarded-proto")?, "http");
    assert_eq!(answer.received_one("x-forwarded-host")?, "orders.test");
    assert_eq!(answer.header("keep-alive"), None);
    Ok(())
}

#[tokio::test]
async fn a_trusted_proxy_chain_is_kept() -> TestResult {
    let h = harness().await?;
    let request = from(
        "10.0.0.5:4000",
        Request::get("/")
            .header("host", "builds.test")
            .header("authorization", "Bearer alice")
            .header("x-forwarded-for", "192.0.2.1, 10.1.9.9")
            .header("x-forwarded-proto", "https")
            .body(Body::empty())?,
    )?;
    let answer = send(&h, request).await?;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    assert_eq!(
        answer.received_one("x-forwarded-for")?,
        "192.0.2.1, 10.1.9.9, 10.0.0.5"
    );
    assert_eq!(answer.received_one("x-forwarded-proto")?, "https");
    Ok(())
}

#[tokio::test]
async fn an_exchanged_token_is_cached_per_token_and_host() -> TestResult {
    let h = harness().await?;
    for _ in 0..3 {
        let answer = send(&h, get("orders.test", "/", Some("alice"))?).await?;
        assert_eq!(answer.status, StatusCode::OK);
    }
    send(&h, get("orders.test", "/", Some("bob"))?).await?;
    let answer = send(&h, get("builds.test", "/", Some("alice"))?).await?;
    assert_eq!(
        answer.received_one("authorization")?,
        format!("Bearer {}", minted("alice@builds.test", NOW + 900)?)
    );
    let calls: Vec<_> = h
        .exchanger
        .calls()
        .into_iter()
        .map(|(token, host)| format!("{token}@{host}"))
        .collect();
    assert_eq!(
        calls,
        ["alice@orders.test", "bob@orders.test", "alice@builds.test"]
    );
    Ok(())
}

#[tokio::test]
async fn concurrent_misses_share_one_exchange() -> TestResult {
    let h = harness().await?;
    let mut sends = Vec::new();
    for _ in 0..8 {
        let request = get("orders.test", "/", Some("carol"))?;
        let router = h.router.clone();
        sends.push(tokio::spawn(async move {
            tower::ServiceExt::oneshot(router, request).await
        }));
    }
    for sent in sends {
        assert_eq!(sent.await??.status(), StatusCode::OK);
    }
    assert_eq!(h.exchanger.calls().len(), 1);
    Ok(())
}

#[tokio::test]
async fn an_expiring_token_and_a_failed_exchange_are_not_kept() -> TestResult {
    let h = harness().await?;
    for token in ["expiring", "expiring", "unavailable", "unavailable"] {
        send(&h, get("orders.test", "/", Some(token))?).await?;
    }
    assert_eq!(h.exchanger.calls().len(), 4);
    Ok(())
}

#[tokio::test]
async fn an_opaque_minted_token_is_forwarded() -> TestResult {
    let h = harness().await?;
    let answer = send(&h, get("orders.test", "/", Some("opaque"))?).await?;
    assert_eq!(
        answer.received_one("authorization")?,
        "Bearer opaque-minted"
    );
    Ok(())
}

#[tokio::test]
async fn a_missing_or_malformed_bearer_token_is_a_401() -> TestResult {
    let h = harness().await?;
    for authorization in [
        None,
        Some("Basic YWxpY2U="),
        Some("Bearer"),
        Some("Bearer "),
        Some("Bearer a b"),
        Some("bearer\talice"),
    ] {
        let mut builder = Request::get("/").header("host", "orders.test");
        if let Some(value) = authorization {
            builder = builder.header("authorization", value);
        }
        let answer = send(&h, from(CLIENT, builder.body(Body::empty())?)?).await?;
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{authorization:?}");
        assert_eq!(answer.header("www-authenticate"), Some("Bearer"));
    }
    let twice = Request::get("/")
        .header("host", "orders.test")
        .header("authorization", "Bearer alice")
        .header("authorization", "Bearer bob")
        .body(Body::empty())?;
    let answer = send(&h, from(CLIENT, twice)?).await?;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert!(h.exchanger.calls().is_empty());
    Ok(())
}

#[tokio::test]
async fn the_bearer_scheme_is_case_insensitive() -> TestResult {
    let h = harness().await?;
    let request = Request::get("/")
        .header("host", "orders.test")
        .header("authorization", "BEARER alice")
        .body(Body::empty())?;
    let answer = send(&h, from(CLIENT, request)?).await?;
    assert_eq!(answer.status, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn exchange_failures_map_to_statuses() -> TestResult {
    let h = harness().await?;
    for (token, status, body) in [
        ("invalid", StatusCode::UNAUTHORIZED, "bad signature\n"),
        (
            "untargeted",
            StatusCode::FORBIDDEN,
            "audience not allowed\n",
        ),
        ("unscoped", StatusCode::FORBIDDEN, "scope not allowed\n"),
        (
            "unavailable",
            StatusCode::SERVICE_UNAVAILABLE,
            "jwks down\n",
        ),
        (
            "broken",
            StatusCode::INTERNAL_SERVER_ERROR,
            "signing failed\n",
        ),
    ] {
        let answer = send(&h, get("orders.test", "/", Some(token))?).await?;
        assert_eq!(answer.status, status, "{token}");
        assert_eq!(answer.body, body, "{token}");
    }
    let answer = send(&h, get("orders.test", "/", Some("invalid"))?).await?;
    assert_eq!(
        answer.header("www-authenticate"),
        Some(r#"Bearer error="invalid_token""#)
    );
    Ok(())
}

#[tokio::test]
async fn the_route_is_found_by_host_without_port_or_case() -> TestResult {
    let h = harness().await?;
    for host in ["orders.test:8443", "ORDERS.test"] {
        let answer = send(&h, get(host, "/", Some("alice"))?).await?;
        assert_eq!(answer.status, StatusCode::OK, "{host}");
        assert_eq!(answer.received_one("x-forwarded-host")?, host);
    }
    let absolute = Request::get("http://orders.test/abs?q=1")
        .header("authorization", "Bearer alice")
        .body(Body::empty())?;
    let answer = send(&h, from(CLIENT, absolute)?).await?;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.echoed()?.get("path"), Some(&json!("/abs?q=1")));
    assert_eq!(answer.received_one("x-forwarded-host")?, "orders.test");
    Ok(())
}

#[tokio::test]
async fn an_unknown_or_missing_host_is_a_404() -> TestResult {
    let h = harness().await?;
    let answer = send(&h, get("nowhere.test", "/", Some("alice"))?).await?;
    assert_eq!(answer.status, StatusCode::NOT_FOUND);
    let hostless = Request::get("/")
        .header("authorization", "Bearer alice")
        .body(Body::empty())?;
    assert_eq!(
        send(&h, from(CLIENT, hostless)?).await?.status,
        StatusCode::NOT_FOUND
    );
    let garbled = Request::get("/")
        .header("host", "a b")
        .body(Body::empty())?;
    assert_eq!(
        send(&h, from(CLIENT, garbled)?).await?.status,
        StatusCode::NOT_FOUND
    );
    assert!(h.exchanger.calls().is_empty());
    Ok(())
}

#[tokio::test]
async fn clients_outside_the_allow_lists_are_refused() -> TestResult {
    let h = harness().await?;
    for (peer, host, status) in [
        ("192.0.2.1:1", "orders.test", StatusCode::FORBIDDEN),
        ("10.2.0.1:1", "orders.test", StatusCode::OK),
        ("10.2.0.1:1", "builds.test", StatusCode::FORBIDDEN),
        ("10.1.0.1:1", "builds.test", StatusCode::OK),
        ("[::1]:1", "orders.test", StatusCode::OK),
        ("[::ffff:10.2.0.1]:1", "orders.test", StatusCode::OK),
        ("[::ffff:10.2.0.1]:1", "builds.test", StatusCode::FORBIDDEN),
    ] {
        let request = Request::get("/")
            .header("host", host)
            .header("authorization", "Bearer alice")
            .body(Body::empty())?;
        let answer = send(&h, from(peer, request)?).await?;
        assert_eq!(answer.status, status, "{peer} {host}");
    }
    Ok(())
}

#[tokio::test]
async fn a_forged_forwarded_for_does_not_pass_the_allow_list() -> TestResult {
    let h = harness().await?;
    let request = Request::get("/")
        .header("host", "builds.test")
        .header("authorization", "Bearer alice")
        .header("x-forwarded-for", "10.1.0.1")
        .body(Body::empty())?;
    let answer = send(&h, from("10.2.0.1:1", request)?).await?;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn a_trusted_proxy_with_a_malformed_chain_is_a_400() -> TestResult {
    let h = harness().await?;
    let request = Request::get("/")
        .header("host", "orders.test")
        .header("authorization", "Bearer alice")
        .header("x-forwarded-for", "10.1.0.1, not-an-ip")
        .body(Body::empty())?;
    let answer = send(&h, from("10.0.0.5:1", request)?).await?;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn an_unreachable_downstream_is_a_502() -> TestResult {
    let closed = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = closed.local_addr()?;
    drop(closed);
    let config = config_to(&format!("http://{address}"))?;
    let h = harness_with(&config, Arc::new(FakeExchanger::default()), address)?;
    let answer = send(&h, get("orders.test", "/", Some("alice"))?).await?;
    assert_eq!(answer.status, StatusCode::BAD_GATEWAY);
    Ok(())
}

#[tokio::test]
async fn an_empty_body_is_not_sent() -> TestResult {
    let h = harness().await?;
    let answer = send(&h, get("orders.test", "/", Some("alice"))?).await?;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    assert_eq!(answer.received("transfer-encoding")?, Vec::<String>::new());
    assert_eq!(answer.echoed()?.get("body"), Some(&json!("")));
    Ok(())
}

#[tokio::test]
async fn a_streamed_body_is_forwarded_whole() -> TestResult {
    let h = harness().await?;
    let chunks: Vec<Result<&'static str, std::io::Error>> =
        vec![Ok("one,"), Ok("two,"), Ok("three")];
    let request = from(
        CLIENT,
        Request::put("/stream")
            .header("host", "orders.test")
            .header("authorization", "Bearer alice")
            .body(Body::from_stream(futures_util::stream::iter(chunks)))?,
    )?;
    let answer = send(&h, request).await?;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    assert_eq!(answer.echoed()?.get("method"), Some(&json!("PUT")));
    assert_eq!(answer.echoed()?.get("body"), Some(&json!("one,two,three")));
    Ok(())
}
