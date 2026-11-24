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
            .header("x-forwarded-host", "public.example.com")
            .body(Body::empty())?,
    )?;
    let answer = send(&h, request).await?;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    assert_eq!(
        answer.received_one("x-forwarded-for")?,
        "192.0.2.1, 10.1.9.9, 10.0.0.5"
    );
    assert_eq!(answer.received_one("x-forwarded-proto")?, "https");
    assert_eq!(
        answer.received_one("x-forwarded-host")?,
        "public.example.com"
    );
    Ok(())
}

#[tokio::test]
async fn unreadable_hops_left_of_the_client_pass_through() -> TestResult {
    let h = harness().await?;
    let request = from(
        "10.0.0.5:4000",
        Request::get("/")
            .header("host", "builds.test")
            .header("authorization", "Bearer alice")
            .header(
                "x-forwarded-for",
                axum::http::HeaderValue::from_bytes(b"caf\xe9, unknown")?,
            )
            .header("x-forwarded-for", "10.1.9.9")
            .body(Body::empty())?,
    )?;
    let answer = send(&h, request).await?;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
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

/// Asserts the gateway answered a 401 with `challenge` and `body` itself,
/// so the downstream never saw the request.
fn assert_refused(answer: &Answer, challenge: &str, body: &str, case: &str) {
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{case}");
    assert_eq!(answer.header("www-authenticate"), Some(challenge), "{case}");
    assert_eq!(answer.header("x-echo"), None, "{case}");
    assert_eq!(answer.body, body, "{case}");
}

#[tokio::test]
async fn malformed_headers_and_other_schemes_are_refused() -> TestResult {
    const MALFORMED: &str = "a bearer token is required\n";
    const UNSUPPORTED: &str = "only the Bearer scheme is accepted\n";
    const REPEATED: &str = "more than one Authorization header\n";
    let h = harness().await?;
    for (values, body) in [
        (&[""][..], MALFORMED),
        (&["Bearer"], MALFORMED),
        (&["Bearer "], MALFORMED),
        (&["bearer   "], MALFORMED),
        (&["Bearer a b"], MALFORMED),
        (&[" Bearer alice"], MALFORMED),
        (&["Bearer\talice"], MALFORMED),
        (&["Bearer al\tice"], MALFORMED),
        (&["Bearer alice\t"], MALFORMED),
        (&["Bearer alice", "Bearer bob"], REPEATED),
        (&["Bearer alice", "Basic YWxpY2U="], REPEATED),
        (&["", ""], REPEATED),
        (&["Basic YWxpY2U6c2VjcmV0"], UNSUPPORTED),
        (&["basic YWxpY2U6c2VjcmV0"], UNSUPPORTED),
        (&["Basic"], UNSUPPORTED),
        (&["DPoP eyJhbGciOiJFUzI1NiJ9.e30.c2ln"], UNSUPPORTED),
        (&["Negotiate YIIBhwYGKwYBBQUCoIIBezCCAXc="], UNSUPPORTED),
    ] {
        let answer = send(&h, authorized(values)?).await?;
        assert_refused(&answer, "Bearer", body, &format!("{values:?}"));
    }
    assert!(h.exchanger.calls().is_empty());
    assert_eq!(h.anonymous("orders", 401), 0);
    Ok(())
}

#[tokio::test]
async fn a_request_without_a_token_passes_through_unexchanged() -> TestResult {
    let h = harness().await?;
    let request = from(
        CLIENT,
        Request::post("/catalog?page=2")
            .header("host", "orders.test")
            .header("x-request-id", "r-anon")
            .header("proxy-authorization", "Basic cHJveHk=")
            .body(Body::from("hello"))?,
    )?;
    let answer = send(&h, request).await?;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    assert_eq!(answer.header("x-echo"), Some("yes"));
    assert!(answer.received("authorization")?.is_empty());
    assert!(answer.received("proxy-authorization")?.is_empty());
    let echoed = answer.echoed()?;
    assert_eq!(echoed.get("path"), Some(&json!("/catalog?page=2")));
    assert_eq!(echoed.get("body"), Some(&json!("hello")));
    assert_eq!(answer.received_one("x-forwarded-for")?, "10.1.2.3");
    assert_eq!(answer.received_one("x-request-id")?, "r-anon");

    assert!(h.exchanger.calls().is_empty());
    assert_eq!(
        (h.metrics.cache_hits.get(), h.metrics.cache_misses.get()),
        (0, 0)
    );
    assert_eq!(h.anonymous("orders", 200), 1);
    Ok(())
}

#[tokio::test]
async fn an_anonymous_request_is_counted_with_the_status_it_got() -> TestResult {
    let (_refusing, h) = refusing_harness()?;
    let answer = send(&h, get("orders.test", "/", None)?).await?;
    assert_eq!(answer.status, StatusCode::BAD_GATEWAY);
    assert_eq!(h.anonymous("orders", 502), 1);
    Ok(())
}

#[tokio::test]
async fn an_access_token_in_the_query_is_refused_as_a_downstream_reads_it() -> TestResult {
    let h = harness().await?;
    let refused = [
        "access_token=alice",
        "page=2&access_token=alice",
        "access_token",
        "access_token=",
        "%61ccess_token=alice",
        "access%5Ftoken=alice",
        "access%5ftoken=alice",
        "ACCESS_TOKEN=alice",
        "Access_Token=alice",
        "Access_token=alice",
        "x=1;access_token=alice",
        "access.token=alice",
        "access+token=alice",
        "access%20token=alice",
        "access%5Btoken=alice",
        "access_token[]=alice",
        "access_token[x]=alice",
        "access_token%5B%5D=alice",
        "+access_token=alice",
        "%20access_token=alice",
        "access_token%00x=alice",
        "acce%C5%BF%C5%BF_token=alice",
        "ACCE%C5%BFS_TO%E2%84%AAEN=alice",
        "access_to%E2%84%AAen=alice",
        "access-token=alice",
        "access__token=alice",
        "access%255Ftoken=alice",
        "access%25255Ftoken=alice",
        "access%u005Ftoken=alice",
        "%U0061ccess_token=alice",
        "acce%u017Fs_token=alice",
        "%uFF41ccess_token=alice",
        "%EF%BC%A1ccess_token=alice",
    ];
    for query in refused {
        for token in [None, Some("alice")] {
            let answer = send(&h, get("orders.test", &format!("/?{query}"), token)?).await?;
            assert_refused(
                &answer,
                "Bearer",
                "a token in the query is not accepted\n",
                &format!("{query} {token:?}"),
            );
        }
    }
    assert!(h.exchanger.calls().is_empty());
    // Each refused query was sent once without an Authorization header.
    assert_eq!(h.anonymous("orders", 401), u64::try_from(refused.len())?);
    for query in [
        "my_access_token=x",
        "access_token_x=1",
        "x=access_token",
        "x=1;y=access_token",
        "access%5token=x",
        "access_tokens=x",
        "xaccess_token=x",
        "x=a%26access_token%3Dy",
        "access%u5Ftoken=x",
        "access%2525255Ftoken=x",
    ] {
        let answer = send(&h, get("orders.test", &format!("/?{query}"), None)?).await?;
        assert_eq!(answer.status, StatusCode::OK, "{query}");
    }
    Ok(())
}

#[tokio::test]
async fn a_bearer_token_of_visible_ascii_is_exchanged() -> TestResult {
    let h = harness().await?;
    let tokens = [
        "AZaz09-._~+/==",
        "glpat:x%2Cy,z",
        "al!ce=x",
        "=alice",
        "===",
        r##"!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"##,
    ];
    for token in tokens {
        let answer = send(&h, get("orders.test", "/", Some(token))?).await?;
        assert_eq!(answer.status, StatusCode::OK, "{token}: {}", answer.body);
    }
    let exchanged: Vec<String> = h.exchanger.calls().into_iter().map(|(t, _)| t).collect();
    assert_eq!(exchanged, tokens);
    Ok(())
}

#[tokio::test]
async fn a_bad_bearer_token_is_refused_not_passed_through() -> TestResult {
    let h = harness().await?;
    let answer = send(&h, get("orders.test", "/", Some("invalid"))?).await?;
    assert_refused(
        &answer,
        r#"Bearer error="invalid_token""#,
        "bad signature\n",
        "invalid",
    );
    let answer = send(&h, get("orders.test", "/", Some("unscoped"))?).await?;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(answer.header("x-echo"), None);
    assert_eq!(
        (h.anonymous("orders", 401), h.anonymous("orders", 403)),
        (0, 0)
    );
    Ok(())
}

#[tokio::test]
async fn the_bearer_scheme_is_case_insensitive() -> TestResult {
    let h = harness().await?;
    for scheme in ["BEARER", "bearer", "bEaReR"] {
        let answer = send(&h, authorized(&[&format!("{scheme} alice")])?).await?;
        assert_eq!(answer.status, StatusCode::OK, "{scheme}");
        assert_eq!(
            answer.received_one("authorization")?,
            format!("Bearer {}", minted("alice@orders.test", NOW + 900)?),
            "{scheme}"
        );
    }
    assert_eq!(h.exchanger.calls().len(), 1);
    assert_eq!(h.metrics.cache_hits.get(), 2);
    assert_eq!(h.anonymous("orders", 200), 0);
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
            "token exchange is unavailable\n",
        ),
        (
            "broken",
            StatusCode::INTERNAL_SERVER_ERROR,
            "token exchange failed\n",
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
async fn the_allow_lists_refuse_anonymous_requests_too() -> TestResult {
    let h = harness().await?;
    for (peer, host, status) in [
        ("192.0.2.1:1", "orders.test", StatusCode::FORBIDDEN),
        ("10.2.0.1:1", "builds.test", StatusCode::FORBIDDEN),
        ("10.1.0.1:1", "builds.test", StatusCode::OK),
    ] {
        let request = Request::get("/").header("host", host).body(Body::empty())?;
        let answer = send(&h, from(peer, request)?).await?;
        assert_eq!(answer.status, status, "{peer} {host}");
    }
    assert_eq!(h.anonymous("builds", 200), 1);
    assert_eq!(
        (h.anonymous("orders", 403), h.anonymous("builds", 403)),
        (1, 1)
    );
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
    let (_refusing, h) = refusing_harness()?;
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

#[tokio::test]
async fn a_stalled_downstream_is_a_504_after_its_read_timeout() -> TestResult {
    let address = downstream().await?;
    let mut config = config_to(&format!("http://{address}"))?;
    config.gateway.read_timeout = std::time::Duration::from_millis(200);
    for route in &mut config.routes {
        if route.name == "builds" {
            route.read_timeout = Some(std::time::Duration::from_secs(10));
        }
    }
    let h = harness_with(&config, Arc::new(FakeExchanger::default()), address)?;
    let answer = send(&h, get("orders.test", "/stall", Some("alice"))?).await?;
    assert_eq!(answer.status, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(answer.body, "the downstream did not answer in time\n");
    let answer = send(&h, get("builds.test", "/stall", Some("alice"))?).await?;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    Ok(())
}

#[tokio::test]
async fn each_request_is_correlated_downstream_and_back() -> TestResult {
    let h = harness().await?;
    let request = from(
        CLIENT,
        Request::get("/")
            .header("host", "orders.test")
            .header("authorization", "Bearer alice")
            .header("x-request-id", "r-9")
            .header(
                "traceparent",
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            )
            .body(Body::empty())?,
    )?;
    let answer = send(&h, request).await?;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    assert_eq!(answer.header("x-request-id"), Some("r-9"));
    assert_eq!(answer.received_one("x-request-id")?, "r-9");
    let traceparent = answer.received_one("traceparent")?;
    assert_eq!(
        tsong_issuer::trace_id(&traceparent),
        Some("4bf92f3577b34da6a3ce929d0e0e4736")
    );
    assert_eq!(
        h.exchanger.contexts(),
        [tsong_issuer::ExchangeContext {
            request_id: Some("r-9".into()),
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".into()),
        }]
    );

    let refused = send(&h, get("nowhere.test", "/", Some("alice"))?).await?;
    let id = refused.header("x-request-id").ok_or("no request ID")?;
    assert_eq!(id.len(), 32, "even a refusal carries a request ID");
    Ok(())
}

#[tokio::test]
async fn the_cache_counts_hits_and_misses() -> TestResult {
    let h = harness().await?;
    for token in ["alice", "alice", "alice", "bob", "unavailable"] {
        send(&h, get("orders.test", "/", Some(token))?).await?;
    }
    assert_eq!(h.metrics.cache_misses.get(), 3);
    assert_eq!(h.metrics.cache_hits.get(), 2);
    assert_eq!(h.metrics.cache_entries.get(), 2);
    Ok(())
}

#[tokio::test]
async fn requests_are_counted_by_route_and_status_and_timed() -> TestResult {
    use prometheus_client::registry::Registry;
    use tsong_gateway::{RouteLabel, RouteStatus};

    let h = harness().await?;
    send(&h, get("orders.test", "/", Some("alice"))?).await?;
    send(&h, get("orders.test", "/", None)?).await?;
    send(&h, get("orders.test", "/", Some("invalid"))?).await?;
    send(&h, get("nowhere.test", "/", Some("alice"))?).await?;
    let count = |route: &str, status: u16, anonymous: bool| {
        h.metrics
            .requests
            .get_or_create(&RouteStatus {
                route: route.into(),
                status,
                anonymous,
            })
            .get()
    };
    assert_eq!(count("orders", 200, false), 1);
    assert_eq!(count("orders", 200, true), 1);
    assert_eq!(count("orders", 401, false), 1);
    assert_eq!(count("-", 404, false), 1);

    let mut registry = Registry::default();
    registry.register("downstream", "timing", h.metrics.downstream_seconds.clone());
    let mut text = String::new();
    prometheus_client::encoding::text::encode(&mut text, &registry)?;
    assert!(
        text.contains(r#"downstream_count{route="orders"} 2"#),
        "{text}"
    );
    h.metrics
        .downstream_seconds
        .get_or_create(&RouteLabel {
            route: "orders".into(),
        })
        .observe(0.0);
    Ok(())
}

#[tokio::test]
async fn each_default_credential_parameter_is_refused_in_the_query() -> TestResult {
    let h = harness().await?;
    for query in [
        "access_token=x",
        "private_token=x",
        "PRIVATE_TOKEN=x",
        "job_token=x",
        "Job-Token=x",
        "api_key=x",
        "API.KEY=x",
    ] {
        for token in [None, Some("alice")] {
            let answer = send(&h, get("orders.test", &format!("/?{query}"), token)?).await?;
            assert_refused(
                &answer,
                "Bearer",
                "a token in the query is not accepted\n",
                &format!("{query} {token:?}"),
            );
        }
    }
    assert!(h.exchanger.calls().is_empty());
    Ok(())
}

#[tokio::test]
async fn each_default_credential_header_is_refused_in_any_case() -> TestResult {
    let h = harness().await?;
    for (header, configured) in [
        ("PRIVATE-TOKEN", "PRIVATE-TOKEN"),
        ("private-token", "PRIVATE-TOKEN"),
        ("JOB-TOKEN", "JOB-TOKEN"),
        ("Job-Token", "JOB-TOKEN"),
        ("X-API-Key", "X-API-Key"),
        ("x-api-key", "X-API-Key"),
        ("X_API_Key", "X-API-Key"),
        ("x_api_key", "X-API-Key"),
        ("X-Api_Key", "X-API-Key"),
        ("private_token", "PRIVATE-TOKEN"),
        ("PRIVATE_TOKEN", "PRIVATE-TOKEN"),
    ] {
        for token in [None, Some("alice")] {
            let mut builder = Request::get("/")
                .header("host", "orders.test")
                .header(header, "glpat-secret");
            if let Some(token) = token {
                builder = builder.header("authorization", format!("Bearer {token}"));
            }
            let answer = send(&h, from(CLIENT, builder.body(Body::empty())?)?).await?;
            assert_refused(
                &answer,
                "Bearer",
                &format!("the {configured} header is not accepted\n"),
                &format!("{header} {token:?}"),
            );
        }
    }
    assert!(h.exchanger.calls().is_empty());
    Ok(())
}

#[tokio::test]
async fn configured_lists_replace_the_defaults_but_access_token_stays() -> TestResult {
    let address = downstream().await?;
    let mut config = config_to(&format!("http://{address}"))?;
    config.gateway.refused_query_params = vec!["sig".into()];
    config.gateway.refused_headers = vec!["X-Session".into()];
    let h = harness_with(&config, Arc::new(FakeExchanger::default()), address)?;
    let answer = send(&h, get("orders.test", "/?SIG=1", None)?).await?;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    let session = Request::get("/")
        .header("host", "orders.test")
        .header("x-session", "s")
        .body(Body::empty())?;
    let answer = send(&h, from(CLIENT, session)?).await?;
    assert_eq!(answer.body, "the X-Session header is not accepted\n");
    let answer = send(&h, get("orders.test", "/?api_key=1", None)?).await?;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    let answer = send(&h, get("orders.test", "/?Access-Token=1", None)?).await?;
    assert_eq!(
        answer.status,
        StatusCode::UNAUTHORIZED,
        "access_token is always refused"
    );
    let session = Request::get("/")
        .header("host", "orders.test")
        .header("x_session", "s")
        .body(Body::empty())?;
    let answer = send(&h, from(CLIENT, session)?).await?;
    assert_eq!(answer.body, "the X-Session header is not accepted\n");
    Ok(())
}
