mod common;

use std::time::Duration;

use common::{NOW, TestResult, minted};
use tsong_gateway::lifetime;
use tsong_issuer::TokenResponse;

fn response(access_token: String, expires_in: u64) -> TokenResponse {
    TokenResponse {
        access_token,
        issued_token_type: tsong_issuer::ACCESS_TOKEN.into(),
        token_type: "Bearer".into(),
        expires_in,
        scope: None,
    }
}

#[test]
fn a_token_is_kept_until_its_exp_less_the_skew() -> TestResult {
    let skew = Duration::from_secs(30);
    let token = response(minted("a", NOW + 900)?, 1);
    assert_eq!(lifetime(&token, NOW, skew), Duration::from_secs(870));
    assert_eq!(lifetime(&token, NOW + 880, skew), Duration::ZERO);
    assert_eq!(lifetime(&token, NOW + 2000, skew), Duration::ZERO);
    Ok(())
}

#[test]
fn expires_in_stands_in_when_exp_cannot_be_read() -> TestResult {
    let skew = Duration::from_secs(30);
    for token in [
        "opaque".to_owned(),
        "h.!!!.s".to_owned(),
        "h.bm90IGpzb24.s".to_owned(),
        format!("h.{}.s", "eyJuYW1lIjoibm8gZXhwIn0"),
        format!("h.{}.s", "eyJleHAiOiJzb29uIn0"),
    ] {
        assert_eq!(
            lifetime(&response(token.clone(), 600), NOW, skew),
            Duration::from_secs(570),
            "{token}"
        );
    }
    assert_eq!(
        lifetime(&response("opaque".into(), 10), NOW, skew),
        Duration::ZERO
    );
    Ok(())
}
