//! Validates arbitrary text as a bearer token: it must never panic, and
//! nothing but a token the trusted issuer signed is accepted, which random
//! input never is.

#![no_main]

use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;
use tokio::runtime::Runtime;
use tsong_clock::ManualClock;
use tsong_config::Config;
use tsong_validate::Validator;
use tsong_validate::testkit::{FakeFetcher, TestKey};

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
algorithms = ["ES256", "RS256", "EdDSA"]
"#;

/// A runtime and a validator trusting one issuer, built once.
fn state() -> Option<&'static (Runtime, Validator)> {
    static STATE: OnceLock<Option<(Runtime, Validator)>> = OnceLock::new();
    STATE
        .get_or_init(|| {
            let runtime = tokio::runtime::Builder::new_current_thread().build().ok()?;
            let key = TestKey::new("k1", 1).ok()?;
            let fetcher = Arc::new(FakeFetcher::with(vec![key.jwk()]));
            let config = Config::from_toml(CONFIG).ok()?;
            let validator = Validator::new(&config, fetcher, Arc::new(ManualClock::at(1_000_000)));
            Some((runtime, validator))
        })
        .as_ref()
}

fuzz_target!(|data: &[u8]| {
    let Ok(token) = std::str::from_utf8(data) else {
        return;
    };
    let Some((runtime, validator)) = state() else {
        return;
    };
    let result = runtime.block_on(validator.validate(token));
    assert!(result.is_err(), "accepted an unsigned token: {token:?}");
});
