//! The issuer under test: a config, an inbound issuer and a fixed clock.
#![allow(dead_code)]

use std::sync::Arc;

use p256::ecdsa::SigningKey as EcKey;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use serde_json::{Value, json};
use tsong_clock::ManualClock;
use tsong_config::Config;
use tsong_issuer::{ACCESS_TOKEN, Issuer, TOKEN_EXCHANGE, TokenRequest};
use tsong_keys::{FileKey, KeySet};
use tsong_validate::Validator;
use tsong_validate::testkit::{FakeFetcher, TestKey};

pub const NOW: u64 = 1_000_000;

pub const CONFIG: &str = r#"
[issuer]
url = "https://tsong.test"
listen = "127.0.0.1:0"
token_lifetime = "15m"
clock_skew = "30s"

[issuer.signing]
provider = "file"
algorithm = "ES256"

[[issuer.signing.keys]]
kid = "tsong-1"
path = "unused.pem"
state = "active"

[gateway]
listen = "127.0.0.1:0"

[gateway.cache]
max_entries = 10

[trusted_issuers.test]
issuer = "https://issuer.test"
audiences = ["tsong"]
algorithms = ["ES256"]

[trusted_issuers.other]
issuer = "https://other.test"
audiences = ["tsong"]
algorithms = ["ES256"]

[claims]
copy = ["email", "groups"]

[claims.rename.test]
oid = "sub"
uid = "user"

[[routes]]
name = "orders"
match = { path_prefix = "/orders" }
downstream = "https://orders.internal.test/api"
trusted_issuers = ["test"]
audience = "orders-api"
scopes = ["orders.read", "orders.write"]
required_scopes = ["orders"]

[[routes]]
name = "plain"
match = { path_prefix = "/plain" }
downstream = "https://plain.test"
trusted_issuers = ["test"]
audience = "plain.test"

[[routes]]
name = "shared-other"
match = { path_prefix = "/shared-a" }
downstream = "https://a.test"
trusted_issuers = ["other"]
audience = "shared"
scopes = ["a"]

[[routes]]
name = "shared-test"
match = { path_prefix = "/shared-b" }
downstream = "https://b.test"
trusted_issuers = ["test"]
audience = "shared"
scopes = ["b"]
"#;

pub struct Harness {
    pub issuer: Arc<Issuer>,
    pub fetcher: Arc<FakeFetcher>,
    pub inbound: TestKey,
}

pub fn harness_with_keys(keys: KeySet) -> Harness {
    let config = Arc::new(Config::from_toml(CONFIG).unwrap());
    let inbound = TestKey::new("in-1", 1);
    let fetcher = Arc::new(FakeFetcher::with(vec![inbound.jwk()]));
    let clock = Arc::new(ManualClock::at(NOW));
    let validator = Validator::new(&config, fetcher.clone(), clock.clone());
    let issuer = Arc::new(Issuer::new(config, keys, validator, clock));
    Harness {
        issuer,
        fetcher,
        inbound,
    }
}

pub fn harness() -> Harness {
    let pem = EcKey::from_slice(&[5; 32])
        .unwrap()
        .to_pkcs8_pem(LineEnding::LF)
        .unwrap();
    let key = Arc::new(FileKey::from_pem("tsong-1", &pem).unwrap());
    harness_with_keys(KeySet::new(key, vec![]).unwrap())
}

pub fn subject(changes: Value) -> Value {
    let mut claims = json!({
        "iss": "https://issuer.test",
        "sub": "alice",
        "aud": "tsong",
        "exp": NOW + 3600,
        "scope": "orders",
        "email": "alice@example.test",
        "groups": ["admins"],
        "uid": "a-1",
        "secret": "not copied",
    });
    for (name, value) in changes.as_object().unwrap() {
        if value.is_null() {
            claims.as_object_mut().unwrap().remove(name);
        } else {
            claims[name] = value.clone();
        }
    }
    claims
}

pub fn request(h: &Harness, audience: &str, claims: Value) -> TokenRequest {
    TokenRequest {
        grant_type: Some(TOKEN_EXCHANGE.into()),
        subject_token: Some(h.inbound.sign(&claims)),
        subject_token_type: Some(ACCESS_TOKEN.into()),
        audience: Some(audience.into()),
        ..TokenRequest::default()
    }
}
