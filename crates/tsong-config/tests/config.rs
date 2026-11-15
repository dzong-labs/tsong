use std::time::Duration;

use tsong_config::{
    Config, ConfigError, InboundAlgorithm, KeyProvider, KeyState, SigningAlgorithm, Validation,
};

const SAMPLE: &str = include_str!("../../../examples/tsong.toml");

const ISSUER: &str = r#"
[issuer]
url = "https://tsong.example.com"
token_lifetime = "15m"
clock_skew = "30s"

[issuer.signing]
provider = "file"
algorithm = "ES256"
"#;

const ACTIVE_KEY: &str = r#"
[[issuer.signing.keys]]
kid = "k1"
path = "k1.pem"
state = "active"
"#;

const GATEWAY: &str = r#"
[gateway]
listen = "127.0.0.1:8443"

[gateway.cache]
max_entries = 10
"#;

const OKTA: &str = r#"
[trusted_issuers.okta]
issuer = "https://okta.example.com"
audiences = ["api"]
algorithms = ["RS256"]
"#;

fn minimal() -> String {
    format!("{ISSUER}{ACTIVE_KEY}{GATEWAY}")
}

fn problems(text: &str) -> Vec<String> {
    match Config::from_toml(text) {
        Err(ConfigError::Invalid(problems)) => problems.0,
        other => panic!("expected invalid config, got {other:?}"),
    }
}

fn parse_error(text: &str) -> String {
    match Config::from_toml(text) {
        Err(ConfigError::Parse(error)) => error.to_string(),
        other => panic!("expected parse error, got {other:?}"),
    }
}

#[test]
fn sample_loads() {
    let config = Config::from_toml(SAMPLE).unwrap();
    assert_eq!(config.issuer.token_lifetime, Duration::from_secs(15 * 60));
    assert_eq!(config.issuer.clock_skew, Duration::from_secs(30));
    assert_eq!(config.issuer.signing.provider, KeyProvider::File);
    assert_eq!(config.issuer.signing.algorithm, SigningAlgorithm::ES256);
    assert_eq!(config.active_key().kid, "2026-11");
    assert_eq!(config.issuer.signing.keys[1].state, KeyState::Retiring);
    assert_eq!(config.gateway.cache.max_entries, 100_000);
    assert_eq!(config.gateway.trusted_proxies.len(), 1);
    assert_eq!(config.trusted_issuers.len(), 3);
    assert_eq!(config.trusted_issuers["okta"].validation, Validation::Jwt);
    assert_eq!(
        config.trusted_issuers["okta"].algorithms,
        [InboundAlgorithm::RS256]
    );
    assert_eq!(
        config.trusted_issuers["gitlab"].validation,
        Validation::Introspection
    );
    assert_eq!(config.claims.rename["entra"]["oid"], "sub");
    assert_eq!(config.routes.len(), 2);
    assert_eq!(
        config.routes[0].matcher.host.as_deref(),
        Some("api.example.com")
    );
    assert_eq!(config.routes[1].allow.len(), 1);
}

#[test]
fn minimal_loads() {
    let config = Config::from_toml(&minimal()).unwrap();
    assert!(config.trusted_issuers.is_empty());
    assert!(config.routes.is_empty());
    assert!(config.gateway.allow.is_empty());
}

#[test]
fn load_reads_a_file() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/tsong.toml");
    assert_eq!(Config::load(&path).unwrap().routes.len(), 2);
}

#[test]
fn load_takes_relative_key_paths_from_the_config_directory() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tsong.toml");
    std::fs::write(&path, minimal()).unwrap();
    let config = Config::load(&path).unwrap();
    assert_eq!(
        config.active_key().path.as_deref(),
        Some(&*dir.path().join("k1.pem"))
    );
}

#[test]
fn load_reports_a_missing_file() {
    let error = Config::load(std::path::Path::new("no-such-file.toml")).unwrap_err();
    assert!(matches!(error, ConfigError::Read { .. }));
    assert!(error.to_string().starts_with("reading no-such-file.toml: "));
}

#[test]
fn unknown_fields_are_rejected() {
    let text = minimal().replace("clock_skew", "clock_skw");
    assert!(parse_error(&text).contains("unknown field `clock_skw`"));
}

#[test]
fn durations_must_parse() {
    let text = minimal().replace("\"30s\"", "\"soon\"");
    parse_error(&text);
}

#[test]
fn none_and_hmac_are_not_inbound_algorithms() {
    for algorithm in ["none", "HS256"] {
        let text = format!("{}{}", minimal(), OKTA.replace("RS256", algorithm));
        parse_error(&text);
    }
}

#[test]
fn issuer_url_must_be_https() {
    let text = minimal().replace("https://tsong", "http://tsong");
    assert_eq!(problems(&text), ["issuer.url must be https"]);
}

#[test]
fn clock_skew_must_be_shorter_than_token_lifetime() {
    let text = minimal().replace("\"30s\"", "\"15m\"");
    assert_eq!(
        problems(&text),
        ["issuer.clock_skew must be shorter than issuer.token_lifetime"]
    );
}

#[test]
fn exactly_one_key_is_active() {
    let none = format!(
        "{ISSUER}{}{GATEWAY}",
        ACTIVE_KEY.replace("active", "retiring")
    );
    assert_eq!(
        problems(&none),
        ["issuer.signing.keys must have exactly one active key, not 0"]
    );
    let two = format!(
        "{ISSUER}{ACTIVE_KEY}{}{GATEWAY}",
        ACTIVE_KEY.replace("k1", "k2")
    );
    assert_eq!(
        problems(&two),
        ["issuer.signing.keys must have exactly one active key, not 2"]
    );
}

#[test]
fn kids_are_unique_and_not_empty() {
    let repeated = format!(
        "{ISSUER}{ACTIVE_KEY}{}{GATEWAY}",
        ACTIVE_KEY.replace("active", "retiring")
    );
    assert_eq!(
        problems(&repeated),
        [r#"issuer.signing.keys repeats kid "k1""#]
    );
    let empty = minimal().replace(r#"kid = "k1""#, r#"kid = """#);
    assert_eq!(
        problems(&empty),
        ["issuer.signing.keys has a key with an empty kid"]
    );
}

#[test]
fn file_keys_need_a_path() {
    let text = minimal().replace("path = \"k1.pem\"\n", "");
    assert_eq!(
        problems(&text),
        [r#"issuer.signing.keys "k1" needs a path for the file provider"#]
    );
}

#[test]
fn cache_needs_room() {
    let text = minimal().replace("max_entries = 10", "max_entries = 0");
    assert_eq!(
        problems(&text),
        ["gateway.cache.max_entries must be above zero"]
    );
}

#[test]
fn trusted_issuers_are_https() {
    let text = format!(
        "{}{}",
        minimal(),
        OKTA.replace("https://okta", "http://okta")
    );
    assert_eq!(
        problems(&text),
        ["trusted_issuers.okta.issuer must be https"]
    );
}

#[test]
fn introspection_urls_are_https() {
    let text = format!(
        "{}{}",
        minimal(),
        OKTA.replace(
            "algorithms",
            "validation = \"introspection\"
introspection_url = \"http://okta.example.com/introspect\"
client_id = \"tsong\"
client_secret_env = \"SECRET\"
algorithms"
        )
    );
    assert_eq!(
        problems(&text),
        ["trusted_issuers.okta.introspection_url must be https"]
    );
}

#[test]
fn trusted_issuers_need_audiences() {
    let text = format!("{}{}", minimal(), OKTA.replace(r#"["api"]"#, "[]"));
    assert_eq!(problems(&text), ["trusted_issuers.okta.audiences is empty"]);
}

#[test]
fn jwt_validation_needs_algorithms() {
    let text = format!("{}{}", minimal(), OKTA.replace(r#"["RS256"]"#, "[]"));
    assert_eq!(
        problems(&text),
        ["trusted_issuers.okta.algorithms is empty, and jwt validation needs at least one"]
    );
}

#[test]
fn introspection_needs_its_endpoint_and_credentials() {
    let text = format!(
        "{}{}",
        minimal(),
        OKTA.replace("algorithms", "validation = \"introspection\"\nalgorithms")
    );
    assert_eq!(
        problems(&text),
        [
            "trusted_issuers.okta.introspection_url is required for introspection",
            "trusted_issuers.okta.client_id is required for introspection",
            "trusted_issuers.okta.client_secret_env is required for introspection",
        ]
    );
}

#[test]
fn claim_renames_name_trusted_issuers() {
    let text = format!("{}{OKTA}[claims.rename.entra]\noid = \"sub\"\n", minimal());
    assert_eq!(
        problems(&text),
        ["claims.rename.entra names no trusted issuer"]
    );
}

const ROUTE: &str = r#"
[[routes]]
name = "orders"
match = { path_prefix = "/orders" }
upstream = "https://orders.example.com"
trusted_issuers = ["okta"]
audience = "orders-api"
"#;

fn with_route(route: &str) -> String {
    format!("{}{OKTA}{route}", minimal())
}

#[test]
fn a_valid_route_loads() {
    let config = Config::from_toml(&with_route(ROUTE)).unwrap();
    assert_eq!(config.routes[0].audience, "orders-api");
    assert!(config.routes[0].scopes.is_empty());
}

#[test]
fn route_names_are_unique() {
    let text = with_route(&format!("{ROUTE}{ROUTE}"));
    assert_eq!(problems(&text), [r#"routes repeats name "orders""#]);
}

#[test]
fn routes_match_something() {
    let text = with_route(&ROUTE.replace(r#"path_prefix = "/orders""#, ""));
    assert_eq!(
        problems(&text),
        [r#"route "orders" must match a host, a path_prefix or both"#]
    );
    let host_only =
        with_route(&ROUTE.replace(r#"path_prefix = "/orders""#, r#"host = "api.example.com""#));
    Config::from_toml(&host_only).unwrap();
}

#[test]
fn path_prefixes_are_absolute() {
    let text = with_route(&ROUTE.replace("\"/orders\"", "\"orders\""));
    assert_eq!(
        problems(&text),
        [r#"route "orders" path_prefix must start with /"#]
    );
}

#[test]
fn upstreams_are_http() {
    let text = with_route(&ROUTE.replace("https://orders", "ftp://orders"));
    assert_eq!(
        problems(&text),
        [r#"route "orders" upstream must be http or https"#]
    );
    let plain = with_route(&ROUTE.replace("https://orders", "http://orders"));
    Config::from_toml(&plain).unwrap();
}

#[test]
fn routes_trust_known_issuers() {
    let none = with_route(&ROUTE.replace(r#"["okta"]"#, "[]"));
    assert_eq!(problems(&none), [r#"route "orders" trusts no issuer"#]);
    let unknown = with_route(&ROUTE.replace(r#"["okta"]"#, r#"["okta", "entra"]"#));
    assert_eq!(
        problems(&unknown),
        [r#"route "orders" trusts "entra", which is not in trusted_issuers"#]
    );
}

#[test]
fn routes_have_an_audience() {
    let text = with_route(&ROUTE.replace(r#""orders-api""#, r#""""#));
    assert_eq!(problems(&text), [r#"route "orders" has an empty audience"#]);
}

#[test]
fn every_problem_is_reported() {
    let text = minimal()
        .replace("https://tsong", "http://tsong")
        .replace("max_entries = 10", "max_entries = 0");
    let error = Config::from_toml(&text).unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid config:\n- issuer.url must be https\n- gateway.cache.max_entries must be above zero\n"
    );
}
