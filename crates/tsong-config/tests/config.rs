use std::error::Error;
use std::path::Path;
use std::time::Duration;

use tsong_config::{
    Config, ConfigError, ConfigStore, FileStore, InboundAlgorithm, KeyProvider, KeyState, Route,
    SigningAlgorithm, TrustedIssuer, Validation,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SAMPLE: &str = include_str!("../../../examples/tsong.toml");

const ISSUER: &str = r#"
[issuer]
url = "https://tsong.example.com"
listen = "127.0.0.1:8444"
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

/// The problems validation finds in `text`, or a test failure when it
/// loads or fails some other way.
fn problems(text: &str) -> TestResult<Vec<String>> {
    match Config::from_toml(text) {
        Err(ConfigError::Invalid(problems)) => Ok(problems.0),
        other => Err(format!("expected an invalid config, got {other:?}").into()),
    }
}

/// The parse error for `text`, or a test failure when it parses.
fn parse_error(text: &str) -> TestResult<String> {
    match Config::from_toml(text) {
        Err(ConfigError::Parse(error)) => Ok(error.to_string()),
        other => Err(format!("expected a parse error, got {other:?}").into()),
    }
}

fn trusted<'a>(config: &'a Config, name: &str) -> TestResult<&'a TrustedIssuer> {
    Ok(config
        .trusted_issuers
        .get(name)
        .ok_or(format!("no trusted issuer {name}"))?)
}

fn route(config: &Config, index: usize) -> TestResult<&Route> {
    Ok(config
        .routes
        .get(index)
        .ok_or(format!("no route {index}"))?)
}

#[test]
fn sample_loads() -> TestResult {
    let config = Config::from_toml(SAMPLE)?;
    assert_eq!(config.issuer.token_lifetime, Duration::from_secs(15 * 60));
    assert_eq!(config.issuer.clock_skew, Duration::from_secs(30));
    assert_eq!(config.issuer.signing.provider, KeyProvider::File);
    assert_eq!(config.issuer.signing.algorithm, SigningAlgorithm::ES256);
    assert_eq!(
        config.active_key().map(|key| key.kid.as_str()),
        Some("2026-11")
    );
    let states: Vec<_> = config.issuer.signing.keys.iter().map(|k| k.state).collect();
    assert_eq!(states, [KeyState::Active, KeyState::Retiring]);
    assert_eq!(config.gateway.cache.max_entries, 100_000);
    assert_eq!(config.gateway.trusted_proxies.len(), 1);
    assert_eq!(config.trusted_issuers.len(), 3);
    let okta = trusted(&config, "okta")?;
    assert_eq!(okta.validation, Validation::Jwt);
    assert_eq!(okta.algorithms, [InboundAlgorithm::RS256]);
    assert_eq!(okta.jwks_refetch, Duration::from_secs(30));
    assert!(okta.jwks_url.is_none());
    assert_eq!(
        trusted(&config, "gitlab")?.validation,
        Validation::Introspection
    );
    assert_eq!(
        config
            .claims
            .rename
            .get("entra")
            .and_then(|renames| renames.get("oid"))
            .map(String::as_str),
        Some("sub")
    );
    assert_eq!(config.routes.len(), 2);
    let orders = route(&config, 0)?;
    assert_eq!(orders.matcher.host.as_deref(), Some("api.example.com"));
    assert_eq!(orders.required_scopes, ["orders"]);
    assert_eq!(route(&config, 1)?.allow.len(), 1);
    Ok(())
}

#[test]
fn minimal_loads() -> TestResult {
    let config = Config::from_toml(&minimal())?;
    assert!(config.trusted_issuers.is_empty());
    assert!(config.routes.is_empty());
    assert!(config.gateway.allow.is_empty());
    Ok(())
}

#[test]
fn load_reads_a_file() -> TestResult {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/tsong.toml");
    assert_eq!(Config::load(&path)?.routes.len(), 2);
    Ok(())
}

#[test]
fn load_takes_relative_key_paths_from_the_config_directory() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("tsong.toml");
    std::fs::write(&path, minimal())?;
    let config = Config::load(&path)?;
    assert_eq!(
        config.active_key().and_then(|key| key.path.as_deref()),
        Some(&*dir.path().join("k1.pem"))
    );
    Ok(())
}

#[test]
fn load_reports_a_missing_file() {
    let result = Config::load(Path::new("no-such-file.toml"));
    assert!(matches!(result, Err(ConfigError::Read { .. })));
    assert!(
        result.is_err_and(|error| error.to_string().starts_with("reading no-such-file.toml: "))
    );
}

#[test]
fn unknown_fields_are_rejected() -> TestResult {
    let text = minimal().replace("clock_skew", "clock_skw");
    assert!(parse_error(&text)?.contains("unknown field `clock_skw`"));
    Ok(())
}

#[test]
fn durations_must_parse() -> TestResult {
    let text = minimal().replace("\"30s\"", "\"soon\"");
    parse_error(&text)?;
    Ok(())
}

#[test]
fn none_and_hmac_are_not_inbound_algorithms() -> TestResult {
    for algorithm in ["none", "HS256"] {
        let text = format!("{}{}", minimal(), OKTA.replace("RS256", algorithm));
        parse_error(&text)?;
    }
    Ok(())
}

#[test]
fn issuer_url_must_be_https() -> TestResult {
    let text = minimal().replace("https://tsong", "http://tsong");
    assert_eq!(problems(&text)?, ["issuer.url must be https"]);
    Ok(())
}

#[test]
fn clock_skew_must_be_shorter_than_token_lifetime() -> TestResult {
    let text = minimal().replace("\"30s\"", "\"15m\"");
    assert_eq!(
        problems(&text)?,
        ["issuer.clock_skew must be shorter than issuer.token_lifetime"]
    );
    Ok(())
}

#[test]
fn exactly_one_key_is_active() -> TestResult {
    let none = format!(
        "{ISSUER}{}{GATEWAY}",
        ACTIVE_KEY.replace("active", "retiring")
    );
    assert_eq!(
        problems(&none)?,
        ["issuer.signing.keys must have exactly one active key, not 0"]
    );
    let two = format!(
        "{ISSUER}{ACTIVE_KEY}{}{GATEWAY}",
        ACTIVE_KEY.replace("k1", "k2")
    );
    assert_eq!(
        problems(&two)?,
        ["issuer.signing.keys must have exactly one active key, not 2"]
    );
    Ok(())
}

#[test]
fn kids_are_unique_and_not_empty() -> TestResult {
    let repeated = format!(
        "{ISSUER}{ACTIVE_KEY}{}{GATEWAY}",
        ACTIVE_KEY.replace("active", "retiring")
    );
    assert_eq!(
        problems(&repeated)?,
        [r#"issuer.signing.keys repeats kid "k1""#]
    );
    let empty = minimal().replace(r#"kid = "k1""#, r#"kid = """#);
    assert_eq!(
        problems(&empty)?,
        ["issuer.signing.keys has a key with an empty kid"]
    );
    Ok(())
}

#[test]
fn file_keys_need_a_path() -> TestResult {
    let text = minimal().replace("path = \"k1.pem\"\n", "");
    assert_eq!(
        problems(&text)?,
        [r#"issuer.signing.keys "k1" needs a path for the file provider"#]
    );
    Ok(())
}

#[test]
fn cache_needs_room() -> TestResult {
    let text = minimal().replace("max_entries = 10", "max_entries = 0");
    assert_eq!(
        problems(&text)?,
        ["gateway.cache.max_entries must be above zero"]
    );
    Ok(())
}

#[test]
fn trusted_issuers_are_https() -> TestResult {
    let text = format!(
        "{}{}",
        minimal(),
        OKTA.replace("https://okta", "http://okta")
    );
    assert_eq!(
        problems(&text)?,
        ["trusted_issuers.okta.issuer must be https"]
    );
    Ok(())
}

#[test]
fn introspection_urls_are_https() -> TestResult {
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
        problems(&text)?,
        ["trusted_issuers.okta.introspection_url must be https"]
    );
    Ok(())
}

#[test]
fn jwks_urls_are_https() -> TestResult {
    let text = format!(
        "{}{}",
        minimal(),
        OKTA.replace(
            "algorithms",
            "jwks_url = \"http://okta.example.com/keys\"
algorithms"
        )
    );
    assert_eq!(
        problems(&text)?,
        ["trusted_issuers.okta.jwks_url must be https"]
    );
    let https = text.replace(
        "http://okta.example.com/keys",
        "https://okta.example.com/keys",
    );
    let config = Config::from_toml(&https)?;
    assert_eq!(
        trusted(&config, "okta")?
            .jwks_url
            .as_ref()
            .map(|url| url.as_str()),
        Some("https://okta.example.com/keys")
    );
    Ok(())
}

#[test]
fn issuers_are_kept_exactly_as_written() -> TestResult {
    let text = format!("{}{OKTA}", minimal());
    let config = Config::from_toml(&text)?;
    assert_eq!(config.issuer.url, "https://tsong.example.com");
    assert_eq!(trusted(&config, "okta")?.issuer, "https://okta.example.com");
    Ok(())
}

#[test]
fn issuer_urls_must_parse() -> TestResult {
    let text = minimal().replace("https://tsong.example.com", "not a url");
    assert_eq!(problems(&text)?, ["issuer.url must be https"]);
    Ok(())
}

#[test]
fn jwks_refetch_is_configurable() -> TestResult {
    let text = format!(
        "{}{}",
        minimal(),
        OKTA.replace(
            "algorithms",
            "jwks_refetch = \"5m\"
algorithms"
        )
    );
    let config = Config::from_toml(&text)?;
    assert_eq!(
        trusted(&config, "okta")?.jwks_refetch,
        Duration::from_secs(300)
    );
    Ok(())
}

#[test]
fn claim_mapping_may_not_write_reserved_claims() -> TestResult {
    let text = format!(
        "{}{OKTA}[claims]
copy = [\"email\", \"aud\"]
[claims.rename.okta]
uid = \"sub\"
x = \"exp\"
",
        minimal()
    );
    assert_eq!(
        problems(&text)?,
        [
            r#"claims.copy may not copy reserved claim "aud""#,
            r#"claims.rename.okta may not write reserved claim "exp""#,
        ]
    );
    Ok(())
}

#[test]
fn trusted_issuers_need_audiences() -> TestResult {
    let text = format!("{}{}", minimal(), OKTA.replace(r#"["api"]"#, "[]"));
    assert_eq!(
        problems(&text)?,
        ["trusted_issuers.okta.audiences is empty"]
    );
    Ok(())
}

#[test]
fn jwt_validation_needs_algorithms() -> TestResult {
    let text = format!("{}{}", minimal(), OKTA.replace(r#"["RS256"]"#, "[]"));
    assert_eq!(
        problems(&text)?,
        ["trusted_issuers.okta.algorithms is empty, and jwt validation needs at least one"]
    );
    Ok(())
}

#[test]
fn introspection_needs_its_endpoint_and_credentials() -> TestResult {
    let text = format!(
        "{}{}",
        minimal(),
        OKTA.replace("algorithms", "validation = \"introspection\"\nalgorithms")
    );
    assert_eq!(
        problems(&text)?,
        [
            "trusted_issuers.okta.introspection_url is required for introspection",
            "trusted_issuers.okta.client_id is required for introspection",
            "trusted_issuers.okta.client_secret_env is required for introspection",
        ]
    );
    Ok(())
}

#[test]
fn claim_renames_name_trusted_issuers() -> TestResult {
    let text = format!("{}{OKTA}[claims.rename.entra]\noid = \"sub\"\n", minimal());
    assert_eq!(
        problems(&text)?,
        ["claims.rename.entra names no trusted issuer"]
    );
    Ok(())
}

const ROUTE: &str = r#"
[[routes]]
name = "orders"
match = { path_prefix = "/orders" }
downstream = "https://orders.example.com"
trusted_issuers = ["okta"]
audience = "orders-api"
"#;

fn with_route(route: &str) -> String {
    format!("{}{OKTA}{route}", minimal())
}

#[test]
fn a_valid_route_loads() -> TestResult {
    let config = Config::from_toml(&with_route(ROUTE))?;
    let orders = route(&config, 0)?;
    assert_eq!(orders.audience, "orders-api");
    assert!(orders.scopes.is_empty());
    assert!(orders.required_scopes.is_empty());
    Ok(())
}

#[test]
fn a_config_without_an_active_key_has_none() -> TestResult {
    let mut config = Config::from_toml(&minimal())?;
    config.issuer.signing.keys.clear();
    assert!(config.active_key().is_none());
    Ok(())
}

#[tokio::test]
async fn a_file_store_loads_its_file() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("tsong.toml");
    std::fs::write(&path, minimal())?;
    let store: Box<dyn ConfigStore> = Box::new(FileStore::new(&path));
    let config = store.load().await?;
    assert_eq!(config.issuer.listen.port(), 8444);
    let missing = FileStore::new(dir.path().join("missing.toml"));
    assert!(matches!(
        missing.load().await,
        Err(ConfigError::Read { .. })
    ));
    Ok(())
}

#[test]
fn route_names_are_unique() -> TestResult {
    let text = with_route(&format!("{ROUTE}{ROUTE}"));
    assert_eq!(problems(&text)?, [r#"routes repeats name "orders""#]);
    Ok(())
}

#[test]
fn routes_match_something() -> TestResult {
    let text = with_route(&ROUTE.replace(r#"path_prefix = "/orders""#, ""));
    assert_eq!(
        problems(&text)?,
        [r#"route "orders" must match a host, a path_prefix or both"#]
    );
    let host_only =
        with_route(&ROUTE.replace(r#"path_prefix = "/orders""#, r#"host = "api.example.com""#));
    Config::from_toml(&host_only)?;
    Ok(())
}

#[test]
fn path_prefixes_are_absolute() -> TestResult {
    let text = with_route(&ROUTE.replace("\"/orders\"", "\"orders\""));
    assert_eq!(
        problems(&text)?,
        [r#"route "orders" path_prefix must start with /"#]
    );
    Ok(())
}

#[test]
fn downstreams_are_http() -> TestResult {
    let text = with_route(&ROUTE.replace("https://orders", "ftp://orders"));
    assert_eq!(
        problems(&text)?,
        [r#"route "orders" downstream must be http or https"#]
    );
    let plain = with_route(&ROUTE.replace("https://orders", "http://orders"));
    Config::from_toml(&plain)?;
    Ok(())
}

#[test]
fn routes_trust_known_issuers() -> TestResult {
    let none = with_route(&ROUTE.replace(r#"["okta"]"#, "[]"));
    assert_eq!(problems(&none)?, [r#"route "orders" trusts no issuer"#]);
    let unknown = with_route(&ROUTE.replace(r#"["okta"]"#, r#"["okta", "entra"]"#));
    assert_eq!(
        problems(&unknown)?,
        [r#"route "orders" trusts "entra", which is not in trusted_issuers"#]
    );
    Ok(())
}

#[test]
fn routes_have_an_audience() -> TestResult {
    let text = with_route(&ROUTE.replace(r#""orders-api""#, r#""""#));
    assert_eq!(
        problems(&text)?,
        [r#"route "orders" has an empty audience"#]
    );
    Ok(())
}

#[test]
fn every_problem_is_reported() {
    let text = minimal()
        .replace("https://tsong", "http://tsong")
        .replace("max_entries = 10", "max_entries = 0");
    let message = Config::from_toml(&text).map_err(|error| error.to_string());
    assert_eq!(
        message.err().as_deref(),
        Some(
            "invalid config:\n- issuer.url must be https\n- gateway.cache.max_entries must be above zero\n"
        )
    );
}
