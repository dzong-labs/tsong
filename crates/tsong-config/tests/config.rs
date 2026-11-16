use std::error::Error;
use std::path::Path;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tsong_config::{
    ANY, Config, ConfigError, ConfigStore, FileStore, InboundAlgorithm, KeyProvider, KeyState,
    Route, RouteTable, SigningAlgorithm, TrustedIssuer, Validation, Warnings, hex,
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
allow = ["10.0.0.0/8"]

[gateway.cache]
max_entries = 10
"#;

const OKTA: &str = r#"
[trusted_issuers.okta]
sub_prefix = "okta"
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
    assert_eq!(orders.host, "orders.example.com");
    assert_eq!(orders.append_audience, "orders.example.com");
    assert_eq!(orders.allowed_scopes, ["orders.read", "orders.write"]);
    assert!(orders.allow.is_none());
    assert_eq!(route(&config, 1)?.allow.as_ref().map(Vec::len), Some(1));
    assert!(config.warnings().0.is_empty());
    Ok(())
}

#[test]
fn minimal_loads() -> TestResult {
    let config = Config::from_toml(&minimal())?;
    assert!(config.trusted_issuers.is_empty());
    assert!(config.routes.is_empty());
    assert_eq!(config.gateway.allow.len(), 1);
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

/// The okta issuer with `lines` added.
fn okta_with(lines: &str) -> String {
    format!(
        "{}{}",
        minimal(),
        OKTA.replace("algorithms", &format!("{lines}\nalgorithms"))
    )
}

#[test]
fn key_timing_has_defaults_and_is_configurable() -> TestResult {
    let config = Config::from_toml(&okta_with(""))?;
    let okta = trusted(&config, "okta")?;
    assert_eq!(
        (
            okta.jwks_max_age,
            okta.jwks_retry,
            okta.jwks_refetch,
            okta.jwks_timeout
        ),
        (
            Duration::from_secs(3600),
            Duration::from_secs(10),
            Duration::from_secs(30),
            Duration::from_secs(10)
        )
    );
    let config = Config::from_toml(&okta_with(
        "jwks_max_age = \"2h\"\njwks_retry = \"5s\"\njwks_timeout = \"3s\"",
    ))?;
    let okta = trusted(&config, "okta")?;
    assert_eq!(
        (okta.jwks_max_age, okta.jwks_retry, okta.jwks_timeout),
        (
            Duration::from_secs(7200),
            Duration::from_secs(5),
            Duration::from_secs(3)
        )
    );
    Ok(())
}

#[test]
fn key_timing_is_above_zero() -> TestResult {
    for field in ["jwks_max_age", "jwks_retry", "jwks_refetch", "jwks_timeout"] {
        assert_eq!(
            problems(&okta_with(&format!("{field} = \"0s\"")))?,
            [format!("trusted_issuers.okta.{field} must be above zero")]
        );
    }
    Ok(())
}

#[test]
fn a_discovery_url_is_https() -> TestResult {
    let http = okta_with(
        "discovery_url = \"http://okta.example.com/tenant/.well-known/openid-configuration\"",
    );
    assert_eq!(
        problems(&http)?,
        ["trusted_issuers.okta.discovery_url must be https"]
    );
    let config = Config::from_toml(&http.replace("http://", "https://"))?;
    assert_eq!(
        trusted(&config, "okta")?
            .discovery_url
            .as_ref()
            .map(|url| url.as_str()),
        Some("https://okta.example.com/tenant/.well-known/openid-configuration")
    );
    Ok(())
}

#[test]
fn a_discovery_url_and_a_jwks_url_are_not_both_set() -> TestResult {
    let both = okta_with(
        "discovery_url = \"https://okta.example.com/d\"\njwks_url = \"https://okta.example.com/k\"",
    );
    assert_eq!(
        problems(&both)?,
        [
            "trusted_issuers.okta sets both discovery_url and jwks_url; jwks_url skips discovery, so set one"
        ]
    );
    Ok(())
}

#[test]
fn keys_trusted_for_more_than_a_day_warn() -> TestResult {
    let warning = "trusted_issuers.okta.jwks_max_age is over 24h; a key the issuer withdraws stays trusted that long".to_owned();
    let day = Config::from_toml(&okta_with("jwks_max_age = \"24h\""))?;
    assert!(!day.warnings().0.contains(&warning), "{}", day.warnings());
    let longer = Config::from_toml(&okta_with("jwks_max_age = \"25h\""))?;
    assert!(
        longer.warnings().0.contains(&warning),
        "{}",
        longer.warnings()
    );
    let introspected = Config::from_toml(&okta_with(
        "jwks_max_age = \"25h\"\nvalidation = \"introspection\"\nintrospection_url = \"https://okta.example.com/introspect\"\nclient_id = \"tsong\"\nclient_secret_env = \"SECRET\"",
    ))?;
    assert!(
        !introspected.warnings().0.contains(&warning),
        "{}",
        introspected.warnings()
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
y = \"sub_id\"
",
        minimal()
    );
    assert_eq!(
        problems(&text)?,
        [
            r#"claims.copy may not copy reserved claim "aud""#,
            r#"claims.rename.okta may not write reserved claim "exp""#,
            r#"claims.rename.okta may not write reserved claim "sub_id""#,
        ]
    );
    Ok(())
}

#[test]
fn a_rename_writes_each_claim_from_one_claim() -> TestResult {
    let text = format!(
        "{}{OKTA}[claims.rename.okta]
oid = \"sub\"
upn = \"sub\"
uid = \"user\"
",
        minimal()
    );
    assert_eq!(
        problems(&text)?,
        [r#"claims.rename.okta writes claim "sub" from more than one claim"#]
    );
    Ok(())
}

#[test]
fn a_sub_prefix_is_required() -> TestResult {
    let text = format!(
        "{}{}",
        minimal(),
        OKTA.replace("sub_prefix = \"okta\"\n", "")
    );
    assert!(parse_error(&text)?.contains("missing field `sub_prefix`"));
    Ok(())
}

#[test]
fn sub_prefixes_are_lowercase_letters_digits_and_dashes() -> TestResult {
    for good in ["okta", "okta-2", "0"] {
        let text = format!(
            "{}{}",
            minimal(),
            OKTA.replace("\"okta\"\n", &format!("{good:?}\n"))
        );
        Config::from_toml(&text)?;
    }
    for bad in [
        "", "Okta", "ok:ta", "ok ta", "ok_ta", "ok.ta", "okta/", "ökta",
    ] {
        let text = format!(
            "{}{}",
            minimal(),
            OKTA.replace("\"okta\"\n", &format!("{bad:?}\n"))
        );
        assert_eq!(
            problems(&text)?,
            [format!(
                "trusted_issuers.okta.sub_prefix must be lowercase letters, digits and -, not {bad:?}"
            )]
        );
    }
    Ok(())
}

#[test]
fn sub_prefixes_are_unique() -> TestResult {
    let other = OKTA
        .replace("trusted_issuers.okta", "trusted_issuers.other")
        .replace("okta.example.com", "other.example.com");
    let text = format!("{}{OKTA}{other}", minimal());
    assert_eq!(
        problems(&text)?,
        [r#"trusted_issuers.other.sub_prefix "okta" is used by another trusted issuer"#]
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
host = "orders.example.com"
downstream = "https://orders-lb.example.com"
append_audience = "orders.example.com"
allowed_audiences = ["api"]
allowed_scopes = ["orders.read"]
"#;

fn with_route(route: &str) -> String {
    format!("{}{OKTA}{route}", minimal())
}

/// The route with one line of `ROUTE` replaced.
fn route_with(from: &str, to: &str) -> String {
    with_route(&ROUTE.replace(from, to))
}

#[test]
fn a_valid_route_loads() -> TestResult {
    let config = Config::from_toml(&with_route(ROUTE))?;
    let orders = route(&config, 0)?;
    assert_eq!(orders.append_audience, "orders.example.com");
    assert_eq!(orders.allowed_audiences, ["api"]);
    assert!(orders.allow.is_none());
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
    let fetched = store.load().await?;
    assert_eq!(fetched.text, minimal());
    assert_eq!(fetched.revision, hex(&Sha256::digest(minimal().as_bytes())));
    assert_eq!(fetched.content, fetched.revision);
    assert_eq!(fetched.revision.len(), 64);
    assert_eq!(fetched.author, None);
    assert_eq!(fetched.base_dir.as_deref(), Some(dir.path()));
    let snapshot = fetched.parse()?;
    assert_eq!(snapshot.config.issuer.listen.port(), 8444);
    assert_eq!(snapshot.content, snapshot.revision);
    assert_eq!(snapshot.author, None);
    assert_eq!(
        snapshot
            .config
            .active_key()
            .and_then(|key| key.path.clone()),
        Some(dir.path().join("k1.pem"))
    );
    std::fs::write(
        &path,
        minimal().replace("max_entries = 10", "max_entries = 11"),
    )?;
    assert_ne!(store.load().await?.revision, snapshot.revision);
    let missing = FileStore::new(dir.path().join("missing.toml"));
    assert!(matches!(
        missing.load().await,
        Err(ConfigError::Read { .. })
    ));
    Ok(())
}

#[test]
fn the_gateway_allow_list_is_required() -> TestResult {
    let text = minimal().replace("allow = [\"10.0.0.0/8\"]\n", "");
    assert!(parse_error(&text)?.contains("missing field `allow`"));
    Ok(())
}

#[test]
fn route_fields_are_required() -> TestResult {
    for field in [
        "host",
        "downstream",
        "append_audience",
        "allowed_audiences",
        "allowed_scopes",
    ] {
        let line = ROUTE
            .lines()
            .find(|line| line.starts_with(field))
            .ok_or(format!("no {field} line"))?;
        let text = route_with(line, "");
        assert!(
            parse_error(&text)?.contains(&format!("missing field `{field}`")),
            "{field}"
        );
    }
    Ok(())
}

#[test]
fn route_names_are_unique() -> TestResult {
    let second = ROUTE.replace(
        r#"host = "orders.example.com""#,
        r#"host = "other.example.com""#,
    );
    let text = with_route(&format!("{ROUTE}{second}"));
    assert_eq!(problems(&text)?, [r#"routes repeats name "orders""#]);
    Ok(())
}

#[test]
fn route_hosts_are_unique_without_regard_to_case() -> TestResult {
    let second = ROUTE
        .replace(r#"name = "orders""#, r#"name = "orders-2""#)
        .replace(
            r#"host = "orders.example.com""#,
            r#"host = "Orders.Example.COM""#,
        );
    let text = with_route(&format!("{ROUTE}{second}"));
    assert_eq!(
        problems(&text)?,
        [r#"routes repeats host "Orders.Example.COM""#]
    );
    Ok(())
}

#[test]
fn route_hosts_are_bare_host_names() -> TestResult {
    for host in [
        "",
        "orders.example.com:443",
        "orders.example.com/orders",
        "https://orders.example.com",
        "user@orders.example.com",
        "orders example.com",
    ] {
        let text = route_with(
            r#"host = "orders.example.com""#,
            &format!("host = {host:?}"),
        );
        assert_eq!(
            problems(&text)?,
            [r#"route "orders" host must be a host name, without a scheme, port or path"#],
            "{host}"
        );
    }
    for host in ["Orders.Example.com", "10.1.2.3", "[::1]", "localhost"] {
        let text = route_with(
            r#"host = "orders.example.com""#,
            &format!("host = {host:?}"),
        );
        Config::from_toml(&text).map_err(|error| format!("{host}: {error}"))?;
    }
    Ok(())
}

#[test]
fn downstreams_are_https_origins() -> TestResult {
    for downstream in [
        "http://orders-lb.example.com",
        "https://orders-lb.example.com/api",
        "https://orders-lb.example.com/?x=1",
        "https://orders-lb.example.com/#top",
        "https://user@orders-lb.example.com",
        "https://:pass@orders-lb.example.com",
        "unix:/run/orders.sock",
    ] {
        let text = route_with(
            r#"downstream = "https://orders-lb.example.com""#,
            &format!("downstream = {downstream:?}"),
        );
        assert_eq!(
            problems(&text)?,
            [
                r#"route "orders" downstream must be an https origin, without a path, query or credentials"#
            ],
            "{downstream}"
        );
    }
    for downstream in [
        "https://orders-lb.example.com/",
        "https://orders-lb.example.com:8443",
    ] {
        let text = route_with(
            r#"downstream = "https://orders-lb.example.com""#,
            &format!("downstream = {downstream:?}"),
        );
        Config::from_toml(&text).map_err(|error| format!("{downstream}: {error}"))?;
    }
    Ok(())
}

#[test]
fn the_route_table_finds_routes_by_host_without_regard_to_case() -> TestResult {
    let second = ROUTE
        .replace(r#"name = "orders""#, r#"name = "builds""#)
        .replace(
            r#"host = "orders.example.com""#,
            r#"host = "Builds.Example.com""#,
        );
    let config = Config::from_toml(&with_route(&format!("{ROUTE}{second}")))?;
    let table = RouteTable::new(&config.routes);
    let name = |host: &str| table.get(host).map(|route| route.name.clone());
    assert_eq!(name("orders.example.com").as_deref(), Some("orders"));
    assert_eq!(name("ORDERS.example.com").as_deref(), Some("orders"));
    assert_eq!(name("builds.example.com").as_deref(), Some("builds"));
    assert_eq!(name("example.com"), None);
    assert!(RouteTable::default().get("orders.example.com").is_none());
    Ok(())
}

#[test]
fn the_route_table_keeps_the_first_of_a_repeated_host() -> TestResult {
    let config = Config::from_toml(&with_route(ROUTE))?;
    let first = route(&config, 0)?.clone();
    let mut second = first.clone();
    second.name = "second".into();
    second.host = "ORDERS.example.com".into();
    let table = RouteTable::new(&[first, second]);
    let found = table
        .get("orders.example.com")
        .map(|route| route.name.as_str());
    assert_eq!(found, Some("orders"));
    Ok(())
}

/// The orders route with these allowed audiences and scopes.
fn orders(audiences: &[&str], scopes: &[&str]) -> TestResult<Route> {
    let config = Config::from_toml(&with_route(ROUTE))?;
    let mut route = route(&config, 0)?.clone();
    route.allowed_audiences = audiences.iter().map(|value| (*value).to_owned()).collect();
    route.allowed_scopes = scopes.iter().map(|value| (*value).to_owned()).collect();
    Ok(route)
}

#[test]
fn a_route_accepts_a_token_with_one_allowed_audience() -> TestResult {
    let route = orders(&["a", "b"], &[])?;
    assert!(route.accepts_audiences(["x", "b"].into_iter()));
    assert!(!route.accepts_audiences(["x", "y"].into_iter()));
    assert!(!route.accepts_audiences(std::iter::empty()));
    Ok(())
}

#[test]
fn an_empty_audience_list_accepts_nothing_and_a_star_accepts_anything() -> TestResult {
    let empty = orders(&[], &[])?;
    assert!(!empty.accepts_audiences(["a"].into_iter()));
    let any = orders(&[ANY], &[])?;
    assert!(any.accepts_audiences(["a"].into_iter()));
    assert!(any.accepts_audiences(std::iter::empty()));
    Ok(())
}

#[test]
fn a_route_refuses_the_first_scope_it_does_not_allow() -> TestResult {
    let route = orders(&[], &["read", "write"])?;
    assert_eq!(route.refused_scope(["read", "write"].into_iter()), Ok(()));
    assert_eq!(route.refused_scope(std::iter::empty()), Ok(()));
    assert_eq!(
        route.refused_scope(["read", "admin", "root"].into_iter()),
        Err(Some("admin"))
    );
    Ok(())
}

#[test]
fn an_empty_scope_list_refuses_everything_and_a_star_accepts_anything() -> TestResult {
    let empty = orders(&[], &[])?;
    assert_eq!(empty.refused_scope(std::iter::empty()), Err(None));
    assert_eq!(empty.refused_scope(["read"].into_iter()), Err(None));
    let any = orders(&[], &["read", ANY])?;
    assert_eq!(any.refused_scope(["admin"].into_iter()), Ok(()));
    Ok(())
}

#[test]
fn a_clean_config_has_no_warnings() -> TestResult {
    let config = Config::from_toml(&with_route(ROUTE))?;
    assert_eq!(config.warnings(), Warnings::default());
    assert_eq!(config.warnings().to_string(), "");
    Ok(())
}

#[test]
fn empty_lists_warn_as_omissions() -> TestResult {
    let route = ROUTE
        .replace(r#"allowed_audiences = ["api"]"#, "allowed_audiences = []")
        .replace(
            r#"allowed_scopes = ["orders.read"]"#,
            "allowed_scopes = []\nallow = []",
        );
    let text = with_route(&route).replace(r#"allow = ["10.0.0.0/8"]"#, "allow = []");
    let warnings = Config::from_toml(&text)?.warnings();
    assert_eq!(
        warnings.0,
        [
            "gateway.allow is empty; every client will be denied",
            r#"route "orders": allowed_audiences is empty; every request will be denied"#,
            r#"route "orders": allowed_scopes is empty; every request will be denied"#,
            r#"route "orders": allow is empty; every client will be denied"#,
        ]
    );
    assert_eq!(
        warnings.to_string().lines().next(),
        Some("warning: gateway.allow is empty; every client will be denied")
    );
    Ok(())
}

#[test]
fn accept_anything_entries_warn_as_decisions() -> TestResult {
    let route = ROUTE
        .replace(
            r#"allowed_audiences = ["api"]"#,
            r#"allowed_audiences = ["api", "*"]"#,
        )
        .replace(
            r#"allowed_scopes = ["orders.read"]"#,
            "allowed_scopes = [\"*\"]\nallow = [\"::/0\"]",
        );
    let text = with_route(&route).replace(
        r#"allow = ["10.0.0.0/8"]"#,
        r#"allow = ["0.0.0.0/0", "10.0.0.0/8", "::/0"]"#,
    );
    let warnings = Config::from_toml(&text)?.warnings();
    assert_eq!(
        warnings.0,
        [
            "gateway.allow has 0.0.0.0/0; every address is allowed",
            "gateway.allow has ::/0; every address is allowed",
            r#"route "orders": allowed_audiences has "*"; any value is accepted"#,
            r#"route "orders": allowed_scopes has "*"; any value is accepted"#,
            r#"route "orders": allow has ::/0; every address is allowed"#,
        ]
    );
    Ok(())
}

#[test]
fn the_read_timeout_defaults_to_a_minute_and_a_route_may_override_it() -> TestResult {
    let second = ROUTE
        .replace(r#"name = "orders""#, r#"name = "slow""#)
        .replace(
            r#"host = "orders.example.com""#,
            r#"host = "slow.example.com""#,
        )
        .replace(
            r#"allowed_scopes = ["orders.read"]"#,
            "allowed_scopes = [\"orders.read\"]\nread_timeout = \"5m\"",
        );
    let config = Config::from_toml(&with_route(&format!("{ROUTE}{second}")))?;
    assert_eq!(config.gateway.read_timeout, Duration::from_secs(60));
    assert_eq!(
        route(&config, 0)?.read_timeout(&config.gateway),
        Duration::from_secs(60)
    );
    assert_eq!(
        route(&config, 1)?.read_timeout(&config.gateway),
        Duration::from_secs(300)
    );
    let text = with_route(ROUTE).replace(
        "[gateway.cache]",
        "read_timeout = \"90s\"\n\n[gateway.cache]",
    );
    let config = Config::from_toml(&text)?;
    assert_eq!(
        route(&config, 0)?.read_timeout(&config.gateway),
        Duration::from_secs(90)
    );
    Ok(())
}

#[test]
fn read_timeouts_are_above_zero() -> TestResult {
    let text = route_with(
        r#"allowed_scopes = ["orders.read"]"#,
        "allowed_scopes = [\"orders.read\"]\nread_timeout = \"0s\"",
    )
    .replace(
        "[gateway.cache]",
        "read_timeout = \"0s\"\n\n[gateway.cache]",
    );
    assert_eq!(
        problems(&text)?,
        [
            r#"route "orders" read_timeout must be above zero"#,
            "gateway.read_timeout must be above zero",
        ]
    );
    let bad = route_with(
        r#"allowed_scopes = ["orders.read"]"#,
        "allowed_scopes = [\"orders.read\"]\nread_timeout = \"soon\"",
    );
    parse_error(&bad)?;
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

#[test]
fn without_a_directory_key_paths_must_be_absolute() -> TestResult {
    match Config::from_text(&minimal(), None) {
        Err(ConfigError::Invalid(problems)) => assert_eq!(
            problems.0,
            [
                r#"issuer.signing.keys "k1" path must be absolute, since the config has no directory"#
            ]
        ),
        other => return Err(format!("expected invalid, got {other:?}").into()),
    }
    let absolute = std::env::temp_dir().join("k1.pem");
    let text = minimal().replace(
        r#"path = "k1.pem""#,
        &format!("path = '{}'", absolute.display()),
    );
    let config = Config::from_text(&text, None)?;
    let path = config.active_key().and_then(|key| key.path.clone());
    assert_eq!(path, Some(absolute));
    Ok(())
}

#[test]
fn a_directory_resolves_relative_key_paths() -> TestResult {
    let dir = std::env::temp_dir();
    let config = Config::from_text(&minimal(), Some(&dir))?;
    let path = config.active_key().and_then(|key| key.path.clone());
    assert_eq!(path, Some(dir.join("k1.pem")));
    Ok(())
}

#[test]
fn hex_is_lowercase_and_two_digits_a_byte() {
    assert_eq!(hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
    assert_eq!(hex(&[]), "");
}
