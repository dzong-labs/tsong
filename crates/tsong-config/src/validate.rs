//! Checks that span fields: references resolve, one active key signs each
//! route's algorithm, each validation mode has what it needs.

use std::collections::BTreeSet;
use std::fmt;

use url::Url;

use crate::{ANY, Config, KeyProvider, KeyState, Policy, PolicyKind, Validation, is_scope_token};

/// Claims claim mapping may not write: those Tsong sets on every token it
/// issues, and `scp`, which would carry the subject's scopes past
/// narrowing and the route's scope policy. For the same reason, a rename
/// may not read `scope` or `scp` either.
pub const RESERVED_CLAIMS: [&str; 11] = [
    "iss", "aud", "exp", "iat", "nbf", "jti", "scope", "scp", "act", "cnf", "sub_id",
];

/// The subject token's scope claims, which reach the minted token only as
/// its `scope`, after the route's scope policy and narrowing.
const SCOPE_CLAIMS: [&str; 2] = ["scope", "scp"];

/// Whether the normalized header name `name` is one the gateway reads,
/// sets or strips itself, so refusing it would refuse every request or
/// clash with the gateway's own handling: `Authorization`,
/// `Proxy-Authorization`, `Host`, the correlation headers, and the
/// forwarding headers.
fn is_gateway_header(name: &str) -> bool {
    matches!(
        name,
        "authorization"
            | "proxyauthorization"
            | "host"
            | "xrequestid"
            | "traceparent"
            | "tracestate"
            | "forwarded"
            | "xforwardedfor"
            | "xforwardedhost"
            | "xforwardedproto"
    )
}

/// Whether `text` is an RFC 9110 token, as a header name must be.
fn is_header_name(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

/// Whether `text` is an https URL.
fn is_https(text: &str) -> bool {
    Url::parse(text).is_ok_and(|url| url.scheme() == "https")
}

/// Whether `text` is a usable subject prefix: not empty, and only
/// lowercase letters, digits and `-`. With no `:` in a prefix, the first
/// `:` of a minted `sub` always ends the prefix.
fn is_sub_prefix(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// Every problem a config has, one per line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problems(pub Vec<String>);

impl fmt::Display for Problems {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for problem in &self.0 {
            writeln!(f, "- {problem}")?;
        }
        Ok(())
    }
}

impl Config {
    pub(crate) fn validate(&self) -> Result<(), Problems> {
        let mut problems = Vec::new();
        self.check_issuer(&mut problems);
        self.check_keys(&mut problems);
        self.check_trusted_issuers(&mut problems);
        self.check_claims(&mut problems);
        self.check_routes(&mut problems);
        if self.gateway.read_timeout.is_zero() {
            problems.push("gateway.read_timeout must be above zero".into());
        }
        if self.gateway.cache.max_entries == 0 {
            problems.push("gateway.cache.max_entries must be above zero".into());
        }
        self.check_refused(&mut problems);
        if problems.is_empty() {
            Ok(())
        } else {
            Err(Problems(problems))
        }
    }

    fn check_refused(&self, problems: &mut Vec<String>) {
        let gateway = &self.gateway;
        for name in &gateway.refused_query_params {
            if crate::normalize_name(name).is_empty() {
                problems.push(format!(
                    "gateway.refused_query_params has \"{name}\", which has no letters or digits"
                ));
            }
        }
        if gateway.refused_headers.is_empty() {
            problems
                .push("gateway.refused_headers is empty; leave it unset for the defaults".into());
        }
        for name in &gateway.refused_headers {
            let normalized = crate::normalize_name(name);
            if !is_header_name(name) {
                problems.push(format!(
                    "gateway.refused_headers has \"{name}\", which isn't a header name"
                ));
            } else if normalized.is_empty() {
                problems.push(format!(
                    "gateway.refused_headers has \"{name}\", which has no letters or digits"
                ));
            } else if is_gateway_header(&normalized) {
                problems.push(format!(
                    "gateway.refused_headers may not hold {name}, which the gateway reads, sets or strips itself"
                ));
            }
        }
    }

    fn check_issuer(&self, problems: &mut Vec<String>) {
        let issuer = &self.issuer;
        if !is_https(&issuer.url) {
            problems.push("issuer.url must be https".into());
        }
        if issuer.clock_skew >= issuer.token_lifetime {
            problems.push("issuer.clock_skew must be shorter than issuer.token_lifetime".into());
        }
    }

    fn check_keys(&self, problems: &mut Vec<String>) {
        let signing = &self.issuer.signing;
        let mut active = BTreeSet::new();
        let mut repeated = BTreeSet::new();
        for key in &signing.keys {
            if key.state == KeyState::Active
                && !active.insert(key.algorithm)
                && repeated.insert(key.algorithm)
            {
                problems.push(format!(
                    "issuer.signing.keys has more than one active {} key",
                    key.algorithm
                ));
            }
        }
        if active.is_empty() {
            // One problem, not another for every route.
            problems.push("issuer.signing.keys has no active key".into());
        } else {
            for route in &self.routes {
                if !active.contains(&route.signing_algorithm) {
                    problems.push(format!(
                        "route {:?} signs with {}, which no active key in issuer.signing.keys does",
                        route.name, route.signing_algorithm
                    ));
                }
            }
        }
        let mut kids = BTreeSet::new();
        for key in &signing.keys {
            if key.kid.is_empty() {
                problems.push("issuer.signing.keys has a key with an empty kid".into());
            } else if !kids.insert(key.kid.as_str()) {
                problems.push(format!("issuer.signing.keys repeats kid {:?}", key.kid));
            }
            if signing.provider == KeyProvider::File && key.private_key.is_none() {
                problems.push(format!(
                    "issuer.signing.keys {:?} needs a private_key for the file provider",
                    key.kid
                ));
            }
        }
    }

    fn check_trusted_issuers(&self, problems: &mut Vec<String>) {
        let mut prefixes = BTreeSet::new();
        for (name, trusted) in &self.trusted_issuers {
            let prefix = trusted.sub_prefix.as_str();
            if !is_sub_prefix(prefix) {
                problems.push(format!(
                    "trusted_issuers.{name}.sub_prefix must be lowercase letters, digits and -, not {prefix:?}"
                ));
            } else if !prefixes.insert(prefix) {
                problems.push(format!(
                    "trusted_issuers.{name}.sub_prefix {prefix:?} is used by another trusted issuer"
                ));
            }
            if !is_https(&trusted.issuer) {
                problems.push(format!("trusted_issuers.{name}.issuer must be https"));
            }
            for (field, url) in [
                ("discovery_url", &trusted.discovery_url),
                ("jwks_url", &trusted.jwks_url),
            ] {
                if let Some(url) = url
                    && url.scheme() != "https"
                {
                    problems.push(format!("trusted_issuers.{name}.{field} must be https"));
                }
            }
            if trusted.discovery_url.is_some() && trusted.jwks_url.is_some() {
                problems.push(format!(
                    "trusted_issuers.{name} sets both discovery_url and jwks_url; jwks_url skips discovery, so set one"
                ));
            }
            for (field, duration) in [
                ("jwks_max_age", trusted.jwks_max_age),
                ("jwks_retry", trusted.jwks_retry),
                ("jwks_refetch", trusted.jwks_refetch),
                ("jwks_timeout", trusted.jwks_timeout),
            ] {
                if duration.is_zero() {
                    problems.push(format!("trusted_issuers.{name}.{field} must be above zero"));
                }
            }
            if let Some(url) = &trusted.introspection_url
                && url.scheme() != "https"
            {
                problems.push(format!(
                    "trusted_issuers.{name}.introspection_url must be https"
                ));
            }
            if trusted.audiences.is_empty() {
                problems.push(format!("trusted_issuers.{name}.audiences is empty"));
            }
            match trusted.validation {
                Validation::Jwt => {
                    if trusted.algorithms.is_empty() {
                        problems.push(format!(
                            "trusted_issuers.{name}.algorithms is empty, and jwt validation needs at least one"
                        ));
                    }
                    if trusted.token_types.is_empty() {
                        problems.push(format!(
                            "trusted_issuers.{name}.token_types is empty, which refuses every token; leave it unset for [\"at+jwt\"]"
                        ));
                    }
                }
                Validation::Introspection => {
                    for (field, set) in [
                        ("introspection_url", trusted.introspection_url.is_some()),
                        ("client_id", trusted.client_id.is_some()),
                        ("client_secret", trusted.client_secret.is_some()),
                    ] {
                        if !set {
                            problems.push(format!(
                                "trusted_issuers.{name}.{field} is required for introspection"
                            ));
                        }
                    }
                }
            }
        }
    }

    fn check_claims(&self, problems: &mut Vec<String>) {
        for claim in &self.claims.copy {
            if RESERVED_CLAIMS.contains(&claim.as_str()) {
                problems.push(format!("claims.copy may not copy reserved claim {claim:?}"));
            }
        }
        for (name, renames) in &self.claims.rename {
            let mut targets = BTreeSet::new();
            for source in renames.keys() {
                if SCOPE_CLAIMS.contains(&source.as_str()) {
                    problems.push(format!(
                        "claims.rename.{name} may not rename {source:?}: scopes reach the minted \
                         token only through \"scope\", after the route's scope policy and narrowing"
                    ));
                }
            }
            for target in renames.values() {
                if RESERVED_CLAIMS.contains(&target.as_str()) {
                    problems.push(format!(
                        "claims.rename.{name} may not write reserved claim {target:?}"
                    ));
                } else if !targets.insert(target.as_str()) {
                    problems.push(format!(
                        "claims.rename.{name} writes claim {target:?} from more than one claim"
                    ));
                }
            }
        }
        for name in self.claims.rename.keys() {
            if !self.trusted_issuers.contains_key(name) {
                problems.push(format!("claims.rename.{name} names no trusted issuer"));
            }
        }
    }

    fn check_routes(&self, problems: &mut Vec<String>) {
        let mut names = BTreeSet::new();
        let mut hosts = BTreeSet::new();
        for route in &self.routes {
            let name = &route.name;
            if !names.insert(name.as_str()) {
                problems.push(format!("routes repeats name {name:?}"));
            }
            if !is_host(&route.host) {
                problems.push(format!(
                    "route {name:?} host must be a host name, without a scheme, port or path"
                ));
            } else if !hosts.insert(route.host.to_ascii_lowercase()) {
                problems.push(format!("routes repeats host {:?}", route.host));
            }
            for (kind, policy) in route.policies() {
                check_policy(name, kind, policy, problems);
            }
            if route.read_timeout.is_some_and(|timeout| timeout.is_zero()) {
                problems.push(format!("route {name:?} read_timeout must be above zero"));
            }
            if !is_origin(&route.downstream) {
                problems.push(format!(
                    "route {name:?} downstream must be an https origin, without a path, query or credentials"
                ));
            }
        }
    }
}

/// Checks a route's audience or scope policy: `allow` is not empty, every
/// value names one value once, `"*"` stands alone in `allow` and nowhere
/// else, `deny` is set only under `"*"`, and every `require` value is one
/// `allow` admits and not one `deny` lists.
fn check_policy(name: &str, kind: PolicyKind, policy: &Policy, problems: &mut Vec<String>) {
    let (list, noun) = (kind.key(), kind.noun());
    let any = policy.allows(ANY);
    if policy.allow.is_empty() {
        problems.push(format!(
            "route {name:?} {list}.allow is empty; omit allow to admit any {noun}, or remove the route to refuse every token"
        ));
    }
    for (field, values) in [
        ("allow", &policy.allow),
        ("require", &policy.require),
        ("deny", &policy.deny),
    ] {
        let mut seen = BTreeSet::new();
        let mut repeated = BTreeSet::new();
        for value in values {
            if !seen.insert(value.as_str()) {
                if repeated.insert(value.as_str()) {
                    problems.push(format!(
                        "route {name:?} {list}.{field} repeats {noun} {value:?}"
                    ));
                }
            } else if value.is_empty() {
                problems.push(format!(
                    "route {name:?} {list}.{field} has an empty value; name each {noun}"
                ));
            } else if value == ANY && field != "allow" {
                problems.push(format!(
                    "route {name:?} {list}.{field} may not hold \"*\"; name each {noun}"
                ));
            } else if value == ANY && values.iter().any(|value| value != ANY) {
                problems.push(format!(
                    "route {name:?} {list}.allow has \"*\" with other values; \"*\" allows any {noun}, so it stands alone"
                ));
            } else if kind == PolicyKind::Scopes && !is_scope_token(value) {
                // No token can carry such a scope, so the route would
                // refuse every token.
                problems.push(format!(
                    "route {name:?} {list}.{field} has {noun} {value:?}, which is not an RFC 6749 scope token: printable ASCII except space, '\"' and '\\'"
                ));
            } else if value.contains(char::is_whitespace) {
                problems.push(format!(
                    "route {name:?} {list}.{field} has {noun} {value:?}, which holds whitespace"
                ));
            } else if field == "require" && any && policy.denies(value) {
                problems.push(format!(
                    "route {name:?} both requires and denies {noun} {value:?}"
                ));
            } else if field == "require" && !policy.allows(value) {
                problems.push(format!(
                    "route {name:?} requires {noun} {value:?}, which its {list}.allow doesn't admit"
                ));
            }
        }
    }
    if !any && !policy.deny.is_empty() {
        problems.push(format!(
            "route {name:?} {list}.deny applies only when {list}.allow is \"*\" or omitted; remove the denied {list} from allow instead"
        ));
    }
}

/// Whether `text` is a bare host name: no scheme, port, path or
/// credentials.
fn is_host(text: &str) -> bool {
    !text.is_empty()
        && Url::parse(&format!("https://{text}")).is_ok_and(|url| {
            url.host_str()
                .is_some_and(|host| host.eq_ignore_ascii_case(text))
        })
}

/// Whether `url` is an https origin: scheme, host and port only.
fn is_origin(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none()
}
