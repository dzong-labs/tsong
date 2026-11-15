//! Checks that span fields: references resolve, exactly one key signs,
//! each validation mode has what it needs.

use std::collections::BTreeSet;
use std::fmt;

use url::Url;

use crate::{Config, KeyProvider, KeyState, Validation};

/// Claims Tsong sets on every token it issues, which claim mapping may not
/// write.
pub const RESERVED_CLAIMS: [&str; 9] = [
    "iss", "aud", "exp", "iat", "nbf", "jti", "scope", "act", "cnf",
];

/// Whether `text` is an https URL.
fn is_https(text: &str) -> bool {
    Url::parse(text).is_ok_and(|url| url.scheme() == "https")
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
        if self.gateway.cache.max_entries == 0 {
            problems.push("gateway.cache.max_entries must be above zero".into());
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(Problems(problems))
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
        let active = signing
            .keys
            .iter()
            .filter(|key| key.state == KeyState::Active)
            .count();
        if active != 1 {
            problems.push(format!(
                "issuer.signing.keys must have exactly one active key, not {active}"
            ));
        }
        let mut kids = BTreeSet::new();
        for key in &signing.keys {
            if key.kid.is_empty() {
                problems.push("issuer.signing.keys has a key with an empty kid".into());
            } else if !kids.insert(key.kid.as_str()) {
                problems.push(format!("issuer.signing.keys repeats kid {:?}", key.kid));
            }
            if signing.provider == KeyProvider::File && key.path.is_none() {
                problems.push(format!(
                    "issuer.signing.keys {:?} needs a path for the file provider",
                    key.kid
                ));
            }
        }
    }

    fn check_trusted_issuers(&self, problems: &mut Vec<String>) {
        for (name, trusted) in &self.trusted_issuers {
            if !is_https(&trusted.issuer) {
                problems.push(format!("trusted_issuers.{name}.issuer must be https"));
            }
            if let Some(url) = &trusted.jwks_url
                && url.scheme() != "https"
            {
                problems.push(format!("trusted_issuers.{name}.jwks_url must be https"));
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
                }
                Validation::Introspection => {
                    for (field, set) in [
                        ("introspection_url", trusted.introspection_url.is_some()),
                        ("client_id", trusted.client_id.is_some()),
                        ("client_secret_env", trusted.client_secret_env.is_some()),
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
            for target in renames.values() {
                if RESERVED_CLAIMS.contains(&target.as_str()) {
                    problems.push(format!(
                        "claims.rename.{name} may not write reserved claim {target:?}"
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
        for route in &self.routes {
            let name = &route.name;
            if !names.insert(name.as_str()) {
                problems.push(format!("routes repeats name {name:?}"));
            }
            let matcher = &route.matcher;
            if matcher.host.is_none() && matcher.path_prefix.is_none() {
                problems.push(format!(
                    "route {name:?} must match a host, a path_prefix or both"
                ));
            }
            if let Some(prefix) = &matcher.path_prefix
                && !prefix.starts_with('/')
            {
                problems.push(format!("route {name:?} path_prefix must start with /"));
            }
            if !matches!(route.downstream.scheme(), "http" | "https") {
                problems.push(format!("route {name:?} downstream must be http or https"));
            }
            if route.trusted_issuers.is_empty() {
                problems.push(format!("route {name:?} trusts no issuer"));
            }
            for issuer in &route.trusted_issuers {
                if !self.trusted_issuers.contains_key(issuer) {
                    problems.push(format!(
                        "route {name:?} trusts {issuer:?}, which is not in trusted_issuers"
                    ));
                }
            }
            if route.audience.is_empty() {
                problems.push(format!("route {name:?} has an empty audience"));
            }
        }
    }
}
