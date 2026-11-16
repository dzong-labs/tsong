//! Warnings: settings that are valid but look like a mistake. An empty
//! allow list denies everything, which looks like an omission; an entry
//! that accepts anything looks like a decision worth confirming.

use std::fmt;

use ipnet::IpNet;

use crate::{ANY, Config};

/// Every warning a config has, one per line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Warnings(pub Vec<String>);

impl fmt::Display for Warnings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for warning in &self.0 {
            writeln!(f, "warning: {warning}")?;
        }
        Ok(())
    }
}

impl Config {
    /// The config's warnings, in config order.
    pub fn warnings(&self) -> Warnings {
        let mut warnings = Vec::new();
        ip_list(&mut warnings, "gateway.allow", &self.gateway.allow);
        for route in &self.routes {
            let name = &route.name;
            for (field, values) in [
                ("allowed_audiences", &route.allowed_audiences),
                ("allowed_scopes", &route.allowed_scopes),
            ] {
                if values.is_empty() {
                    warnings.push(format!(
                        "route {name:?}: {field} is empty; every request will be denied"
                    ));
                } else if values.iter().any(|value| value == ANY) {
                    warnings.push(format!(
                        "route {name:?}: {field} has \"*\"; any value is accepted"
                    ));
                }
            }
            if let Some(allow) = &route.allow {
                ip_list(&mut warnings, &format!("route {name:?}: allow"), allow);
            }
        }
        Warnings(warnings)
    }
}

/// Warns on an IP allow list that denies every client or allows every
/// address of a family.
fn ip_list(warnings: &mut Vec<String>, field: &str, list: &[IpNet]) {
    if list.is_empty() {
        warnings.push(format!("{field} is empty; every client will be denied"));
    }
    for net in list.iter().filter(|net| net.prefix_len() == 0) {
        warnings.push(format!("{field} has {net}; every address is allowed"));
    }
}
