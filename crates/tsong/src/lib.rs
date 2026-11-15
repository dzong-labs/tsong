//! The `tsong` command. For now it only checks a config: that it parses,
//! validates and its signing keys load.

use std::path::Path;

use tsong_config::{Config, ConfigError};
use tsong_keys::{KeyError, KeySet};

/// How to run the command.
pub const USAGE: &str = "usage: tsong check <config.toml>";

/// Why the command failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{USAGE}")]
    Usage,
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Key(#[from] KeyError),
}

/// Runs the command for its arguments, without the program name, and
/// returns what to print.
pub fn run(args: impl IntoIterator<Item = String>) -> Result<String, Error> {
    let args: Vec<_> = args.into_iter().collect();
    match args.as_slice() {
        [command, path] if command == "check" => check(Path::new(path)),
        _ => Err(Error::Usage),
    }
}

/// Loads the config at `path` and its signing keys.
pub fn check(path: &Path) -> Result<String, Error> {
    let config = Config::load(path)?;
    let keys = KeySet::from_config(&config.issuer.signing)?;
    Ok(format!(
        "{}: ok, {} routes, {} trusted issuers, signing with {}",
        path.display(),
        config.routes.len(),
        config.trusted_issuers.len(),
        keys.active().kid(),
    ))
}
