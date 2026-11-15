//! The `tsong` command: `check` validates a config and loads its keys;
//! `serve` runs the token exchange issuer.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;

use tsong_clock::SystemClock;
use tsong_config::{Config, ConfigError, ConfigStore, FileStore};
use tsong_issuer::Issuer;
use tsong_keys::{KeyError, KeySet};
use tsong_validate::{HttpFetcher, Validator};

/// How to run the command.
pub const USAGE: &str = "usage: tsong check <config.toml> | tsong serve <config.toml>";

/// Why the command failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{USAGE}")]
    Usage,
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error("serving: {0}")]
    Io(#[from] std::io::Error),
}

/// Runs the command for its arguments, without the program name, and
/// returns what to print.
pub async fn run(args: impl IntoIterator<Item = String>) -> Result<String, Error> {
    let args: Vec<_> = args.into_iter().collect();
    match args.as_slice() {
        [command, path] if command == "check" => check(Path::new(path)).await,
        [command, path] if command == "serve" => {
            serve_until(Path::new(path), shutdown_signal()).await?;
            Ok("stopped".into())
        }
        _ => Err(Error::Usage),
    }
}

/// Loads the config at `path` and its signing keys.
pub async fn check(path: &Path) -> Result<String, Error> {
    let config = FileStore::new(path).load().await?;
    let keys = KeySet::from_config(&config.issuer.signing)?;
    Ok(format!(
        "{}: ok, signing with {}",
        path.display(),
        keys.active().kid(),
    ))
}

/// Serves the issuer for the config at `path` on its `issuer.listen`
/// address until `shutdown` completes.
pub async fn serve_until(
    path: &Path,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), Error> {
    let config = FileStore::new(path).load().await?;
    let (listen, issuer) = issuer(config)?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, tsong_issuer::router(issuer))
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

/// The issuer for `config`, and where it listens.
fn issuer(config: Config) -> Result<(std::net::SocketAddr, Arc<Issuer>), Error> {
    let keys = KeySet::from_config(&config.issuer.signing)?;
    let clock = Arc::new(SystemClock);
    let validator = Validator::new(&config, Arc::new(HttpFetcher::default()), clock.clone());
    let listen = config.issuer.listen;
    Ok((
        listen,
        Arc::new(Issuer::new(Arc::new(config), keys, validator, clock)),
    ))
}

/// Completes on Ctrl+C. If the signal can't be watched, it never
/// completes, and the process is stopped some other way.
async fn shutdown_signal() {
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}
