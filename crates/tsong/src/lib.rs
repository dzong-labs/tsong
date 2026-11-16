//! The `tsong` command: `check` validates a config, loads its keys and
//! reports its warnings; `serve` runs the gateway and the token exchange
//! issuer.

use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::watch;
use tsong_clock::SystemClock;
use tsong_config::{ConfigError, ConfigStore, FileStore, Warnings};
use tsong_gateway::{Gateway, GatewayError};
use tsong_issuer::Issuer;
use tsong_keys::{KeyError, KeySet};
use tsong_validate::{HttpFetcher, Validator};

/// How to run the command.
pub const USAGE: &str =
    "usage: tsong check [--deny-warnings] <config.toml> | tsong serve <config.toml>";

/// The flag that makes `check` fail on warnings.
pub const DENY_WARNINGS: &str = "--deny-warnings";

/// Why the command failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{USAGE}")]
    Usage,
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error(transparent)]
    Gateway(#[from] GatewayError),
    #[error("{0}warnings are denied")]
    Warnings(Warnings),
    #[error("serving: {0}")]
    Io(#[from] std::io::Error),
}

/// Runs the command for its arguments, without the program name, and
/// returns what to print.
pub async fn run(args: impl IntoIterator<Item = String>) -> Result<String, Error> {
    let args: Vec<_> = args.into_iter().collect();
    match args.as_slice() {
        [command, path] if command == "check" => check(Path::new(path), false).await,
        [command, flag, path] if command == "check" && flag == DENY_WARNINGS => {
            check(Path::new(path), true).await
        }
        [command, path] if command == "serve" => {
            serve_until(Path::new(path), shutdown_signal()).await?;
            Ok("stopped".into())
        }
        _ => Err(Error::Usage),
    }
}

/// Loads the config at `path` and its signing keys, and reports its
/// warnings. With `deny_warnings`, a warning fails the check.
pub async fn check(path: &Path, deny_warnings: bool) -> Result<String, Error> {
    let config = FileStore::new(path).load().await?;
    let keys = KeySet::from_config(&config.issuer.signing)?;
    let warnings = config.warnings();
    if deny_warnings && !warnings.0.is_empty() {
        return Err(Error::Warnings(warnings));
    }
    Ok(format!(
        "{warnings}{}: ok, signing with {}",
        path.display(),
        keys.active().kid(),
    ))
}

/// Serves the gateway on `gateway.listen` and the issuer on
/// `issuer.listen`, for the config at `path`, until `shutdown` completes.
pub async fn serve_until(
    path: &Path,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), Error> {
    let config = Arc::new(FileStore::new(path).load().await?);
    let clock = Arc::new(SystemClock);
    let keys = KeySet::from_config(&config.issuer.signing)?;
    let validator = Validator::new(&config, Arc::new(HttpFetcher::default()), clock.clone());
    let issuer = Arc::new(Issuer::new(config.clone(), keys, validator, clock.clone()));
    let gateway = Arc::new(Gateway::new(&config, issuer.clone(), clock)?);

    let issuer_listener = TcpListener::bind(config.issuer.listen).await?;
    let gateway_listener = TcpListener::bind(config.gateway.listen).await?;

    // One shutdown, heard by both servers.
    let (stop, stopping) = watch::channel(false);
    let stopped = |mut stopping: watch::Receiver<bool>| async move {
        let _ = stopping.wait_for(|stop| *stop).await;
    };
    let signal = async move {
        shutdown.await;
        let _ = stop.send(true);
        Ok::<(), std::io::Error>(())
    };
    let issuer_server = axum::serve(issuer_listener, tsong_issuer::router(issuer))
        .with_graceful_shutdown(stopped(stopping.clone()));
    let gateway_server = axum::serve(
        gateway_listener,
        tsong_gateway::router(gateway).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(stopped(stopping));
    tokio::try_join!(signal, async { issuer_server.await }, async {
        gateway_server.await
    },)?;
    Ok(())
}

/// Completes on Ctrl+C. If the signal can't be watched, it never
/// completes, and the process is stopped some other way.
async fn shutdown_signal() {
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}
