//! The `tsong` command: `check` validates a config, loads its keys and
//! reports its warnings; `serve` reads a bootstrap file, then runs the
//! gateway and the token exchange issuer, reloading the config when its
//! Git branch moves.

pub mod admin;
pub mod reload;
pub mod state;

use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::{Notify, watch};
use tsong_clock::{Clock, SystemClock};
use tsong_config::{
    Bootstrap, BootstrapError, ConfigError, ConfigStore, FileStore, Source, Warnings,
};
use tsong_gateway::GatewayError;
use tsong_git::GitStore;
use tsong_keys::{KeyError, KeySet};

use crate::admin::Hook;
use crate::reload::{Lines, Reloader};
use crate::state::State;

/// How to run the command.
pub const USAGE: &str =
    "usage: tsong check [--deny-warnings] <config.toml> | tsong serve <bootstrap.toml>";

/// The flag that makes `check` fail on warnings.
pub const DENY_WARNINGS: &str = "--deny-warnings";

/// Why the command failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{USAGE}")]
    Usage,
    #[error(transparent)]
    Bootstrap(#[from] BootstrapError),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error(transparent)]
    Gateway(#[from] GatewayError),
    #[error("{0}warnings are denied")]
    Warnings(Warnings),
    #[error("the environment variable {0} is not set")]
    Secret(String),
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
    let config = FileStore::new(path).load().await?.config;
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

/// Serves Tsong for the bootstrap file at `path` until `shutdown`
/// completes: the issuer on `issuer.listen`, the gateway on
/// `gateway.listen`, and the admin listener when the bootstrap file has
/// one. A git source is reloaded on each webhook delivery and poll.
pub async fn serve_until(
    path: &Path,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), Error> {
    let bootstrap = Bootstrap::load(path)?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let (store, poll) = store(&bootstrap.source);
    let first = State::build(store.load().await?, clock.clone())?;
    let issuer_address = first.config.issuer.listen;
    let gateway_address = first.config.gateway.listen;
    let reloader = Arc::new(Reloader::new(
        store,
        first,
        Arc::new(Lines::new(std::io::stdout())),
        clock,
    ));
    let trigger = Arc::new(Notify::new());
    let admin = match &bootstrap.admin {
        Some(admin) => {
            let hook = hook(&bootstrap, admin.webhook.as_ref())?;
            let router = admin::router(hook, trigger.clone(), reloader.status());
            Some((TcpListener::bind(admin.listen).await?, router))
        }
        None => None,
    };
    let issuer_listener = TcpListener::bind(issuer_address).await?;
    let gateway_listener = TcpListener::bind(gateway_address).await?;

    // One shutdown, heard by every server and the reload loop.
    let (stop, stopping) = watch::channel(false);
    let stopped = |mut stopping: watch::Receiver<bool>| async move {
        let _ = stopping.wait_for(|stop| *stop).await;
    };
    let signal = async move {
        shutdown.await;
        let _ = stop.send(true);
        Ok::<(), std::io::Error>(())
    };
    let issuer_server = axum::serve(
        issuer_listener,
        state::current(reloader.subscribe(), |state| &state.issuer)
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(stopped(stopping.clone()));
    let gateway_server = axum::serve(
        gateway_listener,
        state::current(reloader.subscribe(), |state| &state.gateway)
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(stopped(stopping.clone()));
    let admin_server = {
        let stopping = stopping.clone();
        async move {
            match admin {
                Some((listener, router)) => {
                    axum::serve(listener, router)
                        .with_graceful_shutdown(stopped(stopping))
                        .await
                }
                None => Ok(()),
            }
        }
    };
    let reloads = async move {
        if let Some(poll) = poll {
            reload_loop(&reloader, &trigger, poll, stopped(stopping)).await;
        }
        Ok(())
    };
    tokio::try_join!(
        signal,
        async { issuer_server.await },
        async { gateway_server.await },
        admin_server,
        reloads,
    )?;
    Ok(())
}

/// The store for `source`, and how often to poll it: never for a file.
fn store(source: &Source) -> (Box<dyn ConfigStore>, Option<Duration>) {
    match source {
        Source::Git(git) => (Box::new(GitStore::new(git)), Some(git.poll)),
        Source::File { path } => (Box::new(FileStore::new(path)), None),
    }
}

/// The webhook's verification, with its secret read from the environment.
fn hook(
    bootstrap: &Bootstrap,
    webhook: Option<&tsong_config::Webhook>,
) -> Result<Option<Hook>, Error> {
    let (Some(webhook), Source::Git(git)) = (webhook, &bootstrap.source) else {
        return Ok(None);
    };
    let secret = std::env::var(&webhook.secret_env)
        .ok()
        .filter(|secret| !secret.is_empty())
        .ok_or_else(|| Error::Secret(webhook.secret_env.clone()))?;
    Ok(Some(Hook {
        host: webhook.host,
        secret: secret.into_bytes(),
        branch: git.branch.clone(),
    }))
}

/// Reloads on each trigger and each poll until `stopped` completes.
pub async fn reload_loop(
    reloader: &Reloader,
    trigger: &Notify,
    poll: Duration,
    stopped: impl Future<Output = ()>,
) {
    tokio::pin!(stopped);
    loop {
        tokio::select! {
            () = &mut stopped => return,
            () = trigger.notified() => {}
            () = tokio::time::sleep(poll) => {}
        }
        reloader.reload().await;
    }
}

/// Completes on Ctrl+C. If the signal can't be watched, it never
/// completes, and the process is stopped some other way.
async fn shutdown_signal() {
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}
