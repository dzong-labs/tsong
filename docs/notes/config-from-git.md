---
title: Config reloads from Git when the watched branch moves
type: note
summary: A bootstrap file names the config source; a Git source fetches the branch over SSH with gitoxide, reloads on a webhook or a slow poll, and swaps in fully validated state through a watch channel.
status: evolving
created: 2026-11-16
part-of: "[[roadmap]]"
---

# Config reloads from Git when the watched branch moves

Tsong reads its config from a Git branch and reloads when the branch moves. A reload builds the whole runtime state from the new commit, validates it, and swaps it in at once. A config that fails validation never replaces the one being served. This is item 7 of the [[roadmap]].

## Bootstrap

Settings that say where the config lives can't live in that config. A bootstrap TOML file, deployed with the app, holds them, and `tsong serve <bootstrap.toml>` reads it.

```toml
[source]
store = "git"
url = "ssh://git@github.com/example/tsong-config.git"
branch = "main"
folder = "tsong"                          # the repo folder holding tsong.toml
checkout = "/var/lib/tsong/config.git"    # a bare clone Tsong keeps
ssh_key = "/etc/tsong/deploy_key"
known_hosts = "/etc/tsong/known_hosts"
poll = "5m"

[admin]
listen = "0.0.0.0:8445"                   # GET /status

[webhook]
listen = "0.0.0.0:8446"                   # POST /hooks/config
allow = ["192.30.252.0/22"]               # the Git host's delivery addresses
host = "github"                           # or "gitlab"
secret_env = "TSONG_WEBHOOK_SECRET"
```

`store = "file"` with `path` reads a config file from disk and never reloads. Relative paths in the bootstrap file, a file source's `path` and a Git source's `checkout`, `ssh_key`, `known_hosts` and local `url`, are taken from the bootstrap file's directory.

## Fetching

`GitStore` implements the `ConfigStore` trait (`crates/tsong-config/src/store.rs`), so another store, such as one using a Git host's file API, can be injected later from the bootstrap file. It uses gitoxide (`gix`):

- It keeps a bare clone at `checkout` and fetches only the watched branch.
- It reads `tsong.toml` from `folder` in the fetched commit's tree. Nothing is checked out. The folder leaves room for route files split out of `tsong.toml`, roadmap item 15.
- It authenticates with a read-only deploy key over SSH. gix runs the system `ssh` program with the key, `known_hosts`, `StrictHostKeyChecking=yes` and `IdentitiesOnly=yes`, so the OpenSSH client must be installed. An ssh url must set both `ssh_key` and `known_hosts`. The `ssh` command reads no `ssh_config` (`-F /dev/null`) and no system-wide known hosts (`GlobalKnownHostsFile=/dev/null`), so host keys are pinned to `known_hosts` alone and nothing on the machine can relax them. Only ssh urls and local paths are accepted: a transport nothing authenticates, such as `http://` or `git://`, would let anyone on the path rewrite the trusted issuers.

Every `ConfigStore` returns the config with a revision and a content ID. The revision is the commit ID for Git and a SHA-256 of the file for a file store; it is what `/status` and the audit log name. The content ID is the config file's blob ID for Git and the same SHA-256 for a file store; a reload compares it, so a commit that doesn't touch `tsong.toml` rebuilds nothing. A config that fails to parse or validate is reported with its revision and content ID, as `ConfigError::AtRevision`.

A fetch is abandoned after two minutes, and `ssh` gives up on a dead connection through `ConnectTimeout` and `ServerAliveInterval`. A shutdown cancels a reload in progress and interrupts its fetch, so a stalled Git host can't hold Tsong open.

Private keys never live in Git. The config refers to a key by a pointer, a file path today and a secret ARN once item 8 lands. A file key path in a config from Git must be absolute, because a relative path would point into the clone.

## Triggers

- A webhook on its own listener, `webhook.listen`, at `POST /hooks/config`. The secret is read from the environment variable `webhook.secret_env` at start; Tsong refuses to start without it. GitHub requests are verified by the HMAC-SHA256 in `X-Hub-Signature-256`, GitLab requests by the shared token in `X-Gitlab-Token`, both compared in constant time. Deliveries may be JSON or GitHub's default form encoding, up to GitHub's 25 MB limit. A verified push to the watched branch triggers a fetch and answers 202. Any other verified delivery, such as a ping or a push to another branch, answers 204, and an unverified one 401. The payload's commit ID is not trusted; the fetch decides what changed.
- A poll every `poll` interval, in case a webhook is missed.

Each listener has its own allow list. The webhook listener admits only peers in `webhook.allow`, which holds the Git host's delivery addresses (GitHub publishes them at `api.github.com/meta`). That list is deployed in the bootstrap file, never loaded from Git, and is checked against each connection's own address, since nothing should proxy the webhook. The admin listener admits clients in `gateway.allow` of the config being served, found through `gateway.trusted_proxies` like the gateway and the issuer.

## Reload

1. Fetch. If the branch's commit is the one being served, stop.
2. Parse and validate the config, load its signing keys, and build new state: route table, issuer, validator, gateway, downstream clients and an empty exchange cache.
3. On any failure, keep serving the old state and log why. A config rejected as invalid isn't rejected again until its content changes; a failed fetch or build is retried every time.
4. Otherwise send the new state on a `tokio::sync::watch` channel. Each request takes a snapshot of the state when it starts, so requests in flight finish on the old config.

Rebuilding the state clears the exchange cache, drops cached JWKS, picks up new signing keys and builds clients for new read timeouts.

## Subscribers

Eight things react to a reload. Four are part of the state, so rebuilding it handles them: the exchange cache is cleared, cached JWKS are dropped, new signing keys are loaded, and clients for new read timeouts are built. The reloader (`crates/tsong/src/reload.rs`) handles the other four, because a failed reload produces no new state for a watcher to see:

- The audit log writes one JSON line to stdout for each new revision and each failure: the time, commit, author, outcome, and the routes added, removed and changed, keyed by host. A fetch that finds the revision being served writes nothing. Collecting stdout belongs to the platform.
- `GET /status` on the admin listener reports the revision being served, when it loaded, the count of reloads and failed reloads, and the last failure as a short reason: `fetch_failed`, `invalid_config` or `build_failed`. The detail stays in the audit log.
- The reload counts in `/status` stand in for metrics until observability, roadmap item 9.
- A change to `issuer.listen` or `gateway.listen` is named in the audit line's `restart_required`. The old addresses stay bound until a restart.

## Deferred

- HTTPS with a token, as an alternative to the deploy key.
- A store that reads through a Git host's file API.
- Signed-commit verification.
