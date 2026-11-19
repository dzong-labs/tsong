# Tsong

Tsong is an API gateway and an RFC 8693 token exchange issuer. It replaces each caller's access token, issued by any of several trusted identity providers, with a token signed by Tsong, so your services trust one issuer instead of many.

## Request flow

1. A caller sends a request with `Authorization: Bearer <token>`. The token comes from an identity provider Tsong is configured to trust, called a trusted issuer, such as Entra or Okta.
2. Tsong picks a route by the request's host name. The route names the service the request goes to.
3. Tsong validates the token: its signature, issuer, audience and expiry, and the route's audience and scope rules.
4. Tsong exchanges the token for a new one signed by Tsong. The new token's subject names the issuer, such as `entra:<id>`, so subjects from different providers never collide.
5. Tsong forwards the request to the route's service with the new token in place of the original. The original token never reaches the service.

Tsong caches the new token until shortly before it expires, so a repeat request with the same token skips steps 3 and 4.

## Parts

- The gateway: carries out the steps above. It handles host routing, IP allow lists, the exchange cache and header rewriting.
- The issuer: the token exchange, also reachable directly as an RFC 8693 token endpoint. It publishes its signing keys (JWKS) and an OIDC discovery document, which services use to validate the tokens signed by Tsong.

## Terms

- Upstream: the caller.
- Downstream: the service a route forwards to. Some gateways use these two words the other way around.
- Subject token: the caller's token, in RFC 8693's terms.
- Minted token: the token signed by Tsong that replaces it.

## Features

1. Routing. Tsong routes a request by its host alone, ignoring port and case, to the route's https downstream. The path and query pass through unchanged, and request and response bodies stream.
2. Token exchange. The gateway swaps the caller's bearer token for one signed by Tsong.
3. Exchange cache. Tsong exchanges a token at most once per route host while it stays cached, and concurrent requests share one exchange. An entry expires at the minted token's `exp` less the clock skew, and `max_entries` bounds the cache. Failed exchanges aren't cached.
4. Inbound validation. Tsong checks tokens against the trusted issuers' JWKS. Every check is mandatory: `iss`, `aud`, `exp`, `nbf`, signature, algorithm and key ID.
5. Issuer keys expire. Tsong trusts an issuer's keys for `jwks_max_age`, one hour by default, and renews them in the background three quarters of the way through. A renewal that fails is retried every `jwks_retry`. If the keys expire before a renewal succeeds, Tsong refuses that issuer's tokens with a 503 until the issuer answers. A token with an unknown key ID, or whose signature fails with a known key, triggers one refetch, no more often than `jwks_refetch`. An issuer's discovery document is found at the well-known path unless the config sets `discovery_url` or `jwks_url` for it. Each fetch has a timeout.
6. Route policy. A token must carry one of the route's `allowed_audiences`, and only scopes in its `allowed_scopes`. An empty list denies everything; `"*"` accepts anything. A route's optional `required_scopes` must all be present, and a token minted for the route always keeps them. Each item of an Entra-style `scp` array must be one scope, so a minted `scope` string never gains scopes the token didn't hold.
7. Minted tokens. JWTs, signed with the route's `signing_algorithm` (ES256 by default; RS256/384/512, PS256/384/512, ES384 and EdDSA on request), that keep the inbound `aud` and scopes and add the route's `append_audience`. The inbound token's expiry and `token_lifetime` cap their lifetime. Tsong copies the inbound claims the config lists, and renames claims per issuer.
8. Issuer-qualified subjects. The minted `sub` is the trusted issuer's `sub_prefix`, a colon and the subject, such as `rauthy:123456`, so two issuers' subjects never collide. Tsong keeps the original subject in an RFC 9493 `sub_id` claim. Its `iss_sub` format holds the subject token's own `iss` and `sub`. When a rename supplies the subject, such as Entra's `oid`, Tsong refuses a token without that claim instead of falling back to its `sub`.
9. RFC 8693 issuer. The token endpoint, JWKS and discovery document. The endpoint is reachable directly and enforces the same route policy and IP allow lists as the gateway. A subject token that fails validation gets `invalid_request`, as RFC 8693 section 2.2.2 requires.
10. IP allow lists. `gateway.allow` applies everywhere, and a route's optional `allow` narrows it. Tsong believes `X-Forwarded-For` only from trusted proxies.
11. Header hygiene. Tsong strips hop-by-hop and `Forwarded` headers, and sets `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host`. It keeps a trusted proxy's values.
12. Fails closed. 401 for a missing or bad token; 403 for a refused client, audience or scope; 503 when an issuer is unavailable; 502 when the downstream is unreachable; 504 when it stops answering past its read timeout.
13. Signing keys. Behind the `SigningKey` trait, with PKCS#8 PEM keys today, read through secret references. Each key names its algorithm, and Tsong refuses a key of the wrong type: P-256 for ES256, P-384 for ES384, Ed25519 for EdDSA, and a 2048- to 8192-bit RSA key (`openssl genpkey -algorithm RSA`, not `RSA-PSS`) for the RS and PS algorithms. One key is active for each algorithm the routes sign with, and retiring keys stay published in the JWKS.
14. Config. One TOML file, read through the `ConfigStore` trait from disk or from a folder on a Git branch. Unknown fields are errors, and Tsong reports every problem at once.
15. Reload from Git. A signed push webhook from GitHub or GitLab, or a poll, fetches the branch over SSH with a deploy key. Tsong validates a new config and builds its state in full before swapping it in. A config that fails leaves the old one serving. Tsong audits each reload as a JSON line on stdout, and `GET /status` on the admin listener reports the revision being served and when the store was last read. If Git can't be read, the last good config keeps serving, and metrics show its age and each replica's revision.
16. Observability. Liveness and readiness on their own listener, Prometheus metrics at `GET /metrics` (cache hits and misses, requests and downstream latency by route, exchanges, JWKS failures and key age, reloads), one JSON audit line per token exchange with the caller's `iss` and `sub`, an audit line for each failed JWKS fetch and for the fetch that recovers, and every request correlated by `X-Request-Id` and W3C `traceparent`.
17. CLI. `tsong check` validates a config and loads its keys. It warns on empty or accept-anything lists, and on issuer keys trusted for more than a day. `--deny-warnings` fails on warnings in CI. `tsong serve` reads a bootstrap file, deployed with Tsong, that names the config source and the admin and webhook listeners, then runs the gateway and the issuer.
18. Secret references. A secret field holds a reference, never the secret: a table with one key, the scheme. `{ env = "NAME" }` reads an environment variable, and `{ file = "path" }` reads a file of up to 64 KiB, without one trailing line ending, a relative path taken from the config file's directory. The secret fields are a signing key's `private_key`, a trusted issuer's `client_secret` and the bootstrap file's `webhook.secret`. Anything else in them is refused, as are a missing or empty secret.

## Usage

```sh
tsong check [--deny-warnings] <config.toml>
tsong serve <bootstrap.toml>
```

[examples/tsong.toml](examples/tsong.toml) is a sample config, and [examples/bootstrap.toml](examples/bootstrap.toml) a sample bootstrap file. [docs/notes/gateway-plan.md](docs/notes/gateway-plan.md) describes how the gateway works, and [docs/notes/roadmap.md](docs/notes/roadmap.md) lists what comes next: introspection for opaque tokens, actor tokens, and keys from a secrets manager.

`tsong serve` stops on SIGTERM or Ctrl+C. With a `[health]` listener in the bootstrap file, readiness fails first and stays failed for `health.drain`, 5s by default. The load balancer stops sending requests, and then the listeners close. A second signal ends the drain at once. Without a `[health]` listener, the listeners close at once. [docs/notes/shutdown-and-draining.md](docs/notes/shutdown-and-draining.md) explains how the drain, the load balancer's health check and the orchestrator's deregistration fit together.

### Container

The [Containerfile](Containerfile) builds an image that runs `tsong serve /etc/tsong/bootstrap.toml` as an unprivileged user. Its base is Debian slim, which carries the `ssh` a Git source needs. The root filesystem can be read-only: the only writable path is `/var/lib/tsong`, for a Git source's clone. [deploy/podman](deploy/podman) runs it in local podman with a stub bootstrap file and config:

```sh
deploy/podman/run.sh build    # build tsong:local
deploy/podman/run.sh start    # gateway :8443, issuer :8444, admin :8445, health :8447
deploy/podman/run.sh stop     # SIGTERM, then the drain
```

## Crates

- `tsong-config`: the TOML model, its validation and warnings, the host route table, the client-address rules, the bootstrap file, and the `ConfigStore` trait with the file store.
- `tsong-clock`: the injected `Clock`.
- `tsong-secrets`: the `SecretSource` trait, and the sources that read secret references.
- `tsong-keys`: the `SigningKey` trait, the `KeySet` that rotates keys, and the file provider.
- `tsong-validate`: inbound token validation and JWKS fetching, shared by the issuer and the gateway.
- `tsong-issuer`: the RFC 8693 token endpoint, JWKS and discovery.
- `tsong-gateway`: the API gateway and the exchange cache.
- `tsong-git`: the Git config store and webhook verification.
- `tsong`: the command, the reloader, and the admin and webhook listeners.

## Development

`cargo test --workspace` runs the tests. Each crate's own tests cover its code. Line coverage stays above 95%, measured with `cargo llvm-cov`.

`rust-toolchain.toml` installs the stable toolchain with clippy, rustfmt and rust-analyzer. Enable the hooks once per clone. Before each commit they check formatting, lints, docs and tests; before each push, coverage and the dependency audit, as CI does. The push checks need `cargo-llvm-cov` and `cargo-audit`.

```sh
git config core.hooksPath .githooks
```

Tsong runs on Linux, so mutation testing runs on Linux only: in CI on each pull request, or locally in podman with `scripts/linux.sh mutants --workspace`.

[CONTRIBUTING.md](CONTRIBUTING.md) says how to propose a change and what a pull request needs. [CHANGELOG.md](CHANGELOG.md) lists each release's changes.

## Security

Report a vulnerability privately, as [SECURITY.md](SECURITY.md) describes, never in a public issue.
