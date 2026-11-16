# Tsong

Tsong is a reverse-proxy API gateway that exchanges tokens. A request arrives with a bearer token from one of the organization's trusted issuers. Tsong validates it, exchanges it for a token Tsong signs itself, and forwards the request to the route's downstream service with the new token in place of the old one. The original token never reaches the downstream.

It has two parts:

- The gateway: routes by host, IP allow lists, the exchange cache and header rewriting.
- The issuer: an RFC 8693 token exchange endpoint, with JWKS and OIDC discovery so downstream services can validate the tokens it signs.

In Tsong's terms the upstream is the caller and the downstream is the service a route forwards to.

## Features

1. Reverse proxy. A request is routed by its host alone, without port or case, to the route's https downstream. The path and query pass through unchanged, and request and response bodies stream.
2. Token exchange. The gateway swaps the caller's bearer token for one Tsong signs.
3. Exchange cache. A token is exchanged at most once per route host while it stays cached, and concurrent requests share one exchange. An entry expires at the minted token's `exp` less the clock skew, and `max_entries` bounds the cache. Failed exchanges are not kept.
4. Inbound validation. Tokens are checked against the trusted issuers' JWKS, refetched on an unknown key ID. Every check is mandatory: `iss`, `aud`, `exp`, `nbf`, signature, algorithm and key ID.
5. Route policy. A token must carry one of the route's `allowed_audiences`, and only scopes in its `allowed_scopes`. An empty list denies everything; `"*"` accepts anything.
6. Minted tokens. ES256 JWTs that keep the inbound `aud` and scopes and add the route's `append_audience`. Their lifetime is capped by the inbound token and `token_lifetime`. Claims can be copied, or renamed per issuer.
7. Issuer-qualified subjects. The minted `sub` is the trusted issuer's `sub_prefix`, a colon and the subject, such as `rauthy:123456`, so two issuers' subjects never collide. The original subject is kept in an RFC 9493 `sub_id` claim in the `iss_sub` format, holding the subject token's own `iss` and `sub`.
8. RFC 8693 issuer. The token endpoint, JWKS and discovery document. The endpoint is reachable directly and enforces the same route policy and IP allow lists as the gateway. A subject token that fails validation gets `invalid_request`, as RFC 8693 section 2.2.2 requires.
9. IP allow lists. `gateway.allow` applies everywhere, and a route's optional `allow` narrows it. `X-Forwarded-For` is believed only from trusted proxies.
10. Header hygiene. Hop-by-hop and `Forwarded` headers are stripped, and `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host` are set. A trusted proxy's values are kept.
11. Fails closed. 401 for a missing or bad token; 403 for a refused client, audience or scope; 503 when an issuer is unavailable; 502 when the downstream is unreachable; 504 when it stops answering past its read timeout.
12. Signing keys. Behind the `SigningKey` trait, with PEM files today. One key is active, and retiring keys stay published in the JWKS.
13. Config. One TOML file, read through the `ConfigStore` trait from disk or from a folder on a Git branch. Unknown fields are errors, and every problem is reported at once.
14. Reload from Git. A signed push webhook from GitHub or GitLab, or a poll, fetches the branch over SSH with a deploy key. A new config is validated and its state built in full before it is swapped in; a config that fails keeps the old one serving. Each reload is audited as a JSON line on stdout, and `GET /status` on the admin listener reports the revision being served.
15. Observability. Liveness and readiness on their own listener, Prometheus metrics at `GET /metrics` (cache hits and misses, requests and downstream latency by route, exchanges, JWKS failures, reloads), one JSON audit line per token exchange with the caller's `iss` and `sub`, and every request correlated by `X-Request-Id` and W3C `traceparent`.
16. CLI. `tsong check` validates a config and loads its keys, and warns on empty or accept-anything lists; `--deny-warnings` fails on warnings in CI. `tsong serve` reads a bootstrap file, deployed with Tsong, that names the config source and the admin and webhook listeners, then runs the gateway and the issuer.

## Usage

```sh
tsong check [--deny-warnings] <config.toml>
tsong serve <bootstrap.toml>
```

[examples/tsong.toml](examples/tsong.toml) is a sample config, and [examples/bootstrap.toml](examples/bootstrap.toml) a sample bootstrap file. [docs/notes/gateway-plan.md](docs/notes/gateway-plan.md) describes how the gateway works, and [docs/notes/roadmap.md](docs/notes/roadmap.md) lists what comes next: introspection for opaque tokens, actor tokens, and keys from a secrets manager.

## Crates

- `tsong-config`: the TOML model, its validation and warnings, the host route table, the client-address rules, the bootstrap file, and the `ConfigStore` trait with the file store.
- `tsong-clock`: the injected `Clock`.
- `tsong-keys`: the `SigningKey` trait, the `KeySet` that rotates keys, and the file provider.
- `tsong-validate`: inbound token validation and JWKS fetching, shared by the issuer and the gateway.
- `tsong-issuer`: the RFC 8693 token endpoint, JWKS and discovery.
- `tsong-gateway`: the reverse proxy and the exchange cache.
- `tsong-git`: the Git config store and webhook verification.
- `tsong`: the command, the reloader, and the admin and webhook listeners.

## Development

`cargo test --workspace` runs the tests. Each crate's own tests cover its code. Line coverage stays above 95%, measured with `cargo llvm-cov`.

`rust-toolchain.toml` installs the stable toolchain with clippy, rustfmt and rust-analyzer. Enable the hooks once per clone. Before each commit they check formatting, lints, docs and tests; before each push, coverage and the dependency audit, as CI does. The push checks need `cargo-llvm-cov` and `cargo-audit`.

```sh
git config core.hooksPath .githooks
```

Tsong runs on Linux, so mutation testing runs on Linux only: in CI on each pull request, or locally in podman with `scripts/linux.sh mutants --workspace`.
