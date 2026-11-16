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
7. RFC 8693 issuer. The token endpoint, JWKS and discovery document. The endpoint is reachable directly and enforces the same route policy and IP allow lists as the gateway.
8. IP allow lists. `gateway.allow` applies everywhere, and a route's optional `allow` narrows it. `X-Forwarded-For` is believed only from trusted proxies.
9. Header hygiene. Hop-by-hop and `Forwarded` headers are stripped, and `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host` are set. A trusted proxy's values are kept.
10. Fails closed. 401 for a missing or bad token; 403 for a refused client, audience or scope; 503 when an issuer is unavailable; 502 when the downstream is unreachable; 504 when it stops answering past its read timeout.
11. Signing keys. Behind the `SigningKey` trait, with PEM files today. One key is active, and retiring keys stay published in the JWKS.
12. Config. One TOML file, read through the `ConfigStore` trait. Unknown fields are errors, and every problem is reported at once.
13. CLI. `tsong check` validates a config and loads its keys, and warns on empty or accept-anything lists; `--deny-warnings` fails on warnings in CI. `tsong serve` runs the gateway and the issuer.

## Usage

```sh
tsong check [--deny-warnings] <config.toml>
tsong serve <config.toml>
```

[examples/tsong.toml](examples/tsong.toml) is a sample config. [docs/notes/gateway-plan.md](docs/notes/gateway-plan.md) describes how the gateway works, and [docs/notes/roadmap.md](docs/notes/roadmap.md) lists what comes next: introspection for opaque tokens, actor tokens, and config loaded from Git and reloaded on merge.

## Crates

- `tsong-config`: the TOML model, its validation and warnings, the host route table, the client-address rules, and the `ConfigStore` trait with the file store.
- `tsong-clock`: the injected `Clock`.
- `tsong-keys`: the `SigningKey` trait, the `KeySet` that rotates keys, and the file provider.
- `tsong-validate`: inbound token validation and JWKS fetching, shared by the issuer and the gateway.
- `tsong-issuer`: the RFC 8693 token endpoint, JWKS and discovery.
- `tsong-gateway`: the reverse proxy and the exchange cache.
- `tsong`: the command.

## Development

`cargo test --workspace` runs the tests. Each crate's own tests cover its code. Line coverage stays above 95%, measured with `cargo llvm-cov`.

`rust-toolchain.toml` installs the stable toolchain with clippy, rustfmt and rust-analyzer. Enable the hooks once per clone. Before each commit they check formatting, lints, docs and tests; before each push, coverage and the dependency audit, as CI does. The push checks need `cargo-llvm-cov` and `cargo-audit`.

```sh
git config core.hooksPath .githooks
```

Tsong runs on Linux, so mutation testing runs on Linux only: in CI on each pull request, or locally in podman with `scripts/linux.sh mutants --workspace`.
