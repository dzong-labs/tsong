# Tsong

Tsong is a reverse-proxy API gateway that exchanges tokens. A request arrives with a token from one of the organization's trusted issuers. Tsong validates it, exchanges it for a token it signs itself for the route's downstream service, caches the exchange for the inbound token's lifetime, and forwards the request with the new token.

It has two parts:

- The gateway: routes, inbound validation, the exchange cache and header rewriting.
- The issuer: an RFC 8693 token exchange endpoint, with JWKS and OIDC discovery so downstream services can validate the tokens it signs.

Configuration lives in Git and reloads on merge to main.

## Status

`tsong serve <config.toml>` runs the gateway and the issuer. The gateway looks up each request's route by host, checks the client against the IP allow lists, exchanges the bearer token through a read-through cache, and streams the request to the route's downstream with the exchanged token. The issuer serves the RFC 8693 token endpoint, the JWKS and the discovery document, and mints ES256 tokens. `tsong check [--deny-warnings] <config.toml>` validates a config, loads its keys and reports its warnings. [docs/notes/gateway-plan.md](docs/notes/gateway-plan.md) describes the gateway, and [docs/notes/roadmap.md](docs/notes/roadmap.md) lists what comes next. [examples/tsong.toml](examples/tsong.toml) is a sample config.

In Tsong's terms the upstream is the caller and the downstream is the service a route forwards to.

## Crates

- `tsong-config`: the TOML model, its validation, and the `ConfigStore` trait with the file store.
- `tsong-clock`: the injected `Clock`.
- `tsong-keys`: the `SigningKey` trait, the `KeySet` that rotates keys, and the file provider.
- `tsong-validate`: inbound token validation and JWKS fetching, shared by the issuer and the gateway.
- `tsong-issuer`: the RFC 8693 token endpoint, JWKS and discovery.
- `tsong-gateway`: the reverse proxy.
- `tsong`: the command.

## Development

`cargo test --workspace` runs the tests. Each crate's own tests cover its code. Line coverage stays above 95%, measured with `cargo llvm-cov`.

`rust-toolchain.toml` installs the stable toolchain with clippy, rustfmt and rust-analyzer. Enable the hooks once per clone. Before each commit they check formatting, lints, docs and tests; before each push, coverage and the dependency audit, as CI does. The push checks need `cargo-llvm-cov` and `cargo-audit`.

```sh
git config core.hooksPath .githooks
```

Tsong runs on Linux, so mutation testing runs on Linux only: in CI on each pull request, or locally in podman with `scripts/linux.sh mutants --workspace`.
