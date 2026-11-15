# Tsong

Tsong is a reverse-proxy API gateway that exchanges tokens. A request arrives with a token from one of the organization's trusted issuers. Tsong validates it, exchanges it for a token it signs itself for the route's upstream, caches the exchange for the inbound token's lifetime, and forwards the request with the new token.

It has two parts:

- The gateway: routes, inbound validation, the exchange cache and header rewriting.
- The issuer: an RFC 8693 token exchange endpoint, with JWKS and OIDC discovery so upstreams can validate the tokens it signs.

Configuration lives in Git and reloads on merge to main.

## Status

A skeleton. The config loads and validates, and the file signing-key provider signs ES256 and publishes its JWK. `tsong check <config.toml>` checks a config and loads its keys. The issuer and the gateway come next. [examples/tsong.toml](examples/tsong.toml) is a sample config.

## Crates

- `tsong-config`: the TOML model and its validation.
- `tsong-keys`: the `SigningKey` trait, the `KeySet` that rotates keys, and the file provider.
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
