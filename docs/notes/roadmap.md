---
title: Roadmap
type: note
summary: What Tsong has built and what comes next, in order.
status: evolving
created: 2026-11-15
---

# Roadmap

Done means built, tested above the 95% line-coverage floor, and merged. Until something is merged it stays on the list.

1. Skeleton: the config model and its validation, the `SigningKey` trait with the file provider, and `tsong check` (done).
2. Issuer: the RFC 8693 token endpoint, JWT validation of subject tokens against each trusted issuer's JWKS, minting, the JWKS and the discovery document, and `tsong serve` (done).
3. Introspection: validate opaque tokens, such as GitLab personal access tokens, by posting them to the issuer's RFC 7662 introspection endpoint. Until then, opaque tokens fail with "introspection is not supported yet" (`ValidateError::Unsupported` in `crates/tsong-validate/src/lib.rs`). So do JWTs from an issuer configured for introspection.
4. Actor tokens: accept `actor_token` and `actor_token_type` on the token endpoint and record the actor in the minted token's `act` claim. A token gets an `act` claim only when an actor token is sent. Until then, either parameter fails with `invalid_request`.
5. Gateway: the reverse proxy. Match routes by host and path prefix, enforce the IP allow-list, and believe `X-Forwarded-For` hops only from trusted proxies. Exchange the inbound token through the issuer, replace the `Authorization` header, and strip the inbound token and hop-by-hop headers. Fail closed with 401 or 503 and never forward the original token.
6. Exchange cache: key each entry on a hash of the inbound token plus the target audience. Expire it at the earlier of the inbound token's `exp` and the minted token's `exp`, minus the clock skew. Bound its memory with `gateway.cache.max_entries`.
7. Config from Git: a `ConfigStore` (`crates/tsong-config/src/store.rs`) that watches `main` and reloads on merge, triggered by a webhook. Validate a new config fully, swap it in atomically, and keep the last good config when a merged one is invalid. Optionally require signed commits.
8. Cloud signing keys: AWS KMS, Azure Key Vault and HSM providers behind the `SigningKey` trait (`crates/tsong-keys/src/lib.rs`), which signs without exposing private keys.
9. Observability: an audit log of every exchange that records the issuer and the outcome but never token contents, plus metrics, tracing, and health and readiness endpoints.
10. Hooks: pre-exchange and post-exchange plugins, sandboxed in WebAssembly.
11. Rauthy integration test: exchange a token from a real issuer, Rauthy in podman, in addition to the in-process fake issuer the tests use now.
12. Issuer behind a path: the router serves `/token`, `/jwks.json` and `/.well-known/openid-configuration` at the root. For an `issuer.url` with a path, such as `https://example.com/tsong`, the discovery document names endpoints under that path. The router doesn't serve them there yet.
