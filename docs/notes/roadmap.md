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
5. Gateway: the reverse proxy, planned in [[gateway-plan]]. Look up the route by host, enforce the IP allow lists, exchange the bearer token, replace the `Authorization` header and stream the request to the route's downstream. Fail closed and never forward the original token. (done)
6. Exchange cache: a read-through cache keyed on a hash of the inbound token plus the route host, expiring at the minted token's `exp` minus the clock skew, bounded by `gateway.cache.max_entries`. Planned in [[gateway-plan]] and built with item 5. (done)
7. Config from Git: a bootstrap file names the config source; `GitStore` fetches the branch over SSH and reloads on a webhook or a poll, swapping in fully validated state and keeping the last good config when a new one fails. Planned in [[config-from-git]] (done).
8. Cloud signing keys: AWS KMS and HSM providers behind the `SigningKey` trait (`crates/tsong-keys/src/lib.rs`), alongside the file provider, which sign without the private key leaving them. The config refers to a key by a pointer, such as an ARN, never by its contents.
9. Observability: liveness and readiness on their own listener, Prometheus metrics, one audit line per token exchange, and request correlation by `X-Request-Id` and `traceparent`. Planned in [[observability]] (done).
10. Hooks: pre-exchange and post-exchange plugins, sandboxed in WebAssembly.
11. Rauthy integration test: exchange a token from a real issuer, Rauthy in podman, in addition to the in-process fake issuer the tests use now.
12. Issuer behind a path: the router serves `/token`, `/jwks.json` and `/.well-known/openid-configuration` at the root. For an `issuer.url` with a path, such as `https://example.com/tsong`, the discovery document names endpoints under that path. The router doesn't serve them there yet.
13. Downstream TLS names: verify a downstream's certificate when its DNS name differs from the name the certificate covers.
14. Minted-token policy per route: audiences and scopes the minted token carries, beyond the filters on the inbound token.
15. Split route files: load routes from many files in the config folder, so one config file doesn't grow unbounded.
16. Remote exchanger: an HTTP `Exchanger` for a gateway that runs apart from the issuer.
17. Upgraded connections: WebSocket and other `Upgrade` requests through the gateway, which strips hop-by-hop headers until then.
18. `Forwarded`: read and send the RFC 7239 `Forwarded` header alongside `X-Forwarded-*`. Until then the gateway strips it.
19. Git over HTTPS: fetch the config with a token, as an alternative to the SSH deploy key. Until then only ssh urls and local paths are accepted.
20. Git host file API: a `ConfigStore` that reads the config through a Git host's API instead of a clone, chosen in the bootstrap file.
21. Signed commits: refuse a config whose commit isn't signed by a trusted key.
22. Tracing export: record the gateway's and the issuer's spans and export them through OpenTelemetry. Until then trace context is propagated but no spans are recorded.
23. Subject identity: each trusted issuer has a required, unique `sub_prefix`, and the minted `sub` is `<sub_prefix>:<sub>`. The subject token's own `iss` and `sub` go in an RFC 9493 `sub_id` claim (`iss_sub` format), always present and reserved from claim mapping. A token with an empty `sub`, or without the claim a rename makes its subject, is refused. A subject token that fails validation gets `invalid_request`, as RFC 8693 section 2.2.2 requires (done).
24. Issuer key expiry: each trusted issuer's keys expire after `jwks_max_age`, and a background refresher renews them three quarters of the way through, retrying a failure every `jwks_retry`. Keys that expire before a renewal succeeds refuse the issuer's tokens with a 503, with an audit line for each failure and for the recovery. A token with an unknown key ID, or whose signature fails with a known key, refetches once, no more often than `jwks_refetch`. `discovery_url` and `jwks_url` are set per issuer, and `jwks_timeout` bounds each fetch (done).
25. Config staleness: `tsong_config_last_fetch_timestamp_seconds` and `fetched_at` in `/status` report when the config store was last read, `tsong_config_revision_info` reports the revision each replica serves, and `tsong_config_tip_rejected` flags a branch tip that won't load, so a Git outage, a stuck replica or replicas that haven't converged can be alerted on. The last good config keeps serving through an outage (done).
26. Container: `tsong serve` stops on SIGTERM, failing readiness for `health.drain` before the listeners close. A `Containerfile` builds a non-root Debian slim image that runs with a read-only root filesystem, and `deploy/podman/run.sh` runs it in local podman with stub files. Building and publishing the image in CI comes later (done).
27. Required scopes: a route's optional `required_scopes` must all be present in the inbound token, and a token minted for the route keeps them all. Each must be one `allowed_scopes` accepts. Scope names pass through unchanged (done).
28. Signing algorithms: each route's `signing_algorithm` picks how its tokens are signed, from the nine asymmetric algorithms inbound validation accepts, ES256 by default. Each signing key names its algorithm, one key per algorithm is active, and every algorithm a route uses needs an active key. Keys are PKCS#8 PEM, signed through `aws-lc-rs`, and a key of the wrong type, or an RSA key under 2048 bits, is refused (done).
29. Secret references: a secret field holds `<scheme>:<id>`, never the secret, and the `SecretSource` for the scheme reads it (`crates/tsong-secrets/src/lib.rs`). `env:` and `file:` are built (done). Next, `aws-sm:<arn>` for AWS Secrets Manager, then other secret stores as they are needed. The introspection `client_secret` is parsed and required, but read only once introspection (item 3) uses it.
