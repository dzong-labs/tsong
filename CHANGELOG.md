# Changelog

Each release lists what changed for people who run Tsong or write its config. Security fixes are listed first in their release, with the advisory and CVE. Tsong follows [Semantic Versioning](https://semver.org); before 1.0, a minor release can break the config or the API.

## Unreleased

## 0.1.0

The first release.

### Added

- The API gateway: routes by host to an https downstream, streams bodies, strips hop-by-hop and `Forwarded` headers, and sets `X-Forwarded-*`.
- The RFC 8693 token exchange issuer, with its JWKS and OIDC discovery document.
- The exchange cache: one exchange per token and route host while cached, shared by concurrent requests.
- Inbound validation against each trusted issuer's JWKS, with keys that expire after `jwks_max_age` and renew in the background.
- Route policy: `allowed_audiences`, `allowed_scopes` and `required_scopes`.
- Issuer-qualified subjects and the RFC 9493 `sub_id` claim.
- Per-route signing algorithms: ES256 by default; RS256/384/512, PS256/384/512, ES384 and EdDSA on request.
- IP allow lists, global and per route, with trusted proxies.
- Config from a file or from a folder on a Git branch, reloaded by a signed webhook or a poll, with the last good config kept serving.
- Secret references, `{ env = "NAME" }` and `{ file = "path" }`, for every secret field.
- Observability: liveness and readiness, Prometheus metrics, a JSON audit line per exchange and reload, and request correlation by `X-Request-Id` and `traceparent`.
- A readiness drain on SIGTERM, and a container image that runs as an unprivileged user.
- The `tsong check` and `tsong serve` commands.
