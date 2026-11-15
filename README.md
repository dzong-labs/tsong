# Tsong

Tsong is a reverse-proxy API gateway that exchanges tokens. A request arrives with a token from one of the organization's trusted issuers. Tsong validates it, exchanges it for a token it signs itself for the route's upstream, caches the exchange for the inbound token's lifetime, and forwards the request with the new token.

It has two parts:

- The gateway: routes, inbound validation, the exchange cache and header rewriting.
- The issuer: an RFC 8693 token exchange endpoint, with JWKS and OIDC discovery so upstreams can validate the tokens it signs.

Configuration lives in Git and reloads on merge to main.
