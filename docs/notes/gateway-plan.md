---
title: The gateway exchanges each bearer token once and forwards by host
type: note
summary: The gateway looks up a route by host, exchanges the bearer token through a read-through cache, swaps it in, and streams the request to the route's downstream. A request with no `Authorization` header is passed through without a token.
status: evolving
created: 2026-11-15
---

# The gateway exchanges each bearer token once and forwards by host

The gateway authenticates callers. Downstreams own authorization. A request flows through these steps:

1. Look up the route by the request's host.
2. Check the client IP against the allow lists.
3. Read the bearer token.
4. Get the exchanged token from the cache, exchanging on a miss.
5. Replace the bearer token and stream the request to the route's downstream.

A request with no `Authorization` header skips steps 3 and 4 and is passed through without a token: step 5 streams it with no `Authorization` header, as roadmap item 33 describes. Deciding what an anonymous caller may see is the downstream's job.

The gateway is item 5 of the [roadmap](../../ROADMAP.md), and its exchange cache is item 6.

## Routes

A route maps one host to one downstream. Matching uses the host alone. There is no path matching, so the path and query go to the downstream unchanged.

```toml
[[routes]]
name = "orders"
host = "orders.example.com"
downstream = "https://orders-lb.internal.example.com"
append_audience = "orders.example.com"
allow = ["10.20.0.0/16"]

[routes.audiences]
allow = ["api://orders", "orders.example.com"]

[routes.scopes]
allow = ["orders.read", "orders.write"]
require = ["orders.read"]

[[routes]]
name = "builds"
host = "builds.example.com"
downstream = "https://builds-lb.internal.example.com"
append_audience = ""

[routes.audiences]
deny = ["api://admin"]

[routes.scopes]
require = ["read_api"]
```

- `host` is the key. It is compared lowercased, without its port. Two routes with the same host are a config error.
- `downstream` is an `https` origin with no path, query or fragment. It names the load balancer to forward to, by DNS name. IP addresses are not used, because load balancer addresses change.
- `append_audience` is added to the minted token's `aud`. When it is empty, nothing is added.
- `[routes.audiences]` holds the route's audience policy. Every audience the inbound token carries must be in `allow`. Validation has already refused a token with no audience its trusted issuer accepts. Optional `require` lists audiences it must all carry, and optional `deny` audiences it may not carry. `allow` is optional, and omitted means `"*"`. `"*"` must stand alone in `allow`, and then only `deny` narrows it; `deny` may hold values only under `"*"`. An empty `allow` is refused. Each `require` value must be one `allow` admits and not one `deny` lists. No list may repeat a value, and no value may be empty or hold whitespace.
- `[routes.scopes]` holds the route's scope policy, with the same keys and rules, checked against the inbound `scope` and `scp`. A token with no scopes passes unless `require` names one. A scope narrowed with the token endpoint's `scope` parameter must keep every scope in `require`.
- `signing_algorithm`, optional, is the algorithm the route's minted tokens are signed with: RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384 or EdDSA, ES256 when unset. A key for it must be active in `issuer.signing.keys`.
- `allow` is optional, and adds a second IP check to the gateway-wide `gateway.allow`. A client must be in both lists, so a route can only narrow access. A route without `allow` takes `gateway.allow` alone.
- `read_timeout` is optional, and overrides `gateway.read_timeout`, the longest the gateway waits on a downstream between reads. That defaults to 60 seconds.

`gateway.refused_query_params` and `gateway.refused_headers` list the credentials the gateway refuses in a query or a header, as [request handling](#request-handling) describes. Both are optional, with defaults. An empty `refused_query_params` refuses only `access_token`, which is always refused; an empty `refused_headers` is a load error: leave it unset for the defaults.

An omitted `audiences.allow` or `scopes.allow` means `"*"`, which accepts any value, and then only the same table's `deny` narrows it. An empty one is refused at load. An empty IP list, `gateway.allow` or a route's `allow`, denies every client, and `["0.0.0.0/0", "::/0"]` allows every client. Validation stays mandatory: the config sets values, and no value switches a check off.

`[[routes]]` deserializes as `Vec<Route>`. `RouteTable` in `crates/tsong-config/src/lib.rs` indexes it as a `HashMap<String, Route>` keyed by lowercased host, and the issuer and the gateway each hold one. The audience and scope lists stay `Vec<String>`: they hold a few entries, and scanning a few entries costs less than hashing. A config reload, which roadmap item 32 adds, builds a new table and swaps it in.

## Exchange

The token endpoint stays reachable on its own, so the issuer enforces the route, not the gateway. Before an exchange it applies the same IP allow lists the gateway does, `gateway.allow` and the named route's `allow`, finding the client through the same trusted proxies, and refuses with `access_denied` (403). The gateway asks for an exchange with `audience` set to the request's host. A request parameter sent empty counts as omitted, by RFC 6749 section 3.1. The issuer then:

1. Looks up the route by that host, and fails with `invalid_target` when there is none.
2. Validates the subject token against the global trusted issuers. Every trusted issuer may exchange into every route.
3. Checks the inbound `aud` against `[routes.audiences]`, and the inbound scopes against `[routes.scopes]`. A failure is `invalid_target` for the audience and `invalid_scope` for the scopes.
4. Mints a token whose `aud` is the inbound `aud` followed by `append_audience`, without duplicates.
5. Sets the minted `scope` to the inbound scopes. A `scope` parameter on the request narrows them. It must be scope tokens separated by single spaces, by RFC 6749 section 3.3. A malformed one, asking for a scope the inbound token lacks, or narrowing away one the route requires, is `invalid_scope`.

The gateway calls the issuer through an `Exchanger` trait. The MVP implementation calls the `Issuer` in-process. An HTTP implementation can come later.

## Cache

The cache is read-through. A miss exchanges the token and stores the result, and concurrent misses on the same key share one exchange. It uses `moka`.

- The key is the SHA-256 of the inbound token plus the route host. The cache never holds an inbound token in the clear.
- An entry expires at the minted token's `exp` minus the clock skew. The gateway reads `exp` from the minted token's payload, because the downstream enforces `exp` and `expires_in` drifts with response latency. `expires_in` is the fallback for a token whose payload can't be read. A minted `exp` never exceeds the inbound `exp`, so the inbound lifetime caps the entry too.
- `gateway.cache.max_entries` bounds the entry count.
- A failed exchange is not cached.

## Request handling

- The client IP is the TCP peer, unless the peer is in `gateway.trusted_proxies`. In that case the gateway walks `X-Forwarded-For` from the right and stops at the first address outside `trusted_proxies`. A caller can forge `X-Forwarded-For`, so only trusted proxies are believed.
- The gateway-wide `allow` list applies first, then the route's `allow`.
- The token comes from `Authorization: Bearer`. The scheme name compares without regard to case (RFC 9110 section 11.1).
- A request with no `Authorization` header is anonymous. It is passed through without a token, never exchanged and never cached. `tsong_gateway_requests_total` counts it with `anonymous="true"`. It writes no audit line: the audit log is for exchanges.
- A bearer token must be one or more visible ASCII characters, 0x21 to 0x7E. Whitespace inside it, such as a tab, is malformed. That is wider than RFC 6750's `b64token`, because opaque tokens use characters such as `:`, `%` and `,`.
- A request whose query has an `access_token` parameter (RFC 6750 section 2.3), or one named in `gateway.refused_query_params`, is refused with a 401, whatever its `Authorization` header, so a token in the URL never reaches a downstream. `access_token` is always refused, whatever the config says; the list adds to it, and listing it there is harmless. Unset, the list is `private_token`, `job_token` and `api_key`. Rather than follow each framework's parser, each name, in the query and in the list, is normalized generously: pairs split on `&` or `;`, the name percent-decoded with `+` as a space and IIS's `%uXXXX` escapes read as UTF-8, repeated while a `%` remains, up to three passes, so `%255F` decodes too, cut at the first NUL or `[`, whichever comes first, case-folded (a character that Java, JavaScript or .NET upper- or lowercases to ASCII letters reads as them, such as `ſ` as `s`, the dotless `ı` and `İ` as `i`, the Kelvin sign as `k`, `ß` as `ss` and the ligature `ﬁ` as `fi`, and fullwidth forms read as their ASCII letters), and stripped of everything but ASCII letters and digits. A query name counts when it, with or without the cut, equals a normalized entry, such as `accesstoken`, so `ACCESS_TOKEN`, `access.token`, `access-token`, ` access_token` and `access_token[]` all count, while `access_tokens` and `my_access_token` don't. Only names are read, never values, so `access_token=` hidden in another parameter's encoded value isn't a credential. A name isn't split again after decoding, so an encoded `=` or `&` inside it, as in `access_token%3Dx=1`, stays part of the name. An entry that normalizes to nothing is a load error. This changes the bearer path too: a bearer request whose URL carries `access_token` used to be forwarded and is now refused.
- A request carrying a header named in `gateway.refused_headers` is refused with a 401 and a bare `Bearer` challenge, whatever its `Authorization` header. Unset, the list is GitLab's `PRIVATE-TOKEN` and `JOB-TOKEN`, and `X-API-Key`. Header names are compared normalized, as query names are: case-folded and stripped to ASCII letters and digits, since CGI, PHP, Django and nginx with `underscores_in_headers` read `X_API_Key` as `X-API-Key`. The refusal names the header as the config spells it. Each entry must be a header name with a letter or digit, and the headers the gateway reads, sets or strips itself aren't allowed in any spelling that normalizes to theirs: `Authorization`, `Proxy-Authorization`, `Host`, `X-Request-Id`, `traceparent`, `tracestate`, `Forwarded` and `X-Forwarded-*`. Bodies and cookies are not inspected: a downstream must not accept a token from either.
- A bearer token that fails is refused, never downgraded to anonymous. Any other scheme, such as `Basic`, `Digest`, `NTLM`, `Negotiate` or `DPoP`, is refused, so no `Authorization` credential Tsong hasn't vouched for reaches a downstream.
- The `Authorization` header is replaced with the minted token. The inbound token is never forwarded.
- Hop-by-hop headers are stripped, as RFC 9110 section 7.6.1 requires of an intermediary. They, and the headers the gateway replaces, are matched by normalized name, so a spelling such as `X_Forwarded_For` or `Proxy_Authorization`, which some frameworks read as the dashed name, is stripped too.
- The gateway sends `X-Forwarded-*`, which load balancers and downstream frameworks read by default. It strips any inbound `Forwarded` header (RFC 7239), so a downstream never trusts a value the gateway didn't check.
- `Host` is set to the downstream's host. `X-Forwarded-Host` carries the original host. `X-Forwarded-For` and `X-Forwarded-Proto` are set. A trusted proxy's `X-Forwarded-For` chain, `X-Forwarded-Proto` and `X-Forwarded-Host` are kept; anyone else's are replaced.
- Hops left of the client in `X-Forwarded-For` are never read, so an unparsable entry there doesn't fail the request.
- Request and response bodies stream through a `reqwest` client. A request body known to be empty is not sent. The client follows no redirects and uses no proxy.

The gateway fails closed:

| Condition | Status |
| --- | --- |
| No route for the host | 404 |
| A trusted proxy's `X-Forwarded-For` hop is not an IP address | 400 |
| Client IP not allowed | 403 |
| A refused query parameter, such as `access_token` | 401 with `WWW-Authenticate: Bearer` |
| A refused header, such as `PRIVATE-TOKEN` | 401 with `WWW-Authenticate: Bearer` |
| More than one `Authorization` header | 401 with `WWW-Authenticate: Bearer` |
| Malformed `Authorization`: empty, or `Bearer` without exactly one token of visible ASCII | 401 with `WWW-Authenticate: Bearer` |
| A scheme other than `Bearer` | 401 with `WWW-Authenticate: Bearer` |
| Inbound token invalid | 401 with `WWW-Authenticate: Bearer error="invalid_token"` |
| Audience or scope not allowed for the route | 403 |
| Issuer or inbound JWKS unavailable | 503, without the cause |
| Exchange failed inside the issuer, such as signing | 500, without the cause |
| Downstream unreachable | 502 |
| Downstream silent past its read timeout | 504 |

A scheme other than `Bearer` gets a 401 with a bare `Bearer` challenge, the one Tsong accepts, as RFC 9110 section 11.6.1 requires of a 401. It carries no error code: RFC 6750 section 3.1 says a request that used an unsupported authentication method should get none, and its `invalid_request` would call for a 400. The body names the reason.

## Config lint

`tsong check <config.toml>` lints the config for CI.

- Errors exit 1. They are everything validation rejects, such as a repeated host or a `downstream` that is not an `https` origin.
- Warnings print and exit 0, unless `--deny-warnings` is set, which makes them exit 1.
- An empty IP `allow` list warns that every client will be denied, which looks like an omission.
- `0.0.0.0/0` or `::/0` in an IP `allow` list warns that every address is allowed, which needs confirming.
- An audience policy that admits no audience a trusted issuer validating JWTs accepts warns that every token will be refused.
- A `jwks_max_age` over a day warns that a withdrawn key stays trusted that long.

An empty `audiences.allow` or `scopes.allow` is an error, not a warning; omit `allow` to admit any value, or remove the route to refuse every token. Each message names the route and the field, such as `warning: route "builds": allow is empty; every client will be denied`.

## Serve

`tsong serve` runs the gateway on `gateway.listen` and the issuer on `issuer.listen`, sharing one `Issuer`, one config and one shutdown signal.

## Tests

The gateway tests run an in-process fake downstream that echoes the request it receives. Most use a fake `Exchanger` that answers by token. One runs the real `Issuer` against the in-process fake inbound issuer. Like all tsong code, the tests never panic.

## Deferred

- Downstream TLS name verification when the downstream's DNS name differs from the certificate's name.
- Per-route audience and scope policy for the minted token. The MVP only filters the inbound token.
- Route files split across many files, so that one config file doesn't grow unbounded.
- An HTTP `Exchanger` for a gateway that runs apart from the issuer.
- WebSocket and other `Upgrade` requests.
- Reading and sending the RFC 7239 `Forwarded` header.
