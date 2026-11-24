# Tsong hub design

A design draft for the Tsong hub: a read-only console for watching the gateway, its routes and its token exchanges. These files are the source of the Tsong Metro design canvas, kept here so the design is versioned with the code. They render only on that canvas: they load its `support.js` and fonts uploaded to it.

## Pages

The hub is one horizontal strip of panes, in the Metro style:

1. start: headline numbers, alerts, status, the latest events, and what's worth a look.
2. alerts: open, reviewed and all.
3. watch: the audit stream, with a time range and a filter.
4. routes: the busiest routes, a sort and a filter. A route opens its own page.
5. trust: one pivot entry per trusted issuer.
6. keys: Tsong's signing keys, the JWKS and the discovery document.
7. explain: walk a token through every check for a route.
8. callers: who exchanges tokens, and flagged patterns.
9. config: the revision each replica serves, and the revision history.
10. status: objectives and signals.
11. help: config reference, troubleshooting and a glossary.

| File | What it is |
|---|---|
| `Monitor.dc.html` | the strip, all 11 panes |
| `MonitorSelawik.dc.html`, `MonitorOpenSans.dc.html` | the strip in the fallback typefaces |
| `MonitorPanorama.dc.html` | a window sliding over the strip, as the hub will show it |
| `Route.dc.html` | a route page, `orders.test` |
| `SignIn.dc.html` | sign-in through the organization's identity provider |
| `canvas.json` | the canvas layout |

## Design language

- Metro: type and space carry the structure. No borders, rules or dividers.
- Type: Segoe UI, then Selawik and Open Sans as fallbacks; Cascadia Mono for identifiers, tokens and config. Sizes 14, 16, 21, 29, 40 and 87 px (10, 12, 16, 22, 30 and 65 pt), weights 300, 400 and 600.
- Colour: text `#D4D4D4`, secondary text `#9D9D9D`, surface `#1E1E1E`; alternate rows `#282828`. Serious is red with a shield icon, warning is yellow with a triangle; neither is shown by colour alone.
- Pivots switch views within a pane. The title and pivot stay put; the content below scrolls.
- Text fields are a slightly darker fill with no border.
- Dialogs: buttons at the bottom right, cancel to the left of the main action.
- Filters across the hub use one small query language: fields compared with `=` and `!=`, `*` as a wildcard, joined with `and`, `or` and `not`.

The example data is invented. Hosts end in `.test`, and anything specific to an organization is a placeholder in brackets.
