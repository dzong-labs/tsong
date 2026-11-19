# Security

Tsong validates and issues access tokens, so a flaw in it can let a caller reach a service it shouldn't. Please report one privately.

## Reporting a vulnerability

Report it through GitHub's private vulnerability reporting: [Report a vulnerability](https://github.com/marklauter/tsong/security/advisories/new). Only the maintainers see the report.

Don't open a public issue, pull request or discussion for a vulnerability.

A useful report says:

- what an attacker can do, such as get a token for a route, a scope or an audience it shouldn't have, or reach a downstream it shouldn't;
- the version or commit, and the config that shows the flaw, with secrets removed;
- the steps or a test that reproduces it.

## What happens next

- An answer within 14 days, saying whether we confirm the flaw.
- For a confirmed critical flaw, a fix released within 7 days of confirming it. It comes before all other work.
- For a confirmed flaw rated medium or higher, a fix released within 60 days of the report, usually much sooner.
- A GitHub security advisory and a CVE for each confirmed flaw, published with the fix. The release notes name it: on [GitHub Releases](https://github.com/marklauter/tsong/releases), and in [CHANGELOG.md](CHANGELOG.md) for 0.1.0.
- Credit in the advisory, unless you'd rather not be named.

Please give us until the fix is released before you disclose the flaw publicly.

## Supported versions

Tsong is before 1.0. Only the latest release gets security fixes.

## Scope

In scope: the `tsong` binary and the crates in this repository, the container image built from the [Containerfile](Containerfile), and the sample configs in [examples](examples) and [deploy](deploy) where they would mislead someone who copies them.

Out of scope: flaws in a trusted issuer, in a downstream service, or in a dependency that Tsong uses as documented. Report those to their own projects. Tell us too if Tsong needs a change because of one.
