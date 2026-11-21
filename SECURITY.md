# Security

Tsong validates and issues access tokens, so a flaw in it can let a caller reach a service it shouldn't. Please report one privately.

## Reporting a vulnerability

Report it through GitHub's private vulnerability reporting: [Report a vulnerability](https://github.com/dzong-labs/tsong/security/advisories/new). Only the maintainers see the report.

Don't open a public issue, pull request or discussion for a vulnerability.

A useful report says:

- what an attacker can do, such as get a token for a route, a scope or an audience it shouldn't have, or reach a downstream it shouldn't;
- the version or commit, and the config that shows the flaw, with secrets removed;
- the steps or a test that reproduces it.

## What happens next

- An answer within 14 days, saying whether we confirm the flaw.
- For a confirmed critical flaw, a fix released within 7 days of confirming it. It comes before all other work.
- For a confirmed flaw rated medium or higher, a fix released within 60 days of the report, usually much sooner.
- A GitHub security advisory and a CVE for each confirmed flaw, published with the fix. The release notes name it: on [GitHub Releases](https://github.com/dzong-labs/tsong/releases), and in [CHANGELOG.md](CHANGELOG.md) for 0.1.0.
- Credit in the advisory, unless you'd rather not be named.

Please give us until the fix is released before you disclose the flaw publicly.

## Verifying a release

From 0.2.0, each release is built and signed by the [release workflow](.github/workflows/release.yml), never on a developer's machine. The binary on the [GitHub release](https://github.com/dzong-labs/tsong/releases) and the container image at `ghcr.io/dzong-labs/tsong` each carry a GitHub artifact attestation: a Sigstore signature, made with a short-lived certificate for that workflow, binding the file to the commit and workflow run that built it. There is no long-lived signing key to obtain or trust; the signature is checked against GitHub's public Sigstore trust root.

With the [GitHub CLI](https://cli.github.com):

```sh
gh attestation verify tsong-x86_64-linux --repo dzong-labs/tsong   --signer-workflow dzong-labs/tsong/.github/workflows/release.yml
gh attestation verify SHA256SUMS --repo dzong-labs/tsong   --signer-workflow dzong-labs/tsong/.github/workflows/release.yml
gh attestation verify oci://ghcr.io/dzong-labs/tsong:<tag> --repo dzong-labs/tsong   --signer-workflow dzong-labs/tsong/.github/workflows/release.yml
sha256sum -c SHA256SUMS
```

Each release also carries the signed provenance itself, `tsong.intoto.jsonl`, so the binary can be verified without asking GitHub for the attestation:

```sh
gh attestation verify tsong-x86_64-linux --bundle tsong.intoto.jsonl   --repo dzong-labs/tsong --signer-workflow dzong-labs/tsong/.github/workflows/release.yml
```

Release 0.2.0 was published before the repository moved from `marklauter/tsong` to `dzong-labs/tsong`. Its image is `ghcr.io/marklauter/tsong`, and its attestations name `marklauter/tsong`, so verify it with `marklauter/tsong` in place of `dzong-labs/tsong`. Its binary, `tsong-x86_64-linux`, has the SHA-256 digest `34fcbcec604d13a719d46fca5a1914c2541d5802bada6e59cf93b27954823133`, which doesn't depend on either name.

Each fails unless the file was built and signed by this repository's release workflow, from a tagged commit on `main`. A version is signed once: the workflow refuses to change a published release or to move an existing image tag. The release binary is reproducible: `scripts/reproducible.sh` rebuilds it bit for bit from the tagged commit.

## Supported versions

Tsong is before 1.0. Only the latest release gets security fixes.

## Scope

In scope: the `tsong` binary and the crates in this repository, the container image built from the [Containerfile](Containerfile), and the sample configs in [examples](examples) and [deploy](deploy) where they would mislead someone who copies them.

Out of scope: flaws in a trusted issuer, in a downstream service, or in a dependency that Tsong uses as documented. Report those to their own projects. Tell us too if Tsong needs a change because of one.
