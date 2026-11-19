---
title: A release is a signed tag on main, built and signed by the release workflow
type: note
summary: The maintainer pushes a signed version tag on a main commit; the release workflow builds the binary and the image from a clean tree, signs each with a keyless GitHub artifact attestation, and puts them on a draft release that the maintainer reviews and publishes. A version is signed once and never changed.
status: evolving
created: 2026-11-19
---

# A release is a signed tag on main, built and signed by the release workflow

No release is built on a developer's machine. The maintainer tags a commit on `main`, and `.github/workflows/release.yml` builds, signs and publishes it. A tag ruleset, "release tags", lets only repository admins create, move or delete a `v*` tag, so no other account, token or app can start a release. [GOVERNANCE.md](../../GOVERNANCE.md) assigns the job to the maintainer, and [SECURITY.md](../../SECURITY.md#verifying-a-release) tells users how to verify what ships.

## Cutting a release

1. Pull `main` and tag the commit to release with a signed, annotated tag, then push the tag:

   ```sh
   git switch main && git pull
   git tag -s v0.2.0 -m "Tsong 0.2.0"
   git push origin v0.2.0
   ```

2. The release workflow runs on the tag. When it finishes, a draft release holds the binary and its `SHA256SUMS`, with notes GitHub generated from the merged pull requests.
3. Edit the draft's notes for people who run Tsong: what changed, and how to move an existing config across any breaking change. Then publish it.

Tsong follows [Semantic Versioning](https://semver.org). Before 1.0, a change that breaks the config or the API bumps the minor version, `0.1.0` to `0.2.0`; anything else bumps the patch version.

## What the workflow does

Two jobs run on the tag, each with only the permissions it needs.

The `binary` job:

1. Refuses the tag unless its commit is on `main`.
2. Builds the release binary with `scripts/release-build.sh`: locked dependencies, paths remapped, no build cache. It is the same build that `scripts/reproducible.sh` checks weekly, so anyone can rebuild the tagged commit and get the same bytes.
3. Names the binary `tsong-x86_64-linux` and writes `SHA256SUMS`.
4. Signs both with a GitHub artifact attestation.
5. Creates a draft release with both files, or adds them to a draft that already exists. It refuses a release that is already published.

The `image` job:

1. Refuses the tag unless its commit is on `main`, and refuses an image tag that already exists in the registry.
2. Builds the `Containerfile` and pushes `ghcr.io/marklauter/tsong:<tag>`.
3. Signs the image's digest with a GitHub artifact attestation, stored beside the image in the registry.

## How signing works

An artifact attestation is a Sigstore signature over a provenance statement: which repository, workflow, commit and run built the file. The workflow gets a short-lived certificate for its own identity from GitHub's Sigstore instance, signs with it, and discards it. No long-lived signing key exists, so there is none to store, rotate, leak or hand to a successor.

A user checks a file with `gh attestation verify`, pinned to this repository and the release workflow, as SECURITY.md shows. The check fails unless the file was built and signed by `release.yml` in `marklauter/tsong`.

The tag is signed separately, by the maintainer's own key, so `git tag -v` and GitHub's "Verified" badge show who cut the release. That key signs only the tag, never the artifacts.

## One-time setup

- A signing key for tags. With SSH: `git config --global gpg.format ssh` and `git config --global user.signingkey ~/.ssh/id_ed25519.pub`, and the public key added to GitHub as a signing key.
- After the first release, make the `tsong` package on GHCR public. GHCR creates a new package private.

## If a run fails

Nothing the workflow publishes is ever overwritten. Fix the cause, and either re-run the failed job or delete the draft release and the tag, then tag again. A published release, or an image tag already in the registry, stays as it is; a fix ships as a new version.
