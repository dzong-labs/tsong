# Contributing

Thanks for helping with Tsong. This file says how to report a problem, propose a change, and what a pull request needs before it merges. Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

## Reporting a bug or asking for a feature

Open a [GitHub issue](https://github.com/dzong-labs/tsong/issues). For a bug, give the version or commit, the config with secrets removed, what you expected and what happened.

A question about using Tsong, or an idea that isn't a concrete request yet, goes to [GitHub Discussions](https://github.com/dzong-labs/tsong/discussions). Issues are for bugs and for work that is agreed or ready to agree on.

A security flaw goes through [SECURITY.md](SECURITY.md) instead, never a public issue.

## Proposing a change

For anything larger than a small fix, open an issue first so we can agree on the design before you write the code.

Then send a pull request against `main`. Each pull request is squashed into one commit, so its title becomes the commit message. Write it in the imperative and say what changes, as the existing history does: "Expire trusted issuers' keys and renew them on a schedule".

## What a pull request needs

CI's `passed` check must succeed. It runs these, and the hooks run most of them locally:

- Formatting: `cargo fmt --all --check`.
- Lints: `cargo clippy --workspace --all-targets --all-features` with warnings denied. The workspace forbids `unsafe` and denies `unwrap`, `expect`, `panic!`, indexing and their kin, tests included: failures are values, and tests return `Result` and propagate with `?`. Every crate must inherit the workspace lints.
- Docs: `cargo doc --workspace --no-deps` with warnings denied.
- Tests: `cargo test --workspace`, in the dev and release profiles.
- Coverage: line coverage stays at or above 95%, measured with `cargo llvm-cov`.
- Mutation testing: no mutant of a line the pull request changes survives `cargo mutants`.
- Dependency audit: `cargo audit --deny warnings`, and again with `--file fuzz/Cargo.lock`, since the fuzz crate keeps its own lockfile.
- Dependency graph: `cargo deny --locked check bans licenses sources`, under the rules in `deny.toml`.
- Fuzzing: every target under `fuzz/` for 20 seconds, with `scripts/fuzz.sh`.
- CodeQL, for Rust and for the workflows.
- Sign-off: every commit is signed off by its author, as [License](#license) describes. The `DCO` check verifies it on every pull request; only Dependabot's own commits, on pull requests it opened, are exempt.

Enable the hooks once per clone:

```sh
git config core.hooksPath .githooks
```

The prepare-commit-msg hook signs off each commit. The pre-push hook needs `cargo-llvm-cov`, `cargo-audit` and `cargo-deny`. Mutation testing runs on Linux only: `scripts/linux.sh mutants --workspace` runs it locally in podman.

## Tests

Tests come with the change, written first where you can. New behaviour gets tests of that behaviour, and a bug fix gets a test that fails without the fix. Each crate's own tests cover its own code, because each mutant runs only its crate's tests. A pull request that adds functionality without tests won't merge.

## Code

- No `unsafe`.
- Wall-clock time, such as token expiry and key age, comes from the injected `Clock`, never `SystemTime`, so tests can control it.
- Secrets are references, read through `SecretSource`. Never commit a key, a token or a client secret, even a test one: tests generate their keys.
- Cryptography goes through the existing libraries (`aws-lc-rs`, `jsonwebtoken`, `p256`). Don't implement a primitive.
- A new dependency needs a reason in the pull request. Prefer well-maintained crates with few dependencies of their own.
- A change a user can see updates the [README](README.md). Its pull request title becomes its line in the release notes on [GitHub Releases](https://github.com/dzong-labs/tsong/releases), so write the title for a user. [CHANGELOG.md](CHANGELOG.md) holds the notes for 0.1.0 only.

## License

Tsong is licensed under [Apache-2.0](LICENSE). By sending a pull request you agree that your contribution is licensed under the same terms, as section 5 of the license says.

Each commit must be signed off under the [Developer Certificate of Origin](https://developercertificate.org): a `Signed-off-by` line with your name and email certifies that you have the right to submit the change under the project's license. `git commit -s` adds the line, and so does the prepare-commit-msg hook in `.githooks`. A commit without it fails the `DCO` check.
