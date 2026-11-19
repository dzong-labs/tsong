# Contributing

Thanks for helping with Tsong. This file says how to report a problem, propose a change, and what a pull request needs before it merges.

## Reporting a bug or asking for a feature

Open a [GitHub issue](https://github.com/marklauter/tsong/issues). For a bug, give the version or commit, the config with secrets removed, what you expected and what happened.

A security flaw goes through [SECURITY.md](SECURITY.md) instead, never a public issue.

## Proposing a change

For anything larger than a small fix, open an issue first so we can agree on the design before you write the code.

Then send a pull request against `main`. Each pull request is squashed into one commit, so its title becomes the commit message. Write it in the imperative and say what changes, as the existing history does: "Expire trusted issuers' keys and renew them on a schedule".

## What a pull request needs

CI's `passed` check must succeed. It runs these, and the hooks run most of them locally:

- Formatting: `cargo fmt --all --check`.
- Lints: `cargo clippy --workspace --all-targets --all-features` with warnings denied. The workspace denies `unwrap`, `expect`, `panic!`, indexing and their kin, tests included: failures are values, and tests return `Result` and propagate with `?`.
- Docs: `cargo doc --workspace --no-deps` with warnings denied.
- Tests: `cargo test --workspace`, in the dev and release profiles.
- Coverage: line coverage stays at or above 95%, measured with `cargo llvm-cov`.
- Mutation testing: no mutant of a line the pull request changes survives `cargo mutants`.
- Dependency audit: `cargo audit --deny warnings`.
- CodeQL, for Rust and for the workflows.

Enable the hooks once per clone:

```sh
git config core.hooksPath .githooks
```

The pre-push hook needs `cargo-llvm-cov` and `cargo-audit`. Mutation testing runs on Linux only: `scripts/linux.sh mutants --workspace` runs it locally in podman.

## Tests

Tests come with the change, written first where you can. New behaviour gets tests of that behaviour, and a bug fix gets a test that fails without the fix. Each crate's own tests cover its own code, because each mutant runs only its crate's tests. A pull request that adds functionality without tests won't merge.

## Code

- No `unsafe`.
- Wall-clock time, such as token expiry and key age, comes from the injected `Clock`, never `SystemTime`, so tests can control it.
- Secrets are references, read through `SecretSource`. Never commit a key, a token or a client secret, even a test one: tests generate their keys.
- Cryptography goes through the existing libraries (`aws-lc-rs`, `jsonwebtoken`, `p256`). Don't implement a primitive.
- A new dependency needs a reason in the pull request. Prefer well-maintained crates with few dependencies of their own.
- A change a user can see updates the [README](README.md) and adds a line to [CHANGELOG.md](CHANGELOG.md) under Unreleased.

## License

Tsong is licensed under [Apache-2.0](LICENSE). By sending a pull request you agree that your contribution is licensed under the same terms, as section 5 of the license says.
