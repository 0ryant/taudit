# GHA Manifest Cargo build.rs On PR Trigger With Token

**Rule ID:** `gha_manifest_cargo_build_rs_pull_request_with_token`
**Severity:** High
**Category:** Supply Chain
**Tags:** security, supply-chain, manifest-as-code, rust, github-actions

## Detection

Fires when a workflow's `on:` block includes `pull_request` or `pull_request_target`, AND a step runs `cargo build`, `cargo test`, `cargo run`, `cargo doc`, `cargo install --path .`, `cargo publish`, or any other cargo command that compiles the workspace, AND the same job has credential-bearing env (`${{ secrets.* }}`, default `GITHUB_TOKEN`, `id-token: write`, `CARGO_REGISTRY_TOKEN`, cloud creds).

## Risk

Three documented cargo-internal mechanisms execute Rust code during `cargo build`:

1. `build.rs` files are compiled and run before the crate compiles.
2. Proc-macro crates (any dependency declared as `[lib] proc-macro = true`) are compiled and run during dependent-crate compilation.
3. `[build-dependencies]` are compiled and linked into `build.rs`.

A PR that adds or modifies `build.rs`, that adds a `[build-dependencies]` entry pointing at a malicious crate, or that bumps a transitive proc-macro dependency to a malicious version, runs PR-author Rust code with the CI step's env in scope. The compilation host has access to every secret in env, every credential file, the `GITHUB_TOKEN`, any minted OIDC, and the workspace tree.

This is the analogue of the npm `postinstall` attack, applied to Rust. It is not catalogued as a vulnerability per se because it is documented behavior — but in CI workflows that compile PR-author code under credentials, it is the same trust collapse as MAC-1.

## Remediation

Run `cargo build`/`cargo test` against PR-author code in a sandboxed job with no secrets, no `id-token: write`, no PAT, and no registry credentials. Promote artifacts to the privileged job only after content verification. Where compiling a PR's code in a privileged job is unavoidable, use `--frozen` plus a CODEOWNERS-protected `Cargo.lock` and reject any PR that modifies `build.rs`, `[build-dependencies]`, or the `Cargo.lock` digest of a `proc-macro` crate.
