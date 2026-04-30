# Contributing

## Development setup

`taudit` is a Rust workspace. Use the pinned toolchain configured by the repo.

## Local quality gate

The canonical local gate is:

```bash
just quality-gate
```

That runs Rust quality checks plus governance/security tooling:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo deny check licenses bans sources`
- `cargo audit`
- `gitleaks` (secrets scanning)
- `trivy` (filesystem vuln/misconfig/secret scan)
- `checkov` (GitHub Actions + secrets policy scan)
- `taudit` workflow scan + invariant verification
- **Golden paths** — after `cargo test`, runs [`scripts/golden-paths.sh`](scripts/golden-paths.sh) against `target/debug/taudit` (same flows as [docs/golden-paths.md](docs/golden-paths.md))
- **Starter `taudit verify` (advisory)** — why many findings on our own workflows do not fail the gate: [docs/contributing/dogfood-taudit-verify.md](docs/contributing/dogfood-taudit-verify.md)

Quick Rust-only gate:

```bash
just check
```

Contract-focused check:

```bash
just contracts
```

## Common development tasks

```bash
just versions
just fix
just self-test
just golden-paths
just pre-commit-gate
just pre-push-gate
```

**Docs drift:** if you change CLI output that the golden-path script asserts on, run **`just golden-paths`** locally and update [docs/golden-paths.md](docs/golden-paths.md) if you add a new blessed flow.

Install local hooks:

```bash
just install-hooks
```

Optional runtime-integration smoke:

```bash
just runtime-smoke
```

## Pull requests

- Keep changes focused and minimal.
- Update docs when behavior or operator-facing output changes.
- If you change JSON schemas, examples, or machine-readable outputs, treat them as release-contract changes and update them together.
- Include tests for behavior changes when practical.

## Release expectations

**Cadence — at most one crates.io / GitHub release per calendar week** unless a security fix forces an out-of-band ship. Batch doc-only tweaks, small fixes, and metadata into that weekly window instead of tagging every merge. Prefer fewer, intentional releases over changelog noise.

For each release, keep the repository owner, install instructions, and report output examples aligned with shipped behavior. When you bump `version` in the crate manifests, update `CHANGELOG.md`, align any pinned `cargo install taudit --version …` strings in docs and examples, and push the `vM.m.p` tag only when `main` is green and the set of changes is what you want users to consume together.