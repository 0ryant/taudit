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

For public release work, keep the repository owner, install instructions, and report output examples aligned with shipped behavior.