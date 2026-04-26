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
just pre-commit-gate
just pre-push-gate
```

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