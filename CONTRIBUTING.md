# Contributing

## Development setup

`taudit` is a Rust workspace. Use the pinned toolchain configured by the repo.

## Local quality gate

The canonical local gate is:

```bash
just check
```

That runs:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo deny check licenses bans sources`

Optional extra check:

```bash
just audit
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
just cellos-smoke
```

## Pull requests

- Keep changes focused and minimal.
- Update docs when behavior or operator-facing output changes.
- If you change JSON schemas, examples, or machine-readable outputs, treat them as release-contract changes and update them together.
- Include tests for behavior changes when practical.

## Release expectations

For public release work, keep the repository owner, install instructions, and report output examples aligned with shipped behavior.