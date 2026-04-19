# taudit v0.1.0 release copy

`taudit` is a Rust CLI that shows how secrets, identities, and privileges propagate through GitHub Actions workflows.

It builds an authority graph from workflow YAML, then reports where authority crosses trust boundaries, where `GITHUB_TOKEN` is broader than needed, and where unpinned actions or long-lived credentials increase risk.

## Install

```bash
cargo install taudit
```

## Build from source

```bash
git clone https://github.com/0ryant/taudit.git
cd taudit
cargo install --path crates/taudit-cli
```

## Canonical example

```bash
taudit scan .github/workflows/ --format sarif
```

## Included output formats

- terminal
- json
- sarif
- cloudevents

## Project scope

- current parser support: GitHub Actions
- current install path: Cargo and source build
- product support: GitHub Issues
- security disclosure: see `SECURITY.md`