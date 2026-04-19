# Release trust

This document describes what a tagged `taudit` release ships and how to verify it.

## What ships with each `vX.Y.Z` tag

Every version tag produces:

- GitHub Release archives for Linux x86_64, Linux arm64, macOS x86_64, macOS arm64, and Windows x86_64
- one `.sha256` checksum file per release archive
- one SPDX 2.3 dependency SBOM: `taudit-vX.Y.Z.spdx.json`
- a crates.io publish of the `taudit` crate after the tagged quality gate and archive jobs succeed

## Release gate

The tag workflow reruns the same release-critical checks before publishing:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo deny check licenses bans sources`
- `cargo audit`

## Verifying a release archive

Download an archive and its matching checksum from the GitHub Release page, then verify it locally.

### Unix

```bash
curl -LO https://github.com/0ryant/taudit/releases/download/<tag>/taudit-x86_64-linux.tar.gz
curl -LO https://github.com/0ryant/taudit/releases/download/<tag>/taudit-x86_64-linux.tar.gz.sha256
sha256sum -c taudit-x86_64-linux.tar.gz.sha256
```

### macOS

```bash
shasum -a 256 -c taudit-aarch64-macos.tar.gz.sha256
```

### Windows PowerShell

```powershell
$expected = (Get-Content .\taudit-x86_64-windows.zip.sha256).Split(' ')[0]
$actual = (Get-FileHash .\taudit-x86_64-windows.zip -Algorithm SHA256).Hash.ToLower()
if ($expected -ne $actual) { throw 'checksum mismatch' }
```

## Verifying the SBOM

Download the SBOM from the same release page:

```bash
curl -LO https://github.com/0ryant/taudit/releases/download/<tag>/taudit-<tag>.spdx.json
jq '.packages[].name' taudit-<tag>.spdx.json
```

The SBOM covers Rust workspace dependencies resolved from `Cargo.lock` at release time.

## Trust boundary

The release workflow is defined in `.github/workflows/release.yml` and publishes only after the tag build passes the release quality gate and all archive jobs complete.

This release trust surface currently includes checksums and a dependency SBOM. It does not yet include signed artifacts.