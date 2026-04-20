# Changelog

All notable changes to this project will be documented in this file.

## v0.1.1

Patch release to refresh crates.io metadata and release surfaces.

Highlights:

- publish corrected repository and owner metadata for the canonical `0ryant/taudit` source
- carry the shared-envelope CloudEvents provenance and correlation work into the next published crate set
- keep workspace crate versions aligned for the next cargo publish

## v0.1.0

Initial public release of `taudit`.

Highlights:

- GitHub Actions authority-graph parsing
- authority propagation and privilege finding rules
- terminal, JSON, SARIF, and CloudEvents output modes
- CLI support for scan, map, diff, version, and CellOS spec emission
- JSON schemas and example reports for machine-readable integrations