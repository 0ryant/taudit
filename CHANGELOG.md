# Changelog

All notable changes to this project will be documented in this file.

## v0.2.3 — 2026-04-25

### Added

- **3 new ADO PR-boundary rules** — all gate on `trigger=pr` context so they fire only when attacker-controlled code is involved, not on every pipeline:
  - `variable_group_in_pr_job` (Critical) — ADO variable group secrets are reachable from a PR-triggered job; malicious PR code can exfiltrate them via log output or network calls.
  - `self_hosted_pool_pr_hijack` (Critical) — PR-triggered job runs on a self-hosted agent and checks out the repository; attacker can inject malicious git hooks that persist on the shared runner and execute with full pipeline authority on subsequent runs.
  - `service_connection_scope_mismatch` (High) — broad-scope ADO service connection (subscription-wide Azure RBAC, no OIDC federation) is reachable from a PR-triggered job, enabling lateral movement into the Azure tenant.

- **Parser tagging for new rules:**
  - ADO: `pool.name` without `vmImage` → Image node tagged `self_hosted: true`; variable group secrets tagged `variable_group: true`; `checkout: self` steps tagged `checkout_self: true`; service connections tagged `service_connection: true`.
  - GHA: `runs-on: self-hosted` (string, sequence, or group mapping) → Image node tagged `self_hosted: true`; `actions/checkout` steps tagged `checkout_self: true` regardless of pin level (trigger context gates the rule, not the pin).

- **`taudit explain` subcommand** — `taudit explain` lists all 16 rules with severity. `taudit explain <rule>` shows the full description, tags, and remediation guidance. Unknown rule exits 2 with the valid ID list.

### Fixed

- **`cargo fmt`** — format gate now passes on all crates.

## v0.2.2 — 2026-04-25

### Fixed

- **Multi-document YAML** — pipeline files using `---` document separators now parse correctly. Both the GHA and ADO parsers use `serde_yaml::Deserializer` to read the first document cleanly; if additional documents are present the graph is marked partial with an explanatory gap note. Previously taudit errored out immediately on any `---`-separated file.
- **`cargo deny` Zlib license** — `foldhash v0.2.0` (transitive via `jsonschema → reqwest → hashbrown`) was rejected by the licence allowlist. `Zlib` added to `deny.toml`.
- **`rustls-webpki` security advisory** — updated `rustls-webpki` from `0.103.12` to `0.103.13` to resolve RUSTSEC-2026-0104 (reachable panic in CRL parsing, transitive via `reqwest`).

## v0.2.1 — 2026-04-25

### Fixed

- **SARIF output with multiple files** — scanning a directory or passing multiple paths with `--format sarif` previously emitted one complete SARIF document per file, concatenated end-to-end. Downstream consumers (`jq`, `sarif-tools`, VS Code SARIF Viewer, any `json.load`) failed with `JSONDecodeError: Extra data`. All findings are now aggregated into a single SARIF 2.1.0 document with one `runs[0]` entry, as the spec requires.

## v0.2.0 — 2026-04-25

### Added

- **Azure DevOps platform support** — `--platform azure-devops` parses ADO YAML pipelines (stages/jobs/steps, all three shapes). Detects System.AccessToken, service connections, variable groups, `$(VAR)` references, and template references.
- **`PersistsTo` edge** — new graph edge kind for credentials written to disk (e.g. `persistCredentials: true` on checkout steps).
- **`PersistedCredential` finding** — fires High severity when a checkout step writes credentials to `.git/config`, making the token available to all subsequent steps.
- **`-var` flag exposure detection** — secrets passed as Terraform `-var "key=$(SECRET)"` arguments are marked `cli_flag_exposed: true`. The `UntrustedWithAuthority` finding message and remediation now note the log exposure risk and recommend `TF_VAR_*` env vars instead.
- **Colored CI output** — ANSI color is now on by default. GitHub Actions and Azure DevOps log viewers render it from piped stdout. Disable with `--no-color` or `NO_COLOR` env var (any value).
- **Redesigned terminal reporter** — severity-keyed colors, per-file horizontal rule headers, `[partial]` tag on every finding from an incomplete graph, node-kind annotations on paths, clean-file suppression (counted in summary instead of noisy per-file output), and a run-level summary footer.
- **Graceful CI artifact paths** — runtime artifact paths (telemetry, receipts, logs) now resolve independently. If HOME/XDG is unset (minimal CI containers), artifacts are silently skipped instead of hard-failing before any scanning occurs.

### Changed

- `EgressBlindspot` and `MissingAuditTrail` finding categories are reserved for future API-enriched implementations and marked `#[doc(hidden)]`. They cannot be detected from pipeline YAML alone.

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