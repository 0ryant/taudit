# Runtime Script Fetched From Floating Url

**Rule ID:** `runtime_script_fetched_from_floating_url`
**Severity:** see SARIF `security-severity` for the authoritative value
**Category:** see SARIF `tags` (security + injection / supply-chain / privilege-escalation / credentials)
**Status:** stub doc — to be expanded with detection walkthrough, attack scenario, and remediation.

## Detection

The rule fires when its detection logic in `crates/taudit-core/src/rules.rs::runtime_script_fetched_from_floating_url` returns a non-empty `Vec<Finding>`. The detection is deterministic: it inspects parsed graph metadata (no path traversal). See the function's doc-comment in source for the precise signal it watches.

## Risk

Concrete attack scenario, blast-radius classification, and corpus references will be added in a follow-up doc pass. The rule was added in v0.9.1; the SARIF `fullDescription` field contains the production-grade attack-scenario summary used by the rendered docs and `taudit explain` UI.

## Remediation

See the SARIF `fullDescription` for the recommended remediation. A walkthrough with concrete YAML before/after will be added in a follow-up doc pass.

## See also

- `docs/rules/index.md` — full rule catalogue
- [`crates/taudit-report-sarif/src/lib.rs`](../../crates/taudit-report-sarif/src/lib.rs) — authoritative `RuleDef` entry with full description, default level, security severity, and tags
- [`crates/taudit-core/src/rules.rs`](../../crates/taudit-core/src/rules.rs) — detection implementation (`pub fn runtime_script_fetched_from_floating_url`)

## What counts as a mutable URL

A fetched script is treated as mutable unless its URL pins itself to bytes the
publisher cannot silently change. Three things count as pinned:

- a full commit SHA or digest in the path (40 or 64 hex characters),
- an explicit `refs/tags/` ref,
- a version-bearing path segment, such as `/v1.2.3/` or `/1.2.3/`.

Everything else is mutable, including bare vendor install endpoints like
`https://sh.rustup.rs`, `https://get.docker.com` and
`https://install.python-poetry.org`. Those carry no version at all, so the
publisher can change the executed bytes at any time, and one compromise reaches
every pipeline that trusts them.

Before taudit 1.4, only branch-pinned URLs such as
`raw.githubusercontent.com/<owner>/<repo>/main/install.sh` were flagged, so the
vendor-endpoint shape (by far the more common one in real pipelines) was missed
on every platform.
