# Unpinned Include Remote Or Branch Ref

**Rule ID:** `unpinned_include_remote_or_branch_ref`
**Severity:** see SARIF `security-severity` for the authoritative value
**Category:** see SARIF `tags` (security + injection / supply-chain / privilege-escalation / credentials)
**Status:** stub doc — to be expanded with detection walkthrough, attack scenario, and remediation.

## Detection

The rule fires when its detection logic in `crates/taudit-core/src/rules.rs::unpinned_include_remote_or_branch_ref` returns a non-empty `Vec<Finding>`. The detection is deterministic: it inspects parsed graph metadata (no path traversal). See the function's doc-comment in source for the precise signal it watches.

## Risk

Concrete attack scenario, blast-radius classification, and corpus references will be added in a follow-up doc pass. The rule was added in v0.9.1; the SARIF `fullDescription` field contains the production-grade attack-scenario summary used by the rendered docs and `taudit explain` UI.

## Remediation

See the SARIF `fullDescription` for the recommended remediation. A walkthrough with concrete YAML before/after will be added in a follow-up doc pass.

## See also

- `docs/rules/index.md` — full rule catalogue
- [`crates/taudit-report-sarif/src/lib.rs`](../../crates/taudit-report-sarif/src/lib.rs) — authoritative `RuleDef` entry with full description, default level, security severity, and tags
- [`crates/taudit-core/src/rules.rs`](../../crates/taudit-core/src/rules.rs) — detection implementation (`pub fn unpinned_include_remote_or_branch_ref`)
