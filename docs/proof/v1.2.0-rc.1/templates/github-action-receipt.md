# GitHub Action Receipt Template

Status: Template only. This file is not a receipt.

Use this template for `GHA-001` through `GHA-004` hosted smoke, immutable tag,
moving tag, release, and Marketplace listing evidence. Template field tokens use
the form `{{TEMPLATE_FIELD:name}}`; they are not evidence and must be replaced
before the receipt can be cited.

Authority: [ADR 0021](../../../adr/0021-operator-proof-receipt-contract.md) and
[surface ledger](../surface-ledger.md).

## Required Fields

| Field | Value |
| --- | --- |
| Receipt ID | `{{TEMPLATE_FIELD:receipt_id_GHA_001_to_GHA_004}}` |
| Surface | GitHub Action |
| Repository | `{{TEMPLATE_FIELD:repository}}` |
| Action ref or tag | `{{TEMPLATE_FIELD:action_ref_or_tag}}` |
| Action target commit SHA | `{{TEMPLATE_FIELD:action_target_commit_sha}}` |
| Hosted run URL | `{{TEMPLATE_FIELD:hosted_run_url}}` |
| Release URL where applicable | `{{TEMPLATE_FIELD:release_url_or_not_applicable}}` |
| Marketplace listing URL where applicable | `{{TEMPLATE_FIELD:marketplace_listing_url_or_not_applicable}}` |
| Resolved taudit version | `{{TEMPLATE_FIELD:resolved_taudit_version}}` |
| Exit code and outcome | `{{TEMPLATE_FIELD:exit_code_and_outcome}}` |
| Timestamp UTC | `{{TEMPLATE_FIELD:timestamp_utc}}` |
| Operator | `{{TEMPLATE_FIELD:operator}}` |
| Secrets/sanitization note | `{{TEMPLATE_FIELD:secrets_sanitization_note}}` |
| Residual risk | `{{TEMPLATE_FIELD:residual_risk}}` |

## Evidence Summary

`{{TEMPLATE_FIELD:evidence_summary}}`

## Claim Permitted

`{{TEMPLATE_FIELD:bounded_claim}}`

## Follow-Up

`{{TEMPLATE_FIELD:follow_up}}`
