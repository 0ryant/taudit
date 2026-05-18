# Release Asset Receipt Template

Status: Template only. This file is not a receipt.

Use this template for `REL-001` release archive, installer, checksum, and
release-object evidence. Template field tokens use the form
`{{TEMPLATE_FIELD:name}}`; they are not evidence and must be replaced before the
receipt can be cited.

Authority: [ADR 0021](../../../adr/0021-operator-proof-receipt-contract.md) and
[surface ledger](../surface-ledger.md).

## Required Fields

| Field | Value |
| --- | --- |
| Receipt ID | `{{TEMPLATE_FIELD:receipt_id_REL_001}}` |
| Surface | GitHub release assets |
| Release tag | `{{TEMPLATE_FIELD:release_tag}}` |
| Release URL | `{{TEMPLATE_FIELD:release_url}}` |
| Source commit SHA | `{{TEMPLATE_FIELD:source_commit_sha}}` |
| Workflow run URL or command transcript | `{{TEMPLATE_FIELD:workflow_run_url_or_transcript}}` |
| Asset names | `{{TEMPLATE_FIELD:asset_names}}` |
| SHA-256 checksums | `{{TEMPLATE_FIELD:sha256_checksums}}` |
| Checksum generation command | `{{TEMPLATE_FIELD:checksum_command}}` |
| Timestamp UTC | `{{TEMPLATE_FIELD:timestamp_utc}}` |
| Operator | `{{TEMPLATE_FIELD:operator}}` |
| Outcome | `{{TEMPLATE_FIELD:outcome}}` |
| Secrets/sanitization note | `{{TEMPLATE_FIELD:secrets_sanitization_note}}` |
| Residual risk | `{{TEMPLATE_FIELD:residual_risk}}` |

## Evidence Summary

`{{TEMPLATE_FIELD:evidence_summary}}`

## Claim Permitted

`{{TEMPLATE_FIELD:bounded_claim}}`

## Follow-Up

`{{TEMPLATE_FIELD:follow_up}}`
