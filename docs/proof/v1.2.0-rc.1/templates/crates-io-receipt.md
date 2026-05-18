# crates.io Receipt Template

Status: Template only. This file is not a receipt.

Use this template for `CRATE-001` crates.io publish/readback evidence. Template
field tokens use the form `{{TEMPLATE_FIELD:name}}`; they are not evidence and
must be replaced before the receipt can be cited.

Authority: [ADR 0021](../../../adr/0021-operator-proof-receipt-contract.md) and
[surface ledger](../surface-ledger.md).

## Required Fields

| Field | Value |
| --- | --- |
| Receipt ID | `{{TEMPLATE_FIELD:receipt_id_CRATE_001}}` |
| Surface | crates.io |
| Crate name | `{{TEMPLATE_FIELD:crate_name}}` |
| Package version | `{{TEMPLATE_FIELD:package_version}}` |
| crates.io URL or API readback | `{{TEMPLATE_FIELD:crates_io_url_or_api_readback}}` |
| Publish command or workflow run | `{{TEMPLATE_FIELD:publish_command_or_run_url}}` |
| Source commit SHA | `{{TEMPLATE_FIELD:source_commit_sha}}` |
| Package checksum or registry digest | `{{TEMPLATE_FIELD:package_checksum_or_registry_digest}}` |
| Publish order note | `{{TEMPLATE_FIELD:publish_order_note}}` |
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
