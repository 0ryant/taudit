# docs.rs Receipt Template

Status: Template only. This file is not a receipt.

Use this template for `CRATE-002` docs.rs render/readback evidence. Template
field tokens use the form `{{TEMPLATE_FIELD:name}}`; they are not evidence and
must be replaced before the receipt can be cited.

Authority: [ADR 0021](../../../adr/0021-operator-proof-receipt-contract.md) and
[surface ledger](../surface-ledger.md).

## Required Fields

| Field | Value |
| --- | --- |
| Receipt ID | `{{TEMPLATE_FIELD:receipt_id_CRATE_002}}` |
| Surface | docs.rs |
| Crate name | `{{TEMPLATE_FIELD:crate_name}}` |
| Package version | `{{TEMPLATE_FIELD:package_version}}` |
| docs.rs URL | `{{TEMPLATE_FIELD:docs_rs_url}}` |
| docs.rs build status URL or readback | `{{TEMPLATE_FIELD:docs_rs_build_status_or_readback}}` |
| Source commit SHA | `{{TEMPLATE_FIELD:source_commit_sha}}` |
| Rendered public item sample | `{{TEMPLATE_FIELD:rendered_public_item_sample}}` |
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
