# Azure Task Receipt Template

Status: Template only. This file is not a receipt.

Use this template for `ADO-001` and `ADO-002` Azure DevOps task package,
readback, and hosted `Taudit@1` smoke evidence. Template field tokens use the
form `{{TEMPLATE_FIELD:name}}`; they are not evidence and must be replaced
before the receipt can be cited.

Authority: [ADR 0021](../../../adr/0021-operator-proof-receipt-contract.md) and
[surface ledger](../surface-ledger.md).

## Required Fields

| Field | Value |
| --- | --- |
| Receipt ID | `{{TEMPLATE_FIELD:receipt_id_ADO_001_or_ADO_002}}` |
| Surface | Azure DevOps task |
| Extension id | `{{TEMPLATE_FIELD:extension_id}}` |
| Extension version | `{{TEMPLATE_FIELD:extension_version}}` |
| Package artifact name | `{{TEMPLATE_FIELD:package_artifact_name}}` |
| Package artifact SHA-256 | `{{TEMPLATE_FIELD:package_artifact_sha256}}` |
| Listing or readback URL | `{{TEMPLATE_FIELD:listing_or_readback_url}}` |
| Hosted run URL | `{{TEMPLATE_FIELD:hosted_run_url}}` |
| Pool and agent image | `{{TEMPLATE_FIELD:pool_and_agent_image}}` |
| Task version | `{{TEMPLATE_FIELD:task_version}}` |
| Resolved taudit version | `{{TEMPLATE_FIELD:resolved_taudit_version}}` |
| `tauditVerify.taudit.outcome` | `{{TEMPLATE_FIELD:taudit_verify_outcome}}` |
| Artifact file list and checksums | `{{TEMPLATE_FIELD:artifact_file_list_and_checksums}}` |
| Source commit SHA | `{{TEMPLATE_FIELD:source_commit_sha}}` |
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
