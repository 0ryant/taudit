# SBOM Receipt Template

Status: Template only. This file is not a receipt.

Use this template for `REL-002` SPDX and CycloneDX SBOM evidence. Template field
tokens use the form `{{TEMPLATE_FIELD:name}}`; they are not evidence and must be
replaced before the receipt can be cited.

Authority: [ADR 0021](../../../adr/0021-operator-proof-receipt-contract.md) and
[surface ledger](../surface-ledger.md).

## Required Fields

| Field | Value |
| --- | --- |
| Receipt ID | `{{TEMPLATE_FIELD:receipt_id_REL_002}}` |
| Surface | Release SBOM assets |
| Release tag | `{{TEMPLATE_FIELD:release_tag}}` |
| Release URL | `{{TEMPLATE_FIELD:release_url}}` |
| Source commit SHA | `{{TEMPLATE_FIELD:source_commit_sha}}` |
| SBOM generation command or workflow run | `{{TEMPLATE_FIELD:sbom_command_or_run_url}}` |
| SPDX asset name | `{{TEMPLATE_FIELD:spdx_asset_name}}` |
| SPDX SHA-256 | `{{TEMPLATE_FIELD:spdx_sha256}}` |
| CycloneDX asset name | `{{TEMPLATE_FIELD:cyclonedx_asset_name}}` |
| CycloneDX SHA-256 | `{{TEMPLATE_FIELD:cyclonedx_sha256}}` |
| SBOM validation command | `{{TEMPLATE_FIELD:sbom_validation_command}}` |
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
