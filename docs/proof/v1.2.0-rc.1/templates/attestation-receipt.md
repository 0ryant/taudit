# Attestation Receipt Template

Status: Template only. This file is not a receipt.

Use this template for `REL-003` GitHub Artifact Attestation verification.
Template field tokens use the form `{{TEMPLATE_FIELD:name}}`; they are not
evidence and must be replaced before the receipt can be cited.

Authority: [ADR 0021](../../../adr/0021-operator-proof-receipt-contract.md) and
[surface ledger](../surface-ledger.md).

## Required Fields

| Field | Value |
| --- | --- |
| Receipt ID | `{{TEMPLATE_FIELD:receipt_id_REL_003}}` |
| Surface | GitHub Artifact Attestations |
| Release tag | `{{TEMPLATE_FIELD:release_tag}}` |
| Source commit SHA | `{{TEMPLATE_FIELD:source_commit_sha}}` |
| Verified archive asset | `{{TEMPLATE_FIELD:verified_archive_asset}}` |
| Verified SBOM asset | `{{TEMPLATE_FIELD:verified_sbom_asset}}` |
| `gh attestation verify` command for archive | `{{TEMPLATE_FIELD:archive_attestation_verify_command}}` |
| `gh attestation verify` command for SBOM | `{{TEMPLATE_FIELD:sbom_attestation_verify_command}}` |
| Verification output path or run URL | `{{TEMPLATE_FIELD:verification_output_or_run_url}}` |
| Trusted identity or workflow | `{{TEMPLATE_FIELD:trusted_identity_or_workflow}}` |
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
