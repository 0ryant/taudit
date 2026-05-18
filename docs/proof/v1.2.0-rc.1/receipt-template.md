# Receipt Template

Status: Template only. This file is not a receipt.

Copy this structure into a new receipt file when concrete evidence exists. A
completed receipt must be bounded to one surface and one outcome.

Template field tokens use the form `{{TEMPLATE_FIELD:name}}`. They are not
evidence and must be replaced before a copied receipt can move out of Template
status.

## Required Fields

| Field | Value |
| --- | --- |
| Receipt ID | `{{TEMPLATE_FIELD:receipt_id}}` |
| Surface | `{{TEMPLATE_FIELD:surface}}` |
| Version/ref | `{{TEMPLATE_FIELD:version_or_ref}}` |
| Command/run URL | `{{TEMPLATE_FIELD:command_or_run_url}}` |
| Commit SHA | `{{TEMPLATE_FIELD:commit_sha}}` |
| Artifact checksum where applicable | `{{TEMPLATE_FIELD:artifact_checksum_or_not_applicable}}` |
| Timestamp | `{{TEMPLATE_FIELD:timestamp_utc}}` |
| Operator | `{{TEMPLATE_FIELD:operator}}` |
| Outcome | `{{TEMPLATE_FIELD:outcome}}` |
| Secrets/sanitization note | `{{TEMPLATE_FIELD:secrets_sanitization_note}}` |
| Residual risk | `{{TEMPLATE_FIELD:residual_risk}}` |

## Evidence Summary

Record the shortest useful summary of what was observed. Link to the command
output, hosted run, release object, Marketplace listing, or local artifact path
that supports the outcome.

`{{TEMPLATE_FIELD:evidence_summary}}`

## Claim Permitted

State the exact wording this receipt permits. Keep it narrower than the
evidence when uncertain.

`{{TEMPLATE_FIELD:bounded_claim}}`

## Follow-Up

List any docs, listings, release notes, or ledger entries that may now be
updated because this receipt exists.

`{{TEMPLATE_FIELD:follow_up}}`

## Specialized Templates

Use the narrowest template that matches the surface:

- [release asset receipt](templates/release-asset-receipt.md)
- [SBOM receipt](templates/sbom-receipt.md)
- [attestation receipt](templates/attestation-receipt.md)
- [crates.io receipt](templates/crates-io-receipt.md)
- [docs.rs receipt](templates/docs-rs-receipt.md)
- [GitHub Action receipt](templates/github-action-receipt.md)
- [Azure task receipt](templates/azure-task-receipt.md)
- [VS Code extension receipt](templates/vscode-extension-receipt.md)
