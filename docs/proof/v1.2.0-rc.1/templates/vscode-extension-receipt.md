# VS Code Extension Receipt Template

Status: Template only. This file is not a receipt.

Use this template for `VSC-001` through `VSC-004` VSIX package, local install,
hosted install, command smoke, Marketplace listing, and install-readback
evidence. Template field tokens use the form `{{TEMPLATE_FIELD:name}}`; they are
not evidence and must be replaced before the receipt can be cited.

Authority: [ADR 0021](../../../adr/0021-operator-proof-receipt-contract.md) and
[surface ledger](../surface-ledger.md).

## Required Fields

| Field | Value |
| --- | --- |
| Receipt ID | `{{TEMPLATE_FIELD:receipt_id_VSC_001_to_VSC_004}}` |
| Surface | VS Code extension |
| Extension id | `{{TEMPLATE_FIELD:extension_id}}` |
| Extension version | `{{TEMPLATE_FIELD:extension_version}}` |
| VSIX path or artifact URL | `{{TEMPLATE_FIELD:vsix_path_or_artifact_url}}` |
| VSIX SHA-256 | `{{TEMPLATE_FIELD:vsix_sha256}}` |
| Manifest version readback | `{{TEMPLATE_FIELD:manifest_version_readback}}` |
| Install command or hosted run URL | `{{TEMPLATE_FIELD:install_command_or_hosted_run_url}}` |
| Activation or command smoke result | `{{TEMPLATE_FIELD:activation_or_command_smoke_result}}` |
| Marketplace listing URL where applicable | `{{TEMPLATE_FIELD:marketplace_listing_url_or_not_applicable}}` |
| Installed extension readback | `{{TEMPLATE_FIELD:installed_extension_readback}}` |
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
