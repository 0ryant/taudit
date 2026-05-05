# GHA Action Minted Secret To Helper

**Rule ID:** `gha_action_minted_secret_to_helper`
**Severity:** High
**Category:** Credentials
**Tags:** security, credentials, github-actions

## Detection

Fires when a same-job earlier step writes to `GITHUB_PATH` and a later known action mints or exchanges credentials before delegating them to a PATH-resolved helper.

Current action coverage includes `teleport-actions/database-tunnel`, `google-github-actions/setup-gcloud` with `skip_install: true`, and `aws-actions/amazon-ecr-login`.

## Risk

The authority is created after the earlier PATH mutation, then handed to a helper that earlier state can influence.

## Remediation

Resolve and validate helpers before credential minting, or move helper installation/PATH mutation into a separate job.
