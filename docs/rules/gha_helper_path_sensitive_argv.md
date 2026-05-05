# GHA Helper PATH Sensitive Argv

**Rule ID:** `gha_helper_path_sensitive_argv`
**Severity:** High
**Category:** Credentials
**Tags:** security, credentials, github-actions

## Detection

Fires when a same-job earlier step writes to `GITHUB_PATH` and a later known helper-delegating GitHub Action passes sensitive material to a bare helper through argv.

Current action coverage includes `azure/login`, `aws-actions/amazon-ecr-login`, `cachix/cachix-action`, and `google-github-actions/setup-gcloud` when `skip_install: true`.

## Risk

The earlier step can select the helper binary that later receives action-only credentials. Argv values are also exposed through process tables and runner telemetry more broadly than stdin or scoped env.

## Remediation

Resolve helpers to trusted absolute paths before credentials are materialized, reject helpers under workspace/temp paths, or split `GITHUB_PATH` mutation into a separate job.
