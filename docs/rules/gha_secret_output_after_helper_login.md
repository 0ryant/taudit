# GHA Secret Output After Helper Login

**Rule ID:** `gha_secret_output_after_helper_login`
**Severity:** High
**Category:** Credentials
**Tags:** security, credentials, github-actions

## Detection

Fires when a known login action is configured to expose credential material as step outputs after helper login.

Current coverage detects `aws-actions/amazon-ecr-login` with `mask-password: false`.

## Risk

Step and job outputs are easy to forward across jobs and are less contained than credentials consumed only by the login step.

## Remediation

Keep masking enabled and avoid forwarding helper login credentials through outputs.
