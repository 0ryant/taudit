# GHA Helper PATH Sensitive Stdin

**Rule ID:** `gha_helper_path_sensitive_stdin`
**Severity:** High
**Category:** Credentials
**Tags:** security, credentials, github-actions

## Detection

Fires when a same-job earlier step writes to `GITHUB_PATH` and a later known helper-delegating action pipes sensitive material to a bare helper over stdin.

Current action coverage includes `docker/login-action` and `cloudflare/wrangler-action`.

## Risk

Stdin is preferable to argv, but only if it reaches a trusted helper. A PATH-selected helper can still read the registry password or worker-secret payload.

## Remediation

Keep stdin handoff, but invoke only a trusted absolute helper path or validate the resolved helper before passing secret data.
