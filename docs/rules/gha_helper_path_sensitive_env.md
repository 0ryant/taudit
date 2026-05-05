# GHA Helper PATH Sensitive Env

**Rule ID:** `gha_helper_path_sensitive_env`
**Severity:** High
**Category:** Credentials
**Tags:** security, credentials, github-actions

## Detection

Fires when a same-job earlier step writes to `GITHUB_PATH` and a later known helper-delegating action invokes a bare helper while sensitive env authority is in scope.

Current action coverage includes `teleport-actions/database-tunnel`, `cloudflare/wrangler-action`, `JS-DevTools/npm-publish`, and `cachix/cachix-action`.

## Risk

The helper inherits action inputs, token-bearing env, or credential file pointers selected for the later action.

## Remediation

Validate helper paths, reduce inherited env to an allowlist, and keep credential-bearing helper execution away from mutable runner PATH state.
