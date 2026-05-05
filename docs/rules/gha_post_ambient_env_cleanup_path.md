# GHA Post Ambient Env Cleanup Path

**Rule ID:** `gha_post_ambient_env_cleanup_path`
**Severity:** Medium
**Category:** Cleanup
**Tags:** security, cleanup, github-actions

## Detection

Fires when a known post-cleanup action appears before a later same-job step that writes to `GITHUB_ENV`.

Current action coverage includes `google-github-actions/auth`, `prefix-dev/setup-pixi`, and `cachix/cachix-action`.

## Risk

If the post action recomputes cleanup paths from ambient env, later env writes can retarget deletion or cleanup behavior.

## Remediation

Store cleanup paths in `GITHUB_STATE` / `core.saveState` and read only that state in post cleanup.
