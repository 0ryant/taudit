# GHA Helper Untrusted Path Resolution

**Rule ID:** `gha_helper_untrusted_path_resolution`
**Severity:** Medium
**Category:** Supply Chain
**Tags:** security, supply-chain, github-actions

## Detection

Fires when a same-job earlier step writes to `GITHUB_PATH` and a later known action invokes a security-sensitive helper by bare name.

## Risk

This is the structural precursor to the sensitive argv/stdin/env rules. It is useful when the workflow shape is risky but taudit cannot prove the exact secret handoff from YAML alone.

## Remediation

Pin helper execution to a trusted absolute path or avoid running helper-delegating actions after mutable PATH writes.
