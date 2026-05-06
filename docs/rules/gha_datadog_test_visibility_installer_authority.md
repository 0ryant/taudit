# gha_datadog_test_visibility_installer_authority

Flags `datadog/test-visibility-github-action` when an earlier same-job step
mutates `GITHUB_PATH` and Datadog API key or test visibility upload authority is
present around installer/runtime helper resolution.

This is a source-lead classifier for installer helper boundaries.

## Remediation

Run Datadog test visibility setup before mutable PATH setup, or resolve
installer/runtime helpers through trusted paths before API key authority is
present.
