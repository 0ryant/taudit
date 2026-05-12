# gha_workflow_run_artifact_to_build_scan_publish

Flags `workflow_run` or `pull_request_target` consumers that download
PR-context artifacts and feed artifact-controlled data into a build-scan,
Gradle Enterprise, or Develocity publication path.

This is a deterministic build-scan publication lane, not a generic artifact
warning.

## Remediation

Generate build-scan publication inputs inside the trusted consumer. Do not
publish artifact-controlled URLs, tags, or metadata without schema validation
and provenance checks.
