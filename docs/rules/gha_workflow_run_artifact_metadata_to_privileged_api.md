# gha_workflow_run_artifact_metadata_to_privileged_api

Flags `workflow_run` or `pull_request_target` consumers that download a
PR-context artifact, interpret artifact-derived PR metadata, and use it near a
write-class GitHub API or comment sink.

This is a precise artifact-poisoning subrule. It does not flag artifact
downloads by themselves.

## Remediation

Derive PR identity from the trusted `workflow_run` event payload or GitHub API,
not from downloaded artifact content. Validate artifact fields against a strict
schema before any write API call.
