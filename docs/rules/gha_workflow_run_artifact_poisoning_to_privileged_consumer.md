# gha_workflow_run_artifact_poisoning_to_privileged_consumer

Flags `workflow_run` or `pull_request_target` consumers that download
PR-context artifact content, interpret it, and also hold privileged authority.

This is the disclosure-oriented subset of PR artifact poisoning leads.

## Remediation

Treat workflow-run artifacts as untrusted data. Validate against a strict
schema, never feed artifact content into env/output/comment/script sinks, and
isolate privileged follow-up work from artifact parsing.
