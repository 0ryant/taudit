# gha_workflow_run_artifact_report_to_pr_comment

Flags `workflow_run` or `pull_request_target` consumers that download
PR-context artifacts, read report content from those artifacts, and post the
content to a PR or review comment sink while privileged authority is present.

This separates comment/report handoff from generic artifact interpretation.

## Remediation

Treat artifact report text as untrusted markdown. Generate the comment body in
the trusted consumer, code-fence or escape untrusted sections, cap length, and
do not use artifact content to select the target PR.
