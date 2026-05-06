# gha_issue_comment_command_to_write_token

Flags `issue_comment` workflows where comment or issue-controlled input reaches
command sinks while write-token authority is present.

This is a command-bot privilege lane: comment text becomes command selection on
a privileged runner.

## Remediation

Parse issue-comment commands with a strict allowlist, require maintainer
authorization, and move write-token operations to a separate gated workflow.
