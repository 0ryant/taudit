# GHA Autonomous Agent Input From Untrusted Event

**Rule ID:** `gha_telemetry_autonomous_agent_input_from_untrusted_event`
**Severity:** High
**Category:** Trust
**Tags:** security, autonomous-agent, prompt-injection, github-actions

## Detection

Fires when an autonomous code-agent action (`anthropics/claude-code-action`, `aider`, `cursor-agent`, `openai/codex-action`, equivalent) receives prompt content, files, env, or stdin populated from `github.event.issue.title`, `github.event.issue.body`, `github.event.pull_request.title`, `github.event.pull_request.body`, `github.event.comment.body`, or artifacts produced by a `pull_request`/`pull_request_target`/`workflow_run` upstream — and the same job grants the agent tool-use, write-file, shell, git-staging, or git-push capability, OR a later step in the same job runs `git push`, `peter-evans/create-pull-request`, `peter-evans/create-or-update-comment`, `gh pr edit`, deploy, publish, or sign.

## Risk

The autonomous agent treats its prompt and accessible files as instructions. Anyone who can populate the event-derived content drafts those instructions. Combined with mutation capability, the workflow becomes a remote code-execution and repo-mutation surface gated only by the agent's prompt-injection resistance.

This is the autonomous-agent variant of `script_injection_via_untrusted_context`, with two distinguishing properties: the agent's interpretation is non-deterministic, so static input validation does not bound the output; and the agent often inherits secrets and `id-token: write` because it needs to call cloud APIs, so prompt-injection escalates to credential authority.

## Remediation

Gate agent invocation behind a static actor allowlist of `MAINTAINER`/`OWNER`/`ADMIN`, NOT a label or comment-body match (those are mutable by triage roles). Strip event-derived text to fixed-shape metadata (PR number, author login as a constant) before passing to the agent. If the agent must consume PR content, run it in a job with no secrets, no `id-token: write`, no PAT, and no mutation step. Require human review on the agent's output before any `git push` or API mutation.
