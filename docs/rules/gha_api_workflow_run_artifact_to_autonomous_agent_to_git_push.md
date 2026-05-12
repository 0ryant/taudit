# GHA Workflow-Run Artifact To Autonomous Agent To Git Push

**Rule ID:** `gha_api_workflow_run_artifact_to_autonomous_agent_to_git_push`
**Severity:** High
**Category:** Trust
**Tags:** security, autonomous-agent, prompt-injection, repo-mutation, github-actions

## Detection

Fires when a `workflow_run` consumer (or a workflow gated by mutable label/comment state) downloads an artifact, consumes upstream-job outputs, or reads CI-failure data from a producer triggered by `pull_request`/`pull_request_target`, AND passes that content into an autonomous code-agent action (`anthropics/claude-code-action`, `aider`, `cursor-agent`, `openai/codex-action`), AND a later step in the same job runs `git push`, `peter-evans/create-pull-request`, `peter-evans/create-or-update-comment`, `gh pr edit`, `gh pr review`, or `gh pr merge`.

## Risk

The autonomous agent receives PR-author-influenced text (CI failure logs frequently include attacker-shaped output: stack traces with file paths from the PR diff, log strings the PR's code emitted, test output the PR's test produced). The agent treats that as instructions, then executes mutation steps — `git push` to the PR branch under the bot identity, comment creation, PR edit. The bot identity has more authority than the PR author; the mutation appears authoritative.

This combines TCA-4 (artifact replay across trust) with TCA-5 (API self-mutation) through the autonomous-agent prompt-injection surface. It is currently the highest-leverage TCA class because:

- the failure-data flow looks innocuous to reviewers;
- the agent's tool-use is broad by default;
- branch protection on the PR head ref typically does not constrain bot pushes;
- downstream reviewers see the bot's commit and assume CI verified it.

## Remediation

Do not pass `workflow_run` artifact contents, upstream job outputs, or CI-failure logs into autonomous agents that have mutation capability. If a triage flow needs failure analysis, run the agent in a sandboxed job with no `git push`, no `gh pr` mutation, no `peter-evans/*` actions, and no secrets — and surface the agent's recommendations only to a human reviewer. Require a static actor allowlist (`MAINTAINER`/`OWNER`) before any agent-driven mutation runs.
