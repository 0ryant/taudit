# GHA Telemetry PR Or Issue Text To External Sink

**Rule ID:** `gha_telemetry_pr_or_issue_text_to_external_sink`
**Severity:** Medium
**Category:** Disclosure
**Tags:** security, telemetry, exfiltration, github-actions

## Detection

Fires when an external observability or notification sink (`slack-send`, `slackapi/slack-github-action`, `8398a7/action-slack`, Discord webhook, `actions-ecosystem/action-create-issue`, custom POST `curl` or `gh api`) interpolates `github.event.pull_request.title`, `github.event.pull_request.body`, `github.event.issue.title`, `github.event.issue.body`, or `github.event.comment.body` into the payload.

Severity rises when the workflow is reachable via `pull_request_target`, `workflow_run`, or `issue_comment`, when the sink ingests payloads with longer retention than GitHub Actions logs, or when the same job has secret-bearing env that may leak into the sink via debug logging.

## Risk

The PR author drafts the payload that posts into a sink the workflow author trusts. Possible outcomes:

- the sink retains attacker-controlled text in chat history that downstream tooling indexes (Slack search, Discord transcripts);
- if the sink renders payload as rich content, social-engineering surface;
- if the payload is ever re-emitted into a privileged downstream context (auto-summarized into a release note, fed to an autonomous agent, used as a deploy-decision metric), the attacker's text drives that decision.

Combined with TCA-2 secret re-encoding, the sink also becomes an exfil channel for secrets that GitHub's masker did not recognize.

## Remediation

Render PR/issue text only to constant string templates that quote/escape it; never interpolate it directly into JSON, YAML, or shell strings. If the payload must include user-authored text, pass it as an opaque `payload-file:` argument that the sink action treats as data, not as template. Pair with strong actor gates if the workflow is reachable from low-trust triggers.
