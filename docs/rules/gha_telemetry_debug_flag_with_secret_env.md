# GHA Telemetry Debug Flag With Secret Env

**Rule ID:** `gha_telemetry_debug_flag_with_secret_env`
**Severity:** High
**Category:** Disclosure
**Tags:** security, telemetry, exfiltration, github-actions

## Detection

Fires when the workflow or job `env:` block sets `ACTIONS_STEP_DEBUG: true`, `ACTIONS_STEP_DEBUG: ${{ secrets.* }}`, or `ACTIONS_RUNNER_DEBUG: true`, and any step in the same job has `${{ secrets.* }}` references in env or `with:`.

## Risk

GitHub's automatic secret masker performs string-match redaction over the unmodified secret value. Debug logging emits expanded command lines, env dumps, action input metadata, and step traces. Several encoding paths bypass the masker:

- secret values that reach the runner as base64/hex/url-encoded transformations of the original secret (`echo $TOKEN | base64`);
- secret-bearing JSON-stringified outputs whose escape characters break the masker's exact-match;
- file contents derived from a secret (e.g., `~/.netrc` written from `$NPM_TOKEN`) shown verbatim by debug;
- substring portions of a secret (first 8 chars) used in commands or logs.

When debug logging is enabled in a token-bearing job, these encoding-bypass paths become observable to anyone with read access to the workflow logs.

## Remediation

Never set `ACTIONS_STEP_DEBUG` or `ACTIONS_RUNNER_DEBUG` from a static `true` value in workflow `env:` of a token-bearing job. If debug is required for a triage build, isolate it in a separate workflow file with no secret env, or gate it on `if: github.event_name == 'workflow_dispatch'` plus an actor allowlist. Treat the debug flag itself as a privileged operation.
