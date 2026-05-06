# gha_token_remote_url_with_trace_or_process_exposure

Flags GitHub Actions shell steps that use a token-bearing Git remote URL while
trace/debug output or process-inspection exposure is enabled.

The concern is concrete token observability through argv, logs,
`/proc/*/cmdline`, or process-list output.

## Remediation

Avoid embedding tokens in Git remote URLs. Use credential helpers or
header-based auth, and keep `GIT_TRACE`, `set -x`, process dumps, and
`/proc/*/cmdline` inspection away from token-bearing commands.
