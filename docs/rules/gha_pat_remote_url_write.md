# gha_pat_remote_url_write

Flags GitHub Actions shell steps that embed token material in a GitHub remote
URL and perform write-capable git operations.

Token-bearing remote URLs can leak through argv, logs, shell traces, or
`.git/config`.

## Remediation

Avoid token-bearing git remote URLs. Use credential helpers or `gh` with
least-privileged token scope, and prevent tokens from entering argv, logs, or
repository config.
