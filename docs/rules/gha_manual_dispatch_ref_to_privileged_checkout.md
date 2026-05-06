# gha_manual_dispatch_ref_to_privileged_checkout

Flags `workflow_dispatch` inputs that control `actions/checkout` `ref:` inside
a job with write-token, secret, OIDC, or deploy authority.

Dispatch permission becomes code-selection authority on a privileged runner.

## Remediation

Use a choice allowlist for dispatch refs, map choices to trusted refs, and keep
write-token or secret authority out of jobs that checkout operator-supplied
refs.
