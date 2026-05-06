# gha_action_token_env_before_bare_download_helper

Flags reviewed upload or release actions when an earlier same-job step mutates
`GITHUB_PATH` and the later action receives token authority before delegating to
bare download or verification helpers such as `curl`, `wget`, `gpg`, or checksum
tools.

This is a deterministic source-lead classifier. It does not claim
exploitability without action-source review or witness evidence.

## Remediation

Run token-bearing upload or release actions before mutable PATH setup, split
PATH mutation into an authority-free job, or resolve download and verification
helpers through trusted absolute paths before token environment is present.
