# gha_ssh_agent_private_key_to_path_helper

Flags `webfactory/ssh-agent` when an earlier same-job step mutates
`GITHUB_PATH` and the later action receives SSH private-key material before
starting `ssh-agent` or feeding `ssh-add`.

This is a source-lead classifier. It is customer-safe hardening signal, not a
vulnerability claim.

## Remediation

Start SSH agent setup before mutable PATH changes, or ensure `ssh-agent` and
`ssh-add` resolve to trusted absolute paths before private keys reach the
helper boundary.
