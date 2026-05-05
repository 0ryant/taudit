# later_secret_materialized_after_path_mutation

Flags a GitHub Actions authority edge where an earlier same-job step mutates
`GITHUB_PATH`, and a later known helper action receives or mints sensitive
authority before resolving a bare helper through mutable `PATH`.

This is the normalized umbrella classifier for helper-resolution authority
confusion. It should not fire for a PATH mutation alone; the later authority
handoff is required.

## Remediation

Resolve helpers to trusted absolute paths before credentials are materialized,
reject workspace/temp helper paths, or split mutable PATH setup into a separate
authority-free job.

