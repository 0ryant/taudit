# gha_composite_entrypoint_path_shadow_with_secret_env

Flags local or composite action references that run after an earlier same-job
`GITHUB_PATH` mutation while secret authority is directly attached to the action
step.

taudit does not inline local action internals, so this rule is emitted as a
review lead for entrypoint and internal helper resolution.

## Remediation

Inline or audit the local composite action entrypoint, resolve internal helpers
to trusted paths, and avoid running local actions with secret environment after
mutable PATH setup.
