# gha_script_injection_to_privileged_shell

Flags direct interpolation of attacker-controlled GitHub context into a
`run:`/script body when the same job holds secrets, OIDC, cloud, registry,
package, signing, or write-token authority.

This is the high-confidence subset of generic script-injection leads.

## Remediation

Bind attacker-controlled values through step-level `env:` and reference them as
data (`"$VAR"` or `process.env.VAR`). Keep write tokens and secrets out of jobs
that render attacker-controlled expressions into scripts.
