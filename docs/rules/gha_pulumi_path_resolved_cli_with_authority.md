# gha_pulumi_path_resolved_cli_with_authority

Flags `pulumi/actions` when an earlier same-job step mutates `GITHUB_PATH` and
the later action has Pulumi token, stack, cloud, or secret-provider authority
before delegating to a PATH-resolved `pulumi` helper.

This is an action-boundary source lead.

## Remediation

Run Pulumi before mutable PATH setup, split mutable setup into an authority-free
job, or ensure the Pulumi CLI resolves from a trusted absolute path before stack
or cloud credentials are available.
