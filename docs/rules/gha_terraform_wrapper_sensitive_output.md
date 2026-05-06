# gha_terraform_wrapper_sensitive_output

Flags `hashicorp/setup-terraform` wrapper mode when later same-job shell steps
consume wrapper `stdout` or `stderr` outputs.

Terraform output and plan text can carry sensitive values. This rule identifies
places where wrapper outputs may become an unintended authority-bearing data
channel.

## Remediation

Avoid propagating Terraform wrapper stdout/stderr as generic step outputs when
plans or outputs may contain sensitive values. Select explicit nonsensitive
outputs and redact or mask before reuse.
