# gha_kubernetes_helper_kubeconfig_authority

Flags workflow shell steps that invoke `kubectl` or `helm` deploy helpers after
an earlier same-job `GITHUB_PATH` mutation while kubeconfig, cluster, or deploy
authority is in scope.

This is a Kubernetes helper-resolution authority lead.

## Remediation

Resolve `kubectl` and `helm` through trusted absolute paths before kubeconfig or
deploy credentials are present, or split mutable PATH setup into an
authority-free job.
