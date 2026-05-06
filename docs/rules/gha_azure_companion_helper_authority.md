# gha_azure_companion_helper_authority

Flags workflow shell steps that invoke Azure companion helpers such as
`sqlcmd`, `SqlPackage`, `kubelogin`, `pwsh`, or `powershell` after an earlier
same-job `GITHUB_PATH` mutation and after Azure login or cloud authority is
present.

This is an Azure helper-boundary source lead.

## Remediation

Resolve Azure companion helpers through trusted absolute paths before Azure
login credentials are present, and keep Azure deployment helpers in a job
without prior mutable PATH state.
