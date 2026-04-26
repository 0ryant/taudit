# Prod Deploy Job Has No Environment Gate

**Rule ID:** `prod_deploy_job_no_environment_gate`
**Severity:** High
**Category:** Privilege Escalation
**Tags:** security, privilege-escalation, azure-devops
**Platform:** Azure DevOps only

## Detection

Positive-invariant rule — fires on the *absence* of an `environment:` binding for an ADO job that operates against production. Strictly broader than [terraform_auto_approve_in_prod](terraform_auto_approve_in_prod.md), which only fires when `terraform apply -auto-approve` is also present.

For each Step node:

1. Graph platform must be Azure DevOps (`META_PLATFORM == "azure-devops"`).
2. The step targets a production-named service connection — either via `META_SERVICE_CONNECTION_NAME` matching a production token (`prod`, `production`, `prd`), or via a `HasAccessTo` edge to an Identity node that carries `META_SERVICE_CONNECTION = "true"` and a name matching the same pattern.
3. The step does NOT carry `META_ENV_APPROVAL` (parser stamps every step inside an environment-bound deployment job — its absence means the enclosing job has no `environment:` key).

Fires once per matching step.

## Risk

ADO `environment:` is the platform's only declarative approval gate for production changes. An environment can be configured with required approvers, branch-control checks, manual validation, business-hours windows, and concurrency limits. None of those controls apply to a job that has no `environment:` binding — the job runs immediately on every trigger, applies its changes, and produces no entry in the ADO Environments audit trail.

The risk is independent of `terraform apply -auto-approve`:

- An `AzureCLI@2` step running `az deployment group create` against a prod SC has the same property — every commit applies infrastructure.
- An ARM template deployment via `AzureResourceManagerTemplateDeployment@3` does too.
- A custom `pwsh` step calling `New-AzResourceGroupDeployment` likewise.

The blue-team corpus showed multiple Azure Landing Zone pipelines deploying to production VMs, domain controllers, and shared services without any `environment:` binding — meaning every commit to the deploy branch was an immediate prod change with no approval queue.

## Remediation

Wrap the production deployment in a `deployment:` job with an `environment:` binding:

```yaml
stages:
  - stage: ProdDeploy
    jobs:
      - deployment: DeployToProd
        environment: 'production-prd'   # configure approvers in ADO Environments UI
        strategy:
          runOnce:
            deploy:
              steps:
                - task: AzureCLI@2
                  inputs:
                    azureSubscription: 'platform-prod-sc'
                    scriptType: 'bash'
                    scriptLocation: 'inlineScript'
                    inlineScript: |
                      az deployment group create ...
```

In ADO → Pipelines → Environments, configure `production-prd` with:

- A required approver group (typically the platform-engineering or SRE team).
- Optionally a branch control check restricting which branches can release into the environment.
- Optionally a business-hours / concurrency check.

The environment binding is the chokepoint. Once it's in place, audit and approval policy become an environment configuration concern (visible in the ADO UI) rather than a per-pipeline YAML concern (invisible to most reviewers).

## See also

- [terraform_auto_approve_in_prod](terraform_auto_approve_in_prod.md) — strict subset of this rule; fires only on the `-auto-approve` Terraform variant.
- [variable_group_in_pr_job](variable_group_in_pr_job.md) — related ADO change-control gap.
- [Microsoft Learn — Pipeline environments and approvals](https://learn.microsoft.com/azure/devops/pipelines/process/environments)
- [Microsoft Learn — Approvals and checks](https://learn.microsoft.com/azure/devops/pipelines/process/approvals)
