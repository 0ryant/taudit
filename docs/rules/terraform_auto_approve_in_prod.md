# Terraform Auto-Approve in Prod

**Rule ID:** `terraform_auto_approve_in_prod`
**Severity:** Critical
**Category:** Configuration
**Tags:** security, configuration, azure-devops

## Detection

taudit walks every `Step` node and looks for the parser-set marker `META_TERRAFORM_AUTO_APPROVE = "true"`. The ADO parser sets this marker in two cases:

1. The step is an inline `script:` / `bash:` / `pwsh:` / `inlineScript:` block whose body matches the pattern `terraform apply ... --auto-approve` (or `-auto-approve`) — including the common multi-line continuation forms (`\` for shell, backtick for PowerShell).
2. The step is a `TerraformCLI@N` (or `TerraformTaskV1..V4`) task with `inputs.command: apply` AND `inputs.commandOptions` containing the substring `auto-approve`.

The rule then requires two additional conditions on the same step:

- The step references a service connection whose name matches a production pattern (`prod`, `production`, `prd` — as a whole token, with `-`/`_` separators, or as a leading/trailing segment). The match is case-insensitive. The connection name comes from `inputs.azureSubscription` / `inputs.connectedServiceName*` / `inputs.environmentServiceName` / `inputs.backendServiceArm`, captured by the parser as `META_SERVICE_CONNECTION_NAME`. As a fallback, the rule also walks `HasAccessTo` edges to find a service-connection `Identity` node.
- The enclosing job has **no** `environment:` binding (parser sets `META_ENV_APPROVAL` for steps inside environment-bound jobs — the rule skips those).

Fires once per matching step.

## Risk

`terraform apply -auto-approve` skips Terraform's interactive confirmation prompt and applies the diff to real infrastructure. Outside a deployment job's `environment:` approval gate, the only barrier between a malicious or accidental commit and a production rewrite is the queue-build permission. Any committer who can trigger the pipeline can:

- delete or recreate any cloud resource governed by the Terraform state,
- swap a managed identity's role assignments,
- replace a key vault's RBAC scope,
- destabilise the entire stack with a single apply.

Combined with a self-hosted agent pool — where workspaces persist between runs — the same attacker can also stage payloads (modified Terraform modules, swapped plan files) that the next apply will execute.

The marker `--auto-approve` is the *only* difference between an interactive sanity check and a fully automated production rewrite. Removing it is rarely correct in modern automation; the right answer is an explicit approval gate.

## Remediation

1. **Move the apply step into a deployment job with an environment gate (preferred):**
   ```yaml
   jobs:
     - deployment: TerraformApply
       environment: production-prd   # ADO requires approver to release
       strategy:
         runOnce:
           deploy:
             steps:
               - task: TerraformCLI@2
                 inputs:
                   command: apply
                   commandOptions: '-auto-approve'   # gated by approver
                   environmentServiceName: 'prod-sc'
   ```
   In ADO → Pipelines → Environments, configure the environment with a required approver. Apply still runs unattended after release, but a human releases it.

2. **Replace `-auto-approve` with a saved plan file:**
   ```yaml
   - task: TerraformCLI@2
     inputs:
       command: plan
       commandOptions: '-out=tfplan'
   - task: ManualValidation@0   # explicit ADO checkpoint
     inputs:
       notifyUsers: 'platform-team@example.com'
   - task: TerraformCLI@2
     inputs:
       command: apply
       commandOptions: 'tfplan'  # no -auto-approve needed; plan IS the approval
   ```

3. **For non-prod connections:** keep `-auto-approve`, but rename the service connection so it doesn't match `prod`/`prd`. The rule fires on naming convention; a `dev`-named connection is by definition not flagged.

4. **Verify:** Re-run `taudit scan --platform azure-devops`. The rule should disappear once the job carries an `environment:` binding.

## See also

- [variable_group_in_pr_job](variable_group_in_pr_job.md) — related ADO change-control gap
- [self_hosted_pool_pr_hijack](self_hosted_pool_pr_hijack.md) — pairs with auto-approve on shared agents
- [Microsoft Learn — Approvals and checks](https://learn.microsoft.com/azure/devops/pipelines/process/approvals)
