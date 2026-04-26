# addSpnToEnvironment with Inline Script

**Rule ID:** `add_spn_with_inline_script`
**Severity:** High
**Category:** Credentials
**Tags:** security, credentials, azure-devops

## Detection

taudit walks every `Step` node and looks for two co-occurring parser-set markers:

1. `META_ADD_SPN_TO_ENV = "true"` — the parser sets this when an `AzureCLI@2` (or compatible) task carries `inputs.addSpnToEnvironment: true` (booleans, the YAML strings `"true"`/`"True"`, or any case-insensitive variant are all accepted).
2. `META_SCRIPT_BODY` — non-empty inline script text. The parser populates this from `inputs.inlineScript`, `inputs.script`, `inputs.bash`, `inputs.powershell`, or `inputs.pwsh` blocks.

When both are present, the rule fires once per matching step.

The rule additionally inspects the script body for explicit token-laundering patterns: a `##vso[task.setvariable]` directive that writes any of `$env:idToken`, `$env:servicePrincipalKey`, `$env:servicePrincipalId`, `$env:tenantId`, or the conventional `ARM_OIDC_TOKEN` / `ARM_CLIENT_ID` / `ARM_CLIENT_SECRET` / `ARM_TENANT_ID` variables. When found, the finding's message escalates to "explicit token laundering detected" so reviewers can prioritise.

## Risk

Setting `addSpnToEnvironment: true` on an Azure CLI task tells ADO to inject the federated service principal's credentials into the script's environment as plain variables — `$env:idToken`, `$env:servicePrincipalKey`, `$env:servicePrincipalId`, `$env:tenantId`. With modern workload-identity-federation service connections, `idToken` is the actual OIDC token used to mint Azure access tokens.

These environment variables are inside the script process and are *not* automatically masked in pipeline log output. Worse, an inline script can copy them into normal pipeline variables with `##vso[task.setvariable variable=X]$env:idToken`. Once that happens:

- the value is inherited un-masked by every downstream task in the same job (and across jobs that depend on the output),
- it can appear in plain text in artifact upload logs,
- it bypasses the secret-redaction that ADO would otherwise apply to a properly declared `secret:` variable,
- it can be read by any third-party task downstream that prints its environment.

The combination of `addSpnToEnvironment: true` and an inline script is the canonical pattern for federated-token exfiltration in real ADO breach reports — the script is the laundering machine.

A reviewed, in-repo script file (`scriptPath:`) is harder to use as a laundering vector because it requires a code-review trail; an inline script can be edited in any PR.

## Remediation

1. **Use the task's first-class auth surface (preferred):**
   Most tasks that need ARM/Graph access have a typed input that handles the federation transparently. For example, `AzureCLI@2` runs `az login` for you when you specify `azureSubscription:` — you don't need `addSpnToEnvironment: true` unless you're building tooling that consumes the raw token.

2. **If you genuinely need the SPN material:** move the script into a reviewed file in the repo:
   ```yaml
   - task: AzureCLI@2
     inputs:
       azureSubscription: 'prod-sc'
       addSpnToEnvironment: true
       scriptType: pscore
       scriptLocation: scriptPath
       scriptPath: 'scripts/configure-arm-backend.ps1'  # under code review
   ```

3. **Never `setvariable` token material:** if the script must hand the token off to a later step, write it to a file with restrictive permissions and read it back, or refactor so the producer and consumer are the same step.

4. **Verify:** Re-run `taudit scan --platform azure-devops`. The rule clears once `addSpnToEnvironment` is removed or the inline script is moved to `scriptPath:`.

## See also

- [authority_propagation](authority_propagation.md) — covers downstream propagation of the laundered token
- [self_mutating_pipeline](self_mutating_pipeline.md) — same primitive (`##vso[task.setvariable]`) used for environment mutation
- [Microsoft Learn — Workload identity federation for Azure DevOps](https://learn.microsoft.com/azure/devops/pipelines/library/connect-to-azure)
