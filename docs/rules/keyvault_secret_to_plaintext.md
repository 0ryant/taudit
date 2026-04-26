# Key Vault Secret To Plaintext

**Rule ID:** `keyvault_secret_to_plaintext`
**Severity:** Medium
**Category:** Credentials
**Tags:** security, credentials, azure-devops

## Detection

The ADO parser stamps every Step's inline script body as `META_SCRIPT_BODY`. The rule walks every Step that carries a non-empty script body and matches against a small set of PowerShell idioms that pull a Key Vault secret directly into a non-`SecureString` variable:

- `Get-AzKeyVaultSecret … -AsPlainText` (PowerShell 7 / Az 4+)
- `ConvertFrom-SecureString … -AsPlainText` (PowerShell 7+ — flat plaintext extraction)
- `(Get-AzKeyVaultSecret …).SecretValueText` (older Az syntax, still common in long-lived deployment templates)
- `Get-AzKeyVaultSecret … PtrToStringAuto` (BSTR/marshal pattern from pre-Az 1.0)

The match is case-insensitive and applies to `PowerShell@2`, `AzurePowerShell@5`, and any other task whose `inputs.script` / `inputs.Inline` body is PowerShell.

The rule does not require the Step to have a `HasAccessTo` Secret edge — Key Vault secrets are pulled directly via Azure RBAC on the service connection, so they never appear as ADO variable-group secrets in the graph.

## Risk

A Key Vault secret pulled inline with `-AsPlainText` is structurally invisible to ADO's pipeline log masking. Masking only protects values that travel through the pipeline's variable-group / secret-variable plane — values fetched at runtime from Azure Key Vault by a `Get-AzKeyVaultSecret` call inside a script are unknown to the pipeline runner.

The exposure paths:

1. **Verbose Az / PowerShell logging** — `Set-PSDebug -Trace 1`, `$VerbosePreference = "Continue"`, `$DebugPreference = "Continue"`, or `Connect-AzAccount -Verbose` will print every variable assignment, including the line where the secret lands in `$pwd`.
2. **Error stack traces** — when a downstream cmdlet fails (`New-AzVm`, `Set-AzKeyVaultAccessPolicy`, custom REST calls), PowerShell's default error record includes the parameter values that were passed in. Plaintext credentials show up directly in the failed-pipeline log.
3. **`Get-Variable *` debugging** — common in legacy automation. Anything bound to `$pass` / `$cred` is dumped to stdout.
4. **Cross-step contamination** — a `$global:` or `$script:` variable holding the plaintext leaks into every later step in the same job.

The pattern most commonly fires on Active Directory join and certificate-issuance jobs that need a domain-admin password from Key Vault. The historical version (`.SecretValueText`) was removed from `Az.KeyVault` 4.0 — but pipeline templates that target older Az versions (still common on Windows Server 2019 self-hosted agents) keep using it, and the replacement `-AsPlainText` flag is just as exposed.

## Remediation

1. **Keep the secret as a `SecureString` end-to-end.** `Get-AzKeyVaultSecret` returns a `PSKeyVaultSecret` whose `.SecretValue` is already a `SecureString`:
   ```powershell
   $sec  = Get-AzKeyVaultSecret -VaultName $vault -Name 'svc-pwd'
   $cred = New-Object PSCredential ('svc', $sec.SecretValue)
   Add-Computer -Domain $domain -Credential $cred
   ```
   `PSCredential` accepts a `SecureString` directly — no plaintext conversion needed.

2. **For values that must be plaintext** (REST calls, env vars, command-line arguments) — convert at the moment of consumption, scoped to a single expression:
   ```powershell
   $sec = Get-AzKeyVaultSecret -VaultName $vault -Name 'api-key'
   Invoke-RestMethod -Uri $url -Headers @{
     'X-Api-Key' = ([Net.NetworkCredential]::new('', $sec.SecretValue).Password)
   }
   ```
   The plaintext exists for one expression evaluation and is never bound to a named variable.

3. **Prefer ADO variable groups linked to Key Vault** when the secret needs to flow through the pipeline. The variable-group → Key Vault link respects pipeline log masking — the value still appears as `$(SECRET)` in scripts but is masked in log output. Note this still trips `secret_to_inline_script_env_export` if you then `export` it inside a script.

4. **Disable verbose / debug logging** on any step that handles credentials:
   ```powershell
   $VerbosePreference = 'SilentlyContinue'
   $DebugPreference   = 'SilentlyContinue'
   Set-PSDebug -Off
   ```
   This is a partial mitigation — a future template edit can re-enable them.

5. **Verify:** Re-run `taudit scan`. The finding clears once the script no longer combines `Get-AzKeyVaultSecret` with `-AsPlainText` / `.SecretValueText` / `ConvertFrom-SecureString -AsPlainText`.

## See also

- [secret_to_inline_script_env_export](secret_to_inline_script_env_export.md) — same exposure model for ADO variable-group secrets bound to shell variables
- [secret_materialised_to_workspace_file](secret_materialised_to_workspace_file.md) — when the plaintext is then written to a file
- [long_lived_credential](long_lived_credential.md) — flags long-lived credential names (Key Vault is the recommended store for those)
- [Azure PowerShell — handling SecureString](https://learn.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-pscredential)
