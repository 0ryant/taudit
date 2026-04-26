# Secret To Inline Script Env Export

**Rule ID:** `secret_to_inline_script_env_export`
**Severity:** High
**Category:** Credentials
**Tags:** security, credentials, azure-devops

## Detection

The ADO parser stamps every Step's inline script body as `META_SCRIPT_BODY` — the raw text from `script:`, `bash:`, `powershell:`, `pwsh:`, or task `inputs.script` / `inputs.inlineScript` / `inputs.Inline` (case-insensitive).

The rule walks every Step that holds at least one Secret via `HasAccessTo`, then for each `$(SECRET)` reference inside the script body checks whether the surrounding line looks like a shell-variable assignment:

- bash/sh: `export VAR=$(SECRET)`, `VAR="$(SECRET)"`, `declare`/`local`/`readonly` prefixes
- PowerShell: `$X = "$(SECRET)"`, `$env:VAR = "$(SECRET)"`, `Set-Variable -Name X -Value "$(SECRET)"`

References that appear as command-line arguments (e.g. `terraform plan -var "k=$(SECRET)"`) are intentionally **not** flagged here — those are covered by the CLI-flag exposure marker on the secret node itself and surface through `untrusted_with_authority`.

## Risk

Azure DevOps masks `$(SECRET)` in pipeline log output, but the mask is applied to the rendered command string before the shell runs. Once the value is bound to a shell variable, the mask no longer protects it.

The leak vectors that fire in the wild:

1. **Transcripts** — `Start-Transcript` (PowerShell), `bash -x` / `set -x` (bash), or `script(1)` capture every command and every assignment, including the right-hand side of an `export FOO=secretvalue`.
2. **Tool debug logging** — `terraform TF_LOG=DEBUG`, `az --debug`, `kubectl --v=10`, `helm --debug` print the value of every environment variable they read.
3. **Error stack traces** — when a downstream command fails, PowerShell and many CLIs include the offending command (with substituted variable values) in the error output.
4. **`env` / `Get-ChildItem env:` calls** in the same script — common in "what's my context?" debugging steps that nobody removes.

This is the historical breach vector for ADO-hosted Terraform Cloud pipelines and Azure CLI deployment jobs. The pipeline owner sees `$(TF_TOKEN)` in their YAML, assumes it's masked, and never notices that `terraform init` with `TF_LOG=DEBUG` enabled prints the token in cleartext.

## Remediation

1. **Pass the secret as a step-level `env:` mapping** instead of materialising it inside the script body:
   ```yaml
   - bash: terraform init -backend-config="backend.hcl"
     env:
       TF_TOKEN_app_terraform_io: $(TF_TOKEN)
   ```
   The shell process still receives the value, but it never travels through an `export` statement that transcripts can capture.

2. **For PowerShell — keep the secret as a `SecureString`** and only convert it to plaintext at the exact moment of consumption, scoped to a single expression:
   ```powershell
   # bad
   $pass = "$(KeyVaultPass)"
   Connect-AzAccount -Credential (New-Object PSCredential('svc', (ConvertTo-SecureString $pass -AsPlainText -Force)))

   # good
   $secure = ConvertTo-SecureString "$(KeyVaultPass)" -AsPlainText -Force
   Connect-AzAccount -Credential (New-Object PSCredential('svc', $secure))
   ```
   The `-AsPlainText -Force` line is still flagged by the related `keyvault_secret_to_plaintext` rule when the source is Key Vault — for ADO variable-group secrets it is the lesser evil.

3. **Disable transcripts and verbose logging** on any step that handles secrets — `Stop-Transcript` early, unset `TF_LOG`, drop `--debug`. This is a partial mitigation only: a future pipeline edit can re-enable them.

4. **Verify:** Re-run `taudit scan`. The finding clears once `$(SECRET)` no longer sits on a line that the rule classifies as an assignment.

## See also

- [untrusted_with_authority](untrusted_with_authority.md) — flags `$(SECRET)` references on `-var` / CLI flag arguments via `META_CLI_FLAG_EXPOSED`
- [secret_materialised_to_workspace_file](secret_materialised_to_workspace_file.md) — companion rule for secrets written to disk rather than just bound to a shell variable
- [keyvault_secret_to_plaintext](keyvault_secret_to_plaintext.md) — same exposure model for Key Vault secrets pulled via `Get-AzKeyVaultSecret -AsPlainText`
- [Azure DevOps — set secret variables](https://learn.microsoft.com/en-us/azure/devops/pipelines/process/set-secret-variables) (official guidance to use `env:` mapping)
