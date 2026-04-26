# VM Remote Exec via Pipeline Secret

**Rule ID:** `vm_remote_exec_via_pipeline_secret`
**Severity:** High
**Category:** Credentials / Lateral Movement
**Tags:** security, credentials, lateral-movement
**Platforms:** ADO

## Detection

taudit reads each pipeline Step's inline script body (stamped on the Step node as `META_SCRIPT_BODY` by the parser). The rule fires when the body matches **both** of the following:

1. **A VM remote-execution primitive is invoked.** Case-insensitive substring match against:
   - `Set-AzVMExtension` (specifically with `CustomScriptExtension` / `CustomScript`)
   - `Invoke-AzVMRunCommand`
   - `az vm run-command` (e.g. `az vm run-command invoke ... --scripts ...`)
   - `az vm extension set` (with `--settings` containing `commandToExecute`)
2. **A credential is interpolated into the executed command line.** Either:
   - the script interpolates a known pipeline-secret variable (the step has `HasAccessTo` a Secret node whose name appears as `$name` / `"$name"` / `$(NAME)` in the body), **or**
   - the script mints a SAS token in the same body (`New-AzStorage*SASToken`, `az storage * generate-sas`).

Each matching step emits one finding. The rule deliberately does not deduplicate against [short_lived_sas_in_command_line](short_lived_sas_in_command_line.md) — the two rules describe different angles of the same risk and are expected to co-fire on the SAS variant.

## Risk

This is a pipeline-to-VM lateral movement primitive. Once it ships, every pipeline run can RCE every VM in scope of the loop, and the credential embedded in the command line is logged in plaintext in places the pipeline author never touches:

1. **VM-side log surface.** `CustomScriptExtension` writes the executed `commandToExecute` string to `C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\<ver>\Status\<n>.status` on Windows (and `/var/lib/waagent/custom-script/...` on Linux). On Windows this is also visible in the event log. Anyone with local read on the VM — including all subsequent script extensions, all logged-in admins, and any backup that captures these paths — can recover the SAS or secret.
2. **ARM extension status.** `Set-AzVMExtension` returns the same `commandToExecute` string in the extension status JSON that ARM itself stores. Any principal with `Microsoft.Compute/virtualMachines/extensions/read` (e.g. the built-in `Reader` role on the resource) can pull it via `Get-AzVMExtension` or the REST API. SAS tokens minted with multi-hour lifetimes (the corpus shows 3 hours) remain attacker-usable for the full window.
3. **Pipeline-step log redaction does not save you.** ADO secret masking runs on the pipeline log stream — it does not propagate to the VM-side or ARM-side log surfaces. The credential lands in plaintext at the destination regardless of whether the pipeline log itself is masked.
4. **Blast radius is the foreach.** The corpus pattern wraps `Get-AzVM | foreach Set-AzVMExtension` — one pipeline run plants the credential on every VM in the resource group, every time the pipeline runs.

The corpus example (`Azure_Landing_Zone/sharedservice-solarwinds/.pipeline/deployment.yml`) is a textbook case: a 3-hour read SAS for the `packages` container is minted in-pipeline and pasted into `commandToExecute` for `CustomScriptExtension`. The same pattern recurs in `sharedservice-commvault`, `userapp-mvit-prd`, `msamlin-central/deployment-fileservers.yml`, and `9d-fileserver-deploy/...`.

## Remediation

1. **Use `protectedSettings` instead of `settings` for any value that is or contains a credential.** ARM encrypts `protectedSettings` at rest and never returns it in extension status:
   ```powershell
   Set-AzVMExtension -ResourceGroupName $rg -VMName $vm -Name customScript `
     -Publisher 'Microsoft.Compute' -ExtensionType 'CustomScriptExtension' -TypeHandlerVersion '1.10' `
     -Settings           @{ "fileUris" = @($installpackagesURL) } `
     -ProtectedSettings  @{ "commandToExecute" = "powershell -File install.ps1"; `
                            "managedIdentity"  = @{} }
   ```
   The `managedIdentity` block tells the extension to fetch blobs using the VM's managed identity — **no SAS needed at all**. This is the recommended pattern for Azure-stored payloads.

2. **If you cannot remove the SAS, stage it on the VM out-of-band.** Use `Invoke-AzVMRunCommand` (which supports `-Parameter` runtime variables that are *not* embedded in the command line) or write the SAS to an Azure Key Vault and have the VM pull it via managed identity.

3. **For `Invoke-AzVMRunCommand`:** pass parameters via `-Parameter @{ key = $value }`, not by interpolating into `-ScriptString`. The runtime substitutes the value inside the script process — argv only sees the parameter name.

4. **For `az vm run-command`:** use `--parameters key=value` (substituted inside the script process) and read with `$args` / `${{key}}`. Do not interpolate secrets into `--scripts`.

5. **For `az vm extension set`:** put credential-bearing fields in `--protected-settings` (encrypted; not returned in status) rather than `--settings`.

6. **Verify:** rescan the file with `taudit scan` and confirm both this rule and `short_lived_sas_in_command_line` no longer fire.

## See also

- [short_lived_sas_in_command_line](short_lived_sas_in_command_line.md) — fires on the SAS-on-argv angle of the same step
- [Azure docs — Custom Script Extension protectedSettings](https://learn.microsoft.com/azure/virtual-machines/extensions/custom-script-windows#property-values)
- [Azure docs — Invoke-AzVMRunCommand parameters](https://learn.microsoft.com/powershell/module/az.compute/invoke-azvmruncommand)
