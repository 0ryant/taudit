# Short-Lived SAS in Command Line

**Rule ID:** `short_lived_sas_in_command_line`
**Severity:** Medium
**Category:** Credentials
**Tags:** security, credentials
**Platforms:** ADO

## Detection

taudit reads each pipeline Step's inline script body (stamped on the Step node as `META_SCRIPT_BODY` by the parser). The rule fires when **all** of the following hold:

1. **A SAS token is minted in the script body.** Case-insensitive substring match against:
   - `New-AzStorageContainerSASToken`
   - `New-AzStorageBlobSASToken`
   - `New-AzStorageAccountSASToken`
   - `az storage container generate-sas`
   - `az storage blob generate-sas`
   - `az storage account generate-sas`
2. **The body references a command-line sink.** Case-insensitive substring match against:
   - `commandToExecute` (used by `Set-AzVMExtension`, `az vm extension set`, ARM templates)
   - `scriptArguments`
   - `--arguments`
   - `-ArgumentList`
   - `--scripts` (used by `az vm run-command invoke`)
   - `-ScriptString` (used by `Invoke-AzVMRunCommand`)
3. **The minted SAS variable appears interpolated** somewhere in the body. The rule extracts variable names from `$<name> = New-AzStorage...SASToken ...` assignments and checks whether any are interpolated as `$name` / `"$name"` / `$(NAME)` later in the body. If no minted-SAS variable can be statically bound to a sink (e.g. inline `az` subshells), the rule still fires using the weaker "mint + sink in same script" evidence — explicitly noted in the finding message.

The detection is heuristic. The goal is to catch the corpus pattern reliably, not to achieve perfect specificity. False positives are acceptable; false negatives on the lateral-movement primitive are not.

This rule is allowed to co-fire with [vm_remote_exec_via_pipeline_secret](vm_remote_exec_via_pipeline_secret.md) on the same step. Each describes a different angle of the same risk class — one focuses on the destination (VM RCE), the other on the medium (SAS on argv).

## Risk

"Short-lived" credentials in argv are not transient when the destination keeps a permanent record. A SAS token passed as a command-line argument lands in three log surfaces that retain the value for at least the SAS lifetime, often longer:

1. **Linux `/proc/<pid>/cmdline`.** Any process running as the same user — and any process with `CAP_SYS_PTRACE` or root — can read the full command line of any running process. Any agent that snapshots `/proc` (auditd, falco, the cloud-provider VM agent, container runtime metrics) preserves the value beyond the process's own lifetime.
2. **Windows ETW process-create events.** With `Audit Process Creation` enabled (default in many compliance baselines), every command-line invocation is written to the Windows Security event log with full argv. Sysmon Event ID 1 captures the same. These logs are routinely shipped to SIEMs that retain them for months.
3. **ARM extension status JSON.** When the SAS is passed via `commandToExecute` to `Set-AzVMExtension` / `az vm extension set`, the full string is returned in the extension's instance-view status and is fetchable via `Get-AzVMExtension` by anyone with `Reader` on the resource. It is also visible in the Azure portal extension blade.

Even a 60-minute SAS is enough for an attacker who can read any of these surfaces to download the entire blob the SAS authorises. The 3-hour SAS the corpus uses is functionally a long-lived credential to any reader on the VM or the resource.

ADO pipeline-log secret masking does not help here. Masking runs on the pipeline log stream — it does not propagate into `/proc`, into Windows event logs, or into ARM. The credential lands in plaintext at every destination.

The corpus example (`Azure_Landing_Zone/sharedservice-solarwinds/.pipeline/deployment.yml`) mints `$sastokenpackages` with `New-AzStorageContainerSASToken -Permission r -ExpiryTime (Get-Date).AddHours(3)` and embeds it in the `commandToExecute` of a `CustomScriptExtension` deployment. Both this rule and `vm_remote_exec_via_pipeline_secret` fire on the same step.

## Remediation

1. **Eliminate the SAS entirely with managed identity.** If the destination is an Azure VM and the source is Azure Storage, give the VM a managed identity with `Storage Blob Data Reader` on the container, and have the install script `az login --identity && az storage blob download ...`. No SAS is minted, none is logged.

2. **If you cannot use managed identity, never put the SAS on argv.** Pass it via:
   - **Env var on the receiving process.** `Invoke-AzVMRunCommand -Parameter @{ SAS = $sas }` (Az.Compute substitutes the parameter inside the running script, not in argv).
   - **Stdin.** Write the SAS to stdin of the consuming command rather than as an argument: `$sas | & install.ps1 -SasFromStdin`.
   - **`protectedSettings` for VM extensions.** Anything in `protectedSettings` is encrypted at rest by ARM and is **not** returned in extension status. Move `commandToExecute` (and any SAS it contains) from `Settings` into `ProtectedSettings`.

3. **For `az vm run-command`:** prefer `--parameters key=value` over interpolating into `--scripts`. The runtime substitutes inside the script process; argv shows only the parameter name.

4. **Shorten the SAS lifetime to the minimum the operation needs.** Even with the above mitigations, a 5-minute SAS is preferable to a 3-hour one. Use `(Get-Date).AddMinutes(N)` rather than `.AddHours(N)`.

5. **Verify:** rescan with `taudit scan` and confirm the rule no longer fires. If it still fires after moving to `protectedSettings`, check that the sink keyword (`commandToExecute`) was removed from the unprotected `Settings` block.

## See also

- [vm_remote_exec_via_pipeline_secret](vm_remote_exec_via_pipeline_secret.md) — fires on the VM-RCE angle of the same step
- [long_lived_credential](long_lived_credential.md) — long-lived static credential patterns
- [Azure docs — VM extension protectedSettings](https://learn.microsoft.com/azure/virtual-machines/extensions/features-windows#extension-execution)
- [Azure docs — Invoke-AzVMRunCommand `-Parameter`](https://learn.microsoft.com/powershell/module/az.compute/invoke-azvmruncommand)
