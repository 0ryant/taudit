# Setvariable Issecret False

**Rule ID:** `setvariable_issecret_false`
**Severity:** High
**Category:** Credentials / Information Disclosure
**Tags:** security, credentials
**Platform:** Azure DevOps only

## Detection

taudit fires when a `##vso[task.setvariable variable=<name>]` directive is found **without** `issecret=true` in the directive header, and the variable name contains a sensitive token.

Sensitive names are detected by tokenizing the variable name on `_` and `-` separators and checking whether any token matches: `password`, `passwd`, `token`, `secret`, `key`, `credential`, `cert`, `api_key`, `apikey`, `auth`.

## Risk

ADO pipeline variables set without `issecret=true` are printed in the pipeline log in plaintext. Any user with log-read access — including contributors on internal teams who are not in the deployment approvers group — can see the value.

This is the primary leak vector for `ARM_OIDC_TOKEN` and similar values in ADO pipelines. A step that captures an OIDC token via `##vso[task.setvariable variable=ARM_OIDC_TOKEN]$(some.output)` and omits `issecret=true` will write the raw token into the job log. The token may be short-lived, but an attacker polling the logs in real time can capture it within the TTL window.

The attack path:

1. A pipeline step captures a sensitive value into an ADO variable using `##vso[task.setvariable]`.
2. The directive does not include `issecret=true`.
3. ADO writes the raw variable value to the pipeline log as part of the step's standard output.
4. Any user with "View build" access (or broader) can read the log and extract the value.
5. Depending on the token type, the attacker can authenticate to Azure, call APIs, or pivot to other services within the token's TTL.

Unlike GitHub Actions masked variables (which require explicit `add-mask`), ADO's `issecret=true` is the only mechanism to suppress the value from logs. There is no automatic detection of secret patterns in variable values.

## Remediation

Add `issecret=true` to the setvariable directive:

```bash
# Before (value printed in log)
echo "##vso[task.setvariable variable=ARM_OIDC_TOKEN]$(arm.oidc.token)"

# After (value masked in log)
echo "##vso[task.setvariable variable=ARM_OIDC_TOKEN;issecret=true]$(arm.oidc.token)"
```

For variables set inside PowerShell steps:

```powershell
# Before
Write-Host "##vso[task.setvariable variable=MY_TOKEN]$tokenValue"

# After
Write-Host "##vso[task.setvariable variable=MY_TOKEN;issecret=true]$tokenValue"
```

**Verify:** Re-run `taudit scan`. The finding resolves when `issecret=true` is present in the directive header for the flagged variable. Confirm in ADO by checking the pipeline log — the value should appear as `***` rather than the raw string.

Note: if your variable name uses a resource-name suffix (e.g. `MY_KEY_VAULT_RG`) and `rg` triggers a false positive, use `taudit suppress` to waive the finding for that specific variable with a documented justification.

## See also

- [vm_remote_exec_via_pipeline_secret](vm_remote_exec_via_pipeline_secret.md) — secret values used to drive VM remote execution
- [secret_to_inline_script_env_export](secret_to_inline_script_env_export.md) — secrets exported into inline script environments
