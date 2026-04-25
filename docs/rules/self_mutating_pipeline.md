# Self-Mutating Pipeline

**Rule ID:** `self_mutating_pipeline`
**Severity:** Critical (untrusted step) / High (step with secret access) / Medium (other steps)
**Category:** Injection
**Tags:** security, injection

## Detection

taudit checks every Step node for `META_WRITES_ENV_GATE = "true"`, which is set by the parser when a step contains a write to `$GITHUB_ENV`, `$GITHUB_PATH`, or the ADO equivalent (`##vso[task.setvariable]`). When found, the rule fires with graduated severity based on the step's trust zone and whether it holds authority.

## Risk

`$GITHUB_ENV` and `$GITHUB_PATH` are special files that modify the execution environment for all subsequent steps in the same job. Writing to them is an intentional GitHub Actions feature for setting environment variables and extending `$PATH`. But they are a two-edged capability.

The attack scenarios:

**Untrusted step writes to `$GITHUB_ENV` (Critical):**
1. An unpinned third-party action (or one running attacker-controlled code) executes.
2. It writes `MY_SECRET=exfiltrated_value` to `$GITHUB_ENV`.
3. Every subsequent step in the job now has `MY_SECRET` set to the attacker-controlled value.
4. If a later step passes `$MY_SECRET` to an external service, or uses it as a credential, the attacker controls that credential.

**Step with secrets writes to `$GITHUB_ENV` (High):**
1. A step that has access to `$SECRET` writes it (intentionally or accidentally) to `$GITHUB_ENV`.
2. The secret is now in the environment of every subsequent step, including any third-party action that runs later.
3. A compromised later action can read and exfiltrate it.

**`$GITHUB_PATH` hijacking:**
1. A step writes `/attacker-controlled-dir` to `$GITHUB_PATH`.
2. Subsequent steps invoke tools by name (e.g., `python`, `curl`, `terraform`).
3. The attacker's binary in the injected path intercepts the invocation and executes with the step's full authority.

This vector is why GitHub introduced step-level `env:` scoping — values written to `$GITHUB_ENV` are harder to contain than per-step environment variables.

## Remediation

1. **Audit every `$GITHUB_ENV` and `$GITHUB_PATH` write in your workflow:**
   ```bash
   grep -rn 'GITHUB_ENV\|GITHUB_PATH\|vso\[task.setvariable\]' .github/workflows/
   ```
   For each match, ask: who controls this step? Could the value written be attacker-influenced?

2. **Use step outputs instead of environment injection where possible:**
   ```yaml
   # Instead of: echo "RESULT=value" >> $GITHUB_ENV
   - name: Compute result
     id: compute
     run: echo "result=value" >> $GITHUB_OUTPUT
   
   - name: Use result
     run: echo "${{ steps.compute.outputs.result }}"
   ```
   Step outputs are explicitly scoped and cannot be read by untrusted intermediate steps.

3. **If you must write to `$GITHUB_ENV`:** Ensure the writing step is SHA-pinned and first-party. Never write attacker-influenced values (PR body, issue title, commit message) to `$GITHUB_ENV`.

4. **For `$GITHUB_PATH` writes:** Prefer using absolute paths in `run:` steps instead of mutating `$PATH`. If a tool needs to be on `$PATH`, install it before the job's critical steps and verify its checksum.

5. **Apply GitHub's step-level `env:` isolation** (where available in newer runner versions) to limit which steps can read which variables.

6. **Verify:** Re-run `taudit scan`. The finding will persist as long as the `$GITHUB_ENV` write exists — it is a structural signal. Resolve it by using step outputs instead, or by ensuring only trusted, SHA-pinned code writes to the environment gate.

## See also

- [untrusted_with_authority](untrusted_with_authority.md) — direct credential access by untrusted steps
- [authority_propagation](authority_propagation.md) — multi-hop propagation through delegation edges
- [GitHub Actions — environment files](https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-an-environment-variable)
- [GitHub Actions — passing information between steps](https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-an-output-parameter)
