# Untrusted With Authority

**Rule ID:** `untrusted_with_authority`
**Severity:** Critical (explicit secrets/identities) / Info (ADO System.AccessToken)
**Category:** Propagation
**Tags:** security, privilege-escalation

## Detection

taudit looks for Step nodes in the Untrusted trust zone that have a direct `HasAccessTo` edge to a Secret or Identity node. This rule is distinct from `authority_propagation`: it fires on the direct edge rather than a multi-hop BFS path. No propagation traversal is required — the untrusted step already has the credential in scope.

Severity is Critical for explicit secrets (user-defined) and explicit service connections. For ADO `System.AccessToken`, severity is Info because the platform injects this token into every task by design — it is structural access, not a misconfiguration.

An additional check fires when a secret is passed as a `-var` flag argument to a tool like Terraform: the value appears in pipeline log output before secret masking runs. These findings carry an extra note in the message.

## Risk

This is a direct, zero-hop credential exposure. The attack path:

1. A step in your workflow runs code from an untrusted source (an unpinned third-party action, or a step calling out to an external URL).
2. That code executes with the full process environment, which includes any secrets you've placed in `env:` at the job or step level.
3. The untrusted code reads the secret from the environment and exfiltrates it.

The difference from `authority_propagation` is immediacy. There's no multi-step chain — the credential is directly present in the execution context of code you don't fully control. If the action is also unpinned (mutable tag), the attacker only needs to compromise the action's repository once to get credentials from every workflow that depends on it.

For CLI flag exposure (`-var "KEY=$(SECRET)"`): the secret value appears verbatim in the command log of the pipeline run, making it readable by anyone with pipeline read access — no compromise required.

## Remediation

1. **Immediate — check whether the step actually needs the credential:**
   If it doesn't, remove the `env:` entry for that secret from the step.

2. **Scope to step level, not job level:**
   ```yaml
   jobs:
     build:
       # Remove secrets from here — they flow to every step
       env:
         SECRET: ${{ secrets.SECRET }}  # BAD
       steps:
         - uses: untrusted-action/foo@v1  # gets SECRET from job env
         - name: actual-step-that-needs-it
           env:
             SECRET: ${{ secrets.SECRET }}  # GOOD — only this step
           run: ./use-secret.sh
   ```

3. **Pin the action before giving it any credentials:**
   If the step must receive the secret, pin the action to a full SHA first:
   ```yaml
   - uses: some-org/some-action@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2  # v1.2.3
     env:
       SECRET: ${{ secrets.SECRET }}
   ```

4. **CLI flag exposure — move to environment variable:**
   ```bash
   # Before (value visible in logs)
   terraform plan -var "db_password=$(DB_PASSWORD)"
   
   # After (environment variable — masked in logs)
   TF_VAR_db_password=$DB_PASSWORD terraform plan
   ```

5. **For ADO System.AccessToken (Info finding):** The token is platform-injected and cannot be prevented. Minimise the blast radius by setting it explicitly on only the tasks that require it:
   ```yaml
   - task: SomeTask@1
     env:
       SYSTEM_ACCESSTOKEN: $(System.AccessToken)  # only here, not job-wide
   ```

6. **Verify:** Re-run `taudit scan`. Critical findings should be resolved. Info findings for System.AccessToken are expected if you use ADO — they document the structural exposure for audit purposes.

## See also

- [authority_propagation](authority_propagation.md) — multi-hop version of this finding
- [unpinned_action](unpinned_action.md) — the Untrusted step is usually also unpinned
- [GitHub Actions security hardening — least privilege access](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-secrets)
