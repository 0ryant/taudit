# Self-Hosted Pool PR Hijack

**Rule ID:** `self_hosted_pool_pr_hijack`
**Severity:** Critical
**Category:** Injection
**Tags:** security, injection
**Platform:** Azure DevOps only

## Detection

taudit fires when all three of the following are simultaneously true:
1. The pipeline has a `pr:` trigger.
2. At least one Image node has `META_SELF_HOSTED = "true"` (a self-hosted agent pool).
3. At least one Step has `META_CHECKOUT_SELF = "true"` (a checkout of the repository).

All three conditions must be present. A self-hosted pool on a non-PR pipeline is not flagged. A PR pipeline that runs on Microsoft-hosted agents is not flagged. The combination is what creates the attack vector.

## Risk

Self-hosted agents are shared infrastructure. Unlike Microsoft-hosted agents (which are destroyed after each run), self-hosted agents persist their filesystem state across pipeline runs. This persistence is the attack surface.

The attack path:

1. An external contributor opens a pull request.
2. The PR pipeline runs on a self-hosted agent and checks out the PR code.
3. The attacker's PR includes a `.git/hooks/post-checkout` script (or any other hook that fires during checkout).
4. Git executes the hook as part of the checkout. The hook copies itself to the agent's git global hooks directory or another persistent location.
5. The hook is now on the shared runner's filesystem.
6. The next time a legitimate run (on the main branch, with full deploy credentials) runs on the same agent, the hook executes — with the legitimate run's full authority.

Git hooks are not sandbox-aware. The hook process inherits the full environment of the pipeline: secrets, variable groups, service connections, everything. The attacker has now achieved persistent, lateral-movement-capable code execution on your build infrastructure without their code ever being merged.

This is not a theoretical attack. It has been demonstrated against CI/CD systems with shared agents. The shared-state nature of self-hosted agents is the root cause.

## Remediation

1. **Immediate — move PR pipelines to Microsoft-hosted (ephemeral) agents:**
   ```yaml
   # Before
   pool:
     name: MyPrivatePool  # self-hosted
   
   # After
   pool:
     vmImage: ubuntu-latest  # Microsoft-hosted, ephemeral, destroyed after run
   ```

2. **If self-hosted is required for PR pipelines** (e.g., for access to private network resources):

   **Use containerized ephemeral agents:** Configure your self-hosted agent pool to use Azure Container Instances or Kubernetes-based agent pools. Each pipeline run spins up a fresh container and destroys it at completion — no persistent filesystem state.

   ```bash
   # Azure Pipelines — configure scale set agent pool
   # Project Settings → Agent Pools → Add pool → Azure virtual machine scale set
   # Enable "Automatically tear down virtual machine after each use"
   ```

3. **Disable checkout in PR validation jobs that don't need source code:**
   ```yaml
   steps:
     - checkout: none  # no workspace contamination
     - task: SomeValidationTask@1
   ```

4. **If checkout is required on self-hosted for PRs:** Clean the git hooks directory before and after checkout:
   ```yaml
   - script: rm -rf /path/to/agent-work/.git/hooks
     displayName: Clean git hooks (defence in depth)
   - checkout: self
   - script: rm -rf $(Build.SourcesDirectory)/.git/hooks
     displayName: Remove PR-injected git hooks
   ```
   This is a compensating control, not a full fix. Ephemeral agents remain the correct solution.

5. **Verify:** Re-run `taudit scan`. The finding resolves when the PR pipeline no longer uses a self-hosted pool, or when the checkout is removed. If you have switched to ephemeral containerized agents, confirm by checking the pool configuration — taudit detects the `pool.name` field, so if you've changed to a Microsoft-hosted `vmImage`, the self-hosted marker will be absent.

## See also

- [checkout_self_pr_exposure](checkout_self_pr_exposure.md) — the checkout-on-PR risk (without the self-hosted persistence angle)
- [variable_group_in_pr_job](variable_group_in_pr_job.md) — credentials accessible from PR jobs
- [ADO scale set agent pools (ephemeral)](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/scale-set-agents)
- [ADO containerized agents](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/docker)
