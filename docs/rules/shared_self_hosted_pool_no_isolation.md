# Shared Self-Hosted Pool No Isolation

**Rule ID:** `shared_self_hosted_pool_no_isolation`
**Severity:** High
**Category:** Injection
**Tags:** security, injection, azure-devops
**Platform:** Azure DevOps only

## Detection

taudit fires when:
1. The pipeline platform is Azure DevOps (`META_PLATFORM = "azure-devops"`).
2. At least one Image node (pool) has `META_SELF_HOSTED = "true"`.
3. That pool does NOT have `META_WORKSPACE_CLEAN = "true"` (no `workspace: { clean: all }` declared).

Microsoft-hosted agents are ephemeral and are never flagged. The rule fires once per self-hosted pool node that lacks workspace isolation.

## Risk

Self-hosted agents retain their workspace directory between pipeline runs. Without `workspace: { clean: all }`, artefacts, compiled binaries, injected git hooks, and environment files from one run persist on disk for the next run on the same agent — which may be a privileged deployment pipeline running in a different security context.

Attack path:

1. A low-trust pipeline run (e.g., a PR validation job) executes on the self-hosted agent.
2. The run deliberately or accidentally writes malicious files to the shared workspace: git hooks, shell scripts, compiled binaries, `.env` files with injected content.
3. Those files persist because no workspace clean is configured.
4. A subsequent high-privilege run (e.g., a production deployment) starts on the same agent and picks up the poisoned workspace state — git hooks fire, injected environment variables load, or stale binaries execute.

Unlike `self_hosted_pool_pr_hijack`, this rule does not require a PR trigger or a repository checkout. Any combination of low-trust and high-privilege runs sharing an agent without isolation is the risk.

This has appeared in real CI/CD incidents. The 88× corpus hit rate on internal ADO datasets confirms it is widespread.

## Remediation

**Preferred — add workspace isolation to all jobs using self-hosted pools:**

```yaml
# Before
jobs:
  - job: Build
    pool:
      name: MyPrivatePool

# After
jobs:
  - job: Build
    pool:
      name: MyPrivatePool
    workspace:
      clean: all   # wipes sources, binaries, and outputs before each run
```

`workspace: { clean: all }` is the strongest option. ADO also supports `clean: resources` (sources only) and `clean: outputs` (output directories only), but `all` is the recommended choice for isolation.

**Alternative — use Microsoft-hosted (ephemeral) agents:**

```yaml
jobs:
  - job: Build
    pool:
      vmImage: ubuntu-latest   # ephemeral — destroyed after each run
```

Microsoft-hosted agents are created fresh per run and destroyed at completion. No cross-run contamination is possible.

**If self-hosted is required for hardware or network access:**

Use Azure Virtual Machine Scale Set agent pools with "Automatically tear down after each use" enabled, or Kubernetes-based ephemeral agent pools. Both give ephemeral-style isolation with self-hosted capabilities.

**Verify:** After adding `workspace: { clean: all }`, re-run `taudit scan`. The finding resolves when the workspace clean metadata is detected on the pool node.

## See also

- [self_hosted_pool_pr_hijack](self_hosted_pool_pr_hijack.md) — a related but narrower rule: PR trigger + self-hosted + checkout (git hook injection path)
- [variable_group_in_pr_job](variable_group_in_pr_job.md) — credentials accessible from PR-triggered jobs
- [ADO workspace options reference](https://learn.microsoft.com/en-us/azure/devops/pipelines/yaml-schema/jobs-job-workspace)
- [ADO scale set agents (ephemeral)](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/scale-set-agents)
