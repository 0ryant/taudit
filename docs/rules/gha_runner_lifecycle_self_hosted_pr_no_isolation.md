# GHA Self-Hosted Runner On PR Trigger Without Workspace Isolation

**Rule ID:** `gha_runner_lifecycle_self_hosted_pr_no_isolation`
**Severity:** High
**Category:** Trust
**Tags:** security, runner, self-hosted, github-actions

## Detection

Fires when:

- a job specifies `runs-on:` with `self-hosted` in the labels (any
  shape: `[self-hosted, ...]`, `self-hosted`, or
  `[self-hosted, <pool>, <arch>]`); AND
- the workflow's `on:` block includes `pull_request`,
  `pull_request_target`, `workflow_run` whose upstream is
  PR-triggered, or `issue_comment`; AND
- the job does NOT use a container-based ephemeral runner (`container:`
  with a fresh image), does NOT specify `workspace: { clean: all }`
  (Azure-DevOps-style; GHA equivalent is `actions/checkout` with
  `clean: true` AND a clean job hook), and does NOT use ARC
  ephemeral-pod semantics.

## Risk

Self-hosted GitHub Actions runners persist their workspace by default
across jobs. Files written to `$GITHUB_WORKSPACE` or
`$RUNNER_TEMP` by one job can be observed by a subsequent job on the
same runner. A PR-author whose code runs on the self-hosted runner can:

- read state left by prior privileged jobs (cached credentials,
  partial build artifacts, env files);
- write state that subsequent privileged jobs trust (poisoned
  `node_modules/`, modified shell scripts, plant credentials);
- exhaust runner-local resources to influence scheduling.

In the public corpus, 18 of 18 PR-trigger workflows that pin to
self-hosted runners lack workspace isolation. The class is pervasive
and uniform.

This is the GHA-native counterpart to the Azure-DevOps-specific
`shared_self_hosted_pool_no_isolation` rule. The boundary is the
runner's own filesystem and process state, not the workflow's
authority alone.

## Remediation

Use ephemeral runners for any PR-trigger workflow:

- ARC (Actions Runner Controller) with `ephemeral: true` and one job
  per pod;
- GitHub-hosted runners (`runs-on: ubuntu-latest`) where the workload
  fits;
- container-based jobs (`container: { image: <pinned-digest> }`) with
  a fresh container per job.

For existing self-hosted pools, gate PR triggers behind a label that
restricts execution to MAINTAINER/OWNER actors AND clean the workspace
before each job:

```yaml
- name: Clean workspace before run
  run: rm -rf "$GITHUB_WORKSPACE"/* "$GITHUB_WORKSPACE"/.* 2>/dev/null || true
```

Note that workspace cleanup is best-effort; a determined attacker can
plant state outside `$GITHUB_WORKSPACE` (in `$HOME`, `/tmp`, the
runner's tool cache). The only sound mitigation is ephemeral runners.
