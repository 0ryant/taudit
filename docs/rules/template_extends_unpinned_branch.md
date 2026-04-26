# Template Extends Unpinned Branch

**Rule ID:** `template_extends_unpinned_branch`
**Severity:** High
**Category:** Supply Chain
**Tags:** security, supply-chain
**Platform:** Azure DevOps only

## Detection

taudit walks every entry in the pipeline's `resources.repositories[]` block and classifies its `ref:` value:

| `ref:` value | Classification | Behaviour |
|---|---|---|
| `refs/tags/<x>` | Pinned (immutable) | Does not fire |
| 40-char hex SHA (bare or `refs/heads/<sha>`) | Pinned | Does not fire |
| `refs/heads/<branch_name>` | Mutable branch | Fires |
| Bare branch name (`main`, `develop`, ...) | Mutable branch | Fires |
| Field absent | Default branch | Fires |

An entry with an **explicit `ref:` field** that resolves to a mutable branch always fires — the explicit branch ref signals intent to consume, even when the consumer is in an included template file outside the per-file scan boundary (a common ADO pattern: a root pipeline declares the repo and child template files do `checkout: <alias>`).

An entry with **no `ref:` field at all** only fires when an in-file consumer is detected. taudit looks for three usage shapes:

1. `extends: { template: <path>@<alias> }` at the pipeline root
2. `template: <path>@<alias>` anywhere in stages, jobs, or steps
3. `checkout: <alias>` inside a job's steps

This split avoids noise on purely vestigial declarations — a leftover `resources.repositories[]` entry with no ref and no consumer is not an active attack surface.

This is the ADO equivalent of [unpinned_action](unpinned_action.md). Both rules detect the same supply-chain class — a pipeline accepts code from a mutable upstream pointer — but the detection logic and remediation steps are platform-specific, so they are kept as separate rules.

## Risk

Whoever owns the target branch of an unpinned `resources.repositories[]` entry can inject steps into every consuming pipeline at the next run. The attack path:

1. Your `azure-pipelines.yml` declares:
   ```yaml
   resources:
     repositories:
       - repository: shared-templates
         type: git
         name: Platform/shared-templates
         ref: refs/heads/main          # <- mutable
   extends:
     template: pipeline.yml@shared-templates
   ```
2. The `Platform/shared-templates` repo's default branch is `main`, currently at commit `abc123`.
3. An attacker who gains write access to `main` (compromised maintainer account, an over-permissive branch policy, an insider) pushes a new commit that adds a step to `pipeline.yml`.
4. On the next run of your pipeline, ADO resolves `@shared-templates` against the new tip of `main`. The injected step executes with whatever authority your pipeline holds — variable groups, service connections, OIDC federations, the System.AccessToken.
5. If your pipeline also runs on a self-hosted agent pool ([self_hosted_pool_pr_hijack](self_hosted_pool_pr_hijack.md)), the injected step can persist on the runner across pipelines from other teams.

This is a known supply-chain attack class. The risk is identical in shape to compromised GitHub Actions ([unpinned_action](unpinned_action.md)) — the mitigation strategy is also identical: pin the upstream pointer to something immutable.

## Remediation

1. **Find the SHA you currently consume:**
   ```bash
   # In an ADO Repos repo, get the latest commit on the branch you trust today:
   az repos ref list --repository "shared-templates" \
     --query "[?name=='refs/heads/main'].objectId" -o tsv
   # → a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0
   ```

2. **Replace the mutable ref with a SHA, keeping the branch as a comment:**
   ```yaml
   resources:
     repositories:
       - repository: shared-templates
         type: git
         name: Platform/shared-templates
         ref: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0  # main as of 2026-04-26
   ```
   Or pin to a tag if the upstream repo publishes them:
   ```yaml
         ref: refs/tags/v1.4.2
   ```

3. **Lock the upstream branch policy:** Even with SHA pinning, when you bump the SHA you should know that the new commit was reviewed. Configure the upstream `Platform/shared-templates` repo with required reviewers, build validation, and push protection on `main`.

4. **For `checkout: <alias>` consumers:** The same pin applies — ADO will check out the repo at the alias's `ref:`, which means an unpinned ref lands attacker-controlled code in the workspace before any of your steps run.

5. **Verify:** Re-run `taudit scan`. The finding should disappear once `ref:` is a 40-char hex SHA or `refs/tags/<x>`.

## See also

- [unpinned_action](unpinned_action.md) — same supply-chain class for GitHub Actions `uses:` references
- [self_hosted_pool_pr_hijack](self_hosted_pool_pr_hijack.md) — when this finding combines with a shared agent pool, the blast radius extends to other pipelines on the same pool
- [cross_workflow_authority_chain](cross_workflow_authority_chain.md) — covers the case where the consuming pipeline holds authority that the resolved template inherits
- [Azure Pipelines: Repository resources](https://learn.microsoft.com/en-us/azure/devops/pipelines/process/resources?view=azure-devops#define-a-repositories-resource)
