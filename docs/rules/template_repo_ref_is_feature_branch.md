# Template Repo Ref Is Feature Branch

**Rule ID:** `template_repo_ref_is_feature_branch`
**Severity:** High
**Category:** Supply Chain
**Tags:** security, supply-chain, azure-devops
**Platform:** Azure DevOps only

## Detection

taudit walks every entry in the pipeline's `resources.repositories[]` block and inspects the `ref:` value. The rule fires when the `ref:` resolves to a **feature-class branch** — anything outside the platform-blessed trunk set:

| Branch shape | Treated as | Behaviour |
|---|---|---|
| `main`, `master` (with or without `refs/heads/` prefix) | Trunk | Does not fire |
| `release/*`, `releases/*` | Trunk | Does not fire |
| `hotfix/*`, `hotfixes/*` | Trunk | Does not fire |
| 40-char hex SHA, `refs/tags/*`, `refs/heads/<sha>` | Pinned | Does not fire (not mutable) |
| Field absent | Default branch | Does not fire (handled by [template_extends_unpinned_branch](template_extends_unpinned_branch.md)) |
| `feature/*`, `topic/*`, `dev/*`, `wip/*`, `users/*`, `develop`, anything else | **Feature-class** | **Fires** |

Comparison is case-insensitive and handles both bare branch names (`feature/maps-network`) and the fully-qualified form (`refs/heads/feature/maps-network`).

This rule **co-fires with [template_extends_unpinned_branch](template_extends_unpinned_branch.md)** by design: the parent rule says "this `resources.repositories[]` entry isn't pinned to an immutable target"; this rule adds "and the branch it points to has weaker push protection than the trunk". They describe the same entry from two different angles, and an entry that triggers this rule will always trigger the parent rule too.

## Risk

The attack model is structurally identical to [template_extends_unpinned_branch](template_extends_unpinned_branch.md), but the blast radius is larger: feature branches typically have weaker push protection than the trunk.

A typical Azure DevOps org configures the trunk (`main`) with required reviewers, build validation, and push restrictions. Feature branches almost never have those policies — any developer with write access to the repo can `git push` directly to `feature/<x>` without code review.

When a production pipeline pins its template library checkout to a feature branch:

1. The pipeline `azure-pipelines.yml` declares:
   ```yaml
   resources:
     repositories:
       - repository: templateLibRepo
         type: git
         name: Template Library/Template Library
         ref: feature/maps-network          # <- a developer's WIP branch
   jobs:
     - job: deploy
       steps:
         - checkout: templateLibRepo
         - template: templates/deploy.yaml@templateLibRepo
   ```
2. Any developer with write access to the Template Library repo can push to `feature/maps-network` without a code review (no branch protection on the feature branch).
3. The malicious commit lands. The next run of the production pipeline checks out the feature branch and executes the injected steps with whatever authority the consuming pipeline holds — service connections, variable groups, OIDC federations, `System.AccessToken`.
4. If the consuming pipeline runs on a self-hosted agent pool (see [self_hosted_pool_pr_hijack](self_hosted_pool_pr_hijack.md)), the injected step can persist on the runner and intercept other teams' pipelines.

The corpus pattern this rule was built for: enterprise Active Directory and file server deployment pipelines that pin `Template Library/Template Library` to `feature/maps-network`. These pipelines deploy to domain controllers — RCE on the template feature branch is RCE on enterprise AD.

## Remediation

Pinning to `main` (or any other trunk branch) is an immediate hygiene improvement, but not the final remediation — `main` is still mutable, and `template_extends_unpinned_branch` will continue to fire on it. The proper fix is to pin to a SHA or a tag.

1. **Find the SHA you currently consume:**
   ```bash
   az repos ref list --repository "Template Library" \
     --query "[?name=='refs/heads/feature/maps-network'].objectId" -o tsv
   # → a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0
   ```

2. **Replace the feature-branch ref with a SHA:**
   ```yaml
   resources:
     repositories:
       - repository: templateLibRepo
         type: git
         name: Template Library/Template Library
         ref: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0  # feature/maps-network as of 2026-04-26
   ```
   Or merge the feature branch's contents into `main` (or a tagged release) and pin to that:
   ```yaml
         ref: refs/tags/template-lib-v1.4.2
   ```

3. **Lock the upstream branch policy:** Even after SHA pinning, when you bump the SHA you should know that the new commit was reviewed. Configure the upstream `Template Library` repo with required reviewers and build validation on `main`.

4. **Verify:** Re-run `taudit scan`. Both this rule and `template_extends_unpinned_branch` should disappear once `ref:` is a 40-char hex SHA or `refs/tags/<x>`.

## See also

- [template_extends_unpinned_branch](template_extends_unpinned_branch.md) — the parent rule that fires on any non-pinned `resources.repositories[]` entry, including pins to the trunk. This rule is its strict refinement for the higher-risk feature-branch subcase.
- [unpinned_action](unpinned_action.md) — same supply-chain class for GitHub Actions `uses:` references
- [self_hosted_pool_pr_hijack](self_hosted_pool_pr_hijack.md) — when this finding combines with a shared self-hosted pool, the blast radius extends to other pipelines on the same pool
- [Azure Pipelines: Repository resources](https://learn.microsoft.com/en-us/azure/devops/pipelines/process/resources?view=azure-devops#define-a-repositories-resource)
