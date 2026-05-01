# Hygiene pass decisions (deep dive)

During a repo hygiene pass, two sets of **uncommitted** changes were evaluated: **security workflow triggers** and **experimental CI governance**. This document records **why** choices were made so the next iteration does not re-litigate them blindly.

## 1. Keep `pull_request` on `.github/workflows/security.yml`

**What showed up:** a local edit removed the `pull_request:` trigger so the workflow would only run on `push` to `main` and on `schedule`.

**Why that is the wrong default for taudit:**

- **PRs are the highest-risk surface** for dependency and workflow edits. `cargo audit`, `cargo deny`, and related gates exist partly to catch **what the PR introduces**, not only what landed on `main` yesterday.
- **Fail closed on the contribution path:** dropping PR coverage moves discovery to post-merge or weekly cron, widening the merge window for vulnerable deps or copied-paste workflow YAML.

**Right choice:** retain **`pull_request`** (alongside `push` / `schedule` as designed) so every PR gets the same security signal as `main`, modulo intentional path filters elsewhere.

## 2. Do not merge ad hoc “CellOS Docker supply-chain gate” into taudit CI until it is contractually pinned

**What showed up:** `governance.yml` and `azure-pipelines.yml` were rewritten to call **`0ryant/CellOS`** composite `@main` and **`ghcr.io/.../supply-chain-gate:latest`** on Azure.

**Problems with that snapshot:**

| Issue | Detail |
|--------|--------|
| **Non-reproducible refs** | `@main` and `:latest` move. A green pipeline today is not an auditable artifact tomorrow. |
| **Coupling** | taudit’s governance story lives in **this** repo (`scripts/tool-versions.env`, `install-governance-tools.sh`, `quality-gate.sh`). Swapping to an external image without an ADR + pin transfers the contract elsewhere without version alignment. |
| **Reviewability** | The diff was large, cross-cutting, and not tied to a tracked issue — high risk of “works on my org” configuration leaking in. |

**Right choice:** keep the **pinned shell installer + same-repo scripts** until there is an explicit decision to:

1. Pin the composite action to a **full commit SHA** (or version tag backed by SHA).
2. Pin the container image to a **digest**.
3. Document the trust boundary in `docs/integrations/` (who updates pins, cadence, failure modes).

## 3. Quality workflow matrix and `paths-ignore`

**What shipped (separate commit):** `quality.yml` uses `paths-ignore` for doc-only paths and runs the **full OS matrix on `push` to `main`**, single OS on PRs.

**Rationale:** reduces queue heat on typo PRs while keeping **main** representative across runners. Security and governance workflows are **not** doc-gated the same way on purpose.

---

When any of the above needs revisiting, add an **ADR** or extend `docs/integrations/ci-mirrors.md` rather than relying on chat-only context.
