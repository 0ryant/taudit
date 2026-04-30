# CI mirrors — Azure DevOps, GitLab, Bitbucket

This repository’s **primary** CI is **GitHub Actions** (`.github/workflows/`). The files below **mirror** the same quality and security intent on other hosts so we exercise taudit across the ecosystems we ship for (**GitHub Actions**, **Azure DevOps**, **GitLab CI**) and keep **Bitbucket** build hygiene ready until a native parser exists.

| Host | Definition file | taudit native scan of *this* CI file |
|------|-------------------|--------------------------------------|
| GitHub Actions | `.github/workflows/*.yml` | Yes (`--platform github-actions`) |
| Azure DevOps | `azure-pipelines.yml` (repo root) | Yes (`--platform azure-devops`) |
| GitLab | `.gitlab-ci.yml` | Yes (`--platform gitlab`) |
| Bitbucket Pipelines | `bitbucket-pipelines.yml` | **Not yet** — mirror runs Rust gates only |

---

## Azure DevOps (org **0ryant**)

### One-time setup

1. In **https://dev.azure.com/0ryant**, create or pick a **project** (e.g. `taudit`).
2. **Pipelines** → **New pipeline** → **GitHub** (YAML) → Authorize Azure Pipelines for your GitHub account/org if prompted.
3. Select repo **`0ryant/taudit`**, branch **`main`**, choose **Existing Azure Pipelines YAML file**, path **`/azure-pipelines.yml`**.
4. Save and run. On first run, grant **“Access to all pipelines”** / **OAuth** scope so ADO can read the repo.

### What the mirror runs

- **Parallel:** `test` on **Ubuntu**, **macOS**, **Windows** (`cargo test --workspace`).
- **quality (Ubuntu):** `fmt`, `clippy`, Python invariant schema check, `cargo insta`, `cargo deny`, `cargo audit`, **`scripts/install-ci-linters.sh`** (**actionlint** + **yamllint**), **Trivy + Checkov + Gitleaks** via `scripts/quality-gate.sh ci-governance`, contract tests, **release build**, **golden-paths**, **taudit self-scan** of `.github/workflows/` and **`azure-pipelines.yml`** (SARIF artifacts), advisory `taudit verify` on starter + ADO example policy, **fuzz smoke** on `main` only.
- **Parallel security:** full **`cargo deny`** (incl. advisories) and **hard-fail** **`taudit scan`** of `.github/workflows/` at high+ (SARIF artifact).

### SARIF in ADO

Pipeline publishes **`PublishPipelineArtifact@1`** for SARIF. To feed **Azure DevOps Advanced Security** or other tools, add a follow-up task (e.g. **SARIF SAST Scans** tab / extension) that ingests those artifacts — wiring is org-specific.

### Secrets

The mirror **does not** publish to crates.io or GHCR. No secrets are required for the default YAML. Add variable groups only if you extend the pipeline (e.g. private crate mirrors).

### Stack-integration: separate ADO pipeline (sketch)

GitHub’s **[`stack-integration.yml`](../../.github/workflows/stack-integration.yml)** clones **tsafe** and **CellOS** (or pulls **CellOS** from **GHCR**), builds **taudit**, scans tsafe’s **`.github/workflows/`**, then runs **`scripts/cellos_smoke_docker.sh`** or **`scripts/cellos_smoke.sh`**. That flow needs **cross-repo GitHub read** and **GHCR read** — credentials **Actions** gets “for free” from **`GITHUB_TOKEN` + `packages:read`** are **not** available the same way on Azure Pipelines when the YAML lives in GitHub but runs on ADO.

**Keep it out of root [`azure-pipelines.yml`](../../azure-pipelines.yml)** so the default mirror stays **secretless** and fork-safe. Instead:

1. **Add a second pipeline** in ADO → **New pipeline** → same GitHub repo → YAML path **`/azure-pipelines.stack-integration.yml`** (skeleton in-repo).
2. **Triggers:** the skeleton uses **`trigger: none`** / **`pr: none`** so it only runs when you **Run pipeline** (or add a **scheduled** run / a **branch policy** later). That matches “optional stack smoke” better than every `main` push.
3. **GitHub access (pick one pattern):**
   - **Service connection (recommended):** **Project settings** → **Service connections** → **New** → **GitHub** (OAuth or PAT). Grant **read** on **`{org}/tsafe`** and **`{org}/CellOS`**. In YAML **`resources.repositories`**, set **`endpoint:`** to that connection’s name and **`name:`** to `owner/repo` for each sibling (see comments in **`azure-pipelines.stack-integration.yml`**).
   - **PAT in a variable group:** store a fine-grained or classic PAT (`repo`, **`read:packages`** for GHCR) as a **secret** variable; use **`git clone https://$(GITHUB_PAT)@github.com/...`** in a script step instead of `resources.repositories` if your org avoids extra service connections (rotate PAT; never echo it).
4. **GHCR login:** before **`docker pull ghcr.io/.../cellos-supervisor`**, run **`docker login ghcr.io`** with the same PAT (**`read:packages`**) or a dedicated token; set **`CELLOS_SUPERVISOR_IMAGE`** / **`CELLOS_SUPERVISOR_TAG`** as pipeline variables to mirror GitHub **`vars`**. **`tsafe` vault CLI is still not invoked** — same contract as GitHub stack-integration.
5. **Correlation:** export **`TAUDIT_CORRELATION_ID`** like **`ado-stack-tsafe-$(Build.BuildId)-$(System.JobAttempt)`** / **`ado-stack-cellos-...`** so CloudEvents line up with [GitHub stack-integration](index.md#github-actions-stack-integration-this-repo).
6. **Failure policy:** decide per org whether a missing sibling (**`continueOnError: true`** on checkout) should **warn** (log issue) or **fail** the job; GitHub uses notices + soft skips for forks.

After you replace placeholders and wire secrets, add a **branch policy** or **schedule** only if you want this on every `main` commit; otherwise treat it as a **gated smoke** for people who maintain the full stack.

The committed **[`azure-pipelines.stack-integration.yml`](../../azure-pipelines.stack-integration.yml)** checks out **CellOS** on every run so the **GHCR-failed** path can run `cellos_smoke.sh` without a second dynamic checkout; you can optimize later (e.g. clone only after a failed `docker pull`).

---

## GitLab

### Setup

- **GitLab.com or self-managed:** push this repo (or enable a **Pull mirror** from GitHub). GitLab auto-discovers **`.gitlab-ci.yml`**.
- Default image: **`rust:1.88-bookworm`** (aligned with GitHub’s Rust **1.88**).

### What runs

- **`test:linux`** — `cargo test --workspace`.
- **`quality:linux`** — same Rust + Python + insta + deny + audit + **`install-ci-linters.sh`** + governance gate + contracts + release build + golden paths + **taudit scan** of `.github/workflows/` and **`.gitlab-ci.yml`** (artifacts), plus advisory verify steps.
- **`security:*`** — full `cargo deny` and hard-fail `taudit scan` of `.github/workflows/`.

### Rules

Jobs run for **merge requests** and **`main`** (`rules:`). Adjust for your default branch name if forked.

---

## Bitbucket Pipelines

### Setup

Enable **Pipelines** in the Bitbucket repo settings. **`bitbucket-pipelines.yml`** defines **parallel** steps: fmt/clippy/test and deny/audit/contract tests.

### taudit

**Bitbucket Pipelines YAML is not yet modeled** in taudit’s parsers. This file exists so:

- CI parity and **Rust** quality travel with the repo.
- When/if a Bitbucket parser lands, we can add **`taudit scan bitbucket-pipelines.yml`** the same way as ADO/GitLab.

Track parser / rule work in [`docs/ROADMAP.md`](../ROADMAP.md) if you open a dedicated item.

---

## Keeping mirrors honest

- When you change **GitHub** `quality.yml`, update **`azure-pipelines.yml`**, **`.gitlab-ci.yml`**, and (if applicable) **`bitbucket-pipelines.yml`** in the same PR, or follow immediately with a **“ci: sync mirrors”** commit.
- **Rust toolchain** version is pinned in comments / `variables` — bump with the same cadence as `.github/workflows/quality.yml` (dtolnay pin).
- **Governance** (`ci-governance`) still scans the **whole repo** (Trivy fs, Checkov on `.github/`, Gitleaks) — that is intentional: we keep scanning **GitHub workflow definitions** even when CI runs on ADO/GitLab, because those files remain in-tree.

---

## FinOps (GitHub Actions)

Terraform smoke under **`infra/finops-smoke/`** and workflow **[`.github/workflows/finops.yml`](../../.github/workflows/finops.yml)** run **`terraform fmt` / `validate`** on path changes; **Infracost** runs when repository secret **`INFRACOST_API_KEY`** is configured ([`infra/finops-smoke/README.md`](../../infra/finops-smoke/README.md)). This lane is **GitHub-only** for now (not mirrored on ADO / GitLab).

---

## Related

- [Stack integrations index](index.md) — tsafe / CellOS / `stack-integration` on GitHub.
- Optional ADO parity: **[`azure-pipelines.stack-integration.yml`](../../azure-pipelines.stack-integration.yml)** + § **Stack-integration** above.
- [Release strategy](../release-strategy.md) — stable vs edge; registry vs host CI.
