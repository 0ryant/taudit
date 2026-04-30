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
- **quality (Ubuntu):** `fmt`, `clippy`, Python invariant schema check, `cargo insta`, `cargo deny`, `cargo audit`, **Trivy + Checkov + Gitleaks** via `scripts/quality-gate.sh ci-governance`, contract tests, **release build**, **golden-paths**, **taudit self-scan** of `.github/workflows/` and **`azure-pipelines.yml`** (SARIF artifacts), advisory `taudit verify` on starter + ADO example policy, **fuzz smoke** on `main` only.
- **Parallel security:** full **`cargo deny`** (incl. advisories) and **hard-fail** **`taudit scan`** of `.github/workflows/` at high+ (SARIF artifact).

### SARIF in ADO

Pipeline publishes **`PublishPipelineArtifact@1`** for SARIF. To feed **Azure DevOps Advanced Security** or other tools, add a follow-up task (e.g. **SARIF SAST Scans** tab / extension) that ingests those artifacts — wiring is org-specific.

### Secrets

The mirror **does not** publish to crates.io or GHCR. No secrets are required for the default YAML. Add variable groups only if you extend the pipeline (e.g. private crate mirrors).

---

## GitLab

### Setup

- **GitLab.com or self-managed:** push this repo (or enable a **Pull mirror** from GitHub). GitLab auto-discovers **`.gitlab-ci.yml`**.
- Default image: **`rust:1.88-bookworm`** (aligned with GitHub’s Rust **1.88**).

### What runs

- **`test:linux`** — `cargo test --workspace`.
- **`quality:linux`** — same Rust + Python + insta + deny + audit + governance gate + contracts + release build + golden paths + **taudit scan** of `.github/workflows/` and **`.gitlab-ci.yml`** (artifacts), plus advisory verify steps.
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

## Related

- [Stack integrations index](index.md) — tsafe / CellOS / `stack-integration` on GitHub.
- [Release strategy](../release-strategy.md) — stable vs edge; registry vs host CI.
