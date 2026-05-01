# standardise-ecosystem.md — taudit

> This file is the authoritative ecosystem standard. AI assistants working in any of these repos should read this file before making CI or governance changes. Humans should read it before opening governance PRs.

This is a living standard and prompt source of truth — not a changelog or ADR. Treat its contents as binding for the three repos in the ecosystem (`taudit`, `CellOS`, `tsafe`). When you make changes here, propagate them to all three repo copies in the same change-set.

---

## Ecosystem identity

The ecosystem is composed of **three peer repositories** that together form a security-tooling stack:

| Repo | Role |
| --- | --- |
| **taudit** | Scans CI workflows for authority-propagation issues. |
| **tsafe** | Manages secrets and credentials. |
| **CellOS** | Provides microVM execution isolation. |

These are **peer repos**. They are not a monorepo, and they must mutually integrate in CI: each repo's governance job validates the other two ecosystem tools (see *Ecosystem CI integration* below).

---

## CI shape (mandatory for all repos)

Every repo MUST contain the following CI jobs. Job names are normative.

### 1. `governance` job
Runs on: `push` to `main`/`master` and on `pull_request`.

Required tools (pinned versions — see *Tool version pins*):
- `gitleaks` 8.30.1
- `trivy` 0.70.0
- `checkov` 3.2.497
- `taudit` 1.0.12
- `zizmor` 1.24.1

### 2. `quality` job
Runs on: `push` to `main`/`master` and on `pull_request`.

Required steps (in this order):
1. `cargo fmt --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace`
4. `cargo deny check`
5. `cargo audit`

### 3. `release` job
Runs on: `v*` tags only.

Required:
- Multi-platform builds (Linux x86_64, Linux aarch64, macOS x86_64, macOS aarch64, Windows x86_64 — adjust to repo's actual support matrix).
- SPDX SBOM emitted on every release (see *SBOM standard*).

### 4. `scheduled` jobs
Required cadence:
- **Weekly CVE sweep** — Monday.
- **Weekly mutation testing** — Monday.
- **Weekly fuzz** — Tuesday.

Demo and integration-only workflows MUST be `workflow_dispatch` (manual). No scheduled demos. No double-trigger on push + pull_request from the same branch.

---

## Ecosystem CI integration (mandatory for all three repos)

Every repo's `governance` job MUST also validate the other two ecosystem tools:

1. **tsafe smoke test** — validate the `tsafe` binary works (or run a deterministic mock if the binary is unavailable in the runner).
2. **taudit scan** — run `taudit` against the repo's own `.github/workflows` (and any mirror workflow directories).
3. **CellOS contract validation** — run fixture validation for CellOS contracts.

If a repo cannot perform one of these directly (e.g. environment isolation), it MUST stub the step with an explicit `mock` or `skip-with-reason` annotation in the workflow.

---

## Tool version pins (exact, do not drift)

```
GITLEAKS_VERSION=8.30.1
TRIVY_VERSION=0.70.0
CHECKOV_VERSION=3.2.497
TAUDIT_VERSION=1.0.12
ZIZMOR_VERSION=1.24.1
```

These versions MUST be updated across **all three repos simultaneously** when bumped. A version bump in one repo without the other two is a governance violation.

---

## Rust toolchain standard

- **MSRV: 1.88** (target for all three repos).
  - Current drift: `taudit` and `tsafe` are at 1.85 and need to be bumped.
- `rust-toolchain.toml` is **required** at the repo root with an explicit channel pin (e.g. `channel = "1.88.0"`). Do not pin to `stable`.
- Required components: `rustfmt`, `clippy`.

---

## Required linter config files

These files MUST exist at the repo root (not buried in CI scripts):

- `.clippy.toml` — clippy configuration. Clippy flags must NOT be defined only in CI scripts; local runs must match CI.
- `rustfmt.toml` — formatter configuration. Style must be deterministic across machines.

---

## Required governance files

Every repo MUST have all of the following:

- `SECURITY.md` — responsible-disclosure policy with a contact channel.
- `LICENSE` — plain-text file at repo root. Dual-licensed: **MIT OR Apache-2.0**.
- `.github/CODEOWNERS` — minimum content: `* @rytilcock`.
- `CONTRIBUTING.md` — local quality-gate instructions.

---

## `deny.toml` standards

Required settings:

- `yanked = "deny"`
- `unknown-git = "deny"` (NOT `warn` — this is a supply-chain control)
- `unknown-registry = "deny"`
- `confidence-threshold = 0.8`

License allowlist — minimum set:

- `MIT`
- `Apache-2.0`
- `Apache-2.0 WITH LLVM-exception`
- `BSD-2-Clause`
- `BSD-3-Clause`
- `ISC`
- `Zlib`
- `Unicode-3.0`
- `CDLA-Permissive-2.0`

Repo-specific bans (e.g. CellOS banning ML inference crates) are allowed and intentional — see *Non-goals*.

---

## SBOM standard

- **SPDX JSON** generated on every release (mandatory).
- **CycloneDX 1.5** also generated on every release (target).
  - `taudit` already emits both; `CellOS` and `tsafe` should match.

---

## Multi-platform CI mirrors

All three repos MUST maintain parallel CI on:

1. **GitHub Actions** — primary, source of truth.
2. **GitLab CI** — mirror.
3. **Azure DevOps** — mirror.
4. **Bitbucket Pipelines** — mirror.

All mirrors MUST pin the same tool versions as GitHub Actions. When the GitHub Actions workflow changes, mirrors are updated in the same change-set.

---

## SHA-pinned GitHub Actions

All `uses:` references MUST be pinned to a full commit SHA, with a comment naming the version tag:

```yaml
uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
```

No floating refs — `@v4`, `@main`, `@latest` are all forbidden.

---

## Pre-commit / pre-push hooks

- A `just install-hooks` (or equivalent) target MUST be available so developers can install the hooks with one command.
- **Pre-commit** runs:
  - `cargo fmt`
  - `cargo clippy`
  - `gitleaks` against staged files
  - `trivy` config scan
  - `taudit verify`
- **Pre-push** runs the pre-commit set plus:
  - `cargo test`
  - `cargo deny check`
  - `cargo audit`
  - Full-repo `gitleaks` (not staged-only)

---

## Release automation

- `taudit` and `CellOS` MUST adopt `release-plz`.
- `tsafe` already has it — use as the template.
- **Conventional Commits** are required for the automated changelog.

---

## Goals

- Identical security-scanning posture across all three repos.
- Any developer working across the ecosystem sees the same local gate experience.
- New repos in the ecosystem use the `rust-service-template` scaffold as a starting point.
- CI credit budget is conserved: no double triggers, demo workflows are `workflow_dispatch`-only.

## Non-goals

- Identical Cargo dependencies — each repo has different domain needs.
- Identical `deny.toml` ban lists — CellOS bans ML inference crates by design; this is intentional.
- Same application architecture — `cellos-lite`'s inference policy is a local exception.
- Merging into a monorepo.

---

## Repo-specific notes

These are taudit's intentional local deviations and follow-ups. They are acceptable as-is, but the listed gaps SHOULD close over time.

- **Reference status** — taudit has the most mature CI shape in the ecosystem. Treat its `governance` and `quality` job structure as the reference implementation that `CellOS` and `tsafe` are aligning to.
- **Shipped in-repo (taudit):** `rust-toolchain.toml` (**1.88.0**), `.github/CODEOWNERS`, `.clippy.toml`, `rustfmt.toml`, `scripts/tool-versions.env` + `scripts/install-governance-tools.sh` (pinned **gitleaks / trivy / checkov / zizmor**), `.github/workflows/governance.yml` (**job `governance`**), `.github/workflows/scheduled-fuzz.yml` (Tuesday), `.github/workflows/release-plz.yml` + `release-plz.toml` (**workflow_dispatch** until tokens are wired), `scripts/ecosystem-governance-integrations.sh` (tsafe / CellOS skip-with-reason stubs), **MSRV** `workspace.package.rust-version = "1.88"`.
- **SBOM** — taudit emits both **SPDX** and **CycloneDX 1.5**. This is the target shape; CellOS and tsafe should match.
- **Release automation** — `release-plz` workflow is present (manual); enable `push: branches: [main]` and publishing secrets when ready to drive releases from conventional commits.
