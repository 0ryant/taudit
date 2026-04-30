# Adoption runbook — Day 0 → Day 1

Single checklist for rolling **taudit** onto a repository: local bootstrap, policy layout, baselines / suppressions, optional SARIF, and **merge-gating CI** for **GitHub Actions**, **GitLab CI**, and **Azure DevOps**. taudit is **graph-first**—it models **authority propagation** across CI/CD; merge gates and YAML invariants sit on top of that model, not the other way around.

**Version pinning:** replace `1.0.12` below with the **exact** crate version your org pins (same value in every `cargo install` line). Prefer **`--locked`** so transitive deps do not drift between CI runs.

**Further reading:** [USERGUIDE.md](../USERGUIDE.md) (end-user spine), [verify.md](verify.md), [baselines.md](baselines.md), [suppressions.md](suppressions.md), [custom-rules.md](custom-rules.md), [golden-paths.md](golden-paths.md), [policies/cookbook-partial-graphs.md](policies/cookbook-partial-graphs.md). Strategic phased adoption: [adr/0003-strategic-spine-adoption-phased.md](adr/0003-strategic-spine-adoption-phased.md).

---

## Day 0 — Local (once per repo)

### 1. Install

```bash
cargo install taudit --version 1.0.12 --locked
taudit --version
```

### 2. First scan (pick your substrate)

```bash
taudit scan .github/workflows/          # GitHub Actions
# taudit scan .gitlab-ci.yml …          # GitLab — add every pipeline path you rely on
# taudit scan azure-pipelines.yml       # Azure DevOps
```

### 3. Policy directory

- Create **`.taudit/policy/`** (conventional name; any directory works as `--policy`).
- Seed from your internal pack or from this repo’s **`invariants/starter/`** and **`invariants/policies/`** (copy YAML into **`.taudit/policy/`**, then edit for your org).
- Inventory what will run:

```bash
taudit invariants list --invariants-dir .taudit/policy/
```

### 4. Choose what the gate enforces

| Goal | Pattern |
|------|---------|
| **YAML policy only** | `taudit verify --policy .taudit/policy/ <paths>` |
| **Policy + 61 built-ins** | add **`--include-builtin`** and usually **`--severity-threshold high`** (or stricter) |

### 5. Brownfield adoption (pick one or combine)

**A — Per-pipeline baselines (default story for legacy noise)**

```bash
taudit baseline init .github/workflows/    # adjust paths
# Writes .taudit/baselines/<pipeline-content-sha>.json
git add .taudit/
```

After that, **`taudit scan`** / **`taudit verify`** classify findings as **NEW** vs **PRE-EXISTING**; the gate focuses on **NEW** (with non‑negotiable rules for **critical** — see [baselines.md](baselines.md)).

Supporting commands: **`taudit baseline diff`**, **`taudit baseline review`**, **`taudit baseline accept`** (use **`--expires-at`** when waiving criticals).

**B — Report baseline**

```bash
taudit scan <paths> --format json > taudit-baseline.json
# Later:
taudit scan <paths> --baseline taudit-baseline.json
```

**C — Suppressions file (long-lived, audited accepts)**

Author **`.taudit-suppressions.yml`** (see [suppressions.md](suppressions.md)), then:

```bash
taudit scan --suppressions .taudit-suppressions.yml <paths>
```

Tune **`--suppression-mode`** (`downgrade` vs `suppress`) as needed.

### 6. Optional ergonomics

- **`taudit map`** / **`taudit graph --format mermaid|json|summary`** — review and runbooks.
- **`taudit diff before.yml after.yml`** — authority-focused PR diffs.
- **`taudit remediate suggest`** / **`diff`** — reviewable edits; **`taudit remediate --unstable apply`** only with human review and backup discipline (**`list-backups`**, **`rollback`**).

### 7. Exit codes and coverage (teach the team)

- **`taudit verify`:** **`0`** pass, **`1`** violations, **`2`** cannot decide (policy path, **`--strict`** parse behavior, empty policy without **`--include-builtin`**, etc.) — [verify.md](verify.md).
- **Partial / unknown graphs** are first-class: see [USERGUIDE.md](../USERGUIDE.md) §5 and [policies/cookbook-partial-graphs.md](policies/cookbook-partial-graphs.md).

---

## Day 1 — CI merge gate

Use the **same** pinned `cargo install taudit --version 1.0.12 --locked` everywhere.

### GitHub Actions

Minimal required check (pin **`actions/checkout`** to a **full commit SHA** in production):

```yaml
name: Pipeline policy
on: [pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<FULL_SHA>
      - name: Install taudit
        run: cargo install taudit --version 1.0.12 --locked
      - name: Verify pipeline policy
        run: taudit verify --policy .taudit/policy/ .github/workflows/
```

Mark the job as a **required status check** in branch protection.

**Optional — SARIF on the PR + hard gate** (double run is intentional: first upload, second enforces exit code):

```yaml
      - name: Verify and emit SARIF
        run: taudit verify --policy .taudit/policy/ --format sarif -o results.sarif .github/workflows/
        continue-on-error: true
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
      - name: Re-fail if violations
        run: taudit verify --policy .taudit/policy/ .github/workflows/
```

See also the committed example [examples/ci-gate-taudit-verify.yml](examples/ci-gate-taudit-verify.yml).

### GitLab CI

```yaml
verify-pipeline-policy:
  stage: test
  script:
    - cargo install taudit --version 1.0.12 --locked
    - taudit verify --policy .taudit/policy/ .gitlab-ci.yml   # add paths if split across files
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

Configure protected branches / merge rules so this job blocks merge when it fails.

### Azure DevOps

```yaml
- task: Bash@3
  displayName: Verify pipeline policy
  inputs:
    targetType: inline
    script: |
      cargo install taudit --version 1.0.12 --locked
      taudit verify --policy .taudit/policy/ azure-pipelines.yml
```

Pass every YAML file that defines the pipeline surface taudit must evaluate (templates / split files: list each path).

---

## After Day 1

1. **Policy changes** — PR updates under **`.taudit/policy/`**; optionally paste **`taudit invariants list --invariants-dir .taudit/policy/`** output in the PR.
2. **Workflow edits change content hash** — re-run **`taudit baseline init`** for that pipeline or use **`baseline accept`** for fingerprint-level waivers ([baselines.md](baselines.md)).
3. **Upgrade taudit** — bump the pinned version in lockstep across repos; if you use JSON report baselines or SARIF baseline flows, see [finding-fingerprint.md](finding-fingerprint.md).
