# taudit — TODO backlog

MoSCoW: **Must** | **Should** | **Could** | **Won't**

**Parallel execution:** [`docs/jobs-phased-lanes.md`](docs/jobs-phased-lanes.md) (Phase 3 — ADO variable-group enrichment).

---

## Must Have

### GitHub Marketplace action proof gate

**Status:** Proof-gated — implementation checklist items are recorded, but
this repository has no completed `v1.2.0-rc.1` receipt proving external
Marketplace publication, installability, immutable tag, moving `v1` tag, or
hosted smoke. Treat all adopter-facing GitHub Marketplace action wording as
planned/pending receipt until the proof chain in
[`docs/rc/v1.2.0/marketplace-proof-state.md`](docs/rc/v1.2.0/marketplace-proof-state.md)
is complete.
**Effort:** Medium
**Impact:** After receipts are recorded, make taudit available as a first-class
GitHub Marketplace action for CI/CD authority scanning and merge-gate adoption.
**UX decision:** Ratified in [`docs/research/2026-05-14-github-marketplace-action-ux.md`](docs/research/2026-05-14-github-marketplace-action-ux.md). Marketplace v1 is **verify-first**: `scan` is advisory/bootstrap, `graph` is observability, `verify` is the default team gate.
**Contract:** [`docs/integrations/github-marketplace-action-contract.md`](docs/integrations/github-marketplace-action-contract.md) defines `dev.taudit.github-action.v1`: input schema, output schema, argv mapping, exit semantics, security invariants, and compatibility rules.
**Configuration model:** `policy` is only the invariant bundle. Suppressions, `.tauditignore`, and baselines are separate first-class controls and must be exposed/documented separately.

#### Current state

Receipt rule: checked implementation items below record wrapper readiness work
only. They do not prove that the action is published, installable from
Marketplace, tag-addressable as `v1`, or hosted-smoked on GitHub runners.

taudit has a local composite action at [`.github/actions/taudit-scan/action.yml`](.github/actions/taudit-scan/action.yml), but this repository is not shaped for direct Marketplace publication:

- The action metadata is nested, not at repository root.
- This repository contains product source, release workflows, docs, fixtures, and other files beyond a single action package.
- The current composite action installs with `cargo install` and assumes `taudit scan` exit code means findings, but `scan` is now informational; enforcement should use `taudit verify`.
- The current action interpolates user inputs into shell commands and is not ready for Marketplace exposure.

#### Target shape

Create a dedicated public action repository, `0ryant/taudit-action`, with:

- Root `action.yml`.
- Minimal wrapper code and README only.
- No product release workflows from this repository copied across.
- A unique Marketplace `name`, clear `description`, `author`, and `branding`.
- Tags aligned to taudit stable releases, plus a moving compatible major tag such as `v1`.

#### Implementation tasks

- [x] Create dedicated Marketplace repository (`taudit-action`) or equivalent dedicated repo name.
- [x] Add root `action.yml` with validated inputs:
  - `mode`: `verify` (default), `scan`, or `graph`
  - `version`: default to current stable, not floating `latest`
  - `paths`: newline-separated paths/globs
  - `platform`
  - `ado-org`
  - `ado-project`
  - `ado-pat`
  - `severity-threshold`
  - `policy`
  - `include-builtin`
  - `ignore-file`
  - `suppressions`
  - `suppression-mode`
  - `baseline-root`
  - `gate-on-all`
  - `strict`
  - `ignore-partial`
  - `format`
  - `output`
  - `graph-view`
  - `max-hops`
  - `no-color`
  - `fallback-cargo`
- [x] In the action repo, commit `contracts/taudit-action-inputs.v1.schema.json` matching [`docs/integrations/github-marketplace-action-contract.md`](docs/integrations/github-marketplace-action-contract.md).
- [x] Replace shell-string construction with a safe argv-building wrapper.
- [x] Validate enum-like inputs before execution (`mode`, `platform`, `format`, severity).
- [x] Ensure `scan` mode is advisory by default unless an explicit fail option is selected.
- [x] Ensure `verify` mode preserves taudit exit semantics: `0` pass, `1` violations, `2` cannot decide/config error.
- [x] Preserve CLI control semantics:
  - `policy` is required for `verify` and is not a suppressions directory.
  - ADO enrichment inputs are all-or-none and `ado-pat` is masked.
  - built-ins run in `verify` only when `include-builtin` is true.
  - `.tauditignore` auto-discovery works unless `ignore-file` is supplied.
  - `.taudit-suppressions.yml` and `.taudit/suppressions.yml` auto-discovery works unless `suppressions` is supplied.
  - `.taudit/baselines/` auto-discovery works unless `baseline-root` is supplied.
  - `gate-on-all` overrides baseline-new-only gating.
  - `ignore-partial` is explicit, visible in summary, and never silently enabled.
- [x] Emit clear action summary/output fields for loaded controls:
  - `policy-path`
  - `ignore-file-used`
  - `suppressions-file-used`
  - `suppression-mode-used`
  - `baseline-root-used`
  - `baseline-status`
  - `partial-policy`
  - `ado-enrichment`
  - `new-findings-count`
  - `preexisting-critical-count`
  - `waived-count`
- [x] Prefer downloading the pinned taudit release binary for runner OS/arch.
- [x] Add a locked `cargo install taudit --version <version> --locked` fallback for unsupported platforms or missing release assets.
- [x] Avoid echoing secrets, tokens, raw command lines with secret-bearing inputs, or untrusted arguments.
- [x] Omit raw `extra-args` from v1; add only typed, validated inputs.
- [x] Document SARIF upload as a separate `github/codeql-action/upload-sarif` step with explicit permissions.

#### Documentation tasks

- [x] Add Marketplace README with copy-paste workflows:
  - required `verify` gate with policy directory
  - link to the full action contract/schema
  - config model explaining policy vs `.tauditignore` vs suppressions vs baselines
  - advisory scan/bootstrap for first adoption
  - SARIF output and upload
  - graph artifact generation
  - baseline-first adoption for existing repos
  - suppression workflow using `suppression_key`
- [x] Document suppression modes:
  - `downgrade` can affect severity-threshold gating.
  - `tag-only` preserves severity and does not by itself make `verify` pass.
- [x] Document critical waiver behavior: critical suppressions require expiry; expired waivers stop applying; baselined critical findings still gate unless explicitly time-waived.
- [x] Document the action step summary so users can explain exactly which policy, ignore file, suppression file, and baseline were applied.
- [x] Make first-run/baseline errors crisp: explain whether policy or baseline is missing and show the exact bootstrap command.
- [x] Document exact exit-code behavior for each mode.
- [x] Document recommended pinning:
  - `uses: 0ryant/taudit-action@v1` for compatible updates
  - full SHA pin for high-control environments
  - taudit CLI version pin via `version`
- [ ] Update taudit docs to point users at the Marketplace action after the publication receipt is recorded.
- [x] Replace stale `cargo install taudit --version 1.0.12 --locked` examples with the current stable version where appropriate.
- [x] Add a short security model: what the action reads, what it uploads, required permissions, and how it handles untrusted inputs.

#### Test and readiness gates

- [x] Unit-test wrapper argument construction and input validation.
- [x] Add injection tests for `paths`, `policy`, `ignore-file`, `suppressions`, `baseline-root`, `output`, and any optional extra argument field.
- [x] Add a negative test proving no v1 `extra-args` passthrough exists.
- [ ] Run `actionlint` and `yamllint` on all README workflow examples. (`actionlint` passed locally; `yamllint` unavailable.)
- [ ] Hosted-runner smoke on `ubuntu-latest`, `macos-latest`, and `windows-latest`.
- [ ] Smoke `scan` mode on a clean fixture and a leaky fixture.
- [ ] Smoke `verify` mode with:
  - clean/noop policy exits `0`
  - violating policy exits `1`
  - missing policy or bad config exits `2`
  - built-ins absent by default and present with `include-builtin`
  - explicit missing suppression/ignore/policy paths fail clearly
  - `suppression-mode: tag-only` does not suppress the gate
  - `suppression-mode: downgrade` changes severity-threshold behavior
  - critical suppression without expiry exits as a config error
  - expired suppression no longer applies
  - baseline-new-only gating, unwaived critical blocking, and `gate-on-all`
  - `ignore-partial` behavior and summary visibility
  - ADO enrichment all-or-none validation and PAT masking
- [ ] Smoke `graph` mode for `json`, `dot`, `mermaid`, and `summary`.
- [ ] Verify SARIF file generation and upload in a disposable repository.
- [ ] Verify SARIF upload runs in a separate trusted job/workflow and does not grant `security-events: write` to untrusted PR execution.
- [ ] Verify binary download path for each supported OS/arch.
- [ ] Verify cargo fallback path on at least one runner.
- [x] Verify no secrets or token-like values appear in logs from normal and failure paths.
- [x] Verify action summary outputs loaded policy/ignore/suppressions/baseline state without leaking sensitive values.
- [ ] Run the action against this repository's `.github/workflows/` as an advisory self-scan.
- [ ] Run at least one disposable-repo end-to-end workflow using `uses: 0ryant/taudit-action@<tag>`.

#### Marketplace proof tasks

- [ ] Record receipt confirming the dedicated action repository public readback.
- [ ] Confirm GitHub Marketplace Developer Agreement is accepted for the publishing account/org and record the receipt or operator note.
- [ ] Confirm root `action.yml` has no Marketplace validation warnings and record the receipt.
- [ ] Confirm action `name` is unique and not a reserved GitHub feature/category/user/org name and record the receipt.
- [ ] Choose primary category; likely `Security` if available, otherwise closest Marketplace category.
- [ ] Cut immutable release tag for the action repository.
- [ ] Create/move compatible major tag (`v1`) only after the immutable tag passes hosted smoke.
- [ ] Draft GitHub release from root `action.yml`.
- [ ] Select **Publish this Action to the GitHub Marketplace**.
- [ ] Publish release with release notes that name the bundled taudit version and supported modes.
- [ ] After publication, install from Marketplace in a disposable repo and rerun smoke workflows.

#### Acceptance criteria

- [ ] A user can add one `uses: 0ryant/taudit-action@v1` step and get a useful advisory scan.
- [ ] A team can make `verify` mode a required PR check without custom shell scripting.
- [ ] SARIF and graph outputs can be produced without unsafe shell interpolation.
- [ ] The action works on GitHub-hosted Linux, macOS, and Windows.
- [ ] Docs explain how the action helps teams lock down pipelines: baseline, gate new authority paths, inspect graph output, and apply suppressions with reviewable keys.
- [ ] Marketplace listing receipt shows links to current docs and a current stable taudit release.

#### Won't scope for first Marketplace release

- Docker action packaging.
- Automatic policy authoring.
- Built-in upload to third-party storage or SIEM.
- Non-GitHub CI wrappers; keep ADO/GitLab examples in taudit docs, not the Marketplace action repo.

---

## Could Have

### `--ado-pat`: ADO variable group resolution at scan time

**Status:** In progress; pre-req static increment shipped (`dependsOn` explicit partial signaling) and API enrichment runtime path landed with graceful fallback.  
**Effort:** Medium (1–2 weeks)  
**Impact:** High noise reduction for ADO pipelines with variable groups

#### Problem

When taudit sees `- group: MyGroup` in an ADO pipeline it marks the graph
`[partial]` — it can't look inside the group to distinguish padlock-secret
variables from plain config strings, so it conservatively treats the entire
group as a secret blob. Every step that inherits from the group gets flagged.
In practice this produces ~144 `[partial]` criticals on a real enterprise
pipeline where only 8–12 involve genuinely secret variables.

BUG-3 (`--ignore-partial`) reduces the noise but doesn't eliminate it; the
graph stays `Partial` and baselines are unstable because the underlying
findings shift whenever group membership changes.

#### Proposed solution

Add three optional flags to `taudit scan` and `taudit verify`:

```
--ado-org    https://dev.azure.com/<org>
--ado-project <project>
--ado-pat    <PAT or $env var>
```

At parse time, after the ADO parser marks a group `[partial]`, call:

```
GET {org}/{project}/_apis/distributedtask/variablegroups?api-version=7.1
```

ADO returns each variable with:
- `isSecret: true` → value redacted → keep as `NodeKind::Secret`
- `isSecret: false` → value in clear → add to `plain_vars`, no Secret node

The graph node for the group becomes `Complete`. Baselines stabilise.
The 144 partial criticals collapse to the 8–12 that touch genuinely secret
variables.

#### PAT scope required

`Variable Groups (Read)` only — no write, no code, no build access.

In CI:

```yaml
- name: taudit verify
  run: |
    taudit verify \
      --ado-org https://dev.azure.com/MyOrg \
      --ado-project MyProject \
      --ado-pat "${{ secrets.TAUDIT_ADO_READ_PAT }}" \
      --policy .taudit/policy \
      --include-builtin \
      .pipelines/
```

#### Design constraints

- **Opt-in only.** Without `--ado-pat`, existing behaviour is unchanged.
  Static-only path remains fully functional via BUG-3 + `--ignore-partial`.
- **Graceful degradation.** If the API call fails (network blocked, expired
  PAT, permission denied) emit a `warning:` and fall back to the current
  partial-graph behaviour. Never fail the scan due to an enrichment error.
- **No caching between runs.** Group contents can change between pipeline
  runs. Fetch fresh on every invocation.
- **Reproducibility caveat documented.** Same YAML + different ADO group state
  → different graph. Document this explicitly in `docs/baselines.md` under a
  "ADO-aware mode" section: baselines created with `--ado-pat` should note the
  group snapshot date.
- **No secret leakage.** The PAT is injected via flag only; never logged,
  never written to disk. Audit log records "ado-enrichment: yes" without the
  token value.

#### Implementation sketch

1. Add `ado_org`, `ado_project`, `ado_pat` fields to `AdoParser` (or pass as
   `ParseContext`).
2. After parsing the YAML structure, for each `AdoVariable::Group`, if PAT
   present: call the API, iterate returned variables, populate `plain_vars`
   for non-secret entries and create `NodeKind::Secret` only for `isSecret:
   true` entries.
3. Remove the `graph.mark_partial(...)` call for that group (graph is now
   complete for it).
4. New `ureq` call using the existing `ureq` workspace dependency (already
   present in `taudit-cli`).
5. Add `--ado-pat` to `taudit scan` and `taudit verify` CLI variants.
6. Update `docs/verify.md` and `docs/baselines.md`.

#### Won't scope

- Caching group contents between runs.
- Writing back to ADO (strictly read-only).
- Supporting Azure DevOps Server (on-prem) — `dev.azure.com` cloud only for
  now.
- Service connection resolution (separate API, separate scope, separate
  feature).

### VulnOps tooling in CI/CD

**Status:** Not started  
**Effort:** TBD  
**Impact:** Centralise vulnerability-operations style checks alongside existing supply-chain gates (Trivy, Checkov, Gitleaks, `cargo deny` / `cargo audit`).

#### Scope (draft)

- [ ] Select **vulnops** (or named successor / integration path) and map overlap vs `scripts/quality-gate.sh`, `.github/workflows/security.yml`, and **CI mirrors** (`azure-pipelines.yml`, `.gitlab-ci.yml`).
- [ ] Add GitHub Actions job or extend governance stage; keep **secrets out of logs** and document any PAT/API scope.
- [ ] Mirror the same gate into **ADO / GitLab** mirrors once stable on `main`.
- [ ] Update [`docs/integrations/ci-mirrors.md`](docs/integrations/ci-mirrors.md) and release notes when behaviour is contract-stable.

### Linters in CI (workflow + infra YAML)

**Status:** Baseline shipped (extend later)  
**Effort:** Done for GHA + mirrors via governance gate  
**Impact:** **actionlint** + **yamllint** (pinned installers in [`scripts/install-ci-linters.sh`](scripts/install-ci-linters.sh), config [`.yamllint`](.yamllint)) run inside [`scripts/quality-gate.sh`](scripts/quality-gate.sh) **`ci-governance`** — wired from [`.github/workflows/quality.yml`](.github/workflows/quality.yml), [`azure-pipelines.yml`](azure-pipelines.yml), [`.gitlab-ci.yml`](.gitlab-ci.yml). Complementary to taudit ([`docs/integrations/ci-mirrors.md`](docs/integrations/ci-mirrors.md)).

#### Follow-ups (optional)

- [ ] ADO / GitLab **native** YAML validators beyond actionlint+yamllint if they add signal.
- [ ] Ingest external linter **SARIF** as triage context — explicit flag + ADR only ([`docs/integrations/index.md`](docs/integrations/index.md)).

### FinOps tooling in CI/CD

**Status:** Baseline shipped (GitHub-first)  
**Effort:** Terraform smoke + optional Infracost  
**Impact:** [`infra/finops-smoke/`](infra/finops-smoke/) + [`.github/workflows/finops.yml`](.github/workflows/finops.yml) — **`terraform fmt` / `validate`** always; **Infracost** when secret **`INFRACOST_API_KEY`** is set (see [`infra/finops-smoke/README.md`](infra/finops-smoke/README.md)). **Not** a taudit finding surface.

#### Follow-ups (optional)

- [ ] PR cost comments / budgets / ADO–GitLab mirrors once org wants them.
- [ ] OpenCost / cloud billing APIs — separate PAT + ADR.
