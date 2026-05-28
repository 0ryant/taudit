# Marketplace install and operator hardening subtasks

Date: 2026-05-23
Status: active task plan
Decision: [ADR 0025](../adr/0025-marketplace-install-and-operator-hardening.md)

## Source signal

External user feedback found that taudit fills the missing CI/CD authority
graph gap next to secret scanning, Trivy, Terraform validate, TFLint, and ADF
JSON validation. The Azure DevOps extension is the right adoption UX, but
operators need clearer install messaging and sharper handling around path
identity, task inputs, partial graph wording, baseline lifecycle, and graph
artifact formats.

## Task lanes

### M1: Marketing install push

**Objective:** Make it easy for marketing and DevRel to tell users to install
taudit from Visual Studio Marketplace today.

**Owned files or surfaces:**

- `docs/marketing/visual-studio-marketplace-install-brief.md`
- `README.md`
- `docs/integrations/index.md`
- Marketplace listing copy for `Algol.taudit-vscode`
- Marketplace listing copy for `Algol.taudit-azure-pipelines`

**Inputs and dependencies:**

- Live VS Code listing: `https://marketplace.visualstudio.com/items?itemName=Algol.taudit-vscode`
- Live Azure Pipelines listing: `https://marketplace.visualstudio.com/items?itemName=Algol.taudit-azure-pipelines`
- Screenshot plan: `docs/integrations/marketplace-media-shot-list.md`

**Acceptance criteria:**

- Marketing brief contains direct install links, short copy, social copy,
  newsletter copy, internal enablement copy, and do-not-say guidance.
- Repo README points directly to both Marketplace listings.
- Integration index points users to the correct install surface by audience.
- Copy says taudit adds the CI/CD authority-graph layer and does not claim to
  replace secret, CVE, IaC, JSON, or YAML linters.

**Verification evidence:**

- `FILE(docs/marketing/visual-studio-marketplace-install-brief.md)`
- `FILE(README.md)`
- `FILE(docs/integrations/index.md)`
- `SEARCH(Visual Studio Marketplace listing URLs, scope=official Marketplace)`

**Stop conditions:**

- A Marketplace listing stops rendering.
- Publisher identity or extension identifier changes.
- Marketing asks for claims that exceed verified product behavior.

### M2: Marketplace proof media

**Objective:** Produce reviewable assets that prove the install path and first
operator flow.

**Owned files or surfaces:**

- `docs/integrations/marketplace-media-shot-list.md`
- `docs/media/`
- Marketplace screenshot slots for both listings

**Inputs and dependencies:**

- Live VS Code extension install.
- Live Azure Pipelines task install.
- Demo story: `docs/demos/corpus-expo-docs-authority-exploit-story.md`
- Graph assets: `docs/demos/assets/`

**Acceptance criteria:**

- One VS Code verify screenshot exists and names the command result.
- One VS Code graph screenshot exists and shows authority or exploit graph
  output from a committed fixture.
- One Azure Pipelines task run screenshot exists and shows `Taudit@1`.
- One Azure Pipelines graph artifact screenshot exists.
- Every asset has a regeneration note or committed source fixture.

**Verification evidence:**

- `FILE(docs/media/<asset>)`
- `CMD(taudit graph ..., exit=0)`
- `TOOL(Marketplace page render, result=screenshot visible)`

**Stop conditions:**

- Screenshots expose secrets, private org names, unrelated browser state, or
  unreviewed claims.

### D1: Path identity documentation

**Objective:** Make baseline path identity predictable for teams whose CI
stages or copies pipeline files before scanning.

**Owned files or surfaces:**

- `docs/baselines.md`
- `docs/adoption-day0-day1.md`
- `integrations/azure-devops-extension/README.md`
- `integrations/azure-devops-extension/overview.md`
- `docs/integrations/azure-devops-marketplace-extension-contract.md`

**Inputs and dependencies:**

- Existing baseline implementation: `crates/taudit-core/src/baselines.rs`
- Existing ADO task path handling: `integrations/azure-devops-extension/Taudit/lib/inputs.js`
- User feedback about `quality.yaml` vs `ado-pipelines/quality.yaml`

**Acceptance criteria:**

- Docs explicitly say scan path is part of current authority/baseline identity.
- Docs give a recommended CI pattern: scan files at stable repo-relative paths.
- Docs warn that staged/copied pipeline paths can produce fixed/new churn.
- Docs say `baselineRoot` must stay workspace-relative in `Taudit@1`.

**Verification evidence:**

- `FILE(docs/baselines.md)`
- `FILE(docs/adoption-day0-day1.md)`
- `FILE(integrations/azure-devops-extension/README.md)`

**Stop conditions:**

- Maintainers decide to change path identity semantics before documenting the
  current contract.

### C1: Path remap or logical root design

**Objective:** Decide whether taudit should support explicit logical path
identity for staged or copied pipeline files.

**Owned files or surfaces:**

- `docs/adr/`
- `docs/baselines.md`
- `crates/taudit-cli/src/main.rs`
- `crates/taudit-core/src/baselines.rs`
- `crates/taudit-cli/tests/`

**Inputs and dependencies:**

- D1 documentation outcome.
- Existing fingerprint and baseline schema contracts.

**Acceptance criteria:**

- A decision exists for one of these options:
  - keep path identity unchanged and document it;
  - add `--logical-root`;
  - add `--path-map <from>=<to>`;
  - add a baseline schema field for source path identity.
- Decision names migration behavior for existing baselines.
- Decision says whether graph, scan, and verify share the same path mapping.

**Verification evidence:**

- `FILE(docs/adr/<new-path-identity-adr>.md)`
- `TEST(path identity regression, result=pass)`

**Stop conditions:**

- Proposed normalization would merge distinct security surfaces without an
  explicit operator opt-in.

### C2: Graph and verify path/baseline parity tests

**Objective:** Prove graph mode and verify mode agree on path and baseline
semantics where they share controls.

**Owned files or surfaces:**

- `crates/taudit-cli/tests/`
- `tests/fixtures/`
- `docs/baselines.md`

**Inputs and dependencies:**

- Current CLI graph/verify flags.
- Existing baseline fixtures and helper functions.

**Acceptance criteria:**

- Test fixture scans the same YAML from a stable path and a staged/copied path.
- Test records whether identity changes are expected under current semantics.
- Test covers `verify --baseline-root` and graph artifact generation in the
  same path layout.
- Docs link to the tested behavior.

**Verification evidence:**

- `TEST(cargo test -p taudit-cli path_baseline_parity, result=pass)`

**Stop conditions:**

- CLI graph mode has no baseline interaction to compare; in that case, narrow
  the test to shared path resolution and document the non-overlap.

### A1: Azure DevOps task input/env contract

**Objective:** Remove the feeling that `Taudit@1` inputs are magical.

**Owned files or surfaces:**

- `integrations/azure-devops-extension/Taudit/index.js`
- `integrations/azure-devops-extension/Taudit/lib/inputs.js`
- `integrations/azure-devops-extension/test/inputs.test.mjs`
- `integrations/azure-devops-extension/README.md`
- `integrations/azure-devops-extension/overview.md`
- `docs/integrations/azure-devops-marketplace-extension-contract.md`

**Inputs and dependencies:**

- Azure Pipelines task-lib `getInput` behavior.
- Current task fields: `policy`, `baselineRoot`, `ignoreFile`,
  `suppressions`.
- User feedback about setting both task inputs and `INPUT_*` variables.

**Acceptance criteria:**

- Tests state exactly which environment variables the task reads directly.
- Docs say task inputs are the supported contract.
- Docs explain whether `INPUT_POLICY`, `INPUT_BASELINEROOT`,
  `INPUT_IGNOREFILE`, and `INPUT_SUPPRESSIONS` are task-lib materialization
  details or supported user contract.
- If direct env fallback is added, tests prove task input precedence.
- If direct env fallback is not added, docs say not to set `INPUT_*`
  variables manually.

**Verification evidence:**

- `TEST(npm test -- inputs.test.mjs, result=pass)`
- `FILE(integrations/azure-devops-extension/README.md)`
- `FILE(docs/integrations/azure-devops-marketplace-extension-contract.md)`

**Stop conditions:**

- A change would make secret-bearing inputs appear in argv, logs, summaries,
  or artifacts.

### A2: Azure DevOps path summary

**Objective:** Make every `Taudit@1` run explain which controls were actually
used.

**Owned files or surfaces:**

- `integrations/azure-devops-extension/Taudit/index.js`
- `integrations/azure-devops-extension/Taudit/lib/results.js`
- `integrations/azure-devops-extension/test/`

**Inputs and dependencies:**

- Current output variables: `taudit.exitCode`, `taudit.outcome`,
  `taudit.reportPath`, `taudit.findingsCount`, `taudit.tauditVersion`.

**Acceptance criteria:**

- Task log or summary includes active `policy`, `ignoreFile`, `suppressions`,
  `suppressionMode`, `baselineRoot`, `ignorePartial`, and `gateOnAll`.
- Summary redacts ADO PAT material.
- Missing optional controls are rendered as absent, not as empty mystery
  values.

**Verification evidence:**

- `TEST(integration summary fixture, result=pass)`
- `ABSENCE(secret-like value, scope=task logs)`

**Stop conditions:**

- Summary would leak workspace secrets or untrusted raw command lines.

### P1: Partial graph wording pass

**Objective:** Make partial graph output actionable without making it sound
like failure or success.

**Owned files or surfaces:**

- `USERGUIDE.md`
- `docs/policies/cookbook-partial-graphs.md`
- `docs/verify.md`
- terminal reporter strings in `crates/taudit-report-terminal/src/lib.rs`
- relevant CLI snapshots under `crates/taudit-cli/tests/snapshots/`

**Inputs and dependencies:**

- Current `AuthorityCompleteness::Partial` behavior.
- Existing partial graph fixtures.

**Acceptance criteria:**

- Docs use "review focus area" wording.
- CLI output makes clear that partial means preserved uncertainty.
- CLI output does not imply partial means ignored.
- Snapshot tests capture the wording.

**Verification evidence:**

- `TEST(cargo test -p taudit-cli snapshot_..., result=pass)`
- `FILE(docs/policies/cookbook-partial-graphs.md)`

**Stop conditions:**

- Wording weakens the fact that taudit could not fully model the pipeline.

### B1: Stale baseline listing

**Objective:** Help teams identify baseline files that no current scan path can
reference.

**Owned files or surfaces:**

- `crates/taudit-cli/src/main.rs`
- `crates/taudit-core/src/baselines.rs`
- `docs/baselines.md`
- `crates/taudit-cli/tests/`

**Inputs and dependencies:**

- Existing `.taudit/baselines/<hash>.json` layout.
- Current path identity decision from C1.

**Acceptance criteria:**

- Command or subcommand can list stale baseline files for a provided scan set.
- Default behavior is read-only.
- Output includes baseline path, last associated pipeline path if stored, and
  reason it is stale or orphaned.
- Docs show a dry-run workflow.

**Verification evidence:**

- `CMD(cargo test -p taudit-cli baseline_stale, exit=0)`
- `FILE(docs/baselines.md)`

**Stop conditions:**

- Staleness cannot be determined without changing the baseline schema; create
  the schema decision first.

### B2: Stale baseline pruning

**Objective:** Provide an explicit cleanup path after B1 proves stale baseline
classification.

**Owned files or surfaces:**

- `crates/taudit-cli/src/main.rs`
- `crates/taudit-core/src/baselines.rs`
- `docs/baselines.md`
- `crates/taudit-cli/tests/`

**Inputs and dependencies:**

- B1 stale baseline listing.
- Baseline schema and path identity decision.

**Acceptance criteria:**

- Prune command defaults to dry-run or requires an explicit write flag.
- Prune never removes files outside the configured baseline root.
- Prune output is reviewable in CI logs.
- Docs show recommended review flow before committing baseline cleanup.

**Verification evidence:**

- `TEST(prune rejects outside-root path, result=pass)`
- `TEST(prune dry-run leaves files unchanged, result=pass)`

**Stop conditions:**

- The command cannot prove its resolved delete targets stay inside the baseline
  root.

### G1: HTML or SVG graph artifact output

**Objective:** Make graph artifacts cheaper to review in Azure Pipelines and
Marketplace demos.

**Owned files or surfaces:**

- `crates/taudit-cli/src/main.rs`
- `crates/taudit-core/src/graph.rs`
- `docs/authority-graph.md`
- `docs/golden-paths.md`
- `integrations/azure-devops-extension/README.md`
- `integrations/azure-devops-extension/overview.md`

**Inputs and dependencies:**

- Current `taudit graph --format dot|mermaid|json|summary`.
- Marketplace media requirements.

**Acceptance criteria:**

- Decision exists for first friendly format: `svg`, `html`, or documented
  Graphviz render recipe.
- If native `svg` or `html` is added, tests prove deterministic output for a
  fixture.
- Azure DevOps examples use the review-friendly format or show the render step.
- DOT remains available for tool users.

**Verification evidence:**

- `TEST(graph friendly artifact snapshot, result=pass)`
- `FILE(docs/golden-paths.md)`

**Stop conditions:**

- HTML output would embed untrusted pipeline text without escaping.

### G2: Marketplace graph review recipe

**Objective:** Give users a copy-paste Azure Pipelines graph artifact flow
without requiring them to understand DOT tooling first.

**Owned files or surfaces:**

- `integrations/azure-devops-extension/overview.md`
- `integrations/azure-devops-extension/README.md`
- `docs/golden-paths.md`
- `docs/integrations/marketplace-media-shot-list.md`

**Inputs and dependencies:**

- G1 decision.

**Acceptance criteria:**

- Azure Pipelines docs show one graph artifact recipe.
- Recipe produces an artifact reviewers can open from a pipeline run.
- Recipe names the difference between authority and exploit graph views.

**Verification evidence:**

- `FILE(integrations/azure-devops-extension/overview.md)`
- `CMD(taudit graph ..., exit=0)`

**Stop conditions:**

- Recipe requires a Marketplace task capability not yet shipped.

### O1: Marketplace growth loop

**Objective:** Turn install feedback into measurable listing improvements.

**Owned files or surfaces:**

- `docs/research/2026-05-15-marketplace-growth-notes.md`
- `docs/marketing/visual-studio-marketplace-install-brief.md`
- Marketplace listing metrics

**Inputs and dependencies:**

- Marketplace install count and active install count.
- Support issues and operator feedback.

**Acceptance criteria:**

- A monthly review records install count, active installs, rating count, top
  support issue themes, and next patch-copy action.
- Review does not claim verified publisher or top publisher status before the
  Marketplace badges exist.

**Verification evidence:**

- `FILE(docs/research/<growth-review>.md)`
- `TOOL(Marketplace listing metrics, result=recorded)`

**Stop conditions:**

- Metrics cannot be accessed by maintainers.

## Recommended execution order

1. M1: complete install messaging and docs links.
2. D1 and A1: remove the two sharpest first-use surprises.
3. C2: pin current path/baseline parity with regression tests.
4. P1: tune partial wording before wider adoption increases support load.
5. B1 then B2: add baseline lifecycle tooling.
6. G1 then G2: add review-friendly graph artifacts.
7. M2 and O1: scale the Marketplace growth loop with proof assets and metrics.
