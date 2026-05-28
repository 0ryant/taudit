# Marketplace Trust Pack Workstream Brief

## Goal

For `v1.2.0-rc.1`, prove taudit in the operator surfaces where teams actually adopt CI/CD security controls: GitHub Marketplace action, Azure DevOps task, VS Code extension/preflight, release provenance, proof receipts, screenshots/media, and adoption docs.

The workstream should not add a second taudit engine. It should make the existing graph-first CLI surface visibly trustworthy through thin typed adapters, runnable receipts, and docs that stay aligned with the contracts in `docs/integrations/`.

## Why This Takes taudit Skyward

taudit is already positioned as a CI/CD authority graph analyzer: the graph is the product, and findings, SARIF, merge gates, and adapters are consumers of that graph (`README.md`). The trust pack turns that architecture into operator proof.

- GitHub Action proof makes `verify` a copy-paste PR gate instead of a custom shell snippet (`docs/integrations/github-marketplace-action-contract.md`).
- Azure DevOps proof shows taudit working in a non-GitHub operator surface with version-pinned release-asset execution and task outputs (`docs/integrations/azure-devops-marketplace-extension-contract.md`, `integrations/azure-devops-extension/README.md`).
- VS Code proof shifts taudit left into local preflight while preserving `verify`, `scan`, and `graph` semantics (`docs/integrations/visual-studio-marketplace-extension-contract.md`, `integrations/vscode-extension/README.md`).
- Release-trust proof connects marketplace wrappers to SHA-256 checksums, SBOMs, and GitHub build attestations instead of asking users to trust a downloaded binary by vibes (`docs/release-trust.md`).
- Media and adoption docs make the authority graph understandable enough to sell, support, and troubleshoot (`docs/integrations/marketplace-media-shot-list.md`, `docs/golden-paths.md`, `docs/adoption-day0-day1.md`).

## Current Evidence

- Core positioning is ready: `README.md` defines taudit as a graph-first authority analyzer, lists GitHub Action, VS Code, and Azure DevOps as maintained operator surfaces, documents self-audit semantics, and calls out Azure DevOps task pinning limitations.
- Release trust is documented: release archives, checksums, SPDX/CycloneDX SBOMs, and GitHub artifact attestation verification are described in `docs/release-trust.md`.
- GitHub Action contract is implemented on paper: `docs/integrations/github-marketplace-action-contract.md` defines `dev.taudit.github-action.v1`, typed inputs, outputs, exit semantics, no raw passthrough, and security invariants.
- GitHub Action implementation evidence exists but publication is still blocked: `TODOS.md`, `docs/research/2026-05-14-marketplace-action-tranche-record.md`, `docs/research/2026-05-14-marketplace-publish-supervised-tranche.md`, and `docs/research/2026-05-15-marketplace-runtime-tranche.md` record the dedicated `0ryant/taudit-action` repo, local tests, local smoke, a later graph-mode drift fix, and the hard blocker that hosted smoke failed before runner execution because of GitHub billing/spending-limit state.
- Azure DevOps contract is implemented: `docs/integrations/azure-devops-marketplace-extension-contract.md` defines `dev.taudit.azure-pipelines-task.v1`; `integrations/azure-devops-extension/package.json` and `integrations/azure-devops-extension/vss-extension.json` currently show extension version `0.1.9`; the Visual Studio Marketplace listing is linked from the contract and integration index.
- Azure live proof is defined but not yet recorded: `docs/integrations/azure-devops-live-proof-checklist.md` requires one real `Taudit@1` run covering `scan`, authority graph, exploit graph, `verify`, output variables, and a published `taudit-task-smoke` artifact.
- VS Code surface exists in-tree: `integrations/vscode-extension/package.json` shows `algol.taudit-vscode` version `0.1.6`; `docs/integrations/visual-studio-marketplace-extension-operator-guide.md` documents commands, controls, local preflight, Azure hosted preflight, and the live Marketplace install link.
- VS Code publication-state docs are reconciled as of 2026-05-23: `docs/integrations/visual-studio-marketplace-extension-operator-guide.md` now treats the extension as installable, while fresh hosted install/activation evidence remains a proof gap for release receipts.
- Media plan is concrete: `docs/integrations/marketplace-media-shot-list.md` names the minimum VS Code and Azure screenshots/GIF, stable filenames, proof surfaces, and storage target for marketplace assets.
- Adoption docs exist and should be linked from listings: `docs/golden-paths.md` provides stable copy-paste flows; `docs/adoption-day0-day1.md` covers install, policy, baselines, suppressions, exit codes, and CI gates.

## Deliverables

- GitHub Marketplace action proof pack:
  - hosted SHA smoke in a disposable repo against the current action commit
  - immutable action tag, moving `v1`, GitHub release, and Marketplace listing only after hosted runner execution passes
  - receipt recording action SHA, tag, taudit binary version, `exit-code`, `outcome`, and run URL
  - docs updated once published, especially `TODOS.md`, `README.md`, `docs/integrations/index.md`, and `docs/research/2026-05-15-marketplace-runtime-tranche.md`
- Azure DevOps task proof pack:
  - one real run of `azure-pipelines.taudit-task-smoke.yml`
  - receipt with run URL, pool/agent, resolved taudit version, `tauditVerify.taudit.outcome`, artifact name, and artifact file list
  - downloaded or inspected artifacts for `taudit-scan.json`, `taudit-authority.dot`, `taudit-exploit.dot`, and `taudit-verify.json`
- VS Code extension/preflight proof pack:
  - local `npm run preflight` evidence from `integrations/vscode-extension/`
  - hosted Azure preflight evidence from `azure-pipelines.vscode-extension.yml`
  - VSIX artifact path/checksum, install/uninstall smoke, and one command smoke for `verify`, `scan`, authority graph, exploit graph, and `showOutput`
  - fresh release proof so operator guide, research ledger, package metadata, and marketplace listing stay synchronized
- Marketplace media pack:
  - stable assets under `docs/integrations/assets/marketplace/` following `docs/integrations/marketplace-media-shot-list.md`
  - at minimum: VS Code verify success, VS Code authority graph, VS Code exploit graph, policy-bootstrap GIF, Azure task run success, Azure task outputs/artifact proof
- Adoption and backlink pass:
  - marketplace listings and READMEs link to `docs/golden-paths.md`, `docs/adoption-day0-day1.md`, `docs/integrations/index.md`, the demo story, and the relevant contract/operator guide
  - GitHub Action, Azure DevOps, and VS Code examples all use current pinned versions consistently
- Contract drift register:
  - one table or checklist comparing contract docs, package manifests, README claims, TODO statuses, action repo commit/tag, and live marketplace state
  - explicit handling for version drift, graph-mode flag drift, ADO path normalization, ADO enrichment scaffolding, and publication-state drift

## Acceptance Criteria

- Each operator surface has one runnable first-use path and one proof receipt that cites exact run URL or local command, commit/tag, adapter version, taudit version, and result.
- GitHub Action is not called Marketplace-ready until hosted runner execution passes and `0ryant/taudit-action@v1` resolves to a verified immutable tag.
- Azure DevOps is not called live-proven until the `Taudit@1` smoke produces expected output variables and the `taudit-task-smoke` artifact contents named in `docs/integrations/azure-devops-live-proof-checklist.md`.
- VS Code is not called release-proven for a new version until local and hosted preflight, VSIX install smoke, and Marketplace install/listing state are recorded across `docs/integrations/visual-studio-marketplace-extension-operator-guide.md` and the relevant research ledger.
- All wrappers preserve taudit exit semantics: `0` pass, `1` violations, `2` config/cannot-decide error, as documented in `docs/integrations/github-marketplace-action-contract.md`, `docs/integrations/azure-devops-marketplace-extension-contract.md`, and `docs/integrations/visual-studio-marketplace-extension-contract.md`.
- Proof media is based on real operator surfaces or committed fixtures, not mockups, and uses stable filenames from `docs/integrations/marketplace-media-shot-list.md`.
- Release trust claims are bounded to what `docs/release-trust.md` actually ships: checksums, SBOMs, GitHub build attestations, and future minisign as not yet shipped.
- Contract drift is checked before RC handoff: no stale version examples, no unpublished listing links presented as live, no raw passthrough in v1 surfaces, and no hidden policy/suppressions/baseline conflation.

## Risks / Non-Goals

- External account state can block proof: GitHub billing/spending limit, Marketplace Developer Agreement, Azure hosted minutes, Azure DevOps publisher/PAT rights, and org extension installation are outside the repo.
- The action implementation lives in a dedicated external repository, so local docs can drift from `0ryant/taudit-action` unless every receipt records the action commit/tag.
- Current docs still show drift risk: examples mix recent taudit versions across docs, and live Marketplace state can drift from repo manifests unless each release records receipts.
- Screenshots can overclaim. A YAML screenshot is not a live receipt; a local smoke is not a hosted runner proof; a marketplace page is not proof the adapter ran correctly.
- Non-goals for this RC: automatic policy authoring, raw `extra-args`, automatic CI mutation, built-in third-party upload/SIEM publishing, broad PAT scopes, verified-publisher/top-publisher badge claims, or changing taudit core graph semantics.

## Suggested Verification

- Repo preservation:
  - `git status --short`
- Docs and adoption smoke:
  - `just golden-paths`
  - `rg -n "1.1.4|1.1.5|not claim|published successfully|taudit-action@v1|Taudit@1|algol.taudit-vscode|algol.taudit-azure-pipelines" README.md TODOS.md docs integrations`
- VS Code extension:
  - from `integrations/vscode-extension/`: `npm ci`, `cargo build -p taudit`, `npm run preflight`
  - hosted: run `azure-pipelines.vscode-extension.yml` and record run URL, VSIX checksum, and install smoke result
- Azure DevOps task:
  - from `integrations/azure-devops-extension/`: `npm ci`, `npm run preflight`
  - hosted: run `azure-pipelines.taudit-task-smoke.yml` and verify output variables plus the `taudit-task-smoke` artifact contents
- GitHub Action:
  - in the dedicated action repo: run unit/input/argv/injection tests, syntax checks, `actionlint` on examples, and hosted SHA smoke in a disposable repo
  - only after hosted SHA smoke passes: cut immutable tag, verify tag resolution, move/create `v1`, create release, and publish Marketplace listing
- Release trust:
  - download one release archive and matching checksum, verify SHA-256, then run `gh attestation verify <asset> --repo 0ryant/taudit`
  - repeat for one SBOM if the wrapper release notes cite SBOM provenance
