# v1.2.0-rc.1 Adoption Proof Audit

Status: L6-01 through L6-05 audit and ledger setup.

This audit applies [ADR 0021](../../adr/0021-operator-proof-receipt-contract.md)
and [ADR 0022](../../adr/0022-adoption-doc-version-and-link-policy.md) to the
`v1.2.0-rc.1` adoption surfaces. Local contracts, manifests, and planning docs
are evidence that a surface is designed or scaffolded. They are not proof that
an external operator surface is published, installable, hosted-smoked, or
usable by adopters.

The receipt home for this RC is
[docs/proof/v1.2.0-rc.1/](../../proof/v1.2.0-rc.1/README.md). Until a completed
receipt exists there, external adoption claims stay planned/pending receipt.

## Claim Ceiling

| State | Allowed wording | Not allowed without receipt |
| --- | --- | --- |
| Local contract or scaffold observed | "contract exists", "in-repo adapter exists", "planned proof lane" | "published", "installable", "Marketplace-ready", "hosted-smoked" |
| External run or listing not recorded | "planned/pending receipt" | "proven", "live", "ready for adopters" |
| Completed receipt recorded | receipt-bounded claim only | broader claims than the receipt proves |

## L6 Gate Status

| ID | Gate | Status | Evidence and next action |
| --- | --- | --- | --- |
| L6-01 | Audit docs for stable, RC, and planned labels | Partial | This file records the current claim ceiling and pending receipt inventory. Existing operator docs outside this wave remain unmodified and still require the L6-02 wording/link pass before the gate can close. |
| L6-02 | Refresh README, USERGUIDE, golden paths, adoption docs, and integration docs | Planned/pending follow-up | The audit identifies surfaces that need bounded wording after this wave. This task is blocked on the broader L6 docs pass and receipts. |
| L6-03 | Reconcile VS Code publication contradictions | Planned/pending receipt | Local docs conflict: the operator guide says no publication claim, while the runtime tranche records a successful publish. A VS Code receipt must resolve this before published-copy ships. |
| L6-04 | Update the root marketplace action backlog state | Planned/pending follow-up | The root backlog is outside this wave's write scope. The action remains pending hosted smoke, immutable tag, moving `v1`, release, and Marketplace receipt. |
| L6-05 | Create proof ledger directory and receipt template | Complete for template setup | See [proof README](../../proof/v1.2.0-rc.1/README.md), [receipt template](../../proof/v1.2.0-rc.1/receipt-template.md), and [surface ledger](../../proof/v1.2.0-rc.1/surface-ledger.md). |

## Surface Audit

| Surface | Local evidence observed | Unproven external claim | Required receipt before live wording | Current RC label |
| --- | --- | --- | --- | --- |
| GitHub Action | [Action contract](../../integrations/github-marketplace-action-contract.md); root action backlog; [runtime tranche](../../research/2026-05-15-marketplace-runtime-tranche.md) records local action work and a hosted smoke blocked before runner execution. | `0ryant/taudit-action@v1` installability, immutable tag, moving `v1`, GitHub release, and Marketplace listing. | Hosted SHA smoke run URL, action commit SHA, taudit version, exit code, outcome, immutable tag readback, moving `v1` readback, release/listing URL, operator, timestamp, residual risk. | Planned/pending receipt. |
| Azure DevOps task | [ADO contract](../../integrations/azure-devops-marketplace-extension-contract.md); [live proof checklist](../../integrations/azure-devops-live-proof-checklist.md); [extension manifest](../../../integrations/azure-devops-extension/vss-extension.json); [task manifest](../../../integrations/azure-devops-extension/Taudit/task.json). | A real installed `Taudit@1` operator run with expected outputs and artifact contents. Some docs use installable-task language; this audit treats that as pending until a live receipt is recorded. | Azure run URL, pool/agent, extension version/ref, task version, source commit SHA, resolved taudit version, `tauditVerify.taudit.outcome`, `taudit-task-smoke` artifact file list, artifact checksum where applicable, sanitization note, residual risk. | Planned/pending receipt. |
| VS Code extension | [VS Code contract](../../integrations/visual-studio-marketplace-extension-contract.md); [operator guide](../../integrations/visual-studio-marketplace-extension-operator-guide.md); [manifest](../../../integrations/vscode-extension/package.json); [publish track](../../research/2026-05-15-visual-studio-marketplace-publish-track.md); [runtime tranche](../../research/2026-05-15-marketplace-runtime-tranche.md). | Publication state and Marketplace installability are contradictory in local docs. No completed proof receipt is in this RC ledger. | VSIX path and checksum, local preflight command result, hosted preflight run URL, Marketplace listing URL/readback, installed extension id/version, command smoke result, source commit SHA, timestamp, operator, sanitization note, residual risk. | Planned/pending receipt until reconciled. |
| crates.io and docs.rs | Workspace manifests show current local versions: `taudit` [1.1.5](../../../crates/taudit-cli/Cargo.toml) and `taudit-api` [0.4.1](../../../crates/taudit-api/Cargo.toml); [release-gates brief](workstreams/release-gates-semver.md) defines the `v1.2.0-rc.1` plan. | `v1.2.0-rc.1` published to crates.io or rendered on docs.rs. | crates.io version URLs/readback, docs.rs build/render URL, package checksum or registry digest where available, source commit SHA, timestamp, operator, outcome, residual risk. | Planned/pending receipt for RC; stable examples remain separate from RC claims. |
| Release assets, SBOM, and attestation | [Release trust](../../release-trust.md) describes expected archives, checksums, SPDX/CycloneDX SBOMs, and GitHub Artifact Attestations; [release-gates brief](workstreams/release-gates-semver.md) makes them RC gates. | `v1.2.0-rc.1` release assets, checksums, SBOMs, and attestations exist and verify. | Tag workflow run URL, release URL, asset names, SHA-256 checksums, SBOM names/checksums, `gh attestation verify` command results for at least one archive and one SBOM, commit SHA, timestamp, operator, residual risk. | Planned/pending receipt after tag workflow. |
| Marketplace media | [Shot list](../../integrations/marketplace-media-shot-list.md) defines VS Code and Azure proof media targets. | Screenshots or GIFs prove real Marketplace/operator surfaces. | Asset filename, source receipt link, capture command or run URL, artifact checksum where applicable, timestamp, operator, secrets/sanitization note, residual risk. | Planned/pending receipt; mockups or YAML-only screenshots must not prove live adoption. |
| Docs links and backlinks | [Golden paths](../../golden-paths.md), [adoption runbook](../../adoption-day0-day1.md), [integration index](../../integrations/index.md), and [demo story](../../demos/corpus-expo-docs-authority-exploit-story.md) are local adoption targets. | Marketplace listings, release notes, README, and integration docs all link to live/current surfaces. | Link/path audit command output, listing backlink readbacks where external, source commit SHA, timestamp, operator, outcome, residual risk. | Planned/pending receipt for external listing backlinks; local links can be checked independently. |

## Current Contradictions To Resolve

| Area | Contradiction | Required resolution |
| --- | --- | --- |
| VS Code publication | The operator guide says it does not claim publication, while the runtime tranche records `algol.taudit-vscode@0.1.6` as published. | Record a VS Code receipt or downgrade all publication wording to planned/pending receipt. |
| Azure DevOps live proof | The ADO package appears shaped for Marketplace publication, and the runtime tranche records authenticated readback, but the live proof checklist still has no `Taudit@1` smoke receipt. | Record one real `Taudit@1` run receipt before claiming task-ready adoption proof. |
| Azure version alignment | The ADO contract names default taudit `1.1.5`; the task manifest and README examples still show `1.1.4` in places. | Version/link pass in L6-02 after the release/version owner confirms the intended stable pin. |
| GitHub Action state | The root action backlog has implementation tasks checked, but hosted runner smoke, tags, release, and Marketplace publish remain open. | Keep action wording planned/pending receipt until the hosted action receipt chain is complete. |

## Receipt Requirements

Every completed receipt for this RC must include these fields:

- surface
- version/ref
- command/run URL
- commit SHA
- artifact checksum where applicable
- timestamp
- operator
- outcome
- secrets/sanitization note
- residual risk

Use the [receipt template](../../proof/v1.2.0-rc.1/receipt-template.md). A receipt
with missing required fields is a draft, not proof.

## Next Dependency Unblocked

This audit unblocks the L6-02 wording pass and the L1/L6 receipt collection
lanes by giving each adoption surface a bounded claim ceiling and a receipt
slot. It does not prove any external surface by itself.
