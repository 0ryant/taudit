# Architecture Decision Records (ADRs)

Records in this directory capture **significant** product and technical decisions for taudit: context, decision, and consequences. They supplement [positioning.md](../positioning.md), [authority-graph.md](../authority-graph.md), and the versioned schemas.

| ADR | Title |
|-----|--------|
| [0001](0001-graph-native-exports-and-leverage.md) | Graph as product: native exports (Mermaid) and leverage strategy |
| [0002](0002-authority-signal-roadmap-phased.md) | Authority signal roadmap: phased goals, deliverables, non-goals |
| [0003](0003-strategic-spine-adoption-phased.md) | Strategic spine, merge gate, adoption: phased tasks (council-aligned; see implementation status in ADR) |
| [0004](0004-prereleases-publish-to-crates-io.md) | Prereleases publish to crates.io, gated by Cargo's resolver |
| [0005](0005-authority-edge-classifier-and-witness-handoff.md) | Authority-edge classifier and witness handoff |
| [0006](0006-exploit-path-view-and-ruleset.md) | Exploit-path view and ruleset |
| [0007](0007-standardize-release-harness.md) | Standardize releases through a repo-owned harness |
| [0008](0008-synthesize-research-into-maintained-artifacts.md) | Synthesize research into maintained artifacts, not scratch files |
| [0009](0009-v1-2-release-contract-and-semver-map.md) | v1.2 release contract and SemVer map |
| [0010](0010-public-contract-boundary-and-api-readiness.md) | Public contract boundary and API readiness |
| [0011](0011-ordered-authority-evidence-model.md) | Ordered authority evidence model |
| [0012](0012-public-output-identity-contract.md) | Public output identity contract |
| [0013](0013-evidence-rendering-and-output-ceiling.md) | Evidence rendering and output ceiling |
| [0014](0014-parser-completeness-and-platform-promise.md) | Parser completeness and platform promise |
| [0015](0015-real-input-corpus-provenance-and-runner.md) | Real-input corpus provenance and runner |
| [0016](0016-external-resolution-and-enrichment-boundary.md) | External resolution and enrichment boundary |
| [0017](0017-current-output-profile-and-contract-examples.md) | Current output profile and contract examples |
| [0018](0018-suppression-baseline-and-exit-code-semantics.md) | Suppression, baseline, and exit-code semantics |
| [0019](0019-reporter-sink-sanitization-boundary.md) | Reporter and sink sanitization boundary |
| [0020](0020-output-conformance-harness-and-rc-gate.md) | Output conformance harness and RC gate |
| [0021](0021-operator-proof-receipt-contract.md) | Operator proof receipt contract |
| [0022](0022-adoption-doc-version-and-link-policy.md) | Adoption doc version and link policy |
| [0023](0023-ecosystem-evidence-envelope-and-stack-contracts.md) | Ecosystem evidence envelope and stack contracts |
| [0024](0024-external-diagnostic-intake-boundary.md) | External diagnostic intake boundary |

## Conventions

- **Numbering:** `NNNN-short-title.md`, four-digit sequence.
- **Status:** Proposed / Accepted / Superseded / Deprecated in the ADR body.
- **Supersession:** New ADR links to the old one and marks the old status `Superseded by ADR NNNN`.
