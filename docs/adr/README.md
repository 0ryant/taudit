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

## Conventions

- **Numbering:** `NNNN-short-title.md`, four-digit sequence.
- **Status:** Proposed / Accepted / Superseded / Deprecated in the ADR body.
- **Supersession:** New ADR links to the old one and marks the old status `Superseded by ADR NNNN`.
