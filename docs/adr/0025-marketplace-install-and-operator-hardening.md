# ADR 0025: Visual Studio Marketplace install path and operator hardening

- **Status:** Accepted
- **Date:** 2026-05-23
- **Context:** [VS Code operator guide](../integrations/visual-studio-marketplace-extension-operator-guide.md), [Azure DevOps task contract](../integrations/azure-devops-marketplace-extension-contract.md), [Marketplace install brief](../marketing/visual-studio-marketplace-install-brief.md), [install and hardening subtasks](../research/2026-05-23-marketplace-install-and-hardening-subtasks.md).

## Context

taudit now has live Visual Studio Marketplace surfaces for both local editor
review and Azure Pipelines execution:

- `Algol.taudit-vscode`
- `Algol.taudit-azure-pipelines`

External user feedback says the Azure DevOps extension is the right adoption
UX because it removes Rust install, Cargo cache, and PATH work from ordinary
pipeline authors. The same feedback identifies rough edges that can create
adoption friction:

- path-sensitive baseline identity can produce fixed/new churn when CI stages
  or copies YAML files before scanning;
- Azure DevOps task input behavior can feel magical when task inputs and
  `INPUT_*` environment variables appear to interact;
- partial graph modeling around templates, runtime expressions, variable
  groups, and conditions can be misread as either failure or success;
- hashed per-pipeline baselines need stale-file lifecycle tooling;
- graph artifacts need a review-friendly HTML or SVG path in addition to DOT;
- graph mode and verify mode need regression coverage for shared path and
  baseline semantics.

## Decision

Use Visual Studio Marketplace as the primary install path for editor and Azure
DevOps adoption, while treating the reported rough edges as release-line
hardening work rather than as reasons to pause install messaging.

The public message is:

```text
taudit adds the CI/CD authority-graph layer that other scanners do not cover.
```

The operator contract is:

- VS Code users install `Algol.taudit-vscode` for local verify, scan, and graph
  review.
- Azure DevOps users install `Algol.taudit-azure-pipelines` and add `Taudit@1`
  to pipeline YAML.
- `verify` is the gate mode.
- `scan` is advisory and migration-oriented.
- `graph` is a review artifact mode.
- policy, ignore files, suppressions, and baselines remain distinct controls.
- partial graph output is worded as a review focus area, not as a failure and
  not as a clean bill of health.

The hardening backlog must be tracked as first-class work:

- path identity documentation and optional normalization/remap design;
- Azure DevOps task input and environment-variable contract tests/docs;
- graph/verify parity regression tests;
- stale baseline listing/prune workflow;
- HTML/SVG-friendly graph artifact output;
- Marketplace growth assets and install proof loop.

## Alternatives considered

### Keep Marketplace links quiet until hardening is complete

Rejected. The Azure DevOps task already solves a real adoption problem and
the rough edges are documentable. Waiting would hide useful value from teams
that can benefit from the installable wrapper now.

### Push CLI-only adoption first

Rejected for Azure DevOps. CLI-only adoption requires each team to solve Rust
install, binary caching, PATH, and runner portability. The extension is the
lower-friction operator surface.

### Canonicalize all paths silently

Deferred. Path identity is part of the current authority and baseline contract.
Changing it silently could collapse distinct scan surfaces. A future change
must be explicit, tested, and documented as a path remap or logical-root
contract.

### Hide partial graph modeling from users

Rejected. Partial modeling is an important honesty signal. The wording should
make it actionable rather than removing it from the surface.

## Consequences

- Marketing and docs can tell users to install from Visual Studio Marketplace.
- Maintainers must keep Marketplace copy, repo docs, and operator contracts in
  sync with live listings.
- Baseline path semantics become a documented contract until a future ADR or
  implementation change replaces them.
- The rough-edge work is now a product-hardening lane, not scattered feedback.

## Acceptance criteria

- The repo has a marketing-ready install brief with both Marketplace links.
- README and integration docs link directly to the live Marketplace listings.
- A task plan exists for path identity, input/env behavior, partial wording,
  baseline lifecycle, graph artifact output, and graph/verify parity.
- Any future path normalization feature includes tests proving graph and
  verify agree on path and baseline identity.
- Any future Azure DevOps task input change includes tests proving task inputs
  and `INPUT_*` materialization are either equivalent or explicitly documented
  as different.

## Metrics

- Time from Marketplace discovery to first local `Verify Workspace`.
- Time from Azure DevOps install to first `Taudit@1` run.
- Number of installs and active installs on both Marketplace listings.
- Number of support issues about baseline path churn.
- Number of support issues about task input/environment behavior.
- Ratio of graph artifacts opened by reviewers to graph artifacts produced.
- Partial modeling findings that result in documented review action.

## Residual risks

- Live Marketplace install counts and ratings are external state and can drift
  independently of repo docs.
- Current evidence confirms Marketplace pages render, but this ADR does not by
  itself prove fresh install smoke, upgrade smoke, or every Marketplace asset.
- Path identity remains surprising until the docs and regression tests are
  tightened.
- HTML/SVG graph output and stale baseline pruning are not implemented by this
  decision; they are accepted backlog items.
