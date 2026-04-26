# No Workflow-Level Permissions Block

**Rule ID:** `no_workflow_level_permissions_block`
**Severity:** Medium
**Category:** Configuration
**Tags:** security, configuration, github-actions
**Platform:** GitHub Actions only

## Detection

Positive-invariant rule — fires on the *absence* of an expected defensive control rather than the presence of a misconfigured one. The rule fires when ALL of the following hold:

1. The graph platform is GitHub Actions (`META_PLATFORM == "github-actions"`).
2. The parser stamped `META_NO_WORKFLOW_PERMISSIONS = "true"` on the graph (workflow file declares no top-level `permissions:` key).
3. No Identity node exists with a name starting `GITHUB_TOKEN (` and no top-level `GITHUB_TOKEN` Identity carries a `META_PERMISSIONS` annotation. (Per-job overrides create per-job Identity nodes; their presence means at least one job has its own scoped permissions block, in which case this rule does not fire.)

Fires once per workflow file.

## Risk

Without an explicit `permissions:` declaration, `GITHUB_TOKEN` falls back to the broad GitHub default scope. Today that's roughly `contents: write`, `packages: write`, `metadata: read`, plus repository-type-specific extras. Tomorrow it might change again — GitHub has shifted these defaults twice in the last three years.

The defensive problem is twofold:

- **Triage opacity.** A reviewer or incident responder cannot determine the workflow's blast radius from the file alone. They must cross-reference the GitHub default-permissions documentation for the repo type *as it stood when the workflow last ran*.
- **Compounding effect.** Every other finding in the same workflow gets the broadest possible scope as its starting point. A `checkout_self_pr_exposure` in a workflow with an explicit `permissions: { contents: read }` is materially less dangerous than the same finding in a workflow with the default broad token.

The blue-team corpus scan saw roughly 730 GHA workflow files in this state (~76 % of the GHA corpus), so this is the single most common defensive gap across the public GHA ecosystem.

## Remediation

The minimum fix is a top-level `permissions: {}` (strips every default), followed by per-job grants of only what each job needs:

```yaml
name: ci
on:
  push:
permissions: {}                  # strips defaults at the workflow level
jobs:
  lint:
    permissions:
      contents: read             # grant only what lint actually needs
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - run: npm run lint

  release:
    permissions:
      contents: write            # for tag push
      packages: write            # for npm publish
      id-token: write            # for npm provenance
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - run: npm publish --provenance
```

Adding a workflow-level `permissions:` block is the single highest-leverage GHA hardening change a team can make: one line, no behaviour change for any well-written workflow, immediate audit clarity, and a much smaller blast radius for every other finding the file might carry.

## See also

- [over_privileged_identity](over_privileged_identity.md) — fires when a *declared* permissions block is broader than needed; this rule is its negative-space complement.
- [GitHub Docs — Assigning permissions to jobs](https://docs.github.com/actions/using-jobs/assigning-permissions-to-jobs)
- [GitHub Docs — Default GITHUB_TOKEN permissions](https://docs.github.com/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token)
