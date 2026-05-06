# GHA Cross-Repo Org-Level Credential Multiplexing

**Rule ID:** `gha_crossrepo_org_credential_multiplexing`
**Severity:** High
**Category:** Supply Chain
**Tags:** security, supply-chain, manifest-as-code, cross-repo, github-actions

## Detection

Fires when two or more workflows (in the same repo, or known across multiple repos in the same org during a multi-repo scan) reference the same shared callable target — `<same-org>/<shared-repo>/.github/workflows/<X>.yml@<ref>` or `<same-org>/<shared-action-repo>@<ref>` — at a floating ref AND with `secrets: inherit` (or with overlapping named secrets). The blast radius is the count of distinct callers.

## Risk

Organizations that centralize CI/CD into a shared callable repo create a single point of failure. One push to the shared repo's `main` branch reaches every consumer's next run, each running under that consumer's secrets. The compromise multiplexes: a single producer breach yields N distinct credential surfaces (N = number of consumer repos).

The shape is widespread across public orgs:

- **chef** — 8+ stub workflows in `chef/chef` call `chef/common-github-actions@main` with `secrets: inherit`.
- **huggingface** — 10+ workflows call `huggingface/hf-workflows@main` and `huggingface/hf-workflows/.github/actions/post-slack@main` with Slack tokens, AMD CI scheduled callers cascade `secrets: inherit`.
- **grafana** — 5+ workflows call `grafana/shared-workflows@main` and `grafana/grafana-github-actions@main`.
- **cloudposse** — 4+ workflows call `cloudposse/.github@main` and `cloudposse/github-actions-workflows-*@main` for release automation.
- **anchore** — 5+ workflows call `anchore/workflows@main` for release/PR coordination.

This is structurally distinct from any individual unpinned-ref or `secrets: inherit` finding because the impact is multiplicative. A finding-per-caller noise pattern obscures the architectural concern. The right alert is a single org-level finding with a blast-radius count.

## Remediation

Treat the shared callable repo as production infrastructure. Apply branch protection at least as strict as the strongest consumer (require admin reviewers, signed commits, required status checks, and disallow force-pushes). Pin every consumer's `uses:` to a SHA, and update SHAs on a coordinated cadence (with consumer audits). Where `secrets: inherit` is used cross-repo, replace it with explicit per-secret forwarding so each consumer's blast radius is bounded to the secrets the callable actually needs.
