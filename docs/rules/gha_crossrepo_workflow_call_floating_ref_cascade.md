# GHA Cross-Repo Workflow-Call Floating-Ref Cascade

**Rule ID:** `gha_crossrepo_workflow_call_floating_ref_cascade`
**Severity:** High
**Category:** Supply Chain
**Tags:** security, supply-chain, manifest-as-code, cross-repo, github-actions

## Detection

Fires when a workflow uses `uses: <org>/<repo>/.github/workflows/<X>.yml@<ref>` where `<ref>` is `main`, `master`, `HEAD`, or a floating major version (`v1`, `v2`, `v3`, `v4`, `v5`), AND the producing repo is not the same as the consuming repo. The reference must not be a 40-character SHA pin.

## Risk

A reusable callable workflow runs in the caller's runner with the caller's permissions and the caller's secrets (whether named or `secrets: inherit`). When the ref is mutable, whoever can push to the producer repo's branch determines what code runs the next time any consumer triggers the call. The producer's branch protection is the actual security boundary, not the consumer's.

This is a different boundary from "unpinned action": that rule fires on any third-party action with a floating ref. This rule specifically classifies callable-workflow refs because the caller-callee security model is more permissive (full caller env, full caller secrets, runs in caller's repo context with caller's `GITHUB_TOKEN`) than a typical action invocation, and because callable-workflow refs are usually internal-org tooling that workflow authors mentally categorize as "trusted" without verifying the producer's branch protection.

The class is widespread:

- 56 cross-repo callable-workflow refs at `@main`/`@master`/floating major in the public corpus.
- First-party `actions/setup-node` consumes `actions/reusable-workflows/.github/workflows/check-dist.yml@main` — even GitHub's own actions org uses this pattern.
- `langchain-ai/langchain/_refresh_model_profiles.yml@master` is consumed cross-workflow; `@master` is mutable.
- `grafana/grafana` consumes `grafana/security-patch-actions/.github/workflows/create-patch.yml@main` for security-patch automation.

## Remediation

Pin every cross-repo callable-workflow ref to a 40-character SHA. Where a floating ref is intentional, document the producer repo's branch protection and CODEOWNERS strength, and ensure both meet or exceed the consumer's. For high-stakes flows (release, deploy, security patches), require SHA pinning and audit the producer repo's `main` history before each consumer release.
