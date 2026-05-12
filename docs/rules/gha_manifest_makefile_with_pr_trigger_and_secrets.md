# GHA Manifest Makefile On PR Trigger With Secrets

**Rule ID:** `gha_manifest_makefile_with_pr_trigger_and_secrets`
**Severity:** High
**Category:** Supply Chain
**Tags:** security, supply-chain, manifest-as-code, github-actions

## Detection

Fires when a workflow's `on:` block includes `pull_request`, `pull_request_target`, `workflow_run`, or `issue_comment`, AND a step's `run:` body invokes `make`, `make <target>`, `gmake`, `bmake`, or any equivalent that reads a `Makefile` from the working tree, AND the same job has `${{ secrets.* }}` references, default `GITHUB_TOKEN` with write scope, `id-token: write`, or registry/cloud/PAT credentials.

## Risk

`Makefile` recipes are arbitrary shell. A PR that adds a recipe — or modifies an existing one targeted by the workflow — runs PR-author shell with the CI step's full env. Common dangerous patterns:

- a workflow that runs `make lint`/`make test`/`make format` against PR head — the lint/test/format target is whatever the PR's `Makefile` says it is;
- a workflow that runs `make release` after merge — the release target executes against the just-merged PR's `Makefile`, before any further review;
- a workflow with `make docker-build` that runs under registry credentials.

Empirically, `make` is the single most-invoked build tool in the public corpus (~258 occurrences) and at least 7 workflows reach `make` from `pull_request_target` triggers with credential-bearing env.

## Remediation

Treat `Makefile` as code subject to CODEOWNERS-gated review. Where PR-trigger workflows must invoke `make`, restrict the targets to a hardcoded allowlist passed via `make --warn-undefined-variables -B <known-target>` and reject any PR that modifies the `Makefile` without CODEOWNERS approval. Where lint/test invocation is required on PRs, run `make` in a sandboxed job with no secrets and promote the result to the privileged job only after content verification.
