# GHA Attestation Subject Path Workspace Glob With PR Trigger

**Rule ID:** `gha_attestation_subject_path_workspace_glob_with_pr_trigger`
**Severity:** High
**Category:** Supply Chain
**Tags:** security, supply-chain, attestation, slsa, sigstore, github-actions

## Detection

Fires when `actions/attest@*`, `actions/attest-build-provenance@*`, or `actions/attest-sbom@*` uses `subject-path:` containing a workspace glob (`*`, `**`, `dist/*`, `./builds/**/*.tar.gz`), and the workflow's `on:` block includes `pull_request`, `pull_request_target`, or `workflow_run`, and the attest step's `if:` gate does not unambiguously exclude those triggers.

## Risk

`subject-path` accepts globs and the action hashes whatever files match. On a PR-reachable workflow, files written into the workspace by the PR's checkout, by build steps that consume PR-controlled source, or by composite actions whose inputs include PR data become the bytes that get signed. The OIDC and cert chain are real, but the bytes are PR-author-chosen.

Downstream verifiers that check the cert SAN's `Source URI` and workflow filename without pinning to `refs/heads/main` accept these PR-built artifacts as authentic. If the workflow file's identity passes the verifier policy, the artifact rides through.

## Remediation

Gate the attest step with `if: github.event_name == 'push' && (startsWith(github.ref, 'refs/tags/v') || github.ref == 'refs/heads/main')` (or equivalent) so PR triggers cannot reach it. Pin verifiers to the expected ref via `--certificate-identity` regex including the ref segment. Where attestation on PRs is intentional (e.g., to surface preview builds), publish attestations to a different audience or with a clearly distinguished cert identity so production verifiers cannot accept them.
