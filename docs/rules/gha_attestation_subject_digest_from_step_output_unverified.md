# GHA Attestation Subject Digest From Step Output (Unverified)

**Rule ID:** `gha_attestation_subject_digest_from_step_output_unverified`
**Severity:** High
**Category:** Supply Chain
**Tags:** security, supply-chain, attestation, slsa, sigstore, github-actions

## Detection

Fires when `actions/attest@*`, `actions/attest-build-provenance@*`, or `actions/attest-sbom@*` is invoked with `subject-digest:` interpolated from `${{ steps.*.outputs.* }}`, `${{ needs.*.outputs.* }}`, `${{ inputs.* }}`, or `${{ matrix.* }}`, and the same job declares `id-token: write` and `attestations: write`.

The action accepts `subject-digest` AS-IS without verifying the digest matches any file at `subject-name` or `subject-path` (confirmed in the action's `action.yml` documentation). Whoever populates the producing step's output controls what gets signed.

## Risk

The signed attestation binds the workflow's verified identity (OIDC token, Fulcio cert with the workflow path in the SAN) to a digest that the action did not independently compute. Any earlier step that can write to the producing step's outputs — or whose output computation includes attacker-influenced state (PR-controlled file content, matrix value, workflow_dispatch input, reusable-workflow input) — controls the signed predicate. Downstream verifiers checking only `Source URI` and workflow path accept the attestation as authentic provenance for an artifact that was not actually built by the workflow.

This is supply-chain trust laundering: the cryptographic envelope is genuine; the binding to the artifact is not.

## Remediation

Compute the subject digest in the same step that runs the attest action, and compute it from a file the action's `subject-path` input would also hash. Prefer `subject-path` (which the action hashes itself) over `subject-digest` whenever possible. If `subject-digest` must be used, validate the producing step is sandboxed against PR-controlled input and that no later step can mutate the output before attest. Pin the action to a SHA, not a major version, so behavior is stable.
