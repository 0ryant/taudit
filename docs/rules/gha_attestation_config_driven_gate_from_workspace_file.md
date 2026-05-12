# GHA Attestation Config-Driven Gate From Workspace File

**Rule ID:** `gha_attestation_config_driven_gate_from_workspace_file`
**Severity:** High
**Category:** Supply Chain
**Tags:** security, supply-chain, attestation, slsa, sigstore, github-actions

## Detection

Fires when the `if:` gate that controls reachability of an attestation step (`actions/attest@*`, `actions/attest-build-provenance@*`, `actions/attest-sbom@*`) reads `fromJson(needs.<job>.outputs.<x>)` (or equivalent) and the producing job parses a workspace config file editable by pull requests — for example `dist-workspace.toml` (cargo-dist), `.goreleaser.yml`, custom JSON/YAML in repo root, or any tool config under `./` that PRs can modify.

## Risk

The workflow author intends the `if:` to gate on a release-mode flag that maintainers control. In practice, the flag value is whatever the workspace config file says at PR-build time. A PR that edits the config file to flip the mode (e.g., `pr_run_mode = "upload"` in cargo-dist) collapses the gate and reaches the attest step on the PR ref. The attestation is then minted with PR-author bytes and a real OIDC.

This is a config-driven attestation bypass — the gate exists but is not adversary-resistant.

## Remediation

Gate the attest step on event metadata (`github.event_name`, `github.ref`) and actor allowlists, not on workspace config. If the config file's flag is part of the build contract, validate the file is on the protected branch (`if: contains(toJson(github.event.commits.*.modified), 'dist-workspace.toml') == false || github.event_name == 'push'`) before honoring the flag. Move release-mode flags into branch-protected files, environment variables, or repository-level vars that PRs cannot edit.
