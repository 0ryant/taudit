# GHA Container Image Attacker Influenced With Secret Env

**Rule ID:** `gha_container_image_attacker_influenced_with_secret_env`
**Severity:** High
**Category:** Credentials
**Tags:** security, credentials, authority-confusion, github-actions, container

## Detection

Fires when a job declares `container:` and the `container.image` value is interpolated from `${{ inputs.* }}`, `${{ matrix.* }}`, or `${{ github.event.* }}`, and the same job exports or inherits credential-bearing secrets — including `GITHUB_TOKEN` with write scope, npm/PyPI/Cargo/Container-registry publish tokens, cloud credentials, or `permissions.id-token: write`.

## Risk

The job's steps execute inside a container the attacker can choose. The image's entrypoint, embedded tools, environment, and on-disk state are fully controlled by the image supplier. Combined with secrets present in the job env, this collapses the action's apparent trust contract: every step appears to run "in the callee" but actually runs in attacker code. PATH hardening, helper-path validation, and pinned action SHAs do not mitigate, because the helper interpreter itself is replaced.

This is the container-side analogue of action-helper PATH confusion. The boundary that fails is the image trust boundary, not the executable name.

## Remediation

Pin `container.image` to a digest (`sha256:...`) sourced from a constant or a small enumerated set validated by an `if:` gate. Avoid interpolating image values from `inputs`, `matrix`, or `github.event.*` when the job carries any credential-bearing secret. If matrix-driven multi-image testing is required, drop secrets from the matrixed jobs.
