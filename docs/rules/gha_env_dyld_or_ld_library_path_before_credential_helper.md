# GHA Dynamic-Linker Env Before Credential Helper

**Rule ID:** `gha_env_dyld_or_ld_library_path_before_credential_helper`
**Severity:** High
**Category:** Credentials
**Tags:** security, credentials, authority-confusion, github-actions, binary-hijack

## Detection

Fires when a same-job earlier step writes `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, or `DYLD_LIBRARY_PATH` (via `env:`, matrix, or `>> $GITHUB_ENV`) to a workspace, input-derived, or attacker-influenceable path, and a later step in the same job invokes a dynamically linked credential-bearing helper (`aws`, `az`, `gcloud`, `kubectl`, `helm`, `terraform`, `cosign`, `gpg`, compiled CLIs, signing tools) or a custom build that consumes credentials.

## Risk

Dynamic-linker env vars cause the loader to resolve shared objects from attacker-chosen directories or to preload arbitrary `.so`/`.dylib` files into every dynamically linked binary started afterwards. This is authority confusion below the helper boundary: the helper is at an absolute, action-owned path, but the libraries it links are not. An attacker-influenced earlier step can intercept credential reads, mint operations, signing primitives, or TLS validation inside the legitimate binary.

On macOS, `DYLD_*` is suppressed for SIP-protected binaries; downgrade severity when the later helper is a system-shipped binary on a hosted macOS runner. Linux `LD_*` has no equivalent suppression for non-suid binaries.

## Remediation

Treat dynamic-linker env writes as privileged. Confine them to the single step that needs them, or unset them before subsequent credential-bearing steps. Prefer building libraries into action-owned, validated locations. Audit `>> $GITHUB_ENV` writes for any of these variables and reject them in CI policy.
