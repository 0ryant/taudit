# GHA Temporal OIDC Freshness Across Multi-Step Build

**Rule ID:** `gha_temporal_oidc_freshness_across_multistep_build`
**Severity:** High
**Category:** Trust
**Tags:** security, oidc, temporal, attestation, github-actions

## Detection

Fires when a job declares `id-token: write`, mints an OIDC token early
(via `actions/attest@*`, `actions/attest-build-provenance@*`,
`sigstore/cosign-installer` followed by `cosign sign --yes`, or any
explicit `core.getIDToken()` call), AND uses the token after a step
sequence whose cumulative time may exceed the OIDC token's validity
window (default ~10 minutes for GitHub OIDC). Detection signals:

- `timeout-minutes: > 30` on the same job;
- intervening long-running steps: `docker build`/`docker buildx build`,
  `cargo build`, `mvn package`, `gradle build` of large workspaces;
- attestation/sign step at job-end after such builds.

## Risk

GitHub OIDC tokens have a default lifetime of approximately 10
minutes. A workflow that mints OIDC at job start and uses it after a
multi-stage build may submit a stale token to the downstream verifier
(Fulcio, cloud STS, custom trust policy). Whether downstream verifiers
re-validate `exp` at use time vs at issue time is heterogeneous:

- Fulcio rejects expired tokens;
- some custom trust policies do not check `exp` if the cached cert is
  still valid;
- cloud STS providers vary.

When the token is stale, two failure modes appear: (a) the workflow
errors at use time and the build fails (no security impact); (b) the
verifier silently accepts a stale token because of weak `exp`
enforcement (security impact: any token leaked from a prior run could
be replayed within the verifier's tolerance window).

The class concern is consistency: workflow authors do not see the OIDC
issue time, do not know the token's `exp`, and cannot easily measure
the multi-step delay.

## Remediation

Mint OIDC immediately before use, not at job start. Refresh the token
between long-running steps. Pair with a verifier configuration that
strictly enforces `exp` and rejects tokens within a configurable safety
margin. Where possible, use ephemeral signing identities that do not
require a long-lived token.

For attestation flows specifically, structure the job so that the
attest step is preceded by a fresh OIDC mint:

```yaml
- name: Refresh OIDC immediately before attestation
  run: |
    # Discard any cached OIDC; force re-mint
    unset ACTIONS_ID_TOKEN_REQUEST_URL
    unset ACTIONS_ID_TOKEN_REQUEST_TOKEN
- name: Attest
  uses: actions/attest-build-provenance@<sha>
  with:
    subject-path: ./dist/*
```
