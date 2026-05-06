# GHA Cosign Certificate Identity Regex Repo-Only Without Ref

**Rule ID:** `gha_identity_cosign_certificate_identity_repo_only_no_ref`
**Severity:** Medium-High
**Category:** Trust
**Tags:** security, identity, sigstore, cosign, github-actions

## Detection

Fires when a workflow runs `cosign verify` / `cosign verify-blob` /
`cosign verify-attestation` with `--certificate-identity-regexp`
matching the repo path WITHOUT including the `@refs/heads/` or
`@refs/tags/` segment of the cert SAN. Examples:

- `--certificate-identity-regexp 'https://github.com/<org>/<repo>/.*'`
- `--certificate-identity-regexp 'https://github.com/<org>/<repo>/.github/workflows/.*'`
- `--certificate-identity 'https://github.com/<org>/<repo>'` (exact, no ref)

Severity rises further when the regex is a wildcard
(`'.*'`/`'.+'`/`'[^.]+'`).

## Risk

The Fulcio cert's `Subject Alternative Name` for a GitHub Actions OIDC
identity has the form
`https://github.com/<org>/<repo>/.github/workflows/<file>@refs/heads/<branch>`
(or `@refs/pull/<n>/merge`, `@refs/tags/<tag>`). Verifiers that match
only the repo prefix accept certs minted by ANY workflow run in that
repo — including a `pull_request` workflow that an internal contributor
opens.

Combined with the foundational TCA-1 primitive (the action accepts
`subject-digest` as-is), an attacker can produce a Fulcio cert whose
SAN reflects a PR ref and an in-toto Subject whose digest is
fabricated. A verifier configured with repo-only identity matches
both, and the laundered attestation passes verification.

This is the consumer-side companion to TCA-1 attestation laundering.

## Remediation

Anchor the identity regex to the expected ref or tag:

```bash
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/<org>/<repo>/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ...
```

Or equivalently: use exact `--certificate-identity` with the full ref.
For attestation verification specifically, pass `--source-digest` so
the verifier independently re-hashes the artifact against the cert
Subject. See sibling rule
`gha_verifier_gh_attestation_missing_source_digest_check`.
