# GHA Verifier `gh attestation verify` Missing `--source-digest`

**Rule ID:** `gha_verifier_gh_attestation_missing_source_digest_check`
**Severity:** High
**Category:** Supply Chain
**Tags:** security, supply-chain, attestation, verifier, github-actions

## Detection

Fires when a workflow runs `gh attestation verify <artifact>` with
`--repo <X>` and/or `--signer-repo <X>` flags but WITHOUT
`--source-digest` (or equivalent content-binding flag). The verifier
checks that the attestation was signed by an OIDC identity tied to the
expected repo; it does NOT check that the artifact's actual hash
matches the digest the attestation claims.

## Risk

`gh attestation verify` is the official GitHub CLI verifier for
build-provenance attestations. Its default flag set checks:

- the Sigstore bundle is well-formed;
- the Fulcio cert chain is valid;
- the cert's SAN matches the repo / signer-repo if specified.

Without `--source-digest`, the verifier does NOT independently re-hash
the artifact. The attestation's claim "this artifact has digest X" is
trusted as-is.

Combined with the foundational TCA-1 primitive (`actions/attest`'s
`subject-digest`-as-is), the attack chain is complete:

1. Producer-side: `actions/attest` accepts a fabricated `subject-digest`
   and signs it (TCA-1 / pack
   `ALGOL-CANDIDATE-20260506-064`).
2. Consumer-side: `gh attestation verify --repo <X> --signer-repo <X>`
   accepts the signed bundle without re-hashing the artifact bytes
   (this rule).

Net effect: an attestation signed under the project's real OIDC
identity binds an attacker-chosen artifact to an attacker-chosen
subject-name inside the project's namespace, and a default-configured
verifier accepts the binding.

In the public corpus, only 1 of 3 `gh attestation verify` invocations
includes `--source-digest`. The default-config behavior is widespread.

## Remediation

Always pass `--source-digest <digest>` to `gh attestation verify`,
where `<digest>` is computed locally from the artifact bytes BEFORE
the verifier is invoked:

```bash
ACTUAL_DIGEST="sha256:$(shasum -a 256 my-artifact.tgz | awk '{print $1}')"
gh attestation verify my-artifact.tgz \
  --repo my-org/my-repo \
  --signer-repo my-org/my-repo \
  --source-digest "${ACTUAL_DIGEST}"
```

Pair this with `--certificate-identity-regexp` anchored to a specific
workflow file and ref segment (see sibling rule
`gha_identity_cosign_certificate_identity_repo_only_no_ref`).

For class-level remediation: the gh CLI maintainers should consider
making `--source-digest` mandatory or emitting a strong warning when
omitted.
