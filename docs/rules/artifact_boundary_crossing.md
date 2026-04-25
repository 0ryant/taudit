# Artifact Boundary Crossing

**Rule ID:** `artifact_boundary_crossing`
**Severity:** High
**Category:** Supply Chain
**Tags:** security, supply-chain

## Detection

taudit looks for Artifact nodes that are produced by a privileged Step (one with `HasAccessTo` a Secret or Identity) and consumed by a Step in a lower trust zone. The producer step must have authority access — artifacts produced by unprivileged steps are excluded because there is no credential blast radius. A finding fires once per (producer, artifact, consumer) triple.

## Risk

The attack scenario is a poisoned artifact:

1. A privileged job (with access to signing keys, deploy credentials, or a cloud identity) produces a build artifact — a binary, package, or container image.
2. The artifact is uploaded to GitHub Actions artifact storage, an ADO pipeline artifact drop, or an intermediate registry.
3. A lower-trust job or an external consumer downloads and executes that artifact without verifying its provenance.
4. If the privileged job's build environment is compromised at step 1, the artifact contains attacker-controlled content. Downstream consumers execute it with their own permissions — which may include production deployment access.

Without attestation, there is no way for a consumer to distinguish a legitimate artifact from a tampered one. The artifact itself is the trust boundary — and it is unguarded.

An attacker who compromises the CI runner used in step 1 can also exfiltrate the credentials directly (see [authority_propagation](authority_propagation.md)), but even if they don't — injecting a backdoor into the artifact itself is a persistent compromise with long-term payoff.

## Remediation

1. **Generate provenance attestation in the privileged job (GHA):**
   ```yaml
   permissions:
     id-token: write
     attestations: write
     contents: read
   
   steps:
     - name: Build
       run: ./build.sh
       id: build
   
     - name: Attest build provenance
       uses: actions/attest-build-provenance@<sha>
       with:
         subject-path: ./dist/myapp
   ```

2. **Verify the attestation before consuming (GHA):**
   ```bash
   gh attestation verify ./dist/myapp \
     --repo your-org/your-repo \
     --format json
   ```
   This fails if the artifact was not produced by your workflow with a verifiable OIDC identity.

3. **Use digest-based artifact references:** When uploading and downloading, record and verify the digest:
   ```yaml
   - uses: actions/upload-artifact@<sha>
     with:
       name: build-output
       path: ./dist/
   
   # In consumer job
   - uses: actions/download-artifact@<sha>
     with:
       name: build-output
   ```

4. **For container images — sign with cosign:**
   ```bash
   cosign sign --yes ghcr.io/your-org/your-image@$DIGEST
   
   # Consumer verifies
   cosign verify ghcr.io/your-org/your-image@$DIGEST \
     --certificate-identity-regexp "https://github.com/your-org/your-repo" \
     --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
   ```

5. **Verify:** Re-run `taudit scan`. The finding should resolve once attestation is added. Also check [uplift_without_attestation](uplift_without_attestation.md) — it fires as a softer signal on OIDC workflows without attestation steps.

## See also

- [uplift_without_attestation](uplift_without_attestation.md) — Info-level signal for missing attestation on OIDC workflows
- [SLSA provenance levels](https://slsa.dev/spec/v1.0/levels)
- [GitHub Artifact Attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds)
- [cosign keyless signing](https://docs.sigstore.dev/cosign/signing/overview/)
