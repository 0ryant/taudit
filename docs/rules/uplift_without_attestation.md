# Uplift Without Attestation

**Rule ID:** `uplift_without_attestation`
**Severity:** Info
**Category:** Supply Chain
**Tags:** security, supply-chain

## Detection

taudit looks for workflows that have at least one OIDC-capable Identity node (`permissions: id-token: write` is set, which enables OIDC token issuance). If the graph contains such an identity but no Step node has `META_ATTESTS = "true"` (i.e., no step runs `actions/attest-build-provenance`, `actions/attest`, or equivalent), the rule fires once listing all steps that access the OIDC identity.

This is an Info-level finding. There is no immediate exploitation path — it signals a missed opportunity to provide downstream consumers with verifiable provenance.

## Risk

OIDC-enabled workflows are already doing something right: they have short-lived, unforgeable identity tokens. What they're not doing is using that identity to sign their artifacts.

The consequence: downstream consumers of the artifacts produced by this workflow have no way to verify:
- Which workflow produced the artifact
- Whether it was produced from the expected repository and branch
- Whether the artifact was tampered with after production

Without attestation, your artifact supply chain relies entirely on the security of the artifact storage mechanism (e.g., GitHub Actions artifact storage, a container registry). If an artifact is replaced or tampered with in storage, consumers cannot detect it.

This finding is especially relevant for workflows that build and publish packages, container images, or release binaries. The OIDC infrastructure is already in place — attestation is the missing last step.

## Remediation

1. **Add `actions/attest-build-provenance` after your build step:**
   ```yaml
   permissions:
     id-token: write       # already present — triggers this rule
     contents: read
     attestations: write   # add this
   
   steps:
     - name: Build
       id: build
       run: ./build.sh
     
     - name: Attest
       uses: actions/attest-build-provenance@<sha>
       with:
         subject-path: ./dist/myapp
   ```

2. **For container images — use `actions/attest-build-provenance` with the image digest:**
   ```yaml
   - name: Build and push image
     id: push
     uses: docker/build-push-action@<sha>
     with:
       push: true
       tags: ghcr.io/your-org/your-image:latest
   
   - name: Attest image
     uses: actions/attest-build-provenance@<sha>
     with:
       subject-name: ghcr.io/your-org/your-image
       subject-digest: ${{ steps.push.outputs.digest }}
       push-to-registry: true
   ```

3. **Consumers verify the attestation before use:**
   ```bash
   gh attestation verify ./dist/myapp \
     --repo your-org/your-repo
   ```

4. **Verify:** Re-run `taudit scan`. The Info finding should be gone once a step with the attest action is detected in the workflow. If it persists, confirm the attestation step uses one of the recognized action names (`actions/attest-build-provenance` or `actions/attest`).

## See also

- [artifact_boundary_crossing](artifact_boundary_crossing.md) — High-severity finding when an unattested artifact crosses a trust boundary
- [GitHub Artifact Attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds)
- [SLSA Build L2 — requires provenance](https://slsa.dev/spec/v1.0/levels#build-l2)
