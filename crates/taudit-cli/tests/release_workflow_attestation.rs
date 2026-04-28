//! Regression: release pipeline keeps GitHub Artifact Attestation steps so
//! docs (`gh attestation verify`, release-trust) stay truthful. No `gh` CLI
//! or network — pure file contract.

mod common;

use common::workspace_root;

#[test]
fn release_workflow_includes_provenance_attestation_steps() {
    let path = workspace_root().join(".github/workflows/release.yml");
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

    let uses_attest = text
        .matches("uses: actions/attest-build-provenance")
        .count();
    assert!(
        uses_attest >= 3,
        "{}: expected at least 3 `uses: actions/attest-build-provenance` steps (SBOM x2 + release archive), found {uses_attest}",
        path.display()
    );

    assert!(
        text.contains("id-token: write"),
        "{} must declare id-token: write for OIDC attestation signing",
        path.display()
    );
    assert!(
        text.contains("attestations: write"),
        "{} must declare attestations: write",
        path.display()
    );
    assert!(
        text.contains("gh attestation verify"),
        "{} should document consumer verification via gh attestation verify",
        path.display()
    );
}
