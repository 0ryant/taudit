# v1.2.0-rc.1 Surface Ledger

Status: Planned/pending receipt inventory. This file is not proof that any
external surface is live.

| Receipt ID | Surface | Gate | Status | Required evidence |
| --- | --- | --- | --- | --- |
| GHA-001 | GitHub Action | Hosted SHA smoke | Planned/pending receipt | Use [GitHub Action template](templates/github-action-receipt.md). Hosted run URL, action commit SHA, taudit version, exit code, outcome, timestamp, operator, sanitization note, residual risk. |
| GHA-002 | GitHub Action | Immutable action tag | Planned/pending receipt | Use [GitHub Action template](templates/github-action-receipt.md). Tag name, tag target SHA, readback command or URL, timestamp, operator, outcome, residual risk. |
| GHA-003 | GitHub Action | Moving `v1` tag | Planned/pending receipt | Use [GitHub Action template](templates/github-action-receipt.md). `v1` target SHA, readback command or URL, timestamp, operator, outcome, residual risk. |
| GHA-004 | GitHub Action | GitHub release and Marketplace listing | Planned/pending receipt | Use [GitHub Action template](templates/github-action-receipt.md). Release URL, listing URL, version/ref, source commit SHA, timestamp, operator, outcome, residual risk. |
| ADO-001 | Azure DevOps task | Package/readback | Planned/pending receipt | Use [Azure task template](templates/azure-task-receipt.md). Extension id/version, package artifact checksum, listing/readback URL, source commit SHA, timestamp, operator, outcome, residual risk. |
| ADO-002 | Azure DevOps task | Live `Taudit@1` smoke | Planned/pending receipt | Use [Azure task template](templates/azure-task-receipt.md). Azure run URL, pool/agent, task version, resolved taudit version, `tauditVerify.taudit.outcome`, artifact file list, artifact checksum where applicable, timestamp, operator, sanitization note, residual risk. |
| VSC-001 | VS Code extension | VSIX package | Planned/pending receipt | Use [VS Code extension template](templates/vscode-extension-receipt.md). VSIX path, checksum, manifest version, source commit SHA, timestamp, operator, outcome, residual risk. |
| VSC-002 | VS Code extension | Local preflight and install smoke | Planned/pending receipt | Use [VS Code extension template](templates/vscode-extension-receipt.md). Command output or transcript path, installed extension id/version, command smoke result, timestamp, operator, sanitization note, residual risk. |
| VSC-003 | VS Code extension | Hosted preflight | Planned/pending receipt | Use [VS Code extension template](templates/vscode-extension-receipt.md). Hosted run URL, VSIX artifact checksum, install/activation smoke result, source commit SHA, timestamp, operator, residual risk. |
| VSC-004 | VS Code extension | Marketplace listing and install readback | Planned/pending receipt | Use [VS Code extension template](templates/vscode-extension-receipt.md). Listing URL, installed extension id/version, install source, command smoke result, timestamp, operator, residual risk. |
| CRATE-001 | crates.io | `taudit` `v1.2.0-rc.1` publish | Planned/pending receipt | Use [crates.io template](templates/crates-io-receipt.md). crates.io URL/readback, package version, source commit SHA, checksum or registry digest where available, timestamp, operator, outcome, residual risk. |
| CRATE-002 | docs.rs | `taudit` and public crate docs render | Planned/pending receipt | Use [docs.rs template](templates/docs-rs-receipt.md). docs.rs URL/build status, package version, source commit SHA, timestamp, operator, outcome, residual risk. |
| REL-001 | Release assets | GitHub release assets and checksums | Planned/pending receipt | Use [release asset template](templates/release-asset-receipt.md). Release URL, asset names, SHA-256 checksums, source commit SHA, timestamp, operator, outcome, residual risk. |
| REL-002 | Release assets | SBOM assets | Planned/pending receipt | Use [SBOM template](templates/sbom-receipt.md). SPDX and CycloneDX asset names, checksums, release URL, source commit SHA, timestamp, operator, outcome, residual risk. |
| REL-003 | Release assets | GitHub Artifact Attestations | Planned/pending receipt | Use [attestation template](templates/attestation-receipt.md). `gh attestation verify` command/run evidence for at least one archive and one SBOM, source commit SHA, timestamp, operator, outcome, residual risk. |
| MEDIA-001 | Marketplace media | VS Code and Azure proof media | Planned/pending receipt | Asset filenames, source receipt links, capture source, artifact checksum where applicable, timestamp, operator, sanitization note, residual risk. |
| DOC-001 | Docs links | Local link/path audit | Planned/pending receipt | Link/path check command, source commit SHA, timestamp, operator, outcome, residual risk. |
| DOC-002 | Docs links | External listing backlinks | Planned/pending receipt | Listing URLs, backlink readback, source commit SHA, timestamp, operator, outcome, residual risk. |
