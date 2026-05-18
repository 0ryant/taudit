# Azure DevOps Parser Lane

## Source Of Truth

`docs/parser-feature-matrix.md` Azure DevOps rows mark `resources.containers`,
`resources.pipelines`, packages, secure files, and pipeline artifacts as a
required structural typed-gap surface for the v1.2.0-rc.1 lane.

## L3-06 Coverage Added

- Added fixture `tests/fixtures/ado-resources-containers-pipelines.yml`.
- Added fixture `tests/fixtures/ado-resources-secure-files-artifacts.yml`.
- Added fuzz corpus seed
  `crates/taudit-parse-ado/fuzz/corpus/seed_resources_containers_pipelines.yml`.
- Added fuzz corpus seed
  `crates/taudit-parse-ado/fuzz/corpus/seed_resources_secure_files_artifacts.yml`.
- Added parser coverage that keeps existing `resources.repositories[]` metadata
  capture while marking `resources.containers`, `resources.pipelines`, and
  packages as `Partial` with `GapKind::Structural`.
- Added parser coverage that marks `DownloadSecureFile@*`,
  `PublishPipelineArtifact@*`, `DownloadPipelineArtifact@*`, and YAML
  `publish:` / `download:` shorthand artifact steps as `Partial` with
  `GapKind::Structural`.

## Safety Boundary

This lane remains offline. The parser does not perform live Azure DevOps REST
calls for resource, endpoint, or artifact enrichment, and no PAT or credential
value is required or persisted for this coverage.

## Remaining Gaps

- Container and pipeline resources are not yet represented as graph nodes or
  authority edges.
- Package resources are not yet represented as graph nodes or authority edges.
- Secure-file materialization, secure-file output path propagation, and
  publish/download pipeline artifact dataflow remain deferred.
- Service endpoint authentication scheme and live resource scope remain
  dynamic-runtime-only and require a separate enrichment boundary.
