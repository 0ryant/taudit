# gha_docker_buildx_authority_path_handoff

Flags Docker Buildx setup or build-push actions when an earlier same-job step
mutates `GITHUB_PATH` and the later Docker action has registry, SSH,
build-secret, provenance, or publish authority in scope.

This is a Docker helper-boundary source lead, not a standalone vulnerability
claim.

## Remediation

Run Buildx setup and build-push before mutable PATH setup where possible,
resolve `docker`/`buildx` through trusted paths, and keep registry/build secrets
scoped to the build boundary.
