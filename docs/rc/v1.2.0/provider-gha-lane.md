# GitHub Actions Parser Lane - L3-05

## Source Of Truth

`docs/parser-feature-matrix.md` remains normative for v1.2.0-rc.1 GitHub
Actions release claims.

## L3-05 Result

The parser now emits typed `structural` partial gaps for the unsupported service
container surface instead of silently returning `complete`.

Covered by fixture and unit test:

- `tests/fixtures/gha-service-containers-and-credentials.yml`
- `crates/taudit-parse-gha/src/lib.rs`
- `crates/taudit-parse-gha/fuzz/corpus/seed_services_credentials.yml`

This is not production support for service containers. The parser does not yet
model service image authority, service ports, volumes, options, private registry
credentials, or container credential authority edges. Job-level `container:`
image and `options` remain the only complete job-container surface; container
`credentials`, `ports`, and `volumes` now keep the graph partial with a
structural gap.

## Release Claim

For v1.2.0-rc.1, GitHub Actions service containers and private registry/container
credential surfaces remain deferred. The improvement is typed-gap coverage, not
completeness.

## Next Dependency Unblocked

L3-10 corpus reporting can now count this GHA fixture as an expected
`partial`/`structural` sample instead of treating the service-container lane as
an untyped parser blind spot.
