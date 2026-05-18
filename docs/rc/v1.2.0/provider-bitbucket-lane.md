# Bitbucket Pipelines Parser Lane - L3-08

Status: named v1.2.0-rc.1 tranche, not stable four-platform completeness.

## Source Of Truth

`docs/parser-feature-matrix.md`, Bitbucket Pipelines section, remains normative
for this lane.

## Coverage Added

- Added broad tracked fixtures under `tests/fixtures/bitbucket-*.yml` for
  contexts, pipes/services/artifacts, cache/clone/runner options,
  parallel/stage samples, and partial malformed/multi-doc forms.
- Added matching fuzz seeds under
  `crates/taudit-parse-bitbucket/fuzz/corpus/`.
- Added a minimal libFuzzer harness under
  `crates/taudit-parse-bitbucket/fuzz/`.
- Added fixture-backed parser coverage for cache, clone, size, runner, and
  workspace options.
- The parser now marks those option surfaces as `Partial` with
  `GapKind::Structural` instead of silently implying completeness.
- Added fixture-backed parser coverage for `parallel:` and `stage:` as
  `Partial` with `GapKind::Structural`.
- Fixed `parallel:` flattening so artifacts produced by one parallel sibling
  are not added as `Consumes` inputs to another sibling.

## Boundary

This is typed-gap coverage, not semantic support for Bitbucket cache behavior,
clone depth/LFS behavior, runner placement, workspace options, or cache
trust-boundary authority edges. Secured variables and deployment permissions
remain provider-live/runtime-only. Parallel and stage groups are traversed for
step discovery only; complete scheduling, fail-fast, deployment, condition, and
artifact semantics remain deferred.

## Next Dependency Unblocked

Corpus reporting can now count Bitbucket as a named tranche with fixture/fuzz
material and an expected `partial`/`structural` sample for cache/clone/runner
options plus parallel/stage grouping, rather than treating the lane as an
untyped parser blind spot.
