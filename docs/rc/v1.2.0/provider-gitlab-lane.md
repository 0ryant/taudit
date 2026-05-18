# GitLab Parser Lane

Status: L3-07 typed partial coverage added for generic artifacts beyond dotenv.

Source of truth: `docs/parser-feature-matrix.md`, GitLab CI section.

## Covered In This Lane

- `artifacts:reports:dotenv` remains the only complete GitLab artifact flow.
- Jobs with generic artifact payloads (`artifacts:paths`, `exclude`, `untracked`, or non-dotenv `reports`) now mark the graph `Partial` with `GapKind::Structural`.
- Jobs that explicitly consume those generic artifacts via `needs:` or `dependencies:` also mark a `Structural` gap.
- Fixture coverage: `tests/fixtures/gitlab-generic-artifacts.yml`.
- Fuzz seed: `crates/taudit-parse-gitlab/fuzz/corpus/seed_generic_artifacts.yml`.

## Boundaries

- No artifact file contents are read.
- No GitLab API or provider-live state is queried.
- Dynamic includes, protected/scoped variable settings, and include/default/extends inheritance remain typed gaps or runtime-only boundaries per the matrix.
- The parser does not yet materialize generic GitLab artifacts as `Artifact` nodes or graph edges.

## Next Dependency Unblocked

Corpus and rule lanes can now distinguish "unsupported and silent" from "known structural gap" for generic GitLab artifacts.
