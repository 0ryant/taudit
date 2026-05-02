# Dogfood corpus

Curated list of real-world public CI YAML files used as the **real-input lens** for the §2.2 stable-promotion gate (`docs/RELEASE_GATES.md`).

## Goals

- ≥100 files across GHA / ADO / GitLab — varied sizes, varied shapes, including known-pathological constructs (deep matrix expansion, reusable workflows, ADO templates, GitLab includes, cross-platform polyglot pipelines).
- Sourced from public repositories (license-compatible: most CI YAML is implicitly distributed under repo licence; we redistribute fixture-style under the same).
- Deliberately includes **one file per common framework / language / CI pattern** so we cover the surface area a stranger's pipeline would land on.

## Refresh cadence

Quarterly. Each refresh updates this list with rationale for any additions / removals. Refreshes also re-pin upstream commit SHAs so the corpus is reproducible.

## Status

- **2026-05-02:** stub created. Population is the next post-rc.1 task; not blocking the rc.1 cut, but blocks the rc.1 → stable promotion per §2.2.

## Sourcing approach (when populated)

For each platform:

- **GitHub Actions:** sample from top-100 most-starred Rust crates, top-50 Python projects, top-50 TypeScript / Node projects, top-30 Go projects. Bias toward projects that have CHANGELOGs of CI churn (more interesting shapes) over projects with one trivial workflow.
- **Azure Pipelines:** sample from public Microsoft-owned `.azure-pipelines.yml` corpora (e.g. on the `microsoft/`, `Azure/` orgs); prefer pipelines using `extends:`, `template:`, `resources.repositories[]`, and self-hosted pools.
- **GitLab CI:** sample from public projects on gitlab.com that publish their `.gitlab-ci.yml` — bias toward projects using `include:`, `extends:`, `trigger:` (downstream pipelines), `id_tokens:`, `services: [docker:dind]`.

For each chosen file:
1. Pin to a specific commit SHA in the source repo.
2. Copy under `corpus/dogfood/<platform>/<source-repo>/<filename>` with a per-file `SOURCE.md` documenting the upstream URL, commit SHA, license, and date pulled.
3. Add to a runs-list file (or a JSON manifest) the corpus loader can ingest.

## Pathological-shape coverage (must-have)

The corpus is incomplete if it doesn't exercise:

- **Deep YAML nesting** (≥10 levels) — guards against parser stack overflow on adversary YAML.
- **Large file** (≥500KB single workflow) — guards against unbounded allocations.
- **Reusable-workflow chains** ≥3 deep (GHA `uses: org/repo/.github/workflows/x.yml@sha`) — guards against secrets-inheritance regressions.
- **ADO `extends:` + `template:` + `resources.repositories[]`** — guards against template-resolution regressions.
- **GitLab `include:` with `remote:` + `project:` + `template:` + dynamic `include: artifact:`** — guards against include-resolution regressions.
- **Matrix workflows** with templated values (`${{ matrix.* }}`) — guards against template-shadow regressions.
- **`pull_request_target` workflows with multiple secret refs** — guards against the env-shadowing fix from v1.1.0-beta.1 staying fixed.
- **Multi-secret values** (`"${{ secrets.A }}-${{ secrets.B }}"`) — guards against the v1.1.0-beta.3 fix staying fixed.
- **Conditional ADO jobs** with `condition:` + `dependsOn:` — guards against the v1.1.0-rc.1 fix staying fixed.
- **At least one workflow that should produce ZERO findings on a clean scan** — sanity check that the tool doesn't false-positive on hello-world workflows.

## Running the corpus

When populated, the runner shape will be a `tests/corpus_run.rs` integration test (or `xtask`-style separate binary) that:

1. Reads the manifest (`corpus/dogfood/manifest.json`).
2. For each entry, runs `taudit scan --format json --no-color` against the file.
3. Asserts: exit code is 0 (scan is informational); stdout JSON validates against `contracts/schemas/taudit-report.schema.json`; no `panic!` / unhandled error is logged on stderr.
4. Aggregates findings counts per (platform, source-repo) and writes a summary to `corpus/dogfood/last-run.md` for the dogfood report.

This is the minimum-viable real-input lens. Any failure in the corpus run is a **§2.2 abort criterion** (auto-rollback to `rc.N+1`).
