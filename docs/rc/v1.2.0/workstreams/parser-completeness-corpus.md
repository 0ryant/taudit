# Parser Completeness + Corpus

## Goal

Make parser completeness a measured v1.2.0-rc.1 direction, not a slogan. The workstream should turn `AuthorityCompleteness` into a platform-by-platform evidence contract: `Complete` only when the supported authority surface is actually resolved, `Partial` when static analysis cannot know, and every uncertainty carries a typed gap that downstream policy can act on.

The brief covers GitHub Actions, Azure DevOps, GitLab CI, and Bitbucket Pipelines. The existing stable-promotion gate names a public corpus across GHA / ADO / GitLab in `docs/RELEASE_GATES.md`; v1.2.0 should keep that as the hard floor and add Bitbucket as an explicit fourth-platform real-input lens where the parser is present.

## Why This Takes taudit Skyward

taudit wins when it is trusted as an authority-model layer, not when it emits the largest pile of findings. `docs/ROADMAP.md` says the next iteration is "precision under uncertainty"; this workstream makes that concrete by tying parser claims to real public CI files, typed incompleteness, and stable JSON/SARIF/CloudEvents behavior.

The lift is credibility:

- A security engineer can tell whether a clean scan means "no current rule fired" or "the graph was partial and this path may be hidden" (`docs/authority-graph.md`).
- Release promotion gains a public real-input lens rather than relying only on hand-authored fixtures (`docs/RELEASE_GATES.md`, `docs/dogfood-corpus.md`).
- Parser work stops being open-ended. Each platform has named unsupported constructs, corpus frequency, and a decision: close, keep partial, or explicitly defer (`docs/jobs-phased-lanes.md`).
- Enterprise ADO noise gets a path to precision without pretending live variable-group state is static YAML (`TODOS.md`).

## Current Evidence

- `AuthorityCompleteness` is already part of the graph contract. `docs/authority-graph.md` defines `complete`, `partial`, and `unknown`, plus parallel `completeness_gaps` and `completeness_gap_kinds` with `expression`, `structural`, and `opaque` categories. It also warns consumers to surface partial graphs because downstream signal is only as complete as the input.
- The roadmap's near-term V1-5 item is still in progress: three-platform parity at `Complete`, with every gap explicitly modelled rather than silently approximated (`docs/ROADMAP.md`). The same file names parser fidelity and real-pipeline credibility as core pressure points.
- Stable promotion already requires a public-corpus dogfood pass: at least 100 real-world public pipeline files across GitHub / GitLab / ADO, varied shapes, no crashes, no hangs, and schema-valid output (`docs/RELEASE_GATES.md`). `docs/dogfood-corpus.md` is currently a stub and says population blocks rc-to-stable promotion.
- The dogfood corpus spec requires pathological shapes: deep YAML nesting, large files, reusable workflow chains, ADO `extends:` / `template:` / `resources.repositories[]`, GitLab `include:` variants, matrices, `pull_request_target` with secrets, multi-secret interpolation, ADO `condition:` / `dependsOn:`, and at least one zero-finding clean workflow (`docs/dogfood-corpus.md`).
- Phase 1 says GitLab and ADO parser lanes should move toward `AuthorityCompleteness::Complete` while preserving typed gaps where impossible; Phase 3 defines ADO variable-group enrichment; Phase 4 leaves limited expression evaluation as a later parser-depth lane (`docs/jobs-phased-lanes.md`).
- GHA currently models jobs, steps, local and third-party actions, containers, services, artifacts, permissions, OIDC, triggers, cache/helper handoffs, and partial reasons when expressions, reusable workflows, composites, or multiple YAML documents hide static authority flow (`crates/taudit-parse-gha/README.md`). The parser code marks partial for reusable workflows, matrix strategy, template-shaped env, local composite action references, multiple YAML docs, and non-empty jobs that produce zero step nodes (`crates/taudit-parse-gha/src/lib.rs`).
- ADO currently models `System.AccessToken`, service connections, variable groups, environments, self-hosted pools, scripts, Terraform markers, `task.setvariable`, helper paths, templates, and resource repository references (`crates/taudit-parse-ado/README.md`). The parser marks partial for template fragments, multiple docs, top-level `stages:` / `jobs:` template expressions, variable groups without enrichment, runtime `condition:`, unresolved `dependsOn:` mappings, and zero-step carrier shapes (`crates/taudit-parse-ado/src/lib.rs`).
- GitLab currently models jobs, broad `CI_JOB_TOKEN`, secrets, `id_tokens`, images, services, artifacts, dotenv, protected-branch hints, trigger context, includes, and extends metadata (`crates/taudit-parse-gitlab/README.md`). The parser still marks partial for `include:`, authority-relevant `default:` inheritance, hidden/template jobs, `extends:`, `inherit:`, conditional `rules:variables`, duplicate-key recovery, multiple docs, and zero-step opaque job carriers (`crates/taudit-parse-gitlab/src/lib.rs`).
- Bitbucket currently models pipeline steps, deployments, credential-shaped variables, images, services, artifacts, pull-request triggers, and duplicate-key recovery (`crates/taudit-parse-bitbucket/README.md`). Its current partial markers are narrower: multiple YAML docs, duplicate-key recovery, missing top-level `pipelines:`, and step entries that are not mappings (`crates/taudit-parse-bitbucket/src/lib.rs`). That makes Bitbucket a completeness opportunity and a documentation risk: the parser exists, but the release gates and roadmap still mostly speak in three-platform language.
- ADO enrichment is already specified as opt-in, read-only, graceful on failure, non-caching, and secret-safe. `TODOS.md` says it can collapse a real enterprise variable-group case from roughly 144 partial criticals to 8-12 genuinely secret-variable paths, while documenting the reproducibility caveat for live ADO state.

## Deliverables

1. Parser feature matrix for GHA, ADO, GitLab, and Bitbucket.
   Include supported constructs, known gaps, gap kind, current behavior, corpus examples, and whether the intended state is `Complete`, typed `Partial`, or explicit defer. Cite `docs/authority-graph.md`, parser READMEs, and parser source markers.

2. Dogfood corpus manifest and runner.
   Populate `corpus/dogfood/` plus a manifest described by `docs/dogfood-corpus.md`; pin public source URLs, commit SHAs, license notes, platform, parser, expected gap classes, and rationale. The runner should scan each file with `taudit scan --format json --no-color`, validate against `contracts/schemas/taudit-report.schema.json`, and produce a summary report with findings and completeness-gap histograms.

3. Public real-input report.
   Write a dogfood report for v1.2.0-rc.1 that says what was scanned, what parsed cleanly, which files were partial, top gap causes by platform, and which findings are signal versus parser uncertainty. This should extend the release-gate evidence model in `docs/RELEASE_GATES.md`, not replace it.

4. Platform gap backlog.
   Turn corpus-observed gaps into scoped work items:
   - GHA: reusable workflow bodies, local action/composite resolution policy, matrix/env expression handling, and wrong-platform/zero-step classification.
   - ADO: template fragments, `extends:` / `template:` / `resources.repositories[]`, variable groups, runtime `condition:`, dynamic `dependsOn:`, and template-expression carriers.
   - GitLab: `include:`, `extends:`, hidden/template jobs, `default:` / `inherit:` inheritance, conditional variables, and protected-branch / scoped-variable limits.
   - Bitbucket: duplicate-key recovery confidence, non-mapping steps, missing `pipelines:`, deployments, services, artifacts, pipes, and whether branch/deployment permissions need a richer model.

5. ADO enrichment decision record.
   Either finish the opt-in `--ado-org` / `--ado-project` / `--ado-pat` path from `TODOS.md`, or explicitly keep it deferred with the exact remaining risk. The decision must preserve graceful degradation, never log/persist the PAT, and document baseline reproducibility.

6. Precision policy for release notes.
   For every parser change, release notes should say whether it reduced incompleteness, reclassified a gap, or deliberately kept `Partial`. Avoid "now complete" language unless backed by corpus and fixture evidence.

## Acceptance Criteria

- A checked-in parser matrix covers GHA, ADO, GitLab, and Bitbucket, with each gap mapped to `expression`, `structural`, or `opaque` using the contract in `docs/authority-graph.md`.
- The corpus has at least 100 pinned public files across GHA / ADO / GitLab, plus a named Bitbucket tranche. If Bitbucket is not included in the hard stable gate, that exclusion is explicit and justified in the report.
- The corpus runner exits successfully on the selected corpus: no parser panic, no hang, no schema-invalid JSON, and no unlabelled parser failure.
- The corpus report includes per-platform counts for `complete`, `partial`, and `unknown`, plus top gap causes. It does not treat zero findings as proof of safety.
- GHA local composites/reusable workflows/matrix/env-template cases are either resolved with fixtures or remain typed `Partial` with corpus evidence.
- ADO variable groups are either enriched through the opt-in PAT flow or reported as static `Partial` with the `TODOS.md` reproducibility and secret-safety constraints carried forward.
- GitLab `include:` / `extends:` / `default:` / `inherit:` / conditional variable gaps are either resolved or preserved as named typed gaps with public corpus examples.
- Bitbucket parser scope is documented honestly: what it models today, which partial markers exist, and what real public Bitbucket files expose.
- Release-gate language for v1.2.0-rc.1 does not overclaim platform completeness before the dogfood corpus and parser matrix support it.

## Risks / Non-Goals

- Not a full CI provider interpreter. Do not attempt complete GitHub expression evaluation, ADO template expansion, GitLab include resolution, Bitbucket permissions lookup, shell execution, or cloud IAM resolution unless scoped as separate work.
- Not a credentialed default scan. ADO variable-group enrichment is opt-in; ordinary `scan` and `verify` stay offline and deterministic except where the operator explicitly supplies ADO context (`TODOS.md`).
- Not a finding-count vanity metric. Corpus counts are triage signal. A clean file only means the current parser and rules emitted no finding for the modelled graph.
- Public corpus sourcing can create license and maintenance drag. Every copied file needs source URL, commit SHA, license context, pull date, and refresh cadence as described in `docs/dogfood-corpus.md`.
- Bitbucket may expose roadmap drift. The parser exists, but core roadmap and stable gates still emphasize three platforms (`docs/ROADMAP.md`, `docs/RELEASE_GATES.md`). The workstream should surface that mismatch rather than silently folding Bitbucket into a promise the release process has not adopted.
- ADO live enrichment makes reproducibility harder. Same YAML plus different variable-group state can produce a different graph; baseline docs must call this out (`TODOS.md`, `docs/baselines.md`).

## Suggested Verification

- `cargo fmt --all`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `just golden-paths` after CLI output, docs examples, or public contract text changes.
- Corpus runner: `taudit scan --format json --no-color` for every manifest entry, schema validation against `contracts/schemas/taudit-report.schema.json`, and a generated summary with platform, parser, completeness, gap kinds, and findings count.
- Focused parser checks for known gap fixtures: GHA reusable workflow / matrix / local action, ADO variable group / template carrier / condition / dependsOn, GitLab include / extends / inherit / conditional variables, and Bitbucket duplicate keys / missing pipelines / non-mapping step.
- Secret-safety check for ADO enrichment: PAT not logged, not serialized in graph metadata, not written to cache, and failure falls back to static partial behavior with a warning.
