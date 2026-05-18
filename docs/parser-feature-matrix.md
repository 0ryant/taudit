# Parser Feature Matrix

This is the L3-01 parser feature matrix for `v1.2.0-rc.1` and ADR 0014.
It is the release-claim boundary for parser completeness until the dogfood
corpus and provider lanes add stronger evidence.

## Evidence Sources

- ADR 0014: `docs/adr/0014-parser-completeness-and-platform-promise.md`
- RC workstream: `docs/rc/v1.2.0/workstreams/parser-completeness-corpus.md`
- Gap contract: `docs/authority-graph.md`
- Parser crates: `crates/taudit-parse-gha`, `crates/taudit-parse-ado`,
  `crates/taudit-parse-gitlab`, `crates/taudit-parse-bitbucket`
- Fixtures and seeds: `tests/fixtures/**` and
  `crates/taudit-parse-{gha,ado,gitlab}/fuzz/corpus/**`
- Bitbucket fuzz harness and seeds:
  `crates/taudit-parse-bitbucket/fuzz/**`

## State And Gap Vocabulary

Support states:

- `complete`: static YAML support is observed for the named construct and the
  supported surface does not require a completeness gap.
- `partial`: parser support is observed and the parser emits
  `AuthorityCompleteness::Partial` with a typed gap.
- `unknown`: repo evidence is insufficient to assert support or non-support.
- `unsupported`: construct is ignored, not modeled, or lacks an observed parser
  path; follow-up lanes should add support or a typed gap.
- `dynamic-runtime-only`: the missing authority depends on provider live state,
  runtime execution, shell evaluation, or remote content outside the YAML file.
- `deferred`: intentionally outside the `v1.2.0-rc.1` release promise.

Gap-kind cells use the public gap taxonomy when the parser emits a gap:
`expression`, `structural`, or `opaque`. `none` means no gap is expected for the
supported static surface. `missing-typed-gap -> target-kind` means current behavior
needs a parser fix so unsupported behavior is not silent.

Release-state cells are normative for `v1.2.0-rc.1`: GitHub Actions, Azure
DevOps, and GitLab CI are release-gated platforms; Bitbucket Pipelines is a
named parser tranche until fixtures, fuzz, and corpus evidence support
promotion.

## Cross-Provider Completeness Sentinel

| Provider | Construct | Support state | Gap kind | Fixture path or marker | Corpus sample need | Intended `v1.2.0-rc.1` release state |
| --- | --- | --- | --- | --- | --- | --- |
| All | `AuthorityCompleteness::Unknown` output from provider parsers | unknown | n/a | MISSING-FIXTURE: provider parser producing `unknown` completeness | Corpus runner should count `unknown` if it appears, but no current provider lane should rely on it as success. | Deferred; use `complete` or typed `partial` for release claims. |

## GitHub Actions

| Construct | Support state | Gap kind | Fixture path or marker | Corpus sample need | Intended `v1.2.0-rc.1` release state |
| --- | --- | --- | --- | --- | --- |
| Workflow jobs, `run:` steps, `uses:` actions, and parent job metadata | complete | none | `tests/fixtures/clean.yml`; `crates/taudit-parse-gha/fuzz/corpus/seed_empty.yml` | Add public workflows with mixed `run:` and `uses:` steps. | Release-gated complete for static job and step carriers. |
| `permissions:` and implicit `GITHUB_TOKEN`, including omitted permissions as unknown scope | complete | none | `tests/fixtures/over-privileged.yml`; `crates/taudit-parse-gha/fuzz/corpus/seed_over_privileged.yml` | Add public workflows with workflow-level, job-level, and omitted `permissions:`. | Release-gated complete for declared YAML permissions; provider default policy remains outside YAML. |
| OIDC identity hints from `id-token: write` and known cloud auth actions | complete | none | `tests/fixtures/algol-authority-confusion-fixture.yml` | Add AWS, Azure, GCP, Vault, Sigstore, and multi-cloud workflows. | Release-gated complete for parser-recognized YAML/action patterns. |
| Trigger metadata for `pull_request_target`, PR, workflow run, comments, dispatch, and `workflow_call` input names | complete | none | `crates/taudit-parse-gha/fuzz/corpus/seed_prt.yml` | Add real PR, PRT, `workflow_run`, `issue_comment`, and reusable-workflow entrypoints. | Release-gated complete for static trigger tokens; runtime event payloads are not statically evaluated. |
| Matrix strategy | partial | expression | `crates/taudit-parse-gha/src/lib.rs` inline test `matrix_strategy_marks_graph_partial` | Add public workflows with matrix-dependent secret, runner, and action choices. | Release-gated typed partial until L3-05 decides limited matrix expansion. |
| Workflow/job/step `env:` template expressions | partial | expression | `crates/taudit-parse-gha/src/lib.rs` inline env-template tests | Add public workflows using `env: ${{ matrix.* }}` or generated env maps. | Release-gated typed partial. |
| Reusable workflow job calls via `jobs.JOB_ID.uses` | partial | structural | `tests/fixtures/partial-structural.yml`; `crates/taudit-parse-gha/src/lib.rs` inline reusable-workflow tests | Add public same-repo and cross-repo reusable workflow calls, including `secrets: inherit` and mapped secrets. | Release-gated typed partial; no callee body resolution in RC. |
| Local action and composite action references via `uses: ./...` | partial | structural | `crates/taudit-parse-gha/src/lib.rs` inline composite/local-action tests | Add public local composite, Docker, and JavaScript action examples. | Release-gated typed partial; filesystem action inlining deferred to L3-05. |
| Job-level `container:` image and options | complete | none | `crates/taudit-parse-gha/src/lib.rs` inline container tests | Add public jobs with string and mapping container forms, pinned and floating images. | Release-gated complete for image/options only. |
| Service containers, private registry credentials, volumes, ports, and container credentials | partial | structural | `tests/fixtures/gha-service-containers-and-credentials.yml`; `crates/taudit-parse-gha/fuzz/corpus/seed_services_credentials.yml`; `crates/taudit-parse-gha/src/lib.rs` inline service-container test | Add public workflows with `services:`, registry credentials, volumes, and ports. | Release-gated typed partial; service/container execution surface is flagged, not modelled as complete. |
| Named `actions/upload-artifact` and `actions/download-artifact` flows | complete | none | `tests/fixtures/propagation-leaky.yml`; `crates/taudit-parse-gha/src/lib.rs` inline artifact tests | Add public artifact handoff workflows with named upload/download pairs. | Release-gated complete for named artifact correlation. |
| Anonymous upload or wildcard download artifact flows | deferred | none | `crates/taudit-parse-gha/src/lib.rs` inline anonymous artifact tests | Add corpus samples to decide whether wildcard downloads need typed partiality. | Deferred; parser intentionally avoids unsafe correlation. |
| Shell environment gates (`GITHUB_ENV`, `GITHUB_PATH`, `GITHUB_OUTPUT`) | complete | none | `tests/fixtures/algol-authority-confusion-fixture.yml`; inline env-gate tests | Add public workflows with helper scripts and env-file writes. | Release-gated complete for static string markers; shell execution remains runtime-only. |
| Multiple YAML documents and wrong-platform zero-step carrier traps | partial | expression or structural | `crates/taudit-parse-gha/src/lib.rs` inline multi-doc and zero-step tests | Add malformed and wrong-platform corpus files. | Release-gated typed partial. |

## Azure DevOps

| Construct | Support state | Gap kind | Fixture path or marker | Corpus sample need | Intended `v1.2.0-rc.1` release state |
| --- | --- | --- | --- | --- | --- |
| Root `steps:`, `jobs:`, `stages:`, regular jobs, deployment jobs, and deployment strategies | complete | none | `crates/taudit-parse-ado/fuzz/corpus/seed_minimal.yml`; `tests/fixtures/ado-shared-pool.yml` | Add public pipelines using each carrier shape. | Release-gated complete for static carrier sequences. |
| `System.AccessToken`, `permissions:`, and static token-scope restriction | complete | none | `crates/taudit-parse-ado/src/lib.rs` inline permissions tests | Add public pipelines with scalar and mapping permissions. | Release-gated complete for YAML-declared token restrictions. |
| PR triggers and scalar opt-outs such as `pr: none`, `pr: false`, and `pr: ~` | complete | none | `tests/fixtures/ado-shared-pool.yml`; inline PR-trigger tests | Add public PR-triggered pipelines and opt-out samples. | Release-gated complete for static trigger shape. |
| Pools, self-hosted pool names, and workspace-clean metadata | complete | none | `tests/fixtures/ado-shared-pool.yml`; `crates/taudit-parse-ado/fuzz/corpus/seed_shared_pool.yml` | Add public hosted, self-hosted, and clean-workspace examples. | Release-gated complete for static pool metadata. |
| Static variables, secret variables, `env:`, task input references, and script `$(VAR)` references | complete | none | `tests/fixtures/ado-setvariable.yml`; `crates/taudit-parse-ado/fuzz/corpus/seed_setvariable.yml` | Add public examples with mapping and sequence variable forms. | Release-gated complete for static variable declarations and references. |
| Variable groups without live enrichment | dynamic-runtime-only | structural | `crates/taudit-parse-ado/src/lib.rs` inline variable-group tests | Add public pipelines using pipeline, stage, and job variable groups. | Release-gated typed partial in offline scans. |
| Opt-in ADO variable-group enrichment through `AdoParserContext` / REST | dynamic-runtime-only | structural on failure | `crates/taudit-parse-ado/src/lib.rs` inline mock enrichment tests | Add mocked and documented live-state samples; do not require live credentials in corpus. | Opt-in dynamic exception; static fallback remains typed partial. |
| Service connections from task inputs (`azureSubscription`, `connectedServiceName*`, etc.) | complete | none | `crates/taudit-parse-ado/src/lib.rs` inline service-connection tests | Add public task samples across AzureCLI, Kubernetes, ARM, Terraform, and deployment tasks. | Release-gated complete for connection-name extraction only. |
| Service endpoint authentication scheme and actual service-connection scope | dynamic-runtime-only | none | MISSING-FIXTURE: ado-service-endpoint-live-scope | Corpus can only show YAML references; live endpoint scope needs provider API. | Deferred to enrichment/ADR 0016; do not infer OIDC or scope from YAML alone. |
| `condition:` at stage, job, and step levels | partial | expression | `crates/taudit-parse-ado/src/lib.rs` inline condition tests | Add public conditional deploy and PR-gate samples. | Release-gated typed partial with condition metadata stamped. |
| `dependsOn:` string and sequence forms | complete | none | `crates/taudit-parse-ado/src/lib.rs` inline dependsOn tests | Add public multi-stage and multi-job dependency chains. | Release-gated complete for explicit static dependencies. |
| `dependsOn:` mappings or template-conditioned dependencies | partial | expression | `crates/taudit-parse-ado/src/lib.rs` inline mapping dependsOn tests | Add public template-conditioned dependency examples. | Release-gated typed partial. |
| Templates, `extends:`, top-level template-expression carriers, and root template fragments | partial | structural or expression | `crates/taudit-parse-ado/src/lib.rs` inline template tests | Add public `extends`, `template`, and parameterized carrier examples. | Release-gated typed partial; no full template expansion in RC. |
| `resources.repositories[]` and checkout/template alias use | complete | none | `crates/taudit-parse-ado/src/lib.rs` inline repository-resource tests | Add public external repository resources with pinned and branch refs. | Release-gated complete for repository metadata capture, not remote content. |
| `resources.containers`, `resources.pipelines`, and packages | partial | structural | `tests/fixtures/ado-resources-containers-pipelines.yml`; `tests/fixtures/ado-resources-secure-files-artifacts.yml`; `crates/taudit-parse-ado/fuzz/corpus/seed_resources_containers_pipelines.yml`; `crates/taudit-parse-ado/fuzz/corpus/seed_resources_secure_files_artifacts.yml` | Add public container-resource, pipeline-resource, and package-resource samples. | Release-gated typed partial; resource nodes, endpoint scope, and package/pipeline authority modelling remain deferred. |
| Secure files and publish/download pipeline artifact tasks plus shorthand | partial | structural | `tests/fixtures/ado-resources-secure-files-artifacts.yml`; `crates/taudit-parse-ado/fuzz/corpus/seed_resources_secure_files_artifacts.yml`; `crates/taudit-parse-ado/src/lib.rs` inline secure-file/artifact task and shorthand test | Add public secure-file and publish/download artifact samples. | Release-gated typed partial; secure-file materialization, output path propagation, and artifact dataflow remain deferred. |
| Duplicate fields and zero-step wrong-platform carrier traps | partial | structural | `crates/taudit-parse-ado/src/lib.rs` inline duplicate/zero-step tests | Add malformed and wrong-platform corpus files. | Release-gated typed partial. |

## GitLab CI

| Construct | Support state | Gap kind | Fixture path or marker | Corpus sample need | Intended `v1.2.0-rc.1` release state |
| --- | --- | --- | --- | --- | --- |
| Jobs, scripts, parent job metadata, and implicit broad `CI_JOB_TOKEN` | complete | none | `crates/taudit-parse-gitlab/fuzz/corpus/seed_minimal.yml` | Add public simple and multi-stage `.gitlab-ci.yml` files. | Release-gated complete for static job carriers. |
| Credential-shaped variables and explicit `secrets:` blocks | complete | none | `tests/fixtures/gitlab-creds.yml`; `crates/taudit-parse-gitlab/fuzz/corpus/seed_secrets.yml` | Add public examples using project variables, `secrets:`, and credential-shaped names. | Release-gated complete for YAML-visible variables and secrets. |
| `id_tokens:` OIDC identities, scalar and list `aud:` forms | complete | none | `crates/taudit-parse-gitlab/src/lib.rs` inline id-token tests | Add public OIDC, Sigstore, cloud federation, and multi-audience samples. | Release-gated complete for declared token and audience metadata. |
| Global/job `image:` and job `services:` image nodes, including Docker-in-Docker marker | complete | none | `crates/taudit-parse-gitlab/fuzz/corpus/seed_docker.yml` | Add public service alias, mapping-form service, and DIND samples. | Release-gated complete for static image/service refs. |
| Merge-request trigger detection from positive `rules:` and `only: merge_requests` | complete | none | `crates/taudit-parse-gitlab/src/lib.rs` inline MR-trigger tests | Add public merge-request pipeline samples and negation traps. | Release-gated complete for positive static trigger patterns. |
| Protected-branch hints and environment name/url metadata | complete | none | `crates/taudit-parse-gitlab/src/lib.rs` inline protected-ref tests | Add public protected deploy jobs and environment mapping samples. | Release-gated complete for recognized static hints; provider protected-variable state is runtime-only. |
| Top-level `include:` | partial | structural | `crates/taudit-parse-gitlab/src/lib.rs` inline include test | Add public local, project, remote, component, and template includes. | Release-gated typed partial; no include resolution in RC. |
| Hidden/template jobs, `extends:`, `default:` inheritance, and `inherit:` | partial | structural | `crates/taudit-parse-gitlab/src/lib.rs` inline hidden/default/extends/inherit tests | Add public template-heavy projects with multi-extends inheritance. | Release-gated typed partial. |
| `workflow:rules:variables` and job `rules:variables` | partial | expression | `crates/taudit-parse-gitlab/src/lib.rs` inline `rules_variables_mark_typed_expression_gap` test | Add public conditional variable examples. | Release-gated typed partial. |
| Child/downstream pipelines via `trigger:` | dynamic-runtime-only | missing-typed-gap -> structural for dynamic artifact includes | `crates/taudit-parse-gitlab/src/lib.rs` trigger classification code | Add public static downstream and dynamic child-pipeline samples. | Static trigger kind metadata is release-gated; dynamic child body resolution is deferred to L3-07. |
| `artifacts:reports:dotenv` plus `needs:` / `dependencies:` dotenv flow | complete | none | `crates/taudit-parse-gitlab/src/lib.rs` inline dotenv/needs tests | Add public dotenv handoff samples, including `artifacts: false`. | Release-gated complete for dotenv metadata and upstream-job capture. |
| Generic GitLab artifacts beyond dotenv reports | partial | structural | `tests/fixtures/gitlab-generic-artifacts.yml`; `crates/taudit-parse-gitlab/fuzz/corpus/seed_generic_artifacts.yml`; `crates/taudit-parse-gitlab/src/lib.rs` inline generic-artifact test | Add public generic artifact upload/download and dependency samples. | Release-gated typed partial; generic artifact dataflow remains deferred beyond dotenv-specific modelling. |
| Cache key and policy metadata for the first matched cache | complete | none | `crates/taudit-parse-gitlab/src/lib.rs` cache extraction code | Add public single-cache and multi-cache examples. | Release-gated for first cache key/policy signal only; multi-cache semantics deferred. |
| Duplicate YAML key recovery, multiple YAML documents, and zero-step opaque carrier traps | partial | structural, expression, or opaque | `crates/taudit-parse-gitlab/src/lib.rs` inline duplicate/multi-doc/zero-step tests | Add malformed and wrong-platform corpus files. | Release-gated typed partial. |
| Group/project/protected variable scopes outside the YAML file | dynamic-runtime-only | none | MISSING-FIXTURE: gitlab-live-variable-scopes | Corpus can include YAML consumers, not live GitLab settings. | Deferred; do not claim scoped variable completeness. |

## Bitbucket Pipelines

| Construct | Support state | Gap kind | Fixture path or marker | Corpus sample need | Intended `v1.2.0-rc.1` release state |
| --- | --- | --- | --- | --- | --- |
| Top-level `pipelines:` contexts: `default`, `branches`, `tags`, `pull-requests`, and `custom` | complete | none | `crates/taudit-parse-bitbucket/src/lib.rs` inline tests | Add public files with every context type and pattern shape. | Named Bitbucket tranche; not release-gated complete. |
| Missing top-level `pipelines:` mapping | partial | structural | `crates/taudit-parse-bitbucket/src/lib.rs` parser branch | Add malformed public or synthetic negative samples. | Named tranche typed partial. |
| Step nodes, names, trigger metadata, and script-body capture | complete | none | `crates/taudit-parse-bitbucket/src/lib.rs` inline tests | Add public simple and multi-step pipelines. | Named tranche static support. |
| Credential-shaped `$VAR` and `${VAR}` references in scripts | complete | none | `crates/taudit-parse-bitbucket/src/lib.rs` inline `parses_step_image_script_oidc_and_secret_refs` test | Add public scripts using workspace/repo variables by name. | Named tranche support for referenced variable names only. |
| Secured variable definitions, workspace/repository variable scopes, and deployment variable scopes | dynamic-runtime-only | none | MISSING-FIXTURE: bitbucket-live-variable-scopes | Corpus can show variable use, but provider UI state is outside YAML. | Deferred; do not claim secured-variable completeness. |
| `oidc: true` step token | complete | none | `crates/taudit-parse-bitbucket/src/lib.rs` inline OIDC test | Add public OIDC deployment and cloud federation samples. | Named tranche support. |
| Global and step-level `image:`, service images under `definitions: services`, built-in Docker service, and `pipe:` refs | complete | none | `crates/taudit-parse-bitbucket/src/lib.rs` inline `parses_pipes_services_and_artifacts` test | Add public pipe, service, and custom image samples with pinned/floating variants. | Named tranche support. |
| Artifacts and sequential artifact consumption | complete | none | `crates/taudit-parse-bitbucket/src/lib.rs` inline artifact test | Add public artifact handoff samples across default, branch, and PR contexts. | Named tranche support; needs broader fixtures before promotion. |
| `deployment:` name and heuristic environment-approval marker | dynamic-runtime-only | none | `crates/taudit-parse-bitbucket/src/lib.rs` deployment metadata code | Add public deployment names and environment permission examples. | Named tranche metadata only; real deployment permissions deferred to L3-08. |
| `parallel:` carrier traversal | partial | structural | `tests/fixtures/bitbucket-parallel-stage-semantics.yml`; `crates/taudit-parse-bitbucket/fuzz/corpus/parallel-stage.yml`; inline no-sibling-consume regression test | Add public parallel groups with artifacts and services. | Named tranche typed partial; parser traverses member steps for discovery but does not claim complete parallel scheduling/fail-fast/artifact semantics. |
| `stage:` grouping and stage-level semantics | partial | structural | `tests/fixtures/bitbucket-parallel-stage-semantics.yml`; `crates/taudit-parse-bitbucket/fuzz/corpus/parallel-stage.yml`; inline structural-gap regression test | Add public staged pipelines with deployment and artifact use. | Named tranche typed partial; parser traverses nested steps for discovery but does not claim complete stage-level deployment/condition/artifact semantics. |
| `caches:`, `clone:`, `size:`, runner options, and workspace options | partial | structural | `tests/fixtures/bitbucket-cache-clone-runner-options.yml`; `crates/taudit-parse-bitbucket/fuzz/corpus/cache-clone-runner-options.yml`; inline fixture-backed structural-gap test | Add public cache, clone-depth/LFS, size, and runner-option samples. | Named tranche typed partial; recognized option surfaces are not semantically modeled as stable support. |
| Multiple YAML documents and duplicate-key recovery | partial | expression or structural | `crates/taudit-parse-bitbucket/src/lib.rs` duplicate/multi-doc parser branches | Add synthetic fixtures plus public malformed samples if available. | Named tranche typed partial. |
| Non-mapping step bodies | partial | structural | `crates/taudit-parse-bitbucket/src/lib.rs` parser branch | Add focused fixture with malformed `step:` scalar/sequence. | Named tranche typed partial. |
| Bitbucket fuzz corpus, fuzz harness, and top-level fixtures | partial | none | `tests/fixtures/bitbucket-*.yml`; `crates/taudit-parse-bitbucket/fuzz/Cargo.toml`; `crates/taudit-parse-bitbucket/fuzz/fuzz_targets/parse_bitbucket.rs`; `crates/taudit-parse-bitbucket/fuzz/corpus/*.yml` | Add public corpus samples and sustained fuzz runs beyond harness build/smoke evidence. | Named tranche evidence exists, but this is not a promotion to release-gated or stable Bitbucket completeness. |

## Follow-Up Provider Lane Inputs

- L3-05 GHA should focus on service containers, private registry/container
  credentials, volumes/options beyond image/options, matrix/env expression
  policy, reusable workflow boundary policy, and local action boundary policy.
- L3-06 ADO should focus on templates/resources beyond repositories, secure
  files, pipeline artifacts, service endpoint live scope, duplicate field
  fixtures, and variable-group enrichment evidence.
- L3-07 GitLab should focus on include/extends/default/inherit resolution
  limits, dynamic child pipelines, generic artifacts, scoped/protected
  variables, and cache/multi-cache semantics.
- L3-08 Bitbucket should use the initial fixtures and fuzz harness to expand
  public corpus evidence, then keep tightening typed gaps for secured
  variables, deployments, pipes, services, and artifact ordering without
  promoting the named tranche to stable completeness prematurely.

## Release Promise Summary

- GitHub Actions, Azure DevOps, and GitLab CI may be described as
  release-gated only for the supported surfaces above.
- Any row marked `partial` is acceptable only when the parser emits the named
  typed gap.
- Any row marked `unsupported`, `unknown`, `dynamic-runtime-only`, or
  `deferred` is not a completeness promise.
- Bitbucket Pipelines must be described as a named parser tranche in
  `v1.2.0-rc.1`, not as stable four-platform completeness.
