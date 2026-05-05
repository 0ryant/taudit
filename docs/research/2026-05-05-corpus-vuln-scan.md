# 2026-05-05 corpus vulnerability scan

## Scope

Corpus root: `corpus/workflow-yaml-testbed/`

Observed corpus at scan time:

| Platform | Files |
| --- | ---: |
| GitHub Actions | 5000 |
| Azure DevOps | 5000 |
| Bitbucket Pipelines | 2608 |
| GitLab CI | 1535 and still harvesting at time of writing |

Local artifacts:

- `corpus/workflow-yaml-testbed/manifest.jsonl`
- `corpus/workflow-yaml-testbed/analysis/vuln_scan_summary.json`
- `corpus/workflow-yaml-testbed/analysis/vuln_scan_findings.jsonl`
- `corpus/workflow-yaml-testbed/analysis/summary.json`
- `corpus/workflow-yaml-testbed/analysis/failures.jsonl`
- Scripts:
  - `scripts/research/harvest_workflow_yamls.py`
  - `scripts/research/vuln_scan_workflow_corpus.py`
  - `scripts/research/analyze_workflow_corpus.py`

## Corpus vuln-pattern result

The pattern scan covered 14,143 files and emitted 19,686 pattern hits.

Top observed signals:

| Pattern | Hits | Platforms | Meaning |
| --- | ---: | --- | --- |
| `image_without_tag_or_digest` | 8494 | ADO, BB, GHA, GL | Container image not pinned by digest or explicit tag. |
| `gh_action_major_pin_only` | 2550 | GHA, ADO false-shape spillover | GitHub Action pinned only to a mutable major tag such as `@v4`. |
| `npm_ignore_scripts_disabled_absent` | 2465 | all | Package install scripts may execute maintainer code. Needs authority context before becoming a rule. |
| `old_github_action_major` | 1792 | GHA | Old major-version action lines. Needs advisory/action metadata. |
| `pip_unhashed_install` | 1546 | all | Python install without `--require-hashes`. Needs dependency context. |
| `latest_tag` | 1291 | all | Mutable action/image/tool ref. |
| `secret_echo_or_print` | 720 | all | Command appears to print secret/token/password-like material. |
| `docker_dind` | 262 | all | Docker-in-Docker or dind image/service use. |
| `curl_pipe_shell` | 252 | all | Remote script piped directly to shell/interpreter. |
| `docker_privileged` | 138 | all | `docker run --privileged`. |
| `docker_sock_mount` | 35 | all | `/var/run/docker.sock` exposed or permissioned. |
| `known compromised action refs` | 24 | GHA | `tj-actions/changed-files` / `reviewdog` advisory families. |

## CVE/advisory matches

### CVE-2025-30066: `tj-actions/changed-files`

Observed corpus hits: 18 direct `tj-actions/changed-files` references after the latest scan.

Examples:

- `corpus/workflow-yaml-testbed/gha/twentyhq_twenty__.github_workflows_ci-server.yaml__bd23d016f373.yaml:91` - `uses: tj-actions/changed-files@v45`
- `corpus/workflow-yaml-testbed/gha/EbookFoundation_free-programming-books__.github_workflows_check-urls.yml__0355bf86d5b2.yml:45` - `uses: tj-actions/changed-files@v46`
- `corpus/workflow-yaml-testbed/gha/local-corpus__bridgecrewio_checkov__pr-test.yml__c9a556c679d1.yml:43` - `uses: tj-actions/changed-files@... # v44`

External evidence:

- GitHub Advisory Database: `tj-actions/changed-files` through `45.0.7` allows secret disclosure in logs; patched in `46.0.1`: https://github.com/advisories/ghsa-mrrh-fwg8-r2c3
- CISA alert links the incident to CVE-2025-30066 and says the compromise allowed disclosure of secrets including access keys, PATs, npm tokens, and private RSA keys: https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction

Important qualification:

Static YAML cannot prove exploitability. Exposure depends on which ref resolved
at the workflow execution time, whether the job had secrets/tokens, and whether
logs were retained. A taudit rule should report this as a known compromised
action reference with advisory metadata and execution-window guidance.

### CVE-2025-30154: `reviewdog/action-setup` and wrapper actions

Observed corpus hits: 4 `reviewdog/action-setup`, 2 wrapper actions after the latest scan.

Examples:

- `corpus/workflow-yaml-testbed/gha/local-corpus__matplotlib_matplotlib__linting.yml__554c1bdc84ef.yml:45` - `uses: reviewdog/action-setup@... # v1.5.0`
- `corpus/workflow-yaml-testbed/gha/supabase_supabase__.github_workflows_docs-lint-v2.yml__f95e70ce963e.yml:62` - `uses: reviewdog/action-setup@... # v1.3.0`
- `corpus/workflow-yaml-testbed/gha/netdata_netdata__.github_workflows_review.yml__6e936e37c2fc.yml:227` - `uses: reviewdog/action-shellcheck@v1`

External evidence:

- GitHub Advisory Database: `reviewdog/action-setup@v1` was compromised on March 11, 2025 between 18:42 and 20:31 UTC; wrapper actions including `action-shellcheck`, `action-composite-template`, `action-staticcheck`, `action-ast-grep`, and `action-typos` were also affected: https://github.com/advisories/ghsa-qmg3-hpqr-gqvc
- CISA alert links the compromise to CVE-2025-30154: https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction

Important qualification:

The advisory says affected wrapper actions can be compromised regardless of
version or pinning method during the compromise window. A taudit rule needs an
execution-date dimension if it wants to distinguish historical exposure from
current static risk.

## Non-CVE vulnerability classes

These are not single CVEs from YAML alone, but they are strong taudit rule
targets because they model CI/CD authority risk.

### Docker socket exposure

Observed hits: 35.

Examples:

- GHA: `metabase_metabase...loki.yml:38` mounts `/var/run/docker.sock`.
- ADO: `AnandJoy7_mysampleapp...azure-pipelines.yml:46` runs `sudo chmod 777 /var/run/docker.sock`.
- ADO: `khs1994-docker_lnmp...azure-pipelines.yml.back:179` configures `tcp://0.0.0.0:2375`.

External evidence:

- Docker `dockerd` docs: the Docker socket requires root permission or docker-group membership; changing daemon bindings or group access can let non-root users gain root access on the host: https://docs.docker.com/reference/cli/dockerd/
- Docker remote-access docs warn that unsecured remote daemon access can let remote non-root users gain root access on the host: https://docs.docker.com/engine/daemon/remote-access/

Rule candidate:

`docker_socket_exposed_to_ci_step`

Severity:

- Critical when the step has a Secret/Identity edge or writes an artifact consumed by a privileged step.
- High otherwise.

### Docker-in-Docker and privileged containers

Observed hits: `docker_dind` 262, `docker_privileged` 138.

External evidence:

- GitLab Docker executor docs state privileged mode has security risks: https://docs.gitlab.com/runner/executors/docker/
- GitLab Docker build docs state Docker-in-Docker in privileged mode effectively disables container security mechanisms and exposes the host to privilege escalation: https://docs.gitlab.com/ci/docker/using_docker_build/

Rule candidates:

- Extend `dind_service_grants_host_authority` beyond GitLab.
- Add `privileged_container_in_ci_step`.

### Remote script execution

Observed hits: 252 `curl|wget | shell`.

Examples:

- Docker Scout installer from `raw.githubusercontent.com/docker/scout-cli/main/install.sh`.
- Poetry installer via `curl -sSL https://install.python-poetry.org | python -`.
- Sentry CLI via `curl -sL https://sentry.io/get-cli/ | bash`.

Existing taudit coverage:

`runtime_script_fetched_from_floating_url` exists but is GHA-oriented and narrower
than the corpus pattern.

Rule candidate:

Generalize `runtime_script_fetched_from_floating_url` across GHA, ADO, GitLab,
and Bitbucket, and catch direct pipe-to-shell forms.

### EOL runtimes

Observed hits: 39 old Node setup versions and 24 old Python setup versions.

External evidence:

- Node.js EOL page says EOL lines receive no further vulnerability fixes, and lists v16 as EOL since 2023-08-08 with historical unresolved vulnerability counts: https://nodejs.org/about/eol
- Python Developer Guide lists old branches such as 3.7 as end-of-life: https://devguide.python.org/versions

Rule candidate:

`eol_runtime_version` for `setup-node`, `setup-python`, ADO task inputs, and
common image tags. It should be Info/Medium by default and escalate when the job
also has secrets, deploy authority, or release publishing.

## taudit defects found by corpus scan

Command:

```bash
python3 scripts/research/analyze_workflow_corpus.py --platform gha --platform ado --platform gl --jobs 8
```

Result:

- Files scanned by taudit: 11,180
- OK: 11,051
- Failed: 129
- GHA failures: 2 / 5000
- ADO failures: 92 / 5000
- GitLab failures: 35 / 1180

Top failure classes:

| Class | Count | Example |
| --- | ---: | --- |
| `duplicate_field` | 7 | GHA/GitLab duplicate top-level fields; parser exits 2. |
| ADO map where sequence expected | 7 | `jobs:` mapping form. |
| Top-level sequence where ADO struct expected | 7 | Template/list shaped ADO files. |
| ADO `steps.env` map where string expected | 2 | Conditional template env block. |
| GitLab duplicate `stages` / merge key | 4 | Duplicate YAML keys / anchors. |
| ADO string `persistCredentials` where bool expected | 2 | `"true"` should be tolerated/coerced or marked Partial. |

Concrete parser hardening backlog:

1. GHA `with:` values should tolerate sequences/maps by stringifying or marking
   `GapKind::Expression` instead of parse-failing. Example:
   `jobs.check-and-update.steps[4].with.labels: invalid type: sequence, expected a string`.
2. ADO `jobs:` map form should parse or mark Structural Partial instead of
   hard fail.
3. ADO `pool`, `stages`, and other duplicate keys should produce an Opaque or
   Structural partial graph where possible, not crash the whole scan.
4. ADO string booleans (`persistCredentials: "true"`) should coerce or mark
   Partial.
5. GitLab duplicate keys and YAML merge-key duplicates should not kill corpus
   scanning; emit Partial with a gap if possible.

## Recommended rule implementation order

1. `known_compromised_action_ref`
   - Critical when advisory says active compromise and workflow has any
     Secret/Identity access.
   - High otherwise.
   - Backed by a local advisory table initially: CVE, GHSA, affected refs,
     patched refs, active window, affected wrapper actions.

2. `docker_socket_exposed_to_ci_step`
   - New cross-platform rule.
   - Needs parser metadata for script bodies and docker socket strings across
     all supported platforms.

3. Generalize `runtime_script_fetched_from_floating_url`
   - Add ADO/GitLab/Bitbucket script body coverage.
   - Detect `curl|wget` pipe to shell even when URL is not an obvious `/main/`
     or `/latest/` mutable path.

4. Extend `dind_service_grants_host_authority`
   - Keep current GitLab service metadata.
   - Add ADO/GHA/Bitbucket script/image detection for `docker:dind`,
     `*-dind`, and privileged daemon contexts.

5. `privileged_container_in_ci_step`
   - Detect `docker run --privileged`.
   - Severity escalates with authority access.

6. `secret_material_logged_to_stdout`
   - Only fire when taudit can connect the printed variable/string to a Secret
     node or high-confidence secret metadata; raw substring hits are too noisy.

7. `eol_runtime_version`
   - Start with Node/Python setup actions and task inputs.
   - Needs a version support table and release-date update process.

## Evidence strength

- Corpus counts: observed from local scanner output.
- Taudit parser failures: observed from local taudit JSON scan harness.
- CVE mappings: observed from GitHub Advisory Database and CISA sources.
- Exploitability of individual corpus files: unresolved unless execution date,
  tag resolution, secrets access, and logs are known.

## Update: larger in-flight corpus scan

After broadening the GitLab public-project harvest, the vulnerability-pattern
scanner was rerun on 16,711 files:

| Platform | Files at scan start |
| --- | ---: |
| GitHub Actions | 5000 |
| Azure DevOps | 5000 |
| Bitbucket Pipelines | 2692 |
| GitLab CI | 4019 |

Updated vulnerability-pattern counts:

| Pattern | Hits |
| --- | ---: |
| `image_without_tag_or_digest` | 10032 |
| `npm_ignore_scripts_disabled_absent` | 2945 |
| `gh_action_major_pin_only` | 2550 |
| `latest_tag` | 2143 |
| `pip_unhashed_install` | 2007 |
| `old_github_action_major` | 1792 |
| `secret_echo_or_print` | 1081 |
| `docker_dind` | 900 |
| `curl_pipe_shell` | 337 |
| `docker_privileged` | 150 |
| `docker_sock_mount` | 74 |
| `known compromised action refs` | 24 |

The top rule priorities did not change, but confidence increased:

1. `docker_socket_exposed_to_ci_step` - 74 hits across all four platforms.
2. `known_compromised_action_ref` - 24 CVE/advisory-family hits in GHA.
3. `secret_material_logged_to_stdout` - 1081 substring hits; must be graph
   confirmed before rule emission.
4. Extend `dind_service_grants_host_authority` - 900 hits, mostly GitLab.
5. Generalize `runtime_script_fetched_from_floating_url` - 337 hits across all
   platforms.
6. `privileged_container_in_ci_step` - 150 hits across all platforms.
7. `remote_kubectl_manifest_apply` - 3 hits.
8. `opaque_encoded_payload_execution` - 2 GitLab hits.

## Update: taudit corpus run

Command:

```bash
python3 scripts/research/analyze_workflow_corpus.py --platform gha --platform ado --platform gl --jobs 8
```

Result:

- Files scanned by taudit: 14,019
- OK: 13,828
- Failed: 191
- GHA failures: 2 / 5000
- ADO failures: 92 / 5000
- GitLab failures: 97 / 4019
- Complete graphs: 7436
- Partial graphs: 6392
- Gap kinds: `expression` 7328, `structural` 19340

Most important taudit bugs / hardening work:

1. YAML shape tolerance: 161 failures are valid-enough real-world CI files
   rejected by strict typed deserialization, for example `steps:` as a map
   where taudit expects a sequence.
2. Duplicate keys: 7 failures from duplicate YAML fields. These should become
   partial/opaque graph gaps where possible instead of killing the file.
3. ADO template/list files: 7 failures from top-level sequences where taudit
   expects `AdoPipeline`.
4. ADO string booleans: 7 failures such as `persistCredentials: "true"`.
5. ADO `jobs:` map form: 5 failures where jobs are keyed maps instead of
   sequences.
6. ADO repository resources: 2 failures from `resources.repositories[]`
   entries missing `repository`.
7. GHA `with:` values: 1 failure where an action input value is a sequence
   but the parser expects a string.

Performance note:

The corpus run confirmed that parser/rule coverage is the bottleneck, not
runtime. The slowest observed file was a large ClickHouse GitHub Actions
workflow at 3333 ms; the second was another ClickHouse workflow at 2337 ms.

## Final settled corpus scan

Final observed corpus state:

| Platform | Files |
| --- | ---: |
| GitHub Actions | 5000 |
| Azure DevOps | 5000 |
| Bitbucket Pipelines | 2692 |
| GitLab CI | 5000 |

Total files: 17,692. Global unique SHA-256 hashes: 17,692. Duplicate files: 0.

Manifest provenance:

| Platform | Source | Files |
| --- | --- | ---: |
| GitHub Actions | existing local corpus | 1448 |
| GitHub Actions | GitHub repository tree | 3548 |
| GitHub Actions | missing legacy source marker | 4 |
| Azure DevOps | missing legacy source marker | 5000 |
| Bitbucket Pipelines | missing legacy source marker | 2692 |
| GitLab CI | GitLab public projects API | 2732 |
| GitLab CI | missing legacy source marker | 2268 |

Gitee was tested as a possible BB backfill source. Public repository searches
for `bitbucket-pipelines.yml` and `.gitlab-ci.yml` returned empty results in
the sampled calls, and the sampled gist/code endpoint returned 404. Treat Gitee
as a low-yield optional source unless a better authenticated/search endpoint is
identified.

Final vulnerability-pattern scan:

- Files scanned: 17,692
- Pattern findings: 26,087

Top final counts:

| Pattern | Hits |
| --- | ---: |
| `image_without_tag_or_digest` | 10847 |
| `npm_ignore_scripts_disabled_absent` | 3133 |
| `gh_action_major_pin_only` | 2550 |
| `latest_tag` | 2433 |
| `pip_unhashed_install` | 2216 |
| `old_github_action_major` | 1792 |
| `secret_echo_or_print` | 1245 |
| `docker_dind` | 1085 |
| `curl_pipe_shell` | 372 |
| `docker_privileged` | 160 |
| `docker_sock_mount` | 78 |
| `known compromised action refs` | 24 |

Current taudit run after parser/rule hardening:

```bash
python3 scripts/research/analyze_workflow_corpus.py --platform gha --platform ado --platform gl --jobs 8
```

- Files scanned by taudit: 15,000
- OK: 14,916
- Failed: 84
- GHA failures: 1 / 5000
- ADO failures: 60 / 5000
- GitLab failures: 23 / 5000
- Complete graphs: 7819
- Partial graphs: 7097
- Gap kinds: `expression` 7413, `structural` 24346

Remaining parser failures by class:

| Class | Count | Platforms |
| --- | ---: | --- |
| YAML syntax / malformed structure | 41 | ADO, GitLab |
| Indentation / block mapping errors | 24 | ADO, GitLab |
| Mapping values not allowed | 11 | ADO, GitLab |
| Duplicate fields | 6 | GHA, ADO |
| Map where sequence expected | 1 | ADO |
| Alias / anchor error | 1 | GitLab |

Current built-in rule counts from `rule_counts.json`:

- `untrusted_with_authority`: 44803
- `authority_propagation`: 14960
- `over_privileged_identity`: 14836
- `no_workflow_level_permissions_block`: 1674
- `known_compromised_action_ref`: 24
- `action_major_version_pin_without_sha`: 6656
- `docker_socket_exposed_to_ci_step`: 41
- `privileged_container_in_ci_step`: 158
- `runtime_script_fetched_from_floating_url`: 114
- `dind_service_grants_host_authority`: 168

Final parser-hardening backlog:

1. DONE: GitLab duplicate-key recovery. Duplicate `<<` merge keys, duplicate
   job/template keys, `stages`, `variables`, `script`, `only`, and singleton
   duplicate fields now recover as `Partial`/`Structural` when the rest of the
   graph can be preserved. Malformed syntax remains a hard parse failure.
2. DONE: GHA `with:` non-scalar values now use
   `HashMap<String, serde_yaml::Value>` and recurse scalar leaves for existing
   secret/env/cloud-auth scans.
3. DONE: ADO tolerant deserialization for `persistCredentials: "true"`, `env`
   maps, `jobs` map form, `dependsOn` odd shapes, and incomplete
   `resources.repositories[]` entries.
4. DONE: ADO root-fragment fallback for sequence-root files, marked
   `Partial`/`Structural` rather than `Complete`; ADO failures dropped from 92
   to 60 across the 5000-file tranche.
5. DONE: ADO `stages:` single-map form now normalizes to a one-stage list.
6. DONE: GitLab `spec: inputs` multi-document components now analyze the
   executable config document after the `---` separator instead of analyzing
   only the header document.
7. DONE: GHA omitted `permissions:` now still creates an implicit
   `GITHUB_TOKEN` identity with `scope=unknown`. This turns missing YAML
   authority from invisible into a medium-severity, evidence-backed authority
   flow while preserving the existing `no_workflow_level_permissions_block`
   rule.
8. ADO duplicate fields should not silently merge. Either hard fail or recover
   into `Partial`/`Opaque` depending on whether graph evidence can be preserved
   without hiding authority.
9. Bitbucket remains corpus-only for now; there is not yet a native
   `taudit-parse-bitbucket` crate.

Rule implementation status:

1. `known_compromised_action_ref`
   - CVE/advisory-backed: CVE-2025-30066 / GHSA-mrrh-fwg8-r2c3 and
     CVE-2025-30154 / GHSA-qmg3-hpqr-gqvc.
   - IMPLEMENTED as a built-in finding with a stable bracketed rule id and
     advisory context.

2. `docker_socket_exposed_to_ci_step`
   - 78 hits across all four platforms.
   - IMPLEMENTED for script bodies referencing `/var/run/docker.sock`.

3. `privileged_container_in_ci_step`
   - 160 hits.
   - IMPLEMENTED for script-level `docker run --privileged` and related
     container runtimes.

4. Extend `dind_service_grants_host_authority`
   - 1085 hits.
   - IMPLEMENTED: now also detects DinD image edges, not only GitLab metadata.

5. Generalize `runtime_script_fetched_from_floating_url`
   - 372 hits.
   - IMPLEMENTED for all parser-stamped script bodies with broader shell forms,
     including PowerShell `iwr|iex`.

6. `eol_runtime_version`
   - 67 final Node/Python hits.
   - NOT YET IMPLEMENTED. Requires parser-side runtime metadata for setup
     actions and container image tags.

7. Defer/noise-gate:
   - `secret_material_logged_to_stdout`, package install script execution,
   unhashed `pip install`, mutable tool installs, hardcoded key identifiers,
   remote `kubectl apply`, and encoded payload execution should require
   graph context or external secret/dependency tooling before default
   built-in emission.

Blue-team / red-team next-rule backlog:

1. `oidc_identity_in_untrusted_context`
   - Platforms: GHA, ADO, GitLab, Bitbucket.
   - Signal: OIDC `Identity` reachable from PR/MR/fork/workflow-run context or
     from a step consuming untrusted checkout/artifact.
   - Reason: OIDC removes long-lived secrets but can still mint cloud/session
     credentials from an unsafe job.

2. `self_hosted_runner_untrusted_code`
   - Platforms: GHA, GitLab, Bitbucket; ADO parity with existing pool rule.
   - Signal: self-hosted runner/image metadata plus PR/MR trigger and checkout
     or untrusted artifact consumption.
   - Reason: persistent runner hosts create cross-run workspace, network, and
     credential exposure.

3. `protected_deploy_resource_without_gate`
   - Platforms: GHA, ADO, GitLab, Bitbucket.
   - Signal: production-like environment/deployment/service connection authority
     with no visible environment binding, manual gate, protected-branch marker,
     or approval/check marker.
   - Reason: deploy authority should be bound to protected resources, not only
     script naming conventions.

4. `external_repository_checkout_with_authority`
   - Platforms: GHA, ADO, GitLab, Bitbucket.
   - Signal: non-self checkout/clone/submodule plus platform token, secret,
     OIDC identity, CI job token, SSH key, or persisted credentials.
   - Reason: external checkout expands the trust boundary of repo tokens and
     deploy credentials.

5. `artifact_to_privileged_env_or_command`
   - Platforms: ADO, Bitbucket; extend GHA/GitLab coverage.
   - Signal: artifact consumed by a privileged step, env/output writer,
     interpreter, deploy/sign/publish step, or service-connection step.
   - Reason: artifact boundaries can move untrusted build output into privileged
     workflows.

Parser/rule evasion findings to convert into tests:

- DONE: GHA omitted `permissions:` should still create an implicit
  `GITHUB_TOKEN` with `scope=unknown`; absence is not proof of no token
  authority.
- GHA service containers should be represented as image/service nodes, including
  private-registry credentials, env secret references, volumes, and options.
- ADO `resources.containers`, `resources.pipelines`, webhooks, service
  connections, secure files, variable groups, and agent pools need graph
  representation or explicit structural gaps.
- Structural template expressions in keys or sequence slots should produce an
  unresolved structure gap, not an empty clean graph.
- Add shared normalization for pin state and authority source across actions,
  reusable workflows, Docker images, GitLab includes/components, ADO templates,
  and future Bitbucket pipes/images.
