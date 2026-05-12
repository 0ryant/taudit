# Algol rule-intake — Trust-Channel Authority

Observed: 2026-05-06.
Authored as part of the Algol Trust-Channel Authority research lane.

Sources:

- `/Users/rytilcock/prj/algol/docs/research/trust-channel-authority-class-2026-05-05.md` (class definition + concrete anchors + lead-candidate seeds)
- Companion: `/Users/rytilcock/prj/algol/docs/research/authority-confusion-novel-subclasses-2026-05-05.md`
- Earlier intake: `docs/research/2026-05-05-algol-rule-intake-env-redirect-and-callee-input.md`
- Current taudit rule index: `docs/rules/index.md`
- Corpus mining over `corpus/gha` (~17,000 GHA workflows) and `corpus/workflow-yaml-testbed`.

## Class definition

Trust-Channel Authority (TCA) is the mirror class to ambient-authority confusion. AC = wrong code runs with right authority. TCA = right code, right authority, **wrong payload-or-destination through a trusted channel**. The cryptographic envelope, the OIDC token, the signed cert, the registry login, the observability sink, the GitHub API call — each is genuine. What rides inside, or where it lands, is not.

Five sub-classes, each with concrete corpus signal:

- **TCA-1** — Attestation / provenance laundering (signed predicate carries attacker-influenced state).
- **TCA-2** — Telemetry / observability exfiltration (legitimate sink carries secret material that bypasses the masker).
- **TCA-3** — Outbound-egress authority confusion (interpolated URL/registry receives bound credential).
- **TCA-4** — Cross-trust cache / output / artifact replay (PR-written content read by privileged consumer).
- **TCA-5** — GitHub API self-mutation under permissive trigger (default token mutates repo from PR/comment-reachable workflow).

These are classifier and prioritization rules. Customer-safe by default. Disclosure-grade promotion requires runtime witness that a verifier or downstream consumer accepts the laundered artifact.

## Foundational primitive (verified)

`actions/attest-build-provenance` accepts `subject-digest` **as-is** without verifying the digest against any file at `subject-name` or `subject-path`. (Confirmed 2026-05-05 from the action's `action.yml` description.) Whoever populates `${{ steps.X.outputs.digest }}` controls what is signed.

`subject-path` accepts globs over the workspace; whoever writes files into the workspace before the attest step controls what gets hashed and bound into the attestation.

`subject-checksums` reads a workspace file of digest-name pairs; whoever writes that file controls the multi-subject attestation.

These three input shapes are the primitive that grounds TCA-1.

## Proposed classifier rules

### TCA-1 — Attestation / provenance laundering

| Canonical rule id | Family | Status | Evidence level | Match shape | Exclusions/downgrades | Next gate |
|---|---|---|---|---|---|---|
| `gha_attestation_subject_digest_from_step_output_unverified` | attestation laundering | queued | corpus signal/source lead | `actions/attest@*`/`actions/attest-build-provenance@*` with `subject-digest:` interpolated from `${{ steps.*.outputs.* }}`/`${{ needs.*.outputs.* }}`/`${{ inputs.* }}`/`${{ matrix.* }}`; `id-token: write` + `attestations: write` present | the producer step is a verified-builder action with no PR-controlled inputs; the workflow is gated to `push`+tag only with no PR reachability | Add fixture for `actions/runner/docker-publish.yml` shape (digest from `docker/build-push-action`). |
| `gha_attestation_subject_path_workspace_glob_with_pr_trigger` | attestation laundering | queued | corpus signal | `subject-path:` is a workspace glob (`*`, `**`, `dist/*`, `./builds/**/*.tar.gz`) AND workflow `on:` includes `pull_request`/`pull_request_target`/`workflow_run` AND the attest step lacks an `if:` gate excluding those triggers | gate is `github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')` with no PR/`workflow_run` reachability | Add fixtures for `containerd/release.yml` (excluded — strong gate) vs. `diesel-rs/diesel/release.yml` (config-driven gate). |
| `gha_attestation_subject_checksums_path_interpolated` | attestation laundering | queued | corpus signal | `subject-checksums:` path includes `${{ ... }}` interpolation (env, inputs, step outputs) | path is a constant or only interpolates immutable values like `github.run_id` | Source-anchor `integrations/terraform-provider-github/release.yaml`. |
| `gha_attestation_predicate_path_interpolated_or_pr_writable` | attestation laundering | queued | source lead | `--predicate <path>` or `predicate-path:` references a file at an interpolated path OR a workspace path that PRs can edit, AND workflow is reachable from PR-controlled triggers | predicate file is in a directory protected by CODEOWNERS that requires review for external contributors | Source-anchor `n8n-io/n8n/.github/workflows/docker-build-push.yml`. |
| `gha_attestation_pr_trigger_with_internal_actor_gate` | attestation laundering | queued | corpus signal | attest step gated only by `github.event.pull_request.head.repo.full_name == github.repository` (or equivalent same-repo check) without further `actor`/`branch`/`environment` gating | gate also pins to `refs/heads/main` or to an actor allowlist | Source-anchor `facebook/react/runtime_build_and_test.yml`. |
| `gha_attestation_floating_major_version_with_authority` | attestation laundering | queued | corpus signal | `actions/attest@v*`, `actions/attest-build-provenance@v*`, or `actions/attest-sbom@v*` pinned only to a major version when `id-token: write` is present | action is pinned to a SHA | Train against the 47-file `attest-build-provenance` corpus subset. |
| `gha_attestation_unpinned_helper_to_signed_subject` | attestation laundering | queued | source lead | a pre-attest step `uses:` an action pinned to `@master`/`@main`/`@HEAD` whose output flows into `subject-name`, `subject-digest`, `subject-checksums`, or the cosign image/blob | helper is a same-org composite action with required-review CODEOWNERS | Source-anchor `home-assistant/core/builder.yml` (uses `home-assistant/actions/helpers/version@master`). |
| `gha_attestation_cosign_sign_yes_with_interpolated_subject` | attestation laundering | queued | corpus signal | shell `cosign sign --yes` or `cosign attest --yes` where the image/blob argument is interpolated AND `id-token: write` is present; severity rises with `COSIGN_EXPERIMENTAL=true` | image is a digest-pinned constant; `--yes` is omitted | Source-anchor `falcosecurity/falco/reusable_publish_docker.yaml`, `ossf/scorecard/publishimage.yml`. |
| `gha_attestation_config_driven_gate_from_workspace_file` | attestation laundering | queued | source lead | the `if:` gate on the attest step reads `fromJson(needs.*.outputs.*)` whose producer parses a workspace config file (cargo-dist `dist-workspace.toml`, goreleaser config, custom JSON) editable by PRs | producer reads only constant fields like `github.event_name` | Source-anchor `diesel-rs/diesel/release.yml` cargo-dist `pr_run_mode=upload` shape. |

### TCA-2 — Telemetry / observability exfiltration

| Canonical rule id | Family | Status | Evidence level | Match shape | Exclusions/downgrades | Next gate |
|---|---|---|---|---|---|---|
| `gha_telemetry_pr_or_issue_text_to_external_sink` | telemetry exfil | queued | corpus signal | sink action (`slack-send`, `slackapi/*`, `8398a7/action-slack`, Discord webhook, `actions-ecosystem/action-create-issue`, custom POST `curl`/`gh api`) interpolates `github.event.pull_request.title`/`body`, `github.event.issue.title`/`body`, or `github.event.comment.body` into payload | the sink writes only constant content, or PR text is rendered code-fenced and the sink is internal-only | Source-anchor `facebook/react/runtime_discord_notify.yml`, `metabase/.../team-issues-slack-notification.yml`, `hashicorp/terraform-provider-aws/comments.yml`. |
| `gha_telemetry_tojson_github_or_env_in_token_job` | telemetry exfil | queued | corpus signal | step uses `toJson(github)`, `toJson(env)`, or `toJson(secrets)` AND the same job has `${{ secrets.* }}` or `id-token: write` | toJson is consumed only by `if:` evaluation (no shell context); job has no token authority | Source-anchor `apache/kafka/ci-complete.yml`. |
| `gha_telemetry_debug_flag_with_secret_env` | telemetry exfil | queued | corpus signal | workflow or job `env:` sets `ACTIONS_STEP_DEBUG: true`, `ACTIONS_STEP_DEBUG: ${{ secrets.* }}`, or `ACTIONS_RUNNER_DEBUG: true` AND any step in the same job has `${{ secrets.* }}` references | debug flag is set only on a step that has no secret env | Source-anchor `electron/.../pipeline-segment-electron-build.yml`, `unionlabs/union/.../deploy-docs.yml`. |
| `gha_telemetry_secret_reencoding_before_log_or_sink` | telemetry exfil | queued | source lead | step contains `echo $<SECRET_VAR> \| (base64\|xxd\|tr\|jq\|printf %x)`, `python -c "import base64; ..."`, or other re-encoding patterns followed by `>> $GITHUB_OUTPUT`, `>> $GITHUB_STEP_SUMMARY`, `curl`, `gh api`, `slack-send`, or artifact upload | re-encoding is performed only locally and never reaches a log, output, or sink | Add a fingerprint pattern for the 27-file corpus subset. |
| `gha_telemetry_step_summary_with_secret_or_event_text` | telemetry exfil | queued | corpus signal | `>> $GITHUB_STEP_SUMMARY` or `core.summary` write that interpolates `${{ secrets.* }}` directly OR `github.event.*.body`/`title`/`comments` | summary is a constant string; PR text is escaped before write | Pair with `sensitive_value_in_job_output`. |
| `gha_telemetry_continue_on_error_with_notify_dump` | telemetry exfil | queued | corpus signal | step has `continue-on-error: true` or runs in a `if: failure()` job with `printenv`/`bash -x`/`set -x` followed by an external-sink notification | the failure path notifies only with constant content | Add corpus fixture. |
| `gha_telemetry_webhook_url_from_input_or_event` | telemetry exfil | queued | corpus signal | webhook URL is interpolated from `${{ inputs.* }}`, `${{ vars.* }}`, or `${{ github.event.* }}` AND payload includes secret-bearing or context-derived material | webhook URL is interpolated only from `${{ secrets.* }}`-managed values | Pair with TCA-3 egress rules. |
| `gha_telemetry_autonomous_agent_input_from_untrusted_event` | telemetry/agent exfil | queued | source lead | autonomous code agent action (e.g. `anthropics/claude-code-action`, `aider`, `cursor-agent`, `openai/codex-action`) receives prompt/files/env from `github.event.issue.*`, `github.event.pull_request.*`, or `github.event.comment.*` AND has tool-use, write, or push capability | agent is gated by `MAINTAINER`/`OWNER` actor allowlist before invocation; agent runs read-only with no mutation | Source-anchor `cockroachdb/cockroach/issue-autosolve.yml`, `pr-autosolve-ci.yml`. |

### TCA-3 — Outbound-egress authority confusion

| Canonical rule id | Family | Status | Evidence level | Match shape | Exclusions/downgrades | Next gate |
|---|---|---|---|---|---|---|
| `gha_egress_curl_authorization_to_interpolated_url` | egress confusion | queued | corpus signal | `run:` body contains `curl` with `Authorization:` header, `-u user:$TOKEN`, or `--netrc` AND URL is interpolated from `${{ inputs.* }}`, `${{ matrix.* }}`, `${{ github.event.* }}`, or `${{ needs.* }}` | URL is a constant or interpolates only `${{ secrets.WEBHOOK_URL }}`-managed values | Add fixture from agent corpus mining. |
| `gha_egress_npm_install_registry_with_token` | egress confusion | queued | corpus signal | `npm install --registry`/`pnpm install --registry`/`yarn config set registry`/`.npmrc` registry override interpolated AND `NPM_TOKEN`/`NODE_AUTH_TOKEN`/`id-token: write` in scope | registry is a constant or org-pinned URL | Pair with `gha_setup_node_cache_helper_path_handoff`. |
| `gha_egress_pip_index_url_with_authority` | egress confusion | queued | corpus signal | `pip install --index-url`/`--extra-index-url` interpolated AND PyPI/private-index credential or OIDC in scope | index is constant; install is dry-run | Pair with `gha_env_pip_index_redirect_before_setup_python_install`. Source-anchor `saltstack/salt/release-upload-virustotal.yml`. |
| `gha_egress_docker_registry_with_authority` | egress confusion | queued | corpus signal | `docker pull`/`docker push`/`docker login` registry host interpolated AND registry credentials in scope | registry is a constant; image is digest-pinned | Pair with `gha_workflow_call_container_image_input_secrets_inherit`. |
| `gha_egress_git_remote_to_interpolated_url_with_persist_credentials` | egress confusion | queued | corpus signal | `git clone`/`git remote add`/`git push` to interpolated URL AND `persist-credentials: true` (or default true) on `actions/checkout` AND token authority present | `persist-credentials: false` is set; URL is a constant | Pair with existing `gha_pat_remote_url_write`. |
| `gha_egress_helm_repo_or_registry_with_cluster_auth` | egress confusion | queued | corpus signal | `helm repo add`/`helm pull`/`helm push`/`helm registry login` URL interpolated AND cluster or registry credentials present | repo URL is a constant | Source-anchor `hashicorp/terraform-provider-kubernetes/acceptance_tests_eks.yaml`. |
| `gha_egress_cloud_cli_endpoint_override` | egress confusion | queued | source lead | `aws`/`az`/`gcloud` with `--endpoint-url`/`--endpoint-override` or `AWS_ENDPOINT_URL`/`AZURE_ENDPOINT_URL` env interpolated AND cloud credentials present | endpoint is the public cloud's documented endpoint | Add fixture once corpus surface is enumerated. |
| `gha_egress_gh_api_path_interpolated` | egress confusion | queued | corpus signal | `gh api ${{ ... }}` or `octokit.request(${{ ... }})` with path/method interpolated AND default `GITHUB_TOKEN` or PAT in scope | path is a constant; method is GET only | Pair with TCA-5 API mutation rules. |

### TCA-4 — Cross-trust cache / output / artifact replay

| Canonical rule id | Family | Status | Evidence level | Match shape | Exclusions/downgrades | Next gate |
|---|---|---|---|---|---|---|
| `gha_cache_pr_save_main_restore_same_key` | cache poisoning | queued | corpus signal | `actions/cache` save in PR-triggered job uses a key shape (`hashFiles(...)`, `runner.os-${...}`) also restored by a `push`/`release`/`workflow_dispatch` job in another file in the same repo with privileged consumer | key includes `github.run_id` or another unique-per-run value; restore-keys do not fall back to PR-shape | Source-anchor `home-assistant/core/ci.yaml`, `python/cpython/build.yml`. |
| `gha_cache_restore_keys_fallback_to_pr_keys` | cache poisoning | queued | corpus signal | `actions/cache.restore-keys:` includes prefixes that PR jobs save under | restore-keys are anchored to constants that PR jobs cannot match | Add corpus fingerprint. |
| `gha_artifact_upload_pr_with_name_collision_to_privileged_consumer` | artifact replay | queued | corpus signal | `actions/upload-artifact` in PR-triggered job uses a name read by `actions/download-artifact` in a `workflow_run` consumer with token authority | artifact name is unique-per-run; consumer downloads only by run-id-scoped pattern | Source-anchor `vercel/next.js/upload_preview_tarballs.yml`, `tiangolo/fastapi/deploy-docs.yml`, `grafana/grafana/backport-workflow.yml`. |
| `gha_job_outputs_pr_to_privileged_needs_consumer` | output replay | queued | corpus signal | a `pull_request`/`pull_request_target` job's `outputs:` are consumed via `needs.*.outputs.*` by a job with `id-token: write`, registry secrets, or deploy authority | consumer job is gated by `if:` to non-PR triggers; outputs are constant strings | Source-anchor `chef/chef/func_spec.yml`, `apache/kafka/ci-complete.yml`. |
| `gha_artifact_download_v3_in_workflow_run_consumer` | artifact replay | queued | source lead | `actions/download-artifact@v3` (vulnerable to known cross-workflow_run leak) used in any privileged consumer job | downgraded to `@v4` with run-id-scoped download | Pair with `unsafe_pr_artifact_in_workflow_run_consumer`. |
| `gha_workflow_run_artifact_to_blob_storage_token` | artifact replay | queued | corpus signal | `workflow_run` consumer downloads artifact AND writes that artifact (or its bytes) to a blob/object-storage destination using a token-bearing action or shell | consumer applies cryptographic verification (signature, attestation) before write | Source-anchor `vercel/next.js/upload_preview_tarballs.yml`. |
| `gha_step_id_reused_across_conditional_branches` | output collision | queued | corpus signal | two or more steps in the same job share an `id:` under different `if:` branches AND a downstream consumer reads `steps.<id>.outputs.*` | steps are mutually exclusive via static `if:` | Add corpus fingerprint. |

### TCA-5 — GitHub API self-mutation under permissive trigger

| Canonical rule id | Family | Status | Evidence level | Match shape | Exclusions/downgrades | Next gate |
|---|---|---|---|---|---|---|
| `gha_api_self_pr_review_approve_under_pr_trigger` | API self-mutation | queued | corpus signal | `gh pr review --approve`, `octokit.pulls.createReview` with `event: 'APPROVE'`, or `actions/github-script` calling same; in a workflow whose triggers include `pull_request_target`, `workflow_run`, or `issue_comment` AND `pull-requests: write` | identity gate is `dependabot[bot]` or app-token signed by a CODEOWNERS-protected app; branch protection does not count `github-actions[bot]` reviews | Source-anchor `metabase/metabase/release-embedding-sdk.yml`, `webpack/webpack/dependabot.yml`. |
| `gha_api_self_auto_merge_under_pr_trigger` | API self-mutation | queued | corpus signal | `gh pr merge --auto`, `octokit.pulls.merge`, or `octokit.repos.merge` with `contents: write` AND PR/comment trigger | merge is gated by required-reviews-from-CODEOWNERS branch protection | Pair with `gh_cli_with_default_token_escalating`. |
| `gha_api_branch_protection_mutation` | API self-mutation | queued | source lead | `octokit.repos.updateBranchProtection`, `gh api -X PUT .../branches/<branch>/protection` | mutation is gated to manual approval environment | Add corpus fixture. |
| `gha_api_repo_settings_mutation` | API self-mutation | queued | source lead | `gh api -X PATCH /repos/<owner>/<repo>` toggling `allow_force_pushes`, `default_branch`, `delete_branch_on_merge`, `allow_auto_merge` | mutation is gated to manual approval environment | Add corpus fixture. |
| `gha_api_secret_or_variable_mutation` | API self-mutation | queued | source lead | `gh api -X PUT .../actions/secrets/<name>`, `octokit.actions.createOrUpdateRepoSecret`, `octokit.actions.createOrUpdateOrgVariable` | rotation flow gated to environment with required reviewers | Add corpus fixture. |
| `gha_api_webhook_or_deploy_key_creation` | API self-mutation | queued | source lead | `gh api .../hooks` POST/PATCH or `gh api .../keys` POST | gated to environment-protected manual approval | Add corpus fixture. |
| `gha_api_label_gated_privileged_step` | API self-mutation | queued | corpus signal | `if: contains(github.event.pull_request.labels.*.name, '<label>')` followed by privileged step (deploy/publish/sign/api-mutate); label is mutable by triage role | label gate is paired with an explicit actor allowlist with MAINTAINER/OWNER | Source-anchor `apache/kafka/workflow-requested.yml`, `cockroachdb/cockroach/pr-autosolve-ci.yml`. |
| `gha_api_comment_command_to_privileged_step` | API self-mutation | queued | corpus signal | `if: github.event.comment.body == '/<cmd>'` style gate followed by privileged step; the comment author gate is not pinned to MAINTAINER/OWNER | comment author allowlist pins to repo OWNER/ADMIN with no co-author class accepted | Source-anchor `sveltejs/svelte/autofix.yml`. |
| `gha_api_rerun_on_comment_to_privileged_workflow` | API self-mutation | queued | corpus signal | `gh run rerun` or `octokit.actions.reRunWorkflow` invoked under `pull_request_review`, `issue_comment`, or `pull_request_review_comment` trigger | re-run is restricted to a CODEOWNERS-gated workflow that has no privileged side-effects | Pair with TCA-2 autonomous agent rule. |
| `gha_api_workflow_run_artifact_to_autonomous_agent_to_git_push` | API self-mutation / agent exfil | queued | source lead | `workflow_run` consumer downloads artifact OR consumes upstream-job outputs/CI-failure data, passes content into an autonomous agent action (`claude-code-action`, `aider`, `cursor-agent`), AND a later step does `git push`, `gh pr edit`, `peter-evans/create-pull-request`, or `peter-evans/create-or-update-comment` | agent runs read-only with no mutation; chain is gated by required-reviews from MAINTAINER/OWNER with no triage bypass | Source-anchor `cockroachdb/cockroach/pr-autosolve-ci.yml`. |

## Severity guidance

| Sub-class | Default | Promote to High when | Demote to Advisory when |
|---|---|---|---|
| TCA-1 — attestation laundering | High | subject/predicate is interpolated AND the workflow is reachable from PR-controlled triggers AND the verifier identity (cert SAN) is checkable but workflow-author docs do not pin to ref | attest step is gated to `push`+tag with no PR/`workflow_run` reachability AND subject is a constant or pinned-by-checksum |
| TCA-2 — telemetry exfil | Medium | secret-bearing payload reaches a sink whose retention or audience differs from GitHub's, OR debug logging is enabled in a token-bearing job | sink consumes only constant content or PR text rendered code-fenced for human review |
| TCA-3 — egress confusion | High | URL is interpolated from `${{ inputs.* }}`/`${{ matrix.* }}`/`${{ github.event.* }}` AND credential is bound | URL is constant or organization-policy-pinned |
| TCA-4 — cache/output/artifact replay | High | privileged consumer reads artifact/output written by a PR-triggered job AND consumer has token authority | consumer is gated to non-PR triggers AND artifact name is unique-per-run |
| TCA-5 — API self-mutation | High | mutation is reachable from PR/comment trigger AND gate is label/comment-content (mutable by triage) | mutation is gated to manual-approval environment with CODEOWNERS reviewer requirement |

## Engineering anchor pointers

These map cleanly into the existing rule machinery:

- **TCA-1** — extend the existing `subject-`/`predicate-` parsing in `taudit-parse-gha`. New shared predicate: "this attest step is reachable on a PR/`workflow_run` trigger after applying `if:` gates."
- **TCA-2** — enrich `propagation::collect_step_writes` to track interpolation sources reaching `>> $GITHUB_STEP_SUMMARY`, webhook payloads, and notification action `with:` blocks. Add a debug-flag predicate.
- **TCA-3** — generalize the existing PIP/NPM index-redirect detection into a shared "credential-bearing outbound + interpolated destination" detector. Use the existing same-job authority predicate.
- **TCA-4** — introduce a cross-file matcher: cache-key shape and artifact-name shape produced in a PR-trigger workflow file, consumed in a non-PR workflow file in the same repo. This is new shape; existing `cache_key_crosses_trust_boundary` is single-file.
- **TCA-5** — extend `gh_cli_with_default_token_escalating` with API-mutation-sink classification (review-approve, auto-merge, label-mutation, branch-protection, secret-mutation). Add a label-gate-mutability predicate based on documented role-to-permission mapping.

## Customer-safety wording

For all rules in this intake, default findings phrase the issue as a hardening recommendation, not a vulnerability claim. Promote to disclosure-grade only when an Algol witness artifact (canary-only) is attached.

## Disclosure pairing notes

- **TCA-1** strongest disclosure path: `actions/attest-build-provenance` accepting `subject-digest` as-is is a class-level platform issue. Filing route: GitHub private security advisory. The cargo-dist `pr_run_mode=upload` config gate is a strong product-specific filing.
- **TCA-2** strongest disclosure path: GitHub platform clarification on `ACTIONS_STEP_DEBUG` and `toJson(secrets)` masking guarantees. Filing route: GitHub private security advisory.
- **TCA-3** strongest disclosure path: pair with the existing ENV-CFG candidate `ALGOL-CANDIDATE-20260505-059` (`aws-actions/configure-aws-credentials`); the egress-confusion frame extends that lead to AWS endpoint-override and to non-AWS clouds.
- **TCA-4** strongest disclosure path: `vercel/next.js/upload_preview_tarballs.yml` is the cleanest exfil-and-replace channel. Filing route: Vercel security.
- **TCA-5** strongest disclosure path: the autonomous-agent class pattern (`cockroachdb/cockroach/pr-autosolve-ci.yml`) is novel and worth a coordinated filing across the agent vendor (Anthropic) and the affected project. The `metabase` auto-approve-and-auto-merge shape is a clean per-project filing.
