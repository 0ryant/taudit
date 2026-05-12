# Algol rule-intake — Authority Class Quintet (TAC + ISC + CFA + SHRL + VA)

Observed: 2026-05-06.
Authored as part of the Algol Authority-Class-Quintet research lane.

Sources:

- `/Users/rytilcock/prj/algol/docs/research/authority-class-quintet-2026-05-06.md`
- Companions: `manifest-authority-confusion-class-2026-05-06.md`,
  `trust-channel-authority-class-2026-05-05.md`,
  `authority-confusion-novel-subclasses-2026-05-05.md`.
- Witness harness: `docs/research/hosted-runner-witness-harness.md`
- Earlier intakes:
  `docs/research/2026-05-05-algol-rule-intake-env-redirect-and-callee-input.md`,
  `docs/research/2026-05-06-trust-channel-authority-rule-intake.md`,
  `docs/research/2026-05-06-manifest-authority-confusion-rule-intake.md`.

These are classifier and prioritization rules. Customer-safe by default.
Disclosure-grade promotion requires runtime witness per the witness
harness contract.

## Class summary

The Quintet adds five new orthogonal classes to Algol's coverage:

| Class | Boundary | Relation to existing classes |
|---|---|---|
| **TAC** Temporal Authority Confusion | time | orthogonal to AC/TCA/MAC |
| **ISC** Identity / Subject Confusion | principal | orthogonal to AC/TCA/MAC |
| **CFA** Cross-Forge Authority | inter-forge | extends MAC-8 across forges |
| **SHRL** Self-Hosted Runner Lifecycle | runner-host | extends existing self-hosted rules to GHA-native and runner-agent lifecycle |
| **VA** Verifier Asymmetry | consumer-side | pairs with TCA-1 producer-side |

The full octet (AC + TCA + MAC + Quintet) is the current Algol coverage
surface. Future candidates should be classified into exactly one of the
eight; if a candidate doesn't fit cleanly, it's a signal a ninth class
may exist.

## Foundational primitives proven this tranche

- **VA paired with TCA-1**: `actions/attest`'s `subject-digest`-as-is
  primitive (already proven in pack -064) pairs with `gh attestation
  verify` without `--source-digest` to produce a complete
  producer-consumer disclosure pair. Pack -069 in this tranche
  implements the combined offline canary.
- **ISC Fulcio-cert SAN under-pinning**: `cosign verify
  --certificate-identity-regexp '.*'` accepts a Fulcio cert whose `sub`
  reflects a PR ref. Pack -070 in this tranche implements the
  consumer-side canary against a synthetic cert.

## Proposed classifier rules

### TAC — Temporal Authority Confusion

| Rule ID | Status | Match shape | Severity |
|---|---|---|---|
| `gha_temporal_oidc_freshness_across_multistep_build` | queued | `id-token: write` + `actions/attest@*` or shell `cosign sign`/`cosign attest` step at job-end after `timeout-minutes: > 30` between mint and use | High |
| `gha_temporal_action_ref_drift_workflow_run_consumer` | queued | `workflow_run` consumer with `actions/checkout@v*` (floating major) + artifact-integrity checks against a producer-time-resolved SHA | Medium-High |
| `gha_temporal_concurrency_cancel_with_credential_env` | queued | `concurrency.cancel-in-progress: true` + `${{ secrets.* }}` reference in same job + cache/artifact write step | Medium |
| `gha_temporal_cache_restore_keys_pr_to_main_drift` | queued | `actions/cache.restore-keys:` broad prefix that PR jobs save under, restored by `push:main`/`push:tag`/`schedule` job | Medium-High |
| `gha_temporal_environment_approval_to_run_window` | queued | `environment:` with required-reviewers AND PR-derived inputs that can change between approval and run | Medium |
| `gha_temporal_tag_rewrite_during_workflow_run` | queued | `workflow_run` consumer that reads a tag-shaped ref produced by a `push:tag` upstream | Medium |
| `gha_temporal_rerun_under_newer_secret_state` | queued | workflows that document `gh run rerun` patterns for retry; candidate for rule when secret rotation is observable | Advisory |

### ISC — Identity / Subject Confusion

| Rule ID | Status | Match shape | Severity |
|---|---|---|---|
| `gha_identity_oidc_aud_claim_multicloud_reuse` | queued | `id-token: write` + multiple cloud-auth actions (aws/azure/gcp) sharing one minted token | High |
| `gha_identity_workflow_dispatch_actor_vs_ref_principal_mismatch` | queued | `workflow_dispatch.inputs.<branch\|ref>` + `id-token: write` without explicit actor gate | Medium-High |
| `gha_identity_cosign_certificate_identity_repo_only_no_ref` | queued | `cosign verify --certificate-identity` regex matching repo path without `@refs/heads/` or `@refs/tags/` segment | Medium-High |
| `gha_identity_reusable_workflow_secrets_inherit_principal_mismatch` | queued | `workflow_call` + `secrets: inherit` + (callee path unpinned `@main` OR caller PR-reachable) | High |
| `gha_identity_github_app_token_in_untrusted_workflow_trigger` | queued | `actions/create-github-app-token` + `workflow_dispatch` with no actor gate, OR `workflow_run` consuming low-trust upstream | Medium |
| `gha_identity_autonomous_agent_untrusted_principal_input` | queued | autonomous code agent (claude-code, aider, cursor-agent, codex-action) with `workflow_run.pull_request` or `github.event.issue.*` prompt + write/push capability | High |
| `gha_identity_environment_protection_bypass_input_version_check` | queued | `environment:` gate + `inputs.*` where version/target validation happens after or in parallel with OIDC issuance | High |
| `gha_identity_workflow_run_artifact_principal_downgrade` | queued | `workflow_run` consumer of PR-uploaded `actions/download-artifact` flowing into sign/deploy/push under default-branch authority | High |

### CFA — Cross-Forge Authority

| Rule ID | Status | Match shape | Severity |
|---|---|---|---|
| `gha_crossforge_mirror_checkout_with_token_push` | queued | `actions/checkout` with `repository:` override + `git push`/`gh api` with credentials in same job | High |
| `gha_crossforge_fork_bot_credential_divergence` | queued | `git push` to alternate-owner fork with distinct PAT (`*_FORK_PAT`, `*_BOT_PAT`) vs canonical secrets | Medium-High |
| `gha_crossforge_git_remote_add_with_authority` | queued | `git remote add <non-canonical-url>` + `git push` with token in `workflow_run`/`issue_comment`/`pull_request_target` context | Medium |
| `gitlab_crossforge_registry_mirror_credential_scope` | queued | `docker pull $CI_REGISTRY_IMAGE` paired with `docker push` to alternate registry | Medium |
| `azure_crossforge_artifact_publish_divergent_pipeline` | queued | `PublishPipelineArtifact@1` alongside GitHub Artifacts and GitLab artifacts in same repo (dual-CI signal) | Advisory |

### SHRL — Self-Hosted Runner Lifecycle

| Rule ID | Status | Match shape | Severity |
|---|---|---|---|
| `gha_runner_lifecycle_self_hosted_pr_no_isolation` | queued | `runs-on: [self-hosted, ...]` + `pull_request*` trigger + no `workspace: { clean: all }` (GHA counterpart of `shared_self_hosted_pool_no_isolation`) | High |
| `gha_runner_lifecycle_arc_jit_provisioning_from_untrusted_context` | queued | `runs-on:` contains `${{ github.run_id }}`/ARC-family syntax + PR/issue trigger; OR callable `runs-on` input from untrusted caller | High |
| `gha_runner_lifecycle_image_build_recursive_trust` | queued | workflow outputs artifact labeled as runner image/toolchain that's consumed by subsequent runs | Medium |
| `gha_runner_lifecycle_pre_post_job_hooks_from_workspace` | queued | step sets `ACTIONS_RUNNER_HOOK_JOB_STARTED`/`_COMPLETED` env to a repo-relative path + PR/untrusted trigger | Critical (if reachable) |
| `gha_runner_lifecycle_jit_registration_token_in_secret` | queued | `RUNNER_REGISTRATION_TOKEN`/`GH_RUNNER_TOKEN`/`ACTIONS_RUNNER_TOKEN`-shape secret referenced by a non-runner-management workflow | Medium-High |

### VA — Verifier Asymmetry

| Rule ID | Status | Match shape | Severity |
|---|---|---|---|
| `gha_verifier_cosign_identity_regex_accept_any` | queued | `cosign verify*` with `--certificate-identity-regexp` matching `.*`/`.+`/`[^.]+` or repo-only regex without ref segment | High |
| `gha_verifier_gh_attestation_missing_source_digest_check` | queued | `gh attestation verify <artifact> --repo <X> [--signer-repo <X>]` without `--source-digest` flag | High |
| `gha_verifier_attest_digest_from_step_output_unverified` | queued (TCA-1 paired) | `actions/attest@*`/`actions/attest-build-provenance@*` with `subject-digest` from `${{ steps.*.outputs.* }}` | High (severity overlapping with TCA-1) |
| `gha_verifier_pip_require_hashes_from_pr_mutable_file` | queued | `pip install --require-hashes -r <pr-mutable-path>` + `pull_request*` trigger | Medium-High |
| `gha_verifier_oci_pull_no_signature_check_before_use` | queued | `docker pull` of interpolated image + later use without intervening `cosign verify`/`crane verify`/`docker trust verify` | Medium |
| `gha_verifier_npm_audit_signatures_silent_skip` | queued | `npm audit signatures` in a flow that doesn't fail on "no signatures available" | Advisory |
| `gha_verifier_slsa_versioned_tag_no_ref_pin` | queued | `slsa-verifier verify-artifact` with `--source-versioned-tag` only (no SHA pin) | Medium |
| `gha_verifier_custom_shell_verifier_repo_mutable` | queued | workflow runs `bash verify.sh` / `./scripts/verify-*.sh` where the script lives in the workspace and credentials are in scope | Medium |

## Severity guidance

| Class | Default | Promote to High when | Demote to Advisory when |
|---|---|---|---|
| TAC | Medium | OIDC freshness window crossed AND attestation/registry endpoint downstream; OR PR-cache restored by main with deploy authority | concurrency-cancel without credential mutation; tag-rewrite where producer SHA is also pinned in consumer |
| ISC | High | reusable callable + secrets:inherit + caller PR-reachable; OR cosign verify with `.*` regex; OR autonomous agent + write capability | bot identity in non-mutating contexts (notify, issue comment) |
| CFA | Medium | mirror-bot PAT with cross-org write authority; fork-bot with separate secret scope reachable from PR | dual-CI doctrine concerns without explicit cross-forge PAT |
| SHRL | High | PR-reachable self-hosted with token-bearing secrets; ARC dynamic label from untrusted context | runner-image build pipelines without observable downstream consumer |
| VA | High | wildcard identity regex; missing `--source-digest`; PR-mutable hashes/keyring; paired with TCA-1 producer | `npm audit signatures` advisory only |

## Engineering anchor pointers

- **TAC** — extend `propagation::collect_step_writes` with a per-step
  timestamp model. New shared predicate: "step-A produces value;
  step-B uses value; T(B) - T(A) > <threshold>". Threshold for OIDC
  freshness is 10 minutes.
- **ISC** — `taudit-parse-gha` already parses `permissions:` and
  `id-token: write`. Add a per-job principal-claim model: which
  `aud`, `sub`, `repository`, `ref`, `environment` the OIDC reflects.
  Cross-reference verifier-config patterns for ISC-3 / VA-1.
- **CFA** — extend the existing `unpinned_action` to emit a
  `cross-forge` boolean when the action's URL is not on github.com.
  Add a per-org dual-CI detection step that walks adjacent
  `.gitlab-ci.yml`, `azure-pipelines.yml`, `bitbucket-pipelines.yml`.
- **SHRL** — port the Azure-DevOps `shared_self_hosted_pool_no_isolation`
  rule to GHA semantics. Add an ARC-label predicate that flags
  `${{ github.run_id }}`-shaped runs-on.
- **VA** — extend `taudit graph`'s sink classification with a
  `verifier-config` node kind. Surface verifier weakness inline in
  the propagation summary so reviewers see "this artifact is
  attested but the verifier accepts repo-only identity."

## Witness harness integration

All five classes use the harness defined in
`docs/research/hosted-runner-witness-harness.md`. SHRL-1 specifically
needs a self-hosted-runner variant (not yet shipped); the harness's
"Future extensions" section calls this out.

For VA + TCA-1 paired disclosure, pack -069 (this tranche) is the
canonical local-runtime canary. ISC-3 / VA-1 paired disclosure is
pack -070.

## Disclosure pairing notes

- **TCA-1 + VA-2** (pack -069): the strongest disclosure pair in the
  Algol research lane. File against GitHub for `actions/attest`
  (producer) AND against the gh CLI maintainers for
  `gh attestation verify` defaults (consumer).
- **ISC-3 + VA-1** (pack -070): file against sigstore/cosign for the
  default behavior of `--certificate-identity-regexp` documentation.
- **TAC-4** (OIDC freshness): file against GitHub Actions runner +
  Sigstore Fulcio for documented freshness handling at use time vs
  issue time.
- **SHRL-1** (PR self-hosted no isolation): per-target filings
  (cockroachdb, valkey, bridgecrew) plus a class-level filing to
  GitHub for documentation defaults.
- **CFA-1** (mirror-bot PAT): per-target filings for the wiki-sync
  shape (Azure terraform CAF) and fork-bot shape (cockroachdb
  autosolver).
