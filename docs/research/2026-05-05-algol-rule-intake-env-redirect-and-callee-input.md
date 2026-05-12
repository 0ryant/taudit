# Algol rule-intake — env-redirect and callee-input authority confusion

Observed: 2026-05-05.
Authored as part of the Algol authority-confusion CVE tranche.

Sources:

- `/Users/rytilcock/prj/algol/docs/research/taudit-authority-confusion-ruleset-handoff.md`
- `/Users/rytilcock/prj/algol/docs/research/taudit-corpus-lead-hunt-ruleset.md`
- Background research in `/Users/rytilcock/prj/algol/docs/research/authority-confusion-novel-subclasses-2026-05-05.md`
- Current taudit rule index: `docs/rules/index.md`
- Corpus mining over `corpus/gha` (~17,000 GHA workflows) and `corpus/workflow-yaml-testbed`.

These are classifier and prioritization rules for customer-safe findings. Corpus hits and source leads are not vulnerability claims. Disclosure-grade evidence still requires runtime witness on the appropriate runner.

## Why these are new

The currently landed authority-confusion rules cover **PATH-resolved bare helpers** (`gha_helper_path_sensitive_*`, `*_cache_helper_path_handoff`, `*_installer_then_shell_helper_authority`) and a small number of action-owned cleanup, output-laundering, and download-helper edges. They do not yet cover:

1. Earlier-step writes to **environment variables that override config-file resolution** for credential helpers (AWS, Azure, GCP, Kubernetes, Docker, Helm, Terraform, npm, pip, GPG, Git). These do not require PATH mutation; the file the helper reads or writes is itself misdirected.
2. Earlier-step writes to **language-runtime startup env** (`NODE_OPTIONS`, `PYTHONPATH`/`PYTHONSTARTUP`, `RUBYOPT`/`BUNDLE_GEMFILE`, `LD_PRELOAD`/`LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`/`DYLD_LIBRARY_PATH`, `PERL5LIB`) that inject code into any later interpreter or dynamically linked helper, even when the helper itself is at an absolute path.
3. **Reusable-workflow caller→callee trust drift**: `on: workflow_call` callees that take `image`, `runs-on`/`runner-label`, `ref`, `script`/`command` inputs while declaring `secrets: inherit`, then are invoked from caller workflows triggered by `pull_request_target`, `workflow_run`, `issue_comment`, or by chained reusables that originate from those triggers.
4. **Container and service-container authority confusion**: `container.image` or `services.<name>.image` interpolated from `${{ inputs.* }}`, `${{ matrix.* }}`, or `${{ github.event.* }}` while the same job carries credential-bearing secrets — including the `--privileged` / `--cap-add` / `-v /var/run/docker.sock` shape that grants escalated runtime authority.
5. **`GITHUB_OUTPUT` / `GITHUB_ENV` last-write-wins collisions** consumed by a downstream privileged sink, including artifact-name-to-matrix flows that select credentials from a less-trusted producer.
6. **Dynamic matrix and `runs-on` interpolation** from `needs.<job>.outputs.*` that originated in an attacker-influenced producer, including `runs-on: ${{ inputs.runner }}` callable workflows.

## Evidence levels

- `corpus signal`: workflow shape exists in public YAML.
- `source lead`: action source or helper documentation confirms the env or input is consulted.
- `runtime witness`: canary-only runner-faithful or hosted-runner proof.

## Proposed classifier rules

### Family A — Config-file env redirection

| Canonical rule id | Family | Status | Evidence level | Match shape | Exclusions/downgrades | Next gate |
|---|---|---|---|---|---|---|
| `gha_env_credential_helper_config_redirect_before_authority` | env-config redirect | queued | source lead | earlier same-job step assigns one of `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE`, `AWS_PROFILE`, `AWS_WEB_IDENTITY_TOKEN_FILE`, `AZURE_CONFIG_DIR`, `CLOUDSDK_CONFIG`, `GOOGLE_APPLICATION_CREDENTIALS`, `KUBECONFIG`, `KUBE_CONFIG_PATH`, `DOCKER_CONFIG`, `DOCKER_HOST`, `NPM_CONFIG_USERCONFIG`, `NPMRC`, `PIP_CONFIG_FILE`, `HELM_REPOSITORY_CONFIG`, `HELM_REGISTRY_CONFIG`, `TF_CLI_CONFIG_FILE`, `GNUPGHOME`, `XDG_CONFIG_HOME` (literal `env:`, matrix, step env, or `>> $GITHUB_ENV`); a later step is a known credential-materializing action or runs the matching helper under token/cloud/registry env | env value is a constant pinned to a workflow-trusted toolcache path; the only later step is read-only metadata; the env is set in the same step that consumes it | Add fixtures and source anchor for `aws-actions/configure-aws-credentials`, `azure/login`, `google-github-actions/auth`, `azure/k8s-set-context`, `helm/kind-action`. |
| `gha_env_pip_index_redirect_before_setup_python_install` | env-config redirect (PyPI) | queued | corpus signal/source lead | earlier same-job step assigns `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`, `PIP_CONFIG_FILE`, or matching `pip_*` env to a value that is interpolated, matrix-derived, or attacker-influenceable; later step uses `actions/setup-python` with `pip-install`, `python -m pip install`, or `pip install` while ambient PyPI/private-index credential or OIDC authority is present | index URL is a hardcoded public registry; install is dry-run only; no token/OIDC env in scope | Source-anchor fixture against `actions/setup-python` and `pypa/gh-action-pypi-publish`. Pair with `gha_setup_python_pip_install_authority_env`. |
| `gha_env_node_options_code_injection_before_node_authority` | env code injection | queued | source lead | earlier same-job step writes `NODE_OPTIONS` (env, matrix, or `>> $GITHUB_ENV`) where the value contains `--require`, `--import`, `--inspect`, `--experimental-loader`, `--experimental-vm-modules`, or `--experimental-policy`; a later step uses any node-based third-party action OR runs `node`, `npm`, `npx`, `pnpm`, `yarn` under token/registry/OIDC authority | NODE_OPTIONS is only `--max-old-space-size=*` or memory tuning; no token/registry/OIDC env present; no later node invocation | Add ESLint matrix and Vercel Next.js patterns to corpus fixtures; downgrade tuning-only values. |
| `gha_env_pythonpath_or_startup_before_python_authority` | env code injection (Python) | queued | source lead | earlier same-job step writes `PYTHONPATH`, `PYTHONSTARTUP`, `PYTHONUSERBASE`, or `PYTHONHOME` to a workspace path or input-derived path; a later step runs `python`, `python3`, `pip`, `twine`, `maturin`, `ansible*`, or a known python-helper action under token/cloud authority | path is an action-owned absolute toolcache; no later python invocation; no authority env in scope | Source-anchor against `bridgecrewio/checkov`, `actions/setup-python`, `crazy-max/ghaction-import-gpg` (when GPG step shells to a python helper). |
| `gha_env_dyld_or_ld_library_path_before_credential_helper` | env binary injection | queued | source lead | earlier same-job step writes `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, or `DYLD_LIBRARY_PATH` to a workspace, input-derived, or attacker-influenceable path; a later step invokes a credential-bearing helper that dynamically links shared libraries (`aws`, `az`, `gcloud`, `kubectl`, `helm`, `gpg`, `cosign`, compiled `*-cli`, custom build tools) | path is an action-owned absolute toolcache; no later credential-bearing helper; macOS SIP context for DYLD_* downgrades reachability | Add `python_cpython__build.yml` and `moby__.windows.yml` source anchors; document SIP downgrade for macOS DYLD_*. |
| `gha_env_ruby_or_perl_inject_before_authority` | env code injection (Ruby/Perl) | queued | source lead | earlier same-job step writes `RUBYOPT`, `BUNDLE_GEMFILE`, or `PERL5LIB` to a workspace or input-derived path; a later step uses `ruby`, `bundle`, `gem`, `rubygems/release-gem`, `actions/setup-ruby`, `ruby/setup-ruby`, or any Perl helper under publish/release authority | env value points to action-owned toolcache; no later authority context | Pair with `gha_rubygems_release_git_token_and_oidc_helper`. |
| `gha_env_git_config_or_askpass_before_token_git` | env credential helper redirect (Git) | queued | source lead | earlier same-job step writes `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`, `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_*`/`GIT_CONFIG_VALUE_*`, `GIT_ASKPASS`, `SSH_ASKPASS`, `SSH_AUTH_SOCK`, or `GIT_TERMINAL_PROMPT`; a later step performs tokenized `git push`, `git fetch` with PAT, `peter-evans/create-pull-request`, `peaceiris/actions-gh-pages`, `JamesIves/github-pages-deploy-action`, or `webfactory/ssh-agent` operations | absolute config path is action-owned; no token/key authority in scope; tested workflow-only configuration | Pair with `gha_create_pr_git_token_path_handoff` and `gha_pages_deploy_token_url_to_git_helper`. |
| `gha_env_gnupghome_redirect_before_import_gpg` | env-config redirect (GPG) | queued | source lead | earlier same-job step writes `GNUPGHOME` (especially via `>> $GITHUB_ENV`); later step uses `crazy-max/ghaction-import-gpg`, raw `gpg --import`, `gpg-connect-agent`, signing helpers, or sigstore signing under key authority | GNUPGHOME is a freshly mktemp'd dir created in the same step; no separate signing step | Pair with `gha_import_gpg_private_key_helper_path`. Source-anchor SaltStack release shape. |
| `gha_env_kubeconfig_redirect_before_kubectl_or_helm_authority` | env-config redirect (Kubernetes) | queued | source lead | earlier same-job step writes `KUBECONFIG` or `KUBE_CONFIG_PATH` to a workspace, input-derived, or `github.workspace`-rooted path; later step runs `kubectl`, `helm`, `kustomize`, `argocd`, or uses `azure/k8s-set-context`, `azure/k8s-deploy`, `azure/aks-set-context`, `google-github-actions/get-gke-credentials`, `aws-actions/amazon-eks-update-kubeconfig` | path is action-owned and re-written by the auth-bearing action before use | Pair with `gha_kubernetes_helper_kubeconfig_authority` and the Azure k8s candidate family. |

### Family B — Reusable workflow caller→callee trust drift

| Canonical rule id | Family | Status | Evidence level | Match shape | Exclusions/downgrades | Next gate |
|---|---|---|---|---|---|---|
| `gha_workflow_call_container_image_input_secrets_inherit` | callable trust drift | queued | corpus signal/source lead | a workflow with `on: workflow_call` defines an input named `image`/`docker`/`container`/`container_image` AND a job sets `container.image: ${{ inputs.<that> }}` AND the workflow declares `secrets: inherit` (or names credential-bearing secrets as inputs) | image input is a closed enum validated by an `if:` gate before the container job runs; secrets are not inherited; image is digest-pinned at the call site | Source-anchor `huggingface/transformers/self-scheduled.yml`, `huggingface/transformers/check_failed_tests.yml`, and `huggingface/transformers/benchmark_v2.yml`. |
| `gha_workflow_call_runner_label_input_privilege_escalation` | callable runner pool selection | queued | corpus signal | a `workflow_call` workflow uses `runs-on: ${{ inputs.<runner|os|runs-on|runner-vm-os|runner-label> }}` (including `fromJson(inputs.runs_on_labels)`) AND the job has secret/cloud/OIDC authority | runner input is a closed enum gated by an `if:` clause; runner is a hosted-only label and self-hosted is impossible; no authority env in scope | Source-anchor `python_cpython__reusable-ubuntu.yml`, `apache_arrow__cpp_windows.yml`, `vercel_next.js__build_reusable.yml`, `hashicorp_terraform__build-terraform-cli.yml`. |
| `gha_workflow_call_script_input_caller_code_injection` | callable script-input shell injection | queued | corpus signal | a `workflow_call` workflow defines an input whose value is interpolated into a `run:` body (`afterBuild`, `run_before_test`, `command`, `script`, `extra_args`, `cmd`, `shell`) without intermediate file/quoting; combined with `secrets: inherit` or any credential-bearing env in the same job | input is referenced only inside `if:` expressions (no shell context); is restricted to a closed enum; the run body uses heredoc/file-passthrough that escapes interpolation | Source-anchor `vercel/next.js/build_reusable.yml` and `vercel/next.js/integration_tests_reusable.yml`. Compose with existing `script_injection_via_untrusted_context` family. |
| `gha_workflow_call_ref_input_caller_supply_chain` | callable checkout-ref drift | queued | corpus signal/source lead | a `workflow_call` workflow's `actions/checkout` step uses `ref: ${{ inputs.<ref|branch|tag|sha|version> }}` AND the same job has token-bearing or publish/deploy authority | ref input is enforced to be a SHA matched against an allowlist; the checkout is read-only and feeds only artifact build with no credential surface | Pair with `gha_manual_dispatch_ref_to_privileged_checkout`. |
| `gha_workflow_call_chained_caller_untrusted_trigger_to_privileged_callee` | indirect callee escalation | queued | corpus signal | a workflow callee with `secrets: inherit` and any of the four input shapes above is invoked (directly or via one or more reusable hops) from a workflow whose `on:` includes `pull_request_target`, `workflow_run`, `issue_comment`, `pull_request_review`, or `pull_request_review_comment` | call chain is gated by an actor allowlist before the privileged step; the callee's privileged inputs cannot be set from caller-controlled data | Source-anchor `bridgecrewio/checkov/security.yml`, `huggingface/transformers/self-comment-ci.yml`. |

### Family C — Container and service authority confusion

| Canonical rule id | Family | Status | Evidence level | Match shape | Exclusions/downgrades | Next gate |
|---|---|---|---|---|---|---|
| `gha_container_image_attacker_influenced_with_secret_env` | container authority confusion | queued | corpus signal | `container.image` is interpolated from `${{ inputs.* }}`, `${{ matrix.* }}`, or `${{ github.event.* }}` AND the same job exports or inherits credential-bearing secrets (GITHUB_TOKEN with write scope, NPM/PyPI/Cargo publish tokens, cloud creds, `id-token: write`) | image is digest-pinned and the interpolation only chooses between pre-validated digests; secrets are not present in the container; the matrix/inputs values are constant-validated | Source-anchor `huggingface/transformers/*`, `chef/chef/func_spec.yml`, `home-assistant/core/builder.yml`. |
| `gha_container_options_privilege_escalation_with_input_image` | container privileged options | queued | corpus signal | `container.options` contains `--privileged`, `--cap-add`, `-v /var/run/docker.sock`, or `--security-opt seccomp=unconfined` AND `container.image` is not digest-pinned OR is interpolated from input/matrix/event | options string is a constant and image is digest-pinned; runner is fully ephemeral with no credential authority | Source-anchor `huggingface/transformers/benchmark_v2_a10_caller.yml` and `chef/chef/func_spec.yml`. |
| `gha_service_container_image_version_from_matrix_with_helper` | service container authority | queued | corpus signal | `services.<name>.image` tag/version is interpolated from `${{ matrix.* }}` or `${{ inputs.* }}` AND a later step in the same job interacts with the service via a bare `psql`, `mysql`, `mongosh`, `redis-cli`, `cqlsh`, or `curl` invocation while service env contains credential-bearing values | image is digest-pinned; service env contains only constants; no later helper interacts with the service | Source-anchor `django/django/postgis.yml`, `pandas-dev/pandas/unit-tests.yml`, `SeaQL/sea-orm/rust.yml`. |

### Family D — Output and state collision

| Canonical rule id | Family | Status | Evidence level | Match shape | Exclusions/downgrades | Next gate |
|---|---|---|---|---|---|---|
| `gha_step_output_collision_last_write_with_privileged_consumer` | output last-write-wins | queued | corpus signal | two or more steps in the same job write the same `>> $GITHUB_OUTPUT` key (or `core.setOutput` of the same name); a later same-job or `needs:` step uses that output as an argv/with: value to a credential-bearing action (deploy, publish, sign, gh release, kubectl, terraform) | the colliding writes are mutually exclusive via static `if:` guards on stable conditions; only one branch is reachable per run | Source-anchor `huggingface/transformers/pr-repo-consistency-bot.yml`, `microsoft/vscode/no-engineering-system-changes.yml`. |
| `gha_env_collision_cross_conditional_to_privileged_step` | env last-write-wins | queued | corpus signal | multiple same-job steps write the same key to `>> $GITHUB_ENV` under different `if:` branches AND a later step consumes the env to authorize a publish/deploy/sign action | branches are guarded by static, non-event-derived `if:` expressions; no later authority consumer | Pair with workflow-shell concentration. |
| `gha_workflow_run_artifact_field_to_matrix_with_secret` | artifact-derived matrix authority | queued | corpus signal | a `workflow_run` consumer extracts an artifact name, listing field, or content into a job output AND a `needs:` consumer uses that output inside `strategy.matrix` AND the matrix run carries credential-bearing secrets (signing, publish, deploy) | artifact field is a constant or strict allowlist; matrix value does not influence credential selection | Pair with `unsafe_pr_artifact_in_workflow_run_consumer`. Source-anchor `apache_kafka__ci-complete.yml`. |
| `gha_dynamic_matrix_from_pr_job_outputs_with_authority` | dynamic matrix poisoning | queued | corpus signal | `strategy.matrix.include: ${{ fromJson(needs.<job>.outputs.<x>) }}` (or `matrix.<x>: fromJson(...)`) AND the producing job ran on `pull_request`-derived data, comment text, or untrusted artifact AND the matrix consumer has credential-bearing secrets | producer is gated to merged/protected branch only; outputs schema is validated in producer; no authority context in matrix consumer | Source-anchor `huggingface_transformers__doctests.yml`, `moby_moby__test.yml`, `langchain-ai_langchain__check_diffs.yml`. |

### Family E — Runner pool selection from interpolation

| Canonical rule id | Family | Status | Evidence level | Match shape | Exclusions/downgrades | Next gate |
|---|---|---|---|---|---|---|
| `gha_runs_on_interpolated_from_inputs_or_event_with_authority` | runner pool selection | queued | corpus signal | a job's `runs-on:` is interpolated from `${{ inputs.* }}`, `${{ github.event.inputs.* }}`, or `${{ needs.<job>.outputs.* }}` (NOT just `${{ matrix.os }}` against a static matrix) AND the job has credential-bearing secrets, OIDC `id-token: write`, or PAT-based checkout | runner expression resolves to an enumerated set of hosted labels; no self-hosted label is reachable; no authority context | Source-anchor `vercel/next.js/build_reusable.yml`, `python/cpython/reusable-macos.yml`, and any `runs-on: [self-hosted, ${{ ... }}]` shape. |

## Severity guidance

| Family | Default | Promote to High when | Demote to Advisory when |
|---|---|---|---|
| Family A — env-config redirect | High | env-redirect path is a workspace or input-derived path AND later step is a known credential-materializing action | env value is an action-owned absolute toolcache or a freshly-created mktemp dir within the same step |
| Family B — callee trust drift | High | callee `secrets: inherit` AND caller chain reaches `pull_request_target`/`workflow_run`/`issue_comment` | caller is gated by `actor`/`branch`/`environment` approval before the privileged step |
| Family C — container/service | High | image not digest-pinned AND options grant privileged authority AND secrets present | image digest-pinned and no privileged options |
| Family D — output/state collision | Medium | downstream consumer is publish/deploy/sign with token authority | collisions are statically mutually exclusive by stable `if:` |
| Family E — runs-on | Medium | self-hosted label is reachable | only hosted labels are reachable |

## Engineering anchor pointers

These should map cleanly into the existing rule machinery:

- Helper for env-key extraction: extend `propagation::collect_step_env_writes` (or similar) to enumerate `env:` keys, matrix-driven keys, and `>> $GITHUB_ENV` writes per step. Family A and the env-injection rules need a stable per-job env timeline.
- Reusable callee detection: `taudit-parse-gha` already parses `on.workflow_call.inputs`. Family B needs a per-input join with downstream usage in `container.image`, `runs-on`, `run:` body, and `actions/checkout.with.ref`.
- Container/service authority: model `container:` and `services:` as graph nodes with image, options, and env edges, then join with same-job sensitive-authority predicates already used by `gha_helper_path_sensitive_env`.
- Output collision: enrich `propagation::step_outputs` with multi-write detection and add a same-name collision predicate that intersects with downstream `with:`/`run:` consumption.
- Runner pool: `gha_runs_on_interpolated_*` only needs interpolation-source classification on the existing `runs-on` token, plus the existing same-job authority predicate.

## Customer-safety wording

For all rules in this intake, default findings should phrase the issue as a hardening recommendation, not a vulnerability claim. Promote to disclosure-grade only when an Algol witness artifact (canary-only) is attached.

## Disclosure pairing notes

Family A, when triggered against `aws-actions/configure-aws-credentials`, `azure/login`, `google-github-actions/auth`, or `azure/k8s-set-context`, is the strongest source-review path that can revive currently-deferred or negative-lead candidates. Treat as `route-research-needed` until a runner-faithful witness is staged in `MEMORY/WORK/`.
