# Algol rule-intake — Manifest Authority Confusion (MAC)

Observed: 2026-05-06.
Authored as part of the Algol Manifest Authority Confusion research lane.

Sources:

- `/Users/rytilcock/prj/algol/docs/research/manifest-authority-confusion-class-2026-05-06.md` (class definition + sub-classes + lead-candidate seeds)
- Companion: `/Users/rytilcock/prj/algol/docs/research/trust-channel-authority-class-2026-05-05.md`
- Companion: `/Users/rytilcock/prj/algol/docs/research/authority-confusion-novel-subclasses-2026-05-05.md`
- Earlier intakes: `docs/research/2026-05-05-algol-rule-intake-env-redirect-and-callee-input.md`, `docs/research/2026-05-06-trust-channel-authority-rule-intake.md`
- Current taudit rule index: `docs/rules/index.md`
- Corpus mining over `corpus/gha` (~17,000 GHA workflows) and `corpus/workflow-yaml-testbed`.

These are classifier and prioritization rules. Customer-safe by default. Disclosure-grade promotion requires runtime witness that the manifest-defined hook actually executes under the credential the rule claims is in scope.

## Class definition

Manifest Authority Confusion (MAC) is the third orthogonal class:

- **AC** — execution boundary fails: wrong code with right authority.
- **TCA** — output boundary fails: right code, right authority, wrong payload-or-destination.
- **MAC** — manifest-as-code boundary fails: a file reviewers treat as data is code the build tool executes; when the file is PR-mutable, CI authority transparently flows into PR-author code.

This frame catches an attack class that has been deployed in the wild for years (`postinstall` hook attacks, malicious `build.rs`, poisoned `Dockerfile RUN`, `.gitmodules` URL injection) but has not been catalogued under a single boundary.

Eight sub-classes:

- **MAC-1** — npm-family lifecycle hooks (npm, pnpm, yarn).
- **MAC-2** — Python build-backend / setup.py / pytest conftest.py.
- **MAC-3** — Cargo `build.rs` and proc-macro / `[build-dependencies]`.
- **MAC-4** — JVM / Ruby / PHP / .NET plugin loaders.
- **MAC-5** — Dockerfile / Makefile / repo-shipped shell-script invocation.
- **MAC-6** — Submodule / LFS / `.gitattributes` filter drivers.
- **MAC-7** — Local composite actions / pre-commit / husky / mise / asdf / direnv.
- **MAC-8** — Cross-repo authority cascade via floating callable-workflow / action ref.

## Foundational primitive

Every major package manager runs lifecycle hooks defined in the project manifest as a documented, default-on feature. None of these tools require a maintainer-vetted manifest. They trust whatever is at the path they were pointed at. The CI workflow points them at the repo's working tree. When the working tree is the PR head, the manifest is PR-author content.

Empirically, in the corpus:

- 409 npm-family install invocations; only 9 (~2.2%) use `--ignore-scripts`. **97.8% unsafe.**
- 162 `pip install` invocations; multiple PR-trigger workflows reach `pip install -e .` against PR head with PyPI publish authority.
- 84 cargo build/test/run/doc invocations on PR triggers; `build.rs` runs on every one.
- 258 `make` invocations; 7 reach `pull_request_target`.
- 32 `submodules: recursive` invocations; 10+ pair with secret env.
- 56 cross-repo callable-workflow refs at `@main`/`@master`/floating major; 9 of those declare `secrets: inherit`.

## Proposed classifier rules

### MAC-1 — npm-family lifecycle hooks

| Canonical rule id | Family | Status | Evidence level | Match shape | Exclusions/downgrades | Next gate |
|---|---|---|---|---|---|---|
| `gha_manifest_npm_lifecycle_hook_pr_trigger_with_token` | manifest-as-code | queued | corpus signal/source lead | workflow `on:` includes `pull_request`/`pull_request_target` AND a step runs `npm install`/`npm ci`/`pnpm install`/`yarn install`/`yarn` (without `--ignore-scripts`) AND the same job has `${{ secrets.* }}` references, default `GITHUB_TOKEN` with write scope, `id-token: write`, or registry/cloud credentials | `--ignore-scripts` is set; `permissions:` strips token to read-only AND no other secrets in scope; `actions/checkout` does not check out PR head | Source-anchor `microsoft/TypeScript/ci.yml`, `vercel/next.js/build_and_test.yml`, `facebook/react/runtime_build_and_test.yml`. |
| `gha_manifest_npm_setup_node_cache_restore_before_install` | manifest-as-code | queued | corpus signal | `actions/setup-node` with `cache: 'npm'\|'pnpm'\|'yarn'` in a PR-triggered job, followed by an install step. Prior PR job's cache may have written the `node_modules`/cache entry that the install trusts | cache scope is unique-per-run via key including `github.run_id`; restore-keys do not fall back to PR-shape | Pair with TCA-4 cache-poison rules; add fixture for `vercel/next.js/build_and_test.yml`. |
| `gha_manifest_npm_workflow_run_artifact_node_modules_extract` | manifest-as-code | queued | corpus signal | `workflow_run` consumer downloads an artifact whose name pattern includes `node_modules`, `tarball`, or generic `dist-*`, then `tar -xf`/`unzip`/extracts AND a later step runs `npm`/`pnpm`/`yarn` against the extracted tree | consumer applies cryptographic verification of artifact provenance before extraction; consumer has no token authority | Source-anchor `vercel/next.js/upload_preview_tarballs.yml`, `vuejs/core/size-report.yml`. |
| `gha_manifest_npm_run_pr_script_with_authority` | manifest-as-code | queued | corpus signal | step runs `npm run <X>`/`pnpm <X>`/`yarn <X>` against the PR-head working tree AND the script body lives in PR-mutable `package.json scripts.<X>` AND credential-bearing env in scope | script invocation is gated by `if:` excluding PR triggers; script body is in a CODEOWNERS-protected file | Pair with `script_injection_via_untrusted_context`. |
| `gha_manifest_npm_publish_prepublishonly_hook` | manifest-as-code | queued | source lead | `npm publish`/`pnpm publish` after a checkout that includes PR-author bytes (PR head, merged HEAD, or release tag pushed by automation that consumes PR content); `prepublishOnly`/`prepack` runs before push | publish flow runs `--ignore-scripts` AND the registry token is short-lived | Source-anchor `bridgecrewio/checkov/pr-test.yml` (`npm install -g danger`). |

### MAC-2 — Python build-backend / setup.py / conftest.py

| Canonical rule id | Family | Status | Evidence level | Match shape | Exclusions/downgrades | Next gate |
|---|---|---|---|---|---|---|
| `gha_manifest_pip_install_editable_with_pr_trigger` | manifest-as-code | queued | corpus signal | `pip install -e .` or `pip install .[<extras>]` in a workflow whose triggers include `pull_request`/`pull_request_target` AND credential-bearing env in scope | install runs in a sandboxed job with no secrets and no `id-token: write`; install uses `--no-build-isolation` against a vetted requirements file | Source-anchor `langchain-ai/langchain/_release.yml`, `huggingface/transformers/release.yml`. |
| `gha_manifest_python_m_build_with_pr_credentials` | manifest-as-code | queued | corpus signal | `python -m build` or `python setup.py *` in a workflow reachable from PR triggers AND `pypa/gh-action-pypi-publish`/`twine upload`/`maturin publish` runs in the same workflow file or via an artifact handoff | build runs only on protected refs gated by `github.event_name == 'release' && startsWith(github.ref, 'refs/tags/')` | Source-anchor `pandas-dev/pandas/wheels.yml`, `astropy/astropy/ci_workflows.yml`, `scikit-learn/scikit-learn/publish_pypi.yml`. |
| `gha_manifest_pytest_conftest_with_pr_target_secret` | manifest-as-code | queued | corpus signal | workflow `on:` includes `pull_request_target` AND a step runs `pytest`/`python -m pytest`/`tox`/`nox` against PR head AND credentials in scope | `conftest.py` lives in a CODEOWNERS-protected directory AND is excluded from PR-mutable paths | Source-anchor `pytest-dev/pytest/test.yml`, `apache/kafka/build.yml`. |
| `gha_manifest_tox_or_nox_with_pr_and_credentials` | manifest-as-code | queued | corpus signal | `tox`/`nox` invoked in a PR-trigger workflow AND `tox.ini`/`noxfile.py` is PR-mutable AND credentials in scope | the tox/nox config is CODEOWNERS-protected | Source-anchor `pandas-dev/pandas/code-checks.yml`. |

### MAC-3 — Cargo build.rs + proc-macros

| Canonical rule id | Family | Status | Evidence level | Match shape | Exclusions/downgrades | Next gate |
|---|---|---|---|---|---|---|
| `gha_manifest_cargo_build_rs_pull_request_with_token` | manifest-as-code | queued | corpus signal | workflow `on:` includes `pull_request`/`pull_request_target` AND a step runs `cargo build`/`cargo test`/`cargo run`/`cargo doc`/`cargo install --path .` AND `${{ secrets.* }}` or `id-token: write` is in scope (note: `build.rs` and proc-macros run on all of these) | repo has no `build.rs` or `[build-dependencies]` AND no proc-macro deps AND `Cargo.toml` is in a CODEOWNERS-protected file | Source-anchor `rust-lang/rust/ci.yml`, `starship/starship/workflow.yml`, `zizmorcore/zizmor/ci.yml`. |
| `gha_manifest_cargo_publish_with_pr_or_unrooted_checkout` | manifest-as-code | queued | corpus signal | `cargo publish` AND the checkout is at PR head, at a tag created by automation that consumes PR content, OR includes submodules:recursive AND `CARGO_REGISTRY_TOKEN` in scope | publish runs in a job that re-checks out a CODEOWNERS-verified ref AND validates `Cargo.toml` against a snapshot | Source-anchor `denoland/deno/cargo_publish.generated.yml`. |
| `gha_manifest_cargo_install_path_with_credentials` | manifest-as-code | queued | source lead | `cargo install --path <pr-relative>` in a token-bearing job; the install runs `build.rs` of the local package | install path is hardcoded to a CODEOWNERS-protected subdirectory | Add corpus fixture. |

### MAC-4 — JVM / Ruby / PHP / .NET plugin loaders

| Canonical rule id | Family | Status | Evidence level | Match shape | Exclusions/downgrades | Next gate |
|---|---|---|---|---|---|---|
| `gha_manifest_gradle_or_maven_plugin_with_pr_credentials` | manifest-as-code | queued | corpus signal | `gradle`/`./gradlew`/`mvn` invocation in a PR-trigger workflow AND `pom.xml`/`build.gradle*` is PR-mutable AND deploy/registry/Develocity credentials in scope | gradle daemon runs `--no-daemon --refresh-dependencies` against a wrapper SHA pinned in CODEOWNERS-protected files | Source-anchor `apache/kafka/ci-complete.yml`. |
| `gha_manifest_ruby_gemfile_rakefile_pr_with_secret` | manifest-as-code | queued | corpus signal | `bundle install`/`bundle exec`/`rake` in a PR-trigger workflow AND `Gemfile`/`Rakefile` PR-mutable AND credential-bearing env | `Gemfile`/`Rakefile` is in CODEOWNERS-protected directory AND `bundle exec` runs only vetted tasks | Source-anchor `chef/chef/gem_tests.yml`. |
| `gha_manifest_dotnet_msbuild_targets_with_pr_credentials` | manifest-as-code | queued | source lead | `dotnet build`/`dotnet pack`/`dotnet publish` in a PR-trigger workflow AND `*.csproj`/`Directory.Build.*`/`*.targets` PR-mutable AND credential-bearing env | builds use `--no-restore` and a CODEOWNERS-protected SDK manifest | Add corpus fixture. |
| `gha_manifest_composer_install_with_pr_credentials` | manifest-as-code | queued | source lead | `composer install`/`composer update` in a PR-trigger workflow AND `composer.json` PR-mutable AND credential-bearing env (composer-bin tokens, packagist) | composer runs `--no-scripts` AND lockfile is CODEOWNERS-protected | Add corpus fixture. |
| `gha_manifest_go_generate_with_pr_credentials` | manifest-as-code | queued | corpus signal | `go generate`/`go run` in a PR-trigger workflow AND `tools.go`/`//go:generate` directives in PR-mutable Go files AND credential-bearing env | go-generate is restricted to a hardcoded list of trusted binaries via `-run=<regex>` | Add corpus fixture. |

### MAC-5 — Dockerfile / Makefile / shell-script

| Canonical rule id | Family | Status | Evidence level | Match shape | Exclusions/downgrades | Next gate |
|---|---|---|---|---|---|---|
| `gha_manifest_dockerfile_run_with_pr_trigger_and_credentials` | manifest-as-code | queued | corpus signal | `docker build`/`docker buildx build`/`docker compose build` in a PR-trigger workflow AND `Dockerfile`/`docker-compose.yml` PR-mutable AND credential-bearing env (registry, cloud, OIDC) | `docker build` is gated to non-PR triggers; Dockerfile is in CODEOWNERS-protected directory | Add corpus fixture; pair with TCA-1 attestation rules where applicable. |
| `gha_manifest_makefile_with_pr_trigger_and_secrets` | manifest-as-code | queued | corpus signal | `make`/`make <target>`/`gmake`/`bmake` invocation in a PR-trigger workflow AND `Makefile` PR-mutable AND credential-bearing env | Makefile is in CODEOWNERS-protected directory; the target is hardcoded and uses `make --warn-undefined-variables -B` against a frozen target list | Source-anchor `nodejs/node/linters.yml`, `prometheus/prometheus/ci.yml`, `denoland/deno/ci.generated.yml`. |
| `gha_manifest_repo_shipped_shell_script_invocation_with_credentials` | manifest-as-code | queued | corpus signal | `run:` body invokes `bash <repo-relative>`/`sh <repo-relative>`/`./scripts/<x>`/`./bin/<x>`/`./ci/<x>` AND the script lives in the repo's working tree (PR-mutable) AND credential-bearing env in scope | script directory is in CODEOWNERS-protected directory | Add corpus fixture. |
| `gha_manifest_docker_compose_pr_image_or_command` | manifest-as-code | queued | source lead | `docker compose up`/`docker compose run`/`docker compose build` AND `docker-compose.yml` PR-mutable AND credentials in scope | compose file is CODEOWNERS-protected | Add corpus fixture. |

### MAC-6 — Submodule / LFS / .gitattributes

| Canonical rule id | Family | Status | Evidence level | Match shape | Exclusions/downgrades | Next gate |
|---|---|---|---|---|---|---|
| `gha_manifest_submodules_recursive_with_pr_authority` | manifest-as-code | queued | corpus signal | `actions/checkout` with `submodules: recursive` or `submodules: true` AND `.gitmodules` is PR-mutable AND credential-bearing env in scope | `.gitmodules` is CODEOWNERS-protected; submodule URLs are explicitly allowlisted by absolute SHA | Source-anchor `rust-lang/rust/dependencies.yml`, `denoland/deno/cargo_publish.generated.yml`, `apache/arrow/python.yml`, `apache/arrow/r.yml`. |
| `gha_manifest_lfs_endpoint_pr_mutable` | manifest-as-code | queued | source lead | `actions/checkout` with `lfs: true` AND `.lfsconfig` PR-mutable AND credential-bearing env in scope | `.lfsconfig` is CODEOWNERS-protected | Add corpus fixture. |
| `gha_manifest_gitattributes_filter_driver_under_credential` | manifest-as-code | queued | source lead | workflow runs `git checkout`/clone with `core.attributesFile` configured AND `.gitattributes` PR-mutable AND filter/clean/smudge drivers defined AND credential-bearing env in scope | `git config --global filter.<x>.process false` is set globally on the runner; `.gitattributes` is CODEOWNERS-protected | Add corpus fixture. |

### MAC-7 — Local composite / pre-commit / mise

| Canonical rule id | Family | Status | Evidence level | Match shape | Exclusions/downgrades | Next gate |
|---|---|---|---|---|---|---|
| `gha_manifest_local_composite_action_pr_mutable_with_credentials` | manifest-as-code | queued | source lead | `uses: ./.github/actions/<name>` (or any `./` path) AND the local action's `action.yml` is in PR-mutable directory AND credential-bearing env in scope | local action directory is CODEOWNERS-protected | Add corpus fixture. |
| `gha_manifest_pre_commit_install_run_with_credentials` | manifest-as-code | queued | corpus signal | `pre-commit install` or `pre-commit run` in a PR-trigger workflow AND `.pre-commit-config.yaml` is PR-mutable AND credential-bearing env in scope | `.pre-commit-config.yaml` is CODEOWNERS-protected; pre-commit hook repos are SHA-pinned | Pair with `gha_manifest_npm_lifecycle_hook_pr_trigger_with_token` since pre-commit can install JS hooks. |
| `gha_manifest_mise_or_asdf_or_direnv_with_credentials` | manifest-as-code | queued | source lead | step runs `mise install`/`asdf install`/`direnv allow` in a PR-trigger workflow AND `.tool-versions`/`mise.toml`/`.envrc` is PR-mutable AND credential-bearing env in scope | tool-version files are CODEOWNERS-protected | Add corpus fixture. |

### MAC-8 — Cross-repo authority cascade

| Canonical rule id | Family | Status | Evidence level | Match shape | Exclusions/downgrades | Next gate |
|---|---|---|---|---|---|---|
| `gha_crossrepo_workflow_call_floating_ref_cascade` | manifest-as-code | queued | corpus signal | `uses: <org>/<repo>/.github/workflows/<X>.yml@<ref>` where `<ref>` is `main`/`master`/`HEAD` or floating major (`v1`, `v2`, `v3`, `v4`, `v5`) AND the producing repo is not the same as the consuming repo | ref is a SHA (40 hex characters) | Source-anchor `actions/setup-node/check-dist.yml` consuming `actions/reusable-workflows/.github/workflows/check-dist.yml@main`, `langchain-ai/langchain/_refresh_model_profiles.yml@master`, `eslint/eslint/stale.yml` consuming `eslint/workflows/.../stale.yml@main`. |
| `gha_crossrepo_secrets_inherit_unreviewed_callee` | manifest-as-code | queued | corpus signal | `uses: <org>/<repo>/.github/workflows/<X>.yml@<ref>` AND `secrets: inherit` AND callee is in a different repo from caller | callee ref is a SHA pin AND callee repo's `main` has CODEOWNERS-protected branch protection | Source-anchor `bridgecrewio/checkov/build.yml` cascading 7+ secrets to `bridgecrewio/gha-reusable-workflows@main`, `chef/chef/ci-main-pull-request-stub.yml` cascading to `chef/common-github-actions@main`. |
| `gha_crossrepo_action_floating_ref_with_credentials` | manifest-as-code | queued | corpus signal | `uses: <org>/<repo>@<floating-ref>` (composite or JS action) where ref is `main`/`master`/floating major AND credential-bearing env in scope in the same job | ref is a SHA pin | Build off existing `unpinned_action`; specifically classify cross-repo refs. |
| `gha_crossrepo_org_credential_multiplexing` | manifest-as-code | queued | corpus signal | multiple workflow files in the same repo (or known multiple repos in the same org) reference `<same-org>/<shared-repo>/.github/workflows/<X>.yml@<floating-ref>` with `secrets: inherit` | the shared repo's branch protection is at least as strong as the caller's, AND CODEOWNERS gating exists on the producer | Source-anchor org clusters: chef (8+ stubs → `chef/common-github-actions`), huggingface (10+ → `huggingface/hf-workflows`), grafana (5+ → `grafana/shared-workflows` and `grafana/grafana-github-actions`), cloudposse (4+ → `cloudposse/.github`), anchore (5+ → `anchore/workflows`). |
| `gha_crossrepo_callable_workflow_consumed_by_pr_trigger_chain` | manifest-as-code | queued | corpus signal | `<org>/<shared-repo>/.github/workflows/<X>.yml@<ref>` is consumed (directly or via chain) by a workflow whose triggers include `pull_request`/`pull_request_target`/`workflow_run`/`issue_comment` | the chain is gated by required-approval environment with CODEOWNERS reviewers before the privileged callee runs | Pair with TCA-5 chain-reachability rules. |

## Severity guidance

| Sub-class | Default | Promote to High when | Demote to Advisory when |
|---|---|---|---|
| MAC-1 npm-family | High | install runs without `--ignore-scripts` AND workflow is reachable from PR-controlled triggers AND credential authority present | `--ignore-scripts` is set, OR the install is gated to non-PR triggers |
| MAC-2 Python | High | `pip install -e .` or `python -m build` against PR head AND publish/cloud authority | install runs on protected refs only AND `--no-build-isolation` is paired with CODEOWNERS-vetted requirements |
| MAC-3 Cargo | High | `cargo build`/`cargo publish` against PR head with publish or cloud authority | repo has no `build.rs`, no proc-macro deps, and Cargo.toml is CODEOWNERS-protected |
| MAC-4 JVM/Ruby/PHP/.NET | High | build tool runs against PR head with deploy/registry authority | plugin set is vetted in a protected file; deploy gated to protected ref |
| MAC-5 Docker/Makefile/Shell | High | `docker build`/`make`/repo-shipped script runs against PR head with credential authority | manifest is CODEOWNERS-protected and `if:` excludes PR triggers |
| MAC-6 Submodule/LFS/.gitattributes | High | `submodules: recursive` AND `.gitmodules` PR-editable AND credential authority | `.gitmodules` is CODEOWNERS-protected OR `submodules: false` |
| MAC-7 Local composite/pre-commit | Medium-High | local action under `.github/actions/<name>` is PR-editable AND consumed in token-bearing workflow | local action path is CODEOWNERS-protected |
| MAC-8 Cross-repo cascade | High | producer repo's branch protection is weaker than the consumer's, OR `secrets: inherit` flows across repo boundary at floating ref | producer ref is a SHA pin AND producer's branch protection ≥ consumer's |

## Engineering anchor pointers

- **MAC-1/2/3/4** — extend `propagation::collect_step_writes` with a "package-manager invocation" predicate. New flag predicate: `safe_install_scripts_disabled`. Combine with existing PR-trigger predicate and same-job authority predicate.
- **MAC-5** — add a `Dockerfile`/`Makefile`/`scripts/*.sh` invocation predicate. The shape is "step runs `make X` / `bash scripts/X.sh` / `docker build` against the checkout of PR head."
- **MAC-6** — `actions/checkout` with `submodules: recursive|true` predicate. Add an authority co-occurrence rule.
- **MAC-7** — `uses: ./<path>` with PR-mutable path AND token authority. CODEOWNERS lookup is out of scope for taudit; rules can downgrade based on a workflow-author-supplied marker comment.
- **MAC-8** — extend `unpinned_action` to specifically classify cross-repo callable-workflow refs (`org/repo/.github/workflows/X.yml@<ref>`) where ref is not a SHA. Also add a per-org "credential multiplexing" predicate by counting how many distinct repos in the same org reference the same shared callable.

## Customer-safety wording

For all rules in this intake, default findings phrase the issue as a hardening recommendation. Promote to disclosure-grade only when an Algol witness artifact is attached.

## Disclosure pairing notes

- **MAC-1 platform-level finding** — adoption of `--ignore-scripts` is 2.2% in the corpus. A docs/defaults filing to GitHub against `actions/setup-node` (default `--ignore-scripts` for PR triggers, or expose an `ignore-scripts` input) is a high-leverage hardening. Route: GitHub private security advisory.
- **MAC-3 Cargo `build.rs` + publish** — `denoland/deno/cargo_publish.generated.yml`-like flows are reachable in the corpus. Filing route: rust-lang security or per-project route.
- **MAC-6 `rust-lang/rust/dependencies.yml`** — `submodules: recursive` + `GITHUB_TOKEN`. Filing route: Rust Foundation security.
- **MAC-8 `actions/setup-node` consuming `actions/reusable-workflows@main`** — first-party GitHub action consumes a cross-repo callable workflow at `@main`. Class-level supply-chain finding. Route: GitHub private security advisory.
- **MAC-8 org-level credential multiplexing** — organizations multiplexing many repos onto one shared callable at floating ref (chef, huggingface, grafana, cloudposse, anchore). Filing route: per-org security route. The `bridgecrewio/checkov` shape (cascading 7+ secrets to a `@main` ref of a separate repo) is the cleanest disclosure candidate.
