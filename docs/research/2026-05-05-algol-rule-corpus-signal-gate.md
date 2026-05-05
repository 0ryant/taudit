# Algol rule corpus signal gate

Observed: 2026-05-05.

This gate trains new authority-confusion classifiers against local corpus
signal before release. The goal is to catch parser bugs, duplicate findings,
and broad noisy predicates before the rules reach downstream users.

## Commands

Fast writable smoke used by the supervisor:

```bash
python3 scripts/research/analyze_workflow_corpus.py --root corpus/workflow-yaml-testbed --binary target/debug/taudit --platform gha --limit-per-platform 500 --jobs 8 --timeout 10
```

Focused build and rule checks:

```bash
cargo test -p taudit-core gha_action_boundary --locked
cargo test -p taudit-core gha_tool_installer_then_shell_dedupes --locked
cargo test -p taudit-core workflow_shell_authority_concentration --locked
python3 scripts/generate-authority-invariant-schema.py --check
```

Full release verification:

```bash
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

Full GHA corpus with known invalid-YAML quarantine:

```bash
python3 scripts/research/analyze_workflow_corpus.py --root corpus/workflow-yaml-testbed --binary target/debug/taudit --platform gha --jobs 8 --timeout 10 --allow-failure-substring meteor_meteor__.github_workflows_test-packages.yml__82ea66dda516.yml
```

## 500-file GHA smoke result

Result: 500 scanned, 500 ok, 0 failed.

Counts after this tranche:

| Rule id | Count | Signal note |
|---|---:|---|
| `gha_workflow_shell_authority_concentration` | 17 | Expected broad workflow-shell sink classifier. Bucket by sink before judging noise. |
| `gha_setup_node_cache_helper_path_handoff` | 3 | Low volume, but examples include generic PATH additions such as Poetry install. Keep watching for over-broad cache handoff noise. |
| `gha_tool_installer_then_shell_helper_authority` | 2 | Dedupe reduced duplicate cosign installer findings from 3 to 2 in the sample. |
| `gha_setup_go_cache_helper_path_handoff` | 0 | Quiet in sample because explicit setup-go cache plus prior `GITHUB_PATH` timing is required. Full corpus currently has one hit. |
| `gha_create_pr_git_token_path_handoff` | 0 | Quiet in sample because prior `GITHUB_PATH` timing edge is required. |
| `gha_import_gpg_private_key_helper_path` | 0 | Quiet in sample because prior `GITHUB_PATH` timing edge is required. |
| `gha_ssh_agent_private_key_to_path_helper` | 0 | Quiet in sample because prior `GITHUB_PATH` timing edge is required. |
| `gha_macos_codesign_cert_security_path` | 0 | Quiet in sample because prior `GITHUB_PATH` timing edge is required. |
| `gha_pages_deploy_token_url_to_git_helper` | 0 | Quiet in sample because prior `GITHUB_PATH` timing edge is required. |

## Full-corpus read-only signal

Lane C read-only scan observed these local corpus roots:

- `corpus/workflow-yaml-testbed/gha`: 5000 YAML
- `corpus/workflow-yaml-testbed/ado`: 5000 YAML
- `corpus/workflow-yaml-testbed/gl`: 5000 YAML
- `corpus/workflow-yaml-testbed/bb`: 2692 YAML
- `corpus/gha`: 1471 YAML
- fixtures and committed workflow corpus under `tests/`, fuzz corpora, and `.github/workflows`

After integrating the action-boundary rules, a read-only pass over
`corpus/workflow-yaml-testbed/gha` plus `corpus/gha` scanned 6,471 files with
one invalid YAML parse blocker. A writable full-harness GHA pass scanned
`corpus/workflow-yaml-testbed/gha` and reported 4,999 ok / 1 failed without
quarantine, then 4,999 ok / 0 failed / 1 allowed-failed with the known invalid
file allowlisted. Relevant counts from the writable harness are finding counts;
the harness does not currently persist per-rule file counts:

| Rule id | Count | Files | Signal note |
|---|---:|---:|---|
| `gha_workflow_shell_authority_concentration` | 265 | n/a | Broad by design; bucket by sink. |
| `gha_setup_node_cache_helper_path_handoff` | 28 | n/a | Watch generic PATH additions before setup-node cache. |
| `gha_tool_installer_then_shell_helper_authority` | 12 | n/a | Mostly signing/deploy helper use; dedupe guard removes duplicated installers per shell sink. |
| `gha_setup_python_pip_install_authority_env` | 5 | n/a | Needs confidence downgrade when only implicit token authority is present. |
| `later_secret_materialized_after_path_mutation` | 4 | n/a | Low volume umbrella timing edge. |
| `gha_helper_untrusted_path_resolution` | 4 | n/a | Low volume helper-path source leads. |
| `gha_helper_path_sensitive_stdin` | 3 | n/a | Low volume, higher-signal transport-specific helper rule. |
| `gha_post_ambient_env_cleanup_path` | 2 | n/a | Low volume; keep source-version validation. |
| `gha_helper_path_sensitive_env` | 2 | n/a | Low volume, higher-signal transport-specific helper rule. |
| `gha_helper_path_sensitive_argv` | 1 | n/a | Low volume, higher-signal transport-specific helper rule. |
| `gha_setup_go_cache_helper_path_handoff` | 1 | n/a | Single full-corpus hit: Ollama release setup-go cache after PATH mutation. |
| New action-boundary rules from this tranche | 0 | 0 | Quiet because they require the prior same-job `GITHUB_PATH` timing edge. |

The full GHA read-only pass found one invalid YAML parse blocker:

- `corpus/workflow-yaml-testbed/gha/meteor_meteor__.github_workflows_test-packages.yml__82ea66dda516.yml`

The file contains duplicate top-level `jobs:` keys, so the blocker is corpus
validity, not a new-rule crash. Until that file is quarantined or allowlisted,
full local GHA corpus should be treated as a signal scan rather than a strict
green release gate.

## Release gate

RC gate:

- 500-file GHA smoke remains 500/500.
- New action-boundary rules do not create unexplained count spikes.
- Workflow-shell findings are reviewed by sink bucket, not raw count alone.
- Schema, docs, `taudit explain`, JSON, SARIF, and CloudEvents agree on rule IDs.

Stable gate:

- Full GHA corpus passes with zero unexpected failures; known invalid YAML must
  be explicit via `--allow-failure-substring` or a future checked-in quarantine.
- `cargo test -p taudit-cli --test corpus_cli_suite` passes in default mode.
- New helper/cache rules have reviewed examples for every nonzero corpus bucket.

## Noise controls

- Do not fire action-boundary helper rules on action reference alone.
- Require earlier same-job `GITHUB_PATH` mutation for helper-path action
  boundary rules.
- Keep workflow-shell rules labeled as workflow hardening unless source or
  witness evidence proves an action-owned helper boundary.
- Keep disclosure, CVE, witness, and red-team routing behind an internal feature
  gate.
