#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE="${1:-quality-gate}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "quality-gate: missing required tool '$1'"
    echo "quality-gate: install '$1' and re-run"
    exit 1
  fi
}

run_rust_fast_gate() {
  echo "quality-gate: cargo fmt"
  cargo fmt --all -- --check

  echo "quality-gate: cargo clippy"
  cargo clippy --workspace --all-targets -- -D warnings
}

run_rust_full_gate() {
  run_rust_fast_gate

  echo "quality-gate: cargo test"
  cargo test --workspace

  echo "quality-gate: cargo deny"
  cargo deny check licenses bans sources

  echo "quality-gate: cargo audit"
  cargo audit
}

# Resolve the built debug binary. CARGO_TARGET_DIR or .cargo/config.toml can move
# it out of ./target (this workspace shares ~/.cargo/shared-target) and Windows
# adds .exe, so ask cargo instead of assuming ./target/debug/taudit.
taudit_debug_bin() {
  local dir
  dir="$(cargo metadata --format-version 1 --no-deps 2>/dev/null |
         sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')"
  [ -n "$dir" ] || dir="target"
  local candidate
  for candidate in "$dir/debug/taudit" "$dir/debug/taudit.exe"; do
    if [ -x "$candidate" ]; then printf '%s' "$candidate"; return 0; fi
  done
  return 1
}

run_golden_paths() {
  echo "quality-gate: golden-paths smoke (docs/golden-paths.md)"
  local bin
  bin="$(taudit_debug_bin)" || {
    echo "quality-gate: no debug taudit binary — run 'cargo build -p taudit' first"
    return 1
  }
  TAUDIT_BIN="$bin" bash scripts/golden-paths.sh
}

run_taudit_gate() {
  if command -v taudit >/dev/null 2>&1; then
    TAUDIT=(taudit)
  else
    TAUDIT=(cargo run -q -p taudit --)
  fi

  echo "quality-gate: taudit scan"
  "${TAUDIT[@]}" scan .github/workflows/ \
    --platform github-actions \
    --severity-threshold high \
    --quiet

  if [ -d invariants/starter ] && ls invariants/starter/*.yml >/dev/null 2>&1; then
    echo "quality-gate: taudit verify starter invariants"
    # Advisory until the starter bundle is tuned for self-application.
    # Matches the CI `|| echo "::warning::..."` policy in quality.yml.
    "${TAUDIT[@]}" verify \
      --policy invariants/starter/ \
      --platform github-actions \
      .github/workflows/ \
      || echo "quality-gate: taudit verify found violations (advisory)"
  fi
}

run_gitleaks_precommit() {
  echo "quality-gate: gitleaks (staged)"
  gitleaks protect --staged --redact --verbose
}

run_gitleaks_repo() {
  echo "quality-gate: gitleaks (repo)"
  gitleaks detect --source . --redact --verbose
}

run_trivy_config() {
  echo "quality-gate: trivy config"
  trivy config \
    --severity HIGH,CRITICAL \
    --skip-dirs MEMORY,.claude,corpus \
    --exit-code 1 \
    .
}

run_trivy_fs() {
  echo "quality-gate: trivy fs"
  trivy fs \
    --scanners vuln,misconfig,secret \
    --severity HIGH,CRITICAL \
    --skip-dirs MEMORY,.claude,corpus \
    --exit-code 1 \
    .
}

run_checkov() {
  echo "quality-gate: checkov"
  checkov \
    -d .github/ \
    --framework github_actions,secrets \
    --quiet
}

run_zizmor() {
  require_cmd zizmor
  echo "quality-gate: zizmor"
  set +e
  zizmor .github/workflows
  zst=$?
  set -e
  if [[ "$zst" -ne 0 ]]; then
    echo "quality-gate: zizmor exited ${zst} (advisory — triage with .zizmor.yml / standardise-ecosystem.md)"
  fi
}

run_ecosystem_integrations() {
  echo "quality-gate: ecosystem CI integrations"
  bash "${ROOT}/scripts/ecosystem-governance-integrations.sh"
}

run_actionlint() {
  require_cmd actionlint
  echo "quality-gate: actionlint"
  actionlint -color
}

run_yamllint() {
  require_cmd yamllint
  echo "quality-gate: yamllint"
  local paths=()
  for p in \
    .github/workflows \
    .github/dependabot.yml \
    .github/ISSUE_TEMPLATE \
    azure-pipelines.yml \
    azure-pipelines.stack-integration.yml \
    .gitlab-ci.yml \
    bitbucket-pipelines.yml \
    invariants/starter \
    invariants/policies/example-enterprise-ado.yml \
    docs/examples/ci-gate-taudit-verify.yml; do
    if [[ -e "$p" ]]; then
      paths+=("$p")
    fi
  done
  if [[ "${#paths[@]}" -eq 0 ]]; then
    echo "quality-gate: yamllint skipped (no paths found)"
    return 0
  fi
  yamllint -c .yamllint "${paths[@]}"
}

# --- local CI ---------------------------------------------------------------
# GitHub Actions is not available for this repository (billing), so the local
# run IS the gate. `local-ci` executes the union of what quality.yml,
# security.yml and governance.yml run, and — unlike the other stages — a
# missing tool SKIPS one check instead of aborting the whole run, so one absent
# linter cannot silently reduce the gate to nothing.
#
# Skips are never silent: they are counted, listed with an install command, and
# reported in the summary. `--strict` turns any skip into a failure; that is
# what a release cut must use, because a gate that "passed" while skipping the
# security scanners is not a gate.
LOCAL_CI_PASSED=()
LOCAL_CI_FAILED=()
LOCAL_CI_SKIPPED=()

PY_BIN=""
pick_python() {
  if [[ -n "$PY_BIN" ]]; then return 0; fi
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then PY_BIN="$candidate"; return 0; fi
  done
  return 1
}

install_hint() {
  case "$1" in
    cargo-insta)  echo "cargo install cargo-insta --locked" ;;
    cargo-deny)   echo "cargo install cargo-deny --locked" ;;
    cargo-audit)  echo "cargo install cargo-audit --locked" ;;
    checkov)      echo "python -m pip install checkov" ;;
    yamllint)     echo "python -m pip install yamllint" ;;
    zizmor)       echo "python -m pip install zizmor" ;;
    actionlint)   echo "go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12" ;;
    gitleaks)     echo "https://github.com/gitleaks/gitleaks/releases" ;;
    trivy)        echo "https://github.com/aquasecurity/trivy/releases" ;;
    python3|python) echo "install Python 3.12+" ;;
    *)            echo "install '$1'" ;;
  esac
}

# step "<label>" "<required tool, or empty>" <command...>
step() {
  local label="$1" tool="$2"
  shift 2
  if [[ -n "$tool" ]] && ! command -v "$tool" >/dev/null 2>&1; then
    LOCAL_CI_SKIPPED+=("${label} — needs '${tool}': $(install_hint "$tool")")
    printf 'SKIP  %s (no %s)\n' "$label" "$tool"
    return 0
  fi
  printf '\n=== %s\n' "$label"
  if "$@"; then
    LOCAL_CI_PASSED+=("$label")
    printf 'PASS  %s\n' "$label"
  else
    LOCAL_CI_FAILED+=("$label")
    printf 'FAIL  %s\n' "$label"
  fi
}

py_step() {
  local label="$1"
  shift
  if ! pick_python; then
    LOCAL_CI_SKIPPED+=("${label} — needs 'python3': $(install_hint python3)")
    printf 'SKIP  %s (no python)\n' "$label"
    return 0
  fi
  step "$label" "" "$PY_BIN" "$@"
}

run_conformance_harness() {
  # The harness exits 0 on an `incomplete` result too, so assert full
  # conformance rather than trusting the exit code (RELEASE_GATES.md §2.1
  # treats `incomplete` as a blocker even when it is deliberate scaffolding).
  local out
  out="$("$PY_BIN" scripts/conformance_harness.py --root . --format json)" || return 1
  printf '%s\n' "$out" | tail -12
  printf '%s' "$out" | grep -q '"full_conformance": true' || {
    echo "conformance harness did not report full_conformance"
    return 1
  }
}

run_local_ci() {
  local strict="${1:-}"

  echo "quality-gate: local-ci — the union of quality.yml, security.yml and governance.yml"

  # --- Rust (quality.yml) ---
  step "cargo fmt"        cargo cargo fmt --all -- --check
  step "cargo clippy"     cargo cargo clippy --workspace --all-targets -- -D warnings
  step "cargo test"       cargo cargo test --workspace
  step "rule-firing benchmark" cargo cargo test -p taudit --test rule_firing_benchmark -- --nocapture
  step "cargo insta (unreferenced reject)" cargo-insta cargo insta test --workspace --unreferenced reject
  # advisories included: security.yml checks them even though quality.yml does not.
  step "cargo deny"       cargo-deny cargo deny check advisories bans licenses sources
  step "cargo audit"      cargo-audit cargo audit

  # --- Contracts, schemas, docs ---
  py_step "authority invariant schema drift" scripts/generate-authority-invariant-schema.py --check
  py_step "starter invariant YAML validation" scripts/validate-authority-invariant-yaml.py invariants/starter
  if pick_python; then
    step "output conformance harness" "" run_conformance_harness
  else
    LOCAL_CI_SKIPPED+=("output conformance harness — needs 'python3'")
    printf 'SKIP  output conformance harness (no python)\n'
  fi
  py_step "doc truth scan" scripts/doc_truth_scan.py

  # --- Smoke (needs a built binary) ---
  step "build taudit (debug, for smoke)" cargo cargo build -p taudit
  if taudit_debug_bin >/dev/null; then
    step "golden paths" "" run_golden_paths
  else
    LOCAL_CI_SKIPPED+=("golden paths — no debug taudit binary (cargo build -p taudit)")
    printf 'SKIP  golden paths (no debug binary)\n'
  fi
  step "taudit scans taudit" "" run_taudit_gate

  # --- Security + governance (security.yml, governance.yml) ---
  step "gitleaks"    gitleaks   run_gitleaks_repo
  step "trivy fs"    trivy      run_trivy_fs
  step "checkov"     checkov    run_checkov
  step "zizmor"      zizmor     run_zizmor
  step "actionlint"  actionlint run_actionlint
  step "yamllint"    yamllint   run_yamllint
  step "ecosystem CI integrations" "" run_ecosystem_integrations

  # --- Summary ---
  echo
  echo "──────────────────────────────────────────────────────────"
  printf 'local-ci: %d passed, %d failed, %d skipped\n' \
    "${#LOCAL_CI_PASSED[@]}" "${#LOCAL_CI_FAILED[@]}" "${#LOCAL_CI_SKIPPED[@]}"
  if [[ "${#LOCAL_CI_FAILED[@]}" -gt 0 ]]; then
    echo
    echo "FAILED:"
    printf '  - %s\n' "${LOCAL_CI_FAILED[@]}"
  fi
  if [[ "${#LOCAL_CI_SKIPPED[@]}" -gt 0 ]]; then
    echo
    echo "SKIPPED (this run is NOT full CI parity):"
    printf '  - %s\n' "${LOCAL_CI_SKIPPED[@]}"
  fi
  echo "──────────────────────────────────────────────────────────"

  if [[ "${#LOCAL_CI_FAILED[@]}" -gt 0 ]]; then
    echo "local-ci: FAILED"
    return 1
  fi
  if [[ "${#LOCAL_CI_SKIPPED[@]}" -gt 0 ]]; then
    if [[ "$strict" == "--strict" ]]; then
      echo "local-ci: INCOMPLETE and --strict was requested — treating skips as failure"
      return 1
    fi
    echo "local-ci: passed everything it ran, but ${#LOCAL_CI_SKIPPED[@]} check(s) were skipped."
    echo "local-ci: install the tools above before using this run to gate a release (or run --strict)."
    return 0
  fi
  echo "local-ci: full parity — every check ran and passed"
  return 0
}

case "$STAGE" in
  pre-commit)
    require_cmd cargo
    require_cmd gitleaks
    require_cmd trivy
    require_cmd checkov

    run_rust_fast_gate
    run_gitleaks_precommit
    run_trivy_config
    run_checkov
    run_taudit_gate

    # cargo clippy regenerates Cargo.lock when Cargo.toml versions change.
    # Stage it automatically so it is never left as a dirty unstaged file
    # after a version-bump commit.
    if ! git diff --quiet Cargo.lock 2>/dev/null; then
      git add Cargo.lock
    fi
    ;;

  pre-push|quality-gate)
    require_cmd cargo
    require_cmd gitleaks
    require_cmd trivy
    require_cmd checkov
    require_cmd cargo-deny
    require_cmd cargo-audit

    run_rust_full_gate
    run_golden_paths
    run_gitleaks_repo
    run_trivy_fs
    run_checkov
    run_taudit_gate
    ;;

  local-ci)
    # Full CI parity locally. Missing tools skip (and are reported) rather than
    # aborting; `--strict` makes any skip a failure. See run_local_ci above.
    run_local_ci "${2:-}"
    ;;

  ci-governance)
    require_cmd gitleaks
    require_cmd trivy
    require_cmd checkov
    require_cmd zizmor
    require_cmd actionlint
    require_cmd yamllint

    run_gitleaks_repo
    run_trivy_fs
    run_checkov
    run_zizmor
    run_actionlint
    run_yamllint
    run_ecosystem_integrations
    run_taudit_gate
    ;;

  *)
    echo "quality-gate: unknown stage '$STAGE'"
    echo "quality-gate: expected one of local-ci | pre-commit | pre-push | quality-gate | ci-governance"
    exit 2
    ;;
esac

if [[ "$STAGE" != "local-ci" ]]; then
  echo "quality-gate: ${STAGE} passed"
fi
