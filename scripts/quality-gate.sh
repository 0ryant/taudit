#!/usr/bin/env bash
set -euo pipefail

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

run_golden_paths() {
  echo "quality-gate: golden-paths smoke (docs/golden-paths.md)"
  TAUDIT_BIN=target/debug/taudit bash scripts/golden-paths.sh
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
    --skip-dirs MEMORY,.claude \
    --exit-code 1 \
    .
}

run_trivy_fs() {
  echo "quality-gate: trivy fs"
  trivy fs \
    --scanners vuln,misconfig,secret \
    --severity HIGH,CRITICAL \
    --skip-dirs MEMORY,.claude \
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

  ci-governance)
    require_cmd gitleaks
    require_cmd trivy
    require_cmd checkov

    run_gitleaks_repo
    run_trivy_fs
    run_checkov
    run_taudit_gate
    ;;

  *)
    echo "quality-gate: unknown stage '$STAGE'"
    echo "quality-gate: expected one of pre-commit | pre-push | quality-gate | ci-governance"
    exit 2
    ;;
esac

echo "quality-gate: ${STAGE} passed"
