# Local tasks — mirror CI: `just check`

set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

default:
    @just --list

release-check tag:
    python scripts/release_harness.py check --tag {{tag}} --require-local-tag

release-notes tag:
    python scripts/release_harness.py notes --tag {{tag}}

release-standardize tag:
    python scripts/release_harness.py ensure-github-release --tag {{tag}}

release-backfill tag:
    python scripts/release_harness.py ensure-github-release --tag {{tag}} --source-ref {{tag}} --skip-publish-metadata

versions:
    @echo "crate versions:"
    @find crates -name Cargo.toml -maxdepth 2 | sort | while read -r manifest; do name=$(grep '^name = ' "$manifest" | head -1 | cut -d '"' -f2); version=$(grep '^version = ' "$manifest" | head -1 | cut -d '"' -f2); printf "  %-28s %s\n" "$name" "$version"; done

check: fmt clippy test deny
    @echo "just check: OK"

contracts:
    cargo test -p taudit-report-json
    cargo test -p taudit-sink-cloudevents

fmt:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo test --workspace

deny:
    cargo deny check licenses bans sources

audit:
    @if command -v cargo-audit >/dev/null 2>&1; then cargo audit; else echo "cargo-audit not found — cargo install cargo-audit --locked"; exit 1; fi

fix:
    cargo fmt --all
    cargo clippy --workspace --all-targets --fix --allow-dirty --allow-staged

install-hooks:
    cp scripts/pre-commit .git/hooks/pre-commit
    cp scripts/pre-push .git/hooks/pre-push
    chmod +x .git/hooks/pre-commit .git/hooks/pre-push
    @echo "git hooks installed: pre-commit, pre-push"

quality-gate:
    bash scripts/quality-gate.sh quality-gate

pre-commit-gate:
    bash scripts/quality-gate.sh pre-commit

pre-push-gate:
    bash scripts/quality-gate.sh pre-push

# Run taudit against its own sister projects (self-test)
self-test:
    cargo run -p taudit -- scan .refs/cellos/.github/workflows/
    cargo run -p taudit -- scan .refs/tsafe/.github/workflows/

# CLI smoke: all committed YAML corpora (fixtures, fuzz seeds, .github/workflows).
# For optional root `corpus/` mirrors, set TAUDIT_TEST_LOCAL_CORPUS=1 (best-effort; may fail on bad files).
corpus-suite:
    cargo test -p taudit --test corpus_cli_suite

# Smoke the blessed flows in docs/golden-paths.md (exit codes + minimal stdout checks).
golden-paths:
    cargo build -p taudit
    TAUDIT_BIN=target/debug/taudit bash scripts/golden-paths.sh

# Run taudit inside an execution-isolation runtime (platform smoke check).
runtime-smoke:
    bash scripts/cellos_smoke.sh

# Backward-compatible alias.
cellos-smoke:
    bash scripts/cellos_smoke.sh
