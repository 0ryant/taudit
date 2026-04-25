# Local tasks — mirror CI: `just check`

set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

default:
    @just --list

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
    chmod +x .git/hooks/pre-commit
    @echo "pre-commit hook installed"

# Run taudit against its own sister projects (self-test)
self-test:
    cargo run -p taudit-cli -- scan .refs/cellos/.github/workflows/
    cargo run -p taudit-cli -- scan .refs/tsafe/.github/workflows/

# Run taudit inside an execution-isolation runtime (platform smoke check).
runtime-smoke:
    bash scripts/cellos_smoke.sh

# Backward-compatible alias.
cellos-smoke:
    bash scripts/cellos_smoke.sh
