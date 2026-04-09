#!/usr/bin/env bash
set -euo pipefail

# Resolve CellOS repository path. Prefer the workspace symlink, then common local path,
# then CELLOS_REPO override for custom setups.
CELLOS_REPO="${CELLOS_REPO:-}"
if [[ -z "${CELLOS_REPO}" ]]; then
  if [[ -d ".refs/cellos" ]]; then
    CELLOS_REPO=".refs/cellos"
  elif [[ -d "../CellOS" ]]; then
    CELLOS_REPO="../CellOS"
  else
    echo "CellOS repository not found. Set CELLOS_REPO=/path/to/CellOS." >&2
    exit 1
  fi
fi

if [[ ! -f "${CELLOS_REPO}/Cargo.toml" ]]; then
  echo "Invalid CELLOS_REPO: ${CELLOS_REPO} (Cargo.toml missing)" >&2
  exit 1
fi

if [[ ! -f "tests/fixtures/clean.yml" ]]; then
  echo "Expected fixture tests/fixtures/clean.yml not found" >&2
  exit 1
fi

echo "Building taudit binary..."
cargo build -p taudit --quiet

TAUDIT_BIN="${PWD}/target/debug/taudit"
SPEC_PATH="$(mktemp /tmp/taudit-cellos-spec.XXXXXX)"

cat >"${SPEC_PATH}" <<EOF
{
  "apiVersion": "cellos.io/v1",
  "kind": "ExecutionCell",
  "spec": {
    "id": "taudit-cellos-smoke",
    "authority": {
      "secretRefs": [],
      "egressRules": []
    },
    "lifetime": { "ttlSeconds": 120 },
    "run": {
      "argv": ["${TAUDIT_BIN}", "scan", "tests/fixtures/clean.yml", "--quiet", "--severity-threshold", "critical"],
      "workingDirectory": "${PWD}"
    }
  }
}
EOF

echo "Running taudit inside CellOS supervisor..."
CELL_OS_USE_NOOP_SINK=1 \
CELLOS_RUN_ARGV0_ALLOW_PREFIXES="${PWD}/target/debug,/usr/bin,/bin" \
cargo run --manifest-path "${CELLOS_REPO}/Cargo.toml" -p cellos-supervisor --quiet -- "${SPEC_PATH}"

rm -f "${SPEC_PATH}"
echo "CellOS smoke passed: taudit executed successfully inside an execution cell."
