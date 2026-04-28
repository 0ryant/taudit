#!/usr/bin/env bash
# Smoke-test commands documented in docs/golden-paths.md.
# Usage: from repo root, with binary already built:
#   TAUDIT_BIN=target/debug/taudit bash scripts/golden-paths.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BIN="${TAUDIT_BIN:-target/debug/taudit}"
if [[ ! -x "$BIN" ]]; then
  echo "golden-paths: $BIN not executable — run: cargo build -p taudit" >&2
  exit 1
fi

export NO_COLOR=1

clean="tests/fixtures/clean.yml"
leaky="tests/fixtures/propagation-leaky.yml"

log() { echo "+ $*" >&2; }

log "$BIN scan $clean --platform github-actions --quiet"
"$BIN" scan "$clean" --platform github-actions --quiet

log "$BIN graph ... --format json"
out_json=$("$BIN" graph "$clean" --platform github-actions --format json)
echo "$out_json" | grep -q '"schema_version"'
echo "$out_json" | grep -q '"graph"'

log "$BIN graph ... --format summary"
out_sum=$("$BIN" graph "$clean" --platform github-actions --format summary)
echo "$out_sum" | grep -q '"schema_version"'
echo "$out_sum" | grep -q bfs_lower_trust_zone_sinks

log "$BIN map $clean ..."
"$BIN" map "$clean" --platform github-actions --no-color | grep -q .

log "$BIN scan $leaky --format json --quiet"
"$BIN" scan "$leaky" --platform github-actions --format json --quiet | grep -q '"findings"'

log "$BIN graph ... --format mermaid"
"$BIN" graph "$clean" --platform github-actions --format mermaid | grep -q flowchart

log "$BIN explain authority_propagation"
"$BIN" explain authority_propagation | grep -q authority_propagation

echo "golden-paths: OK"
