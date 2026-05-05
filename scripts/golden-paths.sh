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
noop_policy="tests/fixtures/verify-golden-noop-policy.yml"

log() { echo "+ $*" >&2; }

log "$BIN scan $clean --platform github-actions --quiet"
"$BIN" scan "$clean" --platform github-actions --quiet

log "$BIN graph ... --format json"
out_json=$("$BIN" graph "$clean" --platform github-actions --format json)
grep -q '"schema_version"' <<<"$out_json"
grep -q '"graph"' <<<"$out_json"

log "$BIN graph ... --format summary"
out_sum=$("$BIN" graph "$clean" --platform github-actions --format summary)
grep -q '"schema_version"' <<<"$out_sum"
grep -q bfs_lower_trust_zone_sinks <<<"$out_sum"

log "$BIN map $clean ..."
"$BIN" map "$clean" --platform github-actions --no-color | grep -q .

log "$BIN scan $leaky --format json --quiet"
"$BIN" scan "$leaky" --platform github-actions --format json --quiet | grep -q '"findings"'

log "$BIN graph ... --format mermaid"
"$BIN" graph "$clean" --platform github-actions --format mermaid | grep -q flowchart

log "$BIN explain authority_propagation"
"$BIN" explain authority_propagation | grep -q authority_propagation

log "$BIN verify (noop policy on clean fixture)"
out_verify=$("$BIN" verify --policy "$noop_policy" "$clean" --platform github-actions --format text)
grep -q "verify: authority graph modeling:" <<<"$out_verify"
grep -q "verify: 0 violations" <<<"$out_verify"

echo "golden-paths: OK"
