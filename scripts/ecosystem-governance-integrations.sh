#!/usr/bin/env bash
# standardise-ecosystem.md — every repo's governance job must touch the three tools.
# In taudit CI we do not vendor tsafe/CellOS binaries; emit explicit skip annotations.
set -euo pipefail

echo "quality-gate: ecosystem — tsafe smoke"
if command -v tsafe >/dev/null 2>&1; then
  tsafe --version || tsafe version || true
else
  echo "::notice::skip-with-reason: tsafe CLI not installed in taudit runner (peer repo). Use stack-integration / sibling checkout for full smoke."
fi

echo "quality-gate: ecosystem — taudit scan (handled by quality-gate taudit_gate)"
# run_taudit_gate already scans .github/workflows/

echo "quality-gate: ecosystem — CellOS contract validation"
if command -v cellos-supervisor >/dev/null 2>&1; then
  cellos-supervisor --version || true
elif [[ -f packaging/docker/cellos-supervisor/Dockerfile ]]; then
  echo "::notice::skip-with-reason: CellOS supervisor not on PATH; use publish-cellos-ghcr / stack-integration for full validation."
else
  echo "::notice::skip-with-reason: CellOS integration fixtures not present."
fi
