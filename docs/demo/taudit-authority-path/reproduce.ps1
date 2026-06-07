#!/usr/bin/env pwsh
# Regenerate the entire taudit-authority-path evidence pack from the two
# workflow files. Run from the repository root:  ./docs/demo/taudit-authority-path/reproduce.ps1
# Requires: cargo (to build taudit) and Node 18+ (to render graph images).
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$P        = "docs/demo/taudit-authority-path"
Set-Location $RepoRoot

# 1. Build taudit (this also refreshes Cargo.lock so locked versions match the
#    manifests — the binary, its --version, and the SARIF tool.version all agree).
Write-Host "==> building taudit (release)" -ForegroundColor Cyan
cargo build -p taudit --release
$Taudit = Join-Path $RepoRoot "target/release/taudit.exe"
if (-not (Test-Path $Taudit)) { $Taudit = Join-Path $RepoRoot "target/release/taudit" }
& $Taudit --version

# 2. Findings: JSON + SARIF for both stages
Write-Host "==> findings (json + sarif)" -ForegroundColor Cyan
foreach ($stage in "before","after") {
  & $Taudit scan "$P/workflows/$stage.yml" --format json  -o "$P/findings/$stage.findings.json"
  & $Taudit scan "$P/workflows/$stage.yml" --format sarif -o "$P/findings/$stage.sarif"
  & $Taudit map  "$P/workflows/$stage.yml" --format text  | Out-File -Encoding utf8 "$P/authority-matrix/$stage.map.txt"
  & $Taudit graph "$P/workflows/$stage.yml" --view authority --format dot     | Out-File -Encoding utf8 "$P/graph/$stage-authority.dot"
  & $Taudit graph "$P/workflows/$stage.yml" --view authority --format mermaid | Out-File -Encoding utf8 "$P/graph/$stage-authority.mmd"
}

# 3. Render graphs DOT -> SVG -> PNG (no system graphviz required)
Write-Host "==> rendering graph images" -ForegroundColor Cyan
Push-Location "$P/tools"
npm ci --no-audit --no-fund
foreach ($stage in "before","after") {
  node render-dot.mjs "../graph/$stage-authority.dot" "../graph/$stage-authority.svg"
  node svg2png.mjs    "../graph/$stage-authority.svg" "../graph/$stage-authority.png"
}
Pop-Location

# 4. Diff + receipts
Write-Host "==> diff + receipts" -ForegroundColor Cyan
& $Taudit diff "$P/workflows/before.yml" "$P/workflows/after.yml" --format terminal | Out-File -Encoding utf8 "$P/results/diff.txt"
& $Taudit diff "$P/workflows/before.yml" "$P/workflows/after.yml" --format json     | Out-File -Encoding utf8 "$P/results/diff.json"
& $Taudit scan "$P/workflows/before.yml" --receipt-dir "$P/receipts" | Out-Null
& $Taudit scan "$P/workflows/after.yml"  --receipt-dir "$P/receipts" | Out-Null

# 5. Baseline the remediated state and prove the gate is clean
Write-Host "==> baseline" -ForegroundColor Cyan
& $Taudit baseline init "$P/workflows/after.yml" --root "$P" --captured-by "taudit-authority-path-demo"
& $Taudit baseline diff "$P/workflows/after.yml" --root "$P" | Out-File -Encoding utf8 "$P/baseline/baseline-diff.txt"

Write-Host "==> done. Evidence pack regenerated under $P" -ForegroundColor Green
