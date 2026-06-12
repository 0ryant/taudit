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

# 2. Findings: JSON + SARIF + maps + graphs for every stage (both scenarios)
Write-Host "==> findings (json + sarif), maps, graphs" -ForegroundColor Cyan
foreach ($stage in "before","after","exploit-before","exploit-after") {
  & $Taudit scan "$P/workflows/$stage.yml" --format json  -o "$P/findings/$stage.findings.json"
  & $Taudit scan "$P/workflows/$stage.yml" --format sarif -o "$P/findings/$stage.sarif"
  & $Taudit map  "$P/workflows/$stage.yml" --format text  | Out-File -Encoding utf8 "$P/authority-matrix/$stage.map.txt"
  & $Taudit graph "$P/workflows/$stage.yml" --view authority --format dot     | Out-File -Encoding utf8 "$P/graph/$stage-authority.dot"
  & $Taudit graph "$P/workflows/$stage.yml" --view authority --format mermaid | Out-File -Encoding utf8 "$P/graph/$stage-authority.mmd"
}
# Scenario B exploit-view kill-chain graphs
& $Taudit graph "$P/workflows/exploit-before.yml" --view exploit --format dot | Out-File -Encoding utf8 "$P/graph/exploit-before-killchain.dot"
& $Taudit graph "$P/workflows/exploit-after.yml"  --view exploit --format dot | Out-File -Encoding utf8 "$P/graph/exploit-after-killchain.dot"

# 3. Render graphs DOT -> SVG -> PNG (no system graphviz required)
Write-Host "==> rendering graph images" -ForegroundColor Cyan
Push-Location "$P/tools"
npm ci --no-audit --no-fund
foreach ($g in "before-authority","after-authority","exploit-before-killchain","exploit-before-authority","exploit-after-authority") {
  node render-dot.mjs "../graph/$g.dot" "../graph/$g.svg"
  node svg2png.mjs    "../graph/$g.svg" "../graph/$g.png"
}
Pop-Location

# 4. Diff + receipts (both scenarios)
Write-Host "==> diff + receipts" -ForegroundColor Cyan
& $Taudit diff "$P/workflows/before.yml" "$P/workflows/after.yml" --format terminal | Out-File -Encoding utf8 "$P/results/diff.txt"
& $Taudit diff "$P/workflows/before.yml" "$P/workflows/after.yml" --format json     | Out-File -Encoding utf8 "$P/results/diff.json"
& $Taudit diff "$P/workflows/exploit-before.yml" "$P/workflows/exploit-after.yml" --format terminal | Out-File -Encoding utf8 "$P/results/exploit-diff.txt"
& $Taudit diff "$P/workflows/exploit-before.yml" "$P/workflows/exploit-after.yml" --format json     | Out-File -Encoding utf8 "$P/results/exploit-diff.json"
foreach ($stage in "before","after","exploit-before","exploit-after") {
  & $Taudit scan "$P/workflows/$stage.yml" --receipt-dir "$P/receipts" | Out-Null
}

# 5. Baseline the remediated state and prove the gate is clean
Write-Host "==> baseline" -ForegroundColor Cyan
& $Taudit baseline init "$P/workflows/after.yml" --root "$P" --captured-by "taudit-authority-path-demo"
& $Taudit baseline diff "$P/workflows/after.yml" --root "$P" | Out-File -Encoding utf8 "$P/baseline/baseline-diff.txt"

# 6. Design-system drift pin: the vendored _assets/site.css must byte-match the
#    algol.cc source. Same discipline as the engineering-doctrine primer pin.
#    Pinned sha256 (algol.cc/css/site.css as of 2026-06-12):
$PinnedSiteCssSha = "2728b214e6e59e926dbaac02a3c7fb08f531c3099074d921d2b818bf4d887182"
Write-Host "==> design-system drift pin (_assets/site.css)" -ForegroundColor Cyan
$VendoredCss = Join-Path $RepoRoot "$P/_assets/site.css"
$AlgolCssSrc = "C:/Users/0ryant/prj/algol.cc/css/site.css"
$VendoredSha = (Get-FileHash -Algorithm SHA256 $VendoredCss).Hash.ToLower()
if ($VendoredSha -ne $PinnedSiteCssSha) {
  throw "site.css drift: vendored _assets/site.css sha256 $VendoredSha != pinned $PinnedSiteCssSha. Re-vendor from algol.cc and update the pin."
}
if (Test-Path $AlgolCssSrc) {
  $SrcSha = (Get-FileHash -Algorithm SHA256 $AlgolCssSrc).Hash.ToLower()
  if ($SrcSha -ne $PinnedSiteCssSha) {
    throw "site.css drift: algol.cc source sha256 $SrcSha != pinned $PinnedSiteCssSha. The design system moved; re-vendor and update index.html + the pin."
  }
  Write-Host "    site.css pinned + matches algol.cc source ($PinnedSiteCssSha)" -ForegroundColor Green
} else {
  Write-Host "    algol.cc source not present locally; vendored copy matches pin ($PinnedSiteCssSha)" -ForegroundColor Yellow
}

Write-Host "==> done. Evidence pack regenerated under $P" -ForegroundColor Green
