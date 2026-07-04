$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$demoRoot = Join-Path $root "demo"
$reports = Join-Path $demoRoot "reports"
$graphs = Join-Path $demoRoot "graphs"
$badReports = Join-Path $reports "bad"
$badGraphs = Join-Path $graphs "bad"
$slides = Join-Path $demoRoot "slides"

$workflowSpecs = @(
    @{
        Name = "developer-tool-authority-path"
        Path = Join-Path $demoRoot "workflows\developer-tool-authority-path.yml"
        Primary = $true
    },
    @{
        Name = "helper-path-authority-path"
        Path = Join-Path $demoRoot "workflows\helper-path-authority-path.yml"
        Primary = $false
    },
    @{
        Name = "pr-writeback-authority-path"
        Path = Join-Path $demoRoot "workflows\pr-writeback-authority-path.yml"
        Primary = $false
    }
)

New-Item -ItemType Directory -Force -Path $reports, $graphs, $badReports, $badGraphs, $slides | Out-Null

function Ensure-DemoRenderer {
    $rendererModule = Join-Path $demoRoot "node_modules\@viz-js\viz"
    if (Test-Path $rendererModule) {
        return
    }

    if (Test-Path (Join-Path $demoRoot "package-lock.json")) {
        & npm --prefix $demoRoot ci --no-fund --no-audit
        return
    }

    & npm --prefix $demoRoot install --no-fund --no-audit
}

function Convert-DotToSvg {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DotPath,
        [Parameter(Mandatory = $true)]
        [string]$SvgPath
    )

    $dot = Get-Command dot -ErrorAction SilentlyContinue
    if ($dot) {
        & dot -Tsvg $DotPath -o $SvgPath
        return
    }

    Ensure-DemoRenderer
    & node (Join-Path $demoRoot "render-dot.mjs") $DotPath $SvgPath
}

function Invoke-TauditArtifactSet {
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkflowPath,
        [Parameter(Mandatory = $true)]
        [string]$ReportStem,
        [Parameter(Mandatory = $true)]
        [string]$GraphStem
    )

    & cargo run -p taudit -- scan $WorkflowPath --no-color --format terminal -o "$ReportStem.scan.txt"
    & cargo run -p taudit -- scan $WorkflowPath --format json -o "$ReportStem.scan.json"
    & cargo run -p taudit -- map $WorkflowPath > "$ReportStem.map.txt"
    & cargo run -p taudit -- graph $WorkflowPath --format mermaid --rich-labels > "$GraphStem.authority.mmd"
    & cargo run -p taudit -- graph $WorkflowPath --format dot --rich-labels > "$GraphStem.authority.dot"
    & cargo run -p taudit -- graph $WorkflowPath --format summary > "$GraphStem.summary.json"
    Convert-DotToSvg -DotPath "$GraphStem.authority.dot" -SvgPath "$GraphStem.authority.svg"
}

Push-Location $root
try {
    foreach ($workflow in $workflowSpecs) {
        $reportStem = Join-Path $badReports $workflow.Name
        $graphStem = Join-Path $badGraphs $workflow.Name
        Invoke-TauditArtifactSet -WorkflowPath $workflow.Path -ReportStem $reportStem -GraphStem $graphStem
    }

    $primary = $workflowSpecs | Where-Object { $_.Primary } | Select-Object -First 1
    if (-not $primary) {
        throw "Primary workflow not configured."
    }

    Copy-Item -Force (Join-Path $badReports "$($primary.Name).scan.txt") (Join-Path $reports "scan.txt")
    Copy-Item -Force (Join-Path $badReports "$($primary.Name).scan.json") (Join-Path $reports "scan.json")
    Copy-Item -Force (Join-Path $badReports "$($primary.Name).map.txt") (Join-Path $reports "map.txt")
    Copy-Item -Force (Join-Path $badGraphs "$($primary.Name).authority.mmd") (Join-Path $graphs "authority.mmd")
    Copy-Item -Force (Join-Path $badGraphs "$($primary.Name).authority.dot") (Join-Path $graphs "authority.dot")
    Copy-Item -Force (Join-Path $badGraphs "$($primary.Name).authority.svg") (Join-Path $graphs "authority.svg")
    Copy-Item -Force (Join-Path $badGraphs "$($primary.Name).summary.json") (Join-Path $graphs "summary.json")
}
finally {
    Pop-Location
}

Write-Host "Demo artifacts regenerated under demo\reports, demo\graphs, and demo\slides"
