param(
    [Parameter(Mandatory = $true)][string]$EnginePath,
    [Parameter(Mandatory = $true)][string]$EngineSha256,
    [string]$Output,
    [switch]$Run
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$engine = (Resolve-Path -LiteralPath $EnginePath).Path
$candidates = @(
    (Join-Path $projectRoot 'network-lab\PathFlux.NetworkLab.exe'),
    (Join-Path $projectRoot 'artifacts\win-x64\network-lab\PathFlux.NetworkLab.exe'),
    (Join-Path $projectRoot 'tools\PathFlux.NetworkLab\bin\Release\net10.0\PathFlux.NetworkLab.exe')
)
$lab = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $lab) { throw 'Build Release or publish PathFlux before running this script.' }
if (-not $Output) { $Output = Join-Path $projectRoot ('lab-results\' + [guid]::NewGuid().ToString('N')) }
$reportDirectory = [IO.Path]::GetFullPath($Output)
if ($Run) {
    Write-Host 'Explicit TUN run: only 198.18.0.1/32. Administrator required. Wintun driver may be installed.'
    & $lab run-isolated $engine $EngineSha256 $reportDirectory --allow-tun
} else {
    Write-Host 'Prepare only: no TUN, no route or DNS changes.'
    & $lab prepare $engine $EngineSha256 $reportDirectory
}
if ($LASTEXITCODE -ne 0) { throw "Lab failed (exit $LASTEXITCODE). See $reportDirectory\report.json" }
