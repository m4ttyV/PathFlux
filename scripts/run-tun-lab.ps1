param(
    [Parameter(Mandatory = $true)][string]$EnginePath,
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$EngineSha256,
    [string]$Output,
    [switch]$Run,
    [switch]$Elevate,
    [ValidateSet('Tcp', 'DockerTcp', 'ExperimentalUdp')][string]$Suite = 'Tcp'
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
    $command = switch ($Suite) { 'DockerTcp' { 'docker-tcp' } 'ExperimentalUdp' { 'udp-tun' } default { 'run-isolated' } }
    Write-Host 'Explicit TUN run: one target /32 plus the lab interface subnet. Administrator required. Wintun driver may be installed.'
    if ($Elevate) { & $lab elevate $command $engine $EngineSha256 $reportDirectory --allow-tun }
    else { & $lab $command $engine $EngineSha256 $reportDirectory --allow-tun }
} else {
    if ($Suite -ne 'Tcp' -or $Elevate) { throw 'Choose -Run explicitly for elevated/network suites.' }
    Write-Host 'Prepare only: no TUN, no route or DNS changes.'
    & $lab prepare $engine $EngineSha256 $reportDirectory
}
if ($LASTEXITCODE -ne 0) { throw "Lab failed (exit $LASTEXITCODE). See $reportDirectory\report.json" }
