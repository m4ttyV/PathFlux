#requires -Version 7.0
param(
    [Parameter(Mandatory = $true)][string]$EnginePath,
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$EngineSha256,
    [Parameter(Mandatory = $true)][string]$Output,
    [string]$ProxyHost = '127.0.0.1',
    [ValidateRange(1, 65535)][int]$ProxyPort = 1080,
    [ValidateSet('Standard', 'DockerNat')][string]$RelayMode = 'Standard',
    [Nullable[int]]$UdpPublishedPortFirst,
    [Nullable[int]]$UdpPublishedPortLast,
    [switch]$Run
)
$ErrorActionPreference = 'Stop'
if (-not $Run) { throw 'Use -Run explicitly: this test starts the ordinary UI and UAC agent with temporary system TUN routes.' }
if ($RelayMode -eq 'DockerNat' -and ($null -eq $UdpPublishedPortFirst -or $null -eq $UdpPublishedPortLast -or $UdpPublishedPortFirst -lt 1 -or $UdpPublishedPortLast -gt 65535 -or $UdpPublishedPortFirst -gt $UdpPublishedPortLast)) { throw 'Docker NAT requires an explicit valid published UDP port range.' }
$projectRoot = Split-Path $PSScriptRoot -Parent
$portable = if (Test-Path -LiteralPath (Join-Path $projectRoot 'PathFlux.exe')) { $projectRoot } else { Join-Path $projectRoot 'artifacts\win-x64' }
$ui = (Resolve-Path -LiteralPath (Join-Path $portable 'PathFlux.exe')).Path
$probe = (Resolve-Path -LiteralPath (Join-Path $portable 'network-lab\PathFlux.NetworkLab.exe')).Path
$directory = [IO.Path]::GetFullPath($Output)
if (Test-Path -LiteralPath $directory) { throw 'Use a new output directory.' }
New-Item -ItemType Directory -Path $directory | Out-Null
$inputData = @{
    EnginePath = (Resolve-Path -LiteralPath $EnginePath).Path; EngineSha256 = $EngineSha256
    ProbeExecutable = $probe; ProxyHost = $ProxyHost; ProxyPort = $ProxyPort
    RelayMode = $(if ($RelayMode -eq 'DockerNat') { 1 } else { 0 })
    PortFirst = $UdpPublishedPortFirst; PortLast = $UdpPublishedPortLast
}
$inputData | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'input.json') -Encoding utf8
$info = [Diagnostics.ProcessStartInfo]::new($ui)
$info.UseShellExecute = $false
$info.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
foreach ($argument in @('--udp-acceptance', $directory, '--allow-system-tun')) { $info.ArgumentList.Add($argument) }
$child = [Diagnostics.Process]::Start($info)
try { $child.WaitForExit(); if ($child.ExitCode -ne 0) { throw "UI UDP acceptance failed ($($child.ExitCode)). Inspect $directory\ui-acceptance-report.json" } }
finally { $child.Dispose() }
$reportPath = Join-Path $directory 'ui-acceptance-report.json'
if (-not (Test-Path -LiteralPath $reportPath)) { throw 'UI acceptance did not produce a report.' }
$report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
$expectedCases = if ($RelayMode -eq 'DockerNat') { 7 } else { 6 }
if ($report.Status -ne 'PassedOrdinaryUiCommands_ExperimentalUdpAndTcp_NotDiscordAcceptance' -or $report.Cases.Count -ne $expectedCases -or @($report.Cases | Where-Object { -not $_.Passed }).Count -ne 0) { throw "UI acceptance report failed: $($report.Status) $($report.ErrorCode)" }
Write-Host "Ordinary UI acceptance passed: $directory\ui-acceptance-report.json"
