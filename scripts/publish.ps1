param([string]$Output = 'artifacts\win-x64')
$ErrorActionPreference = 'Stop'
Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    dotnet publish PathFlux\PathFlux.csproj -c Release -r win-x64 --self-contained false -p:RestoreLockedMode=true -o $Output
    if ($LASTEXITCODE -ne 0) { throw 'UI publish failed.' }
    dotnet publish src\PathFlux.Agent\PathFlux.Agent.csproj -c Release -r win-x64 --self-contained false -p:RestoreLockedMode=true -o (Join-Path $Output 'agent')
    if ($LASTEXITCODE -ne 0) { throw 'Agent publish failed.' }
    dotnet publish tools\PathFlux.NetworkLab\PathFlux.NetworkLab.csproj -c Release -r win-x64 --self-contained false -p:RestoreLockedMode=true -o (Join-Path $Output 'network-lab')
    if ($LASTEXITCODE -ne 0) { throw 'Network lab publish failed.' }
    Copy-Item -LiteralPath 'README.md', 'LICENSE' -Destination $Output -Force
    Copy-Item -LiteralPath 'docs', 'examples' -Destination $Output -Recurse -Force
    $helperDirectory = Join-Path $Output 'scripts'
    New-Item -ItemType Directory -Path $helperDirectory -Force | Out-Null
    Copy-Item -LiteralPath 'scripts\get-engine.ps1', 'scripts\udp-echo-server.py', 'scripts\run-tun-lab.ps1', 'scripts\run-ui-udp-acceptance.ps1', 'scripts\summarize-udp-metrics.ps1' -Destination $helperDirectory -Force
} finally { Pop-Location }
