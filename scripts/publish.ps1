param([string]$Output = 'artifacts\win-x64')
$ErrorActionPreference = 'Stop'
Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    dotnet publish PathFlux\PathFlux.csproj -c Release -r win-x64 --self-contained false -p:RestoreLockedMode=true -o $Output
    if ($LASTEXITCODE -ne 0) { throw 'UI publish failed.' }
    dotnet publish src\PathFlux.Agent\PathFlux.Agent.csproj -c Release -r win-x64 --self-contained false -p:RestoreLockedMode=true -o (Join-Path $Output 'agent')
    if ($LASTEXITCODE -ne 0) { throw 'Agent publish failed.' }
    Copy-Item -LiteralPath 'README.md', 'LICENSE' -Destination $Output -Force
    Copy-Item -LiteralPath 'docs', 'examples' -Destination $Output -Recurse -Force
} finally { Pop-Location }
