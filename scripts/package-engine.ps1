param([string]$Source = 'artifacts/process-tree-experimental', [string]$Output = 'artifacts/engine-package')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$sourceDirectory = [IO.Path]::GetFullPath((Join-Path $root $Source))
$outputDirectory = [IO.Path]::GetFullPath((Join-Path $root $Output))
$engine = Join-Path $sourceDirectory 'sing-box.exe'
$expected = '3149B341FC2AC1F8E383C6A54C5DD3E4BF2E0DEE8901C8A435903A08C0594C81'
if (!(Test-Path -LiteralPath $engine) -or (Get-FileHash -LiteralPath $engine -Algorithm SHA256).Hash -ne $expected) {
    throw 'Pinned PathFlux engine missing or hash mismatch. Build the verified process-tree backend first; see docs/process-tree-backend.md.'
}
foreach ($name in @('source', 'LICENSE.sing-box', 'build-manifest.json')) {
    if (!(Test-Path -LiteralPath (Join-Path $sourceDirectory $name))) { throw "Complete corresponding source/license missing: $name" }
}
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
$archive = Join-Path $outputDirectory 'source.zip'
$temporary = Join-Path $outputDirectory (([Guid]::NewGuid().ToString('N')) + '.zip')
try {
    [IO.Compression.ZipFile]::CreateFromDirectory((Join-Path $sourceDirectory 'source'), $temporary)
    Move-Item -LiteralPath $temporary -Destination $archive -Force
} finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary } }
foreach ($name in @('sing-box.exe', 'LICENSE.sing-box', 'build-manifest.json')) {
    Copy-Item -LiteralPath (Join-Path $sourceDirectory $name) -Destination $outputDirectory -Force
}
Write-Output "Verified engine package with corresponding source: $outputDirectory"
