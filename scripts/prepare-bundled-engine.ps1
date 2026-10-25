# Reproducible release prerequisite. Only official, hash-pinned source/toolchain downloads.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$output = Join-Path $root 'artifacts/process-tree-experimental'
$expectedEngine = '3149B341FC2AC1F8E383C6A54C5DD3E4BF2E0DEE8901C8A435903A08C0594C81'
$binary = Join-Path $output 'sing-box.exe'
if ((Test-Path -LiteralPath $binary) -and (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash -eq $expectedEngine -and
    (Test-Path -LiteralPath (Join-Path $output 'source')) -and (Test-Path -LiteralPath (Join-Path $output 'build-manifest.json'))) { return }
if (Test-Path -LiteralPath $output) { throw 'Existing engine build is incomplete or changed; preserve it and build in a fresh checkout.' }
$cache = Join-Path $root '.local/process-tree-backend'
New-Item -ItemType Directory -Path $cache -Force | Out-Null
function Get-PinnedArchive([string]$Uri, [string]$Path, [string]$Hash) {
    if (!(Test-Path -LiteralPath $Path)) {
        $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.download'
        try {
            Invoke-WebRequest -Uri $Uri -OutFile $temporary
            if ((Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash -ne $Hash) { throw 'Downloaded archive hash mismatch.' }
            Move-Item -LiteralPath $temporary -Destination $Path
        } finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary } }
    }
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $Hash) { throw 'Cached archive hash mismatch.' }
}
$sourceZip = Join-Path $cache 'sing-box-v1.14.3.zip'
Get-PinnedArchive 'https://codeload.github.com/SagerNet/sing-box/zip/refs/tags/v1.14.3' $sourceZip '5BF11EEB2F5B93377166AF1ECDCF24DD2C4BE3C92BCB43C09D95EDD01EB85949'
$goZip = Join-Path $cache 'go1.25.5.windows-amd64.zip'
Get-PinnedArchive 'https://go.dev/dl/go1.25.5.windows-amd64.zip' $goZip 'AE756CCE1CB80C819B4FE01B0353807178F532211B47F72D7FA77949DE054EBB'
$go = Join-Path $cache 'go/bin/go.exe'
if (!(Test-Path -LiteralPath $go)) { Expand-Archive -LiteralPath $goZip -DestinationPath $cache }
& (Join-Path $root 'backends/process-tree/build.ps1') -SourceArchive $sourceZip -Go $go -OutputDirectory $output
if ((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash -ne $expectedEngine) { throw 'Rebuilt engine differs from the pinned installer binary. Package refused.' }
