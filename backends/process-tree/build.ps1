param(
    [Parameter(Mandatory=$true)][string]$SourceArchive,
    [Parameter(Mandatory=$true)][string]$Go,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
$ErrorActionPreference='Stop'
$goExecutable=(Resolve-Path -LiteralPath $Go).Path
$archive=(Resolve-Path -LiteralPath $SourceArchive).Path
if(-not[IO.Path]::IsPathFullyQualified($OutputDirectory) -or (Test-Path -LiteralPath $OutputDirectory)){throw 'NewAbsoluteOutputRequired'}
$archiveHash=(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
if($archiveHash -cne '5BF11EEB2F5B93377166AF1ECDCF24DD2C4BE3C92BCB43C09D95EDD01EB85949'){throw 'PinnedUpstreamArchiveHashMismatch'}
if((& $goExecutable version) -notmatch '^go version go1\.25\.5 windows/amd64$'){throw 'PinnedWindowsGo1255Required'}
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
$sources=Join-Path $OutputDirectory 'source'
Expand-Archive -LiteralPath $archive -DestinationPath $sources
$sourceRoot=Join-Path $sources 'sing-box-1.14.3'
& (Join-Path $PSScriptRoot 'prepare.ps1') -Source $sourceRoot
$oldCgo=$env:CGO_ENABLED
$oldToolchain=$env:GOTOOLCHAIN
Push-Location -LiteralPath $sourceRoot
try {
    $env:CGO_ENABLED='0'
    $env:GOTOOLCHAIN='local'
    & $goExecutable test ./common/pathfluxtree
    if($LASTEXITCODE -ne 0){throw 'ProcessTreeTestsFailed'}
    & $goExecutable test ./route/rule -run '^TestPathFlux' -count=1
    if($LASTEXITCODE -ne 0){throw 'ProcessTreeRuleTestsFailed'}
    $binary=Join-Path $OutputDirectory 'sing-box.exe'
    & $goExecutable build -buildvcs=false -tags with_gvisor -trimpath -ldflags '-s -w -X github.com/sagernet/sing-box/constant.Version=1.14.3-pathflux-tree.1' -o $binary ./cmd/sing-box
    if($LASTEXITCODE -ne 0){throw 'ProcessTreeBuildFailed'}
    $capabilities=& $binary pathflux-capabilities
    if($LASTEXITCODE -ne 0){throw 'CapabilityCommandFailed'}
    Copy-Item -LiteralPath (Join-Path $sourceRoot 'LICENSE') -Destination (Join-Path $OutputDirectory 'LICENSE.sing-box')
    $hash=(Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash
    [ordered]@{Experimental=$true;OfficialSingBox=$false;Upstream='v1.14.3';SourceArchiveSha256=$archiveHash;PatchedSourceIncluded=$true;Go='go1.25.5 windows/amd64';Sha256=$hash;Capabilities=($capabilities|ConvertFrom-Json)} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'build-manifest.json') -Encoding utf8
    Write-Output $hash
} finally { Pop-Location; $env:CGO_ENABLED=$oldCgo; $env:GOTOOLCHAIN=$oldToolchain }
