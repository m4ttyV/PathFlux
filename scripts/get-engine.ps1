param([string]$Destination = '.local\engine', [string]$Version = '1.14.3')
$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' -or [version]$Version -lt [version]'1.12.2') {
    throw 'Choose an official stable sing-box version >= 1.12.2.'
}
$assetName = "sing-box-$Version-windows-amd64.zip"
$release = Invoke-RestMethod -Uri "https://api.github.com/repos/SagerNet/sing-box/releases/tags/v$Version"
if ($release.draft -or $release.prerelease -or $release.tag_name -ne "v$Version") { throw 'Unexpected release metadata.' }
$asset = @($release.assets | Where-Object { $_.name -ceq $assetName })
if ($asset.Count -ne 1 -or $asset[0].digest -notmatch '^sha256:([a-fA-F0-9]{64})$') { throw 'Official archive digest unavailable; download refused.' }
$archiveHash = $Matches[1]
$directory = [IO.Path]::GetFullPath($Destination)
New-Item -ItemType Directory -Path $directory -Force | Out-Null
$zip = Join-Path $directory $assetName
Invoke-WebRequest -Uri "https://github.com/SagerNet/sing-box/releases/download/v$Version/$assetName" -OutFile $zip
if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -ne $archiveHash) { throw 'Archive SHA-256 mismatch; extraction refused.' }
Expand-Archive -LiteralPath $zip -DestinationPath $directory -Force
$exe = Join-Path $directory "sing-box-$Version-windows-amd64\sing-box.exe"
$exeHash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
# Trust is established by the official archive digest; no downloaded executable is run here.
[PSCustomObject]@{ EnginePath = $exe; EngineSha256 = $exeHash; Version = $Version; ArchiveSha256 = $archiveHash }
