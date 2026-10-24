param([string]$Destination = '.local\engine')
$ErrorActionPreference = 'Stop'
$version = '1.12.12'
$archiveHash = '352c69526b76cd199539c0e02b4042d1acc109cde3a0a671a40af4e24290faa4'
$exeHash = 'f1e6453b62482a95c9461d2c84d8e1a95567609f739adf6a1227a9b96c578747'
$directory = [IO.Path]::GetFullPath($Destination)
New-Item -ItemType Directory -Path $directory -Force | Out-Null
$zip = Join-Path $directory 'sing-box-1.12.12-windows-amd64.zip'
Invoke-WebRequest -Uri "https://github.com/SagerNet/sing-box/releases/download/v$version/sing-box-$version-windows-amd64.zip" -OutFile $zip
if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -ne $archiveHash) { throw 'Archive SHA-256 mismatch; extraction refused.' }
Expand-Archive -LiteralPath $zip -DestinationPath $directory -Force
$exe = Join-Path $directory "sing-box-$version-windows-amd64\sing-box.exe"
if ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -ne $exeHash) { throw 'Executable SHA-256 mismatch; do not execute.' }
[PSCustomObject]@{ EnginePath = $exe; EngineSha256 = $exeHash; Version = $version }
