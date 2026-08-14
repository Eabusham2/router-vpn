param([string]$PackageRoot = $PSScriptRoot)

$ErrorActionPreference = 'Stop'
$SingBoxVersion = '1.13.12'
$XrayVersion = '26.7.11'

function Assert-SafeZip([string]$ZipPath) {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $archive = [IO.Compression.ZipFile]::OpenRead($ZipPath)
  try {
    foreach ($entry in $archive.Entries) {
      $name = ([string]$entry.FullName).Replace('/','\')
      if ([IO.Path]::IsPathRooted($name) -or $name -match '(^|\\)\.\.(\\|$)') { throw "Unsafe archive member: $name" }
    }
  } finally { $archive.Dispose() }
}
function Install-PinnedArchive([string]$Name,[string]$Url,[string]$Sha256,[string]$ExeName,[string]$Destination,[string[]]$CompanionPatterns=@()) {
  $temp = Join-Path ([IO.Path]::GetTempPath()) ('router-vpn-'+[Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $temp -Force | Out-Null
  $zip = Join-Path $temp "$Name.zip"
  try {
    Write-Host "Downloading $Name..."
    Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $zip
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLowerInvariant()
    if ($actual -ne $Sha256.ToLowerInvariant()) { throw "$Name SHA-256 mismatch. Expected $Sha256, got $actual" }
    Assert-SafeZip $zip
    $extract = Join-Path $temp 'extract'
    Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force
    $exe = Get-ChildItem -LiteralPath $extract -Recurse -File -Filter $ExeName | Select-Object -First 1
    if (-not $exe) { throw "$Name archive did not contain $ExeName" }
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Copy-Item -LiteralPath $exe.FullName -Destination (Join-Path $Destination $ExeName) -Force
    foreach ($pattern in $CompanionPatterns) {
      Get-ChildItem -LiteralPath $exe.Directory.FullName -File -Filter $pattern -ErrorAction SilentlyContinue |
        ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $Destination $_.Name) -Force }
    }
  } finally { Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue }
}

$PackageRoot = [IO.Path]::GetFullPath($PackageRoot)
if (-not (Test-Path -LiteralPath (Join-Path $PackageRoot 'modes.json')) -and (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $PackageRoot) 'modes.json'))) {
  $PackageRoot = Split-Path -Parent $PackageRoot
}
$Portable = Test-Path -LiteralPath (Join-Path $PackageRoot 'App\RouterVPN') -PathType Container
if ($Portable) {
  $AppRoot = Join-Path $PackageRoot 'App\RouterVPN'
  $DataRoot = Join-Path $PackageRoot 'Data'
  $HelpersRoot = Join-Path $AppRoot 'client'
  $ModesDir = Join-Path $AppRoot 'modes'
  $ModesSource = Join-Path $AppRoot 'modes.json'
  New-Item -ItemType Directory -Force -Path $DataRoot | Out-Null
  if (-not (Test-Path -LiteralPath (Join-Path $DataRoot 'client.json'))) { Copy-Item -LiteralPath (Join-Path $AppRoot 'client.json') -Destination (Join-Path $DataRoot 'client.json') }
} else {
  $AppRoot = $PackageRoot
  $DataRoot = $PackageRoot
  $HelpersRoot = Join-Path $PackageRoot 'client'
  $ModesDir = Join-Path $PackageRoot 'modes'
  $ModesSource = Join-Path $PackageRoot 'modes.json'
}
$Runtime = Join-Path $DataRoot 'runtime\windows'
$Prep = Join-Path $HelpersRoot 'Prepare-Windows-Mode-Catalog-v2.ps1'
$OpenVPNSetup = Join-Path $HelpersRoot 'Install-RouterVPN-OpenVPN.ps1'
if (-not (Test-Path -LiteralPath $Prep -PathType Leaf)) { throw "Missing Windows catalog helper: $Prep" }
if (-not (Test-Path -LiteralPath $OpenVPNSetup -PathType Leaf)) { throw "Missing OpenVPN setup helper: $OpenVPNSetup" }

$arch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
switch ($arch) {
  'x64' {
    $sbAsset = "sing-box-$SingBoxVersion-windows-amd64.zip"
    $sbSha = 'e93fc531134eb1beb4efa3c74990a24e48456098a31c03b60d5ddf17f223cf98'
    $xrAsset = 'Xray-windows-64.zip'
    $xrSha = 'af801b62c4d41d248d3db8016d4c6e2a7ccfb7ed443e3738aeb6f9e062321512'
  }
  'arm64' {
    $sbAsset = "sing-box-$SingBoxVersion-windows-arm64.zip"
    $sbSha = 'e01560b07061fa79e67cb7dc8727ac5e3010fa9f93444ddaf0c014967f52a1b4'
    $xrAsset = 'Xray-windows-arm64-v8a.zip'
    $xrSha = 'c4868e84cbedc9fcc3e636968804a8b3891101eedefe4305aa87d3d05ee1d1b1'
  }
  default { throw "Unsupported Windows architecture: $arch" }
}
$sbUrl = "https://github.com/SagerNet/sing-box/releases/download/v$SingBoxVersion/$sbAsset"
$xrUrl = "https://github.com/XTLS/Xray-core/releases/download/v$XrayVersion/$xrAsset"
Install-PinnedArchive "sing-box-$SingBoxVersion" $sbUrl $sbSha 'sing-box.exe' $Runtime @('*.dll')
Install-PinnedArchive "xray-$XrayVersion" $xrUrl $xrSha 'xray.exe' $Runtime @('*.dll','*.dat')

& (Join-Path $Runtime 'sing-box.exe') version | Select-Object -First 1
if ($LASTEXITCODE -ne 0) { throw 'sing-box runtime verification failed.' }
& (Join-Path $Runtime 'xray.exe') version | Select-Object -First 2
if ($LASTEXITCODE -ne 0) { throw 'Xray runtime verification failed.' }

# OpenVPN needs a Windows driver/service, so its exact-version helper performs
# the one normal UAC elevation itself. It uses the official 2.7.5 x64/ARM64 MSI,
# checks exact asset size and a valid OpenVPN Authenticode signature, and then
# verifies the installed openvpn.exe before returning.
& $OpenVPNSetup
if ($LASTEXITCODE -ne 0) { throw 'OpenVPN runtime setup failed.' }

& $Prep -Root $DataRoot -Source $ModesSource -ModesDir $ModesDir -HelpersRoot $HelpersRoot
if ($LASTEXITCODE -ne 0) { throw 'Windows mode-catalog preparation failed.' }
Write-Host ''
Write-Host "Router VPN native Windows runtime is ready: sing-box $SingBoxVersion + Xray $XrayVersion + OpenVPN 2.7.x."
Write-Host 'No WSL is used. Reopen Router VPN so readiness checks re-evaluate the native modes and custom external nodes.'
