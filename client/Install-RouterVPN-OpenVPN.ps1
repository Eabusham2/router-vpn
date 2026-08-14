param(
  [switch]$CheckOnly,
  [switch]$NoElevation
)

$ErrorActionPreference = 'Stop'
$OpenVPNVersion = '2.7.5'
$OpenVPNBuild = 'I001'
$ReleaseBase = 'https://swupdate.openvpn.org/community/releases'

function Find-OpenVPN {
  $candidates = @(
    "$env:ProgramFiles\OpenVPN\bin\openvpn.exe",
    "$env:ProgramFiles\OpenVPN Connect\OpenVPN\openvpn.exe"
  )
  if (${env:ProgramFiles(x86)}) { $candidates += "${env:ProgramFiles(x86)}\OpenVPN\bin\openvpn.exe" }
  $cmd = Get-Command openvpn.exe -ErrorAction SilentlyContinue
  if ($cmd) { $candidates += $cmd.Source }
  foreach ($candidate in $candidates | Select-Object -Unique) {
    if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate -PathType Leaf)) { return [IO.Path]::GetFullPath($candidate) }
  }
  return $null
}

function Get-OpenVPN-Version([string]$Binary) {
  if ([string]::IsNullOrWhiteSpace($Binary)) { return $null }
  $first = (& $Binary --version 2>&1 | Select-Object -First 1)
  if ([string]$first -match '^OpenVPN\s+([0-9]+\.[0-9]+\.[0-9]+)') { return $Matches[1] }
  return $null
}

function Test-Administrator {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($id)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-Installer {
  $arch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
  switch ($arch) {
    'x64' {
      return @{
        Asset = "OpenVPN-$OpenVPNVersion-$OpenVPNBuild-amd64.msi"
        Size = 5865472
        Arch = 'x64'
      }
    }
    'arm64' {
      return @{
        Asset = "OpenVPN-$OpenVPNVersion-$OpenVPNBuild-arm64.msi"
        Size = 6234112
        Arch = 'ARM64'
      }
    }
    default { throw "Router VPN OpenVPN setup supports modern Windows x64 and ARM64; detected $arch." }
  }
}

function Assert-OfficialMSI([string]$Path, [int64]$ExpectedSize) {
  $item = Get-Item -LiteralPath $Path
  if ($item.Length -ne $ExpectedSize) { throw "OpenVPN MSI size mismatch: expected $ExpectedSize bytes, got $($item.Length)." }
  $signature = Get-AuthenticodeSignature -LiteralPath $Path
  if ($signature.Status -ne 'Valid') { throw "OpenVPN MSI Authenticode signature is not valid: $($signature.Status)." }
  $subject = [string]$signature.SignerCertificate.Subject
  if ($subject -notmatch 'OpenVPN') { throw "OpenVPN MSI signer is unexpected: $subject" }
}

$existing = Find-OpenVPN
$existingVersion = Get-OpenVPN-Version $existing
if ($existingVersion -and $existingVersion -match '^2\.7\.') {
  Write-Host "OpenVPN $existingVersion is ready at $existing"
  exit 0
}
if ($CheckOnly) {
  throw 'OpenVPN 2.7.x is not installed. Router VPN can install the pinned official OpenVPN 2.7.5 MSI with a normal Windows UAC prompt.'
}

if (-not (Test-Administrator)) {
  if ($NoElevation) { throw 'Administrator approval is required to install the OpenVPN Windows driver/service.' }
  Write-Host 'OpenVPN 2.7 is required for custom OpenVPN nodes. Windows will ask for administrator approval once.'
  $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $PSCommandPath),'-NoElevation')
  $elevated = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList $args
  if ($elevated.ExitCode -ne 0) { throw "Elevated OpenVPN setup failed with exit code $($elevated.ExitCode)." }
  $installed = Find-OpenVPN
  $installedVersion = Get-OpenVPN-Version $installed
  if (-not $installedVersion -or $installedVersion -notmatch '^2\.7\.') { throw 'OpenVPN setup returned successfully but OpenVPN 2.7.x is still unavailable.' }
  Write-Host "OpenVPN $installedVersion is ready at $installed"
  exit 0
}

$installer = Resolve-Installer
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('router-vpn-openvpn-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
$msi = Join-Path $tempRoot $installer.Asset
try {
  $url = "$ReleaseBase/$($installer.Asset)"
  Write-Host "Downloading pinned official OpenVPN $OpenVPNVersion $($installer.Arch) from OpenVPN Community..."
  Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $msi
  Assert-OfficialMSI $msi ([int64]$installer.Size)
  Write-Host 'Authenticode signature is valid; installing OpenVPN driver/service...'
  $proc = Start-Process -FilePath 'msiexec.exe' -Wait -PassThru -ArgumentList @('/i',('"{0}"' -f $msi),'/qn','/norestart')
  if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) { throw "OpenVPN MSI installation failed with exit code $($proc.ExitCode)." }
} finally {
  Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$installed = Find-OpenVPN
$installedVersion = Get-OpenVPN-Version $installed
if (-not $installedVersion -or $installedVersion -notmatch '^2\.7\.') { throw 'OpenVPN 2.7 installation did not produce a usable openvpn.exe.' }
Write-Host "OpenVPN $installedVersion is ready at $installed"
