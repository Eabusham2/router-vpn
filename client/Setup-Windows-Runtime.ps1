param([string]$PackageRoot = $PSScriptRoot)

$ErrorActionPreference = 'Stop'
$SingBoxVersion = '1.13.12'
$XrayVersion = '26.7.11'
$TorExpertVersion = '15.0.24'
$TorVersion = '0.4.9.13'
$TorExpertWindowsX64Sha256 = 'e9dc6ccc93cd6afa507193f4de284d6424233ff5102155cd2c94b259e8a22b65'

function Assert-SafeZip([string]$ZipPath) {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $archive = [IO.Compression.ZipFile]::OpenRead($ZipPath)
  try {
    foreach ($entry in $archive.Entries) {
      $name = ([string]$entry.FullName).Replace('/','\')
      if ([IO.Path]::IsPathRooted($name) -or $name -match '^[A-Za-z]:' -or $name -match '(^|\\)\.\.(\\|$)') { throw "Unsafe archive member: $name" }
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

function Get-RouterVPNTorHelperExecution([string]$Architecture) {
  switch ($Architecture) {
    'x64' { return 'x64 helpers' }
    'arm64' {
      if (-not ('RouterVpnTorMachineSupport' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class RouterVpnTorMachineSupport {
  [DllImport("kernel32.dll", ExactSpelling=true)]
  private static extern int GetMachineTypeAttributes(ushort machine, out uint attributes);
  public static bool X64UserEnabled() {
    uint attributes;
    return GetMachineTypeAttributes(0x8664, out attributes) == 0 && (attributes & 1) != 0;
  }
}
'@
      }
      try { $enabled = [RouterVpnTorMachineSupport]::X64UserEnabled() }
      catch { throw 'Windows ARM64 Tor requires the Windows 11 x64 userspace execution API.' }
      if (-not $enabled) { throw 'Windows did not report x64 userspace emulation enabled for Tor helpers.' }
      return 'x64 helpers via Windows emulation; ARM64 VPN engine and driver'
    }
    default { throw "Unsupported Tor helper host architecture: $Architecture" }
  }
}

function Invoke-RouterVPNTorHelperVersion([string]$Executable,[string]$Argument,[string]$Expected) {
  if ($Argument -notin @('--version','-version')) { throw 'Only a version query is allowed for this helper check.' }
  $info = New-Object Diagnostics.ProcessStartInfo
  $info.FileName = $Executable; $info.Arguments = $Argument
  $info.UseShellExecute = $false; $info.CreateNoWindow = $true
  $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
  $process = New-Object Diagnostics.Process
  $process.StartInfo = $info
  try {
    if (-not $process.Start()) { throw 'Tor helper version process did not start.' }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(10000)) { throw 'Tor helper version process exceeded its timeout.' }
    if (-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),2000)) { throw 'Tor helper output did not finish.' }
    $text = $stdout.Result + $stderr.Result
    if ($process.ExitCode -ne 0 -or $text.Length -gt 16384 -or $text -notmatch $Expected) { throw 'Pinned Tor helper failed its version/execution check.' }
    return $text.Trim()
  } finally {
    try { if (-not $process.HasExited) { $process.Kill(); [void]$process.WaitForExit(2000) } } catch { }
    $process.Dispose()
  }
}

function Install-PinnedTorExpertBundle([string]$Url,[string]$Sha256,[string]$ExpectedTorVersion,[string]$RuntimeRoot) {
  $tar = (Get-Command tar.exe -ErrorAction Stop).Source
  if ([string]::IsNullOrWhiteSpace($tar)) { throw 'Windows tar.exe is required to install the pinned Tor Expert Bundle.' }
  $temp = Join-Path ([IO.Path]::GetTempPath()) ('router-vpn-tor-'+[Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $temp -Force | Out-Null
  $archive = Join-Path $temp 'tor-expert.tar.gz'
  try {
    Write-Host "Downloading Tor Expert Bundle $TorExpertVersion..."
    Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $archive
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
    if ($actual -ne $Sha256.ToLowerInvariant()) { throw "Tor Expert Bundle SHA-256 mismatch. Expected $Sha256, got $actual" }

    $members = @(& $tar -tzf $archive 2>&1)
    if ($LASTEXITCODE -ne 0 -or $members.Count -eq 0) { throw 'Could not inspect Tor Expert Bundle members before extraction.' }
    foreach ($raw in $members) {
      $name = ([string]$raw).Trim().Replace('/','\')
      if (-not $name) { continue }
      if ([IO.Path]::IsPathRooted($name) -or $name -match '^[A-Za-z]:' -or $name -match '(^|\\)\.\.(\\|$)') { throw "Unsafe Tor Expert Bundle member: $name" }
    }
    $verbose = @(& $tar -tvzf $archive 2>&1)
    if ($LASTEXITCODE -ne 0) { throw 'Could not inspect Tor Expert Bundle entry types before extraction.' }
    foreach ($line in $verbose) {
      $text = ([string]$line).Trim()
      if (-not $text) { continue }
      if ($text[0] -ne '-' -and $text[0] -ne 'd') { throw "Tor Expert Bundle contains a non-regular/non-directory archive entry: $text" }
    }

    $extract = Join-Path $temp 'extract'
    New-Item -ItemType Directory -Path $extract -Force | Out-Null
    & $tar -xzf $archive -C $extract
    if ($LASTEXITCODE -ne 0) { throw 'Tor Expert Bundle extraction failed.' }
    $reparse = @(Get-ChildItem -LiteralPath $extract -Recurse -Force | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 })
    if ($reparse.Count -ne 0) { throw 'Tor Expert Bundle extraction produced a symlink/reparse point; refusing runtime adoption.' }
    $torMatches = @(Get-ChildItem -LiteralPath $extract -Recurse -File -Filter 'tor.exe')
    $lyrebirdMatches = @(Get-ChildItem -LiteralPath $extract -Recurse -File -Filter 'lyrebird.exe')
    if ($torMatches.Count -ne 1) { throw "Tor Expert Bundle must contain exactly one tor.exe; found $($torMatches.Count)." }
    if ($lyrebirdMatches.Count -ne 1) { throw "Tor Expert Bundle must contain exactly one lyrebird.exe; found $($lyrebirdMatches.Count)." }
    $null = Invoke-RouterVPNTorHelperVersion $torMatches[0].FullName '--version' ('Tor version '+[regex]::Escape($ExpectedTorVersion)+'(?:[. ]|$)')
    $null = Invoke-RouterVPNTorHelperVersion $lyrebirdMatches[0].FullName '-version' '(?i)lyrebird'


    New-Item -ItemType Directory -Force -Path $RuntimeRoot | Out-Null
    $target = Join-Path $RuntimeRoot 'tor-expert'
    $stage = Join-Path $RuntimeRoot ('tor-expert.stage-'+[Guid]::NewGuid().ToString('N'))
    $backup = Join-Path $RuntimeRoot ('tor-expert.backup-'+[Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage | Out-Null
    Get-ChildItem -LiteralPath $extract -Force | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $stage -Recurse -Force }
    $movedOld = $false
    try {
      if (Test-Path -LiteralPath $target) { Move-Item -LiteralPath $target -Destination $backup; $movedOld = $true }
      Move-Item -LiteralPath $stage -Destination $target
      if ($movedOld -and (Test-Path -LiteralPath $backup)) { Remove-Item -LiteralPath $backup -Recurse -Force }
    } catch {
      if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue }
      if ($movedOld -and (Test-Path -LiteralPath $backup)) { Move-Item -LiteralPath $backup -Destination $target -ErrorAction SilentlyContinue }
      throw
    } finally {
      if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
    }

    $adoptedTor = @(Get-ChildItem -LiteralPath $target -Recurse -File -Filter 'tor.exe')
    $adoptedLyrebird = @(Get-ChildItem -LiteralPath $target -Recurse -File -Filter 'lyrebird.exe')
    if ($adoptedTor.Count -ne 1 -or $adoptedLyrebird.Count -ne 1) { throw 'Adopted Tor Expert Bundle lost tor.exe or lyrebird.exe.' }
    Write-Host "Pinned Windows Tor runtime ready: Tor $ExpectedTorVersion + Lyrebird from Expert Bundle $TorExpertVersion."
  } finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
  }
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
. (Join-Path $AppRoot 'client\Install-Bundled-Xray.ps1')
$Runtime = Join-Path $DataRoot 'runtime\windows'
$Prep = Join-Path $HelpersRoot 'Prepare-Windows-Mode-Catalog-v2.ps1'
$OpenVPNSetup = Join-Path $HelpersRoot 'Install-RouterVPN-OpenVPN.ps1'
if (-not (Test-Path -LiteralPath $Prep -PathType Leaf)) { throw "Missing Windows catalog helper: $Prep" }
if (-not (Test-Path -LiteralPath $OpenVPNSetup -PathType Leaf)) { throw "Missing OpenVPN setup helper: $OpenVPNSetup" }

$arch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
$TorHelpersAvailable = $false
switch ($arch) {
  'x64' {
    $sbAsset = "sing-box-$SingBoxVersion-windows-amd64.zip"
    $sbSha = 'e93fc531134eb1beb4efa3c74990a24e48456098a31c03b60d5ddf17f223cf98'
  }
  'arm64' {
    $sbAsset = "sing-box-$SingBoxVersion-windows-arm64.zip"
    $sbSha = 'e01560b07061fa79e67cb7dc8727ac5e3010fa9f93444ddaf0c014967f52a1b4'
  }
  default { throw "Unsupported Windows architecture: $arch" }
}
$torHelperExecution = ''
try {
  $torHelperExecution = Get-RouterVPNTorHelperExecution $arch
  $TorHelpersAvailable = $true
} catch {
  Write-Warning $_.Exception.Message
}
$sbUrl = "https://github.com/SagerNet/sing-box/releases/download/v$SingBoxVersion/$sbAsset"
Install-PinnedArchive "sing-box-$SingBoxVersion" $sbUrl $sbSha 'sing-box.exe' $Runtime @('*.dll')
Install-RouterVPNBundledXray -BundleRoot $AppRoot -Destination $Runtime -Architecture $arch
if ($TorHelpersAvailable) {
  $torUrl = "https://dist.torproject.org/torbrowser/$TorExpertVersion/tor-expert-bundle-windows-x86_64-$TorExpertVersion.tar.gz"
  Install-PinnedTorExpertBundle $torUrl $TorExpertWindowsX64Sha256 $TorVersion $Runtime
} else {
  Write-Host 'Tor helpers are unavailable because this Windows host did not prove x64 userspace execution support.'
}

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
$torStatus = if ($TorHelpersAvailable) { " + Tor $TorVersion/Lyrebird ($torHelperExecution)" } else { ' + Tor helpers unavailable on this Windows host' }
Write-Host "Router VPN native Windows runtime is ready: sing-box $SingBoxVersion + Xray $XrayVersion + OpenVPN 2.7.x$torStatus."
Write-Host 'No WSL is used. Reopen Router VPN so readiness checks re-evaluate the native modes and custom external nodes.'
