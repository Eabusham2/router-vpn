param(
  [Parameter(Mandatory=$true)][string]$PackagesDir,
  [Parameter(Mandatory=$true)][string]$OutDir
)

$ErrorActionPreference = 'Stop'
$InstallerVersion = '3.9.18'
$InstallerSHA256 = '8dc84002f08ae7bf31dd2f422f6f173b6b8ba2371fd508a9876e13f2eb6ef75a'
$InstallerURL = "https://downloads.sourceforge.net/project/portableapps/PortableApps.com%20Installer/PortableApps.comInstaller_$InstallerVersion.paf.exe"

function Wait-ProcessOrFail([System.Diagnostics.Process]$Process, [int]$TimeoutMs, [string]$What) {
  if (-not $Process.WaitForExit($TimeoutMs)) {
    try { $Process.Kill($true) } catch {}
    throw "$What timed out after $([int]($TimeoutMs/1000)) seconds"
  }
  if ($Process.ExitCode -ne 0) {
    throw "$What exited with code $($Process.ExitCode)"
  }
}

function Run-PortableSelfTest([string]$Launcher) {
  $p = Start-Process $Launcher -ArgumentList '--self-test' -PassThru
  Wait-ProcessOrFail $p 90000 "Router VPN Portable self-test ($Launcher)"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$work = Join-Path $env:RUNNER_TEMP 'router-vpn-paf'
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $work | Out-Null

$installerPaf = Join-Path $work "PortableApps.comInstaller_$InstallerVersion.paf.exe"
& curl.exe -L --fail --retry 5 --retry-delay 2 $InstallerURL -o $installerPaf
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $installerPaf)) {
  throw 'Could not download the official PortableApps.com Installer'
}
$actualHash = (Get-FileHash -Algorithm SHA256 $installerPaf).Hash.ToLowerInvariant()
if ($actualHash -ne $InstallerSHA256) {
  throw "PortableApps.com Installer SHA256 mismatch: $actualHash"
}
Write-Host "Verified official PortableApps.com Installer $InstallerVersion ($actualHash)"

# Do not run the Installer PAF's interactive bootstrap in CI. A PAF is an NSIS/
# 7-Zip-extractable package; extract the already-hash-verified official package
# and invoke its command-line packager directly. This avoids a GUI bootstrap
# hanging on a headless GitHub Windows runner while still using the official
# PortableApps.comInstaller.exe bits unchanged.
$toolDestination = Join-Path $work 'PortableAppsTools'
New-Item -ItemType Directory -Force -Path $toolDestination | Out-Null
$sevenZip = (Get-Command 7z.exe -ErrorAction SilentlyContinue).Source
if (-not $sevenZip) {
  $candidates = @(
    "$env:ProgramFiles\7-Zip\7z.exe",
    "$env:ProgramFiles(x86)\7-Zip\7z.exe"
  )
  $sevenZip = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
}
if (-not $sevenZip) { throw '7-Zip is required on the Windows CI runner to extract the verified PortableApps.com Installer PAF' }
& $sevenZip x -y "-o$toolDestination" $installerPaf | Out-Host
if ($LASTEXITCODE -ne 0) { throw "7-Zip could not extract the verified PortableApps.com Installer PAF (exit $LASTEXITCODE)" }
$generator = Get-ChildItem $toolDestination -Recurse -Filter 'PortableApps.comInstaller.exe' -File |
  Where-Object { $_.FullName -notmatch '\\Other\\Source\\' } |
  Select-Object -First 1
if (-not $generator) {
  Write-Host 'Extracted PortableApps tool tree:'
  Get-ChildItem $toolDestination -Recurse -File | Select-Object -ExpandProperty FullName | Out-Host
  throw 'PortableApps.comInstaller.exe was not found inside the verified official PAF'
}
Write-Host "Using official PortableApps.com Installer packager: $($generator.FullName)"

foreach ($arch in @('amd64','arm64')) {
  $zip = Get-ChildItem $PackagesDir -Recurse -Filter "RouterVPNPortable-$arch.zip" -File | Select-Object -First 1
  if (-not $zip) { throw "Missing PortableApps source ZIP for $arch" }

  $sourceParent = Join-Path $work "source-$arch"
  Remove-Item $sourceParent -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force -Path $sourceParent | Out-Null
  Expand-Archive -Path $zip.FullName -DestinationPath $sourceParent -Force
  $sourceRoot = Get-ChildItem $sourceParent -Directory | Select-Object -First 1
  if (-not $sourceRoot) { throw "PortableApps source root missing for $arch" }

  $appInfo = Join-Path $sourceRoot.FullName 'App\AppInfo\appinfo.ini'
  if (-not (Test-Path $appInfo)) { throw "appinfo.ini missing for $arch" }
  $appInfoText = Get-Content $appInfo -Raw
  foreach ($required in @(
    'Type=PortableApps.comFormat',
    'Version=3.9',
    'Start=RouterVPNPortable.exe',
    'RemoveDataDirectory=false'
  )) {
    if ($required -eq 'RemoveDataDirectory=false') {
      $installerIni = Get-Content (Join-Path $sourceRoot.FullName 'App\AppInfo\installer.ini') -Raw
      if ($installerIni -notmatch [regex]::Escape($required)) { throw "PortableApps installer.ini missing $required for $arch" }
    } elseif ($appInfoText -notmatch [regex]::Escape($required)) {
      throw "PortableApps appinfo.ini missing $required for $arch"
    }
  }

  Write-Host "Generating official PAF for $arch from $($sourceRoot.FullName)"
  $before = Get-Date
  $gen = Start-Process $generator.FullName -ArgumentList @($sourceRoot.FullName) -WorkingDirectory $sourceParent -PassThru
  Wait-ProcessOrFail $gen 240000 "PortableApps PAF generation ($arch)"

  # The official packager normally writes beside the source directory. Search
  # both the source parent and the generator's tree so a minor output-location
  # difference across installer versions cannot produce a false negative.
  $paf = @(
    Get-ChildItem $sourceParent -Recurse -Filter '*.paf.exe' -File -ErrorAction SilentlyContinue
    Get-ChildItem $toolDestination -Recurse -Filter '*.paf.exe' -File -ErrorAction SilentlyContinue
  ) |
    Where-Object { $_.LastWriteTime -ge $before.AddSeconds(-2) -and $_.FullName -ne $installerPaf } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
  if (-not $paf) {
    Write-Host 'Source parent after PortableApps generation:'
    Get-ChildItem $sourceParent -Recurse | Select-Object FullName,Length,LastWriteTime | Format-Table -AutoSize | Out-Host
    throw "PortableApps.com Installer completed but did not produce a .paf.exe for $arch"
  }
  $outPaf = Join-Path $OutDir "RouterVPNPortable-$arch`_0.7.0.paf.exe"
  Copy-Item $paf.FullName $outPaf -Force
  Write-Host "Built $outPaf"

  if ($arch -eq 'amd64') {
    $installParent = Join-Path $work 'installed-paf-amd64'
    Remove-Item $installParent -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $installParent | Out-Null

    $install = Start-Process $outPaf -ArgumentList @('/S', "/DESTINATION=$installParent\") -PassThru
    Wait-ProcessOrFail $install 120000 'Router VPN PortableApps install'
    $launcher = Get-ChildItem $installParent -Recurse -Filter 'RouterVPNPortable.exe' -File |
      Where-Object { $_.FullName -notmatch '\\App\\RouterVPN\\' } |
      Select-Object -First 1
    if (-not $launcher) {
      Write-Host 'Installed PAF tree:'
      Get-ChildItem $installParent -Recurse | Select-Object -ExpandProperty FullName | Out-Host
      throw 'Installed PAF did not contain RouterVPNPortable.exe'
    }
    Run-PortableSelfTest $launcher.FullName

    $installedRoot = Split-Path -Parent $launcher.FullName
    $marker = Join-Path $installedRoot 'Data\portableapps-upgrade-preserve.txt'
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $marker) | Out-Null
    Set-Content -Path $marker -Value 'preserve-me' -NoNewline

    $upgrade = Start-Process $outPaf -ArgumentList @('/S', "/DESTINATION=$installParent\") -PassThru
    Wait-ProcessOrFail $upgrade 120000 'Router VPN PortableApps upgrade'
    if (-not (Test-Path $marker) -or (Get-Content $marker -Raw) -ne 'preserve-me') {
      throw 'PortableApps upgrade did not preserve Data'
    }
    Run-PortableSelfTest $launcher.FullName
  }
}

Get-ChildItem $OutDir -Filter '*.paf.exe' | ForEach-Object {
  $hash = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLowerInvariant()
  Write-Host "$hash  $($_.Name)"
}
