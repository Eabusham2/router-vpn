function Get-RouterVPNStandardEngine([string]$Root) {
  $engine = [string]$env:HOMEVPN_STANDARD_ENGINE
  if ([string]::IsNullOrEmpty($engine) -or $engine -ceq 'stock') {
    return (Join-Path $Root 'runtime\windows\sing-box.exe')
  }
  if ($engine -cne 'amnezia' -and $engine -cne 'native') { throw 'Unknown captured standard-node engine.' }
  $controller = [string]$env:HOMEVPN_AMNEZIA_CONTROLLER
  $package = [string]$env:HOMEVPN_AMNEZIA_PACKAGE
  $verify = '--verify-amnezia-runtime'
  if ($engine -ceq 'native') {
    $controller = [string]$env:HOMEVPN_NATIVE_CONTROLLER
    $package = [string]$env:HOMEVPN_NATIVE_PACKAGE
    $verify = '--verify-native-runtime'
  }
  if ([string]::IsNullOrEmpty($controller) -or [string]::IsNullOrEmpty($package)) {
    throw 'Captured native controller/package is missing.'
  }
  Assert-RouterVPNNoReparseAncestors $controller
  Assert-RouterVPNNoReparseAncestors $package
  if (-not (Test-Path -LiteralPath $controller -PathType Leaf)) { throw 'Captured native controller is missing.' }
  $result = @(& $controller $verify $package)
  if ($LASTEXITCODE -ne 0 -or $result.Count -ne 1) { throw 'Native engine verification failed.' }
  $binary = [string]$result[0]
  Assert-RouterVPNNoReparseAncestors $binary
  if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw 'Verified native executable is missing.' }
  return $binary
}
