# Native protection belongs to BFE's captured owner, not a profile selection or
# a mutable rollback file. This adapter invokes only the package's fixed
# controller utility; it never adds firewall rules or changes profile defaults.

function ConvertFrom-RouterVPNOwnedProtectionStatus([string]$Text) {
  if ([string]::IsNullOrEmpty($Text) -or $Text.Length -gt 4096) {
    throw 'Native Windows protection returned an empty or oversized status.'
  }
  # The Go encoder's exact struct grammar rejects duplicate members, omitted
  # members, type coercion and extra output on both PowerShell 5.1 and 7.
  $grammar='\A\{"schema":1,"active":(?:true|false),"policy":"(?:off|on-connect|always|)","phase":"(?:off|owned|retained|preparing|transition)"\}\z'
  if (-not [regex]::IsMatch($Text,$grammar)) {
    throw 'Native Windows protection returned an invalid status record.'
  }
  $value=ConvertFrom-Json -InputObject $Text
  if ($value.phase -ceq 'off') {
    if ($value.active -or $value.policy -cne 'off') { throw 'Native Windows protection Off status is inconsistent.' }
  } elseif ($value.phase -ceq 'preparing') {
    if (-not $value.active -or $value.policy -cne '') { throw 'Native Windows protection preparation status is inconsistent.' }
  } elseif (-not $value.active -or $value.policy -cnotin @('on-connect','always')) {
    throw 'Native Windows protection ownership status is inconsistent.'
  }
  return $value
}

function ConvertFrom-RouterVPNProtectionProbe([string]$Text) {
  if ($null -eq $Text -or -not [regex]::IsMatch($Text,'\A\{"schema":1,"absent":(?:true|false)\}\z')) {
    throw 'Native Windows protection returned an invalid absence observation.'
  }
  return ConvertFrom-Json -InputObject $Text
}

function Test-RouterVPNProtectionElevated {
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  $principal=New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-RouterVPNOwnedWindowsProtection {
  param(
    [Parameter(Mandatory=$true)][string]$ClientDirectory,
    [Parameter(Mandatory=$true)][ValidateSet('probe','status','release','force-off')][string]$Operation
  )
  if (-not (Get-Command Assert-RouterVPNNoReparseAncestors -CommandType Function -ErrorAction SilentlyContinue)) {
    throw 'Router VPN private-state validation is unavailable.'
  }
  $client=[IO.Path]::GetFullPath($ClientDirectory)
  Assert-RouterVPNNoReparseAncestors $client
  if (-not (Test-Path -LiteralPath $client -PathType Container) -or
      (Split-Path -Leaf $client) -ine 'client') {
    throw 'Native Windows protection requires its real package client directory.'
  }
  # Portable stores private state in Data but its executable in App/RouterVPN.
  # Never select a controller from HOMEVPN_ROOT, PATH or a mutable override.
  $controller=Join-Path (Split-Path -Parent $client) 'router-vpn-client.exe'
  Assert-RouterVPNNoReparseAncestors $controller
  $before=Get-Item -LiteralPath $controller -Force -ErrorAction Stop
  if ($before.PSIsContainer -or ($before.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
      $before.Length -le 0 -or $before.Length -gt 536870912) {
    throw 'Native Windows protection controller is not a bounded regular package file.'
  }
  $held=[IO.File]::Open($controller,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  try {
    Assert-RouterVPNNoReparseAncestors $controller
    $opened=Get-Item -LiteralPath $controller -Force -ErrorAction Stop
    if ($opened.FullName -cne $before.FullName -or $opened.Length -ne $held.Length -or
        $opened.LastWriteTimeUtc -ne $before.LastWriteTimeUtc) {
      throw 'Native Windows protection controller changed during capture.'
    }
    # Its utility dispatcher runs before catalog/config initialization and
    # accepts no root, profile, interface, PID, filename or firewall object.
    $output=@(& $controller '--windows-physical-protection' $Operation)
    $code=$LASTEXITCODE
    if ($code -ne 0) { throw "Native Windows protection $Operation failed (exit $code)." }
    if ($output.Count -ne 1 -or $output[0] -isnot [string]) {
      throw 'Native Windows protection returned more than one status record.'
    }
    $value=if ($Operation -ceq 'probe') {
      ConvertFrom-RouterVPNProtectionProbe $output[0]
    } else { ConvertFrom-RouterVPNOwnedProtectionStatus $output[0] }
    $after=Get-Item -LiteralPath $controller -Force -ErrorAction Stop
    if ($after.FullName -cne $before.FullName -or $after.Length -ne $held.Length -or
        $after.LastWriteTimeUtc -ne $before.LastWriteTimeUtc -or
        ($after.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw 'Native Windows protection controller changed during execution.'
    }
    return $value
  } finally { $held.Dispose() }
}

function Get-RouterVPNLegacyProtectionStatePath {
  $directory=[Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
  if ([string]::IsNullOrWhiteSpace($directory)) { throw 'Windows common application data is unavailable.' }
  # Legacy versions selected this path from ProgramData. Refuse ambiguous
  # overrides instead of missing an old baseline or trusting another tree.
  $ambient=[Environment]::GetEnvironmentVariable('ProgramData','Process')
  if (-not [string]::IsNullOrWhiteSpace($ambient) -and
      -not [string]::Equals([IO.Path]::GetFullPath($ambient),[IO.Path]::GetFullPath($directory),[StringComparison]::OrdinalIgnoreCase)) {
    throw 'Legacy Windows protection has an ambiguous ProgramData location.'
  }
  return Join-Path (Join-Path (Join-Path $directory 'RouterVPN') 'KillSwitch') 'windows-state.json'
}

function Get-RouterVPNLegacyWindowsProtection {
  $path=Get-RouterVPNLegacyProtectionStatePath
  Assert-RouterVPNNoReparseAncestors $path
  $state=Test-Path -LiteralPath $path
  if ($state) {
    $leaf=Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($leaf.PSIsContainer -or ($leaf.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $leaf.Length -gt 1048576) {
      throw 'Legacy Windows protection state is not a bounded regular file; explicit recovery is required.'
    }
    # Its contents cannot authorize native WFP takeover. Even corrupt legacy
    # JSON remains an existing owner until the explicit legacy recovery path.
  }
  if (-not (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
    throw 'Cannot inspect existing Windows firewall ownership.'
  }
  $rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop)
  if ($rules.Count -gt 65536) { throw 'Windows firewall inventory exceeds its ownership inspection bound.' }
  $owned=@($rules | Where-Object { [string]$_.Group -ceq 'Router VPN Kill Switch' })
  return [pscustomobject]@{active=([bool]$state -or $owned.Count -gt 0);state_present=[bool]$state;rule_count=$owned.Count}
}

function Assert-RouterVPNNoLegacyWindowsProtection {
  $legacy=Get-RouterVPNLegacyWindowsProtection
  if ($legacy.active) {
    throw 'An existing Router VPN firewall baseline must be disconnected and explicitly turned Off or recovered before native owned protection starts.'
  }
}

function Invoke-RouterVPNOwnedProtectionHandoff {
  param(
    [Parameter(Mandatory=$true)][ValidateSet('check','prepare','tunnel','release','force-off','status')][string]$Action,
    [Parameter(Mandatory=$true)][string]$ClientDirectory,
    [ValidateSet('','off','on-connect','always')][string]$Policy=''
  )
  if (-not (Test-RouterVPNProtectionElevated)) {
    # An ordinary Off check/release previously needed no elevation. Preserve
    # only that no-op path, without treating access denied as Off or allowing a
    # partial/non-transactional observation to authorize any native mutation.
    if ($Action -cne 'release' -and -not ($Action -cin @('check','prepare') -and $Policy -ceq 'off')) {
      throw 'Native Windows protection inspection requires Administrator rights.'
    }
    foreach ($name in @('HOMEVPN_TOR_SESSION','HOMEVPN_EXTERNAL_SESSION','HOMEVPN_MULTIHOP_SESSION','HOMEVPN_NODE_SESSION')) {
      if (-not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($name,'Process'))) {
        throw 'A captured native session requires elevated Windows protection inspection.'
      }
    }
    $observation=Invoke-RouterVPNOwnedWindowsProtection -ClientDirectory $ClientDirectory -Operation probe
    if (-not $observation.absent) {
      throw 'Existing or preparing native Windows protection requires elevated authoritative inspection.'
    }
    # No authoritative status is fabricated from this observation. Returning
    # unhandled permits only the existing no-op legacy path for this caller;
    # all actual legacy state changes retain their own elevation requirement.
    return [pscustomobject]@{handled=$false;status=$null}
  }
  $native=Invoke-RouterVPNOwnedWindowsProtection -ClientDirectory $ClientDirectory -Operation status
  if (-not $native.active) { return [pscustomobject]@{handled=$false;status=$native} }
  $legacy=Get-RouterVPNLegacyWindowsProtection
  if ($legacy.active) {
    throw 'Native and legacy Windows protection both exist; retain both owners and resolve the existing protection explicitly.'
  }
  switch ($Action) {
    'status' { return [pscustomobject]@{handled=$true;status=$native} }
    'release' {
      $value=Invoke-RouterVPNOwnedWindowsProtection -ClientDirectory $ClientDirectory -Operation release
      return [pscustomobject]@{handled=$true;status=$value}
    }
    'force-off' {
      $value=Invoke-RouterVPNOwnedWindowsProtection -ClientDirectory $ClientDirectory -Operation force-off
      return [pscustomobject]@{handled=$true;status=$value}
    }
    'prepare' {
      if ($Policy -ceq 'off') {
        $value=Invoke-RouterVPNOwnedWindowsProtection -ClientDirectory $ClientDirectory -Operation force-off
        return [pscustomobject]@{handled=$true;status=$value}
      }
    }
    'check' {
      if ($Policy -ceq 'off') { return [pscustomobject]@{handled=$true;status=$native} }
    }
  }
  throw 'Existing native Windows protection cannot be adopted by a legacy tunnel or endpoint rule; disconnect and explicitly turn protection Off before switching this path.'
}
