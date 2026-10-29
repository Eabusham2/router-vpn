param(
  [Parameter(Mandatory=$true)][ValidateSet('plan','check','prepare','tunnel','release','force-off','status')][string]$Action,
  [string]$Endpoint = '',
  [string]$TunnelAlias = '',
  [string]$Root = '',
  [ValidateSet('','off','on-connect','always')][string]$Policy = '',
  [ValidateSet('','true','false')][string]$HomeLANAccess = '',
  [string]$StateRoot = ''
)

$ErrorActionPreference = 'Stop'
$RuleGroup = 'Router VPN Kill Switch'
$RulePrefix = 'Router VPN Kill Switch - '

function Test-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Require-Administrator {
  if (-not (Test-Administrator)) { throw 'Strict Windows kill switch requires Administrator rights.' }
}
function Require-FirewallCmdlets {
  foreach ($name in @('Get-NetFirewallProfile','Set-NetFirewallProfile','New-NetFirewallRule','Get-NetFirewallRule','Remove-NetFirewallRule')) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) { throw "Missing Windows firewall primitive: $name" }
  }
}
function Assert-NoReparseAncestors([string]$Path) {
  $full = [IO.Path]::GetFullPath($Path)
  $cursor = if (Test-Path -LiteralPath $full) { $full } else { Split-Path -Parent $full }
  while ($cursor) {
    if (Test-Path -LiteralPath $cursor) {
      $item = Get-Item -LiteralPath $cursor -Force
      if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing reparse-point/junction kill-switch path component: $cursor"
      }
    }
    $parent = Split-Path -Parent $cursor
    if (-not $parent -or $parent -eq $cursor) { break }
    $cursor = $parent
  }
}
function Assert-SafeStateRoot {
  $dir = Get-StateRoot
  Assert-NoReparseAncestors $dir
  if (-not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Path $dir | Out-Null
  }
  $item = Get-Item -LiteralPath $dir -Force
  if (-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw "Windows kill-switch state root is not a real directory: $dir"
  }
  Assert-NoReparseAncestors $dir
  return $dir
}
function Assert-SafeStateLeaf([string]$Path) {
  Assert-NoReparseAncestors $Path
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  $item = Get-Item -LiteralPath $Path -Force
  if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw "Windows kill-switch state is not a regular non-reparse file: $Path"
  }
  if ($item.Length -gt 1048576) { throw "Windows kill-switch state exceeds safety limit: $Path" }
  return $item
}
function Read-SafeJsonFile([string]$Path,[string]$Label,[int]$Limit=1048576) {
  Assert-NoReparseAncestors $Path
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$Label is missing: $Path" }
  $before = Get-Item -LiteralPath $Path -Force
  if ($before.PSIsContainer -or (($before.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or $before.Length -gt $Limit) {
    throw "Unsafe or oversized $Label file: $Path"
  }
  $stream = [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  try {
    if ($stream.Length -gt $Limit) { throw "$Label exceeds safety limit: $Path" }
    $reader = New-Object IO.StreamReader($stream,(New-Object Text.UTF8Encoding($false)),$true,4096,$true)
    try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
    $after = Get-Item -LiteralPath $Path -Force
    if ($after.PSIsContainer -or (($after.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $after.FullName -ne $before.FullName -or $after.Length -ne $stream.Length -or
        $after.LastWriteTimeUtc -ne $before.LastWriteTimeUtc) {
      throw "$Label changed during read: $Path"
    }
  } finally {
    $stream.Dispose()
  }
  $trimmed=$text.Trim()
  if (-not $trimmed.StartsWith('{') -or -not $trimmed.EndsWith('}')) { throw "Invalid $Label JSON object: $Path" }
  try { return $text | ConvertFrom-Json } catch { throw "Invalid $Label JSON: $Path" }
}
function Safe-ProfileId([string]$Value) {
  if ([string]::IsNullOrWhiteSpace($Value)) { return 'router' }
  if ($Value -notmatch '^[A-Za-z0-9_.-]{1,128}$') { throw 'Invalid Router VPN profile id.' }
  return $Value
}
function Resolve-Root {
  if ($Root) { return [IO.Path]::GetFullPath($Root) }
  if ($env:HOMEVPN_ROOT) { return [IO.Path]::GetFullPath($env:HOMEVPN_ROOT) }
  throw 'HOMEVPN_ROOT is required for Windows kill-switch policy.'
}
function Get-StateRoot {
  if ($StateRoot) { return [IO.Path]::GetFullPath($StateRoot) }
  $programData = [string]$env:ProgramData
  if ([string]::IsNullOrWhiteSpace($programData)) { throw 'ProgramData is unavailable; cannot persist kill-switch rollback state.' }
  return Join-Path $programData 'RouterVPN\KillSwitch'
}
function Get-StatePath { return Join-Path (Get-StateRoot) 'windows-state.json' }
function Read-State {
  $dir = Assert-SafeStateRoot
  $path = Join-Path $dir 'windows-state.json'
  if (-not (Test-Path -LiteralPath $path)) { return $null }
  [void](Assert-SafeStateLeaf $path)
  $value=Read-SafeJsonFile $path 'Windows kill-switch rollback state'
  Assert-RollbackState $value
  return $value
}
function Write-State($Value) {
  Assert-RollbackState $Value
  $dir = Assert-SafeStateRoot
  $path = Join-Path $dir 'windows-state.json'
  $prior = Assert-SafeStateLeaf $path
  $tmp = Join-Path $dir ('.windows-state.'+[Guid]::NewGuid().ToString('N')+'.tmp')
  $backup = Join-Path $dir ('.windows-state.'+[Guid]::NewGuid().ToString('N')+'.bak')
  $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes((($Value | ConvertTo-Json -Depth 20) + "`n"))
  if ($bytes.Length -eq 0 -or $bytes.Length -gt 1048576) { throw 'Windows kill-switch state is empty or oversized.' }
  try {
    $stream = New-Object IO.FileStream($tmp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {
      $stream.Write($bytes,0,$bytes.Length)
      $stream.Flush($true)
    } finally { $stream.Dispose() }
    [void](Assert-SafeStateRoot)
    $current = Assert-SafeStateLeaf $path
    if ($prior -and -not $current) { throw 'Windows kill-switch state disappeared before adoption.' }
    if (-not $prior -and $current) { throw 'Windows kill-switch state appeared before adoption.' }
    if ($prior -and $current -and
        ($prior.Length -ne $current.Length -or $prior.LastWriteTimeUtc -ne $current.LastWriteTimeUtc)) {
      throw 'Windows kill-switch state changed before adoption.'
    }
    if ($current) {
      [IO.File]::Replace($tmp,$path,$backup,$true)
    } else {
      [IO.File]::Move($tmp,$path)
    }
  } finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
  }
}
function Remove-State {
  $dir = Assert-SafeStateRoot
  $path = Join-Path $dir 'windows-state.json'
  if (-not (Test-Path -LiteralPath $path)) { return }
  [void](Assert-SafeStateLeaf $path)
  Remove-Item -LiteralPath $path -Force
}
function Get-SelectedProfiles {
  $rootPath = Resolve-Root
  Assert-NoReparseAncestors $rootPath
  $storePath = Join-Path $rootPath 'routers.json'
  $store = Read-SafeJsonFile $storePath 'Router profile store' 4194304
  $selected = if ($env:HOMEVPN_PROFILE_ID) { Safe-ProfileId([string]$env:HOMEVPN_PROFILE_ID) } elseif ($store.selected_id) { Safe-ProfileId([string]$store.selected_id) } else { 'router' }
  $capturedPolicy = [Environment]::GetEnvironmentVariable('HOMEVPN_POLICY_PROFILE_ID','Process')
  $policyID = $selected
  if ($null -ne $capturedPolicy) {
    if ([string]::IsNullOrWhiteSpace($capturedPolicy) -or [string]::IsNullOrWhiteSpace($env:HOMEVPN_PROFILE_ID)) {
      throw 'Captured Windows kill-switch policy and runtime profile IDs are required.'
    }
    $policyID = Safe-ProfileId $capturedPolicy
  }
  $runtimeProfiles = @($store.profiles | Where-Object { $_ -and [string]$_.id -ceq $selected })
  $policyProfiles = @($store.profiles | Where-Object { $_ -and [string]$_.id -ceq $policyID })
  if ($runtimeProfiles.Count -ne 1) { throw "Captured runtime/entry profile '$selected' is missing or ambiguous." }
  if ($policyProfiles.Count -ne 1) { throw "Captured policy/control profile '$policyID' is missing or ambiguous." }
  # The physical entry supplies endpoint exceptions; the captured control/exit
  # owns kill-switch and LAN policy. Read both from the same private snapshot.
  return [pscustomobject]@{ runtime=$runtimeProfiles[0]; policy=$policyProfiles[0] }
}
function Parse-Bool([string]$Value,[bool]$Default) {
  if ([string]::IsNullOrWhiteSpace($Value)) { return $Default }
  return $Value.ToLowerInvariant() -eq 'true'
}
function Captured-EndpointAddresses([string]$Primary) {
  $raw = $env:HOMEVPN_NATIVE_ENDPOINTS_JSON
  if ($null -eq $raw) { if ($Primary) { return @($Primary) }; return @() }
  if ($raw.Length -gt 1024 -or $env:HOMEVPN_STANDARD_ENGINE -cne 'native' -or $env:HOMEVPN_EXTERNAL_SESSION -cnotmatch '^[a-f0-9]{32}$') {
    throw 'Native endpoint list has no captured external session.'
  }
  try {
    if (-not $raw.Trim().StartsWith('[') -or -not $raw.Trim().EndsWith(']')) { throw 'array required' }
    # PowerShell 5.1 returns a top-level JSON array as one pipeline object;
    # PowerShell 7 normally enumerates it. Read an object property to retain
    # exactly one array level on both. Validate the original JSON first so it
    # cannot inject another member into the private parsing wrapper.
    $null = ConvertFrom-Json -InputObject $raw
    $parsed = ConvertFrom-Json -InputObject ('{"endpoints":' + $raw + '}')
    $values = @($parsed.endpoints)
    if ($values.Count -lt 1 -or $values.Count -gt 16) { throw 'endpoint count' }
    $result = @()
    foreach ($value in $values) {
      $address = $null
      if ($value -isnot [string] -or -not [Net.IPAddress]::TryParse($value,[ref]$address) -or $address.ToString() -cne $value) { throw 'literal required' }
      if ([Net.IPAddress]::IsLoopback($address) -or $address.Equals([Net.IPAddress]::Any) -or $address.Equals([Net.IPAddress]::IPv6Any) -or $address.Equals([Net.IPAddress]::Broadcast)) { throw 'unicast required' }
      $bytes = $address.GetAddressBytes()
      if ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
        if ($address.IsIPv6Multicast -or $address.IsIPv6LinkLocal -or $address.IsIPv4MappedToIPv6 -or $address.ScopeId -ne 0) { throw 'unicast required' }
      } elseif (($bytes[0] -ge 224 -and $bytes[0] -le 239) -or ($bytes[0] -eq 169 -and $bytes[1] -eq 254)) { throw 'unicast required' }
      if ($result -ccontains $value) { throw 'duplicate endpoint' }
      $result += $value
    }
    if ($result[0] -cne $Primary) { throw 'physical entry changed' }
    return $result
  } catch { throw 'Native endpoint list must retain its captured literal physical remotes.' }
}
function Assert-NativeEgress($Items,[string[]]$Addresses) {
  $values=@($Items);$result=@();$seen=@{};$hosts=@{}
  if($values.Count-lt1-or$values.Count-gt16-or$Addresses.Count-lt1-or$Addresses.Count-gt16){throw 'Invalid captured native egress count.'}
  foreach($item in $values){
    if($null-eq$item-or$item-is[string]-or$item-is[Array]){throw 'Invalid captured native egress tuple.'}
    $names=@($item.PSObject.Properties.Name)
    if($names.Count-ne3-or@($names|Where-Object{$_-cnotin@('host','port','network')}).Count-ne0){throw 'Invalid captured native egress members.'}
    $address=$null
    if($item.host-isnot[string]-or$Addresses-cnotcontains$item.host-or-not[Net.IPAddress]::TryParse($item.host,[ref]$address)-or$address.ToString()-cne$item.host){throw 'Native egress host differs from captured physical remotes.'}
    if([Net.IPAddress]::IsLoopback($address)-or$address.Equals([Net.IPAddress]::Any)-or$address.Equals([Net.IPAddress]::IPv6Any)-or$address.Equals([Net.IPAddress]::Broadcast)){throw 'Native egress host must be unicast.'}
    $bytes=$address.GetAddressBytes()
    if($address.AddressFamily-eq[Net.Sockets.AddressFamily]::InterNetworkV6){
      if($address.IsIPv6Multicast-or$address.IsIPv6LinkLocal-or$address.IsIPv4MappedToIPv6-or$address.ScopeId-ne0){throw 'Native egress host must be unicast.'}
    }elseif(($bytes[0]-ge224-and$bytes[0]-le239)-or($bytes[0]-eq169-and$bytes[1]-eq254)){throw 'Native egress host must be unicast.'}
    if(($item.port-isnot[int]-and$item.port-isnot[long])-or$item.port-lt1-or$item.port-gt65535-or$item.network-cnotin@('tcp','udp')){throw 'Native egress requires an exact port and transport.'}
    $identity=$item.host+'|'+$item.port+'|'+$item.network
    if($seen.ContainsKey($identity)){throw 'Duplicate captured native egress tuple.'}
    $seen[$identity]=$true;$hosts[$item.host]=$true
    $result += [pscustomobject]@{host=[string]$item.host;port=[int]$item.port;network=[string]$item.network}
  }
  if($hosts.Count-ne$Addresses.Count){throw 'Native egress omitted a captured physical host.'}
  return $result
}
function Captured-NativeEgress([string[]]$Addresses) {
  $raw=$env:HOMEVPN_NATIVE_EGRESS_JSON
  if($null-eq$raw){return}
  if($raw.Length-gt4096-or$env:HOMEVPN_STANDARD_ENGINE-cne'native'-or$env:HOMEVPN_EXTERNAL_SESSION-cnotmatch'^[a-f0-9]{32}$'){throw 'Native egress has no captured external session.'}
  # Only the controller's canonical struct encoding reaches this environment.
  # An exact grammar rejects duplicate members before either PowerShell JSON
  # implementation can silently collapse them or change top-level array shape.
  $tuple='\{"host":"[0-9a-f:.]+","port":[1-9][0-9]{0,4},"network":"(?:tcp|udp)"\}'
  if(-not[regex]::IsMatch($raw,('\A\['+$tuple+'(?:,'+$tuple+')*\]\z'))){throw 'Native egress requires canonical captured tuples.'}
  $parsed=ConvertFrom-Json -InputObject ('{"egress":'+$raw+'}')
  return Assert-NativeEgress @($parsed.egress) $Addresses
}
function Resolve-Settings {
  $profile = $null
  $runtimeProfile = $null
  $capturedPolicy = [Environment]::GetEnvironmentVariable('HOMEVPN_POLICY_PROFILE_ID','Process')
  if ($null -ne $capturedPolicy -or -not $Endpoint -or -not $Policy -or -not $HomeLANAccess) {
    try {
      $selection = Get-SelectedProfiles
      $profile = $selection.policy
      $runtimeProfile = $selection.runtime
    } catch { if ($Action -ne 'plan' -or $null -ne $capturedPolicy) { throw } }
  }
  if ($null -ne $capturedPolicy) {
    if ([string]$profile.kill_switch_policy -cnotin @('off','on-connect','always')) { throw 'Captured Windows kill-switch owner has no valid policy.' }
    if ($Policy -and $Policy -cne [string]$profile.kill_switch_policy) { throw 'Explicit policy differs from its captured Windows kill-switch owner.' }
    if ($HomeLANAccess -and (Parse-Bool $HomeLANAccess $false) -ne [bool]$profile.home_lan_access) { throw 'Explicit LAN policy differs from its captured Windows kill-switch owner.' }
  }
  $effectiveEndpoint = if ($Endpoint) { $Endpoint } elseif ($env:HOMEVPN_ENDPOINT) { [string]$env:HOMEVPN_ENDPOINT } elseif ($runtimeProfile) { [string]$runtimeProfile.endpoint } else { '' }
  $effectivePolicy = if ($Policy) { $Policy } elseif ($profile -and $profile.kill_switch_policy) { [string]$profile.kill_switch_policy } else { 'off' }
  if ($effectivePolicy -cnotin @('off','on-connect','always')) { throw 'Unsupported captured Windows kill-switch policy.' }
  $effectiveLAN = if ($HomeLANAccess) { Parse-Bool $HomeLANAccess $false } elseif ($profile) { [bool]$profile.home_lan_access } else { $false }
  $ip = $null
  if ($effectivePolicy -ne 'off' -and -not [System.Net.IPAddress]::TryParse($effectiveEndpoint.Trim().Trim('[',']'), [ref]$ip)) {
    throw 'Strict Windows kill switch requires the selected Router VPN endpoint to be a literal IPv4/IPv6 address; a hostname would require pre-tunnel DNS.'
  }
  $settings=[pscustomobject]@{
    endpoint = $effectiveEndpoint.Trim().Trim('[',']')
    endpoint_ips = @(Captured-EndpointAddresses $effectiveEndpoint.Trim().Trim('[',']'))
    policy = $effectivePolicy
    home_lan_access = $effectiveLAN
    tunnel_alias = $TunnelAlias
  }
  if($null-ne$env:HOMEVPN_NATIVE_EGRESS_JSON){$settings|Add-Member -NotePropertyName native_egress -NotePropertyValue @(Captured-NativeEgress @($settings.endpoint_ips))}
  return $settings
}
function Firewall-Profiles {
  return @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Where-Object { $_.Name -in @('Domain','Private','Public') } | ForEach-Object {
    [pscustomobject]@{ name=[string]$_.Name; default_outbound=[string]$_.DefaultOutboundAction }
  })
}
function Assert-OriginalProfiles($Profiles) {
  if ($Profiles -isnot [array] -or $Profiles.Count -ne 3) {
    throw 'Windows kill-switch rollback requires all three captured firewall profiles.'
  }
  $seen=@{}
  foreach ($profile in $Profiles) {
    if ($profile -isnot [pscustomobject] -or $profile.name -isnot [string] -or
        $profile.name -cnotin @('Domain','Private','Public') -or $seen.ContainsKey($profile.name) -or
        $profile.default_outbound -isnot [string] -or $profile.default_outbound -cnotin @('Allow','Block','NotConfigured')) {
      throw 'Windows kill-switch rollback contains an invalid or duplicate captured firewall profile.'
    }
    $seen[$profile.name]=$true
  }
}
function Assert-RollbackState($Value) {
  if ($Value -isnot [pscustomobject] -or
      ($Value.schema_version -isnot [int] -and $Value.schema_version -isnot [long]) -or $Value.schema_version -ne 1 -or
      $Value.policy -isnot [string] -or $Value.policy -cnotin @('on-connect','always') -or
      $Value.phase -isnot [string] -or $Value.phase -cnotin @('preparing','active')) {
    throw 'Windows kill-switch rollback state has no valid captured policy or phase.'
  }
  Assert-OriginalProfiles $Value.original_profiles
}
function Get-ManagedRules {
  # Query the inventory so an empty group is distinct from a failed query.
  # A failed or partial removal must retain the rollback record for retry.
  $rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop)
  if ($rules.Count -gt 65536) { throw 'Windows firewall inventory exceeds its recovery bound.' }
  return @($rules | Where-Object { [string]$_.Group -ceq $RuleGroup })
}
function Remove-Rules {
  $rules=@(Get-ManagedRules)
  if ($rules.Count -gt 0) { $rules | Remove-NetFirewallRule -ErrorAction Stop }
  if (@(Get-ManagedRules).Count -ne 0) { throw 'Windows kill-switch rule removal was not proved; rollback state is retained.' }
}
function Add-Rule([string]$Name,[hashtable]$RuleArguments) {
  $params = @{ DisplayName = $RulePrefix + $Name; Group = $RuleGroup; Direction='Outbound'; Action='Allow'; Profile='Any' }
  foreach ($key in $RuleArguments.Keys) { $params[$key] = $RuleArguments[$key] }
  New-NetFirewallRule @params | Out-Null
}
function Install-AllowRules($settings) {
  $restricted=$null
  if($null-ne$settings.PSObject.Properties['native_egress']){$restricted=@(Assert-NativeEgress $settings.native_egress @($settings.endpoint_ips))}
  Remove-Rules
  if($null-ne$restricted){
    for($index=0;$index-lt$restricted.Count;$index++){
      $tuple=$restricted[$index];Add-Rule ('native outer '+$index) @{RemoteAddress=@($tuple.host);RemotePort=[string]$tuple.port;Protocol=$tuple.network.ToUpperInvariant()}
    }
  }elseif ($settings.endpoint_ips.Count -gt 0) { Add-Rule 'selected node' @{ RemoteAddress=@($settings.endpoint_ips) } }
  Add-Rule 'loopback' @{ RemoteAddress=@('127.0.0.1','::1') }
  Add-Rule 'DHCPv4' @{ Protocol='UDP'; LocalPort='68'; RemotePort='67' }
  Add-Rule 'IPv6 link maintenance' @{ Protocol='ICMPv6'; IcmpType=@('133','134','135','136') }
  if ($settings.home_lan_access) { Add-Rule 'private LAN' @{ RemoteAddress='LocalSubnet' } }
  if ($settings.tunnel_alias) { Add-Rule 'VPN interface' @{ InterfaceAlias=$settings.tunnel_alias } }
}
function Restore-State($state) {
  if ($null -eq $state) {
    if (@(Get-ManagedRules).Count -ne 0) {
      throw 'Windows kill-switch rules exist without their captured rollback state; firewall defaults remain unchanged.'
    }
    return
  }
  Assert-RollbackState $state
  Remove-Rules
  foreach ($profile in @($state.original_profiles)) {
    Set-NetFirewallProfile -Name $profile.name -DefaultOutboundAction $profile.default_outbound -ErrorAction Stop
  }
  $actual=@(Firewall-Profiles)
  Assert-OriginalProfiles $actual
  foreach ($profile in @($state.original_profiles)) {
    $readback=@($actual | Where-Object { $_.name -ceq $profile.name })
    if ($readback.Count -ne 1 -or $readback[0].default_outbound -cne $profile.default_outbound) {
      throw 'Windows firewall restoration readback differs from its captured policy; rollback state is retained.'
    }
  }
  Remove-State
}
function Assert-Blocked {
  foreach ($profile in @(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object { $_.Name -in @('Domain','Private','Public') })) {
    if ([string]$profile.DefaultOutboundAction -ne 'Block') { throw "Windows firewall profile $($profile.Name) did not enter DefaultOutboundAction=Block." }
  }
}

# Rollback/recovery actions are owned by the persisted firewall state itself and
# must not depend on whichever Router VPN profile happens to be selected now.
$settings = $null
if ($Action -in @('plan','check','prepare')) { $settings = Resolve-Settings }

if ($Action -cne 'plan') {
  $privateState=Join-Path $PSScriptRoot 'Private-RouterVPN-State.ps1'
  $ownedProtection=Join-Path $PSScriptRoot 'Private-RouterVPN-Protection.ps1'
  foreach ($helper in @($privateState,$ownedProtection)) {
    Assert-NoReparseAncestors $helper
    if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) { throw 'Native Windows protection adapter is missing.' }
  }
  . $privateState
  . $ownedProtection
  $selectedPolicy=if ($null -ne $settings) { [string]$settings.policy } else { '' }
  # This occurs outside legacy emergency recovery: a failed/denied native
  # readback must never enter the old global-profile rollback fallback.
  $handoff=Invoke-RouterVPNOwnedProtectionHandoff -Action $Action -ClientDirectory $PSScriptRoot -Policy $selectedPolicy
  if ($handoff.handled) {
    $handoff.status | ConvertTo-Json -Compress
    if ($Action -ceq 'status' -and -not $handoff.status.active) { exit 1 }
    exit 0
  }
}

switch ($Action) {
  'plan' {
    $plan=[pscustomobject]@{
      policy = $settings.policy
      endpoint = $settings.endpoint
      endpoint_ips = @($settings.endpoint_ips)
      home_lan_access = $settings.home_lan_access
      tunnel_alias = $settings.tunnel_alias
      default_outbound = if ($settings.policy -eq 'off') { 'unchanged' } else { 'Block' }
      rule_group = $RuleGroup
      state_path = Get-StatePath
    }
    if($null-ne$settings.PSObject.Properties['native_egress']){$plan|Add-Member -NotePropertyName native_egress -NotePropertyValue @($settings.native_egress)}
    $plan | ConvertTo-Json -Depth 8
    exit 0
  }
  'check' {
    if ($settings.policy -eq 'off') { Write-Output 'Windows kill switch policy is off.'; exit 0 }
    Require-Administrator
    Require-FirewallCmdlets
    Write-Output "Strict Windows kill switch ready for $($settings.endpoint)."
    exit 0
  }
  'prepare' {
    if ($settings.policy -eq 'off') {
      $existing = Read-State
      if ($existing) { Require-Administrator; Require-FirewallCmdlets; Restore-State $existing }
      Write-Output 'Windows kill switch disabled.'
      exit 0
    }
    Require-Administrator
    Require-FirewallCmdlets
    $existing = Read-State
    $original = if ($existing -and $existing.original_profiles) { @($existing.original_profiles) } else { Firewall-Profiles }
    $state = [pscustomobject]@{
      schema_version = 1
      policy = $settings.policy
      endpoint = $settings.endpoint
      endpoint_ips = @($settings.endpoint_ips)
      home_lan_access = $settings.home_lan_access
      tunnel_alias = $settings.tunnel_alias
      phase = 'preparing'
      original_profiles = $original
      updated_at = [DateTime]::UtcNow.ToString('o')
    }
    if($null-ne$settings.PSObject.Properties['native_egress']){$state|Add-Member -NotePropertyName native_egress -NotePropertyValue @($settings.native_egress)}
    Write-State $state
    try {
      Install-AllowRules $settings
      foreach ($name in @('Domain','Private','Public')) { Set-NetFirewallProfile -Name $name -DefaultOutboundAction Block }
      Assert-Blocked
      $state.phase = 'active'
      $state.updated_at = [DateTime]::UtcNow.ToString('o')
      Write-State $state
    } catch {
      try { Restore-State $state } catch { }
      throw
    }
    Write-Output "Strict Windows kill switch $($settings.policy) active."
    exit 0
  }
  'tunnel' {
    Require-Administrator
    Require-FirewallCmdlets
    $state = Read-State
    if (-not $state) { throw 'Cannot allow a VPN interface because no Windows kill-switch state is active.' }
    if (-not $TunnelAlias) { throw 'TunnelAlias is required.' }
    Add-Rule 'VPN interface' @{ InterfaceAlias=$TunnelAlias }
    $state.tunnel_alias = $TunnelAlias
    $state.updated_at = [DateTime]::UtcNow.ToString('o')
    Write-State $state
    exit 0
  }
  'release' {
    $state = Read-State
    if (-not $state) { exit 0 }
    if ([string]$state.policy -eq 'always') { Write-Output 'Windows kill switch remains active because policy=always.'; exit 0 }
    Require-Administrator
    Require-FirewallCmdlets
    Restore-State $state
    Write-Output 'Windows kill switch released.'
    exit 0
  }
  'force-off' {
    Require-Administrator
    Require-FirewallCmdlets
    try {
      $state = Read-State
      Restore-State $state
    } catch {
      # Missing/corrupt recovery authority cannot reveal the user's prior
      # firewall defaults. Never invent Allow, discard the record, or report
      # Off after failed mutation/readback. A valid retained record can retry.
      throw ('Windows kill-switch recovery was not proved; preserve the rollback record and existing firewall policy. '+$_.Exception.Message)
    }
    Write-Output 'Windows kill switch force-disabled.'
    exit 0
  }
  'status' {
    $state = Read-State
    if (-not $state) { [pscustomobject]@{active=$false;policy='off'} | ConvertTo-Json; exit 1 }
    $active = $false
    try {
      Require-FirewallCmdlets
      $active = (@(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object { $_.Name -in @('Domain','Private','Public') -and [string]$_.DefaultOutboundAction -eq 'Block' }).Count -eq 3)
    } catch { }
    [pscustomobject]@{ active=$active; policy=$state.policy; endpoint=$state.endpoint; tunnel_alias=$state.tunnel_alias; phase=$state.phase } | ConvertTo-Json
    if ($active) { exit 0 } else { exit 1 }
  }
}
