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
  return Read-SafeJsonFile $path 'Windows kill-switch rollback state'
}
function Write-State($Value) {
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
function Remove-State([switch]$ForceRecovery) {
  $dir = Assert-SafeStateRoot
  $path = Join-Path $dir 'windows-state.json'
  if (-not (Test-Path -LiteralPath $path)) { return }
  try {
    [void](Assert-SafeStateLeaf $path)
  } catch {
    if (-not $ForceRecovery) { throw }
  }
  Remove-Item -LiteralPath $path -Force
}
function Get-SelectedProfile {
  $rootPath = Resolve-Root
  Assert-NoReparseAncestors $rootPath
  $storePath = Join-Path $rootPath 'routers.json'
  $store = Read-SafeJsonFile $storePath 'Router profile store' 4194304
  $selected = if ($env:HOMEVPN_PROFILE_ID) { Safe-ProfileId([string]$env:HOMEVPN_PROFILE_ID) } elseif ($store.selected_id) { Safe-ProfileId([string]$store.selected_id) } else { 'router' }
  foreach ($item in @($store.profiles)) { if ($item -and [string]$item.id -eq $selected) { return $item } }
  throw "Selected Router VPN profile '$selected' was not found."
}
function Parse-Bool([string]$Value,[bool]$Default) {
  if ([string]::IsNullOrWhiteSpace($Value)) { return $Default }
  return $Value.ToLowerInvariant() -eq 'true'
}
function Resolve-Settings {
  $profile = $null
  if (-not $Endpoint -or -not $Policy -or -not $HomeLANAccess) {
    try { $profile = Get-SelectedProfile } catch { if ($Action -ne 'plan') { throw } }
  }
  $effectiveEndpoint = if ($Endpoint) { $Endpoint } elseif ($env:HOMEVPN_ENDPOINT) { [string]$env:HOMEVPN_ENDPOINT } elseif ($profile) { [string]$profile.endpoint } else { '' }
  $effectivePolicy = if ($Policy) { $Policy } elseif ($profile -and $profile.kill_switch_policy) { [string]$profile.kill_switch_policy } else { 'off' }
  $effectiveLAN = if ($HomeLANAccess) { Parse-Bool $HomeLANAccess $false } elseif ($profile) { [bool]$profile.home_lan_access } else { $false }
  $ip = $null
  if ($effectivePolicy -ne 'off' -and -not [System.Net.IPAddress]::TryParse($effectiveEndpoint.Trim().Trim('[',']'), [ref]$ip)) {
    throw 'Strict Windows kill switch requires the selected Router VPN endpoint to be a literal IPv4/IPv6 address; a hostname would require pre-tunnel DNS.'
  }
  [pscustomobject]@{
    endpoint = $effectiveEndpoint.Trim().Trim('[',']')
    policy = $effectivePolicy
    home_lan_access = $effectiveLAN
    tunnel_alias = $TunnelAlias
  }
}
function Firewall-Profiles {
  return @(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object { $_.Name -in @('Domain','Private','Public') } | ForEach-Object {
    [pscustomobject]@{ name=[string]$_.Name; default_outbound=[string]$_.DefaultOutboundAction }
  })
}
function Remove-Rules {
  Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
}
function Add-Rule([string]$Name,[hashtable]$Args) {
  $params = @{ DisplayName = $RulePrefix + $Name; Group = $RuleGroup; Direction='Outbound'; Action='Allow'; Profile='Any' }
  foreach ($key in $Args.Keys) { $params[$key] = $Args[$key] }
  New-NetFirewallRule @params | Out-Null
}
function Install-AllowRules($settings) {
  Remove-Rules
  if ($settings.endpoint) { Add-Rule 'selected node' @{ RemoteAddress=$settings.endpoint } }
  Add-Rule 'loopback' @{ RemoteAddress=@('127.0.0.1','::1') }
  Add-Rule 'DHCPv4' @{ Protocol='UDP'; LocalPort='68'; RemotePort='67' }
  Add-Rule 'IPv6 link maintenance' @{ Protocol='ICMPv6'; IcmpType=@('133','134','135','136') }
  if ($settings.home_lan_access) { Add-Rule 'private LAN' @{ RemoteAddress='LocalSubnet' } }
  if ($settings.tunnel_alias) { Add-Rule 'VPN interface' @{ InterfaceAlias=$settings.tunnel_alias } }
}
function Restore-State($state) {
  if ($null -eq $state) { Remove-Rules; return }
  Remove-Rules
  foreach ($profile in @($state.original_profiles)) {
    if ($profile -and $profile.name -and $profile.default_outbound) {
      Set-NetFirewallProfile -Name ([string]$profile.name) -DefaultOutboundAction ([string]$profile.default_outbound)
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

switch ($Action) {
  'plan' {
    [pscustomobject]@{
      policy = $settings.policy
      endpoint = $settings.endpoint
      home_lan_access = $settings.home_lan_access
      tunnel_alias = $settings.tunnel_alias
      default_outbound = if ($settings.policy -eq 'off') { 'unchanged' } else { 'Block' }
      rule_group = $RuleGroup
      state_path = Get-StatePath
    } | ConvertTo-Json -Depth 8
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
      home_lan_access = $settings.home_lan_access
      tunnel_alias = $settings.tunnel_alias
      phase = 'preparing'
      original_profiles = $original
      updated_at = [DateTime]::UtcNow.ToString('o')
    }
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
      if ($state) { Restore-State $state } else { Remove-Rules }
    } catch {
      # Explicit local recovery when rollback JSON itself is poisoned. The exact
      # pre-kill-switch defaults are unknowable without valid state, so force-off
      # restores outbound Allow for the three Windows profiles to recover network
      # access, removes only Router VPN's rule group, and deletes only the state
      # leaf without following a reparse target.
      Remove-Rules
      foreach ($name in @('Domain','Private','Public')) {
        Set-NetFirewallProfile -Name $name -DefaultOutboundAction Allow
      }
      Remove-State -ForceRecovery
      Write-Warning 'Windows kill-switch state was unreadable; force-off used emergency outbound-Allow recovery.'
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
