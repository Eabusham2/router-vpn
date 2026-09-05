param(
  [Parameter(Mandatory=$true)][ValidateSet('check','up','down','status')][string]$Action
)

$ErrorActionPreference = 'Stop'
$PrivateState=Join-Path $PSScriptRoot 'Private-RouterVPN-State.ps1'
if(-not(Test-Path -LiteralPath $PrivateState -PathType Leaf)){throw 'Router VPN private-state helper is missing.'}
. $PrivateState

function Fail([string]$Message) {
  [Console]::Error.WriteLine($Message)
  exit 1
}

function Find-WireGuard {
  $candidates = @()
  if (-not [string]::IsNullOrWhiteSpace([string]$env:ProgramFiles)) {
    $candidates += Join-Path $env:ProgramFiles 'WireGuard\wireguard.exe'
  }
  if (-not [string]::IsNullOrWhiteSpace([string]${env:ProgramFiles(x86)})) {
    $candidates += Join-Path ${env:ProgramFiles(x86)} 'WireGuard\wireguard.exe'
  }
  foreach ($candidate in $candidates) {
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
    $item = Get-Item -LiteralPath $candidate -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
    return [IO.Path]::GetFullPath($candidate)
  }
  # This helper manages a privileged tunnel service. Never resolve a same-name
  # executable from PATH; a user-writable shim must not become the VPN runtime.
  return $null
}

function Find-DnsProxy {
  $candidate = Join-Path $root 'router-vpn-dns.exe'
  Assert-RouterVPNNoReparseAncestors $candidate
  if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { return $null }
  $item = Get-Item -LiteralPath $candidate -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Refusing reparse-point Router VPN DNS enforcement binary.'
  }
  # The installer makes this package-owned binary mandatory. Do not fall back to
  # PATH because DNS enforcement is part of the exact raw-WireGuard dataplane.
  return [IO.Path]::GetFullPath($candidate)
}

function Is-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Has-Property($Object,[string]$Name) {
  return $null -ne $Object -and ($Object.PSObject.Properties.Name -contains $Name)
}

function Safe-ProfileId([string]$Value) {
  if ([string]::IsNullOrWhiteSpace($Value) -or $Value -notmatch '^[A-Za-z0-9_-]{1,80}$') {
    Fail 'A valid Router VPN profile is not selected.'
  }
  return $Value
}

function Safe-Under([string]$Parent,[string]$Child) {
  $p = [IO.Path]::GetFullPath($Parent).TrimEnd('\') + '\'
  $c = [IO.Path]::GetFullPath($Child)
  if (-not $c.StartsWith($p,[StringComparison]::OrdinalIgnoreCase)) { Fail "Refusing unsafe path outside $Parent" }
  Assert-RouterVPNNoReparseAncestors $c
  return $c
}

function Write-Utf8NoBom([string]$Path,[string]$Text) {
  [IO.File]::WriteAllText($Path,$Text,(New-Object Text.UTF8Encoding($false)))
}

function Source-Profile-Path {
  $generated = Join-Path $root 'generated'
  $profileRoot = Join-Path $generated $profileId
  $candidate = Join-Path (Join-Path $profileRoot 'wg') 'wg.conf'
  $fullGenerated = [IO.Path]::GetFullPath($generated).TrimEnd('\') + '\'
  $fullCandidate = [IO.Path]::GetFullPath($candidate)
  if (-not $fullCandidate.StartsWith($fullGenerated, [StringComparison]::OrdinalIgnoreCase)) { Fail 'Unsafe WireGuard profile path.' }
  Assert-RouterVPNNoReparseAncestors $fullCandidate
  if (-not (Test-Path -LiteralPath $fullCandidate -PathType Leaf)) { Fail "Raw WireGuard profile is missing: $fullCandidate" }
  return $fullCandidate
}

function Get-SelectedProfile {
  $store = Get-RouterVPNProfileStore $root
  return Get-RouterVPNSelectedProfile $store $profileId
}

function Profile-String($Profile,[string]$Name,[string]$Default='') {
  if ($Profile -and (Has-Property $Profile $Name)) {
    $v=[string]$Profile.$Name
    if (-not [string]::IsNullOrWhiteSpace($v)) { return $v }
  }
  return $Default
}

function Profile-Int($Profile,[string]$Name,[int]$Default=0) {
  if ($Profile -and (Has-Property $Profile $Name)) {
    $n=0
    if ([int]::TryParse(([string]$Profile.$Name),[ref]$n) -and $n -gt 0) { return $n }
  }
  return $Default
}

function Infer-DnsServerName([string]$DnsHost,[string]$Explicit='') {
  if (-not [string]::IsNullOrWhiteSpace($Explicit)) { return $Explicit }
  switch ($DnsHost.Trim('[]')) {
    '1.1.1.1' { return 'cloudflare-dns.com' }
    '1.0.0.1' { return 'cloudflare-dns.com' }
    '2606:4700:4700::1111' { return 'cloudflare-dns.com' }
    '2606:4700:4700::1001' { return 'cloudflare-dns.com' }
    '8.8.8.8' { return 'dns.google' }
    '8.8.4.4' { return 'dns.google' }
    '2001:4860:4860::8888' { return 'dns.google' }
    '2001:4860:4860::8844' { return 'dns.google' }
    '9.9.9.9' { return 'dns.quad9.net' }
    '149.112.112.112' { return 'dns.quad9.net' }
    '2620:fe::fe' { return 'dns.quad9.net' }
  }
  if ($DnsHost -match '[A-Za-z]' -and $DnsHost -notmatch ':') { return $DnsHost }
  return ''
}

function Get-DnsSelection {
  $p = Get-SelectedProfile
  if ($null -eq $p) { throw 'Selected Router VPN profile is unavailable for DNS policy.' }
  $mode = (Profile-String $p 'dns_mode' 'home').ToLowerInvariant()
  $fastest = Profile-String $p 'fastest_dns_host' '1.1.1.1'
  $protocol = (Profile-String $p 'dns_protocol' 'udp').ToLowerInvariant()
  $dnsHost = Profile-String $p 'dns_host' $fastest
  $port = Profile-Int $p 'dns_port' 0
  $serverName = Profile-String $p 'dns_server_name' ''
  $path = Profile-String $p 'dns_path' '/dns-query'
  switch ($mode) {
    'home' { $dnsHost=Profile-String $p 'adguard_ipv4' (Profile-String $p 'adguard_ipv6' '10.77.0.1');$protocol='udp';$port=53;$serverName='';$path='' }
    'fastest' { $dnsHost=$fastest;$protocol='udp';$port=53;$serverName='';$path='' }
    'doh' { $protocol='https';if($port-le 0){$port=443} }
    'dot' { $protocol='tls';if($port-le 0){$port=853} }
    'doh3' { $protocol='h3';if($port-le 0){$port=443} }
    'rescue' { $protocol='rescue';if([string]::IsNullOrWhiteSpace($dnsHost)){$dnsHost=$fastest};if($port-le 0){$port=443} }
    default {
      if($protocol-eq'doh'){$protocol='https'}elseif($protocol-eq'dot'){$protocol='tls'}elseif($protocol-eq'doh3'){$protocol='h3'}
      if($port-le 0){if($protocol-in@('https','h3')){$port=443}elseif($protocol-eq'tls'){$port=853}else{$port=53}}
    }
  }
  $dnsHost = $dnsHost.Trim('[]')
  if ([string]::IsNullOrWhiteSpace($dnsHost)) { throw 'Selected DNS policy has no upstream host.' }
  if ($protocol -eq 'h3') { throw 'DoH3 is unavailable on raw Windows WireGuard because the bounded kernel-mode DNS proxy has no QUIC engine. Choose DoH/DoT or a native sing-box mode; Router VPN will not silently downgrade DoH3.' }
  if ($protocol -notin @('udp','tcp','tls','https','rescue')) { throw "Unsupported DNS protocol for raw Windows WireGuard: $protocol" }
  $parsedIp = $null
  if (-not [Net.IPAddress]::TryParse($dnsHost,[ref]$parsedIp)) {
    throw 'Raw Windows WireGuard requires a literal DNS upstream IP so bootstrap resolution cannot leak or loop. Use a resolver IP or a native sing-box mode for hostname-based DNS.'
  }
  $serverName = Infer-DnsServerName $dnsHost $serverName
  if ($protocol -in @('tls','https') -and [string]::IsNullOrWhiteSpace($serverName)) { throw 'Encrypted DNS on raw Windows WireGuard requires a TLS server name.' }
  if ([string]::IsNullOrWhiteSpace($path)) { $path='/dns-query' }
  return [pscustomobject]@{mode=$mode;protocol=$protocol;dns_host=$dnsHost;port=$port;server_name=$serverName;path=$path}
}

function Test-RuntimeOwner {
  if (-not (Test-Path -LiteralPath $dnsOwnerFile -PathType Leaf)) { return $true }
  if ([string]::IsNullOrWhiteSpace($script:dnsOwnerToken)) { return $false }
  try { $current=(Get-Content -Raw -LiteralPath $dnsOwnerFile -ErrorAction Stop).Trim() } catch { return $false }
  return $current -eq $script:dnsOwnerToken
}

function New-DnsOwner {
  $script:dnsOwnerToken=[Guid]::NewGuid().ToString('N')
  Write-Utf8NoBom $dnsOwnerFile ($script:dnsOwnerToken+"`n")
}

function Remove-OwnedDnsHint {
  if ([string]::IsNullOrWhiteSpace($script:dnsOwnerToken)) { return }
  if (-not (Test-Path -LiteralPath $dnsHint -PathType Leaf)) { return }
  try { $hintText=Get-Content -Raw -LiteralPath $dnsHint -ErrorAction Stop } catch { return }
  $ownerLine='owner='+$script:dnsOwnerToken
  if (@($hintText -split "`r?`n") -contains $ownerLine) {
    Remove-Item -LiteralPath $dnsHint -Force -ErrorAction SilentlyContinue
  }
}

function Stop-DnsProxy {
  if (-not (Test-RuntimeOwner)) { return }
  [void](Stop-RouterVPNRecordedProcess $dnsProcessFile)
}

function Remove-PrivateRuntime {
  if (-not (Test-RuntimeOwner)) { return }
  Remove-OwnedDnsHint
  if (Test-Path -LiteralPath $runDir -PathType Container) { Remove-Item -LiteralPath $runDir -Recurse -Force -ErrorAction SilentlyContinue }
}

function Prepare-RuntimeConfig {
  Stop-DnsProxy
  Remove-PrivateRuntime
  New-Item -ItemType Directory -Force -Path $runDir | Out-Null
  $source = Source-Profile-Path
  $text = Get-Content -Raw -LiteralPath $source -Encoding UTF8
  if ($text -notmatch '(?im)^\s*DNS\s*=') { throw 'Raw WireGuard profile is missing its DNS field; refusing to install an unverified resolver policy.' }
  $patched = [regex]::Replace($text,'(?im)^\s*DNS\s*=.*$','DNS = 127.0.0.1',1)
  Write-Utf8NoBom $runtimeConfig ($patched.TrimEnd()+"`r`n")
}

function Start-DnsProxy($Dns) {
  $dnsProxy = Find-DnsProxy
  if (-not $dnsProxy) { throw 'router-vpn-dns.exe is missing from the Windows package.' }
  New-DnsOwner
  $args = @('-listen','127.0.0.1:53','-protocol',[string]$Dns.protocol,'-server',[string]$Dns.dns_host,'-port',[string]$Dns.port)
  if (-not [string]::IsNullOrWhiteSpace([string]$Dns.server_name)) { $args += @('-server-name',[string]$Dns.server_name) }
  if (-not [string]::IsNullOrWhiteSpace([string]$Dns.path)) { $args += @('-path',[string]$Dns.path) }
  $process = Start-Process -FilePath $dnsProxy -ArgumentList $args -WorkingDirectory $runDir -PassThru -WindowStyle Hidden
  Write-RouterVPNProcessRecord $dnsProcessFile $process
  Start-Sleep -Milliseconds 250
  if ($process.HasExited) { throw "Router VPN selected-DNS proxy exited during startup with code $($process.ExitCode)." }
  $server = if ([string]$Dns.dns_host -match ':') { "[$($Dns.dns_host)]:$($Dns.port)" } else { "$($Dns.dns_host):$($Dns.port)" }
  $hint = "owner=$($script:dnsOwnerToken)`nmode=$($Dns.mode)`nprotocol=$($Dns.protocol)`nserver=$server`n"
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dnsHint) | Out-Null
  Write-Utf8NoBom $dnsHint $hint
}

$wireguard = Find-WireGuard
if (-not $wireguard) {
  Fail 'Native Windows WireGuard is unavailable. Install the official WireGuard for Windows package; Router VPN will not fake native readiness through WSL or a PATH executable.'
}

$rootText = [string]$env:HOMEVPN_ROOT
if ([string]::IsNullOrWhiteSpace($rootText)) { Fail 'HOMEVPN_ROOT is not set.' }
$root = Resolve-RouterVPNPrivateRoot $rootText
$profileId = Safe-ProfileId ([string]$env:HOMEVPN_PROFILE_ID)
$killSwitch = Join-Path $PSScriptRoot 'windows-kill-switch.ps1'
if (-not (Test-Path -LiteralPath $killSwitch -PathType Leaf)) { Fail "Windows kill-switch helper is missing: $killSwitch" }
$runBase = Safe-Under $root (Join-Path $root 'run\windows')
$runDir = Safe-Under $runBase (Join-Path $runBase (Join-Path $profileId 'wg'))
$runtimeConfig = Join-Path $runDir 'wg.conf'
$dnsProcessFile = Join-Path $runDir 'router-vpn-dns.process.json'
$dnsOwnerFile = Join-Path $runDir 'dns.owner'
$dnsHint = Safe-Under $root (Join-Path $root 'run\dns.txt')
$script:dnsOwnerToken=''
if (Test-Path -LiteralPath $dnsOwnerFile -PathType Leaf) {
  try { $script:dnsOwnerToken=(Get-Content -Raw -LiteralPath $dnsOwnerFile -ErrorAction Stop).Trim() } catch { $script:dnsOwnerToken='' }
}
$tunnelName = 'wg'
$serviceName = "WireGuardTunnel`$$tunnelName"

function Invoke-KillSwitch([string]$KillAction,[string]$EndpointValue='') {
  $args=@('-Action',$KillAction,'-Root',$root)
  if ($EndpointValue) { $args += @('-Endpoint',$EndpointValue) }
  if ($KillAction -eq 'prepare') { $args += @('-TunnelAlias',$tunnelName) }
  & $killSwitch @args
  if ($LASTEXITCODE -ne 0) { throw "Windows kill-switch action '$KillAction' failed." }
}

switch ($Action) {
  'check' {
    if (-not (Is-Administrator)) { Fail 'Native WireGuard needs Administrator rights to manage the Windows tunnel service. Run Router VPN as Administrator.' }
    try {
      [void](Source-Profile-Path)
      [void](Get-DnsSelection)
      if (-not (Find-DnsProxy)) { throw 'router-vpn-dns.exe is missing from the Windows package.' }
      Invoke-KillSwitch 'check'
    } catch { Fail $_.Exception.Message }
    Write-Output "Native WireGuard for Windows ready with selected-DNS enforcement: $wireguard"
    exit 0
  }
  'up' {
    if (-not (Is-Administrator)) { Fail 'Native WireGuard needs Administrator rights to install the Windows tunnel service.' }
    $endpoint = [string]$env:HOMEVPN_ENDPOINT
    try {
      $dns = Get-DnsSelection
      Prepare-RuntimeConfig
      Start-DnsProxy $dns
      Invoke-KillSwitch 'prepare' $endpoint
      # Ensure a prior crash/stale service cannot collide with the same deterministic
      # raw-WireGuard tunnel name. Uninstall is idempotent for our purposes.
      & $wireguard /uninstalltunnelservice $tunnelName *> $null
      $process = Start-Process -FilePath $wireguard -ArgumentList @('/installtunnelservice', $runtimeConfig) -Wait -PassThru -NoNewWindow
      if ($process.ExitCode -ne 0) { throw "wireguard.exe /installtunnelservice failed with exit code $($process.ExitCode)." }
      $deadline = (Get-Date).AddSeconds(12)
      do {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq 'Running') {
          Write-Output "Native WireGuard tunnel service is running with selected DNS: $serviceName"
          exit 0
        }
        Start-Sleep -Milliseconds 250
      } while ((Get-Date) -lt $deadline)
      throw "Native WireGuard service did not reach Running state: $serviceName"
    } catch {
      & $wireguard /uninstalltunnelservice $tunnelName *> $null
      Stop-DnsProxy
      Remove-PrivateRuntime
      try { Invoke-KillSwitch 'release' } catch { }
      Fail $_.Exception.Message
    }
  }
  'down' {
    if (-not (Is-Administrator)) { Fail 'Native WireGuard needs Administrator rights to remove the Windows tunnel service.' }
    $failure = ''
    try {
      $process = Start-Process -FilePath $wireguard -ArgumentList @('/uninstalltunnelservice', $tunnelName) -Wait -PassThru -NoNewWindow
      if ($process.ExitCode -ne 0) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) { $failure = "wireguard.exe /uninstalltunnelservice failed with exit code $($process.ExitCode)." }
      }
    } finally {
      Stop-DnsProxy
      Remove-PrivateRuntime
      try { Invoke-KillSwitch 'release' } catch { if (-not $failure) { $failure=$_.Exception.Message } }
    }
    if ($failure) { Fail $failure }
    Write-Output "Native WireGuard tunnel stopped and private DNS runtime cleaned: $tunnelName"
  }
  'status' {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $service) { Write-Output 'DOWN'; exit 1 }
    Write-Output $service.Status
    if ($service.Status -eq 'Running') { exit 0 }
    exit 1
  }
}
