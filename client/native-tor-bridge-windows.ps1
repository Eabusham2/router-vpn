param(
  [Parameter(Mandatory=$true)][ValidateSet('check','up','down')][string]$Action,
  [Parameter(Mandatory=$true)][string]$RuntimeDir,
  [Parameter(Mandatory=$true)][string]$BridgeEndpoint,
  [Parameter(Mandatory=$true)][ValidateRange(1024,65535)][int]$SocksPort,
  [Parameter(Mandatory=$true)][string]$TorBinary,
  [Parameter(Mandatory=$true)][string]$PTBinary,
  [Parameter(Mandatory=$true)][string]$SingBoxBinary,
  [string]$TunnelAlias='router-vpn-tor'
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$PrivateState=Join-Path $PSScriptRoot 'Private-RouterVPN-State.ps1'
$KillSwitch=Join-Path $PSScriptRoot 'windows-kill-switch.ps1'
if(-not(Test-Path -LiteralPath $PrivateState -PathType Leaf)){throw 'Router VPN private-state helper is missing.'}
if(-not(Test-Path -LiteralPath $KillSwitch -PathType Leaf)){throw 'Windows kill-switch helper is missing.'}
. $PrivateState

function Test-Administrator {
  $id=[Security.Principal.WindowsIdentity]::GetCurrent()
  $principal=New-Object Security.Principal.WindowsPrincipal($id)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Exact-Executable([string]$Path,[string]$Label) {
  if([string]::IsNullOrWhiteSpace($Path)){throw "$Label path is empty."}
  $resolved=(Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
  if(-not(Test-Path -LiteralPath $resolved -PathType Leaf)){throw "$Label is missing."}
  if($resolved -match "[`r`n`0]"){throw "$Label path is unsafe."}
  return $resolved
}
function Kill([string]$Kind) {
  & $KillSwitch -Action $Kind -Root $Root -Endpoint $BridgeEndpoint -TunnelAlias $TunnelAlias
  if($LASTEXITCODE-ne 0){throw "Windows Tor kill-switch $Kind failed."}
}
function Stop-Record([string]$Path) {
  if(Test-Path -LiteralPath $Path -PathType Leaf){[void](Stop-RouterVPNRecordedProcess $Path)}
}
function Stop-Owned {
  Stop-Record $SingPidFile
  Stop-Record $TorPidFile
}
function Remove-PrivateRuntime {
  if(Test-Path -LiteralPath $RuntimeDir){[IO.Directory]::Delete($RuntimeDir,$true)}
}
function Read-TorrcPlugin {
  $line=Get-Content -LiteralPath $Torrc -ErrorAction Stop | Where-Object { $_ -like 'ClientTransportPlugin *' } | Select-Object -First 1
  if([string]::IsNullOrWhiteSpace($line)){throw 'Prepared Tor runtime has no ClientTransportPlugin line.'}
  $m=[regex]::Match($line,'^ClientTransportPlugin\s+([a-z0-9_,]+)\s+exec\s+"(.+)"$')
  if(-not$m.Success){throw 'Prepared Tor ClientTransportPlugin line is invalid.'}
  $slash=[string][char]92
  $escapedSlash=$slash+$slash
  $quote=[string][char]34
  $escapedQuote=$slash+$quote
  $decoded=$m.Groups[2].Value.Replace($escapedSlash,$slash).Replace($escapedQuote,$quote)
  return @($m.Groups[1].Value,$decoded)
}
function Test-TorBootstrap([Diagnostics.Process]$Process,[int]$Seconds=90) {
  $deadline=[DateTime]::UtcNow.AddSeconds($Seconds)
  while([DateTime]::UtcNow-lt$deadline){
    $Process.Refresh()
    if($Process.HasExited){throw 'Tor exited before circumvention bootstrap completed.'}
    if(Test-Path -LiteralPath $TorLog -PathType Leaf){
      $text=[IO.File]::ReadAllText($TorLog)
      if($text.Contains('Bootstrapped 100%')){return}
    }
    Start-Sleep -Milliseconds 500
  }
  throw "Tor $env:HOMEVPN_TOR_TRANSPORT path did not reach Bootstrapped 100% within $Seconds seconds."
}
function Test-TcpListener([int]$Port) {
  $deadline=[DateTime]::UtcNow.AddSeconds(3)
  while([DateTime]::UtcNow-lt$deadline){
    $client=New-Object Net.Sockets.TcpClient
    try{$async=$client.BeginConnect('127.0.0.1',$Port,$null,$null);if($async.AsyncWaitHandle.WaitOne(250)){try{$client.EndConnect($async);return}catch{}}}
    finally{$client.Dispose()}
    Start-Sleep -Milliseconds 100
  }
  throw 'Tor SOCKS listener is unavailable after bootstrap.'
}

$Root=Resolve-RouterVPNPrivateRoot ([string]$env:HOMEVPN_ROOT)
$RuntimeDir=Resolve-RouterVPNPrivateChild $Root $RuntimeDir
$RunRoot=Resolve-RouterVPNPrivateChild $Root 'run'
if(-not $RuntimeDir.StartsWith($RunRoot.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Refusing Tor runtime outside HOMEVPN_ROOT\run.'}
$Torrc=Join-Path $RuntimeDir 'torrc'
$Config=Join-Path $RuntimeDir 'sing-box.json'
$TorLog=Join-Path $RuntimeDir 'tor.log'
$TorPidFile=Join-Path $RuntimeDir 'native-tor.process.json'
$SingPidFile=Join-Path $RuntimeDir 'native-tor-singbox.process.json'
$ProfileId=[string]$env:HOMEVPN_PROFILE_ID
$PolicyProfileId=[string]$env:HOMEVPN_POLICY_PROFILE_ID
$Transport=[string]$env:HOMEVPN_TOR_TRANSPORT
$PluginTransports=[string]$env:HOMEVPN_TOR_PLUGIN_TRANSPORTS
if([string]::IsNullOrWhiteSpace($PolicyProfileId)){$PolicyProfileId=$ProfileId}
if([string]::IsNullOrWhiteSpace($ProfileId) -or [string]::IsNullOrWhiteSpace($BridgeEndpoint)){throw 'Tor bridge runtime/profile/bridge endpoint are required.'}
if($PluginTransports -notmatch '^(obfs4|meek_lite|snowflake|webtunnel)(,(obfs4|meek_lite|snowflake|webtunnel))*$'){throw 'Invalid Tor pluggable-transport set.'}
if($Transport -notin @('obfs4','meek_lite','snowflake','webtunnel','custom')){throw 'Invalid Tor transport identity.'}

if($Action -eq 'down'){
  Stop-Owned
  try{Kill 'release'}catch{Write-Warning $_.Exception.Message}
  Remove-PrivateRuntime
  exit 0
}
if(-not(Test-Administrator)){throw 'Native Windows Tor requires an elevated Router VPN process.'}
foreach($file in @($Torrc,$Config)){if(-not(Test-Path -LiteralPath $file -PathType Leaf)){throw 'Prepared Tor bridge runtime files are missing.'}}
$TorBinary=Exact-Executable $TorBinary 'Tor binary'
$PTBinary=Exact-Executable $PTBinary 'Tor PT binary'
$SingBoxBinary=Exact-Executable $SingBoxBinary 'sing-box binary'
$ptName=[IO.Path]::GetFileName($PTBinary).ToLowerInvariant()
if($ptName -notin @('lyrebird.exe','obfs4proxy.exe')){throw 'Tor PT binary is not an approved Router VPN transport helper.'}
if($ptName -eq 'obfs4proxy.exe' -and $PluginTransports -match '(^|,)(snowflake|webtunnel)(,|$)'){throw 'Legacy obfs4proxy cannot provide Snowflake or WebTunnel; Lyrebird is required.'}
$plugin=Read-TorrcPlugin
if($plugin[0] -ne $PluginTransports){throw 'Tor runtime PT set does not match the validated torrc.'}
$torrcPT=(Resolve-Path -LiteralPath $plugin[1] -ErrorAction Stop).Path
if(-not $torrcPT.Equals($PTBinary,[StringComparison]::OrdinalIgnoreCase)){throw 'Tor PT binary changed after capability proof.'}

& $TorBinary --version | Out-Null
if($LASTEXITCODE-ne 0){throw 'Tor binary verification failed.'}
& $SingBoxBinary check -D $RuntimeDir -c $Config | Out-Null
if($LASTEXITCODE-ne 0){throw 'Pinned sing-box rejected the prepared Windows Tor graph.'}
Kill 'check'
if($Action -eq 'check'){Write-Output "native Windows Tor $Transport bridge graph ready ($PluginTransports)";exit 0}

Stop-Owned
Kill 'prepare'
try {
  Set-Content -LiteralPath $TorLog -Value '' -Encoding ascii
  $tor=Start-Process -FilePath $TorBinary -ArgumentList @('-f',$Torrc,'--RunAsDaemon','0') -WorkingDirectory $RuntimeDir -PassThru -WindowStyle Hidden
  Write-RouterVPNProcessRecord $TorPidFile $tor
  Test-TorBootstrap $tor
  Test-TcpListener $SocksPort

  $sing=Start-Process -FilePath $SingBoxBinary -ArgumentList @('run','-D',$RuntimeDir,'-c',$Config) -WorkingDirectory $RuntimeDir -PassThru -WindowStyle Hidden
  Write-RouterVPNProcessRecord $SingPidFile $sing
  Start-Sleep -Milliseconds 500
  $sing.Refresh();if($sing.HasExited){throw 'Tor full-device sing-box exited during startup.'}

  while($true){
    $tor.Refresh();$sing.Refresh()
    if($tor.HasExited){throw 'Tor circumvention process exited; tearing down full-device path.'}
    if($sing.HasExited){throw 'Tor full-device sing-box process exited.'}
    Start-Sleep -Milliseconds 500
  }
} finally {
  Stop-Owned
  try{Kill 'release'}catch{Write-Warning $_.Exception.Message}
  Remove-PrivateRuntime
}
