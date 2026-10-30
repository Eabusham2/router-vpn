param(
  [Parameter(Mandatory=$true)][ValidateSet('check','up','down')][string]$Action,
  [Parameter(Mandatory=$true)][string]$RuntimeDir,
  [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Endpoint,
  [string]$TunnelAlias='router-vpn-multihop'
)
$ErrorActionPreference='Stop'
$PrivateState=Join-Path $PSScriptRoot 'Private-RouterVPN-State.ps1'
if(-not(Test-Path -LiteralPath $PrivateState -PathType Leaf)){throw 'Router VPN private-state helper is missing.'}
. $PrivateState
function Test-Administrator{$id=[Security.Principal.WindowsIdentity]::GetCurrent();$p=New-Object Security.Principal.WindowsPrincipal($id);return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}
$Root=Resolve-RouterVPNPrivateRoot ([string]$env:HOMEVPN_ROOT)
$RuntimeDir=Resolve-RouterVPNPrivateChild $Root $RuntimeDir
$RunRoot=Resolve-RouterVPNPrivateChild $Root 'run'
if(-not $RuntimeDir.StartsWith($RunRoot.TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Refusing multihop runtime outside HOMEVPN_ROOT\run.'}
$Config=Join-Path $RuntimeDir 'sing-box.json'
$KillSwitch=Join-Path $PSScriptRoot 'windows-kill-switch.ps1'
$PidFile=Join-Path $RuntimeDir 'native-multihop.process.json'
$HoldKillSwitch=([string]$env:HOMEVPN_KILLSWITCH_HOLD -eq '1')
$ExternalSession=[string]$env:HOMEVPN_EXTERNAL_SESSION
if($ExternalSession-and(([string]$env:HOMEVPN_STANDARD_ENGINE-ne'native')-or($ExternalSession-cnotmatch'^[a-f0-9]{32}$'))){throw 'Invalid captured external native owner.'}
$NodeSession=[string]$env:HOMEVPN_NODE_SESSION
if($NodeSession-and(([string]$env:HOMEVPN_STANDARD_ENGINE-ne'native')-or($NodeSession-cnotmatch'^[a-f0-9]{32}$')-or([string]$env:HOMEVPN_NODE_CONFIG_SHA256-cnotmatch'^[a-f0-9]{64}$'))){throw 'Invalid captured Router node owner.'}
$PhysicalSource=[string]$env:HOMEVPN_EXTERNAL_PHYSICAL_SOURCE_SHA256
$PhysicalConfig=[string]$env:HOMEVPN_EXTERNAL_PHYSICAL_CONFIG_SHA256
$PhysicalOwned=$PhysicalSource-ne''-or$PhysicalConfig-ne''
if($PhysicalOwned){
  if(-not$ExternalSession-or$NodeSession-or$PhysicalSource-cnotmatch'^[a-f0-9]{64}$'-or$PhysicalConfig-cnotmatch'^[a-f0-9]{64}$'-or
     $Endpoint-ne''-or[string]$env:HOMEVPN_ENDPOINT-ne''-or[string]$env:HOMEVPN_NATIVE_ENDPOINTS_JSON-ne''-or[string]$env:HOMEVPN_NATIVE_EGRESS_JSON-ne''-or
     [string]$env:HOMEVPN_TOR_SESSION-ne''-or[string]$env:HOMEVPN_NODE_CONFIG_SHA256-ne''){
    throw 'Ordinary physical launch lost its exact external owner or acquired legacy endpoint authority.'
  }
}elseif([string]::IsNullOrWhiteSpace($Endpoint)){throw 'Legacy native launch requires its captured endpoint.'}
# A bare `Kill` function loses command resolution to Windows PowerShell's
# built-in kill -> Stop-Process alias, including during read-only checks.
function Invoke-RouterVPNNativeKillSwitch([string]$Kind){& $KillSwitch -Action $Kind -Root $Root -Endpoint $Endpoint -TunnelAlias $TunnelAlias;if($LASTEXITCODE-ne 0){throw "Windows kill-switch $Kind failed."}}
$OwnedProcess=$null;$OwnedIdentity=$null
function Stop-Owned{
  if($null-eq$OwnedProcess-or$null-eq$OwnedIdentity){return}
  try{if($OwnedProcess.HasExited){return};$Current=Get-RouterVPNProcessIdentity $OwnedProcess}catch{throw 'Cannot reprove the captured native Windows child identity; preserving its recovery state.'}
  if([int]$Current.pid-ne[int]$OwnedIdentity.pid-or[Int64]$Current.start_time_utc_ticks-ne[Int64]$OwnedIdentity.start_time_utc_ticks-or-not[string]::Equals([string]$Current.executable_path,[string]$OwnedIdentity.executable_path,[StringComparison]::OrdinalIgnoreCase)){return}
  # The Start-Process object retains this child's process handle. Never look up
  # a replacement process through the current runtime record during finally.
  Stop-Process -InputObject $OwnedProcess -Force -ErrorAction Stop
}
function Remove-PrivateRuntime{if(Test-Path -LiteralPath $RuntimeDir){[IO.Directory]::Delete($RuntimeDir,$true)}}
if($Action-eq'down'){
  if($ExternalSession-or$NodeSession){Write-Output 'Captured native teardown belongs to the controller after native close acknowledgement.';exit 0}
  [void](Stop-RouterVPNRecordedProcess $PidFile)
  if(-not$HoldKillSwitch){try{Invoke-RouterVPNNativeKillSwitch 'release'}catch{Write-Warning $_.Exception.Message}}
  else{Write-Output 'Windows multihop teardown is holding kill-switch ownership for a fail-closed transition.'}
  Remove-PrivateRuntime
  exit 0
}
$EngineSelector=Join-Path $PSScriptRoot 'Select-Standard-Engine.ps1'
Assert-RouterVPNNoReparseAncestors $EngineSelector
. $EngineSelector
$SingBox=Get-RouterVPNStandardEngine $Root
if(-not(Test-Path -LiteralPath $Config -PathType Leaf)){throw 'Prepared multihop sing-box.json is missing.'}
if(-not(Test-Path -LiteralPath $SingBox -PathType Leaf)){throw 'Pinned native sing-box.exe is missing. Run Setup-Windows-Runtime.ps1.'}
if(-not(Test-Path -LiteralPath $KillSwitch -PathType Leaf)){throw 'Windows kill-switch helper is missing.'}
if($PhysicalOwned){
  if((Get-RouterVPNPrivateFileSHA256 $Config 'Captured ordinary physical configuration' 4194304)-cne$PhysicalConfig){throw 'Ordinary physical native graph changed after capture.'}
  # This argument is an expected source identity, never socket authority.
  # The native command independently derives its graph from the private
  # source/capture and refuses any missing, changed or unsupported policy.
  & $SingBox routervpn-external --physical-source-sha256 $PhysicalSource --help|Out-Null
  if($LASTEXITCODE-ne0){throw 'Captured ordinary physical command is unavailable.'}
}
& $SingBox check -D $RuntimeDir -c $Config|Out-Null
if($LASTEXITCODE-ne 0){throw 'Pinned sing-box rejected the prepared Windows multihop graph.'}
if($PhysicalOwned){
  $ProtectionHelper=Join-Path $PSScriptRoot 'Private-RouterVPN-Protection.ps1'
  Assert-RouterVPNNoReparseAncestors $ProtectionHelper
  if(-not(Test-Path -LiteralPath $ProtectionHelper -PathType Leaf)){throw 'Native Windows protection adapter is missing.'}
  . $ProtectionHelper
  Assert-RouterVPNNoLegacyWindowsProtection
  # Read only. Native initialization creates/reproves the owned WFP baseline
  # before any physical socket or TUN starts. A failure has no legacy fallback.
  $null=Invoke-RouterVPNOwnedWindowsProtection -ClientDirectory $PSScriptRoot -Operation status
}else{Invoke-RouterVPNNativeKillSwitch 'check'}
if($Action-eq'check'){Write-Output 'native Windows multihop graph ready';exit 0}
if(-not(Test-Administrator)){throw 'Native Windows multihop requires an elevated Router VPN process.'}
if(-not$PhysicalOwned){Invoke-RouterVPNNativeKillSwitch 'prepare'}
$controllerStopping=$false
try{
  $quoted='"'+$Config+'"'
  $nativeArguments=@('run','-D',('"'+$RuntimeDir+'"'),'-c',$quoted)
  if($ExternalSession){
    $nativeArguments=@('routervpn-external','--runtime-dir',('"'+$RuntimeDir+'"'),'--session',$ExternalSession)
    if($PhysicalOwned){$nativeArguments+=@('--physical-source-sha256',$PhysicalSource)}
  }
  elseif($env:HOMEVPN_NODE_SESSION){
    if($env:HOMEVPN_STANDARD_ENGINE-ne'native'-or$env:HOMEVPN_NODE_SESSION-cnotmatch'^[a-f0-9]{32}$'-or$env:HOMEVPN_NODE_CONFIG_SHA256-cnotmatch'^[a-f0-9]{64}$'){throw 'Invalid captured Router node TUN owner.'}
    $nativeArguments=@('routervpn-node','--runtime-dir',('"'+$RuntimeDir+'"'),'--session',$env:HOMEVPN_NODE_SESSION,'--config-sha256',$env:HOMEVPN_NODE_CONFIG_SHA256)
  }
  $p=Start-Process -FilePath $SingBox -ArgumentList $nativeArguments -WorkingDirectory $RuntimeDir -PassThru -WindowStyle Hidden
  $OwnedProcess=$p;$OwnedIdentity=Get-RouterVPNProcessIdentity $p
  Write-RouterVPNProcessRecord $PidFile $p
  Start-Sleep -Milliseconds 500
  if($p.HasExited){throw 'sing-box exited during native Windows multihop startup.'}
  while(-not$p.HasExited){
    if(Test-RouterVPNControllerStopping){$controllerStopping=$true;break}
    Start-Sleep -Milliseconds 200
    try{$p.Refresh()}catch{}
  }
  if(-not$controllerStopping-and$p.HasExited-and$p.ExitCode-ne0){throw "sing-box multihop exited with code $($p.ExitCode)"}
  if($controllerStopping){Write-Output 'Router VPN controller requested graceful Windows multihop shutdown.'}
}finally{
  Stop-Owned
  if(-not$controllerStopping){
    Write-Warning 'Windows multihop runtime ended unexpectedly; preserving kill-switch ownership until controller recovery/disconnect.'
  }
  # Firewall rollback belongs to the Go controller after owned teardown. This
  # wrapper never releases from finally, so HOMEVPN_KILLSWITCH_HOLD remains real.
  # A finally block cannot retire whichever workspace now occupies an old
  # pathname. Explicit controller down/owned Go cleanup removes private files.
}
