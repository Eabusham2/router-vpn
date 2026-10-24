param(
  [Parameter(Mandatory=$true)][ValidateSet('check','up','down')][string]$Action,
  [Parameter(Mandatory=$true)][string]$RuntimeDir,
  [Parameter(Mandatory=$true)][string]$Endpoint,
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
  if($ExternalSession){Write-Output 'Captured external teardown belongs to the controller after native close acknowledgement.';exit 0}
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
& $SingBox check -D $RuntimeDir -c $Config|Out-Null
if($LASTEXITCODE-ne 0){throw 'Pinned sing-box rejected the prepared Windows multihop graph.'}
Invoke-RouterVPNNativeKillSwitch 'check'
if($Action-eq'check'){Write-Output 'native Windows multihop graph ready';exit 0}
if(-not(Test-Administrator)){throw 'Native Windows multihop requires an elevated Router VPN process.'}
Invoke-RouterVPNNativeKillSwitch 'prepare'
$controllerStopping=$false
try{
  $quoted='"'+$Config+'"'
  $nativeArguments=@('run','-D',('"'+$RuntimeDir+'"'),'-c',$quoted)
  if($ExternalSession){$nativeArguments=@('routervpn-external','--runtime-dir',('"'+$RuntimeDir+'"'),'--session',$ExternalSession)}
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
