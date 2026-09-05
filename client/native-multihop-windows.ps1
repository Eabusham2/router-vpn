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
if(-not $RuntimeDir.StartsWith($RunRoot.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Refusing multihop runtime outside HOMEVPN_ROOT\run.'}
$Config=Join-Path $RuntimeDir 'sing-box.json'
$SingBox=Join-Path $Root 'runtime\windows\sing-box.exe'
$KillSwitch=Join-Path $PSScriptRoot 'windows-kill-switch.ps1'
$PidFile=Join-Path $RuntimeDir 'native-multihop.process.json'
function Kill([string]$Kind){& $KillSwitch -Action $Kind -Root $Root -Endpoint $Endpoint -TunnelAlias $TunnelAlias;if($LASTEXITCODE-ne 0){throw "Windows kill-switch $Kind failed."}}
function Stop-Owned{[void](Stop-RouterVPNRecordedProcess $PidFile)}
function Remove-PrivateRuntime{if(Test-Path -LiteralPath $RuntimeDir){[IO.Directory]::Delete($RuntimeDir,$true)}}
if($Action-eq'down'){Stop-Owned;try{Kill 'release'}catch{Write-Warning $_.Exception.Message};Remove-PrivateRuntime;exit 0}
if(-not(Test-Administrator)){throw 'Native Windows multihop requires an elevated Router VPN process.'}
if(-not(Test-Path -LiteralPath $Config -PathType Leaf)){throw 'Prepared multihop sing-box.json is missing.'}
if(-not(Test-Path -LiteralPath $SingBox -PathType Leaf)){throw 'Pinned native sing-box.exe is missing. Run Setup-Windows-Runtime.ps1.'}
if(-not(Test-Path -LiteralPath $KillSwitch -PathType Leaf)){throw 'Windows kill-switch helper is missing.'}
& $SingBox check -D $RuntimeDir -c $Config|Out-Null
if($LASTEXITCODE-ne 0){throw 'Pinned sing-box rejected the prepared Windows multihop graph.'}
Kill 'check'
if($Action-eq'check'){Write-Output 'native Windows multihop graph ready';exit 0}
Stop-Owned
Kill 'prepare'
$controllerStopping=$false
try{
  $quoted='"'+$Config+'"'
  $p=Start-Process -FilePath $SingBox -ArgumentList @('run','-D',$RuntimeDir,'-c',$quoted)-WorkingDirectory $RuntimeDir -PassThru -WindowStyle Hidden
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
  if($controllerStopping){
    try{Kill 'release'}catch{Write-Warning $_.Exception.Message}
  }else{
    Write-Warning 'Windows multihop runtime ended unexpectedly; preserving kill-switch ownership until controller recovery/disconnect.'
  }
  Remove-PrivateRuntime
}
