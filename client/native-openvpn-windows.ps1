param(
  [Parameter(Mandatory=$true)][ValidateSet('check','up','down')][string]$Action,
  [Parameter(Mandatory=$true)][string]$RuntimeDir,
  [Parameter(Mandatory=$true)][string]$Endpoint,
  [Parameter(Mandatory=$true)][string]$OpenVPNBin
)

$ErrorActionPreference='Stop'

function Test-Administrator {
  $id=[Security.Principal.WindowsIdentity]::GetCurrent()
  $p=New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$Root=[IO.Path]::GetFullPath([string]$env:HOMEVPN_ROOT)
if([string]::IsNullOrWhiteSpace($Root)){throw 'HOMEVPN_ROOT is required.'}
$RuntimeDir=[IO.Path]::GetFullPath($RuntimeDir)
$RunRoot=[IO.Path]::GetFullPath((Join-Path $Root 'run'))
if(-not $RuntimeDir.StartsWith($RunRoot.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Refusing OpenVPN runtime outside HOMEVPN_ROOT\run.'}
$Config=Join-Path $RuntimeDir 'client.ovpn'
$BridgeConfig=Join-Path $RuntimeDir 'entry-bridge.json'
$OpenVPNPid=Join-Path $RuntimeDir 'openvpn-windows.pid'
$BridgePid=Join-Path $RuntimeDir 'openvpn-entry-bridge.pid'
$KillSwitch=Join-Path $PSScriptRoot 'windows-kill-switch.ps1'
$SingBox=Join-Path $Root 'runtime\windows\sing-box.exe'

function Stop-PidFile([string]$Path) {
  if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){return}
  $n=0
  if([int]::TryParse((Get-Content -Raw -LiteralPath $Path).Trim(),[ref]$n)-and$n-gt 0){
    Stop-Process -Id $n -Force -ErrorAction SilentlyContinue
  }
  Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
}
function Stop-Owned {
  Stop-PidFile $OpenVPNPid
  Stop-PidFile $BridgePid
}
function Remove-PrivateRuntime {
  if(Test-Path -LiteralPath $RuntimeDir){[IO.Directory]::Delete($RuntimeDir,$true)}
}
function Kill([string]$Kind,[string]$Alias='') {
  $args=@('-Action',$Kind,'-Root',$Root,'-Endpoint',$Endpoint)
  if(-not[string]::IsNullOrWhiteSpace($Alias)){$args+=@('-TunnelAlias',$Alias)}
  & $KillSwitch @args
  if($LASTEXITCODE-ne 0){throw "Windows kill-switch $Kind failed."}
}
function Kill-Plan {
  $raw=& $KillSwitch -Action plan -Root $Root -Endpoint $Endpoint
  if($LASTEXITCODE-ne 0){throw 'Windows kill-switch plan failed.'}
  return (($raw|Out-String)|ConvertFrom-Json)
}
function Wait-LoopbackPort([int]$Port,[int]$Attempts=60) {
  $last=$null
  for($i=0;$i-lt$Attempts;$i++){
    $c=New-Object Net.Sockets.TcpClient
    try{$iar=$c.BeginConnect('127.0.0.1',$Port,$null,$null);if($iar.AsyncWaitHandle.WaitOne(150)){ $c.EndConnect($iar);$c.Close();return }}catch{$last=$_.Exception}finally{$c.Close()}
    Start-Sleep -Milliseconds 100
  }
  throw "Router VPN entry bridge did not become ready on 127.0.0.1:$Port. $last"
}
function Find-OpenVPNTunnelAlias([int]$Attempts=120) {
  for($i=0;$i-lt$Attempts;$i++){
    $a=@(Get-NetRoute -DestinationPrefix '0.0.0.0/1' -ErrorAction SilentlyContinue)
    $b=@(Get-NetRoute -DestinationPrefix '128.0.0.0/1' -ErrorAction SilentlyContinue)
    foreach($left in $a){
      foreach($right in $b){
        if([int]$left.InterfaceIndex-ne[int]$right.InterfaceIndex){continue}
        $adapter=Get-NetAdapter -InterfaceIndex ([int]$left.InterfaceIndex) -ErrorAction SilentlyContinue
        if($adapter-and$adapter.Status-eq'Up'-and-not[string]::IsNullOrWhiteSpace([string]$adapter.Name)){return [string]$adapter.Name}
      }
    }
    Start-Sleep -Milliseconds 100
  }
  throw 'OpenVPN established no matching def1 tunnel routes; refusing to whitelist an unproven Windows interface.'
}

if($Action-eq'down'){
  Stop-Owned
  try{Kill 'release'}catch{Write-Warning $_.Exception.Message}
  Remove-PrivateRuntime
  exit 0
}
if(-not(Test-Administrator)){throw 'Native Windows OpenVPN requires an elevated Router VPN process.'}
if(-not(Test-Path -LiteralPath $Config -PathType Leaf)){throw 'Prepared OpenVPN client.ovpn is missing.'}
if(-not(Test-Path -LiteralPath $OpenVPNBin -PathType Leaf)){throw 'OpenVPN 2.7 executable is missing.'}
if(-not(Test-Path -LiteralPath $KillSwitch -PathType Leaf)){throw 'Windows kill-switch helper is missing.'}
$first=(& $OpenVPNBin --version 2>&1|Select-Object -First 1)
if([string]$first-notmatch'^OpenVPN 2\.7\.'){throw "Router VPN requires OpenVPN 2.7.x; found '$first'."}
if(Test-Path -LiteralPath $BridgeConfig -PathType Leaf){
  if(-not(Test-Path -LiteralPath $SingBox -PathType Leaf)){throw 'Pinned sing-box.exe is required for a hopped Windows OpenVPN exit.'}
  & $SingBox check -D $RuntimeDir -c $BridgeConfig|Out-Null
  if($LASTEXITCODE-ne 0){throw 'Pinned sing-box rejected the OpenVPN entry bridge.'}
}

$plan=Kill-Plan
$strict=([string]$plan.policy-ne'off')
Kill 'check'
if($Action-eq'check'){Write-Output 'native Windows OpenVPN external runtime ready';exit 0}

Stop-Owned
Kill 'prepare'
$bridge=$null
$openvpn=$null
try{
  if(Test-Path -LiteralPath $BridgeConfig -PathType Leaf){
    $quotedBridge='"'+$BridgeConfig+'"'
    $bridge=Start-Process -FilePath $SingBox -ArgumentList @('run','-D',$RuntimeDir,'-c',$quotedBridge)-WorkingDirectory $RuntimeDir -PassThru -WindowStyle Hidden
    Set-Content -LiteralPath $BridgePid -Encoding ASCII -Value $bridge.Id
    Wait-LoopbackPort 1100
    if($bridge.HasExited){throw 'External-entry bridge exited during Windows OpenVPN startup.'}
  }

  $quotedConfig='"'+$Config+'"'
  $openvpn=Start-Process -FilePath $OpenVPNBin -ArgumentList @('--config',$quotedConfig)-WorkingDirectory $RuntimeDir -PassThru -WindowStyle Hidden
  Set-Content -LiteralPath $OpenVPNPid -Encoding ASCII -Value $openvpn.Id
  Start-Sleep -Milliseconds 300
  if($openvpn.HasExited){throw 'OpenVPN exited during native Windows startup.'}

  if($strict){
    $alias=Find-OpenVPNTunnelAlias
    Kill 'tunnel' $alias
    Write-Output "Strict Windows OpenVPN tunnel allowed only on interface '$alias'."
  }

  while(-not$openvpn.HasExited){
    if($bridge-and$bridge.HasExited){throw 'External-entry bridge exited while Windows OpenVPN was active.'}
    Start-Sleep -Milliseconds 250
    try{$openvpn.Refresh()}catch{}
    if($bridge){try{$bridge.Refresh()}catch{}}
  }
  if($openvpn.ExitCode-ne 0){throw "OpenVPN exited with code $($openvpn.ExitCode)."}
}finally{
  Stop-Owned
  try{Kill 'release'}catch{Write-Warning $_.Exception.Message}
  Remove-PrivateRuntime
}
