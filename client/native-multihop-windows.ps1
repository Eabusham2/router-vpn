param(
  [Parameter(Mandatory=$true)][ValidateSet('check','up','down')][string]$Action,
  [Parameter(Mandatory=$true)][string]$RuntimeDir,
  [Parameter(Mandatory=$true)][string]$Endpoint,
  [string]$TunnelAlias='router-vpn-multihop'
)
$ErrorActionPreference='Stop'
function Test-Administrator{$id=[Security.Principal.WindowsIdentity]::GetCurrent();$p=New-Object Security.Principal.WindowsPrincipal($id);return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}
$Root=[IO.Path]::GetFullPath([string]$env:HOMEVPN_ROOT)
if([string]::IsNullOrWhiteSpace($Root)){throw 'HOMEVPN_ROOT is required.'}
$RuntimeDir=[IO.Path]::GetFullPath($RuntimeDir)
$RunRoot=[IO.Path]::GetFullPath((Join-Path $Root 'run'))
if(-not $RuntimeDir.StartsWith($RunRoot.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Refusing multihop runtime outside HOMEVPN_ROOT\run.'}
$Config=Join-Path $RuntimeDir 'sing-box.json'
$SingBox=Join-Path $Root 'runtime\windows\sing-box.exe'
$KillSwitch=Join-Path $PSScriptRoot 'windows-kill-switch.ps1'
$PidFile=Join-Path $RuntimeDir 'native-multihop.pid'
function Kill([string]$Kind){& $KillSwitch -Action $Kind -Root $Root -Endpoint $Endpoint -TunnelAlias $TunnelAlias;if($LASTEXITCODE-ne 0){throw "Windows kill-switch $Kind failed."}}
function Stop-Owned{if(Test-Path -LiteralPath $PidFile){$n=0;if([int]::TryParse((Get-Content -Raw -LiteralPath $PidFile).Trim(),[ref]$n)-and$n-gt 0){Stop-Process -Id $n -Force -ErrorAction SilentlyContinue};Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue}}
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
try{
  $quoted='"'+$Config+'"'
  $p=Start-Process -FilePath $SingBox -ArgumentList @('run','-D',$RuntimeDir,'-c',$quoted)-WorkingDirectory $RuntimeDir -PassThru -WindowStyle Hidden
  Set-Content -LiteralPath $PidFile -Encoding ASCII -Value $p.Id
  Start-Sleep -Milliseconds 500
  if($p.HasExited){throw 'sing-box exited during native Windows multihop startup.'}
  $p.WaitForExit()
  if($p.ExitCode-ne 0){throw "sing-box multihop exited with code $($p.ExitCode)"}
}finally{
  Stop-Owned
  try{Kill 'release'}catch{Write-Warning $_.Exception.Message}
  Remove-PrivateRuntime
}
