param(
  [Parameter(Mandatory=$true)][string]$Root,
  [switch]$Elevated
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$PrivateState=Join-Path $PSScriptRoot 'Private-RouterVPN-State.ps1'
$KillSwitch=Join-Path $PSScriptRoot 'windows-kill-switch.ps1'
if(-not(Test-Path -LiteralPath $PrivateState -PathType Leaf)){throw 'Router VPN private-state helper is missing.'}
if(-not(Test-Path -LiteralPath $KillSwitch -PathType Leaf)){throw 'Windows kill-switch helper is missing.'}
. $PrivateState

function Test-Administrator {
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  $principal=New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-WireGuard {
  $candidates=@(
    (Join-Path $env:ProgramFiles 'WireGuard\wireguard.exe'),
    (Join-Path ${env:ProgramFiles(x86)} 'WireGuard\wireguard.exe')
  )
  foreach($candidate in $candidates){
    if($candidate-and(Test-Path -LiteralPath $candidate -PathType Leaf)){return $candidate}
  }
  $cmd=Get-Command wireguard.exe -ErrorAction SilentlyContinue
  if($cmd){return [string]$cmd.Source}
  return ''
}

function Get-PrivateProcessRecords([string]$RunRoot) {
  if(-not(Test-Path -LiteralPath $RunRoot)){return @()}
  Assert-RouterVPNNoReparseAncestors $RunRoot
  $rootItem=Get-Item -LiteralPath $RunRoot -Force
  if(-not$rootItem.PSIsContainer-or(($rootItem.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0)){
    throw 'Router VPN run root is not a real directory.'
  }
  $stack=New-Object 'System.Collections.Generic.Stack[string]'
  $stack.Push([IO.Path]::GetFullPath($RunRoot))
  $records=New-Object 'System.Collections.Generic.List[string]'
  $visited=0
  while($stack.Count-gt0){
    $dir=$stack.Pop()
    foreach($item in @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop)){
      $visited++
      if($visited-gt4096){throw 'Router VPN Windows runtime tree exceeds recovery safety limit.'}
      if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){
        throw "Refusing reparse-point/junction in Router VPN runtime tree: $($item.FullName)"
      }
      if($item.PSIsContainer){$stack.Push($item.FullName);continue}
      if($item.Name.EndsWith('.process.json',[StringComparison]::OrdinalIgnoreCase)){$records.Add($item.FullName)}
    }
  }
  return @($records)
}

function Assert-ProcessRecordSchema([string]$Path) {
  $record=Read-RouterVPNPrivateJson $Path 'Router VPN stale process record' 65536
  if($null-eq$record-or[int]$record.version-ne1){throw "Invalid Router VPN process-record version: $Path"}
  $pidValue=0
  if(-not[int]::TryParse(([string]$record.pid),[ref]$pidValue)-or$pidValue-le0){throw "Invalid Router VPN process-record PID: $Path"}
  $ticks=[Int64]0
  if(-not[Int64]::TryParse(([string]$record.start_time_utc_ticks),[ref]$ticks)-or$ticks-le0){throw "Invalid Router VPN process-record start identity: $Path"}
  $exe=[string]$record.executable_path
  if([string]::IsNullOrWhiteSpace($exe)){throw "Invalid Router VPN process-record executable: $Path"}
  try{[void][IO.Path]::GetFullPath($exe)}catch{throw "Invalid Router VPN process-record executable path: $Path"}
}

function Get-KillSwitchStatePath {
  $programData=[string]$env:ProgramData
  if([string]::IsNullOrWhiteSpace($programData)){return ''}
  return Join-Path $programData 'RouterVPN\KillSwitch\windows-state.json'
}

function Test-StaleRuntime([string[]]$Records) {
  if($Records.Count-gt0){return $true}
  if(Get-Service -Name 'WireGuardTunnel$wg' -ErrorAction SilentlyContinue){return $true}
  $state=Get-KillSwitchStatePath
  return (-not[string]::IsNullOrWhiteSpace($state))-and(Test-Path -LiteralPath $state -PathType Leaf)
}

function Invoke-ElevatedSelf([string]$ResolvedRoot) {
  $scriptPath=[IO.Path]::GetFullPath($PSCommandPath)
  $escapedScript=$scriptPath.Replace("'","''")
  $escapedRoot=$ResolvedRoot.Replace("'","''")
  $command="& '$escapedScript' -Root '$escapedRoot' -Elevated"
  $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
  $process=Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded) -Wait -PassThru
  if($null-eq$process-or$process.ExitCode-ne0){throw 'Elevated Router VPN crash recovery did not complete.'}
}

function Invoke-KillSwitchRelease([string]$ResolvedRoot) {
  $process=Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"'+$KillSwitch+'"'),'-Action','release','-Root',('"'+$ResolvedRoot+'"')) -Wait -PassThru -WindowStyle Hidden
  if($process.ExitCode-ne0){throw "Windows kill-switch release/reassert transaction failed with exit code $($process.ExitCode)."}
}

$Root=Resolve-RouterVPNPrivateRoot $Root
$RunRoot=Resolve-RouterVPNPrivateChild $Root 'run'
$Records=@(Get-PrivateProcessRecords $RunRoot)
if(-not(Test-StaleRuntime $Records)){
  Write-Output 'No stale Windows Router VPN runtime ownership found.'
  exit 0
}

if(-not(Test-Administrator)){
  if($Elevated){throw 'Router VPN crash recovery still lacks Administrator rights after elevation.'}
  Invoke-ElevatedSelf $Root
  exit 0
}

# Validate every ownership record before changing anything. A corrupt record is
# not silently discarded because it could be the only safe identity for an
# orphaned privileged VPN process.
foreach($record in $Records){Assert-ProcessRecordSchema $record}

foreach($record in $Records){
  [void](Stop-RouterVPNRecordedProcess $record)
}

# Raw WireGuard is service-owned rather than wrapper-owned. The tunnel name is
# deliberately deterministic in native-wireguard-windows.ps1, so recovery can
# remove exactly Router VPN's service without matching arbitrary WireGuard peers.
$service=Get-Service -Name 'WireGuardTunnel$wg' -ErrorAction SilentlyContinue
if($service){
  $wireguard=Find-WireGuard
  if([string]::IsNullOrWhiteSpace($wireguard)){throw 'Stale Router VPN WireGuard service exists but wireguard.exe is unavailable for exact teardown.'}
  $process=Start-Process -FilePath $wireguard -ArgumentList @('/uninstalltunnelservice','wg') -Wait -PassThru -NoNewWindow
  if($process.ExitCode-ne0-and(Get-Service -Name 'WireGuardTunnel$wg' -ErrorAction SilentlyContinue)){
    throw "Could not remove stale Router VPN WireGuard service (exit $($process.ExitCode))."
  }
}

# Let long-running PowerShell owners observe their now-dead verified child and
# execute their own finally blocks before the next controller starts.
Start-Sleep -Milliseconds 500

# Existing kill-switch semantics are authoritative: stale on-connect state is
# rolled back; policy=always deliberately remains blocked across restart.
Invoke-KillSwitchRelease $Root
Write-Output 'Recovered stale Windows Router VPN runtime ownership before controller startup.'
