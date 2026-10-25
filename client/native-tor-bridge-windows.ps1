param(
  [Parameter(Mandatory=$true)][ValidateSet('check','up','down')][string]$Action,
  [Parameter(Mandatory=$true)][string]$RuntimeDir,
  [Parameter(Mandatory=$true)][string]$BridgeEndpoint,
  [Parameter(Mandatory=$true)][ValidateRange(1024,65535)][int]$SocksPort,
  [Parameter(Mandatory=$true)][string]$TorBinary,
  [Parameter(Mandatory=$true)][string]$NativeBinary,
  [ValidateSet('router-vpn-tor')][string]$TunnelAlias='router-vpn-tor'
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$PrivateState=Join-Path $PSScriptRoot 'Private-RouterVPN-State.ps1'
if(-not(Test-Path -LiteralPath $PrivateState -PathType Leaf)){throw 'Router VPN private-state helper is missing.'}
. $PrivateState
$Root=Resolve-RouterVPNPrivateRoot ([string]$env:HOMEVPN_ROOT)
$RuntimeDir=Resolve-RouterVPNPrivateChild $Root $RuntimeDir
$RunRoot=Resolve-RouterVPNPrivateChild $Root 'run'
if(-not $RuntimeDir.StartsWith($RunRoot.TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Refusing Tor runtime outside its captured private run directory.'}
$Session=[string]$env:HOMEVPN_TOR_SESSION
if([string]$env:HOMEVPN_STANDARD_ENGINE -cne 'native' -or $Session -cnotmatch '^[a-f0-9]{32}$'){throw 'Tor requires its captured native session.'}
if([string]::IsNullOrWhiteSpace([string]$env:HOMEVPN_PROFILE_ID) -or [string]$env:HOMEVPN_POLICY_PROFILE_ID -cne [string]$env:HOMEVPN_PROFILE_ID){throw 'Tor policy has another captured profile.'}
foreach($name in @('HOMEVPN_TOR_SOURCE_SHA256','HOMEVPN_TOR_PROFILE_SHA256','HOMEVPN_TOR_CAPTURE_SHA256','HOMEVPN_TOR_TORRC_SHA256','HOMEVPN_TOR_DEFAULTS_SHA256','HOMEVPN_TOR_CONFIG_SHA256','HOMEVPN_TOR_BINARY_SHA256')){
  if([Environment]::GetEnvironmentVariable($name,'Process') -cnotmatch '^[a-f0-9]{64}$'){throw 'Tor launch is missing an exact input digest.'}
}
# Native drain and private deletion belong to the exact Go controller owner.
# A down invocation never adopts a mutable PID record or deletes a pathname.
if($Action -eq 'down'){exit 0}
$KillSwitch=Join-Path $PSScriptRoot 'windows-kill-switch.ps1'
$JobHelper=Join-Path $PSScriptRoot 'Private-RouterVPN-Job.ps1'
$Selector=Join-Path $PSScriptRoot 'Select-Standard-Engine.ps1'
function Get-RouterVPNTorNativeEnvironment([System.Collections.IDictionary]$Snapshot){
  $captured=New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
  foreach($entry in $Snapshot.GetEnumerator()){
    if(-not ($entry.Key -is [string]) -or -not ($entry.Value -is [string])){throw 'Captured Tor environment has an invalid entry.'}
    # Windows includes per-drive current-directory bookkeeping such as =C:.
    # These are not application variables; every real name/value stays exact.
    if($entry.Key -cmatch '^=[A-Za-z]:$'){continue}
    $captured.Add($entry.Key,$entry.Value)
  }
  return ,$captured
}
function Invoke-RouterVPNTorOwnedNative {
  param(
    [string]$NativeBinary,[string]$RuntimeDir,[string]$Session,[string]$TorBinary,
    [System.Collections.IDictionary]$CapturedEnvironment,
    [Parameter(Mandatory=$true)][System.Collections.IDictionary]$LaunchState
  )
  $owned=$null
  try{
    try{
      # An untyped Start failure cannot prove that no native child exists.
      $LaunchState.StartAttempted=$true
      $LaunchState.NoNativeChild=$false
      # The initial thread stays suspended until its exact Job is assigned.
      $owned=Start-RouterVPNPrivateJob -FilePath $NativeBinary -ArgumentList @('routervpn-tor','--runtime-dir',$RuntimeDir,'--session',$Session,'--tor-binary',$TorBinary) -WorkingDirectory $RuntimeDir -Environment $CapturedEnvironment
    }catch{
      $launchFailure=$_.Exception
      while($null -ne $launchFailure.InnerException){$launchFailure=$launchFailure.InnerException}
      if($launchFailure -is [RouterVPN.PrivateJobStartException]){
        # Start may fail after creating a child whose termination is still
        # pending. Keep the returned handles alive until that child exits.
        $owned=$launchFailure.RecoveryOwner
        if(-not $launchFailure.ChildCreated -and -not $launchFailure.ChildExited -and $null -eq $owned){
          $LaunchState.NoNativeChild=$true
          $LaunchState.NoChildFailure=$true
        }
      }
      throw
    }
    while(-not (Wait-RouterVPNPrivateJob -Owner $owned -Milliseconds 250)){}
    if($owned.ExitCode -ne 0){throw 'Native Tor exited without completing its owned lifecycle.'}
  }finally{
    # Native stop.json/stopped.json owns graceful close. Exceptional cleanup
    # touches only this captured Job and never mints a successful receipt,
    # releases protection, or deletes the controller's private workspace.
    if($null -ne $owned){
      $joined=$false
      while(-not $joined){
        $waitFailed=$false
        try{$joined=Wait-RouterVPNPrivateJob -Owner $owned -Milliseconds 250}catch{$waitFailed=$true}
        if($joined){break}
        try{$joined=Stop-RouterVPNPrivateJob -Owner $owned -Milliseconds 5000}catch{
          # Keep ownership on a failed wait/termination request as well as on
          # timeout; an error is not an acknowledgement of native child exit.
          if($waitFailed){Start-Sleep -Milliseconds 250}
        }
      }
      Close-RouterVPNPrivateJob -Owner $owned
    }
  }
}
function Write-RouterVPNTorPrelaunchFailure {
  param(
    [string]$Action,[string]$Root,[string]$RuntimeDir,[string]$Session,[string]$TorBinary,
    [System.Collections.IDictionary]$CapturedEnvironment,[System.Collections.IDictionary]$LaunchState
  )
  if($Action -cne 'up' -or $null -eq $LaunchState -or
     -not ($LaunchState.NoNativeChild -is [bool]) -or -not $LaunchState.NoNativeChild -or
     -not ($LaunchState.StartAttempted -is [bool]) -or
     ($LaunchState.StartAttempted -and -not ($LaunchState.NoChildFailure -is [bool] -and $LaunchState.NoChildFailure))){return}
  if($Session -cnotmatch '^[a-f0-9]{32}$' -or $null -eq $CapturedEnvironment -or
     [string]$CapturedEnvironment['HOMEVPN_TOR_SESSION'] -cne $Session -or
     [string]$CapturedEnvironment['HOMEVPN_STANDARD_ENGINE'] -cne 'native' -or
     [string]::IsNullOrWhiteSpace([string]$CapturedEnvironment['HOMEVPN_PROFILE_ID']) -or
     [string]$CapturedEnvironment['HOMEVPN_PROFILE_ID'] -cne [string]$CapturedEnvironment['HOMEVPN_POLICY_PROFILE_ID']){throw 'Prelaunch witness lost its captured native identity.'}
  $privateRoot=Resolve-RouterVPNPrivateRoot $Root
  $capturedRoot=Resolve-RouterVPNPrivateRoot ([string]$CapturedEnvironment['HOMEVPN_ROOT'])
  if(-not [string]::Equals($privateRoot,$capturedRoot,[StringComparison]::OrdinalIgnoreCase)){throw 'Prelaunch witness has another private root.'}
  $directory=Resolve-RouterVPNPrivateChild $privateRoot $RuntimeDir
  $category=Resolve-RouterVPNPrivateChild $privateRoot 'run/tor-bridge'
  if(-not [string]::Equals((Split-Path -Parent $directory),$category,[StringComparison]::OrdinalIgnoreCase) -or
     (Split-Path -Leaf $directory) -cnotmatch '^session-[A-Za-z0-9]+$' -or
     -not (Test-Path -LiteralPath $directory -PathType Container)){throw 'Prelaunch witness has another private runtime.'}
  $before=Get-Item -LiteralPath $directory -Force
  $inputs=[ordered]@{
    'torrc'='HOMEVPN_TOR_TORRC_SHA256';'tor-defaults'='HOMEVPN_TOR_DEFAULTS_SHA256';
    'tor-profile.json'='HOMEVPN_TOR_PROFILE_SHA256';'tor-capture.json'='HOMEVPN_TOR_CAPTURE_SHA256';
    'sing-box.json'='HOMEVPN_TOR_CONFIG_SHA256'
  }
  foreach($key in @($inputs.Values)+@('HOMEVPN_TOR_SOURCE_SHA256')){
    if([string]$CapturedEnvironment[$key] -cnotmatch '^[a-f0-9]{64}$'){throw 'Prelaunch witness lacks an exact captured digest.'}
  }
  # Only the pristine captured inputs and empty Tor data directory may exist.
  # A native admission, progress, proof, pending write or earlier receipt is
  # evidence that this wrapper cannot claim a no-native-process failure.
  $verifyInputs={
    Assert-RouterVPNNoReparseAncestors $directory
    $entries=@(Get-ChildItem -LiteralPath $directory -Force)
    if($entries.Count -lt 6 -or $entries.Count -gt 7){throw 'Prelaunch runtime contains native or unowned output.'}
    foreach($entry in $entries){
      if($entry.Name -cne 'tor-data' -and $entry.Name -cne 'stop.json' -and -not (@($inputs.Keys) -ccontains $entry.Name)){throw 'Prelaunch runtime contains native or unowned output.'}
      Assert-RouterVPNNoReparseAncestors $entry.FullName
    }
    $data=Join-Path $directory 'tor-data'
    if(-not (Test-Path -LiteralPath $data -PathType Container) -or @(Get-ChildItem -LiteralPath $data -Force).Count -ne 0){throw 'Prelaunch Tor data is not an empty captured directory.'}
    foreach($entry in $inputs.GetEnumerator()){
      $path=Join-Path $directory $entry.Key
      $digest=Get-RouterVPNPrivateFileSHA256 $path 'Captured Tor prelaunch input' 4194304
      if($digest -cne [string]$CapturedEnvironment[$entry.Value]){throw 'Prelaunch input changed after capture.'}
    }
    $stopPath=Join-Path $directory 'stop.json'
    if(Test-Path -LiteralPath $stopPath){
      $stop=Read-RouterVPNPrivateJson $stopPath 'Captured Tor stop request' 4096
      $fields=@($stop.PSObject.Properties.Name)
      if($fields.Count -lt 3 -or $fields.Count -gt 4 -or
         @($fields|Where-Object{@('schema','session_id','source_sha256','closed') -cnotcontains $_}).Count -ne 0 -or
         $stop.schema -ne 1 -or [string]$stop.session_id -cne $Session -or
         [string]$stop.source_sha256 -cne [string]$CapturedEnvironment['HOMEVPN_TOR_SOURCE_SHA256']){throw 'Prelaunch stop request belongs to another captured owner.'}
      $closed=$stop.PSObject.Properties['closed']
      if($null -ne $closed -and (-not ($closed.Value -is [bool]) -or $closed.Value)){throw 'Prelaunch stop request claims a native close.'}
    }
    $current=Get-Item -LiteralPath $directory -Force
    if(-not $current.PSIsContainer -or $current.CreationTimeUtc -ne $before.CreationTimeUtc -or $current.FullName -cne $before.FullName){throw 'Prelaunch runtime changed during verification.'}
  }
  & $verifyInputs
  $capture=Read-RouterVPNPrivateJson (Join-Path $directory 'tor-capture.json') 'Captured Tor launch' 16384
  $profile=Read-RouterVPNPrivateJson (Join-Path $directory 'tor-profile.json') 'Captured Tor profile' 4194304
  $config=Read-RouterVPNPrivateJson (Join-Path $directory 'sing-box.json') 'Captured Tor graph' 4194304
  if($capture.schema -ne 1 -or [string]$capture.session_id -cne $Session -or [string]$capture.target_os -cne 'windows' -or
     [string]$capture.tor_binary -cne $TorBinary -or [string]$profile.id -cne [string]$CapturedEnvironment['HOMEVPN_PROFILE_ID']){throw 'Prelaunch files belong to another captured owner.'}
  $services=@($config.services)
  if($services.Count -ne 1 -or [string]$services[0].type -cne 'routervpn-desktop-tor-network' -or
     [string]$services[0].tag -cne 'routervpn-tor-physical' -or [string]$services[0].session_id -cne $Session -or
     [string]$services[0].source_sha256 -cne [string]$CapturedEnvironment['HOMEVPN_TOR_SOURCE_SHA256']){throw 'Prelaunch graph has another native physical owner.'}
  & $verifyInputs
  $receipt=[ordered]@{schema=1;session_id=$Session;source_sha256=[string]$CapturedEnvironment['HOMEVPN_TOR_SOURCE_SHA256'];config_sha256=[string]$CapturedEnvironment['HOMEVPN_TOR_CONFIG_SHA256'];no_native_process=$true}|ConvertTo-Json -Compress
  if($receipt.Length -gt 1024){throw 'Prelaunch failure witness exceeds its bound.'}
  Write-RouterVPNPrivateTextAtomic (Join-Path $directory 'prelaunch-failed.json') $receipt
}
$CapturedEnvironment=Get-RouterVPNTorNativeEnvironment ([Environment]::GetEnvironmentVariables('Process'))
$LaunchState=@{StartAttempted=$false;NoNativeChild=$true;NoChildFailure=$false}
try{
  foreach($file in @($KillSwitch,$JobHelper,$Selector,$TorBinary,$NativeBinary)){
    Assert-RouterVPNNoReparseAncestors $file
    if(-not(Test-Path -LiteralPath $file -PathType Leaf)){throw 'Tor native helper is missing.'}
  }
  . $JobHelper
  . $Selector
  $verified=Get-RouterVPNStandardEngine $Root
  if(-not [string]::Equals([IO.Path]::GetFullPath($verified),[IO.Path]::GetFullPath($NativeBinary),[StringComparison]::OrdinalIgnoreCase)){throw 'Tor native engine changed after capture.'}
  foreach($name in @('torrc','tor-defaults','tor-profile.json','tor-capture.json','sing-box.json')){
    $file=Join-Path $RuntimeDir $name
    Assert-RouterVPNNoReparseAncestors $file
    if(-not(Test-Path -LiteralPath $file -PathType Leaf)){throw 'Captured Tor native input is missing.'}
  }
  $info=Get-Item -LiteralPath $TorBinary -Force
  if($info.Length -le 0 -or $info.Length -gt 402653184){throw 'Captured standalone Tor executable exceeds its bound.'}
  if((Get-FileHash -LiteralPath $TorBinary -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$env:HOMEVPN_TOR_BINARY_SHA256){throw 'Standalone Tor bytes changed after capture.'}
  & $NativeBinary routervpn-tor --help | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Native Tor command is unavailable.'}
  & $NativeBinary check -D $RuntimeDir -c (Join-Path $RuntimeDir 'sing-box.json') | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Native Tor graph was rejected.'}
  function Invoke-RouterVPNTorKillSwitch([string]$Kind){
    & $KillSwitch -Action $Kind -Root $Root -Endpoint $BridgeEndpoint -TunnelAlias $TunnelAlias
    if($LASTEXITCODE -ne 0){throw "Windows Tor kill-switch $Kind failed."}
  }
  Invoke-RouterVPNTorKillSwitch 'check'
  if($Action -eq 'check'){exit 0}
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  $principal=New-Object Security.Principal.WindowsPrincipal($identity)
  if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Native Windows Tor requires an elevated Router VPN process.'}
  Invoke-RouterVPNTorKillSwitch 'prepare'
  Invoke-RouterVPNTorOwnedNative -NativeBinary $NativeBinary -RuntimeDir $RuntimeDir -Session $Session -TorBinary $TorBinary -CapturedEnvironment $CapturedEnvironment -LaunchState $LaunchState
}catch{
  try{
    $null=Write-RouterVPNTorPrelaunchFailure -Action $Action -Root $Root -RuntimeDir $RuntimeDir -Session $Session -TorBinary $TorBinary -CapturedEnvironment $CapturedEnvironment -LaunchState $LaunchState
  }catch{
    # An unavailable/tampered private workspace has no trustworthy witness.
    # Retain it for the controller and preserve the original launch failure.
    Write-Warning 'Tor prelaunch failure could not retain a verified no-native-process witness.'
  }
  throw
}
