param([string]$SourceRoot=(Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$script:Checks=0
. (Join-Path $SourceRoot 'client/Private-RouterVPN-Job.ps1')
. (Join-Path $SourceRoot 'client/Private-RouterVPN-State.ps1')
function Check([bool]$Value,[string]$Message){$script:Checks++;if(-not $Value){throw $Message}}
function Unwrap($Value){
  $errorObject=if($Value -is [Management.Automation.ErrorRecord]){$Value.Exception}else{$Value}
  while($null -ne $errorObject.InnerException){$errorObject=$errorObject.InnerException}
  return $errorObject
}
function Detect-Defect([scriptblock]$Action,[string]$Expected){
  $failure=$null
  try{$null=& $Action}catch{$failure=Unwrap $_}
  Check ($null -ne $failure -and $failure.Message -ceq $Expected) ('The executable fixture did not detect: '+$Expected)
}
$source=[IO.File]::ReadAllText((Join-Path $SourceRoot 'client/native-tor-bridge-windows.ps1'))
$tokens=$null;$parseErrors=$null
$tree=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$parseErrors)
Check ($parseErrors.Count -eq 0) 'The shipping Windows Tor wrapper does not parse.'
function Shipping-Function([string]$Name){
  $definitions=@($tree.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $Name},$true))
  Check ($definitions.Count -eq 1) ('Shipping function changed: '+$Name)
  return $definitions[0].Extent.Text
}
$environmentSource=Shipping-Function 'Get-RouterVPNTorNativeEnvironment'
$ownerSource=Shipping-Function 'Invoke-RouterVPNTorOwnedNative'
$witnessSource=Shipping-Function 'Write-RouterVPNTorPrelaunchFailure'
. ([scriptblock]::Create($environmentSource))
. ([scriptblock]::Create($ownerSource))
. ([scriptblock]::Create($witnessSource))
$calls=@($tree.FindAll({param($node)$node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Invoke-RouterVPNTorOwnedNative'},$true))
Check ($calls.Count -eq 1) 'The shipping wrapper has no unique native launch dispatch.'
$script:ShippingCall=[scriptblock]::Create($calls[0].Extent.Text)

# Execute the actual environment capture, including hostile values and the
# real helper's serializer. No native process is launched by this fixture.
function Assert-EnvironmentCapture {
  $snapshot=New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
  $snapshot.Add('=C:','C:\captured\directory');$snapshot.Add('=z:','Z:\another')
  $snapshot.Add('SystemRoot','C:\Windows');$snapshot.Add('C:','real variable')
  $snapshot.Add('HOMEVPN_TOR_SESSION',('a'*32));$snapshot.Add('EMPTY','')
  $snapshot.Add('Unicode',('private '+[char]0x03bb+' '+[char]0x4e2d))
  $snapshot.Add('Literal',"`$(not-a-command) & | value=with=equals`nnext")
  $captured=Get-RouterVPNTorNativeEnvironment $snapshot
  Check ($captured.Count -eq $snapshot.Count-2 -and -not $captured.ContainsKey('=C:') -and -not $captured.ContainsKey('=z:')) 'Windows drive bookkeeping was not removed exactly.'
  foreach($entry in $snapshot.GetEnumerator()){
    if($entry.Key -cmatch '^=[A-Za-z]:$'){continue}
    Check ($captured.ContainsKey($entry.Key) -and $captured[$entry.Key] -ceq $entry.Value) 'A real captured environment variable changed.'
  }
  $method=[RouterVPN.PrivateJobOwner].GetMethod('EnvironmentBlock',[Reflection.BindingFlags]'Static,NonPublic')
  $arguments=New-Object object[] 1;$arguments[0]=$captured.PSObject.BaseObject
  $block=[char[]]$method.Invoke($null,$arguments)
  Check ($block.Length -ge 2 -and $block[-1] -eq [char]0 -and $block[-2] -eq [char]0) 'The filtered capture is not a valid native Unicode environment.'
  $snapshot['Unicode']='replacement';$snapshot.Add('LATE','new')
  Check ($captured['Unicode'] -cne 'replacement' -and -not $captured.ContainsKey('LATE')) 'The environment capture retained mutable input ownership.'
  $foreign=Get-RouterVPNTorNativeEnvironment (@{'=not-a-drive'='invalid'})
  Check ($foreign.ContainsKey('=not-a-drive')) 'An unknown malformed environment entry was silently discarded.'
  $arguments[0]=$foreign.PSObject.BaseObject
  $rejected=$false;try{$null=$method.Invoke($null,$arguments)}catch{$rejected=$true}
  Check $rejected 'The private helper accepted an invalid non-drive environment name.'
  $rejected=$false;try{$null=Get-RouterVPNTorNativeEnvironment (@{'typed'=42})}catch{$rejected=$true}
  Check $rejected 'The wrapper coerced a malformed environment value into a different capture.'
}
Assert-EnvironmentCapture

# The actual sealed owner/typed launch exception are used. Their native handles
# remain invalid and no OS API is called. Only the helper calls below are doubled;
# the shipping wrapper's dispatch, catch, rethrow, polling and finally execute.
$script:OwnerFields=[Reflection.BindingFlags]'Instance,NonPublic'
function Set-OwnerField([string]$Name,$Value){
  $field=[RouterVPN.PrivateJobOwner].GetField($Name,$script:OwnerFields)
  Check ($null -ne $field) ('The inert fixture owner field changed: '+$Name)
  $field.SetValue($script:ExpectedOwner,$Value)
}
function New-LaunchFailure($RecoveryOwner,[bool]$Created){
  $constructor=@([RouterVPN.PrivateJobStartException].GetConstructors($script:OwnerFields))
  Check ($constructor.Count -eq 1) 'The typed launch failure contract changed.'
  $arguments=New-Object object[] 5
  $arguments[0]='fixture launch';$arguments[1]=5;$arguments[2]=$Created;$arguments[3]=$false
  if($null -ne $RecoveryOwner){$arguments[4]=$RecoveryOwner.PSObject.BaseObject}
  return $constructor[0].Invoke($arguments)
}
function Reset-Case([object[]]$Waits,[object[]]$Stops,[uint32]$ExitCode=0){
  $script:ExpectedOwner=[Activator]::CreateInstance([RouterVPN.PrivateJobOwner],$true)
  Set-OwnerField 'closed' $true
  Set-OwnerField 'exited' $false
  Set-OwnerField 'exitCode' $ExitCode
  $script:Waits=New-Object 'System.Collections.Generic.Queue[object]'
  $script:Stops=New-Object 'System.Collections.Generic.Queue[object]'
  foreach($value in $Waits){$script:Waits.Enqueue($value)}
  foreach($value in $Stops){$script:Stops.Enqueue($value)}
  $script:Trace=New-Object 'System.Collections.Generic.List[string]'
  $script:Joined=$false;$script:ClosedWithoutJoin=$false;$script:LaunchError=$null
  $script:LaunchState=@{StartAttempted=$false;NoNativeChild=$true;NoChildFailure=$false}
  $script:ExpectedNativeBinary='C:\Router VPN\sing-box.exe';$script:ExpectedRuntime='C:\Private\run\tor-bridge\session-a';$script:ExpectedTorBinary='C:\Router VPN\tor.exe'
  $script:CapturedEnvironment=Get-RouterVPNTorNativeEnvironment (@{'HOMEVPN_TOR_SESSION'=('a'*32);'EMPTY'='';'PATH'='captured path'})
}
function Start-RouterVPNPrivateJob {
  param($FilePath,[string[]]$ArgumentList,$WorkingDirectory,$Environment)
  $script:Trace.Add('start')
  Check ($FilePath -ceq $script:ExpectedNativeBinary -and $WorkingDirectory -ceq $script:ExpectedRuntime) 'The wrapper changed its captured executable or runtime.'
  Check (($ArgumentList -join '|') -ceq ('routervpn-tor|--runtime-dir|'+$script:ExpectedRuntime+'|--session|'+('a'*32)+'|--tor-binary|'+$script:ExpectedTorBinary)) 'The wrapper changed the exact native CLI arguments.'
  Check ([object]::ReferenceEquals($Environment,$script:CapturedEnvironment)) 'The native call used another environment instead of the captured snapshot.'
  if($null -ne $script:LaunchError){throw $script:LaunchError}
  return $script:ExpectedOwner
}
function Wait-RouterVPNPrivateJob {
  param($Owner,[int]$Milliseconds)
  Check ([object]::ReferenceEquals($Owner,$script:ExpectedOwner)) 'Polling adopted an unrelated process owner.'
  Check ($Milliseconds -eq 250) 'The wrapper native wait is not individually bounded.'
  $script:Trace.Add('wait')
  if($script:Waits.Count -eq 0){throw 'The wrapper consumed an unexpected native wait; fixture cannot prove cleanup.'}
  $result=$script:Waits.Dequeue()
  if($result -is [string]){throw 'fixture native wait failed'}
  if([bool]$result){$script:Joined=$true;Set-OwnerField 'exited' $true}
  return [bool]$result
}
function Stop-RouterVPNPrivateJob {
  param($Owner,[int]$Milliseconds)
  Check ([object]::ReferenceEquals($Owner,$script:ExpectedOwner)) 'Termination adopted an unrelated process owner.'
  Check ($Milliseconds -eq 5000) 'The wrapper termination wait is not individually bounded.'
  $script:Trace.Add('stop')
  if($script:Stops.Count -eq 0){throw 'The wrapper attempted an unexpected native termination.'}
  $result=$script:Stops.Dequeue()
  if($result -is [string]){throw 'fixture native termination failed'}
  if([bool]$result){$script:Joined=$true;Set-OwnerField 'exited' $true}
  return [bool]$result
}
function Close-RouterVPNPrivateJob {
  param($Owner)
  Check ([object]::ReferenceEquals($Owner,$script:ExpectedOwner)) 'Close adopted an unrelated process owner.'
  $script:Trace.Add('close')
  if(-not $script:Joined){$script:ClosedWithoutJoin=$true;throw 'fixture observed premature Close'}
}
function Start-Sleep {
  param([int]$Milliseconds)
  Check ($Milliseconds -eq 250) 'Cleanup retry delay exceeded its bound.'
  $script:Trace.Add('delay')
  if($script:Trace.Count -gt 64){throw 'The fixture exhausted its bounded cleanup outcomes.'}
}
function Invoke-Case {
  $NativeBinary='C:\Router VPN\sing-box.exe';$RuntimeDir='C:\Private\run\tor-bridge\session-a'
  $Session='a'*32;$TorBinary='C:\Router VPN\tor.exe';$CapturedEnvironment=$script:CapturedEnvironment;$LaunchState=$script:LaunchState
  $failure=$null
  try{& $script:ShippingCall}catch{$failure=Unwrap $_}
  Check (-not $script:ClosedWithoutJoin) 'The wrapper closed ownership before actual exit.'
  return $failure
}
function Assert-Recovery {
  Reset-Case @($false,$false,$true) @($false,$false)
  $failure=New-LaunchFailure $script:ExpectedOwner $true
  $script:LaunchError=New-Object InvalidOperationException('fixture outer launch error',$failure)
  $observed=Invoke-Case
  Check ($null -ne $observed -and $observed -is [RouterVPN.PrivateJobStartException]) 'The wrapper replaced the captured launch failure.'
  Check (($script:Trace -join ',') -ceq 'start,wait,stop,wait,stop,wait,close') 'The wrapper did not retain the recovery owner through pending cleanup.'
  Check ($script:Joined -and [object]::ReferenceEquals($observed.RecoveryOwner,$script:ExpectedOwner)) 'The typed launch failure lost its exact recovery owner.'
}

Reset-Case @($false,$false,$true,$true) @()
$observed=Invoke-Case
Check ($null -eq $observed -and ($script:Trace -join ',') -ceq 'start,wait,wait,wait,wait,close') 'Normal native polling terminated or changed the captured owner.'
Reset-Case @($false,$true,$true) @() 17
$observed=Invoke-Case
Check ($null -ne $observed -and $observed.Message -ceq 'Native Tor exited without completing its owned lifecycle.') 'An unsuccessful native exit was reported as a successful wrapper lifecycle.'
Check (($script:Trace -join ',') -ceq 'start,wait,wait,wait,close') 'An already exited native child was force-stopped.'
Assert-Recovery

Reset-Case @($true) @()
$script:LaunchError=New-LaunchFailure $script:ExpectedOwner $true
$observed=Invoke-Case
Check ($observed -is [RouterVPN.PrivateJobStartException] -and ($script:Trace -join ',') -ceq 'start,wait,close') 'A naturally exited recovery owner was terminated again.'
Reset-Case @() @()
$script:LaunchError=New-LaunchFailure $null $false
$observed=Invoke-Case
Check ($observed -is [RouterVPN.PrivateJobStartException] -and ($script:Trace -join ',') -ceq 'start') 'A no-child launch failure invented a cleanup owner.'
Reset-Case @() @()
$script:LaunchError=New-Object InvalidOperationException('fixture unrelated launch error')
$script:LaunchError | Add-Member NoteProperty RecoveryOwner $script:ExpectedOwner
$observed=Invoke-Case
Check ($observed.Message -ceq 'fixture unrelated launch error' -and ($script:Trace -join ',') -ceq 'start') 'An unrelated exception supplied a forged recovery owner.'

Reset-Case @('error',$false,$false,$true) @($false,$false)
$observed=Invoke-Case
Check ($observed.Message -ceq 'fixture native wait failed' -and ($script:Trace -join ',') -ceq 'start,wait,wait,stop,wait,stop,wait,close') 'A failed native wait discarded unconfirmed process ownership.'
Reset-Case @('error','error',$false,$true) @('error',$false)
$observed=Invoke-Case
Check ($observed.Message -ceq 'fixture native wait failed' -and ($script:Trace -join ',') -ceq 'start,wait,wait,stop,delay,wait,stop,wait,close') 'Cleanup errors became a false exit acknowledgement or a busy retry.'
Reset-Case @('error',$false) @($true)
$observed=Invoke-Case
Check ($observed.Message -ceq 'fixture native wait failed' -and ($script:Trace -join ',') -ceq 'start,wait,wait,stop,close' -and $script:Joined) 'An actual termination/join acknowledgement was discarded.'

# Three intended regressions execute through the same shipping functions.
$changed=$environmentSource.Replace("if(`$entry.Key -cmatch '^=[A-Za-z]:`$'){continue}",'if($false){continue}')
Check ($changed -cne $environmentSource) 'Environment mutation did not reach its actual filter.'
. ([scriptblock]::Create($changed))
Detect-Defect {Assert-EnvironmentCapture} 'Windows drive bookkeeping was not removed exactly.'
. ([scriptblock]::Create($environmentSource))
$changed=$ownerSource.Replace('$owned=$launchFailure.RecoveryOwner','$owned=$null')
Check ($changed -cne $ownerSource) 'Recovery mutation did not reach its actual capture.'
. ([scriptblock]::Create($changed))
Detect-Defect {Assert-Recovery} 'The wrapper did not retain the recovery owner through pending cleanup.'
. ([scriptblock]::Create($ownerSource))
$changed=$ownerSource.Replace('$joined=Stop-RouterVPNPrivateJob -Owner $owned -Milliseconds 5000','$null=Stop-RouterVPNPrivateJob -Owner $owned -Milliseconds 5000;$joined=$true')
Check ($changed -cne $ownerSource) 'Timeout mutation did not reach its actual completion boundary.'
. ([scriptblock]::Create($changed))
Detect-Defect {Assert-Recovery} 'The wrapper closed ownership before actual exit.'
. ([scriptblock]::Create($ownerSource))
# Exercise the actual outer dispatch/catch and exclusive receipt writer against
# real private files. Only executable, firewall and elevation boundaries below
# are doubled; native admission state, input hashes and filesystem guards run.
$mainNodes=@($tree.EndBlock.Statements|Where-Object{$_ -is [Management.Automation.Language.TryStatementAst]})
Check ($mainNodes.Count -eq 1) 'The wrapper lost its unique launch/catch ownership scope.'
$mainSource=$mainNodes[0].Extent.Text
foreach($pair in @(
  @('[Security.Principal.WindowsIdentity]::GetCurrent()','(Get-FixtureWindowsIdentity)'),
  @('New-Object Security.Principal.WindowsPrincipal($identity)','(Get-FixtureWindowsPrincipal $identity)')
)){
  Check ($mainSource.Contains($pair[0])) 'The controlled elevation boundary changed.'
  $mainSource=$mainSource.Replace($pair[0],$pair[1])
}
$script:MainDispatch=[scriptblock]::Create($mainSource)
function Get-FixtureWindowsIdentity{return [pscustomobject]@{owned=$true}}
function Get-FixtureWindowsPrincipal($Identity){
  Check $Identity.owned 'The elevation fixture received another identity.'
  $value=New-Object psobject
  $value|Add-Member ScriptMethod IsInRole {param($Role)return $true}
  return $value
}
$script:WitnessBase=Join-Path ([IO.Path]::GetTempPath()) ('routervpn-tor-witness-'+[Guid]::NewGuid().ToString('N'))
$script:WitnessSequence=0
[void][IO.Directory]::CreateDirectory($script:WitnessBase)
function New-WitnessFixture {
  $script:WitnessSequence++
  $root=Join-Path $script:WitnessBase ('private-'+$script:WitnessSequence)
  $runtime=Join-Path $root ('run/tor-bridge/session-'+$script:WitnessSequence)
  [void][IO.Directory]::CreateDirectory((Join-Path $runtime 'tor-data'))
  $helpers=Join-Path $root 'package';[void][IO.Directory]::CreateDirectory($helpers)
  $native=Join-Path $helpers 'native fixture.ps1';$tor=Join-Path $helpers 'tor fixture.exe'
  [IO.File]::WriteAllText($tor,'captured fixture executable')
  [IO.File]::WriteAllText($native,@'
$global:LASTEXITCODE=0
if(($args[0] -ceq 'routervpn-tor' -and $global:TorWitnessFailure -ceq 'help') -or ($args[0] -ceq 'check' -and $global:TorWitnessFailure -ceq 'graph')){$global:LASTEXITCODE=19}
'@)
  $job=Join-Path $helpers 'job.ps1';[IO.File]::WriteAllText($job,'# Native helper calls are controlled by the actual-owner fixture.')
  $selector=Join-Path $helpers 'selector.ps1'
  [IO.File]::WriteAllText($selector,'function Get-RouterVPNStandardEngine($Root){return $global:TorWitnessNativePath}')
  $kill=Join-Path $helpers 'kill.ps1'
  [IO.File]::WriteAllText($kill,@'
param($Action,$Root,$Endpoint,$TunnelAlias)
$global:TorWitnessFirewall.Add([string]$Action)
$global:LASTEXITCODE=0
if($global:TorWitnessFailure -ceq ('firewall-'+$Action)){$global:LASTEXITCODE=23}
'@)
  $capture=[ordered]@{schema=1;session_id=('a'*32);isolation_secret=('b'*64);target_os='windows';tor_binary=$tor}|ConvertTo-Json -Compress
  $config=[ordered]@{services=@([ordered]@{type='routervpn-desktop-tor-network';tag='routervpn-tor-physical';session_id=('a'*32);source_sha256=('c'*64)})}|ConvertTo-Json -Depth 8 -Compress
  $content=[ordered]@{'torrc'="ClientOnly 1`nDisableNetwork 1`n";'tor-defaults'="`n";'tor-profile.json'='{"id":"captured-tor-node"}';'tor-capture.json'=$capture;'sing-box.json'=$config}
  $digests=[ordered]@{'torrc'='HOMEVPN_TOR_TORRC_SHA256';'tor-defaults'='HOMEVPN_TOR_DEFAULTS_SHA256';'tor-profile.json'='HOMEVPN_TOR_PROFILE_SHA256';'tor-capture.json'='HOMEVPN_TOR_CAPTURE_SHA256';'sing-box.json'='HOMEVPN_TOR_CONFIG_SHA256'}
  $environment=@{HOMEVPN_ROOT=$root;HOMEVPN_TOR_SESSION=('a'*32);HOMEVPN_TOR_SOURCE_SHA256=('c'*64);HOMEVPN_STANDARD_ENGINE='native';HOMEVPN_PROFILE_ID='captured-tor-node';HOMEVPN_POLICY_PROFILE_ID='captured-tor-node'}
  foreach($entry in $content.GetEnumerator()){
    $path=Join-Path $runtime $entry.Key
    [IO.File]::WriteAllText($path,$entry.Value,(New-Object Text.UTF8Encoding $false))
    $environment[$digests[$entry.Key]]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
  }
  $environment['HOMEVPN_TOR_BINARY_SHA256']=(Get-FileHash -LiteralPath $tor -Algorithm SHA256).Hash.ToLowerInvariant()
  return [pscustomobject]@{Root=$root;Runtime=$runtime;Native=$native;Tor=$tor;Job=$job;Selector=$selector;Kill=$kill;Environment=$environment;Content=$content;Digests=$digests}
}
function Invoke-WitnessWriter($Fixture,$State,[string]$Action='up'){
  Write-RouterVPNTorPrelaunchFailure -Action $Action -Root $Fixture.Root -RuntimeDir $Fixture.Runtime -Session ('a'*32) -TorBinary $Fixture.Tor -CapturedEnvironment $Fixture.Environment -LaunchState $State
}
function Fresh-WitnessState{return @{StartAttempted=$false;NoNativeChild=$true;NoChildFailure=$false}}
function Check-Witness($Fixture,[bool]$Expected,[string]$Message){
  $path=Join-Path $Fixture.Runtime 'prelaunch-failed.json'
  Check ((Test-Path -LiteralPath $path -PathType Leaf) -eq $Expected) $Message
  if($Expected){
    $data=[IO.File]::ReadAllText($path)|ConvertFrom-Json
    Check (@($data.PSObject.Properties).Count -eq 5 -and $data.schema -eq 1 -and $data.no_native_process -is [bool] -and $data.no_native_process) 'Prelaunch receipt did not retain its exact bounded schema.'
    Check ($data.session_id -ceq ('a'*32) -and $data.source_sha256 -ceq ('c'*64) -and $data.config_sha256 -ceq $Fixture.Environment['HOMEVPN_TOR_CONFIG_SHA256']) 'Prelaunch receipt adopted another captured path.'
    Check ((Get-Item -LiteralPath $path).Length -lt 1024) 'Prelaunch receipt exceeded its bound.'
  }
  foreach($entry in $Fixture.Content.GetEnumerator()){
    Check ([IO.File]::ReadAllText((Join-Path $Fixture.Runtime $entry.Key)) -ceq $entry.Value) 'Prelaunch receipt deleted or changed a captured input.'
  }
  Check (-not(Test-Path -LiteralPath (Join-Path $Fixture.Runtime 'stopped.json'))) 'The wrapper forged a native stopped receipt.'
  Check (-not($global:TorWitnessFirewall -contains 'release')) 'A prelaunch failure released captured protection.'
}
function Assert-MainWitness([string]$Failure,[bool]$Expected){
  $fixture=New-WitnessFixture
  $waits=@();$exit=0
  if($Failure -in @('native-error','normal')){$waits=@($true,$true);if($Failure -eq 'native-error'){$exit=17}}
  if($Failure -in @('typed-recovery','typed-recovery-no-child')){$waits=@($true)}
  Reset-Case $waits @() $exit
  $script:ExpectedNativeBinary=$fixture.Native;$script:ExpectedRuntime=$fixture.Runtime;$script:ExpectedTorBinary=$fixture.Tor
  $script:CapturedEnvironment=Get-RouterVPNTorNativeEnvironment $fixture.Environment
  if($Failure -eq 'typed-no-child'){$script:LaunchError=New-LaunchFailure $null $false}
  if($Failure -eq 'typed-created'){$script:LaunchError=New-LaunchFailure $null $true}
  if($Failure -eq 'typed-recovery'){$script:LaunchError=New-LaunchFailure $script:ExpectedOwner $true}
  if($Failure -eq 'typed-recovery-no-child'){$script:LaunchError=New-LaunchFailure $script:ExpectedOwner $false}
  if($Failure -eq 'untyped'){$script:LaunchError=New-Object InvalidOperationException('untyped Start failure')}
  $global:TorWitnessFailure=$Failure;$global:TorWitnessNativePath=$fixture.Native
  $global:TorWitnessFirewall=New-Object 'System.Collections.Generic.List[string]'
  $Root=$fixture.Root;$RuntimeDir=$fixture.Runtime;$Session='a'*32;$TorBinary=$fixture.Tor;$NativeBinary=$fixture.Native
  $KillSwitch=$fixture.Kill;$JobHelper=$fixture.Job;$Selector=$fixture.Selector;$Action='up';$TunnelAlias='router-vpn-tor';$BridgeEndpoint='198.51.100.1'
  $CapturedEnvironment=$script:CapturedEnvironment;$LaunchState=$script:LaunchState
  if($Failure -in @('helper','witness-tamper-helper')){Remove-Item -LiteralPath $fixture.Job}
  if($Failure -eq 'witness-tamper-helper'){
    $fixture.Content['torrc']+='# changed input; original helper error must survive'
    [IO.File]::WriteAllText((Join-Path $fixture.Runtime 'torrc'),$fixture.Content['torrc'])
  }
  $oldBinary=[Environment]::GetEnvironmentVariable('HOMEVPN_TOR_BINARY_SHA256','Process')
  [Environment]::SetEnvironmentVariable('HOMEVPN_TOR_BINARY_SHA256',$fixture.Environment['HOMEVPN_TOR_BINARY_SHA256'],'Process')
  $errorObject=$null
  try{try{& $script:MainDispatch}catch{$errorObject=Unwrap $_}}finally{[Environment]::SetEnvironmentVariable('HOMEVPN_TOR_BINARY_SHA256',$oldBinary,'Process')}
  Check (($null -ne $errorObject) -eq ($Failure -ne 'normal')) 'The outer launch/catch lost its original success or failure.'
  if($Failure -eq 'witness-tamper-helper'){Check ($errorObject.Message -ceq 'Tor native helper is missing.') 'A rejected witness replaced the original launch error.'}
  Check-Witness $fixture $Expected ('Wrong no-native witness eligibility for '+$Failure)
  if($Failure -in @('typed-created','typed-recovery','typed-recovery-no-child','untyped','native-error','normal')){Check ($LaunchState.StartAttempted -and -not $LaunchState.NoNativeChild) 'A possible native child retained no-child authority.'}
}
function Assert-TamperedWitness {
  $fixture=New-WitnessFixture
  [IO.File]::AppendAllText((Join-Path $fixture.Runtime 'torrc'),'# changed after capture')
  $failure=$null
  try{Invoke-WitnessWriter $fixture (Fresh-WitnessState)}catch{$failure=Unwrap $_}
  Check ($null -ne $failure -and -not(Test-Path -LiteralPath (Join-Path $fixture.Runtime 'prelaunch-failed.json'))) 'Changed captured input received a no-native witness.'
}
try{
  foreach($failure in @('helper','help','graph','firewall-check','firewall-prepare','typed-no-child')){Assert-MainWitness $failure $true}
  foreach($failure in @('typed-created','typed-recovery','typed-recovery-no-child','untyped','native-error','normal','witness-tamper-helper')){Assert-MainWitness $failure $false}
  $global:TorWitnessFirewall=New-Object 'System.Collections.Generic.List[string]'
  foreach($action in @('check','down')){
    $fixture=New-WitnessFixture;Invoke-WitnessWriter $fixture (Fresh-WitnessState) $action
    Check-Witness $fixture $false 'A non-up invocation wrote a no-native witness.'
  }
  foreach($extra in @('progress.json','proof.json','stopped.json','native-admitted.json','.progress.json.pending','foreign.json')){
    $fixture=New-WitnessFixture;[IO.File]::WriteAllText((Join-Path $fixture.Runtime $extra),'native or foreign ownership')
    $failure=$null;try{Invoke-WitnessWriter $fixture (Fresh-WitnessState)}catch{$failure=Unwrap $_}
    Check ($null -ne $failure -and -not(Test-Path -LiteralPath (Join-Path $fixture.Runtime 'prelaunch-failed.json'))) 'An existing native/foreign output received a no-native witness.'
    Check ([IO.File]::ReadAllText((Join-Path $fixture.Runtime $extra)) -ceq 'native or foreign ownership') 'Witness handling changed another runtime owner.'
  }
  $fixture=New-WitnessFixture
  $receipt=Join-Path $fixture.Runtime 'prelaunch-failed.json';[IO.File]::WriteAllText($receipt,'prior-owner')
  $failure=$null;try{Invoke-WitnessWriter $fixture (Fresh-WitnessState)}catch{$failure=Unwrap $_}
  Check ($null -ne $failure -and [IO.File]::ReadAllText($receipt) -ceq 'prior-owner') 'A prelaunch witness overwrote an existing owner.'
  Assert-TamperedWitness
  foreach($kind in @('data','digest','session','source','profile','large','category','link')){
    $fixture=New-WitnessFixture
    switch($kind){
      'data'{[IO.File]::WriteAllText((Join-Path $fixture.Runtime 'tor-data/owned-native-data'),'in use')}
      'digest'{$fixture.Environment['HOMEVPN_TOR_PROFILE_SHA256']='d'*64}
      'session'{$fixture.Environment['HOMEVPN_TOR_SESSION']='d'*32}
      'source'{$fixture.Environment['HOMEVPN_TOR_SOURCE_SHA256']='d'*64}
      'profile'{$fixture.Environment['HOMEVPN_PROFILE_ID']='another';$fixture.Environment['HOMEVPN_POLICY_PROFILE_ID']='another'}
      'large'{[IO.File]::WriteAllText((Join-Path $fixture.Runtime 'torrc'),('x'*4194305))}
      'category'{$fixture.Runtime=Join-Path $fixture.Root 'run/other/session-other';[void][IO.Directory]::CreateDirectory($fixture.Runtime)}
      'link'{
        $leaf=Join-Path $fixture.Runtime 'torrc';$outside=Join-Path $fixture.Root 'outside-torrc'
        [IO.File]::Move($leaf,$outside)
        try{$null=New-Item -ItemType SymbolicLink -Path $leaf -Target $outside -ErrorAction Stop}catch{throw 'The witness fixture requires a real link rejection check on this host.'}
      }
    }
    $failure=$null;try{Invoke-WitnessWriter $fixture (Fresh-WitnessState)}catch{$failure=Unwrap $_}
    Check ($null -ne $failure -and -not(Test-Path -LiteralPath (Join-Path $fixture.Runtime 'prelaunch-failed.json'))) ('Unsafe private witness was accepted: '+$kind)
  }
  foreach($closed in @($null,$false)){
    $fixture=New-WitnessFixture;$stop=[ordered]@{schema=1;session_id=('a'*32);source_sha256=('c'*64)}
    if($null -ne $closed){$stop['closed']=$closed}
    [IO.File]::WriteAllText((Join-Path $fixture.Runtime 'stop.json'),($stop|ConvertTo-Json -Compress))
    Invoke-WitnessWriter $fixture (Fresh-WitnessState)
    Check-Witness $fixture $true 'An exact pending controller cancellation lost its no-native witness.'
  }
  foreach($invalid in @('closed','session','source','extra','typed')){
    $fixture=New-WitnessFixture;$stop=[ordered]@{schema=1;session_id=('a'*32);source_sha256=('c'*64);closed=$false}
    switch($invalid){'closed'{$stop.closed=$true};'session'{$stop.session_id='d'*32};'source'{$stop.source_sha256='d'*64};'extra'{$stop['foreign']=$true};'typed'{$stop.closed='false'}}
    [IO.File]::WriteAllText((Join-Path $fixture.Runtime 'stop.json'),($stop|ConvertTo-Json -Compress))
    $failure=$null;try{Invoke-WitnessWriter $fixture (Fresh-WitnessState)}catch{$failure=Unwrap $_}
    Check ($null -ne $failure -and -not(Test-Path -LiteralPath (Join-Path $fixture.Runtime 'prelaunch-failed.json'))) 'A foreign or completed stop request obtained no-native authority.'
  }
  $old='if(-not $launchFailure.ChildCreated -and -not $launchFailure.ChildExited -and $null -eq $owned)'
  $changed=$ownerSource.Replace($old,'if($true)')
  Check ($changed -cne $ownerSource) 'The child-created defect did not alter the typed admission guard.'
  . ([scriptblock]::Create($changed))
  Detect-Defect {Assert-MainWitness 'typed-recovery' $false} 'Wrong no-native witness eligibility for typed-recovery'
  . ([scriptblock]::Create($ownerSource))
  $old='if($digest -cne [string]$CapturedEnvironment[$entry.Value])'
  $changed=$witnessSource.Replace($old,'if($false)')
  Check ($changed -cne $witnessSource) 'The exact-input defect did not alter its shipping hash guard.'
  . ([scriptblock]::Create($changed))
  Detect-Defect {Assert-TamperedWitness} 'Changed captured input received a no-native witness.'
  . ([scriptblock]::Create($witnessSource))
}finally{
  if(Test-Path -LiteralPath $script:WitnessBase){Remove-Item -LiteralPath $script:WitnessBase -Recurse -Force}
}
Write-Output ("Windows Tor wrapper lifecycle checks passed: {0}; actual shipping dispatch/environment/exception/finally, bounded native-call doubles, exclusive prelaunch witnesses, and five executable defect controls. Windows Job kernel behavior is covered separately." -f $script:Checks)
