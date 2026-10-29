param([string]$Go='go',[string]$Source='')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$helper=if($Source){[IO.Path]::GetFullPath($Source)}else{Join-Path $PSScriptRoot 'Private-RouterVPN-Protection.ps1'}
. (Join-Path $PSScriptRoot 'Private-RouterVPN-State.ps1')
. $helper
$script:checks=0
function Check([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message};$script:checks++}
function Reject([scriptblock]$Body,[string]$Message){
  $failed=$false
  try { & $Body | Out-Null } catch { $failed=$true }
  Check $failed $Message
}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('routervpn-owned-protection-'+[Guid]::NewGuid().ToString('N'))
$names=@('HOMEVPN_ROOT','HOMEVPN_NATIVE_CONTROLLER','HOMEVPN_TOR_SESSION','HOMEVPN_EXTERNAL_SESSION','HOMEVPN_MULTIHOP_SESSION',
         'HOMEVPN_NODE_SESSION','PROTECTION_FIXTURE_OUTPUT','PROTECTION_FIXTURE_LOG','PROTECTION_FIXTURE_EXIT','GOOS','GOARCH','CGO_ENABLED')
$saved=@{}
foreach($name in $names){$saved[$name]=[Environment]::GetEnvironmentVariable($name,'Process');Remove-Item -LiteralPath ('Env:'+$name) -ErrorAction SilentlyContinue}
New-Item -ItemType Directory -Path $temp | Out-Null
try {
  $off='{"schema":1,"active":false,"policy":"off","phase":"off"}'
  $always='{"schema":1,"active":true,"policy":"always","phase":"retained"}'
  foreach($valid in @($off,$always,
    '{"schema":1,"active":true,"policy":"on-connect","phase":"owned"}',
    '{"schema":1,"active":true,"policy":"always","phase":"transition"}',
    '{"schema":1,"active":true,"policy":"","phase":"preparing"}')) {
    $value=ConvertFrom-RouterVPNOwnedProtectionStatus $valid
    Check ($value.schema -eq 1) 'Valid native protection status was rejected.'
  }
  foreach($invalid in @('', 'null','[]',($off+"`n"),(' '+$off),$off.Replace('1','2'),$off.Replace('false','"false"'),
    $off.Replace('"schema":1','"schema":1.0'),$off.Replace('"active":false','"active":false,"active":true'),
    $off.Replace('"policy":"off"','"unknown":0,"policy":"off"'),$off.Replace('false','true'),
    $off.Replace('"off","phase"','"always","phase"'),$always.Replace('true','false'),
    $always.Replace('"always"','"off"'),$always.Replace('retained','preparing'),$always.Replace('retained','connected'),
    $off.Replace('"active":false,',''),('x'*4097))) {
    Reject { ConvertFrom-RouterVPNOwnedProtectionStatus $invalid } 'Malformed or misleading native status was accepted.'
  }
  foreach($valid in @('{"schema":1,"absent":true}','{"schema":1,"absent":false}')){
    Check ((ConvertFrom-RouterVPNProtectionProbe $valid).schema -eq 1) 'Bounded probe record was rejected.'
  }
  foreach($invalid in @($off,'{"schema":1,"absent":"true"}','{"schema":1,"absent":true,"absent":false}',
    '{"schema":1,"absent":true,"active":false}','{"absent":true,"schema":1}','{"schema":1,"absent":null}')){
    Reject { ConvertFrom-RouterVPNProtectionProbe $invalid } 'Probe was confused with authoritative status.'
  }

  # Execute the real held-file/child dispatch against a tiny real executable.
  # Only the external controller's public JSON is a fixture. Package selection,
  # argv, parser, file capture and command-error handling are shipping code.
  $package=Join-Path $temp 'Portable copy'
  $client=Join-Path (Join-Path (Join-Path $package 'App') 'RouterVPN') 'client'
  $data=Join-Path $package 'Data'
  New-Item -ItemType Directory -Path $client -Force | Out-Null
  New-Item -ItemType Directory -Path $data | Out-Null
  $sourceFile=Join-Path $temp 'protection-fixture.go'
  [IO.File]::WriteAllText($sourceFile,@'
package main
import("encoding/json";"fmt";"os";"strconv")
func main(){
  if len(os.Args)!=3 || os.Args[1]!="--windows-physical-protection"{os.Exit(71)}
  switch os.Args[2]{case "probe","status","release","force-off":default:os.Exit(72)}
  f,e:=os.OpenFile(os.Getenv("PROTECTION_FIXTURE_LOG"),os.O_CREATE|os.O_APPEND|os.O_WRONLY,0600);if e!=nil{os.Exit(73)}
  e=json.NewEncoder(f).Encode(os.Args[1:]);if e!=nil{os.Exit(74)};if e=f.Close();e!=nil{os.Exit(75)}
  if text:=os.Getenv("PROTECTION_FIXTURE_EXIT");text!=""{n,_:=strconv.Atoi(text);os.Exit(n)}
  fmt.Println(os.Getenv("PROTECTION_FIXTURE_OUTPUT"))
}
'@,[Text.UTF8Encoding]::new($false))
  $compiler=(Get-Command $Go -CommandType Application -ErrorAction Stop).Source
  $env:GOOS=(& $compiler env GOHOSTOS).Trim();if($LASTEXITCODE -ne 0){throw 'Could not capture the test host Go OS.'}
  $env:GOARCH=(& $compiler env GOHOSTARCH).Trim();if($LASTEXITCODE -ne 0){throw 'Could not capture the test host Go architecture.'}
  $env:CGO_ENABLED='0'
  $controller=Join-Path (Split-Path -Parent $client) 'router-vpn-client.exe'
  & $compiler build -o $controller $sourceFile
  if($LASTEXITCODE -ne 0){throw 'Actual protection utility fixture did not compile.'}
  [IO.File]::WriteAllText((Join-Path $data 'router-vpn-client.exe'),'private data must not select executable')
  $foreign=Join-Path $temp 'ambient-controller.exe'
  [IO.File]::WriteAllText($foreign,'ambient controller must not execute')
  $env:HOMEVPN_ROOT=$data;$env:HOMEVPN_NATIVE_CONTROLLER=$foreign
  $env:PROTECTION_FIXTURE_LOG=Join-Path $temp 'argv.jsonl'
  foreach($operation in @('probe','status','release','force-off')) {
    $env:PROTECTION_FIXTURE_OUTPUT=if($operation -ceq 'probe'){'{"schema":1,"absent":true}'}else{$off}
    $value=Invoke-RouterVPNOwnedWindowsProtection -ClientDirectory $client -Operation $operation
    Check ($value.schema -eq 1) 'Fixed package controller invocation failed.'
  }
  $arguments=@([IO.File]::ReadAllLines($env:PROTECTION_FIXTURE_LOG))
  Check ($arguments.Count -eq 4) 'Actual controller did not receive exactly four utility invocations.'
  for($index=0;$index -lt $arguments.Count;$index++) {
    $expected='["--windows-physical-protection","'+@('probe','status','release','force-off')[$index]+'"]'
    Check ($arguments[$index] -ceq $expected) 'Controller utility argv acquired path/profile/ambient arguments.'
  }
  $env:PROTECTION_FIXTURE_OUTPUT=$off+"`n"+$off
  Reject { Invoke-RouterVPNOwnedWindowsProtection -ClientDirectory $client -Operation status } 'Multiple native status records were accepted.'
  $env:PROTECTION_FIXTURE_OUTPUT='{"schema":1,"absent":true}'
  Reject { Invoke-RouterVPNOwnedWindowsProtection -ClientDirectory $client -Operation status } 'Status accepted a weaker absence probe.'
  $env:PROTECTION_FIXTURE_OUTPUT=$off;$env:PROTECTION_FIXTURE_EXIT='17'
  Reject { Invoke-RouterVPNOwnedWindowsProtection -ClientDirectory $client -Operation status } 'Failed native status was treated as absent.'
  Remove-Item Env:PROTECTION_FIXTURE_EXIT
  Reject { Invoke-RouterVPNOwnedWindowsProtection -ClientDirectory $data -Operation status } 'Private Data was accepted as the executable package.'
  Reject { Invoke-RouterVPNOwnedWindowsProtection -ClientDirectory $client -Operation 'delete' } 'Arbitrary utility operation was accepted.'

  # Real read-only legacy inventory, with only the host cmdlet/path doubled.
  # Every mutating firewall cmdlet is a trap, including accidental fallbacks.
  $script:legacyPath=Join-Path $temp 'legacy-state.json'
  $script:rules=@();$script:queryFails=$false;$script:queryReads=0
  function Get-RouterVPNLegacyProtectionStatePath { return $script:legacyPath }
  function Get-NetFirewallRule {
    param($PolicyStore,$ErrorAction)
    if($PolicyStore -cne 'ActiveStore' -or $ErrorAction -cne 'Stop'){throw 'Legacy inventory did not retain exact read-only store/error semantics.'}
    $script:queryReads++
    if($script:queryFails){throw 'injected firewall inventory failure'}
    return $script:rules
  }
  function New-NetFirewallRule { throw 'Owned handoff mutated a firewall rule.' }
  function Remove-NetFirewallRule { throw 'Owned handoff removed a firewall rule.' }
  function Set-NetFirewallProfile { throw 'Owned handoff changed global firewall defaults.' }
  Check (-not (Get-RouterVPNLegacyWindowsProtection).active) 'Empty legacy inventory fabricated ownership.'
  $script:rules=@([pscustomobject]@{Group='Foreign application';Name='foreign'},[pscustomobject]@{Group='Router VPN Kill Switch';Name='owned'})
  Check ((Get-RouterVPNLegacyWindowsProtection).rule_count -eq 1) 'Legacy inventory lost the exact managed group.'
  Reject { Assert-RouterVPNNoLegacyWindowsProtection } 'Native preparation adopted a live legacy rule.'
  $script:rules=@([pscustomobject]@{Group='Foreign application';Name='foreign'})
  [IO.File]::WriteAllText($script:legacyPath,'malformed legacy JSON must retain ownership')
  Check ((Get-RouterVPNLegacyWindowsProtection).state_present) 'Corrupt legacy state was discarded during takeover.'
  Reject { Assert-RouterVPNNoLegacyWindowsProtection } 'Native preparation adopted corrupt legacy ownership.'
  Remove-Item -LiteralPath $script:legacyPath
  $script:queryFails=$true
  Reject { Get-RouterVPNLegacyWindowsProtection } 'Unknown firewall inventory was treated as empty.'
  $script:queryFails=$false

  # Execute the real decision function against explicit native replies. The
  # actual BFE behavior is independently mandatory in the native kernel gate.
  $script:elevated=$true;$script:operations=@();$script:reply=$off;$script:after=$off;$script:invokeFails=$false
  function Test-RouterVPNProtectionElevated {return $script:elevated}
  function Invoke-RouterVPNOwnedWindowsProtection {
    param($ClientDirectory,$Operation)
    Check ($ClientDirectory -ceq $client) 'Handoff changed the captured package.'
    $script:operations+=,$Operation
    if($script:invokeFails){throw 'injected unknown native status'}
    if($Operation -ceq 'probe'){return ConvertFrom-RouterVPNProtectionProbe $script:probeReply}
    return ConvertFrom-RouterVPNOwnedProtectionStatus $(if($Operation -ceq 'status'){$script:reply}else{$script:after})
  }
  function Reset-Handoff([string]$Before,[string]$After) {$script:operations=@();$script:reply=$Before;$script:after=$After}
  Reset-Handoff $off $off
  Check (-not (Invoke-RouterVPNOwnedProtectionHandoff -Action release -ClientDirectory $client).handled) 'Absent native owner prevented the existing legacy path.'
  Check (($script:operations -join ',') -ceq 'status') 'Absent native owner caused mutation.'
  Reset-Handoff $always $always
  $result=Invoke-RouterVPNOwnedProtectionHandoff -Action release -ClientDirectory $client
  Check ($result.handled -and $result.status.policy -ceq 'always' -and ($script:operations -join ',') -ceq 'status,release') 'Normal release changed Always to an explicit recovery.'
  Reset-Handoff $always $off
  $result=Invoke-RouterVPNOwnedProtectionHandoff -Action force-off -ClientDirectory $client
  Check ($result.handled -and -not $result.status.active -and ($script:operations -join ',') -ceq 'status,force-off') 'Explicit Off failed native ownership routing.'
  Reset-Handoff $always $off
  Check ((Invoke-RouterVPNOwnedProtectionHandoff -Action prepare -Policy off -ClientDirectory $client).handled) 'Selected explicit Off bypassed native cleanup.'
  Check (($script:operations -join ',') -ceq 'status,force-off') 'Selected explicit Off used ordinary release.'
  foreach($action in @('check','prepare','tunnel')) {
    Reset-Handoff $always $off
    Reject { Invoke-RouterVPNOwnedProtectionHandoff -Action $action -Policy always -ClientDirectory $client } 'Legacy action adopted native protection.'
    Check (($script:operations -join ',') -ceq 'status') 'Rejected native-to-legacy migration mutated protection.'
  }
  Reset-Handoff $always $off
  $result=Invoke-RouterVPNOwnedProtectionHandoff -Action status -ClientDirectory $client
  Check ($result.handled -and $result.status.active -and ($script:operations -join ',') -ceq 'status') 'Read-only status mutated native protection.'
  $script:rules=@([pscustomobject]@{Group='Router VPN Kill Switch'})
  foreach($action in @('release','force-off','status')){
    Reset-Handoff $always $off
    Reject { Invoke-RouterVPNOwnedProtectionHandoff -Action $action -ClientDirectory $client } 'Mixed native/legacy ownership was modified.'
    Check (($script:operations -join ',') -ceq 'status') 'Mixed ownership reached a native mutation.'
  }
  $script:rules=@();$script:invokeFails=$true
  Reject { Invoke-RouterVPNOwnedProtectionHandoff -Action release -ClientDirectory $client } 'Unknown native status fell back to legacy cleanup.'
  $script:invokeFails=$false
  $script:elevated=$false;$script:probeReply='{"schema":1,"absent":true}'
  foreach($action in @('check','prepare','release')){
    Reset-Handoff $always $off
    $result=Invoke-RouterVPNOwnedProtectionHandoff -Action $action -Policy off -ClientDirectory $client
    Check (-not $result.handled -and $null -eq $result.status -and ($script:operations -join ',') -ceq 'probe') 'Unprivileged no-op synthesized status or acquired mutation authority.'
  }
  foreach($action in @('status','tunnel','force-off')) {
    Reset-Handoff $off $off
    Reject { Invoke-RouterVPNOwnedProtectionHandoff -Action $action -ClientDirectory $client } 'Unprivileged caller acquired authoritative native status or mutation.'
    Check ($script:operations.Count -eq 0) 'Unprivileged privileged operation reached the controller.'
  }
  $script:probeReply='{"schema":1,"absent":false}'
  Reset-Handoff $off $off
  Reject { Invoke-RouterVPNOwnedProtectionHandoff -Action release -ClientDirectory $client } 'Preparing/protected owner was mistaken for absence.'
  Check (($script:operations -join ',') -ceq 'probe') 'Present owner triggered an unprivileged mutation.'
  $script:probeReply='{"schema":1,"absent":true}';$script:invokeFails=$true
  Reject { Invoke-RouterVPNOwnedProtectionHandoff -Action release -ClientDirectory $client } 'Denied or timed-out probe became absence.'
  $script:invokeFails=$false
  foreach($name in @('HOMEVPN_TOR_SESSION','HOMEVPN_EXTERNAL_SESSION','HOMEVPN_MULTIHOP_SESSION','HOMEVPN_NODE_SESSION')){
    [Environment]::SetEnvironmentVariable($name,('a'*32),'Process');Reset-Handoff $off $off
    Reject { Invoke-RouterVPNOwnedProtectionHandoff -Action release -ClientDirectory $client } 'Captured session used the unprivileged no-op escape.'
    Check ($script:operations.Count -eq 0) 'Captured session performed an unprivileged probe.'
    Remove-Item -LiteralPath ('Env:'+$name)
  }
  Write-Host "PASS $script:checks owned Windows protection assertions: actual package utility dispatch, strict status/probe separation, legacy ownership, Always release, explicit Off and unprivileged no-op boundaries."
} finally {
  foreach($name in $names){[Environment]::SetEnvironmentVariable($name,$saved[$name],'Process')}
  Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
