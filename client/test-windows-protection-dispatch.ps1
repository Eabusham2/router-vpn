param([string]$Go='go',[string]$SourceRoot=(Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$task=Join-Path ([IO.Path]::GetTempPath()) ('routervpn-protection-dispatch-'+[Guid]::NewGuid().ToString('N'))
$client=Join-Path $task 'Package with spaces/client'
$data=Join-Path $task 'Data'
$names=@('HOMEVPN_ROOT','HOMEVPN_PROFILE_ID','HOMEVPN_POLICY_PROFILE_ID','HOMEVPN_ENDPOINT','HOMEVPN_EXTERNAL_SESSION',
  'HOMEVPN_NATIVE_ENDPOINTS_JSON','HOMEVPN_NATIVE_EGRESS_JSON','HOMEVPN_TOR_SESSION','HOMEVPN_MULTIHOP_SESSION','HOMEVPN_NODE_SESSION',
  'PROTECTION_DISPATCH_ROOT','PROTECTION_DISPATCH_BEFORE','PROTECTION_DISPATCH_AFTER','PROTECTION_DISPATCH_PROBE',
  'PROTECTION_DISPATCH_EXIT','PROTECTION_DISPATCH_ELEVATED','PROTECTION_DISPATCH_LEGACY_RULE','GOOS','GOARCH','CGO_ENABLED')
$saved=@{}
foreach($name in $names){$saved[$name]=[Environment]::GetEnvironmentVariable($name,'Process');Remove-Item -LiteralPath ('Env:'+$name) -ErrorAction SilentlyContinue}
$script:checks=0
function Check([bool]$Value,[string]$Message){$script:checks++;if(-not $Value){throw $Message}}
New-Item -ItemType Directory -Path $client -Force | Out-Null
New-Item -ItemType Directory -Path $data | Out-Null
try {
  foreach($name in @('windows-kill-switch.ps1','Private-RouterVPN-State.ps1','Private-RouterVPN-Protection.ps1')){
    Copy-Item -LiteralPath (Join-Path $SourceRoot ('client/'+$name)) -Destination (Join-Path $client $name)
  }
  # The real legacy dispatcher and native adapter both execute. Only local OS
  # privilege/firewall inspection calls and the external utility are doubles.
  # A trap records any attempted profile mutation before throwing, so recovery
  # cannot hide an accidental fallback by catching its failure.
  $overrides=@'
function Test-RouterVPNProtectionElevated {return $env:PROTECTION_DISPATCH_ELEVATED -ceq 'true'}
function Get-RouterVPNLegacyProtectionStatePath {return Join-Path $env:PROTECTION_DISPATCH_ROOT 'windows-state.json'}
function Get-NetFirewallRule {
  param($PolicyStore,$Group,$ErrorAction)
  if($env:PROTECTION_DISPATCH_LEGACY_RULE -ceq 'true'){return [pscustomobject]@{Group='Router VPN Kill Switch'}}
  return [pscustomobject]@{Group='Foreign firewall owner'}
}
function Get-NetFirewallProfile {throw 'Legacy global profile query was reached.'}
function Set-NetFirewallProfile {[IO.File]::AppendAllText((Join-Path $env:PROTECTION_DISPATCH_ROOT 'mutation.log'),'profile');throw 'Legacy profile mutation trap.'}
function New-NetFirewallRule {[IO.File]::AppendAllText((Join-Path $env:PROTECTION_DISPATCH_ROOT 'mutation.log'),'add');throw 'Legacy add mutation trap.'}
function Remove-NetFirewallRule {[IO.File]::AppendAllText((Join-Path $env:PROTECTION_DISPATCH_ROOT 'mutation.log'),'delete');throw 'Legacy delete mutation trap.'}
'@
  [IO.File]::AppendAllText((Join-Path $client 'Private-RouterVPN-Protection.ps1'),("`n"+$overrides),[Text.UTF8Encoding]::new($false))
  $fixture=Join-Path $task 'controller.go'
  [IO.File]::WriteAllText($fixture,@'
package main
import("fmt";"os";"path/filepath";"strconv")
func main(){
 if len(os.Args)!=3||os.Args[1]!="--windows-physical-protection"{os.Exit(81)}
 op:=os.Args[2];switch op{case "probe","status","release","force-off":default:os.Exit(82)}
 f,e:=os.OpenFile(filepath.Join(os.Getenv("PROTECTION_DISPATCH_ROOT"),"native.log"),os.O_CREATE|os.O_APPEND|os.O_WRONLY,0600);if e!=nil{os.Exit(83)}
 if _,e=fmt.Fprintln(f,op);e!=nil{os.Exit(84)};if e=f.Close();e!=nil{os.Exit(85)}
 if text:=os.Getenv("PROTECTION_DISPATCH_EXIT");text!=""{n,_:=strconv.Atoi(text);os.Exit(n)}
 key:="PROTECTION_DISPATCH_BEFORE";if op=="probe"{key="PROTECTION_DISPATCH_PROBE"}else if op!="status"{key="PROTECTION_DISPATCH_AFTER"}
 fmt.Println(os.Getenv(key))
}
'@,[Text.UTF8Encoding]::new($false))
  # Native Windows may return every matching PATH installation. Preserve
  # command resolution order and invoke one executable, never an array joined
  # into a path (the hosted runner also retains its older Go installation).
  $compiler=[string]@(Get-Command $Go -CommandType Application -ErrorAction Stop)[0].Source
  $env:GOOS=(& $compiler env GOHOSTOS).Trim();if($LASTEXITCODE -ne 0){throw 'Could not select fixture host OS.'}
  $env:GOARCH=(& $compiler env GOHOSTARCH).Trim();if($LASTEXITCODE -ne 0){throw 'Could not select fixture host architecture.'}
  $env:CGO_ENABLED='0'
  & $compiler build -o (Join-Path (Split-Path -Parent $client) 'router-vpn-client.exe') $fixture
  if($LASTEXITCODE -ne 0){throw 'Actual protection dispatch utility fixture did not compile.'}
  $shell=(Get-Process -Id $PID).Path
  $always='{"schema":1,"active":true,"policy":"always","phase":"retained"}'
  $onConnect='{"schema":1,"active":true,"policy":"on-connect","phase":"retained"}'
  $off='{"schema":1,"active":false,"policy":"off","phase":"off"}'
  $cases=@(
    @{name='status-always';action='status';before=$always;operations='status'},
    @{name='release-always';action='release';before=$always;after=$always;operations='status,release'},
    @{name='release-on-connect';action='release';before=$onConnect;after=$off;operations='status,release'},
    @{name='force-off';action='force-off';before=$always;after=$off;operations='status,force-off'},
    @{name='explicit-off';action='prepare';policy='off';before=$always;after=$off;operations='status,force-off'},
    @{name='off-check-read-only';action='check';policy='off';before=$always;operations='status'},
    @{name='legacy-prepare-refusal';action='prepare';policy='always';before=$always;fail=$true;operations='status'},
    @{name='legacy-check-refusal';action='check';policy='always';before=$always;fail=$true;operations='status'},
    @{name='legacy-alias-refusal';action='tunnel';before=$always;fail=$true;operations='status'},
    @{name='unknown-status';action='force-off';before=$always;fail=$true;exit='17';operations='status'},
    @{name='malformed-status';action='force-off';before='invalid';fail=$true;operations='status'},
    @{name='mixed-rules';action='release';before=$always;legacyRule=$true;fail=$true;operations='status'},
    @{name='mixed-corrupt-state';action='force-off';before=$always;legacyState=$true;fail=$true;operations='status'},
    @{name='unknown-and-corrupt';action='force-off';before='invalid';legacyState=$true;fail=$true;operations='status'},
    @{name='legacy-noop-release';action='release';before=$off;operations='status'},
    @{name='legacy-corrupt-status';action='status';before=$off;legacyState=$true;fail=$true;operations='status';message='Invalid Windows kill-switch rollback state JSON'},
    @{name='ordinary-off-check';action='check';policy='off';ordinary=$true;operations='probe'},
    @{name='ordinary-off-prepare';action='prepare';policy='off';ordinary=$true;operations='probe'},
    @{name='ordinary-noop-release';action='release';ordinary=$true;operations='probe'},
    @{name='ordinary-present';action='release';ordinary=$true;probe='{"schema":1,"absent":false}';fail=$true;operations='probe'},
    @{name='ordinary-denied';action='release';ordinary=$true;exit='17';fail=$true;operations='probe'},
    @{name='ordinary-captured-session';action='release';ordinary=$true;session=$true;fail=$true;operations=''}
  )
  foreach($case in $cases){
    $caseRoot=Join-Path $data $case.name
    New-Item -ItemType Directory -Path $caseRoot | Out-Null
    $env:HOMEVPN_ROOT=$caseRoot;$env:PROTECTION_DISPATCH_ROOT=$caseRoot
    $env:PROTECTION_DISPATCH_BEFORE=$case['before']
    $env:PROTECTION_DISPATCH_AFTER=$case['after']
    $env:PROTECTION_DISPATCH_PROBE=if($case['probe']){$case['probe']}else{'{"schema":1,"absent":true}'}
    $env:PROTECTION_DISPATCH_ELEVATED=if($case['ordinary']){'false'}else{'true'}
    $env:PROTECTION_DISPATCH_LEGACY_RULE=if($case['legacyRule']){'true'}else{'false'}
    $env:PROTECTION_DISPATCH_EXIT=$case['exit']
    $env:HOMEVPN_TOR_SESSION=if($case['session']){'a'*32}else{''}
    if($case['legacyState']){[IO.File]::WriteAllText((Join-Path $caseRoot 'windows-state.json'),'{broken legacy rollback')}
    $output=Join-Path $caseRoot 'stdout.log';$diagnostics=Join-Path $caseRoot 'stderr.log'
    $arguments=@('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"'+(Join-Path $client 'windows-kill-switch.ps1')+'"'),
      '-Action',$case.action,'-Root',('"'+$caseRoot+'"'),'-StateRoot',('"'+$caseRoot+'"'),'-Endpoint','203.0.113.4','-HomeLANAccess','false','-TunnelAlias','owned-test')
    if($case['policy']){$arguments+=@('-Policy',$case['policy'])}
    # Retain the handle returned by Process.Start itself. Windows PowerShell's
    # redirected Start-Process -PassThru can lose ExitCode after WaitForExit;
    # a missing code must never be interpreted as success or expected denial.
    $child=[Diagnostics.Process]::new()
    $child.StartInfo=[Diagnostics.ProcessStartInfo]::new()
    $child.StartInfo.FileName=$shell
    $child.StartInfo.Arguments=$arguments -join ' '
    $child.StartInfo.UseShellExecute=$false
    $child.StartInfo.CreateNoWindow=$true
    $child.StartInfo.RedirectStandardOutput=$true
    $child.StartInfo.RedirectStandardError=$true
    $started=$false
    try{
      $started=$child.Start()
      if(-not $started){throw ('Real protection dispatcher did not start: '+$case.name)}
      $stdout=$child.StandardOutput.ReadToEndAsync()
      $stderr=$child.StandardError.ReadToEndAsync()
      if(-not $child.WaitForExit(45000)){$child.Kill();$child.WaitForExit();throw ('Real protection dispatcher exceeded its bound: '+$case.name)}
      $child.WaitForExit()
      $outText=$stdout.GetAwaiter().GetResult();$errText=$stderr.GetAwaiter().GetResult()
      [IO.File]::WriteAllText($output,$outText);[IO.File]::WriteAllText($diagnostics,$errText)
      $text=$outText+$errText
      $exitCode=$child.ExitCode
      Check ($null -ne $exitCode) ('Real protection dispatcher omitted its exit code: '+$case.name)
      Check (($exitCode -ne 0) -eq [bool]$case['fail']) ('Unexpected complete protection dispatch result for '+$case.name+' (exit '+$exitCode+'): '+$text)
      $log=Join-Path $caseRoot 'native.log'
      $operations=if(Test-Path -LiteralPath $log){[IO.File]::ReadAllLines($log)-join ','}else{''}
      Check ($operations -ceq $case.operations) ('Protection dispatcher changed owner or operation for '+$case.name+': '+$operations)
      Check (-not (Test-Path -LiteralPath (Join-Path $caseRoot 'mutation.log'))) ('Native protection reached a global firewall mutation for '+$case.name)
      if($case['message']){Check ($text.Contains($case['message'])) ('Legacy rejection boundary changed: '+$text)}
      if($case['legacyState']){Check ([IO.File]::ReadAllText((Join-Path $caseRoot 'windows-state.json')) -ceq '{broken legacy rollback') 'Native dispatch discarded legacy recovery authority.'}
    }finally{
      if($started -and -not $child.HasExited){$child.Kill();$child.WaitForExit()}
      $child.Dispose()
    }
  }
  Write-Output ("PASS {0} full Windows protection dispatcher cases and {1} assertions; real child utility, Portable package paths, Always preservation, explicit Off, denial/mixed-owner retention and no global profile mutation." -f $cases.Count,$script:checks)
}finally{
  foreach($name in $names){[Environment]::SetEnvironmentVariable($name,$saved[$name],'Process')}
  Remove-Item -LiteralPath $task -Recurse -Force -ErrorAction SilentlyContinue
}
