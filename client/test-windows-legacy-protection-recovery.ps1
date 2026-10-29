param([string]$SourceRoot=(Split-Path -Parent $PSScriptRoot),[string]$Source='',[string]$OnlyCase='')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$task=Join-Path ([IO.Path]::GetTempPath()) ('routervpn-legacy-recovery-'+[Guid]::NewGuid().ToString('N'))
$client=Join-Path $task 'Package with spaces/client'
$data=Join-Path $task 'Data'
$names=@('HOMEVPN_ROOT','HOMEVPN_PROFILE_ID','HOMEVPN_POLICY_PROFILE_ID','HOMEVPN_ENDPOINT',
  'HOMEVPN_EXTERNAL_SESSION','HOMEVPN_NATIVE_ENDPOINTS_JSON','HOMEVPN_NATIVE_EGRESS_JSON',
  'HOMEVPN_TOR_SESSION','HOMEVPN_MULTIHOP_SESSION','HOMEVPN_NODE_SESSION',
  'LEGACY_RECOVERY_ROOT','LEGACY_RECOVERY_FAULT')
$saved=@{}
foreach($name in $names){$saved[$name]=[Environment]::GetEnvironmentVariable($name,'Process');Remove-Item -LiteralPath ('Env:'+$name) -ErrorAction SilentlyContinue}
$script:checks=0;$script:children=0
function Check([bool]$Value,[string]$Message){$script:checks++;if(-not $Value){throw $Message}}
New-Item -ItemType Directory -Path $client -Force | Out-Null
New-Item -ItemType Directory -Path $data | Out-Null
try {
  foreach($name in @('windows-kill-switch.ps1','Private-RouterVPN-State.ps1','Private-RouterVPN-Protection.ps1')){
    $path=if($name -ceq 'windows-kill-switch.ps1' -and $Source){[IO.Path]::GetFullPath($Source)}else{Join-Path $SourceRoot ('client/'+$name)}
    Copy-Item -LiteralPath $path -Destination (Join-Path $client $name)
  }
  # The whole shipping legacy dispatcher, JSON reader, validation, restoration
  # and cleanup execute in real child shells. Native WFP dispatch has its own
  # full-process fixture. Only that earlier boundary and actual OS primitives
  # are doubled here; no production recovery function is replaced.
  $overrides=@'
function Test-Administrator {return $true}
function Invoke-RouterVPNOwnedProtectionHandoff {return [pscustomobject]@{handled=$false;status=$null}}
function Read-FixtureFirewall {
  return ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $env:LEGACY_RECOVERY_ROOT 'firewall.json')))
}
function Write-FixtureFirewall($Value) {
  [IO.File]::WriteAllText((Join-Path $env:LEGACY_RECOVERY_ROOT 'firewall.json'),($Value|ConvertTo-Json -Depth 20))
}
function Record-FixtureMutation([string]$Value) {
  [IO.File]::AppendAllText((Join-Path $env:LEGACY_RECOVERY_ROOT 'mutations.log'),($Value+[Environment]::NewLine))
}
function Get-NetFirewallProfile {
  [CmdletBinding()]param($PolicyStore)
  if($env:LEGACY_RECOVERY_FAULT -ceq 'profile-query'){throw 'injected profile query failure'}
  $value=Read-FixtureFirewall
  if($env:LEGACY_RECOVERY_FAULT -ceq 'profile-readback'){
    @($value.profiles | Where-Object {$_.Name -ceq 'Private'})[0].DefaultOutboundAction='Block'
  }
  return $value.profiles
}
function Set-NetFirewallProfile {
  [CmdletBinding()]param($Name,$DefaultOutboundAction)
  if($env:LEGACY_RECOVERY_FAULT -ceq 'profile-write' -and $Name -ceq 'Private'){throw 'injected profile write failure'}
  $value=Read-FixtureFirewall
  $target=@($value.profiles | Where-Object {$_.Name -ceq $Name})
  if($target.Count -ne 1){throw 'profile mutation selected another owner'}
  Record-FixtureMutation ('profile '+$Name+' '+$DefaultOutboundAction)
  $target[0].DefaultOutboundAction=$DefaultOutboundAction
  Write-FixtureFirewall $value
}
function Get-NetFirewallRule {
  [CmdletBinding()]param($PolicyStore,$Group)
  if($env:LEGACY_RECOVERY_FAULT -ceq 'rule-query'){throw 'injected rule query failure'}
  $value=Read-FixtureFirewall
  $rules=@($value.rules)
  if($env:LEGACY_RECOVERY_FAULT -ceq 'rule-readback' -and -not @($rules|Where-Object {$_.Group -ceq 'Router VPN Kill Switch'}).Count){
    $rules+=@([pscustomobject]@{Name='owned-not-removed';Group='Router VPN Kill Switch'})
  }
  if($Group){return @($rules|Where-Object {$_.Group -ceq $Group})}
  return $rules
}
function Remove-NetFirewallRule {
  [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject)
  process {
    if($env:LEGACY_RECOVERY_FAULT -ceq 'rule-remove'){throw 'injected rule removal failure'}
    if($InputObject.Group -cne 'Router VPN Kill Switch'){throw 'foreign rule reached removal'}
    $value=Read-FixtureFirewall
    Record-FixtureMutation ('rule '+$InputObject.Name)
    $value.rules=@($value.rules|Where-Object {$_.Name -cne $InputObject.Name})
    Write-FixtureFirewall $value
  }
}
function New-NetFirewallRule {throw 'Recovery tried to install a new allow rule'}
'@
  [IO.File]::AppendAllText((Join-Path $client 'Private-RouterVPN-Protection.ps1'),([Environment]::NewLine+$overrides),[Text.UTF8Encoding]::new($false))
  $shell=(Get-Process -Id $PID).Path
  $record=[pscustomobject]@{
    schema_version=1;policy='on-connect';phase='active';endpoint='203.0.113.7';endpoint_ips=@('203.0.113.7');
    home_lan_access=$false;tunnel_alias='owned-test';updated_at='2026-10-29T00:00:00Z';
    original_profiles=@(
      [pscustomobject]@{name='Domain';default_outbound='Block'},
      [pscustomobject]@{name='Private';default_outbound='Allow'},
      [pscustomobject]@{name='Public';default_outbound='Block'}
    )
  }
  $valid=$record|ConvertTo-Json -Depth 20 -Compress
  function Changed-Record([scriptblock]$Change){
    $value=ConvertFrom-Json -InputObject $valid
    & $Change $value
    return $value|ConvertTo-Json -Depth 20 -Compress
  }
  $cases=@(
    @{name='force-off-valid';state=$valid;action='force-off'},
    @{name='release-valid';state=$valid;action='release'},
    @{name='prepare-off-valid';state=$valid;action='prepare';policy='off'},
    @{name='preparing-recovery';state=(Changed-Record {param($v)$v.phase='preparing'});action='force-off'},
    @{name='always-release';state=(Changed-Record {param($v)$v.policy='always'});action='release';retain=$true},
    @{name='corrupt-json';state='{broken';invalid=$true},
    @{name='json-null';state='null';invalid=$true},
    @{name='json-array';state=('['+$valid+']');invalid=$true},
    @{name='json-string';state='"unowned"';invalid=$true},
    @{name='empty-object';state='{}';invalid=$true},
    @{name='missing-profile';state=(Changed-Record {param($v)$v.original_profiles=@($v.original_profiles[0],$v.original_profiles[1])});invalid=$true},
    @{name='duplicate-profile';state=(Changed-Record {param($v)$v.original_profiles[2].name='Private'});invalid=$true},
    @{name='foreign-profile';state=(Changed-Record {param($v)$v.original_profiles[2].name='Foreign'});invalid=$true},
    @{name='coerced-default';state=(Changed-Record {param($v)$v.original_profiles[1].default_outbound=$true});invalid=$true},
    @{name='invalid-default';state=(Changed-Record {param($v)$v.original_profiles[1].default_outbound='Unknown'});invalid=$true},
    @{name='string-schema';state=(Changed-Record {param($v)$v.schema_version='1'});invalid=$true},
    @{name='invalid-policy';state=(Changed-Record {param($v)$v.policy='off'});invalid=$true},
    @{name='invalid-phase';state=(Changed-Record {param($v)$v.phase='replaced'});invalid=$true},
    @{name='missing-state-owned-rules';invalid=$true},
    @{name='missing-state-no-rules';empty=$true},
    @{name='rule-query';state=$valid;fault='rule-query'},
    @{name='rule-remove';state=$valid;fault='rule-remove'},
    @{name='rule-readback';state=$valid;fault='rule-readback'},
    @{name='profile-write';state=$valid;fault='profile-write'},
    @{name='profile-query';state=$valid;fault='profile-query'},
    @{name='profile-readback';state=$valid;fault='profile-readback'}
  )
  if($OnlyCase){
    $cases=@($cases|Where-Object {$_.name -ceq $OnlyCase})
    if($cases.Count -ne 1){throw 'The requested legacy recovery case does not exist.'}
  }
  foreach($case in $cases){
    $caseRoot=Join-Path $data $case.name
    New-Item -ItemType Directory -Path $caseRoot | Out-Null
    $env:HOMEVPN_ROOT=$caseRoot;$env:LEGACY_RECOVERY_ROOT=$caseRoot
    $statePath=Join-Path $caseRoot 'windows-state.json'
    if($case.ContainsKey('state')){[IO.File]::WriteAllText($statePath,$case.state,[Text.UTF8Encoding]::new($false))}
    $rules=@([pscustomobject]@{Name='foreign-rule';Group='Foreign policy'})
    if(-not $case['empty']){$rules+=@([pscustomobject]@{Name='owned-rule';Group='Router VPN Kill Switch'})}
    $firewall=[pscustomobject]@{
      profiles=@(
        [pscustomobject]@{Name='Domain';DefaultOutboundAction='Block'},
        [pscustomobject]@{Name='Private';DefaultOutboundAction='Block'},
        [pscustomobject]@{Name='Public';DefaultOutboundAction='Block'},
        [pscustomobject]@{Name='Foreign';DefaultOutboundAction='Block'}
      );rules=$rules
    }
    $firewallPath=Join-Path $caseRoot 'firewall.json'
    $before=$firewall|ConvertTo-Json -Depth 20
    [IO.File]::WriteAllText($firewallPath,$before,[Text.UTF8Encoding]::new($false))
    $attempts=if($case['fault']){2}else{1}
    for($attempt=0;$attempt -lt $attempts;$attempt++){
      $env:LEGACY_RECOVERY_FAULT=if($attempt -eq 0){[string]$case['fault']}else{''}
      $action=if($case['action']){$case.action}else{'force-off'}
      $arguments=@('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"'+(Join-Path $client 'windows-kill-switch.ps1')+'"'),
        '-Action',$action,'-Root',('"'+$caseRoot+'"'),'-StateRoot',('"'+$caseRoot+'"'),'-Endpoint','203.0.113.7','-HomeLANAccess','false')
      if($case['policy']){$arguments+=@('-Policy',$case.policy)}
      $out=Join-Path $caseRoot ('stdout-'+$attempt+'.log');$err=Join-Path $caseRoot ('stderr-'+$attempt+'.log')
      # Retain the process created by Start itself. Redirected Start-Process
      # -PassThru can lose ExitCode under Windows PowerShell 5.1; a missing
      # result is neither a successful recovery nor an expected rejection.
      $child=[Diagnostics.Process]::new()
      $child.StartInfo=[Diagnostics.ProcessStartInfo]::new()
      $child.StartInfo.FileName=$shell
      $child.StartInfo.Arguments=$arguments -join ' '
      $child.StartInfo.UseShellExecute=$false
      $child.StartInfo.CreateNoWindow=$true
      $child.StartInfo.RedirectStandardOutput=$true
      $child.StartInfo.RedirectStandardError=$true
      $started=$false
      try {
        $started=$child.Start()
        if(-not $started){throw ('Legacy recovery child did not start: '+$case.name)}
        $script:children++
        $stdout=$child.StandardOutput.ReadToEndAsync()
        $stderr=$child.StandardError.ReadToEndAsync()
        if(-not $child.WaitForExit(30000)){$child.Kill();$child.WaitForExit();throw ('Legacy recovery child exceeded its bound: '+$case.name)}
        $child.WaitForExit()
        $outText=$stdout.GetAwaiter().GetResult();$errText=$stderr.GetAwaiter().GetResult()
        [IO.File]::WriteAllText($out,$outText);[IO.File]::WriteAllText($err,$errText)
        $diagnostic=$outText+$errText
        $exitCode=$child.ExitCode
        Check ($null -ne $exitCode) ('Legacy recovery child omitted its exit code: '+$case.name)
        $failure=[bool]$case['invalid'] -or ($attempt -eq 0 -and [bool]$case['fault'])
        Check (($exitCode -ne 0) -eq $failure) ('Unexpected recovery verdict for '+$case.name+' (exit '+$exitCode+'): '+$diagnostic)
        $after=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($firewallPath))
        Check (@($after.rules|Where-Object {$_.Name -ceq 'foreign-rule' -and $_.Group -ceq 'Foreign policy'}).Count -eq 1) ('Foreign rule changed: '+$case.name)
        Check (@($after.profiles|Where-Object {$_.Name -ceq 'Foreign' -and $_.DefaultOutboundAction -ceq 'Block'}).Count -eq 1) ('Foreign profile changed: '+$case.name)
        if($failure -or $case['retain']){
          Check ((Test-Path -LiteralPath $statePath) -eq $case.ContainsKey('state')) ('Recovery discarded its rollback record: '+$case.name)
          if($case.ContainsKey('state')){Check ([IO.File]::ReadAllText($statePath) -ceq $case.state) ('Recovery rewrote its original authority: '+$case.name)}
          if($case['invalid'] -or $case['retain']){
            Check ([IO.File]::ReadAllText($firewallPath) -ceq $before) ('Invalid or retained recovery changed firewall policy: '+$case.name)
            Check (-not(Test-Path -LiteralPath (Join-Path $caseRoot 'mutations.log'))) ('Invalid recovery authorized mutation: '+$case.name)
          }
          if($failure){Check (-not $diagnostic.Contains('Windows kill switch force-disabled.')) ('Failed recovery claimed Off: '+$case.name)}
        } else {
          Check (-not(Test-Path -LiteralPath $statePath)) ('Proved recovery did not retire its record: '+$case.name)
          Check (@($after.rules|Where-Object {$_.Group -ceq 'Router VPN Kill Switch'}).Count -eq 0) ('Proved recovery retained an owned rule: '+$case.name)
          foreach($expected in $record.original_profiles){
            $want=if($case['empty']){'Block'}else{$expected.default_outbound}
            Check (@($after.profiles|Where-Object {$_.Name -ceq $expected.name -and $_.DefaultOutboundAction -ceq $want}).Count -eq 1) ('Captured profile was not restored: '+$case.name)
          }
        }
      } finally {
        if($started -and -not $child.HasExited){$child.Kill();$child.WaitForExit()}
        $child.Dispose()
      }
    }
  }
  Write-Output ("PASS {0} legacy recovery cases, {1} actual child dispatches and {2} assertions; invalid authority, checked readback, retained failure/retry and foreign policy preservation." -f $cases.Count,$script:children,$script:checks)
} finally {
  foreach($name in $names){[Environment]::SetEnvironmentVariable($name,$saved[$name],'Process')}
  Remove-Item -LiteralPath $task -Recurse -Force -ErrorAction SilentlyContinue
}
