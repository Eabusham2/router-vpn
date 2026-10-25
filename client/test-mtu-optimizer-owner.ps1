param([string]$Helper='')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$Root=Split-Path $PSScriptRoot -Parent
$TaskRoot=Join-Path ([IO.Path]::GetTempPath()) ('router-vpn-mtu-owner-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($TaskRoot)
$GraphNames=@('HOMEVPN_MTU_GRAPH_TOKEN','HOMEVPN_MTU_GRAPH_SCOPE','HOMEVPN_MTU_CONTROL_PROFILE_ID','HOMEVPN_MTU_PHYSICAL_ENTRY_ID','HOMEVPN_MTU_PHYSICAL_ENTRY_ENDPOINT')
$Names=@('HOMEVPN_MTU_OWNER_HELPER','HOMEVPN_MTU_OWNER_TOKEN','HOMEVPN_MTU_OWNER_URL','HOMEVPN_MTU_MINIMUM','MTU_OWNER_FIXTURE','HOMEVPN_MTU_APPLY_INTERFACE','HOMEVPN_MTU_APPLY_FAMILY','HOMEVPN_MTU_APPLY_VALUE','HOMEVPN_MTU_EXPECTED_PATH_KEY','HOMEVPN_ROOT','HOMEVPN_MODE','HOMEVPN_IP_FAMILY','HOMEVPN_PROFILE_ID','HOMEVPN_POLICY_PROFILE_ID','HOMEVPN_ENDPOINT','HOMEVPN_NETWORK_CONTEXT','HOMEVPN_NATIVE_ENDPOINTS_JSON','HOMEVPN_NATIVE_EGRESS_JSON','HOMEVPN_EXTERNAL_SESSION','HOMEVPN_NODE_SESSION','MTU_GUARD_FIXTURE','MTU_GUARD_FAIL')+$GraphNames
$Saved=@{};foreach($Name in $Names){$Saved[$Name]=[Environment]::GetEnvironmentVariable($Name,'Process')}
$Checks=0
function Assert-Owner([bool]$Condition,[string]$Message){if(-not$Condition){throw $Message};$script:Checks++}
function Assert-Rejected([scriptblock]$Call,[string]$Message){$failed=$false;try{& $Call|Out-Null}catch{$failed=$true};Assert-Owner $failed $Message}
try{
  foreach($Name in $GraphNames){Remove-Item -LiteralPath ('Env:'+$Name) -ErrorAction SilentlyContinue}
  if(-not$Helper){
    $Helper=Join-Path $TaskRoot 'owner.exe'
    & go build -o $Helper (Join-Path $Root 'deploy/testfixtures/mtu-owner/main.go')
    if($LASTEXITCODE-ne0){throw 'Could not build the actual helper subprocess fixture.'}
  }
  $Helper=(Get-Item -LiteralPath $Helper).FullName
  $Body=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Optimize-RouterVPN-MTU.ps1') -Raw
  $Ast=[ScriptBlock]::Create($Body).Ast
  # Execute the actual shipping definitions, including ProcessStartInfo and
  # raw JSON validation. Only admin/node proof/profile boundaries are doubled.
  . (Join-Path $PSScriptRoot 'Private-RouterVPN-State.ps1')
  $Definitions=@($Ast.FindAll({param($Node)$Node-is[System.Management.Automation.Language.FunctionDefinitionAst]},$true)|ForEach-Object{$_.Extent.Text})
  $Consumer=Join-Path $TaskRoot 'shipping-consumer-functions.ps1'
  [IO.File]::WriteAllText($Consumer,([string]::Join("`n",$Definitions)),[Text.UTF8Encoding]::new($false))
  . $Consumer
  $Token='a'*32;$Alias='owned-tun'
  $env:HOMEVPN_MTU_MINIMUM='576';$env:HOMEVPN_MTU_OWNER_HELPER=$Helper;$env:HOMEVPN_MTU_OWNER_TOKEN=$Token;$env:HOMEVPN_MTU_OWNER_URL='http://127.0.0.1:34567/mtu'
  $env:MTU_OWNER_FIXTURE=Join-Path $TaskRoot 'state.json'
  function Reset-Fixture([string]$Mode=''){
    $state=[ordered]@{owner_token=$Token;interface=$Alias;family=4;index=41;mtu=1400;identity='captured-reader:41';mode=$Mode}
    [IO.File]::WriteAllText($env:MTU_OWNER_FIXTURE,($state|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
    if(Test-Path -LiteralPath ($env:MTU_OWNER_FIXTURE+'.calls')){Remove-Item -LiteralPath ($env:MTU_OWNER_FIXTURE+'.calls')}
  }
  function Read-Fixture {return [IO.File]::ReadAllText($env:MTU_OWNER_FIXTURE)|ConvertFrom-Json}
  function Read-Calls {
    if(Test-Path -LiteralPath ($env:MTU_OWNER_FIXTURE+'.calls')){foreach($line in [IO.File]::ReadAllLines($env:MTU_OWNER_FIXTURE+'.calls')){Write-Output -NoEnumerate ($line|ConvertFrom-Json)}}
  }
  Reset-Fixture
  Assert-Owner ((Read-Mtu $Alias 'IPv4')-eq1400) 'Captured helper read failed.'
  Reset-Fixture 'change-reader'
  Set-Mtu $Alias 'IPv4' 1320
  $state=Invoke-MtuOwner $Alias 'IPv4'
  Assert-Owner ($state.mtu-eq1320-and$state.index-eq42-and$state.identity-ceq'native-owned-reader:42') 'Owned native reader replacement was lost.'
  Set-Mtu $Alias 'IPv4' 1400
  Assert-Owner ((Read-Mtu $Alias 'IPv4')-eq1400) 'Captured helper rollback failed.'
  $writes=@(Read-Calls|Where-Object{$_[0]-ceq'--mtu-owner-set'})
  Assert-Owner ($writes.Count-eq2-and$writes[0][1]-ceq'1320'-and$writes[1][1]-ceq'1400') 'The shipping helper changed the exact utility arguments.'
  Reset-Fixture
  Assert-Rejected {Set-Mtu 'replacement' 'IPv4' 1320} 'A foreign alias reached mutation.'
  Assert-Rejected {Set-Mtu $Alias 'IPv6' 1320} 'A foreign family reached mutation.'
  Assert-Rejected {Set-Mtu $Alias 'IPv4' 575} 'Invalid low MTU reached mutation.'
  Assert-Rejected {Set-Mtu $Alias 'IPv4' 9001} 'Invalid high MTU reached mutation.'
  Assert-Owner (@(Read-Calls|Where-Object{$_[0]-ceq'--mtu-owner-set'}).Count-eq0) 'A rejected request changed the captured owner.'
  foreach($Mode in @('wrong-token','wrong-interface','wrong-family','wrong-index','string-number','float-number','boolean-number','empty-identity','control-identity','long-identity','unknown','null','duplicate','escaped-duplicate','array','trailing','oversized','invalid-utf8','stderr','exit-failure','retired')){
    Reset-Fixture $Mode
    Assert-Rejected {Read-Mtu $Alias 'IPv4'} ('Untrusted helper reply was accepted: '+$Mode)
  }
  foreach($Mode in @('set-fails','set-wrong-readback','retire-after-set')){
    Reset-Fixture $Mode
    Assert-Rejected {Set-Mtu $Alias 'IPv4' 1320} ('Failed set/readback was accepted: '+$Mode)
  }
  Reset-Fixture
  $Invalid=@(
    @('HOMEVPN_MTU_OWNER_TOKEN',('b'*31)),@('HOMEVPN_MTU_OWNER_TOKEN',('A'*32)),
    @('HOMEVPN_MTU_OWNER_URL','http://localhost:1234/mtu'),@('HOMEVPN_MTU_OWNER_URL','https://127.0.0.1:1234/mtu'),
    @('HOMEVPN_MTU_OWNER_URL','http://127.0.0.1:65536/mtu'),@('HOMEVPN_MTU_OWNER_URL','http://127.0.0.1:1234/mtu?x=1'),
    @('HOMEVPN_MTU_OWNER_URL','http://x@127.0.0.1:1234/mtu'),@('HOMEVPN_MTU_OWNER_HELPER','relative-helper'),
    @('HOMEVPN_MTU_MINIMUM',''),@('HOMEVPN_MTU_MINIMUM','575'),@('HOMEVPN_MTU_MINIMUM','1281'),@('HOMEVPN_MTU_MINIMUM','1e3'))
  foreach($Case in $Invalid){$prior=[Environment]::GetEnvironmentVariable($Case[0],'Process');try{[Environment]::SetEnvironmentVariable($Case[0],$Case[1],'Process');Assert-Rejected {Read-Mtu $Alias 'IPv4'} ('Invalid helper capability was accepted: '+$Case[0])}finally{[Environment]::SetEnvironmentVariable($Case[0],$prior,'Process')}}
  Assert-Owner (@(Read-Calls).Count-eq0) 'Invalid helper capability spawned a child.'
  $MinMtu=1200;$MaxMtu=1500;$Step=20;$MaxCandidates=16
  $env:HOMEVPN_MTU_MINIMUM='1280'
  $candidates=@(Candidate-Mtus 1400)
  Assert-Owner ($candidates[0]-eq1400-and$candidates-contains1280-and@($candidates|Where-Object{$_-lt1280}).Count-eq0) 'Native TUN candidates crossed the explicit minimum.'
  Assert-Rejected {Set-Mtu $Alias 'IPv4' 1200} 'Native TUN minimum was not checked before mutation.'
  Assert-Owner (@(Read-Calls|Where-Object{$_[0]-ceq'--mtu-owner-set'}).Count-eq0) 'Below-floor candidate reached mutation.'
  $state=Read-Fixture;$state.mtu=1200;[IO.File]::WriteAllText($env:MTU_OWNER_FIXTURE,($state|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
  Assert-Rejected {Read-Mtu $Alias 'IPv4'} 'Below-floor readback was accepted as a rollback target.'
  $env:HOMEVPN_MTU_MINIMUM='576'

  $Graph=@{HOMEVPN_MTU_GRAPH_TOKEN=('b'*64);HOMEVPN_MTU_GRAPH_SCOPE='multihop-exit-path';HOMEVPN_MTU_CONTROL_PROFILE_ID='control';HOMEVPN_MTU_PHYSICAL_ENTRY_ID='entry';HOMEVPN_MTU_PHYSICAL_ENTRY_ENDPOINT='203.0.113.8'}
  $env:HOMEVPN_PROFILE_ID='exit'
  foreach($Missing in $GraphNames){
    foreach($Name in $GraphNames){[Environment]::SetEnvironmentVariable($Name,$Graph[$Name],'Process')}
    Remove-Item -LiteralPath ('Env:'+$Missing) -ErrorAction SilentlyContinue
    Assert-Rejected {Read-Mtu $Alias 'IPv4'} ('Partial graph reached the mutation helper: '+$Missing)
  }
  foreach($Name in $GraphNames){[Environment]::SetEnvironmentVariable($Name,$Graph[$Name],'Process')}
  foreach($Case in @(@('HOMEVPN_MTU_GRAPH_TOKEN',('B'*64)),@('HOMEVPN_MTU_GRAPH_SCOPE','entry-only'),@('HOMEVPN_MTU_CONTROL_PROFILE_ID','../control'),@('HOMEVPN_MTU_PHYSICAL_ENTRY_ID','exit'),@('HOMEVPN_MTU_PHYSICAL_ENTRY_ENDPOINT','entry.example.invalid'))){
    [Environment]::SetEnvironmentVariable($Case[0],$Case[1],'Process')
    Assert-Rejected {Read-Mtu $Alias 'IPv4'} ('Malformed graph reached the mutation helper: '+$Case[0])
    [Environment]::SetEnvironmentVariable($Case[0],$Graph[$Case[0]],'Process')
  }
  $env:HOMEVPN_ROOT=$TaskRoot;$env:HOMEVPN_MODE='wg';$env:HOMEVPN_IP_FAMILY='4';$env:HOMEVPN_NETWORK_CONTEXT=$null
  $Control=[pscustomobject]@{id='control';endpoint='192.0.2.7';kill_switch_policy='always';home_lan_access=$false}
  $Entry=[pscustomobject]@{id='entry';endpoint='203.0.113.8';kill_switch_policy='off';home_lan_access=$true}
  $Exit=[pscustomobject]@{id='exit';endpoint='198.51.100.9';kill_switch_policy='off';home_lan_access=$true}
  $Store=[pscustomobject]@{selected_id='control';profiles=@($Control,$Entry,$Exit)}
  [IO.File]::WriteAllText((Join-Path $TaskRoot 'routers.json'),($Store|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
  function Resolve-EndpointIP([string]$Endpoint){$script:LastResolvedEndpoint=$Endpoint;return [Net.IPAddress]::Parse($Endpoint)}
  function Find-NetRoute {return $null}
  $first=Path-Context $Exit
  Assert-Owner ($script:LastResolvedEndpoint-ceq'203.0.113.8') 'Path fingerprint measured the exit instead of physical entry.'
  $env:HOMEVPN_MTU_GRAPH_TOKEN='c'*64;$second=Path-Context $Exit
  Assert-Owner ($first.Key-cne$second.Key-and$first.Generated-cne$second.Generated) 'Changed graph/proved winner retained its old path fingerprint.'
  $env:HOMEVPN_MTU_GRAPH_TOKEN=$Graph.HOMEVPN_MTU_GRAPH_TOKEN
  $env:HOMEVPN_NATIVE_ENDPOINTS_JSON='["198.51.100.111"]';$env:HOMEVPN_NATIVE_EGRESS_JSON='[{"host":"198.51.100.111"}]';$env:HOMEVPN_EXTERNAL_SESSION='d'*32;$env:HOMEVPN_NODE_SESSION='e'*32
  $env:MTU_GUARD_FIXTURE=Join-Path $TaskRoot 'guard.json';$env:MTU_GUARD_FAIL='0'
  $Guard=@'
param($Action,$Root,$TunnelAlias,$Endpoint,$Policy,$HomeLANAccess)
$exposed=@([Environment]::GetEnvironmentVariables('Process').Keys|Where-Object{$_.StartsWith('HOMEVPN_MTU_')-or$_.StartsWith('HOMEVPN_NATIVE_')-or$_.StartsWith('HOMEVPN_NODE_')-or$_-eq'HOMEVPN_EXTERNAL_SESSION'})
$record=@{action=$Action;root=$Root;tunnel=$TunnelAlias;endpoint=$Endpoint;policy=$Policy;lan=$HomeLANAccess;runtime=$env:HOMEVPN_PROFILE_ID;control=$env:HOMEVPN_POLICY_PROFILE_ID;exposed=$exposed}
[IO.File]::WriteAllText($env:MTU_GUARD_FIXTURE,($record|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
if($env:MTU_GUARD_FAIL-eq'1'){exit 19};exit 0
'@
  [IO.File]::WriteAllText((Join-Path $TaskRoot 'windows-kill-switch.ps1'),$Guard,[Text.UTF8Encoding]::new($false))
  Ensure-KillSwitch $Exit $Alias
  $record=[IO.File]::ReadAllText($env:MTU_GUARD_FIXTURE)|ConvertFrom-Json
  Assert-Owner ($record.runtime-ceq'entry'-and$record.control-ceq'control'-and$record.endpoint-ceq'203.0.113.8'-and$record.policy-ceq'always'-and$record.lan-ceq'false') 'Firewall reassertion used exit policy or exit physical endpoint.'
  Assert-Owner (@($record.exposed).Count-eq0) 'Firewall inherited a foreign egress or MTU mutation capability.'
  Assert-Owner ($env:HOMEVPN_PROFILE_ID-ceq'exit'-and$env:HOMEVPN_MTU_OWNER_TOKEN-ceq$Token-and$env:HOMEVPN_EXTERNAL_SESSION-ceq('d'*32)) 'Firewall reassertion changed the optimizer proof/capability owner.'
  $env:MTU_GUARD_FAIL='1';Assert-Rejected {Ensure-KillSwitch $Exit $Alias} 'Failed captured firewall reassertion was accepted.'
  Assert-Owner ($env:HOMEVPN_PROFILE_ID-ceq'exit'-and$env:HOMEVPN_MTU_OWNER_TOKEN-ceq$Token) 'Failed firewall reassertion did not restore optimizer environment.'
  $Entry.endpoint='203.0.113.99';[IO.File]::WriteAllText((Join-Path $TaskRoot 'routers.json'),($Store|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
  Assert-Rejected {Get-MtuGuardSettings $Exit} 'Changed physical entry profile was accepted.'
  foreach($Name in $GraphNames){Remove-Item -LiteralPath ('Env:'+$Name) -ErrorAction SilentlyContinue}

  function Require-Admin {}
  function Read-Store {return [pscustomobject]@{Profile=[pscustomobject]@{mtu_policy='auto';daita_host='10.77.0.1'}}}
  function Ensure-KillSwitch($Profile,[string]$Alias){}
  function Route-Alias([string]$Target){return 'owned-tun'}
  function Path-Context($Profile){return [pscustomobject]@{Key='captured';Network='network';Generated='profile'}}
  function Prove-Node($Profile){
    $script:ProofCalls++
    if($script:ProofCalls-eq2-and$script:ProofFailure){
      if($script:ProofFailure-ceq'retired'){$state=Read-Fixture;$state.mode='retired';[IO.File]::WriteAllText($env:MTU_OWNER_FIXTURE,($state|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))}
      throw 'Measured path proof failed.'
    }
  }
  $env:HOMEVPN_MTU_APPLY_INTERFACE=$Alias;$env:HOMEVPN_MTU_APPLY_FAMILY='4';$env:HOMEVPN_MTU_APPLY_VALUE='1320';$env:HOMEVPN_MTU_EXPECTED_PATH_KEY='captured'
  $script:ProofCalls=0;$script:ProofFailure='';Reset-Fixture
  $result=(Invoke-ApplyMeasured $false)|ConvertFrom-Json
  Assert-Owner ($result.owner_token-ceq$Token-and$result.applied_mtu-eq1320-and(Read-Fixture).mtu-eq1320) 'Actual apply did not retain the owner receipt.'
  $env:HOMEVPN_MTU_APPLY_VALUE='1400'
  $result=(Invoke-ApplyMeasured $true)|ConvertFrom-Json
  Assert-Owner ($result.owner_token-ceq$Token-and$result.rollback-and(Read-Fixture).mtu-eq1400) 'Actual rollback did not retain the owner receipt.'
  $env:HOMEVPN_MTU_APPLY_VALUE='1320'
  $script:ProofCalls=0;$script:ProofFailure='failed';Reset-Fixture
  Assert-Rejected {Invoke-ApplyMeasured $false} 'A failed post-apply path proof was accepted.'
  Assert-Owner ((Read-Fixture).mtu-eq1400) 'A failed post-apply proof did not restore the captured owner.'
  $script:ProofCalls=0;$script:ProofFailure='retired';Reset-Fixture
  $failed=$false;try{Invoke-ApplyMeasured $false|Out-Null}catch{$failed=$_.Exception.Message-like'*rollback was not confirmed*'}
  Assert-Owner $failed 'Retired owner cleanup pretended rollback succeeded.'
  Assert-Owner (@(Read-Calls|Where-Object{$_[0]-ceq'--mtu-owner-set'}).Count-eq1) 'Retired cleanup sent a late mutation.'
  Write-Host ('PASS actual Windows MTU optimizer/helper subprocess: '+$Checks+' ownership/readback/raw-reply/adoption/rollback checks')
}finally{
  foreach($Name in $Names){if($null-eq$Saved[$Name]){Remove-Item -LiteralPath ('Env:'+$Name) -ErrorAction SilentlyContinue}else{[Environment]::SetEnvironmentVariable($Name,$Saved[$Name],'Process')}}
  if(Test-Path -LiteralPath $TaskRoot){[IO.Directory]::Delete($TaskRoot,$true)}
}
