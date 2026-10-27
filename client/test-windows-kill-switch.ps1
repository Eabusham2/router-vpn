param([switch]$PreserveJsonArrays,[string]$Source='')
$ErrorActionPreference = 'Stop'
if ($PreserveJsonArrays) {
  if (-not (Get-Command Microsoft.PowerShell.Utility\ConvertFrom-Json).Parameters.ContainsKey('NoEnumerate')) { throw 'This compatibility test requires NoEnumerate support.' }
  # Reproduce Windows PowerShell 5.1's top-level array behavior on PowerShell 7.
  function ConvertFrom-Json {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$InputObject)
    process { Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $InputObject -NoEnumerate }
  }
}
$script = if($Source){[IO.Path]::GetFullPath($Source)}else{Join-Path $PSScriptRoot 'windows-kill-switch.ps1'}
$temp = Join-Path ([IO.Path]::GetTempPath()) ('router-vpn-killswitch-test-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $temp | Out-Null
$nativeNames = @('HOMEVPN_STANDARD_ENGINE','HOMEVPN_EXTERNAL_SESSION','HOMEVPN_NATIVE_ENDPOINTS_JSON','HOMEVPN_NATIVE_EGRESS_JSON','HOMEVPN_PROFILE_ID','HOMEVPN_POLICY_PROFILE_ID','HOMEVPN_ENDPOINT','HOMEVPN_ROOT')
$originalNative = @{}
foreach ($name in $nativeNames) {
  $originalNative[$name] = [Environment]::GetEnvironmentVariable($name,'Process')
  Remove-Item -LiteralPath ('Env:'+$name) -ErrorAction SilentlyContinue
}
try {
  $plan = (& $script -Action plan -Endpoint '203.0.113.7' -Policy 'on-connect' -HomeLANAccess 'false' -TunnelAlias 'router-vpn' -StateRoot $temp | ConvertFrom-Json)
  if ($plan.policy -ne 'on-connect') { throw 'plan did not retain on-connect policy' }
  if ($plan.endpoint -ne '203.0.113.7') { throw 'plan did not retain literal endpoint' }
  if ($plan.default_outbound -ne 'Block') { throw 'plan is not fail-closed' }
  if ($plan.home_lan_access) { throw 'plan unexpectedly enabled LAN access' }
  if ($plan.tunnel_alias -ne 'router-vpn') { throw 'plan lost tunnel alias' }

  $lanPlan = (& $script -Action plan -Endpoint '2001:db8::7' -Policy 'always' -HomeLANAccess 'true' -TunnelAlias 'router-vpn-max' -StateRoot $temp | ConvertFrom-Json)
  if (-not $lanPlan.home_lan_access -or $lanPlan.policy -ne 'always') { throw 'LAN/always plan is wrong' }

  $env:HOMEVPN_STANDARD_ENGINE = 'native'
  $env:HOMEVPN_EXTERNAL_SESSION = ('a' * 32)
  $validEndpoints = '["203.0.113.7","198.51.100.20","2001:db8::7"]'
  $env:HOMEVPN_NATIVE_ENDPOINTS_JSON = $validEndpoints
  $nativePlan = (& $script -Action plan -Endpoint '203.0.113.7' -Policy 'on-connect' -HomeLANAccess 'false' -TunnelAlias 'router-vpn' -StateRoot $temp | ConvertFrom-Json)
  if (($nativePlan.endpoint_ips -join ',') -cne '203.0.113.7,198.51.100.20,2001:db8::7') { throw 'native plan lost captured physical failover remotes' }
  if ($nativePlan.default_outbound -ne 'Block' -or $nativePlan.home_lan_access) { throw 'native remote list changed kill-switch or LAN policy' }

  # Exercise the shipping rule builder, doubling only the Windows firewall
  # cmdlets. This also runs under PowerShell 5.1 in the native Windows gate.
  $tokens=$null; $parseErrors=$null
  $tree=[Management.Automation.Language.Parser]::ParseFile($script,[ref]$tokens,[ref]$parseErrors)
  if ($parseErrors.Count) { throw 'Windows kill-switch parse failed' }
  foreach ($functionName in @('Assert-NativeEgress','Remove-Rules','Add-Rule','Install-AllowRules')) {
    $definition=$tree.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName},$true)
    if (-not $definition) { throw "Missing shipping function $functionName" }
    Invoke-Expression $definition.Extent.Text
  }
  $script:capturedRules = @()
  $script:firewallReads=0
  function Get-NetFirewallRule { param($Group,$ErrorAction) $script:firewallReads++ }
  function Remove-NetFirewallRule { param($ErrorAction) }
  function New-NetFirewallRule {
    param($DisplayName,$Group,$Direction,$Action,$Profile,$RemoteAddress,$Protocol,$LocalPort,$RemotePort,$IcmpType,$InterfaceAlias)
    $script:capturedRules += @{} + $PSBoundParameters
  }
  $RuleGroup='Router VPN test'; $RulePrefix='Router VPN test '
  Install-AllowRules $nativePlan
  $nodeRule=@($script:capturedRules | Where-Object { $_.DisplayName -eq 'Router VPN test selected node' })
  if ($nodeRule.Count -ne 1 -or ($nodeRule[0].RemoteAddress -join ',') -cne '203.0.113.7,198.51.100.20,2001:db8::7') { throw 'firewall cmdlet did not receive exactly the captured physical remotes' }
  if (@($script:capturedRules | Where-Object { $_.RemoteAddress -contains 'LocalSubnet' }).Count) { throw 'native path unexpectedly opened the LAN' }
  foreach ($rule in $script:capturedRules) {
    if ($rule.Direction -ne 'Outbound' -or $rule.Action -ne 'Allow') { throw 'native path created an unexpected firewall rule' }
  }

  $egress='[{"host":"203.0.113.7","port":8388,"network":"udp"},{"host":"198.51.100.20","port":8390,"network":"tcp"},{"host":"2001:db8::7","port":8389,"network":"udp"}]'
  $env:HOMEVPN_NATIVE_EGRESS_JSON=$egress
  $egressPlan=(& $script -Action plan -Endpoint '203.0.113.7' -Policy 'always' -HomeLANAccess 'false' -TunnelAlias 'router-vpn' -StateRoot $temp | ConvertFrom-Json)
  if(@($egressPlan.native_egress).Count-ne3){throw 'Captured egress lost its array shape.'}
  $script:capturedRules=@();Install-AllowRules $egressPlan
  $outer=@($script:capturedRules|Where-Object{$_.DisplayName-like'Router VPN test native outer *'})
  if($outer.Count-ne3-or@($script:capturedRules|Where-Object{$_.DisplayName-eq'Router VPN test selected node'}).Count){throw 'Mapped egress widened into an all-port host rule.'}
  for($i=0;$i-lt3;$i++){
    $expected=$egressPlan.native_egress[$i]
    if(@($outer[$i].RemoteAddress).Count-ne1-or$outer[$i].RemoteAddress[0]-cne$expected.host-or$outer[$i].RemotePort-cne[string]$expected.port-or$outer[$i].Protocol-cne$expected.network.ToUpperInvariant()){throw 'Firewall cmdlet lost exact compiled outer tuple.'}
  }
  $badEgress=@('null','{}','[]','[[{"host":"203.0.113.7","port":8388,"network":"udp"}]]',
    '[{"host":"203.0.113.7","port":8388,"network":"udp"}]',
    $egress.Replace('"port":8388','"port":0'),$egress.Replace('"port":8388','"port":65536'),
    $egress.Replace('"port":8388','"port":"8388"'),$egress.Replace('"port":8388','"port":8388.0'),
    $egress.Replace('"port":8388','"port":true'),$egress.Replace('"network":"udp"','"network":"UDP"'),
    $egress.Replace('"network":"udp"','"network":"icmp"'),$egress.Replace('203.0.113.7','vpn.example.test'),
    $egress.Replace('"port":8388','"port":8388,"port":8390'),
    $egress.Replace('"port":8388','"port":8388,"unknown":1'),
    $egress.Replace('203.0.113.7','203.0.113.8'),$egress.Substring(0,$egress.Length-1)+','+$egress.Substring(1),
    (' '*4097))
  foreach($raw in $badEgress){
    $env:HOMEVPN_NATIVE_EGRESS_JSON=$raw;$rejected=$false
    try{& $script -Action plan -Endpoint '203.0.113.7' -Policy 'always' -HomeLANAccess 'false' -StateRoot $temp|Out-Null}catch{$rejected=$true}
    if(-not$rejected){throw 'Malformed native egress reached a permissive plan.'}
  }
  foreach($owner in @('engine','session')){
    $env:HOMEVPN_NATIVE_EGRESS_JSON=$egress;$env:HOMEVPN_STANDARD_ENGINE='native';$env:HOMEVPN_EXTERNAL_SESSION=('a'*32)
    if($owner-eq'engine'){$env:HOMEVPN_STANDARD_ENGINE='openvpn'}else{$env:HOMEVPN_EXTERNAL_SESSION=('A'*32)}
    $rejected=$false;try{& $script -Action plan -Endpoint '203.0.113.7' -Policy 'always' -HomeLANAccess 'false' -StateRoot $temp|Out-Null}catch{$rejected=$true}
    if(-not$rejected){throw 'Unowned native egress reached a permissive plan.'}
  }
  $beforeReads=$script:firewallReads
  $invalidPlan=[pscustomobject]@{endpoint_ips=@('203.0.113.7');native_egress=@();home_lan_access=$false;tunnel_alias='router-vpn'}
  $rejected=$false;try{Install-AllowRules $invalidPlan}catch{$rejected=$true}
  if(-not$rejected-or$script:firewallReads-ne$beforeReads){throw 'Malformed retained tuple list changed firewall rules before rejection.'}
  Remove-Item Env:HOMEVPN_NATIVE_EGRESS_JSON
  $env:HOMEVPN_STANDARD_ENGINE='native';$env:HOMEVPN_EXTERNAL_SESSION=('a'*32)

  $badLists=@('null','{}','[]','"203.0.113.7"','["198.51.100.20"]',
    '["203.0.113.7","203.0.113.7"]','["203.0.113.7",null]',
    '["203.0.113.7",7]','["203.0.113.7",["198.51.100.20"]]',
    '[["203.0.113.7"]]','[],"endpoints":["203.0.113.7"]')
  $badLists += '[' + ((@('"203.0.113.7"') * 17) -join ',') + ']'
  foreach ($address in @('vpn.example.test','198.51.100.20/24',' 198.51.100.20',
    '127.0.0.1','0.0.0.0','255.255.255.255','224.0.0.1','169.254.1.2',
    '::','::1','ff02::1','fe80::1','fe80::1%3','::ffff:198.51.100.20','2001:DB8::7')) {
    $badLists += '["203.0.113.7","' + $address + '"]'
  }
  foreach ($raw in $badLists) {
    $env:HOMEVPN_NATIVE_ENDPOINTS_JSON=$raw
    $rejected=$false
    try { & $script -Action plan -Endpoint '203.0.113.7' -Policy 'on-connect' -HomeLANAccess 'false' -StateRoot $temp | Out-Null } catch { $rejected=$true }
    if (-not $rejected) { throw "Unsafe native physical list was accepted: $raw" }
  }
  foreach ($badOwner in @('engine','missing','uppercase','oversized')) {
    $env:HOMEVPN_STANDARD_ENGINE='native'; $env:HOMEVPN_EXTERNAL_SESSION=('a' * 32); $env:HOMEVPN_NATIVE_ENDPOINTS_JSON=$validEndpoints
    switch ($badOwner) {
      'engine' { $env:HOMEVPN_STANDARD_ENGINE='openvpn' }
      'missing' { Remove-Item Env:HOMEVPN_EXTERNAL_SESSION }
      'uppercase' { $env:HOMEVPN_EXTERNAL_SESSION=('A' * 32) }
      'oversized' { $env:HOMEVPN_NATIVE_ENDPOINTS_JSON=(' ' * 1025) }
    }
    $rejected=$false
    try { & $script -Action plan -Endpoint '203.0.113.7' -Policy 'on-connect' -HomeLANAccess 'false' -StateRoot $temp | Out-Null } catch { $rejected=$true }
    if (-not $rejected) { throw "Unowned native physical list was accepted: $badOwner" }
  }
  foreach ($name in $nativeNames) { Remove-Item -LiteralPath ('Env:'+$name) -ErrorAction SilentlyContinue }

  # Execute actual read-only plans against an owned private store. The entry
  # controls physical endpoint exceptions; the captured exit/control owns
  # kill-switch and LAN policy, independently of the currently selected node.
  $profileRoot=Join-Path $temp 'policy-profiles';New-Item -ItemType Directory -Path $profileRoot|Out-Null
  $policyStore=[pscustomobject]@{selected_id='ordinary';profiles=@(
    [pscustomobject]@{id='ordinary';endpoint='203.0.113.30';kill_switch_policy='on-connect';home_lan_access=$true},
    [pscustomobject]@{id='entry';endpoint='203.0.113.11';kill_switch_policy='off';home_lan_access=$true},
    [pscustomobject]@{id='exit';endpoint='198.51.100.20';kill_switch_policy='always';home_lan_access=$false}
  )}
  function Write-PolicyStore {[IO.File]::WriteAllText((Join-Path $profileRoot 'routers.json'),($policyStore|ConvertTo-Json -Depth 10),(New-Object Text.UTF8Encoding($false)))}
  function Assert-PolicyPlan([string]$ExpectedEndpoint,[string]$ExpectedPolicy,[bool]$ExpectedLAN) {
    $value=(& $script -Action plan -Root $profileRoot -StateRoot $temp -TunnelAlias 'router-vpn'|ConvertFrom-Json)
    if($value.endpoint-cne$ExpectedEndpoint-or$value.policy-cne$ExpectedPolicy-or[bool]$value.home_lan_access-ne$ExpectedLAN){throw 'Captured physical endpoint and policy owner were mixed.'}
  }
  function Assert-PolicyRejected {
    $rejected=$false;try{& $script -Action plan -Root $profileRoot -StateRoot $temp -TunnelAlias 'router-vpn'|Out-Null}catch{$rejected=$true}
    if(-not$rejected){throw 'Invalid captured policy owner fell back to an unrelated profile.'}
  }
  Write-PolicyStore
  Assert-PolicyPlan '203.0.113.30' 'on-connect' $true
  $env:HOMEVPN_PROFILE_ID='entry';Assert-PolicyPlan '203.0.113.11' 'off' $true
  $env:HOMEVPN_PROFILE_ID='exit';Assert-PolicyPlan '198.51.100.20' 'always' $false
  $env:HOMEVPN_PROFILE_ID='entry';$env:HOMEVPN_POLICY_PROFILE_ID='exit'
  Assert-PolicyPlan '203.0.113.11' 'always' $false
  $env:HOMEVPN_ENDPOINT='203.0.113.12';Assert-PolicyPlan '203.0.113.12' 'always' $false
  Remove-Item Env:HOMEVPN_ENDPOINT
  $policyStore.selected_id='missing';Write-PolicyStore
  Assert-PolicyPlan '203.0.113.11' 'always' $false
  $policyStore.profiles[1].kill_switch_policy='always';$policyStore.profiles[1].home_lan_access=$false
  $policyStore.profiles[2].kill_switch_policy='off';$policyStore.profiles[2].home_lan_access=$true;Write-PolicyStore
  Assert-PolicyPlan '203.0.113.11' 'off' $true
  $policyStore.profiles[1].kill_switch_policy='off';$policyStore.profiles[1].home_lan_access=$true
  $policyStore.profiles[2].kill_switch_policy='always';$policyStore.profiles[2].home_lan_access=$false;Write-PolicyStore
  foreach($badID in @('missing','EXIT','../exit',' ')){$env:HOMEVPN_POLICY_PROFILE_ID=$badID;Assert-PolicyRejected}
  $env:HOMEVPN_POLICY_PROFILE_ID='exit'
  foreach($badID in @('missing','ENTRY','../entry',' ')){$env:HOMEVPN_PROFILE_ID=$badID;Assert-PolicyRejected}
  $policyStore.selected_id='ordinary';Write-PolicyStore
  Remove-Item Env:HOMEVPN_PROFILE_ID;Assert-PolicyRejected
  $env:HOMEVPN_PROFILE_ID='entry'
  foreach($index in @(1,2)){
    $originalProfiles=$policyStore.profiles;$policyStore.profiles=@($originalProfiles)+@($originalProfiles[$index]);Write-PolicyStore
    Assert-PolicyRejected;$policyStore.profiles=$originalProfiles;Write-PolicyStore
  }
  foreach($badPolicy in @('invalid','')){$policyStore.profiles[2].kill_switch_policy=$badPolicy;Write-PolicyStore;Assert-PolicyRejected}
  $policyStore.profiles[2].kill_switch_policy='always';Write-PolicyStore
  foreach($overrides in @(@{Policy='off';HomeLANAccess='false'},@{Policy='always';HomeLANAccess='true'})){
    $rejected=$false;try{& $script -Action plan -Root $profileRoot -StateRoot $temp -Endpoint '203.0.113.11' @overrides|Out-Null}catch{$rejected=$true}
    if(-not$rejected){throw 'Explicit arguments bypassed the captured kill-switch/LAN policy owner.'}
  }
  $env:HOMEVPN_POLICY_PROFILE_ID='missing'
  $rejected=$false;try{& $script -Action plan -Root $profileRoot -StateRoot $temp -Endpoint '203.0.113.11' -Policy 'off' -HomeLANAccess 'true'|Out-Null}catch{$rejected=$true}
  if(-not$rejected){throw 'Explicit plan arguments bypassed a missing captured policy owner.'}

  # A Local ordinary predecessor never needs a private Router identity to
  # carry exact strict socket rules. The independent Tor exit owns protection;
  # the entry and unrelated selected profile deliberately request Off/LAN On.
  $policyStore.profiles[1]|Add-Member -NotePropertyName node_kind -NotePropertyValue 'external'
  $policyStore.profiles[1]|Add-Member -NotePropertyName external -NotePropertyValue ([pscustomobject]@{protocol='shadowsocks';expected_public_ip='203.0.113.88';shadowsocks=[pscustomobject]@{server='203.0.113.11';port=8388;method='2022-blake3-aes-256-gcm';password='fixture'}})
  $policyStore.profiles[2]|Add-Member -NotePropertyName node_kind -NotePropertyValue 'external'
  $policyStore.profiles[2]|Add-Member -NotePropertyName external -NotePropertyValue ([pscustomobject]@{protocol='tor-bridge'})
  $env:HOMEVPN_PROFILE_ID='entry';$env:HOMEVPN_POLICY_PROFILE_ID='exit'
  $env:HOMEVPN_STANDARD_ENGINE='native';$env:HOMEVPN_EXTERNAL_SESSION=('a'*32)
  $env:HOMEVPN_NATIVE_ENDPOINTS_JSON='["203.0.113.11"]'
  $env:HOMEVPN_NATIVE_EGRESS_JSON='[{"host":"203.0.113.11","port":8388,"network":"tcp"}]'
  foreach($policy in @('on-connect','always')){
    $policyStore.profiles[2].kill_switch_policy=$policy;Write-PolicyStore
    $strict=(& $script -Action plan -Root $profileRoot -StateRoot $temp -TunnelAlias 'router-vpn-tor'|ConvertFrom-Json)
    if($strict.policy-cne$policy-or$strict.home_lan_access-or$strict.default_outbound-cne'Block'-or$strict.tunnel_alias-cne'router-vpn-tor'){throw 'Ordinary Tor path borrowed an unrelated protection policy.'}
    $script:capturedRules=@();Install-AllowRules $strict
    $outer=@($script:capturedRules|Where-Object{$_.DisplayName-like'Router VPN test native outer *'})
    if($outer.Count-ne1-or$outer[0].RemoteAddress[0]-cne'203.0.113.11'-or$outer[0].RemotePort-cne'8388'-or$outer[0].Protocol-cne'TCP'){throw 'Ordinary Tor path lost its exact physical socket.'}
    if(@($script:capturedRules|Where-Object{$_.DisplayName-eq'Router VPN test selected node'-or$_.RemoteAddress-contains'LocalSubnet'-or$_.RemoteAddress-contains'198.51.100.20'-or$_.RemoteAddress-contains'1.1.1.1'}).Count){throw 'Ordinary Tor path opened a broad host, LAN, direct Tor, or public proof exception.'}
  }
  $env:HOMEVPN_NATIVE_EGRESS_JSON='[{"host":"203.0.113.11","port":8388,"network":"tcp"},{"host":"1.1.1.1","port":443,"network":"tcp"}]'
  Assert-PolicyRejected
  foreach($name in $nativeNames){Remove-Item -LiteralPath ('Env:'+$name) -ErrorAction SilentlyContinue}
  Write-Host 'Windows captured policy-owner plans: direct/router, opposing entry/exit policies, physical endpoint and stale-owner negatives OK'

  $caught = $null
  try {
    & $script -Action plan -Endpoint 'vpn.example.com' -Policy 'on-connect' -StateRoot $temp | Out-Null
  } catch {
    $caught = $_.Exception.Message
  }
  if (-not $caught) { throw 'hostname endpoint was accepted by strict kill switch' }
  if ($caught -notmatch 'literal IPv4/IPv6') { throw "hostname rejection did not explain pre-tunnel DNS risk: $caught" }

  $source = Get-Content -Raw -LiteralPath $script
  foreach ($marker in @(
    'Get-NetFirewallProfile -PolicyStore ActiveStore',
    'Set-NetFirewallProfile',
    'DefaultOutboundAction Block',
    'New-NetFirewallRule',
    'Remove-NetFirewallRule',
    'original_profiles',
    'ProgramData',
    'Router VPN Kill Switch',
    'InterfaceAlias',
    'Assert-NoReparseAncestors',
    'Assert-SafeStateLeaf',
    '[IO.File]::Replace',
    '[Guid]::NewGuid().ToString(''N'')',
    '$stream.Flush($true)',
    'Remove-State -ForceRecovery',
    'emergency outbound-Allow recovery'
  )) {
    if (-not $source.Contains($marker)) { throw "Windows kill-switch source missing marker: $marker" }
  }
  if ($source -match 'Action=.Block.*RemoteAddress=.Any') { throw 'explicit block-all rule would override intended allow rules' }
  if ($source.Contains('$path.tmp')) { throw 'predictable Windows kill-switch state temp path returned' }
  if ($source -match 'Move-Item\s+-LiteralPath\s+\$tmp\s+-Destination\s+\$path\s+-Force') { throw 'non-atomic force move returned for Windows kill-switch state' }

  $badState = Join-Path $temp 'windows-state.json'
  [IO.File]::WriteAllText($badState,'{broken',(New-Object Text.UTF8Encoding($false)))
  $caughtState = $null
  try {
    & $script -Action status -Endpoint '203.0.113.7' -Policy 'on-connect' -HomeLANAccess 'false' -StateRoot $temp | Out-Null
  } catch {
    $caughtState = $_.Exception.Message
  }
  if (-not $caughtState -or $caughtState -notmatch 'Invalid Windows kill-switch rollback state JSON') {
    throw "corrupt persistent Windows kill-switch state did not fail closed: $caughtState"
  }
  Remove-Item -LiteralPath $badState -Force

  Write-Host 'Windows kill-switch plan/rollback/private-state contract: OK'
} finally {
  foreach ($name in $nativeNames) {
    if ($null -eq $originalNative[$name]) { Remove-Item -LiteralPath ('Env:'+$name) -ErrorAction SilentlyContinue }
    else { [Environment]::SetEnvironmentVariable($name,$originalNative[$name],'Process') }
  }
  Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
