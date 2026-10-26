param(
  [string]$Root=(Split-Path $PSScriptRoot -Parent),
  [string]$PrivateSource='',
  [string]$LayeredSource='',
  [string]$WireGuardSource=''
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$Checks=0
function Assert-DNS([bool]$Condition,[string]$Message){$script:Checks++;if(-not $Condition){throw ('CONTROL '+$Message)}}
function Reject-DNS([scriptblock]$Run,[string]$Message,[string]$Reason=''){
  $caught='';try{& $Run | Out-Null}catch{$caught=$_.Exception.Message}
  Assert-DNS ($caught.Length -gt 0 -and (-not $Reason -or $caught.Contains($Reason))) $Message
}
function Read-ShippingDNS([string]$File){
  $body=[IO.File]::ReadAllText($File,[Text.Encoding]::UTF8)
  $tokens=$null;$errors=$null
  $tree=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors)
  Assert-DNS ($errors.Count -eq 0) ('whole-source parse '+$File)
  return $tree
}
if(-not $PrivateSource){$PrivateSource=Join-Path $Root 'client/Private-RouterVPN-State.ps1'}
if(-not $LayeredSource){$LayeredSource=Join-Path $Root 'client/native-windows-mode.ps1'}
if(-not $WireGuardSource){$WireGuardSource=Join-Path $Root 'client/native-wireguard-windows.ps1'}
$privateTree=Read-ShippingDNS $PrivateSource
. ([scriptblock]::Create($privateTree.Extent.Text))
$TaskRoot=Join-Path ([IO.Path]::GetTempPath()) ('routervpn-home-dns-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($TaskRoot)
$EnvNames=@('HOMEVPN_PROFILE_ID','HOMEVPN_DNS_MODE','HOMEVPN_DNS_PROTOCOL','HOMEVPN_DNS_HOST','HOMEVPN_DNS_PORT','HOMEVPN_DNS_SERVER_NAME','HOMEVPN_DNS_PATH','HOMEVPN_ADGUARD4','HOMEVPN_ADGUARD6','HOMEVPN_SOCKS','HOMEVPN_JUMBO','HOMEVPN_MTU')
$SavedEnv=@{};foreach($name in $EnvNames){$SavedEnv[$name]=[Environment]::GetEnvironmentVariable($name,'Process');[Environment]::SetEnvironmentVariable($name,$null,'Process')}

function Invoke-HomeDNSCases([string]$Kind,[string]$SourceFile){
  $tree=Read-ShippingDNS $SourceFile
  $functions=@($tree.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst]},$true))
  foreach($name in @('Has-Property','Get-SelectedProfile','Profile-String','Profile-Int','Infer-DnsServerName','Get-DnsSelection','Write-Utf8NoBom')){
    $found=@($functions | Where-Object {$_.Name -ceq $name})
    Assert-DNS ($found.Count -eq 1) ('shipping function missing '+$name)
    . ([scriptblock]::Create($found[0].Extent.Text))
  }
  $root=Join-Path $TaskRoot $Kind
  [void][IO.Directory]::CreateDirectory($root)
  $profileId='node-a';$env:HOMEVPN_PROFILE_ID=$profileId
  function New-Node{
    return [pscustomobject]@{id='node-a';node_kind='router-vpn';adguard_ipv4='10.77.0.1';adguard_ipv6='fd77::1';ipv6_mode='on';dns_mode='home';dns_protocol='udp';dns_host='';dns_port=0;dns_server_name='AdGuard.node.invalid';dns_path='/private-dns';fastest_dns_host='1.1.1.1';password='unrelated-private-value'}
  }
  function Save-Node($Node){
    $other=[pscustomobject]@{id='node-b';node_kind='router-vpn';adguard_ipv4='10.77.0.2';dns_mode='home';dns_protocol='udp'}
    [IO.File]::WriteAllText((Join-Path $root 'routers.json'),(@{selected_id='node-b';profiles=@($Node,$other)} | ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false))
  }
  function Result-Host($Result){if($Kind -eq 'wireguard'){return [string]$Result.dns_host};return [string]$Result.host}
  function Assert-Selection($Result,[string]$Protocol,[string]$Address,[int]$Port,[string]$TLSName,[string]$Path){
    Assert-DNS ($Result.mode -ceq 'home') 'Home mode replaced'
    Assert-DNS ($Result.protocol -ceq $Protocol) 'Home transport overwritten'
    Assert-DNS ((Result-Host $Result) -ceq $Address) 'Home address replaced'
    Assert-DNS ($Result.port -eq $Port) 'Home port overwritten'
    Assert-DNS ($Result.server_name -ceq $TLSName) 'Home TLS name overwritten'
    Assert-DNS ($Result.path -ceq $Path) 'Home path overwritten'
    Assert-DNS (@($Result.PSObject.Properties.Name).Count -eq 6) 'Home result copied unrelated private fields'
  }
  foreach($protocol in @('udp','tcp','tls','https','h3','dot','doh','doh3')){
    $canonical=switch($protocol){'dot'{'tls'}'doh'{'https'}'doh3'{'h3'}default{$protocol}}
    foreach($family in @('ipv4','ipv6')){
      foreach($port in @(0,5443)){
        $node=New-Node;$node.dns_protocol=$protocol;$node.dns_host=$node.('adguard_'+$family);$node.dns_port=$port
        Save-Node $node
        $selected=Get-DnsSelection
        $expectedPort=if($port -ne 0){$port}elseif($canonical -eq 'tls'){853}elseif($canonical -in @('https','h3')){443}else{53}
        $expectedName=if($canonical -in @('tls','https','h3')){$node.dns_server_name}else{''}
        $expectedPath=if($canonical -in @('https','h3')){$node.dns_path}else{''}
        Assert-Selection $selected $canonical $node.dns_host $expectedPort $expectedName $expectedPath
      }
    }
  }
  $node=New-Node;$node.PSObject.Properties.Remove('dns_mode');$node.PSObject.Properties.Remove('dns_protocol');Save-Node $node
  Assert-Selection (Get-DnsSelection) 'udp' '10.77.0.1' 53 '' ''
  $node=New-Node;$node.adguard_ipv4='';Save-Node $node
  Assert-Selection (Get-DnsSelection) 'udp' 'fd77::1' 53 '' ''
  $node=New-Node;$node.dns_protocol='https';$node.dns_path='';Save-Node $node
  Assert-Selection (Get-DnsSelection) 'https' '10.77.0.1' 443 $node.dns_server_name '/dns-query'
  $node=New-Node;$node.dns_host='[fd77:0:0:0:0:0:0:1]';Save-Node $node
  Assert-Selection (Get-DnsSelection) 'udp' 'fd77::1' 53 '' ''
  # Explicit alternatives still execute the original non-Home branch. These
  # cases also catch malformed PowerShell return tokens in legacy helpers.
  $node=New-Node;$node.dns_mode='custom';$node.dns_host='9.9.9.9';$node.dns_protocol='tls';$node.dns_port=8853;$node.dns_server_name='dns.quad9.net';Save-Node $node
  try{$selected=Get-DnsSelection}catch{throw ('CONTROL explicit custom DNS execution failed: '+$_.Exception.Message)}
  Assert-DNS ($selected.mode -ceq 'custom' -and $selected.protocol -ceq 'tls' -and (Result-Host $selected) -ceq '9.9.9.9' -and $selected.port -eq 8853 -and $selected.server_name -ceq 'dns.quad9.net') 'explicit custom DNS regressed'
  $node=New-Node;$node.dns_mode='fastest';Save-Node $node
  try{$selected=Get-DnsSelection}catch{throw ('CONTROL explicit fastest DNS execution failed: '+$_.Exception.Message)}
  Assert-DNS ($selected.mode -ceq 'fastest' -and $selected.protocol -ceq 'udp' -and (Result-Host $selected) -ceq '1.1.1.1' -and $selected.port -eq 53) 'explicit fastest DNS regressed'
  if($Kind -eq 'wireguard'){
    foreach($mode in @('custom','doh3')){
      $node=New-Node;$node.dns_mode=$mode;$node.dns_protocol='h3';$node.dns_host='8.8.4.4';$node.dns_port=5443;$node.dns_server_name='dns.google';$node.dns_path='/private-h3';Save-Node $node
      $selected=Get-DnsSelection
      Assert-DNS ($selected.mode -ceq $mode -and $selected.protocol -ceq 'h3' -and (Result-Host $selected) -ceq '8.8.4.4' -and $selected.port -eq 5443 -and $selected.server_name -ceq 'dns.google' -and $selected.path -ceq '/private-h3') 'raw custom H3 changed captured policy'
    }
    $node=New-Node;$node.dns_mode='custom';$node.dns_protocol='h3';$node.dns_host='198.51.100.53';$node.dns_server_name='';Save-Node $node
    Reject-DNS {Get-DnsSelection} 'raw H3 accepted missing TLS identity' 'requires a TLS server name'
    $node.dns_host='resolver.example.invalid';$node.dns_server_name='resolver.example.invalid';Save-Node $node
    Reject-DNS {Get-DnsSelection} 'raw H3 allowed bootstrap outside captured literal address' 'requires a literal DNS upstream IP'
  }

  $invalid=@(
    @('missing-address',@{adguard_ipv4='';adguard_ipv6=''}),
    @('wrong-node',@{dns_host='10.77.0.2'}),
    @('public-host',@{dns_host='1.1.1.1'}),
    @('public-node',@{adguard_ipv4='1.1.1.1'}),
    @('public-v6-node',@{adguard_ipv6='2001:4860:4860::8888'}),
    @('loopback-node',@{adguard_ipv4='127.0.0.1'}),
    @('link-local-node',@{adguard_ipv6='fe80::1'}),
    @('mapped-node',@{adguard_ipv6='::ffff:10.77.0.1'}),
    @('zoned-node',@{adguard_ipv6='fd77::1%4'}),
    @('wrong-v4-family',@{adguard_ipv4='fd77::1'}),
    @('wrong-v6-family',@{adguard_ipv6='10.77.0.1'}),
    @('noncanonical-v6',@{adguard_ipv6='FD77::1'}),
    @('short-v4',@{adguard_ipv4='10.1'}),
    @('octal-v4',@{adguard_ipv4='010.077.0.1'}),
    @('spaced-node',@{adguard_ipv4=' 10.77.0.1'}),
    @('mapped-host',@{dns_host='::ffff:10.77.0.1'}),
    @('zoned-host',@{dns_host='fd77::1%0'}),
    @('ipv6-off-explicit',@{ipv6_mode='off';dns_host='fd77::1'}),
    @('ipv6-off-only',@{ipv6_mode='off';adguard_ipv4=''}),
    @('external-owner',@{node_kind='external'}),
    @('wrong-transport',@{dns_protocol='rescue'}),
    @('negative-port',@{dns_port=-1}),
    @('large-port',@{dns_port=65536}),
    @('noninteger-port',@{dns_port=3.5}),
    @('nonnumeric-port',@{dns_port='invalid'}),
    @('boolean-port',@{dns_port=$true}),
    @('missing-tls',@{dns_protocol='tls';dns_server_name=''}),
    @('ip-tls',@{dns_protocol='tls';dns_server_name='10.77.0.1'}),
    @('url-tls',@{dns_protocol='tls';dns_server_name='https://node.invalid'}),
    @('single-label-tls',@{dns_protocol='tls';dns_server_name='adguard'}),
    @('trailing-dot-tls',@{dns_protocol='tls';dns_server_name='node.invalid.'}),
    @('hyphen-tls',@{dns_protocol='tls';dns_server_name='-node.invalid'}),
    @('relative-path',@{dns_protocol='https';dns_path='dns-query'}),
    @('url-path',@{dns_protocol='https';dns_path='https://other.invalid/dns-query'}),
    @('authority-path',@{dns_protocol='https';dns_path='//other.invalid/dns-query'}),
    @('query-path',@{dns_protocol='https';dns_path='/dns-query?other=1'}),
    @('fragment-path',@{dns_protocol='https';dns_path='/dns-query#fragment'}),
    @('newline-path',@{dns_protocol='https';dns_path="/dns`nquery"}),
    @('backslash-path',@{dns_protocol='https';dns_path='/dns\query'}),
    @('escaped-path',@{dns_protocol='https';dns_path='/dns%invalid'}),
    @('large-path',@{dns_protocol='https';dns_path=('/'+('a'*2048))})
  )
  foreach($case in $invalid){
    $node=New-Node;foreach($key in $case[1].Keys){$node.$key=$case[1][$key]};Save-Node $node
    Reject-DNS {Get-DnsSelection} ('invalid Home policy accepted '+$case[0])
  }
  $node=New-Node;Save-Node $node
  $env:HOMEVPN_PROFILE_ID='NODE-A';$profileId='NODE-A'
  Reject-DNS {Get-DnsSelection} 'wrong captured profile case accepted'
  $env:HOMEVPN_PROFILE_ID='missing';$profileId='missing'
  Reject-DNS {Get-DnsSelection} 'missing captured profile fell back'
  $env:HOMEVPN_PROFILE_ID='node-a';$profileId='node-a'
  $node=New-Node;$node.dns_protocol='tls';$node.dns_port=8853;Save-Node $node
  $poison=@{HOMEVPN_DNS_MODE='fastest';HOMEVPN_DNS_PROTOCOL='udp';HOMEVPN_DNS_HOST='8.8.8.8';HOMEVPN_DNS_PORT='53';HOMEVPN_DNS_SERVER_NAME='other.invalid';HOMEVPN_DNS_PATH='/other';HOMEVPN_ADGUARD4='10.77.0.2';HOMEVPN_ADGUARD6='fd77::2'}
  foreach($key in $poison.Keys){[Environment]::SetEnvironmentVariable($key,$poison[$key],'Process')}
  Assert-Selection (Get-DnsSelection) 'tls' '10.77.0.1' 8853 $node.dns_server_name ''
  foreach($key in $poison.Keys){[Environment]::SetEnvironmentVariable($key,$null,'Process')}

  if($Kind -eq 'layered'){
    foreach($name in @('Patch-JsonRecursive','Patch-SingBox','Assert-Ready')){
      $found=@($functions | Where-Object {$_.Name -ceq $name});Assert-DNS ($found.Count -eq 1) ('shipping function missing '+$name)
      . ([scriptblock]::Create($found[0].Extent.Text))
    }
    function New-Config{
      return @{inbounds=@(@{type='tun';tag='tun';interface_name='router-vpn'});outbounds=@(@{type='shadowsocks';tag='proxy';server='router-a.invalid';server_port=8388},@{type='direct';tag='direct'});route=@{rules=@()}}
    }
    $config=Join-Path $root 'sing-box.json'
    foreach($protocol in @('udp','tcp','tls','https','h3')){
      $node=New-Node;$node.dns_protocol=$protocol;$node.dns_port=5443;$node.dns_host='fd77::1';Save-Node $node
      [IO.File]::WriteAllText($config,((New-Config)|ConvertTo-Json -Depth 20))
      Patch-SingBox $config '203.0.113.10'
      $actual=[IO.File]::ReadAllText($config)|ConvertFrom-Json
      Assert-DNS ($actual.dns.final -ceq 'selected-dns' -and @($actual.dns.servers).Count -eq 1) 'layered DNS retained another resolver'
      $server=$actual.dns.servers[0]
      Assert-DNS ($server.type -ceq $protocol -and $server.server -ceq 'fd77::1' -and $server.server_port -eq 5443) 'layered JSON changed Home transport or address'
      Assert-DNS ($server.detour -ceq 'proxy') 'layered Home DNS bypassed tunnel'
      Assert-DNS (@($actual.route.rules|Where-Object {$_.protocol -eq 'dns' -and $_.action -eq 'hijack-dns'}).Count -eq 1) 'layered DNS interception missing'
      if($protocol -in @('tls','https','h3')){Assert-DNS ($server.tls.enabled -and $server.tls.server_name -ceq $node.dns_server_name) 'layered JSON lost Home TLS identity'}
      if($protocol -in @('https','h3')){Assert-DNS ($server.path -ceq $node.dns_path) 'layered JSON lost Home HTTPS path'}
    }
    foreach($case in @('missing','direct','duplicate')){
      $cfg=New-Config
      if($case -eq 'missing'){$cfg.outbounds=@(@{tag='direct';type='direct'})}
      elseif($case -eq 'direct'){$cfg.outbounds[0].type='direct'}
      else{$cfg.outbounds+=@{tag='proxy';type='shadowsocks';server='other.invalid'}}
      $before=$cfg|ConvertTo-Json -Depth 20;[IO.File]::WriteAllText($config,$before)
      Reject-DNS {Patch-SingBox $config '203.0.113.10'} ('layered Home accepted '+$case+' tunnel owner') 'owned tunnel outbound'
      Assert-DNS ([IO.File]::ReadAllText($config) -ceq $before) 'invalid Home config replaced previous file'
    }
    # Execute the real readiness function. Only administrator, executable and
    # firewall boundaries are harmless doubles; no tunnel is opened here.
    function Test-Administrator{return $true}
    function Invoke-KillSwitch{}
    $Source=$root;$Mode='hysteria2';$NeedsXray=@();$SingBox=Join-Path $root 'sing-box-fixture.ps1'
    [IO.File]::WriteAllText($SingBox,'$global:LASTEXITCODE=0')
    $node=New-Node;$node.dns_host='10.77.0.2';Save-Node $node
    Reject-DNS {Assert-Ready} 'layered readiness skipped Home validation' 'does not belong'
  }else{
    foreach($name in @('New-DnsOwner','Start-DnsProxy')){
      $found=@($functions | Where-Object {$_.Name -ceq $name});Assert-DNS ($found.Count -eq 1) ('shipping function missing '+$name)
      . ([scriptblock]::Create($found[0].Extent.Text))
    }
    # Execute the actual proxy launcher and hint writer. Process creation and
    # its process-record boundary are doubled; arguments and files are real.
    function Find-DnsProxy{return 'owned-dns-proxy.exe'}
    function Start-Process{param($FilePath,$ArgumentList,$WorkingDirectory,[switch]$PassThru,$WindowStyle);$script:ProxyCall=@{file=$FilePath;arguments=$ArgumentList;directory=$WorkingDirectory};return [pscustomobject]@{HasExited=$false;ExitCode=0}}
    function Write-RouterVPNProcessRecord($Path,$Process){$script:ProxyRecord=$Path}
    function Start-Sleep{param($Milliseconds)}
    $runDir=Join-Path $root 'run';[void][IO.Directory]::CreateDirectory($runDir)
    $dnsOwnerFile=Join-Path $runDir 'dns.owner';$dnsProcessFile=Join-Path $runDir 'dns.process.json';$dnsHint=Join-Path $runDir 'dns.txt'
    foreach($protocol in @('udp','tcp','tls','https','h3')){
      $node=New-Node;$node.dns_protocol=$protocol;$node.dns_port=5443;$node.dns_host='fd77::1';Save-Node $node
      $dns=Get-DnsSelection;Start-DnsProxy $dns
      $args=$script:ProxyCall.arguments
      Assert-DNS ($script:ProxyCall.file -ceq 'owned-dns-proxy.exe' -and $script:ProxyCall.directory -ceq $runDir -and $script:ProxyRecord -ceq $dnsProcessFile) 'raw DNS proxy lost captured process boundary'
      Assert-DNS ($args[3] -ceq $protocol -and $args[5] -ceq 'fd77::1' -and $args[7] -ceq '5443') 'raw proxy arguments changed Home transport'
      if($protocol -in @('tls','https','h3')){Assert-DNS ($args[8] -ceq '-server-name' -and $args[9] -ceq $node.dns_server_name) 'raw proxy arguments lost Home TLS identity'}
      if($protocol -in @('https','h3')){Assert-DNS ($args[10] -ceq '-path' -and $args[11] -ceq '/private-dns') 'raw proxy arguments lost Home HTTPS path'}
      $hint=@{};foreach($line in [IO.File]::ReadAllLines($dnsHint)){$separator=$line.IndexOf('=');if($separator -ge 0){$hint[$line.Substring(0,$separator)]=$line.Substring($separator+1)}}
      Assert-DNS ($hint.owner -ceq $script:dnsOwnerToken -and $hint.owner -ceq ([IO.File]::ReadAllText($dnsOwnerFile)).Trim()) 'raw DNS hint lost captured owner'
      Assert-DNS ($hint.mode -ceq 'home' -and $hint.protocol -ceq $protocol -and $hint.server -ceq '[fd77::1]:5443') 'raw DNS hint changed Home transport'
      Assert-DNS ($hint.server_name -ceq $dns.server_name -and $hint.path -ceq $dns.path) 'raw DNS hint lost TLS or HTTPS proof fields'
    }
  }
  Write-Host ('Executed shipping '+$Kind+' Home DNS selection and runtime preparation')
}
try{
  Invoke-HomeDNSCases 'layered' $LayeredSource
  Invoke-HomeDNSCases 'wireguard' $WireGuardSource
  Write-Host ('Windows Home DNS: '+$Checks+' executable checks passed')
}finally{
  foreach($name in $EnvNames){[Environment]::SetEnvironmentVariable($name,$SavedEnv[$name],'Process')}
  Remove-Item -LiteralPath $TaskRoot -Recurse -Force -ErrorAction SilentlyContinue
}
