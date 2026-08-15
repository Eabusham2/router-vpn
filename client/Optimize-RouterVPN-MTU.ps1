param(
  [ValidateSet('optimize','self-test')][string]$Action = 'optimize'
)

$ErrorActionPreference = 'Stop'
$MinMtu = 1200
$MaxMtu = 1500
$Step = 20
$MaxCandidates = 16
$RttSamples = 6
$BurstPackets = 32
$BurstRounds = 3
$SocketTimeoutMs = 750
$ProofKind = 'router-vpn-private-agent-v1'

function Has-Property($Object,[string]$Name) { return $null -ne $Object -and ($Object.PSObject.Properties.Name -contains $Name) }
function Hash-Text([string]$Label,[string]$Text) {
  $sha=[Security.Cryptography.SHA256]::Create()
  try{$bytes=$sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Label+[char]0+$Text));return (-join($bytes|ForEach-Object{$_.ToString('x2')})).Substring(0,24)}finally{$sha.Dispose()}
}
function Require-Admin {
  $id=[Security.Principal.WindowsIdentity]::GetCurrent();$p=New-Object Security.Principal.WindowsPrincipal($id)
  if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Optimize MTU requires Administrator rights to change the live tunnel interface.'}
}
function Root-Path {
  $r=[string]$env:HOMEVPN_ROOT
  if([string]::IsNullOrWhiteSpace($r)){throw 'HOMEVPN_ROOT is required.'}
  return [IO.Path]::GetFullPath($r)
}
function Read-Store {
  $path=Join-Path (Root-Path) 'routers.json'
  if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Router profile store is missing: $path"}
  $store=Get-Content -Raw -LiteralPath $path|ConvertFrom-Json
  $selected=if($env:HOMEVPN_PROFILE_ID){[string]$env:HOMEVPN_PROFILE_ID}elseif(Has-Property $store 'selected_id'){[string]$store.selected_id}else{''}
  $profile=$null
  foreach($item in @($store.profiles)){if($item-and[string]$item.id-eq$selected){$profile=$item;break}}
  if(-not$profile){foreach($item in @($store.profiles)){if($item){$profile=$item;break}}}
  if(-not$profile){throw 'Router VPN has no selected node profile.'}
  [pscustomobject]@{Path=$path;Store=$store;Profile=$profile}
}
function Private-IP([string]$Value){
  $ip=$null
  if(-not[Net.IPAddress]::TryParse($Value.Trim().Trim('[',']'),[ref]$ip)){throw 'MTU optimizer requires a literal private tunnel address.'}
  $b=$ip.GetAddressBytes();$ok=$false
  if($ip.AddressFamily-eq[Net.Sockets.AddressFamily]::InterNetwork){$ok=($b[0]-eq10)-or($b[0]-eq127)-or($b[0]-eq169-and$b[1]-eq254)-or($b[0]-eq172-and$b[1]-ge16-and$b[1]-le31)-or($b[0]-eq192-and$b[1]-eq168)}
  else{$ok=$ip.IsIPv6LinkLocal-or$ip.Equals([Net.IPAddress]::IPv6Loopback)-or(($b[0]-band0xfe)-eq0xfc)}
  if(-not$ok){throw 'MTU optimizer refuses a public benchmark destination.'}
  return $ip
}
function Get-Json-NoProxy([Uri]$Uri){
  $req=[Net.HttpWebRequest]::Create($Uri);$req.Method='GET';$req.Proxy=$null;$req.Timeout=3000;$req.ReadWriteTimeout=3000;$req.CachePolicy=New-Object Net.Cache.RequestCachePolicy([Net.Cache.RequestCacheLevel]::NoCacheNoStore)
  $resp=$req.GetResponse();try{$reader=New-Object IO.StreamReader($resp.GetResponseStream());$text=$reader.ReadToEnd();if($text.Length-gt16384){throw'Path proof response exceeded limit'};return $text|ConvertFrom-Json}finally{$resp.Close()}
}
function Prove-Node($Profile){
  $expected=if(Has-Property $Profile 'node_proof_id'){[string]$Profile.node_proof_id}else{''}
  if($expected-notmatch'^[0-9a-f]{64}$'){throw 'Selected node has no valid exact proof id.'}
  $raw=if((Has-Property $Profile 'path_probe_url')-and$Profile.path_probe_url){[string]$Profile.path_probe_url}else{'http://10.77.0.1:8787/health'}
  $uri=[Uri]$raw;if($uri.Scheme-ne'http'-or$uri.UserInfo-or$uri.Fragment-or$uri.AbsolutePath-notin@('/','/health')){throw 'MTU optimizer proof URL must be private literal HTTP /health.'}
  [void](Private-IP $uri.Host)
  $body=Get-Json-NoProxy $uri
  if(-not$body-or$body.ok-ne$true-or[string]$body.node_id-ne$expected-or[string]$body.proof-ne$ProofKind){throw 'Selected-node identity changed or proof failed during MTU optimization.'}
}
function Route-Alias([string]$Target){
  if($env:HOMEVPN_TUN_ALIAS){return [string]$env:HOMEVPN_TUN_ALIAS}
  $route=Find-NetRoute -RemoteIPAddress $Target|Sort-Object RouteMetric,InterfaceMetric|Select-Object -First 1
  if(-not$route-or-not$route.InterfaceAlias){throw 'Could not identify the active Router VPN tunnel interface.'}
  return [string]$route.InterfaceAlias
}
function Address-Family($Ip){if($Ip.AddressFamily-eq[Net.Sockets.AddressFamily]::InterNetworkV6){return 'IPv6'};return 'IPv4'}
function Read-Mtu([string]$Alias,[string]$Family){
  $x=Get-NetIPInterface -InterfaceAlias $Alias -AddressFamily $Family|Sort-Object InterfaceMetric|Select-Object -First 1
  if(-not$x-or[int]$x.NlMtuBytes-lt576){throw 'Could not read current tunnel MTU.'};return [int]$x.NlMtuBytes
}
function Set-Mtu([string]$Alias,[string]$Family,[int]$Mtu){
  if($Mtu-lt$MinMtu-or$Mtu-gt9000){throw"Refusing invalid live MTU $Mtu"}
  Set-NetIPInterface -InterfaceAlias $Alias -AddressFamily $Family -NlMtuBytes $Mtu -ErrorAction Stop
}
function Candidate-Mtus([int]$Ceiling){
  $ceiling=[Math]::Max($MinMtu,[Math]::Min($MaxMtu,$Ceiling));$floor=[Math]::Max($MinMtu,$ceiling-$Step*($MaxCandidates-1));$set=New-Object 'System.Collections.Generic.HashSet[int]'
  for($m=$floor;$m-le$ceiling;$m+=$Step){[void]$set.Add($m)}
  foreach($m in @(1280,1320,1360,1380,1400,1420,1440,1460,1480,1500)){if($m-ge$floor-and$m-le$ceiling){[void]$set.Add($m)}}
  return @($set|Sort-Object -Descending|Select-Object -First $MaxCandidates)
}
function Median([double[]]$Values){if(-not$Values-or$Values.Count-eq0){return 0.0};$s=@($Values|Sort-Object);$n=$s.Count;if($n%2){return [double]$s[[int]($n/2)]};return ([double]$s[$n/2-1]+[double]$s[$n/2])/2.0}
function Bench-Candidate($Ip,[int]$Port,[int]$Mtu){
  if($env:HOMEVPN_MTU_BENCH_FAKE){$table=$env:HOMEVPN_MTU_BENCH_FAKE|ConvertFrom-Json;$row=$table.PSObject.Properties[[string]$Mtu].Value;if(-not$row){return [pscustomobject]@{mtu=$Mtu;working=$false;success_ratio=0.0;mbps=0.0;median_rtt_ms=9999.0}};return [pscustomobject]@{mtu=$Mtu;working=if(Has-Property $row 'working'){[bool]$row.working}else{$true};success_ratio=[double]$row.success_ratio;mbps=[double]$row.mbps;median_rtt_ms=[double]$row.median_rtt_ms}}
  $family=$Ip.AddressFamily;$overhead=if($family-eq[Net.Sockets.AddressFamily]::InterNetworkV6){48}else{28};$size=[Math]::Max(64,$Mtu-$overhead);$payload=New-Object byte[] $size;[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($payload)
  $udp=New-Object Net.Sockets.UdpClient($family);$udp.Client.ReceiveTimeout=$SocketTimeoutMs;$udp.Connect($Ip,$Port);$rtts=New-Object 'System.Collections.Generic.List[double]';$rates=New-Object 'System.Collections.Generic.List[double]';$sent=0;$replies=0
  try{
    for($i=0;$i-lt$RttSamples;$i++){try{$sw=[Diagnostics.Stopwatch]::StartNew();[void]$udp.Send($payload,$payload.Length);$sent++;$remote=New-Object Net.IPEndPoint([Net.IPAddress]::Any,0);if($family-eq[Net.Sockets.AddressFamily]::InterNetworkV6){$remote=New-Object Net.IPEndPoint([Net.IPAddress]::IPv6Any,0)};$data=$udp.Receive([ref]$remote);$sw.Stop();if($data.Length-gt0){$replies++;$rtts.Add($sw.Elapsed.TotalMilliseconds)}}catch{}}
    for($round=0;$round-lt$BurstRounds;$round++){$sw=[Diagnostics.Stopwatch]::StartNew();$roundSent=0;$roundReplies=0;$recvBytes=0;for($i=0;$i-lt$BurstPackets;$i++){try{[void]$udp.Send($payload,$payload.Length);$roundSent++;$sent++}catch{break}};$deadline=[DateTime]::UtcNow.AddMilliseconds($SocketTimeoutMs);while($roundReplies-lt$roundSent-and[DateTime]::UtcNow-lt$deadline){try{$remote=New-Object Net.IPEndPoint([Net.IPAddress]::Any,0);if($family-eq[Net.Sockets.AddressFamily]::InterNetworkV6){$remote=New-Object Net.IPEndPoint([Net.IPAddress]::IPv6Any,0)};$data=$udp.Receive([ref]$remote);if($data.Length-gt0){$roundReplies++;$replies++;$recvBytes+=$data.Length}}catch{break}};$sw.Stop();if($roundSent-gt0){$bits=([double]($roundSent*$payload.Length+$recvBytes))*8.0;$rates.Add($bits/[Math]::Max(.001,$sw.Elapsed.TotalSeconds)/1000000.0)}}
  }finally{$udp.Close()}
  $ratio=if($sent){[double]$replies/$sent}else{0};$rtt=if($rtts.Count){Median $rtts.ToArray()}else{9999};$mbps=if($rates.Count){Median $rates.ToArray()}else{0};$working=$ratio-ge.90-and$rtts.Count-ge3-and$mbps-gt0
  [pscustomobject]@{mtu=$Mtu;working=$working;success_ratio=[Math]::Round($ratio,4);mbps=[Math]::Round($mbps,3);median_rtt_ms=[Math]::Round($rtt,3)}
}
function Pick-Winner($Results){
  $good=@($Results|Where-Object{$_.working-and[double]$_.success_ratio-ge.90});if(-not$good){throw'No MTU candidate passed the private tunnel benchmark.'};$fastest=($good|Measure-Object -Property mbps -Maximum).Maximum;$near=@($good|Where-Object{[double]$_.mbps-ge([double]$fastest*.97)});$bestRtt=($near|Measure-Object -Property median_rtt_ms -Minimum).Minimum;return $near|Where-Object{[double]$_.median_rtt_ms-le([double]$bestRtt+.25)}|Sort-Object mtu -Descending|Select-Object -First 1
}
function Resolve-EndpointIP([string]$Endpoint){
  $candidate=$null;if([Net.IPAddress]::TryParse($Endpoint.Trim().Trim('[',']'),[ref]$candidate)){return $candidate}
  try{return [Net.Dns]::GetHostAddresses($Endpoint)|Select-Object -First 1}catch{return $null}
}
function Get-NetworkFingerprint($Profile){
  if($env:HOMEVPN_NETWORK_CONTEXT){return Hash-Text 'network-override-v1' ([string]$env:HOMEVPN_NETWORK_CONTEXT)}
  $endpoint=([string]$Profile.endpoint).Trim();$ip=Resolve-EndpointIP $endpoint;$parts=New-Object 'System.Collections.Generic.List[string]';$parts.Add('v1');$parts.Add('windows')
  if($ip){
    $parts.Add('family='+$(if($ip.AddressFamily-eq[Net.Sockets.AddressFamily]::InterNetworkV6){'6'}else{'4'}))
    try{$route=Find-NetRoute -RemoteIPAddress $ip.IPAddressToString|Sort-Object RouteMetric,InterfaceMetric|Select-Object -First 1;if($route){$parts.Add('if='+[string]$route.InterfaceAlias);$parts.Add('index='+[string]$route.InterfaceIndex);$parts.Add('next='+[string]$route.NextHop);$fam=if($ip.AddressFamily-eq[Net.Sockets.AddressFamily]::InterNetworkV6){'IPv6'}else{'IPv4'};$local=Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily $fam -ErrorAction SilentlyContinue|Where-Object{$_.IPAddress-notmatch'^(169\.254\.|fe80:)'}|Select-Object -First 1;if($local){$parts.Add('source='+[string]$local.IPAddress)}}}catch{$parts.Add('route=unavailable')}
  }else{$parts.Add('endpoint-resolution=failed')}
  return Hash-Text 'network-route-v1' ([string]::Join('|',$parts))
}
function Get-GeneratedProfileFingerprint($Profile){
  $id=if(Has-Property $Profile 'id'){([string]$Profile.id).Trim()}else{([string]$env:HOMEVPN_PROFILE_ID).Trim()};$mode=([string]$env:HOMEVPN_MODE).Trim();$root=[string]$env:HOMEVPN_ROOT
  if([string]::IsNullOrWhiteSpace($root)-or[string]::IsNullOrWhiteSpace($mode)){return Hash-Text 'generated-profile-v1' ('missing|'+$id+'|'+$mode)}
  $candidates=@();if($id){$candidates+=Join-Path (Join-Path (Join-Path $root 'generated') $id) $mode};$candidates+=Join-Path (Join-Path $root 'generated') $mode;$dir=$null;foreach($candidate in $candidates){if(Test-Path -LiteralPath $candidate -PathType Container){$dir=Get-Item -LiteralPath $candidate;break}}
  if(-not$dir){return Hash-Text 'generated-profile-v1' ('missing|'+$id+'|'+$mode)}
  $files=@(Get-ChildItem -LiteralPath $dir.FullName -File -Recurse|Sort-Object FullName);if($files.Count-gt128){throw'Generated MTU path profile has too many files.'};$total=[int64]0;$parts=New-Object 'System.Collections.Generic.List[string]'
  foreach($file in $files){if($file.Length-gt4MB){throw'Generated MTU path profile file exceeds safety limit.'};$total+=$file.Length;if($total-gt16MB){throw'Generated MTU path profile exceeds safety limit.'};$rel=$file.FullName.Substring($dir.FullName.Length).TrimStart([char]'\',[char]'/');$hash=(Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant();$parts.Add($rel+'='+$hash)}
  return Hash-Text 'generated-profile-v1' ([string]::Join('|',$parts))
}
function Path-Context($Profile){
  $endpoint=([string]$Profile.endpoint).Trim().ToLowerInvariant();$mode=([string]$env:HOMEVPN_MODE).Trim().ToLowerInvariant();$logical=([string]$env:HOMEVPN_LOGICAL_MODE).Trim().ToLowerInvariant();$base=([string]$env:HOMEVPN_BASE).Trim().ToLowerInvariant();$family=([string]$env:HOMEVPN_IP_FAMILY).Trim().ToLowerInvariant();$id=if(Has-Property $Profile 'id'){([string]$Profile.id).Trim().ToLowerInvariant()}else{([string]$env:HOMEVPN_PROFILE_ID).Trim().ToLowerInvariant()};if(-not$family){$ip=Resolve-EndpointIP $endpoint;if($ip){$family=if($ip.AddressFamily-eq[Net.Sockets.AddressFamily]::InterNetworkV6){'6'}else{'4'}}else{$family='unknown'}};$network=Get-NetworkFingerprint $Profile;$generated=Get-GeneratedProfileFingerprint $Profile;$raw=[string]::Join('|',@($endpoint,$mode,$logical,$base,$family,$id,$network,$generated));[pscustomobject]@{Key=(Hash-Text 'mtu-path-v2' $raw);Network=$network;Generated=$generated}
}
function Path-Key($Profile){return (Path-Context $Profile).Key}
function Persist-Winner($Ctx,$Winner,$Results){
  $p=$Ctx.Profile;$path=Path-Context $p;$p|Add-Member effective_mtu ([int]$Winner.mtu) -Force;$p|Add-Member effective_mtu_source 'auto-throughput' -Force;$p|Add-Member effective_mtu_path_key $path.Key -Force;$p|Add-Member effective_mtu_network_fingerprint $path.Network -Force;$p|Add-Member effective_mtu_profile_fingerprint $path.Generated -Force;$p|Add-Member effective_mtu_tested_at ([DateTime]::UtcNow.ToString('o')) -Force;$p|Add-Member effective_mtu_mbps ([double]$Winner.mbps) -Force;$p|Add-Member effective_mtu_median_rtt_ms ([double]$Winner.median_rtt_ms) -Force;$p|Add-Member effective_mtu_success_ratio ([double]$Winner.success_ratio) -Force;$p|Add-Member effective_mtu_candidates @($Results) -Force
  $tmp=$Ctx.Path+'.mtu.tmp';[IO.File]::WriteAllText($tmp,(($Ctx.Store|ConvertTo-Json -Depth 100)+"`n"),(New-Object Text.UTF8Encoding($false)));Move-Item -LiteralPath $tmp -Destination $Ctx.Path -Force
}
function Ensure-KillSwitch($Profile,[string]$Alias){
  $policy=if(Has-Property $Profile 'kill_switch_policy'){([string]$Profile.kill_switch_policy).ToLowerInvariant()}else{'off'}
  if($policy-eq'off'){return}
  $helper=Join-Path $PSScriptRoot 'windows-kill-switch.ps1';if(-not(Test-Path -LiteralPath $helper)){throw'Windows kill-switch helper is missing.'}
  & $helper -Action prepare -Root (Root-Path) -TunnelAlias $Alias;if($LASTEXITCODE-ne0){throw'Windows kill switch could not be enforced before MTU optimization.'}
}

if($Action-eq'self-test'){
  $sample=@([pscustomobject]@{mtu=1380;working=$true;success_ratio=1.0;mbps=100.0;median_rtt_ms=10.0},[pscustomobject]@{mtu=1360;working=$true;success_ratio=1.0;mbps=102.0;median_rtt_ms=9.9},[pscustomobject]@{mtu=1340;working=$false;success_ratio=.5;mbps=130.0;median_rtt_ms=8.0});if((Pick-Winner $sample).mtu-ne1380){throw'Winner tie policy self-test failed'};if((Candidate-Mtus 1380)[0]-ne1380){throw'Candidate ceiling self-test failed'}
  $profile=[pscustomobject]@{id='node';endpoint='203.0.113.10'};$old=[string]$env:HOMEVPN_NETWORK_CONTEXT;try{$env:HOMEVPN_NETWORK_CONTEXT='wifi-a';$first=Path-Key $profile;$env:HOMEVPN_NETWORK_CONTEXT='cellular-b';$second=Path-Key $profile;if($first-eq$second){throw'Network-change path-key self-test failed'}}finally{$env:HOMEVPN_NETWORK_CONTEXT=$old};Write-Output'MTU throughput optimizer Windows self-test OK';exit 0
}

Require-Admin;$ctx=Read-Store;$profile=$ctx.Profile;$policy=if(Has-Property $profile 'mtu_policy'){([string]$profile.mtu_policy).ToLowerInvariant()}else{'default'};if($policy-ne'auto'-and$env:HOMEVPN_MTU_OPTIMIZE_FORCE-notin@('1','true','yes')){throw'Set this node MTU policy to Auto before running Optimize MTU.'};if($env:HOMEVPN_JUMBO-eq'true'){throw'Jumbo is explicit; disable Jumbo before automatic MTU optimization.'}
Prove-Node $profile;$target=if((Has-Property $profile 'daita_host')-and$profile.daita_host){[string]$profile.daita_host}else{'10.77.0.1'};$ip=Private-IP $target;$port=if((Has-Property $profile 'daita_port')-and[int]$profile.daita_port-gt0){[int]$profile.daita_port}else{45999};$alias=Route-Alias $target;$family=Address-Family $ip;$original=Read-Mtu $alias $family;Ensure-KillSwitch $profile $alias;$ceiling=if((Has-Property $profile 'effective_mtu')-and[int]$profile.effective_mtu-ge$MinMtu){[int]$profile.effective_mtu}else{[Math]::Min($MaxMtu,$original)};$results=New-Object System.Collections.ArrayList;$winner=$null
try{foreach($mtu in @(Candidate-Mtus $ceiling)){Set-Mtu $alias $family $mtu;Start-Sleep -Milliseconds 120;Prove-Node $profile;[void]$results.Add((Bench-Candidate $ip $port $mtu))};$winner=Pick-Winner @($results);Set-Mtu $alias $family ([int]$winner.mtu);Prove-Node $profile;Persist-Winner $ctx $winner @($results);[pscustomobject]@{ok=$true;interface=$alias;original_mtu=$original;winner=$winner;results=@($results)}|ConvertTo-Json -Depth 20}catch{try{Set-Mtu $alias $family $original}catch{};throw}
