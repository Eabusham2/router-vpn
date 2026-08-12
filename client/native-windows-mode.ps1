param(
  [Parameter(Mandatory=$true)][string]$Mode,
  [Parameter(Mandatory=$true)][ValidateSet('check','up','down','status')][string]$Action
)

$ErrorActionPreference = 'Stop'
$Supported = @('hysteria2','shadowsocks','naive-h2','naive-h3','reality-vision','reality-pq-vision','split','max')
$NeedsXray = @('reality-vision','reality-pq-vision','split','max')
if ($Supported -notcontains $Mode) { throw "No native Windows adapter is implemented for mode '$Mode'." }

function Test-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Has-Property($Object,[string]$Name) { return $null -ne $Object -and ($Object.PSObject.Properties.Name -contains $Name) }
function Safe-ProfileId([string]$Value) {
  if ([string]::IsNullOrWhiteSpace($Value)) { return 'router' }
  if ($Value -notmatch '^[A-Za-z0-9_.-]{1,128}$') { throw 'Invalid Router VPN profile id.' }
  return $Value
}
function Safe-Under([string]$Parent,[string]$Child) {
  $p=[IO.Path]::GetFullPath($Parent).TrimEnd('\')+'\';$c=[IO.Path]::GetFullPath($Child)
  if (-not $c.StartsWith($p,[StringComparison]::OrdinalIgnoreCase)) { throw "Refusing unsafe path outside $Parent" }
  return $c
}
function Write-Utf8NoBom([string]$Path,[string]$Text) { [IO.File]::WriteAllText($Path,$Text,(New-Object Text.UTF8Encoding($false))) }
function Stop-PidFile([string]$PidFile) {
  if (-not (Test-Path -LiteralPath $PidFile -PathType Leaf)) { return }
  foreach ($line in Get-Content -LiteralPath $PidFile -ErrorAction SilentlyContinue) {
    $pidValue=0
    if ([int]::TryParse(([string]$line).Trim(),[ref]$pidValue) -and $pidValue -gt 0) { Stop-Process -Id $pidValue -Force -ErrorAction SilentlyContinue }
  }
  Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
}

$RootText=[string]$env:HOMEVPN_ROOT;if([string]::IsNullOrWhiteSpace($RootText)){throw 'HOMEVPN_ROOT is required.'}
$Root=[IO.Path]::GetFullPath($RootText);$ProfileId=Safe-ProfileId([string]$env:HOMEVPN_PROFILE_ID)
$GeneratedRoot=Safe-Under $Root (Join-Path $Root 'generated')
$Source=Safe-Under $GeneratedRoot (Join-Path $GeneratedRoot (Join-Path $ProfileId $Mode))
if(-not(Test-Path -LiteralPath $Source -PathType Container)){$legacy=Safe-Under $GeneratedRoot (Join-Path $GeneratedRoot $Mode);if(Test-Path -LiteralPath $legacy -PathType Container){$Source=$legacy}}
$Runtime=Safe-Under $Root (Join-Path $Root 'runtime\windows');$SingBox=Join-Path $Runtime 'sing-box.exe';$Xray=Join-Path $Runtime 'xray.exe'
$RunBase=Safe-Under $Root (Join-Path $Root 'run\windows');$RunDir=Safe-Under $RunBase (Join-Path $RunBase (Join-Path $ProfileId $Mode))
$PidFile=Join-Path $RunDir 'children.pids';$SingConfig=Join-Path $RunDir 'sing-box.json';$XrayConfig=Join-Path $RunDir 'xray.json'
$KillSwitch=Join-Path $PSScriptRoot 'windows-kill-switch.ps1'

function Invoke-KillSwitch([string]$KillAction,[string]$EndpointValue='',[string]$Alias='') {
  if (-not (Test-Path -LiteralPath $KillSwitch -PathType Leaf)) { throw "Windows kill-switch helper is missing: $KillSwitch" }
  $args=@('-Action',$KillAction,'-Root',$Root)
  if ($EndpointValue) { $args += @('-Endpoint',$EndpointValue) }
  if ($Alias) { $args += @('-TunnelAlias',$Alias) }
  & $KillSwitch @args
  if ($LASTEXITCODE -ne 0) { throw "Windows kill-switch action '$KillAction' failed." }
}
function Get-TunAlias([string]$ConfigPath) {
  if ($env:HOMEVPN_SOCKS -eq 'true') { return '' }
  try {
    $cfg=Get-Content -Raw -LiteralPath $ConfigPath|ConvertFrom-Json
    foreach($inbound in @($cfg.inbounds)) {
      if($inbound -and (Has-Property $inbound 'type') -and $inbound.type -eq 'tun' -and (Has-Property $inbound 'interface_name')) { return [string]$inbound.interface_name }
    }
  } catch { }
  return ''
}

function Assert-Ready {
  if(-not(Test-Administrator)){throw 'Native Windows TUN modes require an elevated Router VPN process.'}
  if(-not(Test-Path -LiteralPath $Source -PathType Container)){throw "Missing generated profile directory: $Source"}
  if(-not(Test-Path -LiteralPath (Join-Path $Source 'sing-box.json') -PathType Leaf)){throw "Missing sing-box.json for $Mode"}
  if(-not(Test-Path -LiteralPath $SingBox -PathType Leaf)){throw 'sing-box.exe is missing. Run Setup-Windows-Runtime.ps1.'}
  if(($NeedsXray -contains $Mode)-and -not(Test-Path -LiteralPath (Join-Path $Source 'xray.json') -PathType Leaf)){throw "Missing xray.json for $Mode"}
  if(($NeedsXray -contains $Mode)-and -not(Test-Path -LiteralPath $Xray -PathType Leaf)){throw 'xray.exe is missing. Run Setup-Windows-Runtime.ps1.'}
  & $SingBox check -D $Source -c (Join-Path $Source 'sing-box.json') | Out-Null;if($LASTEXITCODE-ne 0){throw "sing-box rejected the generated $Mode profile."}
  if($NeedsXray -contains $Mode){& $Xray run -test -c (Join-Path $Source 'xray.json')|Out-Null;if($LASTEXITCODE-ne 0){throw "Xray rejected the generated $Mode profile."}}
  Invoke-KillSwitch 'check'
}
function Patch-JsonRecursive($Node,[string]$Endpoint,[string]$BaseDir) {
  if($null-eq$Node){return};if($Node-is[System.Array]){foreach($item in $Node){Patch-JsonRecursive $item $Endpoint $BaseDir};return};if($Node-isnot[PSCustomObject]){return}
  foreach($property in @($Node.PSObject.Properties)){$name=$property.Name;$value=$property.Value;if(($name-eq'endpoint'-or$name-eq'remote_address')-and$value-is[string]){$property.Value=$Endpoint}elseif(($name-eq'certificate_path'-or$name-eq'key_path')-and$value-is[string]-and-not[IO.Path]::IsPathRooted($value)){$property.Value=Join-Path $BaseDir $value}else{Patch-JsonRecursive $value $Endpoint $BaseDir}}
  if(Has-Property $Node 'outbounds'){foreach($outbound in @($Node.outbounds)){if($null-eq$outbound){continue};if((Has-Property $outbound 'tag')-and$outbound.tag-in@('proxy','outer','transport')-and(Has-Property $outbound 'server')){$outbound.server=$Endpoint};if(Has-Property $outbound 'settings'){$settings=$outbound.settings;if($settings-and(Has-Property $settings 'vnext')){foreach($vnext in @($settings.vnext)){if($vnext-and(Has-Property $vnext 'address')){$vnext.address=$Endpoint}}}}}}
}
function Get-SelectedProfile {
  $storePath=Join-Path $Root 'routers.json';if(-not(Test-Path -LiteralPath $storePath -PathType Leaf)){return $null}
  try{$store=Get-Content -Raw -LiteralPath $storePath|ConvertFrom-Json}catch{return $null}
  $selected=if($env:HOMEVPN_PROFILE_ID){[string]$env:HOMEVPN_PROFILE_ID}elseif(Has-Property $store 'selected_id'){[string]$store.selected_id}else{''}
  foreach($p in @($store.profiles)){if($p-and[string]$p.id-eq$selected){return $p}};foreach($p in @($store.profiles)){if($p){return $p}};return $null
}
function Profile-String($Profile,[string]$Name,[string]$Default=''){if($Profile-and(Has-Property $Profile $Name)){$v=[string]$Profile.$Name;if(-not[string]::IsNullOrWhiteSpace($v)){return $v}};return $Default}
function Profile-Int($Profile,[string]$Name,[int]$Default=0){if($Profile-and(Has-Property $Profile $Name)){$n=0;if([int]::TryParse(([string]$Profile.$Name),[ref]$n)-and$n-gt 0){return $n}};return $Default}
function Infer-DnsServerName([string]$Host,[string]$Explicit=''){
  if(-not[string]::IsNullOrWhiteSpace($Explicit)){return $Explicit}
  switch($Host.Trim('[]')){'1.1.1.1'{return'cloudflare-dns.com'}'1.0.0.1'{return'cloudflare-dns.com'}'2606:4700:4700::1111'{return'cloudflare-dns.com'}'2606:4700:4700::1001'{return'cloudflare-dns.com'}'8.8.8.8'{return'dns.google'}'8.8.4.4'{return'dns.google'}'2001:4860:4860::8888'{return'dns.google'}'2001:4860:4860::8844'{return'dns.google'}'9.9.9.9'{return'dns.quad9.net'}'149.112.112.112'{return'dns.quad9.net'}'2620:fe::fe'{return'dns.quad9.net'}}
  if($Host-match'[A-Za-z]'-and$Host-notmatch':'){return $Host};return''
}
function Get-DnsSelection {
  $p=Get-SelectedProfile;$mode=(Profile-String $p 'dns_mode' 'fastest').ToLowerInvariant();$fastest=Profile-String $p 'fastest_dns_host' '1.1.1.1';$protocol=(Profile-String $p 'dns_protocol' 'udp').ToLowerInvariant();$host=Profile-String $p 'dns_host' $fastest;$port=Profile-Int $p 'dns_port' 0;$serverName=Profile-String $p 'dns_server_name' '';$path=Profile-String $p 'dns_path' '/dns-query'
  if($env:HOMEVPN_DNS_MODE){$mode=$env:HOMEVPN_DNS_MODE.ToLowerInvariant()};if($env:HOMEVPN_DNS_PROTOCOL){$protocol=$env:HOMEVPN_DNS_PROTOCOL.ToLowerInvariant()};if($env:HOMEVPN_DNS_HOST){$host=$env:HOMEVPN_DNS_HOST};if($env:HOMEVPN_DNS_PORT-match'^\d+$'){$port=[int]$env:HOMEVPN_DNS_PORT};if($env:HOMEVPN_DNS_SERVER_NAME){$serverName=$env:HOMEVPN_DNS_SERVER_NAME};if($env:HOMEVPN_DNS_PATH){$path=$env:HOMEVPN_DNS_PATH}
  switch($mode){'home'{$host=if($env:HOMEVPN_ADGUARD4){$env:HOMEVPN_ADGUARD4}else{Profile-String $p 'adguard_ipv4' (Profile-String $p 'adguard_ipv6' '10.77.0.1')};$protocol='udp';$port=53;$serverName='';$path=''}'fastest'{$host=$fastest;$protocol='udp';$port=53;$serverName='';$path=''}'doh'{$protocol='https';if($port-le 0){$port=443}}'dot'{$protocol='tls';if($port-le 0){$port=853}}'doh3'{$protocol='h3';if($port-le 0){$port=443}}'rescue'{$protocol='rescue';if([string]::IsNullOrWhiteSpace($host)){$host=$fastest};if($port-le 0){$port=443}}default{if($protocol-eq'doh'){$protocol='https'}elseif($protocol-eq'dot'){$protocol='tls'}elseif($protocol-eq'doh3'){$protocol='h3'};if($port-le 0){if($protocol-in@('https','h3')){$port=443}elseif($protocol-eq'tls'){$port=853}else{$port=53}}}}
  $serverName=Infer-DnsServerName $host $serverName;if($protocol-eq'rescue'){$protocol='https';if([string]::IsNullOrWhiteSpace($serverName)){$host='1.1.1.1';$serverName='cloudflare-dns.com';$port=443;$path='/dns-query'}}
  if($protocol-notin@('udp','tcp','tls','https','h3')){throw "Unsupported DNS protocol: $protocol"};if($protocol-in@('tls','https','h3')-and[string]::IsNullOrWhiteSpace($serverName)){throw 'Encrypted DNS requires a TLS server name; enter one in DNS settings.'};if([string]::IsNullOrWhiteSpace($path)){$path='/dns-query'}
  return[pscustomobject]@{mode=$mode;protocol=$protocol;host=$host.Trim('[]');port=$port;server_name=$serverName;path=$path}
}
function Patch-SingBox([string]$Path,[string]$Endpoint){
  $cfg=Get-Content -Raw -LiteralPath $Path|ConvertFrom-Json;Patch-JsonRecursive $cfg $Endpoint (Split-Path -Parent $Path);$tags=@();foreach($outbound in @($cfg.outbounds)){if($outbound-and(Has-Property $outbound 'tag')){$tags+=[string]$outbound.tag}};$detour='direct';foreach($candidate in @('proxy','tcp-stack','ss-hop','outer')){if($tags-contains$candidate){$detour=$candidate;break}}
  $dns=Get-DnsSelection;$server=[ordered]@{type=$dns.protocol;tag='selected-dns';server=$dns.host;server_port=$dns.port;detour=$detour};if($dns.protocol-in@('tls','https','h3')){$server.tls=[ordered]@{enabled=$true;server_name=$dns.server_name};if($dns.protocol-in@('https','h3')){$server.path=$dns.path}}
  $cfg|Add-Member -NotePropertyName dns -NotePropertyValue([pscustomobject]@{servers=@([pscustomobject]$server);final='selected-dns'})-Force;if(-not(Has-Property $cfg 'route')-or$null-eq$cfg.route){$cfg|Add-Member -NotePropertyName route -NotePropertyValue([pscustomobject]@{})-Force};$rules=@();if(Has-Property $cfg.route 'rules'){$rules=@($cfg.route.rules)};$hasDns=$false;foreach($rule in $rules){if($rule-and(Has-Property $rule 'protocol')-and$rule.protocol-eq'dns'){$hasDns=$true}};if(-not$hasDns){$rules=@([pscustomobject]@{protocol='dns';action='hijack-dns'})+$rules};$cfg.route|Add-Member -NotePropertyName rules -NotePropertyValue $rules -Force
  if($env:HOMEVPN_SOCKS-eq'true'){$cfg.inbounds=@([pscustomobject]@{type='socks';tag='socks-in';listen='127.0.0.1';listen_port=1080;users=@()})}else{$mtu=0;if($env:HOMEVPN_JUMBO-eq'true'){$mtu=9000}elseif($env:HOMEVPN_MTU-match'^\d+$'){$mtu=[int]$env:HOMEVPN_MTU};if($mtu-gt 0){foreach($inbound in @($cfg.inbounds)){if($inbound-and(Has-Property $inbound 'type')-and$inbound.type-eq'tun'){$inbound.mtu=$mtu}}}}
  Write-Utf8NoBom $Path (($cfg|ConvertTo-Json -Depth 100)+"`n")
}
function Patch-Xray([string]$Path,[string]$Endpoint){$cfg=Get-Content -Raw -LiteralPath $Path|ConvertFrom-Json;Patch-JsonRecursive $cfg $Endpoint (Split-Path -Parent $Path);Write-Utf8NoBom $Path (($cfg|ConvertTo-Json -Depth 100)+"`n")}

switch($Action){
 'check'{Assert-Ready;Write-Output "native Windows $Mode ready";exit 0}
 'status'{if(-not(Test-Path -LiteralPath $PidFile -PathType Leaf)){Write-Output'down';exit 1};$alive=$false;foreach($line in Get-Content -LiteralPath $PidFile -ErrorAction SilentlyContinue){$p=0;if([int]::TryParse(([string]$line).Trim(),[ref]$p)-and(Get-Process -Id $p -ErrorAction SilentlyContinue)){$alive=$true}};if($alive){Write-Output'up';exit 0};Write-Output'down';exit 1}
 'down'{Stop-PidFile $PidFile;try{Invoke-KillSwitch 'release'}catch{Write-Warning $_.Exception.Message};exit 0}
 'up'{
  Assert-Ready;$Endpoint=[string]$env:HOMEVPN_ENDPOINT;if([string]::IsNullOrWhiteSpace($Endpoint)){throw 'Choose a router backend in the app first.'};$Endpoint=$Endpoint.Trim().Trim('[]');Stop-PidFile $PidFile;if(Test-Path -LiteralPath $RunDir){Remove-Item -LiteralPath $RunDir -Recurse -Force};New-Item -ItemType Directory -Force -Path $RunDir|Out-Null;Copy-Item -Path(Join-Path $Source '*')-Destination $RunDir -Recurse -Force;Patch-SingBox $SingConfig $Endpoint;if($NeedsXray-contains$Mode){Patch-Xray $XrayConfig $Endpoint};&$SingBox check -D $RunDir -c $SingConfig|Out-Null;if($LASTEXITCODE-ne 0){throw 'Patched native Windows sing-box config failed validation.'}
  $tunAlias=Get-TunAlias $SingConfig
  Invoke-KillSwitch 'prepare' $Endpoint $tunAlias
  $childPids=New-Object System.Collections.Generic.List[int]
  try{if($NeedsXray-contains$Mode){&$Xray run -test -c $XrayConfig|Out-Null;if($LASTEXITCODE-ne 0){throw 'Patched native Windows Xray config failed validation.'};$quotedConfig='"'+$XrayConfig+'"';$xp=Start-Process -FilePath $Xray -ArgumentList @('run','-c',$quotedConfig)-WorkingDirectory $RunDir -PassThru -WindowStyle Hidden;$childPids.Add($xp.Id);Start-Sleep -Milliseconds 350;if($xp.HasExited){throw 'Xray exited during native Windows startup.'}};$childPids|Set-Content -Encoding ASCII -LiteralPath $PidFile;&$SingBox run -D $RunDir -c $SingConfig;$exitCode=$LASTEXITCODE;if($exitCode-ne 0){throw "sing-box exited with code $exitCode"}}finally{Stop-PidFile $PidFile;try{Invoke-KillSwitch 'release'}catch{Write-Warning $_.Exception.Message}}
 }
}
