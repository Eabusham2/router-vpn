param(
  [Parameter(Mandatory=$true)][ValidateSet('check','up','down')][string]$Action,
  [Parameter(Mandatory=$true)][string]$RuntimeDir,
  [Parameter(Mandatory=$true)][AllowEmptyString()][string]$BridgeEndpoint,
  [Parameter(Mandatory=$true)][ValidateRange(1024,65535)][int]$SocksPort,
  [string]$TorBinary='',
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
if([string]$env:HOMEVPN_PROFILE_ID -cnotmatch '^[A-Za-z0-9_-]{1,64}$' -or [string]$env:HOMEVPN_POLICY_PROFILE_ID -cnotmatch '^[A-Za-z0-9_-]{1,64}$'){throw 'Tor requires both captured physical and policy profile IDs.'}
foreach($name in @('HOMEVPN_TOR_SOURCE_SHA256','HOMEVPN_TOR_PROFILE_SHA256','HOMEVPN_TOR_CAPTURE_SHA256','HOMEVPN_TOR_TORRC_SHA256','HOMEVPN_TOR_DEFAULTS_SHA256','HOMEVPN_TOR_CONFIG_SHA256')){
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
function Get-RouterVPNTorCaptureIdentity {
  param(
    [string]$RuntimeDir,[string]$Session,[string]$TorBinary,[string]$BridgeEndpoint,
    [System.Collections.IDictionary]$CapturedEnvironment
  )
  if($null -eq $CapturedEnvironment -or $Session -cnotmatch '^[a-f0-9]{32}$' -or
     [string]$CapturedEnvironment['HOMEVPN_TOR_SESSION'] -cne $Session -or
     [string]$CapturedEnvironment['HOMEVPN_STANDARD_ENGINE'] -cne 'native'){throw 'Tor capture lost its exact native session.'}
  $physicalID=[string]$CapturedEnvironment['HOMEVPN_PROFILE_ID']
  $policyID=[string]$CapturedEnvironment['HOMEVPN_POLICY_PROFILE_ID']
  if($physicalID -cnotmatch '^[A-Za-z0-9_-]{1,64}$' -or $policyID -cnotmatch '^[A-Za-z0-9_-]{1,64}$'){throw 'Tor capture has invalid physical or policy profile identity.'}
  $read={
    param([string]$Name,[string]$DigestName,[int]$Limit)
    $expected=[string]$CapturedEnvironment[$DigestName]
    if($expected -cnotmatch '^[a-f0-9]{64}$'){throw 'Tor capture lacks an exact private input digest.'}
    $path=Join-Path $RuntimeDir $Name
    Assert-RouterVPNNoReparseAncestors $path
    # Hold the same leaf against writes/deletion across both the raw digest
    # check and JSON read; the object must describe those captured bytes.
    $held=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try{
      if($held.Length -le 0 -or $held.Length -gt $Limit){throw 'Tor captured private input exceeds its bound.'}
      if((Get-RouterVPNPrivateFileSHA256 $path 'Captured Tor identity' $Limit) -cne $expected){throw 'Tor identity input changed after capture.'}
      $value=Read-RouterVPNPrivateJson $path 'Captured Tor identity' $Limit
      $reader=[IO.StreamReader]::new($held,[Text.UTF8Encoding]::new($false,$true),$true,4096,$true)
      try{$raw=$reader.ReadToEnd()}finally{$reader.Dispose()}
      return [pscustomobject]@{value=$value;length=$held.Length;raw=$raw}
    }finally{$held.Dispose()}
  }
  $captured=& $read 'tor-capture.json' 'HOMEVPN_TOR_CAPTURE_SHA256' 8388608
  $capture=$captured.value
  $profileCapture=& $read 'tor-profile.json' 'HOMEVPN_TOR_PROFILE_SHA256' 4194304
  $profile=$profileCapture.value
  if($profile.external -isnot [pscustomobject] -or $profile.external.protocol -isnot [string] -or
     $profile.external.protocol -cnotin @('tor','tor-bridge')){throw 'Tor launch lost its exact selected protocol.'}
  $protocol=$profile.external.protocol
  $bridgeSelection=$profile.external.PSObject.Properties['tor_bridge']
  if($protocol -ceq 'tor' -and $null -ne $bridgeSelection -and $null -ne $bridgeSelection.Value){throw 'Plain Tor cannot discard a captured bridge selection.'}
  $required=@('schema','session_id','isolation_secret','target_os','tor_binary')
  $fields=@($capture.PSObject.Properties.Name)
  $predecessor=$capture.PSObject.Properties['predecessor']
  $viaEntry=$null -ne $predecessor
  $server=$capture.schema -eq 2
  $expectedCount=if($viaEntry){6}else{5}
  if($fields.Count -ne $expectedCount -or @($fields|Where-Object{$required -cnotcontains $_ -and $_ -cne 'predecessor'}).Count -ne 0 -or
     ($capture.schema -isnot [int] -and $capture.schema -isnot [long]) -or $capture.schema -notin @(1,2) -or [string]$capture.session_id -cne $Session -or
     [string]$capture.isolation_secret -cnotmatch '^[a-f0-9]{64}$' -or
     [string]$capture.target_os -cne 'windows' -or $capture.tor_binary -isnot [string] -or [string]$capture.tor_binary -cne $TorBinary -or
     $profile.id -isnot [string] -or [string]$profile.id -cne $policyID){throw 'Tor private inputs belong to another captured policy owner.'}
  if($server){
    if(-not $viaEntry -or $TorBinary -or [string]$CapturedEnvironment['HOMEVPN_TOR_BINARY_SHA256'] -or
       [string]$profile.multihop_execution -cne 'server'){throw 'Server Tor acquired a local child or lost its explicit captured execution.'}
    foreach($name in @('torrc','tor-defaults')){
      $path=Join-Path $RuntimeDir $name
      Assert-RouterVPNNoReparseAncestors $path
      $digestName=if($name -ceq 'torrc'){'HOMEVPN_TOR_TORRC_SHA256'}else{'HOMEVPN_TOR_DEFAULTS_SHA256'}
      $newline='01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b'
      if([string]$CapturedEnvironment[$digestName] -cne $newline -or
         (Get-RouterVPNPrivateFileSHA256 $path 'Captured empty Server Tor input' 1) -cne $newline){throw 'Server Tor input contains an unowned local configuration.'}
    }
  }elseif(-not [IO.Path]::IsPathRooted($TorBinary) -or [string]$CapturedEnvironment['HOMEVPN_TOR_BINARY_SHA256'] -cnotmatch '^[a-f0-9]{64}$'){
    throw 'Local Tor lost its captured executable identity.'
  }
  $enabled=$profile.PSObject.Properties['multihop_enabled']
  $entry=$null
  if($viaEntry){
    $entry=$predecessor.Value
    if($entry -isnot [pscustomobject] -or
       ($entry.schema -isnot [int] -and $entry.schema -isnot [long]) -or $entry.schema -notin @(1,2)){throw 'Tor predecessor has no supported captured proof schema.'}
    $externalEntry=$entry.schema -eq 2
    $allowedEntryFields=@('schema','entry_mode','profile','config','assets_sha256')
    if($externalEntry){$allowedEntryFields+=@('entry_kind','source_config')}
    $entryFields=@($entry.PSObject.Properties.Name)
    if($entryFields.Count -ne $allowedEntryFields.Count -or @($entryFields|Where-Object{$allowedEntryFields -cnotcontains $_}).Count -ne 0 -or
       $entry.assets_sha256 -isnot [string] -or $entry.assets_sha256 -cnotmatch '^[a-f0-9]{64}$' -or
       $entry.entry_mode -isnot [string] -or $entry.entry_mode -cnotmatch '^[a-z0-9-]{1,32}$' -or
       $entry.profile -isnot [pscustomobject] -or $entry.config -isnot [pscustomobject] -or
       $entry.profile.id -isnot [string] -or [string]$entry.profile.id -cne $physicalID -or $physicalID -ceq $policyID -or
       $null -eq $enabled -or -not ($enabled.Value -is [bool]) -or -not $enabled.Value -or
       [string]$profile.multihop_entry_id -cne $physicalID -or [string]$profile.multihop_exit_id -cne $policyID -or
       [string]$profile.multihop_entry_mode -cne [string]$entry.entry_mode -or [string]$profile.multihop_exit_mode -cne $protocol){
      throw 'Tor predecessor does not match the captured entry and exit.'
    }
    if($externalEntry){
      if($server -or $entry.entry_kind -isnot [string] -or $entry.entry_kind -cne 'external-public-ip' -or
         $entry.source_config -isnot [pscustomobject] -or @($entry.source_config.PSObject.Properties).Count -eq 0 -or
         [string]$entry.profile.node_kind -cne 'external' -or $entry.profile.external -isnot [pscustomobject] -or
         $entry.profile.external.protocol -isnot [string] -or $entry.profile.external.protocol -cne $entry.entry_mode -or
         $entry.entry_mode -cnotin @('wireguard','amneziawg','socks5','http-connect','https-connect','shadowsocks','hysteria2','openvpn')){
        throw 'Ordinary Tor predecessor borrowed another proof authority or lost its original graph.'
      }
      foreach($key in @('node_proof_id','router_api','api_token')){
        $identity=$entry.profile.PSObject.Properties[$key]
        if($null -ne $identity -and $null -ne $identity.Value -and ($identity.Value -isnot [string] -or $identity.Value -cne '')){throw 'Ordinary Tor predecessor borrowed private Router control identity.'}
      }
      $expectedAddress=$entry.profile.external.PSObject.Properties['expected_public_ip']
      $expectedIP=$null
      if($null -eq $expectedAddress -or $expectedAddress.Value -isnot [string] -or
         -not [Net.IPAddress]::TryParse($expectedAddress.Value,[ref]$expectedIP) -or $expectedIP.ToString() -cne $expectedAddress.Value -or
         [Net.IPAddress]::IsLoopback($expectedIP) -or $expectedIP.Equals([Net.IPAddress]::Any) -or $expectedIP.Equals([Net.IPAddress]::IPv6Any) -or
         $expectedIP.Equals([Net.IPAddress]::Broadcast) -or $expectedIP.IsIPv6Multicast -or $expectedIP.IsIPv6LinkLocal -or $expectedIP.IsIPv4MappedToIPv6){throw 'Ordinary Tor predecessor lost its captured public-address proof.'}
    }elseif([string]$entry.profile.node_kind -cne 'router-vpn'){
      throw 'Router proof schema cannot admit an ordinary Tor predecessor.'
    }
    $execution=$profile.PSObject.Properties['multihop_execution']
    $choices=if($server){@('server')}else{@('','local')}
    if($null -ne $execution -and [string]$execution.Value -cnotin $choices){throw 'Tor predecessor requires its exact captured execution.'}
  }elseif($captured.length -gt 16384 -or $physicalID -cne $policyID -or
          ($null -ne $enabled -and (-not ($enabled.Value -is [bool]) -or $enabled.Value))){throw 'Direct Tor capture has another owner or exceeds its direct bound.'}
  $endpoint=[string]$CapturedEnvironment['HOMEVPN_ENDPOINT']
  $plainDirect=-not $viaEntry -and $protocol -ceq 'tor'
  if($plainDirect){
    $kill=$profile.PSObject.Properties['kill_switch']
    $killPolicy=$profile.PSObject.Properties['kill_switch_policy']
    if($endpoint -cne '' -or $BridgeEndpoint -cne '' -or $null -eq $killPolicy -or $killPolicy.Value -isnot [string] -or $killPolicy.Value -cne 'off' -or
       ($null -ne $kill -and ($kill.Value -isnot [bool] -or $kill.Value))){throw 'Direct plain Tor requires explicit Off protection and no invented guard endpoint.'}
  }elseif([string]::IsNullOrWhiteSpace($endpoint) -or (-not $viaEntry -and $endpoint -cne $BridgeEndpoint)){throw 'Tor capture lost its actual physical endpoint.'}
  # Fixed Direct authority comes only from the complete hashed bridge source.
  # Do not infer sockets from native output, a first bridge, or an entry label.
  $fixedDirect=$false;$directEgress=@();$directHosts=@()
  if(-not $viaEntry -and $protocol -ceq 'tor-bridge' -and $null -ne $bridgeSelection -and $bridgeSelection.Value -is [pscustomobject]){
    $bridgeConfig=$bridgeSelection.Value
    $bridgeFields=@($bridgeConfig.PSObject.Properties.Name)
    $linesProperty=$bridgeConfig.PSObject.Properties['bridges']
    $transportProperty=$bridgeConfig.PSObject.Properties['transport']
    if($null -eq $linesProperty -or $linesProperty.Value -isnot [Array] -or $linesProperty.Value.Count -lt 1 -or $linesProperty.Value.Count -gt 8){throw 'Direct bridge source exceeds its captured bound.'}
    if($null -ne $transportProperty -and $transportProperty.Value -is [string] -and $transportProperty.Value -cin @('obfs4','custom')){
      $fixedDirect=$true;$lineSet=@{};$tupleSet=@{};$hostSet=@{}
      foreach($line in $linesProperty.Value){
        if($line -isnot [string] -or $line.Length -gt 8192 -or $line.Contains([string][char]0) -or $line.Contains("`r") -or $line.Contains("`n")){throw 'Direct bridge source is not a bounded normalized line.'}
        $words=@($line -split '\s+')
        if($words.Count -eq 0 -or $words[0] -cne 'obfs4'){$fixedDirect=$false;break}
        if($words.Count -lt 4 -or ($words -join ' ') -cne $line -or $lineSet.ContainsKey($line) -or $words[2] -cnotmatch '\A[0-9A-F]{40}\z'){throw 'Direct obfs4 source lost its exact normalized identity.'}
        $socket=[regex]::Match($words[1],'\A(?<host>\[[0-9a-f:]+\]|[0-9.]+):(?<port>[1-9][0-9]{0,4})\z')
        if(-not $socket.Success){throw 'Direct obfs4 source lost its literal socket.'}
        $hostValue=$socket.Groups['host'].Value.Trim('[',']');$portValue=[int]$socket.Groups['port'].Value
        $address=$null
        if($portValue -gt 65535 -or -not [Net.IPAddress]::TryParse($hostValue,[ref]$address) -or $address.ToString() -cne $hostValue){throw 'Direct obfs4 source lost its canonical literal socket.'}
        $bytes=$address.GetAddressBytes()
        $private=if($bytes.Length -eq 4){$bytes[0] -eq 10 -or ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or ($bytes[0] -eq 192 -and $bytes[1] -eq 168)}else{($bytes[0] -band 254) -eq 252}
        if($private){throw 'Direct obfs4 source is not a public literal socket.'}
        $lineSet[$line]=$true;$key=$hostValue+'|'+[string]$portValue
        if(-not $tupleSet.ContainsKey($key)){$tupleSet[$key]=$true;$directEgress+=@([ordered]@{host=$hostValue;port=$portValue;network='tcp'})}
        if(-not $hostSet.ContainsKey($hostValue)){$hostSet[$hostValue]=$true;$directHosts+=@($hostValue)}
      }
      if($fixedDirect){
        $socks=$bridgeConfig.PSObject.Properties['socks_port']
        if($bridgeFields.Count -ne 3 -or @($bridgeFields|Where-Object{$_ -cnotin @('transport','bridges','socks_port')}).Count -ne 0 -or
           $null -eq $socks -or ($socks.Value -isnot [int] -and $socks.Value -isnot [long]) -or $socks.Value -lt 1024 -or $socks.Value -gt 65535){throw 'Direct bridge source lost its captured configuration shape.'}
        $canonical=([ordered]@{transport=$transportProperty.Value;bridges=@($linesProperty.Value);socks_port=$socks.Value}|ConvertTo-Json -Depth 8 -Compress)
        $bridgeKeys=@([regex]::Matches($profileCapture.raw,'"(?:\\.|[^"\\])*"')|Where-Object{
          $_.Value -ceq '"tor_bridge"' -and $profileCapture.raw.Substring($_.Index+$_.Length) -match '^\s*:'
        })
        $bridgeSource=[regex]::Matches($profileCapture.raw,('"tor_bridge":'+[regex]::Escape($canonical)+'(?=[,}])'))
        if($bridgeKeys.Count -ne 1 -or $bridgeSource.Count -ne 1 -or $bridgeSource[0].Index -ne $bridgeKeys[0].Index){throw 'Direct bridge source is ambiguous or differs from its exact captured bytes.'}
      }
    }
  }
  if(-not $viaEntry -and $protocol -ceq 'tor-bridge'){
    $kill=$profile.PSObject.Properties['kill_switch'];$killPolicy=$profile.PSObject.Properties['kill_switch_policy']
    if(($null -ne $kill -and $kill.Value -isnot [bool]) -or ($null -ne $killPolicy -and ($killPolicy.Value -isnot [string] -or $killPolicy.Value -cnotin @('','off','on-connect','always')))){throw 'Direct Tor protection lost its captured type.'}
    $strict=($null -ne $killPolicy -and $killPolicy.Value -cin @('on-connect','always')) -or (($null -eq $killPolicy -or $killPolicy.Value -ceq '') -and $null -ne $kill -and $kill.Value)
    if($strict -and -not $fixedDirect){throw 'Dynamic Direct Tor cannot acquire strict physical authority.'}
  }
  $endpointRaw=[string]$CapturedEnvironment['HOMEVPN_NATIVE_ENDPOINTS_JSON']
  $egressRaw=[string]$CapturedEnvironment['HOMEVPN_NATIVE_EGRESS_JSON']
  $hasArrays=$endpointRaw.Length -gt 0 -or $egressRaw.Length -gt 0
  if(($viaEntry -or $fixedDirect) -and -not $hasArrays){throw 'Tor path requires its exact physical egress tuples.'}
  $addresses=@($endpoint);$egress=@()
  if($plainDirect){$addresses=@()}
  if($hasArrays){
    if([string]$CapturedEnvironment['HOMEVPN_EXTERNAL_SESSION'] -cne $Session -or $endpointRaw.Length -gt 1024 -or $egressRaw.Length -gt 4096 -or
       $endpointRaw -cnotmatch '\A\["[0-9a-f:.]+"(?:,"[0-9a-f:.]+")*\]\z'){throw 'Tor physical endpoints lost their exact captured session or encoding.'}
    $parsed=ConvertFrom-Json -InputObject ('{"endpoints":'+$endpointRaw+'}')
    $addresses=@($parsed.endpoints)
    $tuple='\{"host":"[0-9a-f:.]+","port":[1-9][0-9]{0,4},"network":"(?:tcp|udp)"\}'
    if(-not [regex]::IsMatch($egressRaw,('\A\['+$tuple+'(?:,'+$tuple+')*\]\z'))){throw 'Tor physical egress requires canonical captured tuples.'}
    $parsed=ConvertFrom-Json -InputObject ('{"egress":'+$egressRaw+'}')
    $egress=@($parsed.egress)
    if($egress.Count -lt 1 -or $egress.Count -gt 16){throw 'Tor physical egress exceeds its captured tuple bound.'}
  }
  if(-not $plainDirect -and ($addresses.Count -lt 1 -or $addresses.Count -gt 16 -or $addresses[0] -cne $endpoint)){throw 'Tor physical endpoints changed their captured primary owner.'}
  $seen=@{}
  foreach($address in $addresses){
    $ip=$null
    if(-not [Net.IPAddress]::TryParse($address,[ref]$ip) -or $ip.ToString() -cne $address -or
       [Net.IPAddress]::IsLoopback($ip) -or $ip.Equals([Net.IPAddress]::Any) -or $ip.Equals([Net.IPAddress]::IPv6Any) -or
       $ip.Equals([Net.IPAddress]::Broadcast) -or $seen.ContainsKey($address)){throw 'Tor physical endpoint is not a unique canonical unicast literal.'}
    $bytes=$ip.GetAddressBytes()
    if($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6){
      if($ip.IsIPv6Multicast -or $ip.IsIPv6LinkLocal -or $ip.IsIPv4MappedToIPv6 -or $ip.ScopeId -ne 0){throw 'Tor physical endpoint is not unicast.'}
    }elseif($bytes[0] -eq 0 -or $bytes[0] -ge 224 -or ($bytes[0] -eq 169 -and $bytes[1] -eq 254)){throw 'Tor physical endpoint is not unicast.'}
    $seen[$address]=$true
  }
  $seen=@{};$hosts=@{}
  foreach($item in $egress){
    if($addresses -cnotcontains [string]$item.host -or ($item.port -isnot [int] -and $item.port -isnot [long]) -or
       $item.port -lt 1 -or $item.port -gt 65535){throw 'Tor egress tuple does not belong to its captured physical remotes.'}
    $key=[string]$item.host+'|'+[string]$item.port+'|'+[string]$item.network
    if($seen.ContainsKey($key)){throw 'Tor physical egress contains a duplicate tuple.'}
    $seen[$key]=$true;$hosts[[string]$item.host]=$true
  }
  if($hasArrays -and $hosts.Count -ne $addresses.Count){throw 'Tor physical egress omitted a captured endpoint.'}
  $projection=$profile.PSObject.Properties['desktop_physical_egress']
  if($viaEntry -or $fixedDirect){
    if($null -eq $projection -or $null -eq $projection.Value -or $projection.Value -isnot [Array]){throw 'Tor Router entry lacks its captured physical graph projection.'}
    # Consume every complete JSON string before identifying this key, so an
    # escaped key-shaped string inside a credential cannot be confused with a
    # member. Its canonical tuple bytes must match the environment exactly;
    # ConvertFrom-Json must not collapse duplicate members or coerce types.
    $projectionKeys=@([regex]::Matches($profileCapture.raw,'"(?:\\.|[^"\\])*"')|Where-Object{
      $_.Value -ceq '"desktop_physical_egress"' -and $profileCapture.raw.Substring($_.Index+$_.Length) -match '^\s*:'
    })
    $projectionTuples=[regex]::Matches($profileCapture.raw,('"desktop_physical_egress":(?<tuples>\['+$tuple+'(?:,'+$tuple+')*\])(?=[,}])'))
    $rawProjectionValid=$projectionKeys.Count -eq 1 -and $projectionTuples.Count -eq 1 -and
      $projectionTuples[0].Index -eq $projectionKeys[0].Index -and $projectionTuples[0].Groups['tuples'].Value -ceq $egressRaw
    if(-not $rawProjectionValid){throw 'Tor physical graph projection differs from its exact captured tuples.'}
    if($fixedDirect){
      $directJSON=ConvertTo-Json -InputObject @($directEgress) -Depth 8 -Compress
      $hostsJSON=ConvertTo-Json -InputObject @($directHosts) -Compress
      if($directJSON -cne $egressRaw -or $hostsJSON -cne $endpointRaw){throw 'Direct obfs4 tuples differ from the complete captured bridge source.'}
    }
  }elseif($null -ne $projection -or $hasArrays -or [string]$CapturedEnvironment['HOMEVPN_EXTERNAL_SESSION']){
    throw 'Direct Tor acquired an unowned physical predecessor projection.'
  }
  # The raw graph and its observer must share this captured source before any
  # firewall exception is installed. Native check validates graph syntax; the
  # independent native launch still reconstructs its complete private policy.
  $graphCapture=& $read 'sing-box.json' 'HOMEVPN_TOR_CONFIG_SHA256' 4194304
  $graph=$graphCapture.value
  $sourceSHA=[string]$CapturedEnvironment['HOMEVPN_TOR_SOURCE_SHA256']
  if($graph -isnot [pscustomobject] -or @($graph.PSObject.Properties.Name) -cnotcontains 'services' -or
     $graph.services -isnot [Array] -or $sourceSHA -cnotmatch '^[a-f0-9]{64}$'){
    throw 'Tor graph lost its captured native network identity.'
  }
  $observers=@($graph.services|Where-Object{
    $_ -is [pscustomobject] -and @($_.PSObject.Properties.Name) -ccontains 'type' -and
    $_.type -is [string] -and $_.type -ceq 'routervpn-desktop-tor-network'
  })
  if($observers.Count -ne 1){throw 'Tor graph requires exactly one captured native network owner.'}
  $observer=$observers[0]
  $observerFields=@($observer.PSObject.Properties.Name)
  if($observerFields.Count -ne 4 -or @($observerFields|Where-Object{@('type','tag','session_id','source_sha256') -cnotcontains $_}).Count -ne 0 -or
     $observer.tag -isnot [string] -or $observer.tag -cne 'routervpn-tor-physical' -or
     $observer.session_id -isnot [string] -or $observer.session_id -cne $Session -or
     $observer.source_sha256 -isnot [string] -or $observer.source_sha256 -cne $sourceSHA){
    throw 'Tor graph belongs to another captured native network owner.'
  }
  # The controller and native compiler validate the complete entry graph.
  # This envelope binds the firewall handoff to that same immutable capture;
  # it never substitutes the Tor bridge or private proof/DNS destination.
  return [pscustomobject]@{endpoint=$endpoint;via_entry=$viaEntry;server=$server;entry_id=$physicalID;policy_id=$policyID;capture=$capture;profile=$profile;egress=$egress;endpoints=$addresses}
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
      $arguments=@('routervpn-tor','--runtime-dir',$RuntimeDir,'--session',$Session)
      if($TorBinary){$arguments+=@('--tor-binary',$TorBinary)}
      $owned=Start-RouterVPNPrivateJob -FilePath $NativeBinary -ArgumentList $arguments -WorkingDirectory $RuntimeDir -Environment $CapturedEnvironment
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
    [string]$Action,[string]$Root,[string]$RuntimeDir,[string]$Session,[string]$TorBinary,[string]$BridgeEndpoint,
    [System.Collections.IDictionary]$CapturedEnvironment,[System.Collections.IDictionary]$LaunchState
  )
  if($Action -cne 'up' -or $null -eq $LaunchState -or
     -not ($LaunchState.NoNativeChild -is [bool]) -or -not $LaunchState.NoNativeChild -or
     -not ($LaunchState.StartAttempted -is [bool]) -or
     ($LaunchState.StartAttempted -and -not ($LaunchState.NoChildFailure -is [bool] -and $LaunchState.NoChildFailure))){return}
  if($Session -cnotmatch '^[a-f0-9]{32}$' -or $null -eq $CapturedEnvironment -or
     [string]$CapturedEnvironment['HOMEVPN_TOR_SESSION'] -cne $Session -or
     [string]$CapturedEnvironment['HOMEVPN_STANDARD_ENGINE'] -cne 'native' -or
     [string]$CapturedEnvironment['HOMEVPN_PROFILE_ID'] -cnotmatch '^[A-Za-z0-9_-]{1,64}$' -or
     [string]$CapturedEnvironment['HOMEVPN_POLICY_PROFILE_ID'] -cnotmatch '^[A-Za-z0-9_-]{1,64}$'){throw 'Prelaunch witness lost its captured native identity.'}
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
      $limit=if($entry.Key -ceq 'tor-capture.json'){8388608}else{4194304}
      $digest=Get-RouterVPNPrivateFileSHA256 $path 'Captured Tor prelaunch input' $limit
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
  $physical=Get-RouterVPNTorCaptureIdentity -RuntimeDir $directory -Session $Session -TorBinary $TorBinary -BridgeEndpoint $BridgeEndpoint -CapturedEnvironment $CapturedEnvironment
  $config=Read-RouterVPNPrivateJson (Join-Path $directory 'sing-box.json') 'Captured Tor graph' 4194304
  $services=@($config.services)
  $observers=@($services|Where-Object{[string]$_.type -ceq 'routervpn-desktop-tor-network'})
  if($observers.Count -ne 1 -or [string]$observers[0].tag -cne 'routervpn-tor-physical' -or [string]$observers[0].session_id -cne $Session -or
     [string]$observers[0].source_sha256 -cne [string]$CapturedEnvironment['HOMEVPN_TOR_SOURCE_SHA256']){throw 'Prelaunch graph has another native physical owner.'}
  $cover=@($services|Where-Object{[string]$_.type -cne 'routervpn-desktop-tor-network'})
  if($cover.Count -gt 1 -or ($cover.Count -eq 1 -and (-not $physical.via_entry -or
     [string]$cover[0].type -cne 'routervpn-cover' -or [string]$cover[0].tag -cne 'routervpn-cover-entry' -or
     [string]$cover[0].node_id -cne [string]$physical.capture.predecessor.profile.node_proof_id))){throw 'Prelaunch graph has an unowned entry service.'}
  & $verifyInputs
  $receipt=[ordered]@{schema=1;session_id=$Session;source_sha256=[string]$CapturedEnvironment['HOMEVPN_TOR_SOURCE_SHA256'];config_sha256=[string]$CapturedEnvironment['HOMEVPN_TOR_CONFIG_SHA256'];no_native_process=$true}|ConvertTo-Json -Compress
  if($receipt.Length -gt 1024){throw 'Prelaunch failure witness exceeds its bound.'}
  Write-RouterVPNPrivateTextAtomic (Join-Path $directory 'prelaunch-failed.json') $receipt
}
$CapturedEnvironment=Get-RouterVPNTorNativeEnvironment ([Environment]::GetEnvironmentVariables('Process'))
$LaunchState=@{StartAttempted=$false;NoNativeChild=$true;NoChildFailure=$false}
try{
  $helpers=@($KillSwitch,$JobHelper,$Selector,$NativeBinary)
  if($TorBinary){$helpers+=@($TorBinary)}
  foreach($file in $helpers){
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
  $PhysicalCapture=Get-RouterVPNTorCaptureIdentity -RuntimeDir $RuntimeDir -Session $Session -TorBinary $TorBinary -BridgeEndpoint $BridgeEndpoint -CapturedEnvironment $CapturedEnvironment
  if(-not $PhysicalCapture.server){
    $info=Get-Item -LiteralPath $TorBinary -Force
    if($info.Length -le 0 -or $info.Length -gt 402653184){throw 'Captured standalone Tor executable exceeds its bound.'}
    if((Get-FileHash -LiteralPath $TorBinary -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$env:HOMEVPN_TOR_BINARY_SHA256){throw 'Standalone Tor bytes changed after capture.'}
  }
  & $NativeBinary routervpn-tor --help | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Native Tor command is unavailable.'}
  & $NativeBinary check -D $RuntimeDir -c (Join-Path $RuntimeDir 'sing-box.json') | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Native Tor graph was rejected.'}
  function Invoke-RouterVPNTorKillSwitch([string]$Kind){
    & $KillSwitch -Action $Kind -Root $Root -Endpoint $PhysicalCapture.endpoint -TunnelAlias $TunnelAlias
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
    $null=Write-RouterVPNTorPrelaunchFailure -Action $Action -Root $Root -RuntimeDir $RuntimeDir -Session $Session -TorBinary $TorBinary -BridgeEndpoint $BridgeEndpoint -CapturedEnvironment $CapturedEnvironment -LaunchState $LaunchState
  }catch{
    # An unavailable/tampered private workspace has no trustworthy witness.
    # Retain it for the controller and preserve the original launch failure.
    Write-Warning 'Tor prelaunch failure could not retain a verified no-native-process witness.'
  }
  throw
}
