param([string]$Root = (Split-Path $PSScriptRoot -Parent), [string]$Output = '')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$Source=Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $Root 'client/RouterVPN-Windows-TorBridge.ps1')
$Ast=[ScriptBlock]::Create($Source).Ast
$Bodies=@($Ast.FindAll({param($Node)
    $Node -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
    $Node.Value.StartsWith('function TestUnifiedExternalMutationIdle')
},$true))
if($Bodies.Count -ne 1){throw 'Shipping external form composition changed.'}
$Shipping=[ScriptBlock]::Create($Bodies[0].Value)
. $Shipping
$Windows=@($Shipping.Ast.FindAll({param($Node)
    ($Node -is [System.Management.Automation.Language.StringConstantExpressionAst] -or $Node -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) -and $Node.Value.TrimStart().StartsWith('<Window')
},$true))
if($Windows.Count -ne 2){throw 'Shipping external form/path dialog XML changed.'}
foreach($Markup in $Windows){[xml]$Validated=$Markup.Value;if($Validated.DocumentElement.LocalName -ne 'Window'){throw 'External dialog markup is invalid.'}}
$Callbacks=@($Shipping.Ast.FindAll({param($Node)
    $Node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
    $Node.Member.Extent.Text -eq 'Add_Click' -and
    $Node.Expression.Extent.Text -eq '$D.FindName(''ExtSave'')'
},$true))
if($Callbacks.Count -ne 1){throw 'Shipping external Save callback changed.'}
$Save=$Callbacks[0].Arguments[0].ScriptBlock.GetScriptBlock()

$Parameters='Jc=3; Jmin=40; Jmax=900; S1=56; S2=48; S3=24; S4=32; H1=10000000-19999999; H2=20000000-29999999; H3=30000000-39999999; H4=40000000-49999999'
$Expected=@{jc='3';jmin='40';jmax='900';s1='56';s2='48';s3='24';s4='32';h1='10000000-19999999';h2='20000000-29999999';h3='30000000-39999999';h4='40000000-49999999'}
$Private=[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(('p'*32)))
$Peer=[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(('q'*32)))
$Fields=@{}
foreach($Name in @('ExtPort','ExtName','ExtServer','ExtExpected','ExtUser','ExtPassword','ExtTLS','ExtMethod','ExtSecret','ExtWGPrivate','ExtWGPeer','ExtWGAddresses','ExtWGAllowed','ExtWGDNS','ExtWGPSK','ExtWGMTU','ExtWGKeepalive','ExtAWGParameters','ExtResponseURL','ExtResponseName','ExtLayerAPI','ExtLayerPort','ExtLayerKey','ExtServerPeerPublic','ExtServerPeerAddresses','ExtServerPeerMTU','ExtServerPeerKeepalive','ExtOpenVPNConfig','ExtOpenVPNPairing','ExtOpenVPNResponseProbes')){
    $Fields[$Name]=[pscustomobject]@{Text='';Password=''}
}
$Fields.ExtStartLayer=[pscustomobject]@{SelectedItem=[pscustomobject]@{Tag='off'}}
$Fields.ExtPort.Text='51820';$Fields.ExtName.Text='Imported AWG fixture';$Fields.ExtServer.Text='203.0.113.60';$Fields.ExtExpected.Text='203.0.113.60'
$Fields.ExtWGPrivate.Password=$Private;$Fields.ExtWGPeer.Text=$Peer
$Fields.ExtWGAddresses.Text='10.66.0.2/32, fd66::2/128';$Fields.ExtWGAllowed.Text='0.0.0.0/0, ::/0';$Fields.ExtWGDNS.Text='9.9.9.9'
$Fields.ExtWGMTU.Text='1280';$Fields.ExtWGKeepalive.Text='17';$Fields.ExtAWGParameters.Text=$Parameters
$D=[pscustomobject]@{Fields=$Fields}
$D|Add-Member -MemberType ScriptMethod -Name FindName -Value {param($Name) return $this.Fields[$Name]}
$Protocol=[pscustomobject]@{SelectedItem=[pscustomobject]@{Tag='amneziawg'}}
$Status=[pscustomobject]@{Text=''}
$script:Connected=$false;$script:Saved=$null;$script:CurrentPathCatalog=$null
function Api($Path,$Method='GET',$Body=$null,$Timeout=0){
    if($Path -eq '/api/status'){return [pscustomobject]@{connected=$script:Connected;phase='off'}}
    if($Path -eq '/api/nodes'){if($null-ne$script:CurrentPathCatalog){return [pscustomobject]@{profiles=$script:CurrentPathCatalog}};return [pscustomobject]@{profiles=@($Captured)+@($Choices|Where-Object{$_.id})}}
    if($Path -ne '/api/external-profile/create' -or $Method -ne 'POST'){throw 'Unexpected form request.'}
    $script:Saved=$Body
    return [pscustomobject]@{profile=[pscustomobject]@{name='Fixture'}}
}
function Log($Text){}
function RefreshProduct{}
function Check([bool]$Value,[string]$Message){if(-not $Value){throw $Message}}
& $Save
Check ($null -ne $Saved) ('Actual AWG Save callback rejected its valid form: '+$Status.Text)
Check ($Saved.protocol -ceq 'amneziawg' -and $Saved.wg_keepalive -eq 17 -and $Saved.wg_mtu -eq 1280) 'AWG peer settings changed.'
Check ($Saved.awg_parameters.Count -eq 11) 'AWG parameters were dropped.'
foreach($Key in $Expected.Keys){Check ($Saved.awg_parameters[$Key] -is [string] -and $Saved.awg_parameters[$Key] -ceq $Expected[$Key]) ('AWG parameter changed: '+$Key)}
Check ($Saved.wg_private_key -ceq $Private -and $Saved.wg_peer_public_key -ceq $Peer) 'Peer credentials changed.'
if($Output){[void][IO.Directory]::CreateDirectory($Output);[IO.File]::WriteAllText((Join-Path $Output 'amneziawg.json'),($Saved|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))}

$Count=1
foreach($Bad in @('', ($Parameters+';Jc=3'), $Parameters.Replace('S4=32; ',''), ($Parameters+';unknown=7'), $Parameters.Replace('H1=10000000-19999999','H1=1--9'), $Parameters.Replace('S4=32','S4=bad'), ('Jc=3;'*1000))){
    $Fields.ExtAWGParameters.Text=$Bad;$script:Saved=$null;& $Save
    Check ($null -eq $Saved) ('Malformed AWG parameters reached the controller in case '+$Count+'.');$Count++
}
$Fields.ExtAWGParameters.Text=$Parameters
foreach($Bad in @('-1','65536','bad')){
    $Fields.ExtWGKeepalive.Text=$Bad;$script:Saved=$null;& $Save
    Check ($null -eq $Saved) 'Invalid keepalive reached the controller.';$Count++
}
$Fields.ExtWGKeepalive.Text='17'
foreach($Bad in @('1279','9001','bad')){
    $Fields.ExtWGMTU.Text=$Bad;$script:Saved=$null;& $Save
    Check ($null -eq $Saved) 'Invalid MTU reached the controller.';$Count++
}
$Fields.ExtWGMTU.Text='1280'
$script:Connected=$true;$script:Saved=$null;& $Save
Check ($null -eq $Saved) 'Changed VPN state permitted external profile mutation.';$Count++
$script:Connected=$false;$Protocol.SelectedItem.Tag='wireguard';$script:Saved=$null;& $Save
Check ($null -ne $Saved -and -not $Saved.ContainsKey('awg_parameters') -and $Saved.wg_keepalive -eq 17) 'Ordinary WireGuard was changed into AmneziaWG.';$Count++
if($Output){[IO.File]::WriteAllText((Join-Path $Output 'wireguard.json'),($Saved|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))}
$Fields.ExtPort.Text='8388';$Fields.ExtResponseURL.Text='https://203.0.113.60:8443/node-response';$Fields.ExtResponseName.Text='external.example'
$LayerKey=[Convert]::ToBase64String((,[byte]7)*32)
foreach($ProtocolID in @('shadowsocks','hysteria2','socks5','http-connect','https-connect')){
    foreach($Layer in @('off','aes-256-gcm','aes-256-gcm+xor-whitening')){
        $Protocol.SelectedItem.Tag=$ProtocolID;$Fields.ExtStartLayer.SelectedItem.Tag=$Layer
        $Fields.ExtUser.Text=' user literal ';$Fields.ExtPassword.Password=' password literal ';$Fields.ExtMethod.Text='aes-256-gcm';$Fields.ExtSecret.Password=' private proxy secret ';$Fields.ExtTLS.Text='external.example'
        $Fields.ExtLayerAPI.Text='';$Fields.ExtLayerPort.Text='';$Fields.ExtLayerKey.Password=''
        if($Layer -ne 'off'){$Fields.ExtLayerAPI.Text='http://10.77.0.1:8787';$Fields.ExtLayerPort.Text='8389';$Fields.ExtLayerKey.Password=$LayerKey}
        $script:Saved=$null;& $Save
        Check ($null -ne $Saved) ('Valid proxy/layer form failed: '+$Status.Text)
        Check ($Saved.start_layer -ceq $Layer -and $Saved.response_probe.url -ceq $Fields.ExtResponseURL.Text -and $Saved.response_probe.server_name -ceq 'external.example') 'Selected response probe or layer changed.'
        if($ProtocolID -in @('socks5','http-connect','https-connect')){Check ($Saved.username -ceq ' user literal ' -and $Saved.password -ceq ' password literal ') 'Proxy credential whitespace changed.'}
        if($Layer -eq 'off'){Check (-not $Saved.ContainsKey('start_layer_provision')) 'Off retained private layer credentials.'}
        else{Check ($Saved.start_layer_provision.mode -ceq $Layer -and $Saved.start_layer_provision.transport.password -ceq $LayerKey -and $Saved.start_layer_provision.transport.server -ceq '203.0.113.60') 'Provisioned key or node ownership changed.'}
        if($Output){[IO.File]::WriteAllText((Join-Path $Output ($ProtocolID+'-'+$Layer+'.json')),($Saved|ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))}
        $Count++
    }
}
foreach($Bad in @('','0','65536','invalid')){$Fields.ExtLayerPort.Text=$Bad;$script:Saved=$null;& $Save;Check ($null -eq $Saved) 'Invalid provisioned port reached controller.';$Count++}
$Fields.ExtLayerPort.Text='8389'
foreach($Missing in @('ExtLayerAPI','ExtLayerKey')){
    $OldText=$Fields[$Missing].Text;$OldPassword=$Fields[$Missing].Password;$Fields[$Missing].Text='';$Fields[$Missing].Password='';$script:Saved=$null;& $Save
    Check ($null -eq $Saved) 'Incomplete active provision reached controller.';$Fields[$Missing].Text=$OldText;$Fields[$Missing].Password=$OldPassword;$Count++
}
$Fields.ExtStartLayer.SelectedItem.Tag='off';$script:Saved=$null;& $Save;Check ($null -eq $Saved) 'Off silently discarded provisioned credentials.';$Count++
$Fields.ExtLayerAPI.Text='';$Fields.ExtLayerPort.Text='';$Fields.ExtLayerKey.Password=''
$Protocol.SelectedItem.Tag='wireguard';$script:Saved=$null;& $Save;Check ($null -ne $Saved -and -not $Saved.ContainsKey('server_peer')) 'Local WireGuard response probe incorrectly required a server peer.';$Count++
$ServerPublic='bBq3qZ0192YFNiixFZqNRUwTqYBvfydnB3GJrDJliAg='
$Fields.ExtServerPeerPublic.Text=$ServerPublic;$Fields.ExtServerPeerAddresses.Text='10.66.0.3/32, fd66::3/128';$Fields.ExtServerPeerMTU.Text='1360';$Fields.ExtServerPeerKeepalive.Text='25'
foreach($Packet in @('wireguard','amneziawg')){foreach($Layer in @('off','aes-256-gcm','aes-256-gcm+xor-whitening')){
    $Protocol.SelectedItem.Tag=$Packet;$Fields.ExtStartLayer.SelectedItem.Tag=$Layer;$Fields.ExtPort.Text='51820'
    $Fields.ExtLayerAPI.Text='';$Fields.ExtLayerPort.Text='';$Fields.ExtLayerKey.Password=''
    if($Layer -ne 'off'){$Fields.ExtLayerAPI.Text='http://10.77.0.1:8787';$Fields.ExtLayerPort.Text='8389';$Fields.ExtLayerKey.Password=$LayerKey}
    $script:Saved=$null;& $Save;Check ($null -ne $Saved) ('Packet form failed: '+$Status.Text)
    Check ($Saved.server_peer.Count -eq 4 -and $Saved.server_peer.public_key -ceq $ServerPublic -and $Saved.server_peer.mtu -eq 1360 -and $Saved.server_peer.persistent_keepalive_interval -eq 25 -and $Saved.server_peer.addresses.Count -eq 2 -and $Saved.server_peer.addresses[0] -ceq '10.66.0.3/32' -and $Saved.server_peer.addresses[1] -ceq 'fd66::3/128') 'Separate server peer descriptor changed.'
    Check ($Saved.wg_private_key -ceq $Private -and $Saved.wg_peer_public_key -ceq $Peer -and $Saved.wg_addresses[0] -ceq '10.66.0.2/32') 'Server descriptor replaced the local private peer.'
    if($Output){[IO.File]::WriteAllText((Join-Path $Output ($Packet+'-'+$Layer+'.json')),($Saved|ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))};$Count++
}}
foreach($Pair in @(@('ExtServerPeerPublic',''),@('ExtServerPeerPublic','invalid'),@('ExtServerPeerAddresses',''),@('ExtServerPeerMTU',''),@('ExtServerPeerMTU','1279'),@('ExtServerPeerMTU','9001'),@('ExtServerPeerMTU','bad'),@('ExtServerPeerKeepalive','-1'),@('ExtServerPeerKeepalive','65536'))){$Old=$Fields[$Pair[0]].Text;$Fields[$Pair[0]].Text=$Pair[1];$script:Saved=$null;& $Save;Check ($null -eq $Saved) 'Incomplete or invalid server descriptor reached controller.';$Fields[$Pair[0]].Text=$Old;$Count++}
$Protocol.SelectedItem.Tag='shadowsocks';$script:Saved=$null;& $Save;Check ($null -eq $Saved) 'Proxy accepted packet-only server descriptor.';$Count++
foreach($Name in @('ExtServerPeerPublic','ExtServerPeerAddresses','ExtServerPeerMTU','ExtServerPeerKeepalive','ExtOpenVPNConfig','ExtOpenVPNPairing')){$Fields[$Name].Text=''}
$Fields.ExtStartLayer.SelectedItem.Tag='off';$Fields.ExtLayerAPI.Text='';$Fields.ExtLayerPort.Text='';$Fields.ExtLayerKey.Password=''
$Protocol.SelectedItem.Tag='shadowsocks';$Fields.ExtResponseURL.Text='';$script:Saved=$null;& $Save;Check ($null -eq $Saved) 'Partial response endpoint reached controller.';$Count++
$OpenVPNFixtures=Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $Root 'deploy/fixtures/external-openvpn-client.json')|ConvertFrom-Json
foreach($Layer in @('off','aes-256-gcm','aes-256-gcm+xor-whitening')){
    $External=$OpenVPNFixtures.layers.$Layer.external;$Original=$External.openvpn
    $Protocol.SelectedItem.Tag='openvpn';$Fields.ExtServer.Text='203.0.113.20';$Fields.ExtExpected.Text=$External.expected_public_ip
    $Fields.ExtOpenVPNConfig.Text=$Original.config;$Fields.ExtOpenVPNPairing.Text=$External.openvpn_pairing|ConvertTo-Json -Depth 32
    $Fields.ExtUser.Text=$Original.username;$Fields.ExtPassword.Password=$Original.password
    $Fields.ExtResponseURL.Text=$External.response_probe.url;$Fields.ExtResponseName.Text=$External.response_probe.server_name;$Fields.ExtStartLayer.SelectedItem.Tag=$Layer
    $Fields.ExtLayerAPI.Text='';$Fields.ExtLayerPort.Text='';$Fields.ExtLayerKey.Password=''
    if($Layer -cne 'off'){$Fields.ExtLayerAPI.Text=$External.start_layer.api;$Fields.ExtLayerPort.Text=[string]$External.start_layer.transport.server_port;$Fields.ExtLayerKey.Password=$External.start_layer.transport.password}
    $script:Saved=$null;& $Save;Check ($null -ne $Saved) ('OpenVPN form rejected: '+$Status.Text)
    Check ($Saved.openvpn.config -ceq $Original.config -and $Saved.openvpn.username -ceq $Original.username -and $Saved.openvpn.password -ceq $Original.password -and $Saved.openvpn_pairing_json -ceq $Fields.ExtOpenVPNPairing.Text) 'OpenVPN source or raw private pairing changed.'
    if($Output){[IO.File]::WriteAllText((Join-Path $Output ('openvpn-'+$Layer+'.json')),($Saved|ConvertTo-Json -Depth 16),[Text.UTF8Encoding]::new($false))};$Count++
}
$Fields.ExtOpenVPNPairing.Text='';$Fields.ExtOpenVPNConfig.Text+="remote 203.0.113.21 443 tcp`n";$Fields.ExtResponseURL.Text='';$Fields.ExtResponseName.Text='';$Fields.ExtStartLayer.SelectedItem.Tag='off';$Fields.ExtLayerAPI.Text='';$Fields.ExtLayerPort.Text='';$Fields.ExtLayerKey.Password=''
$script:Saved=$null;& $Save;Check ($null -ne $Saved -and -not $Saved.ContainsKey('openvpn_pairing_json')) 'Plain Local multiremote incorrectly requires pairing.'
if($Output){[IO.File]::WriteAllText((Join-Path $Output 'openvpn-local-multiremote.json'),($Saved|ConvertTo-Json -Depth 16),[Text.UTF8Encoding]::new($false))};$Count++
$Multi=Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $Root 'deploy/fixtures/external-openvpn-multihost-client.json')|ConvertFrom-Json
$Fields.ExtOpenVPNConfig.Text=$Multi.external.openvpn.config;$Fields.ExtUser.Text=$Multi.external.openvpn.username;$Fields.ExtPassword.Password=$Multi.external.openvpn.password;$Fields.ExtExpected.Text=$Multi.external.expected_public_ip
$Fields.ExtOpenVPNPairing.Text="`n"+($Multi.external.openvpn_pairing|ConvertTo-Json -Depth 32)+"`n"
$MapText=$Multi.external.openvpn_response_probes|ConvertTo-Json -Depth 8 -Compress;$Fields.ExtOpenVPNResponseProbes.Text="`n"+$MapText+"`n"
$script:Saved=$null;& $Save;Check ($null -ne $Saved -and $Saved.openvpn_response_probes_json -ceq $Fields.ExtOpenVPNResponseProbes.Text -and $Saved.openvpn_pairing_json -ceq $Fields.ExtOpenVPNPairing.Text -and $Saved.openvpn.config -ceq $Fields.ExtOpenVPNConfig.Text -and $Saved.openvpn.username -ceq $Fields.ExtUser.Text -and $Saved.openvpn.password -ceq $Fields.ExtPassword.Password -and -not $Saved.ContainsKey('response_probe')) 'Actual OpenVPN callback changed private map, source, or credentials.'
if($Output){[IO.File]::WriteAllText((Join-Path $Output 'openvpn-multihost.json'),($Saved|ConvertTo-Json -Depth 16),[Text.UTF8Encoding]::new($false))};$Count++
$FirstHost=@($Multi.external.openvpn_response_probes.PSObject.Properties.Name|Sort-Object)[0];$FirstProbe=$Multi.external.openvpn_response_probes.PSObject.Properties[$FirstHost].Value|ConvertTo-Json -Depth 8 -Compress
$Fields.ExtOpenVPNResponseProbes.Text='{"'+$FirstHost+'":'+$FirstProbe+','+$MapText.Substring(1)
$script:Saved=$null;& $Save;Check ($null -ne $Saved -and $Saved.openvpn_response_probes_json -ceq $Fields.ExtOpenVPNResponseProbes.Text) 'Native OpenVPN callback parsed or changed raw duplicate map before strict controller validation.'
if($Output){[IO.File]::WriteAllText((Join-Path $Output 'openvpn-multihost-duplicate.json'),($Saved|ConvertTo-Json -Depth 16),[Text.UTF8Encoding]::new($false))};$Count++
$Fields.ExtOpenVPNResponseProbes.Text='x'*40961;$script:Saved=$null;& $Save;Check ($null -eq $Saved) 'Oversized OpenVPN map reached controller.';$Count++;$Fields.ExtOpenVPNResponseProbes.Text=''
$Protocol.SelectedItem.Tag='shadowsocks';$script:Saved=$null;& $Save;Check ($null -eq $Saved) 'Changing protocol discarded private OpenVPN source.';$Count++
$Fields.ExtOpenVPNConfig.Text='';$Protocol.SelectedItem.Tag='openvpn';$script:Saved=$null;& $Save;Check ($null -eq $Saved) 'Empty OpenVPN source reached controller.';$Count++
$Protocol.SelectedItem.Tag='shadowsocks'
$Profile=[pscustomobject]@{id='captured-exit';node_kind='external';multihop_execution='local'}
foreach($Choice in @('local','server','auto')){
    $Profile.multihop_execution=$Choice
    Check ((GetUnifiedExternalSavedExecution $Profile) -ceq $Choice) 'Saved external execution was not restored.'
    $Body=NewUnifiedExternalConnectBody $Profile 'captured-entry' $Choice $false
    Check ($Body.profile_id -ceq 'captured-exit' -and $Body.entry_id -ceq 'captured-entry' -and $Body.execution -ceq $Choice -and $Body.Count -eq 3) 'Captured external execution used unrelated fields.'
    $Direct=NewUnifiedExternalConnectBody $Profile '' $Choice $true
    Check ($Direct.direct -and $Direct.execution -ceq 'local' -and -not $Direct.ContainsKey('entry_id')) 'Direct reused Server / Compare.';$Count++
}
Check ((GetUnifiedExternalSavedExecution ([pscustomobject]@{id='legacy';node_kind='external'})) -ceq 'local') 'Legacy external node did not default to Local.';$Count++
foreach($Bad in @('invalid','compare')){
    $Rejected=$false;try{[void](NewUnifiedExternalConnectBody $Profile 'captured-entry' $Bad $false)}catch{$Rejected=$true};Check $Rejected 'Invalid external execution was accepted.';$Count++
}
$Rejected=$false;try{[void](NewUnifiedExternalConnectBody $Profile 'captured-exit' 'local' $false)}catch{$Rejected=$true};Check $Rejected 'Self-hop was accepted.';$Count++
$Profile.multihop_execution='invalid';$Rejected=$false;try{[void](GetUnifiedExternalSavedExecution $Profile)}catch{$Rejected=$true};Check $Rejected 'Invalid saved execution silently changed to Local.';$Count++
$PathCallbacks=@($Shipping.Ast.FindAll({param($Node)
    $Node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $Node.Member.Extent.Text -eq 'Add_Click' -and $Node.Expression.Extent.Text -eq '$Dialog.FindName(''PathConnect'')'
},$true))
Check ($PathCallbacks.Count -eq 1) 'Shipping external path confirmation callback changed.'
$ConfirmPath=$PathCallbacks[0].Arguments[0].ScriptBlock.GetScriptBlock()
$Captured=[pscustomobject]@{id='captured-exit';node_kind='external';external=[pscustomobject]@{protocol='shadowsocks';has_response_probe=$true;has_server_peer=$true}}
$EntryMode=[pscustomobject]@{SelectedValue=''}
$EntryModes=if($Output -and (Test-Path -LiteralPath (Join-Path $Output 'entry-mode-catalog.json'))){@((Get-Content -Raw -LiteralPath (Join-Path $Output 'entry-mode-catalog.json')|ConvertFrom-Json).router_vpn_entry_modes)}else{@((Get-Content -Raw -LiteralPath (Join-Path $Root 'configs/client/modes.json')|ConvertFrom-Json)|Where-Object{$_.id -cnotin @('all','smart-auto','custom')})}
$Entry=[pscustomobject]@{SelectedValue='captured-entry'};$Execution=[pscustomobject]@{SelectedItem=[pscustomobject]@{Tag='server'}}
$Choices=@([pscustomobject]@{id='';display_name='Direct'},[pscustomobject]@{id='captured-entry';node_kind='router-vpn'},[pscustomobject]@{id='external-entry';node_kind='external'})
$Dialog=[pscustomobject]@{Tag=$null;Closed=0};$Dialog|Add-Member ScriptMethod Close {$this.Closed++}
$ErrorText=[pscustomobject]@{Text=''};$RequireEntry=$false;$HasProbe=$true
# Deliberately unrelated Router controls must never supply this request.
$MultihopEntryCombo=[pscustomobject]@{SelectedValue='unrelated-router'};$script:UnifiedExecution='unrelated-execution'
$Captured.external|Add-Member NoteProperty has_openvpn_pairing $false -Force
foreach($ProtocolID in @('wireguard','amneziawg','shadowsocks','hysteria2','socks5','http-connect','https-connect','openvpn')){
    foreach($Choice in @('local','server','auto')){
        $Captured.external.protocol=$ProtocolID;$Captured.external.has_openvpn_pairing=$ProtocolID -ceq 'openvpn';$Execution.SelectedItem.Tag=$Choice;$Dialog.Tag=$null;& $ConfirmPath
        Check ($null -ne $Dialog.Tag -and $Dialog.Tag.profile_id -ceq 'captured-exit' -and $Dialog.Tag.entry_id -ceq 'captured-entry' -and $Dialog.Tag.execution -ceq $Choice) ('Actual path callback changed the captured route: '+$ErrorText.Text);$Count++
    }
}
$Fresh=$Captured|ConvertTo-Json -Depth 6|ConvertFrom-Json;$Fresh.external.has_openvpn_pairing=$false;$script:CurrentPathCatalog=@($Fresh,$Choices[1],$Choices[2]);$Dialog.Tag=$null;& $ConfirmPath;Check ($null -eq $Dialog.Tag) 'Stale OpenVPN pairing eligibility reached controller.';$Count++;$script:CurrentPathCatalog=$null;$Captured.external.has_openvpn_pairing=$false
$Execution.SelectedItem.Tag='server';$Captured.external.has_response_probe=$false;$Dialog.Tag=$null;& $ConfirmPath;Check ($null -eq $Dialog.Tag) 'Actual path callback accepted a missing probe.';$Count++
$Captured.external.has_response_probe=$true;$Entry.SelectedValue='external-entry';$Dialog.Tag=$null;& $ConfirmPath;Check ($null -eq $Dialog.Tag) 'Actual path callback used an ordinary external Server entry.';$Count++
$Entry.SelectedValue='captured-entry';$Captured.external.protocol='wireguard';$Captured.external.has_server_peer=$false;$Dialog.Tag=$null;& $ConfirmPath;Check ($null -eq $Dialog.Tag) 'Packet Server accepted a missing independent peer.';$Count++;$Captured.external.has_server_peer=$true
foreach($Changed in @('removed','duplicate','protocol','peer','probe','entry')){
    $Fresh=$Captured|ConvertTo-Json -Depth 6|ConvertFrom-Json
    $script:CurrentPathCatalog=@($Fresh,$Choices[1],$Choices[2])
    if($Changed -eq 'removed'){$script:CurrentPathCatalog=@($Choices[1])}
    if($Changed -eq 'duplicate'){$script:CurrentPathCatalog+=@($Fresh)}
    if($Changed -eq 'protocol'){$Fresh.external.protocol='amneziawg'}
    if($Changed -eq 'peer'){$Fresh.external.has_server_peer=$false}
    if($Changed -eq 'probe'){$Fresh.external.has_response_probe=$false}
    if($Changed -eq 'entry'){$script:CurrentPathCatalog=@($Fresh,$Choices[2])}
    $Dialog.Tag=$null;& $ConfirmPath;Check ($null -eq $Dialog.Tag) ('Stale path identity accepted: '+$Changed);$Count++
};$script:CurrentPathCatalog=$null
$Entry.SelectedValue='captured-entry';$Captured.external.protocol='openvpn';$Dialog.Tag=$null;& $ConfirmPath;Check ($null -eq $Dialog.Tag) 'Actual path callback accepted missing independent OpenVPN pairing.';$Count++
$Captured.external.protocol='shadowsocks';$script:Connected=$true;$Dialog.Tag=$null;& $ConfirmPath;Check ($null -eq $Dialog.Tag) 'Actual path callback ignored a changed VPN owner.';$Count++
$script:Connected=$false;$Entry.SelectedValue='';$Execution.SelectedItem.Tag='local';$RequireEntry=$true;$Dialog.Tag=$null;& $ConfirmPath;Check ($null -eq $Dialog.Tag) 'Via-entry action silently became Direct.';$Count++
$RequireEntry=$false;$Dialog.Tag=$null;& $ConfirmPath;Check ($null -ne $Dialog.Tag -and $Dialog.Tag.direct -and $Dialog.Tag.execution -ceq 'local' -and -not $Dialog.Tag.ContainsKey('entry_id')) 'Direct callback did not clear the previous entry/execution.';$Count++
# Exercise the exact shipping path-confirmation callback for every native entry.
$Captured=[pscustomobject]@{id='exit';node_kind='external';base_tunnel='wg';multihop_entry_mode='wg';external=[pscustomobject]@{protocol='shadowsocks';has_response_probe=$true;has_server_peer=$false}}
$Choices=@([pscustomobject]@{id='';display_name='Direct'},[pscustomobject]@{id='entry';node_kind='router-vpn';base_tunnel='awg'},[pscustomobject]@{id='external-entry';node_kind='external'})
$Entry.SelectedValue='entry'
foreach($Mode in $EntryModes){foreach($Choice in @('local','server','auto')){
    $EntryMode.SelectedValue=$Mode.id;$Execution.SelectedItem.Tag=$Choice;$Dialog.Tag=$null;& $ConfirmPath
    Check ($null -ne $Dialog.Tag -and $Dialog.Tag.entry_mode -ceq $Mode.id -and $Dialog.Tag.entry_id -ceq 'entry' -and $Dialog.Tag.profile_id -ceq 'exit' -and $Dialog.Tag.execution -ceq $Choice) ('Exact Router entry mode changed: '+$ErrorText.Text)
    if($Output){[IO.File]::WriteAllText((Join-Path $Output ('entry-mode-'+$Mode.id+'-'+$Choice+'.json')),($Dialog.Tag|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))};$Count++
}}
$EntryMode.SelectedValue='';$Execution.SelectedItem.Tag='local';$Dialog.Tag=$null;& $ConfirmPath
Check ($null -ne $Dialog.Tag -and $Dialog.Tag.entry_mode -ceq 'awg2-fast') 'Entry saved AWG base was replaced by the exit or unrelated Router choice.';$Count++
$Choices[1].base_tunnel='wg';$Captured.base_tunnel='awg';$Dialog.Tag=$null;& $ConfirmPath
Check ($null -ne $Dialog.Tag -and $Dialog.Tag.entry_mode -ceq 'wg') 'Entry saved WG base was replaced by the exit base.';$Count++
foreach($Bad in @('all','smart-auto','custom','auto','unknown',' wg')){
    $EntryMode.SelectedValue=$Bad;$Dialog.Tag=$null;& $ConfirmPath;Check ($null -eq $Dialog.Tag) 'Unknown or uncompiled Router mode reached the controller.';$Count++
}
$EntryMode.SelectedValue='wg';$Entry.SelectedValue='external-entry';$Dialog.Tag=$null;& $ConfirmPath;Check ($null -eq $Dialog.Tag) 'Ordinary external entry accepted a Router mode.';$Count++
$Entry.SelectedValue='';$Dialog.Tag=$null;& $ConfirmPath;Check ($null -eq $Dialog.Tag) 'Direct accepted an explicit Router mode.';$Count++
$EntryMode.SelectedValue='';$Dialog.Tag=$null;& $ConfirmPath;Check ($null -ne $Dialog.Tag -and -not $Dialog.Tag.ContainsKey('entry_mode')) 'Direct retained a disabled Router entry mode.';$Count++
$Entry.SelectedValue='external-entry';$Dialog.Tag=$null;& $ConfirmPath;Check ($null -ne $Dialog.Tag -and -not $Dialog.Tag.ContainsKey('entry_mode')) 'External entry retained a disabled Router entry mode.';$Count++
$Entry.SelectedValue='entry';$EntryMode.SelectedValue='wg';$Fresh=$Captured|ConvertTo-Json -Depth 6|ConvertFrom-Json;$Fresh.multihop_entry_mode='hysteria2';$script:CurrentPathCatalog=@($Fresh,$Choices[1]);$Dialog.Tag=$null;& $ConfirmPath;Check ($null -eq $Dialog.Tag) 'Changed saved entry-mode owner was accepted.';$Count++;$script:CurrentPathCatalog=$null
$UnifiedSource=Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $Root 'client/RouterVPN-Windows-UnifiedShell.ps1')
$UnifiedBlock=[regex]::Match($UnifiedSource, '(?ms)^    \$extraState = @''\r?\n(.*?)\r?\n''@')
Check $UnifiedBlock.Success 'Shipping primary Connect source missing.'
$Primary=@([ScriptBlock]::Create($UnifiedBlock.Groups[1].Value).Ast.FindAll({param($Node)$Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq 'UnifiedConnect'},$true))
Check ($Primary.Count -eq 1) 'Shipping primary Connect function changed.'
. ([ScriptBlock]::Create($Primary[0].Extent.Text))
function UnifiedAsyncBusy{return $false}
function UnifiedSelectedProfile{return $Captured}
function Control($Name){throw ('Unrelated Router control read during external Connect: '+$Name)}
function StartUnifiedApiAsync($Label,$Path,$Method,$Body,$Timeout,$Success,$Failure,$Finally){$script:DispatchPath=$Path;$script:DispatchBody=$Body;return $true}
foreach($Choice in @('local','server','auto')){
    $Captured=[pscustomobject]@{id='captured-exit';node_kind='external';multihop_execution=$Choice}
    $script:DispatchPath='';$script:DispatchBody=$null;UnifiedConnect
    Check ($DispatchPath -ceq '/api/external-profile/connect' -and $null -ne $DispatchBody -and $DispatchBody.profile_id -ceq 'captured-exit' -and $DispatchBody.execution -ceq $Choice -and $DispatchBody.Count -eq 2) 'Primary Connect borrowed Router controls or dropped saved external execution.'
    $Captured=[pscustomobject]@{id='replacement';node_kind='router-vpn';multihop_execution='auto'}
    Check ($DispatchBody.profile_id -ceq 'captured-exit' -and $DispatchBody.execution -ceq $Choice) 'Replacement selection changed captured primary request.';$Count++
}
$Captured=[pscustomobject]@{id='captured-exit';node_kind='external';multihop_execution='invalid'};$script:DispatchBody=$null;UnifiedConnect;Check ($null -eq $DispatchBody) 'Invalid external execution fell through to Router connect.';$Count++
# Use the real catalog lookup for failure paths; no Router controls may be read.
$Lookup=@([ScriptBlock]::Create($UnifiedBlock.Groups[1].Value).Ast.FindAll({param($Node)$Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq 'UnifiedSelectedProfile'},$true))
Check ($Lookup.Count -eq 1) 'Shipping selected-node lookup changed.'
. ([ScriptBlock]::Create($Lookup[0].Extent.Text))
$CatalogCase='failure';$script:RouterReads=0
function Control($Name){$script:RouterReads++;throw ('Unrelated Router control read: '+$Name)}
function Api($Path,$Method='GET',$Body=$null,$Timeout=0){
    if($Path -eq '/api/status'){return [pscustomobject]@{connected=$false;phase='off'}}
    if($Path -ne '/api/profiles'){throw 'Unexpected request during unavailable selection.'}
    if($CatalogCase -eq 'failure'){throw 'Catalog unavailable'}
    if($CatalogCase -eq 'missing'){return [pscustomobject]@{selected_id='captured-exit';profiles=@()}}
    if($CatalogCase -eq 'wrong'){return [pscustomobject]@{selected_id='captured-exit';profiles=@([pscustomobject]@{id='other';node_kind='external'})}}
    if($CatalogCase -eq 'duplicate'){return [pscustomobject]@{selected_id='captured-exit';profiles=@([pscustomobject]@{id='captured-exit';node_kind='external'},[pscustomobject]@{id='captured-exit';node_kind='router-vpn'})}}
    if($CatalogCase -eq 'unknown'){return [pscustomobject]@{selected_id='captured-exit';profiles=@([pscustomobject]@{id='captured-exit';node_kind='unknown'})}}
    return [pscustomobject]@{}
}
foreach($CatalogCase in @('failure','missing','wrong','duplicate','unknown','malformed')){
    $script:DispatchPath='';$script:DispatchBody=$null;$script:RouterReads=0;UnifiedConnect
    Check ($null -eq $DispatchBody -and -not $DispatchPath -and $RouterReads -eq 0) 'Unavailable selected identity fell through to unrelated Router controls.';$Count++
}
function UnifiedSelectedProfile{return $Captured}
# Negative control: reading the unrelated Router toggle first reproduces the bug
# and must prevent the external dispatch that the positive controls require.
$Broken=$Primary[0].Extent.Text.Replace('$P=UnifiedSelectedProfile',"if((Control 'UnifiedMultihop').IsChecked){return};"+'$P=UnifiedSelectedProfile')
Check ($Broken -cne $Primary[0].Extent.Text) 'Primary priority negative control did not mutate source.'
. ([ScriptBlock]::Create($Broken));$Captured=[pscustomobject]@{id='captured-exit';node_kind='external';multihop_execution='server'};$script:DispatchBody=$null;UnifiedConnect
Check ($null -eq $DispatchBody) 'Primary priority negative control was not rejected.';$Count++
Write-Host ('PASS shipping Windows external Save and captured connection callbacks: '+$Count+' cases')
