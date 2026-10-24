Set-StrictMode -Version Latest
# Direct controller endpoint: /api/tor-bridge/connect. The unified Windows UI
# connects a selected Tor node through /api/external-profile/connect so the
# shared connection-operation owner can dispatch to torBridgeConnectOwned.

function Add-RouterVPNExternalNodeWindowsShell {
    param([Parameter(Mandatory=$true)][string]$ProductSource)

    $nodeOld = '<StackPanel Orientation="Horizontal"><TextBlock Text="Node" FontWeight="SemiBold" Margin="0,0,8,0" VerticalAlignment="Center"/><ComboBox Name="UnifiedNodeCombo" DisplayMemberPath="display_name" SelectedValuePath="id" MinWidth="260"/><Button Name="UnifiedNodesButton" Content="Add / manage nodes" Margin="8,0,0,0" Padding="10,5"/><Button Name="UnifiedTorButton" Content="Tor bridges…" Margin="6,0,0,0" Padding="10,5"/></StackPanel>'
    $nodeNew = '<StackPanel Orientation="Horizontal"><TextBlock Text="Node" FontWeight="SemiBold" Margin="0,0,8,0" VerticalAlignment="Center"/><ComboBox Name="UnifiedNodeCombo" DisplayMemberPath="display_name" SelectedValuePath="id" MinWidth="260"/><Button Name="UnifiedNodesButton" Content="Add / manage nodes" Margin="8,0,0,0" Padding="10,5"/><Button Name="UnifiedExternalNodeButton" Content="Add external node…" Margin="6,0,0,0" Padding="10,5"/><Button Name="UnifiedTorButton" Content="Tor bridges…" Margin="6,0,0,0" Padding="10,5"/></StackPanel>'
    if(-not $ProductSource.Contains($nodeOld)){throw 'Windows external-node UI: unified node row drifted.'}
    $ProductSource=$ProductSource.Replace($nodeOld,$nodeNew)

    $stateMarker='$script:EventSeq=[uint64]0;$script:Busy=$false;$script:NodeSort=''current'';$script:DnsPolicySummary=''Saved DNS policy not loaded yet.'''
    if(-not $ProductSource.Contains($stateMarker)){throw 'Windows external-node UI: product state marker drifted.'}
    $functions=@'
function TestUnifiedExternalMutationIdle{
    try{
        $S=Api '/api/status' -Timeout 4
        $Phase=([string]$S.phase).Trim().ToLowerInvariant()
        return (-not [bool]$S.connected) -and ($Phase -eq '' -or $Phase -eq 'off' -or $Phase -eq 'failed')
    }catch{return $false}
}
function SplitUnifiedExternalCsv([string]$Text){
    return @($Text -split ',' | ForEach-Object{$_.Trim()} | Where-Object{$_})
}
function ParseUnifiedExternalAmneziaParameters([string]$Text){
    if([System.Text.Encoding]::UTF8.GetByteCount($Text) -gt 4096){throw 'AmneziaWG parameters are too long.'}
    $Keys=@('jc','jmin','jmax','s1','s2','s3','s4','h1','h2','h3','h4')
    $Values=@{}
    foreach($Line in ($Text -split '[;\r\n]')){
        if(-not $Line.Trim()){continue}
        $Parts=@($Line -split '=')
        if($Parts.Count -ne 2){throw 'Use one AmneziaWG key=value per line, or separate values with semicolons.'}
        $Key=$Parts[0].Trim().ToLowerInvariant();$Value=$Parts[1].Trim()
        $Pattern='^[0-9]+$';if($Key.StartsWith('h')){$Pattern='^[0-9]+(-[0-9]+)?$'}
        if($Key -notin $Keys -or $Values.ContainsKey($Key) -or $Value -cnotmatch $Pattern){throw 'AmneziaWG parameters contain an unknown, duplicate or malformed value.'}
        $Values[$Key]=$Value
    }
    if($Values.Count -ne $Keys.Count){throw 'Supply all 11 provider values: Jc, Jmin, Jmax, S1-S4 and H1-H4.'}
    return $Values
}
function ExternalPublicValue($Object,[string]$Name,$Default=''){
    if($null-eq$Object){return $Default}
    if($Object -is [System.Collections.IDictionary]){if($Object.Contains($Name)){return $Object[$Name]};return $Default}
    $Property=$Object.PSObject.Properties[$Name];if($null-ne$Property){return $Property.Value};return $Default
}
function GetUnifiedExternalSavedExecution($Profile){
    $Value=[string](ExternalPublicValue $Profile 'multihop_execution' 'local')
    if(-not $Value){return 'local'}
    if($Value -cnotin @('local','server','auto')){throw 'The selected external node has an invalid saved execution choice.'}
    return $Value
}
function NewUnifiedExternalConnectBody($Profile,[string]$EntryID,[string]$Execution,[bool]$Direct){
    $ID=[string](ExternalPublicValue $Profile 'id');$Kind=[string](ExternalPublicValue $Profile 'node_kind')
    if(-not $ID -or $Kind -ne 'external'){throw 'Select an external node first.'}
    if($Execution -cnotin @('local','server','auto')){throw 'Choose Local, Server or Compare both.'}
    if($Direct){return @{profile_id=$ID;direct=$true;execution='local'}}
    if($EntryID -eq $ID){throw 'External entry and exit must be different nodes.'}
    $Body=@{profile_id=$ID;execution=$Execution}
    if($EntryID){$Body.entry_id=$EntryID}
    return $Body
}
function GetUnifiedExternalPathIdentity($Profile){
    $External=ExternalPublicValue $Profile 'external' $null
    return (@([string](ExternalPublicValue $Profile 'id'),[string](ExternalPublicValue $Profile 'node_kind'),[string](ExternalPublicValue $Profile 'endpoint'),[string](ExternalPublicValue $Profile 'start_layer'),[string](ExternalPublicValue $Profile 'multihop_entry_mode'),[string](ExternalPublicValue $External 'protocol'),[string](ExternalPublicValue $External 'expected_public_ip'),(ExternalPublicValue $External 'has_response_probe' $false),(ExternalPublicValue $External 'has_server_peer' $false))|ConvertTo-Json -Compress)
}
function GetUnifiedExternalEntryMode($Captured,$Entry,[string]$Selected,$Modes){
    $Kind=[string](ExternalPublicValue $Entry 'node_kind' 'router-vpn')
    if($null-eq$Entry -or ($Kind -and $Kind -cne 'router-vpn')){
        if($Selected){throw 'An entry mode applies only to a Router VPN entry.'}
        return ''
    }
    $Mode=$Selected
    if(-not $Mode){
        $Base=[string](ExternalPublicValue $Entry 'base_tunnel')
        if($Base -cnotin @('wg','awg')){$Base=[string](ExternalPublicValue $Captured 'base_tunnel')}
        $Mode=if($Base -ceq 'awg'){'awg2-fast'}else{'wg'}
    }
    $Found=@($Modes|Where-Object{[string](ExternalPublicValue $_ 'id') -ceq $Mode})
    if($Found.Count -ne 1){throw 'Choose an exact Router entry mode from the current native catalog.'}
    return $Mode
}
function NewUnifiedExternalPathBody($Captured,[string]$EntryID,[string]$Execution,[bool]$Direct,$Current,$EntryMode=$null,$EntryModes=@()){
    $ID=[string](ExternalPublicValue $Captured 'id')
    $Matches=@($Current|Where-Object{[string](ExternalPublicValue $_ 'id') -ceq $ID})
    if($Matches.Count -ne 1 -or (GetUnifiedExternalPathIdentity $Matches[0]) -cne (GetUnifiedExternalPathIdentity $Captured)){throw 'The external node changed while this dialog was open. Reopen its path settings.'}
    if(-not $Direct){
        $Entries=@($Current|Where-Object{[string](ExternalPublicValue $_ 'id') -ceq $EntryID})
        if(-not $EntryID -or $Entries.Count -ne 1){throw 'The selected entry is missing or ambiguous. Choose it again.'}
    }
    if($Execution -cne 'local'){
        $External=ExternalPublicValue $Matches[0] 'external' $null;$Protocol=[string](ExternalPublicValue $External 'protocol')
        if($Protocol -cnotin @('wireguard','amneziawg','shadowsocks','hysteria2','socks5','http-connect','https-connect')){throw 'Server / Compare requires a supported authenticated external transport.'}
        if((ExternalPublicValue $External 'has_response_probe' $false) -isnot [bool] -or (ExternalPublicValue $External 'has_response_probe' $false) -cne $true){throw 'Server / Compare requires this external node HTTPS response probe.'}
        if($Protocol -cin @('wireguard','amneziawg') -and ((ExternalPublicValue $External 'has_server_peer' $false) -isnot [bool] -or (ExternalPublicValue $External 'has_server_peer' $false) -cne $true)){throw 'WireGuard / AmneziaWG Server / Compare requires a separately provisioned server peer.'}
        if($Direct -or [string](ExternalPublicValue $Entries[0] 'node_kind' 'router-vpn') -cne 'router-vpn'){throw 'Server / Compare requires a Router VPN entry.'}
    }
    $Body=NewUnifiedExternalConnectBody $Captured $EntryID $Execution $Direct
    if($null-ne$EntryMode){
        $SelectedEntry=if($Direct){$null}else{$Entries[0]}
        $Mode=GetUnifiedExternalEntryMode $Captured $SelectedEntry ([string]$EntryMode) $EntryModes
        if($Mode){$Body.entry_mode=$Mode}
    }
    return $Body
}
function AddUnifiedExternalServerPeer($Body,[string]$Protocol,[string]$PublicKey,[string]$Addresses,[string]$MTUText,[string]$KeepaliveText){
    $PublicKey=$PublicKey.Trim();$Addresses=$Addresses.Trim();$MTUText=$MTUText.Trim();$KeepaliveText=$KeepaliveText.Trim()
    if(-not ($PublicKey -or $Addresses -or $MTUText -or $KeepaliveText)){return}
    if($Protocol -cnotin @('wireguard','amneziawg')){throw 'Server peer fields apply only to WireGuard or AmneziaWG.'}
    $MTU=0;$Keepalive=0;$IPs=@(SplitUnifiedExternalCsv $Addresses)
    if(-not $PublicKey -or $IPs.Count -lt 1 -or $IPs.Count -gt 2 -or -not [int]::TryParse($MTUText,[ref]$MTU) -or $MTU -lt 1280 -or $MTU -gt 9000){throw 'Supply the separately provisioned server peer public key, one address per IP family, and MTU 1280–9000.'}
    try{$KeyBytes=[Convert]::FromBase64String($PublicKey);if($KeyBytes.Length -ne 32 -or [Convert]::ToBase64String($KeyBytes) -cne $PublicKey){throw 'invalid'}}catch{throw 'Server peer public key must be canonical 32-byte Base64.'}
    $Peer=@{public_key=$PublicKey;addresses=$IPs;mtu=$MTU}
    if($KeepaliveText){if(-not [int]::TryParse($KeepaliveText,[ref]$Keepalive) -or $Keepalive -lt 0 -or $Keepalive -gt 65535){throw 'Server peer keepalive must be 0–65535 seconds.'};$Peer.persistent_keepalive_interval=$Keepalive}
    $Body.server_peer=$Peer
}
function ShowUnifiedExternalPath([string]$ProfileID='',[bool]$RequireEntry=$false){
    if(-not(TestUnifiedExternalMutationIdle)){Log 'Disconnect or let the active VPN transition finish before choosing an external path.';return}
    try{
        $Store=Api '/api/nodes' -Timeout 5
        if(-not $ProfileID){$ProfileID=[string]$Store.selected_id}
        $Matches=@($Store.profiles|Where-Object{[string]$_.id -ceq $ProfileID})
        if($Matches.Count -ne 1 -or [string]$Matches[0].node_kind -ne 'external'){throw 'Select an external node first.'}
        $Captured=$Matches[0];$SavedExecution=GetUnifiedExternalSavedExecution $Captured
        $Capabilities=Api '/api/external-profile/capabilities' -Timeout 5
        $EntryModes=@(ExternalPublicValue $Capabilities 'router_vpn_entry_modes' @())
        $SavedMode=[string](ExternalPublicValue $Captured 'multihop_entry_mode')
        if($SavedMode -and @($EntryModes|Where-Object{[string]$_.id -ceq $SavedMode}).Count -ne 1){throw 'The saved Router entry mode is missing from the current native catalog.'}
        $SavedEntry=if([bool](ExternalPublicValue $Captured 'multihop_enabled' $false)){[string](ExternalPublicValue $Captured 'multihop_entry_id')}else{''}
        [xml]$PathX=@"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="External path" Width="650" Height="560" MinHeight="450" WindowStartupLocation="CenterOwner" Background="#0B1020" Foreground="#F5F7FF"><ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel Margin="22">
<TextBlock Name="PathNode" FontSize="21" FontWeight="Bold" TextWrapping="Wrap"/>
<TextBlock Text="Entry" Margin="0,14,0,4"/><ComboBox Name="PathEntry" DisplayMemberPath="display_name" SelectedValuePath="id"/>
<TextBlock Text="Router entry mode" Margin="0,14,0,4"/><ComboBox Name="PathEntryMode" DisplayMemberPath="name" SelectedValuePath="id"/>
<TextBlock Text="The exact selected mode and the entry node's saved Start Layer are used. Compatibility and path proof are checked before Connected." TextWrapping="Wrap" Foreground="#A8B6D5" Margin="0,6,0,0"/>
<TextBlock Text="External execution" Margin="0,14,0,4"/><ComboBox Name="PathExecution"><ComboBoxItem Content="Local — exit runs on this device" Tag="local"/><ComboBoxItem Content="Server — exit runs on Router entry" Tag="server"/><ComboBoxItem Content="Compare both — lowest valid average" Tag="auto"/></ComboBox>
<TextBlock Text="Server / Compare requires a Router entry, an authenticated external exit, and its saved HTTPS response probe. WireGuard / AmneziaWG also needs a separately provisioned server peer. Pairing and actual path proof are checked when connecting. Direct uses Local. A successful connection saves this node's choice." TextWrapping="Wrap" Foreground="#A8B6D5" Margin="0,12"/>
<TextBlock Name="PathReadiness" TextWrapping="Wrap" Foreground="#A8B6D5"/><TextBlock Name="PathError" TextWrapping="Wrap" Foreground="#FFCC8A" Margin="0,8"/>
<StackPanel Orientation="Horizontal" HorizontalAlignment="Right"><Button Name="PathConnect" Content="Connect selected path" Padding="12,8"/><Button Name="PathCancel" Content="Cancel" Padding="12,8" Margin="8,0,0,0"/></StackPanel>
</StackPanel></ScrollViewer></Window>
"@
        $Reader=New-Object System.Xml.XmlNodeReader $PathX;$Dialog=[Windows.Markup.XamlReader]::Load($Reader);$Dialog.Owner=$Window
        $Entry=$Dialog.FindName('PathEntry');$EntryMode=$Dialog.FindName('PathEntryMode');$Execution=$Dialog.FindName('PathExecution');$ErrorText=$Dialog.FindName('PathError')
        $Dialog.FindName('PathNode').Text=[string]$Captured.name
        $Choices=@([pscustomobject]@{id='';display_name='Direct — no entry'})+@($Store.profiles|Where-Object{[string]$_.id -cne $ProfileID})
        $Entry.ItemsSource=$Choices;$Entry.SelectedIndex=0
        if($SavedEntry){$Entry.SelectedValue=$SavedEntry;if($Entry.SelectedIndex -lt 0){throw 'The saved external entry is missing. Relink it or select Direct explicitly.'}}
        $Execution.SelectedIndex=@('local','server','auto').IndexOf($SavedExecution)
        $EntryMode.ItemsSource=@([pscustomobject]@{id='';name="Use selected entry's saved base"})+$EntryModes
        $EntryMode.SelectedValue=$SavedMode
        $UpdatePathEntry={
            $Direct=-not [string]$Entry.SelectedValue
            $Selected=@($Choices|Where-Object{[string]$_.id -ceq [string]$Entry.SelectedValue})
            $Kind=if($Selected.Count -eq 1){[string](ExternalPublicValue $Selected[0] 'node_kind' 'router-vpn')}else{'external'}
            $RouterEntry=(-not $Direct) -and (-not $Kind -or $Kind -ceq 'router-vpn')
            $EntryMode.IsEnabled=$RouterEntry
            if(-not $RouterEntry){$EntryMode.SelectedValue=''}
            $Execution.IsEnabled=-not $Direct
            if($Direct){$Execution.SelectedIndex=0}
        }
        & $UpdatePathEntry
        if(-not [string]$Entry.SelectedValue){$Execution.SelectedIndex=0;$Execution.IsEnabled=$false}
        $Entry.Add_SelectionChanged($UpdatePathEntry)
        $HasProbe=[bool](ExternalPublicValue (ExternalPublicValue $Captured 'external' $null) 'has_response_probe' $false)
        $Dialog.FindName('PathReadiness').Text=if($HasProbe){'HTTPS response probe saved; server pairing and native proof remain pending.'}else{'No HTTPS response probe saved. Import or create a provisioned external node before choosing Server / Compare.'}
        $Dialog.FindName('PathCancel').Add_Click({$Dialog.Close()})
        $Dialog.FindName('PathConnect').Add_Click({
            try{
                if(-not(TestUnifiedExternalMutationIdle)){throw 'VPN state changed while the path dialog was open. Nothing was connected.'}
                $EntryID=[string]$Entry.SelectedValue;$Direct=-not $EntryID
                if($RequireEntry -and $Direct){throw 'Choose an entry for this via-entry connection.'}
                $Choice=[string]$Execution.SelectedItem.Tag
                $Current=Api '/api/nodes' -Timeout 5
                $Body=NewUnifiedExternalPathBody $Captured $EntryID $Choice $Direct @($Current.profiles) ([string]$EntryMode.SelectedValue) $EntryModes
                $Dialog.Tag=$Body;$Dialog.Close()
            }catch{$ErrorText.Text=$_.Exception.Message}
        })
        [void]$Dialog.ShowDialog()
        if($null-ne$Dialog.Tag){$Body=$Dialog.Tag;[void](StartUnifiedApiAsync 'Connecting external path…' '/api/external-profile/connect' 'POST' $Body 180 {param($R)Log 'External selected path passed connection proof.'} {param($E)Log ('External path failed: '+$E)} $null)}
    }catch{Log ('External path: '+$_.Exception.Message)}
}
function AddUnifiedExternalTransportFields($Body,[string]$Protocol,[string]$Server,[string]$ProbeURL,[string]$ProbeName,[string]$Layer,[string]$LayerAPI,[string]$LayerPort,[string]$LayerKey){
    $Proxies=@('wireguard','amneziawg','shadowsocks','hysteria2','socks5','http-connect','https-connect')
    $ProbeURL=$ProbeURL.Trim();$ProbeName=$ProbeName.Trim();$LayerAPI=$LayerAPI.Trim();$LayerPort=$LayerPort.Trim()
    if($Layer -cnotin @('off','aes-256-gcm','aes-256-gcm+xor-whitening')){throw 'Choose a supported external Start Layer.'}
    if(($ProbeURL -or $ProbeName -or $Layer -ne 'off' -or $LayerAPI -or $LayerPort -or $LayerKey) -and $Protocol -cnotin $Proxies){throw 'Response probes and external Start Layers require a supported external transport.'}
    if($ProbeName -and -not $ProbeURL){throw 'Supply the HTTPS response URL with its certificate server name.'}
    if($ProbeURL){$Body.response_probe=@{url=$ProbeURL;server_name=$ProbeName}}
    $Body.start_layer=$Layer
    if($Layer -eq 'off'){
        if($LayerAPI -or $LayerPort -or $LayerKey){throw 'Select a Start Layer before supplying its provisioned credentials.'}
        return
    }
    $Port=0;if(-not [int]::TryParse($LayerPort,[ref]$Port) -or $Port -lt 1 -or $Port -gt 65535 -or -not $LayerAPI -or -not $LayerKey){throw 'An active Start Layer requires its private API, AES port (1–65535), and key.'}
    $Body.start_layer_provision=@{mode=$Layer;api=$LayerAPI;transport=@{type='shadowsocks';tag='provisioned-exit-layer';server=$Server.Trim();server_port=$Port;method='2022-blake3-aes-256-gcm';password=$LayerKey}}
}
function ShowUnifiedExternalNodeBuilder{
    if(-not(TestUnifiedExternalMutationIdle)){Log 'Disconnect or let the active VPN transition finish before adding an external node. Unknown controller state fails closed.';return}
    [xml]$X=@"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="Add external node" Width="820" Height="760" MinWidth="680" MinHeight="600" WindowStartupLocation="CenterOwner" Background="#0B1020" Foreground="#F5F7FF">
  <ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel Margin="22">
    <TextBlock Text="Add external node" FontSize="26" FontWeight="Bold"/>
    <TextBlock Margin="0,8,0,14" Foreground="#A8B6D5" TextWrapping="Wrap" Text="Create a full-device external node. OpenVPN uses Import; Tor uses Tor bridges. Home AdGuard is the default through a Router entry. For Direct, choose a resolver in DNS."/>
    <TextBlock Text="Protocol"/><ComboBox Name="ExtProtocol" Margin="0,4,0,10"><ComboBoxItem Content="WireGuard" Tag="wireguard"/><ComboBoxItem Content="AmneziaWG" Tag="amneziawg"/><ComboBoxItem Content="SOCKS5" Tag="socks5"/><ComboBoxItem Content="HTTP CONNECT" Tag="http-connect"/><ComboBoxItem Content="HTTPS CONNECT" Tag="https-connect"/><ComboBoxItem Content="Shadowsocks" Tag="shadowsocks"/><ComboBoxItem Content="Hysteria2" Tag="hysteria2"/></ComboBox>
    <TextBlock Text="Display name"/><TextBox Name="ExtName" Margin="0,4,0,8" Padding="7"/>
    <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="170"/></Grid.ColumnDefinitions><StackPanel Margin="0,0,6,0"><TextBlock Text="Server IP / hostname"/><TextBox Name="ExtServer" Margin="0,4,0,8" Padding="7"/></StackPanel><StackPanel Grid.Column="1" Margin="6,0,0,0"><TextBlock Text="Port"/><TextBox Name="ExtPort" Margin="0,4,0,8" Padding="7"/></StackPanel></Grid>
    <TextBlock Text="Expected public exit IP"/><TextBox Name="ExtExpected" Margin="0,4,0,8" Padding="7"/>
    <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions><StackPanel Margin="0,0,6,0"><TextBlock Text="Username (proxy only)"/><TextBox Name="ExtUser" Margin="0,4,0,8" Padding="7"/></StackPanel><StackPanel Grid.Column="1" Margin="6,0,0,0"><TextBlock Text="Password / proxy credential"/><PasswordBox Name="ExtPassword" Margin="0,4,0,8" Padding="7"/></StackPanel></Grid>
    <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions><StackPanel Margin="0,0,6,0"><TextBlock Text="Shadowsocks method"/><TextBox Name="ExtMethod" Margin="0,4,0,8" Padding="7"/></StackPanel><StackPanel Grid.Column="1" Margin="6,0,0,0"><TextBlock Text="Shadowsocks / Hysteria2 secret"/><PasswordBox Name="ExtSecret" Margin="0,4,0,8" Padding="7"/></StackPanel></Grid>
    <TextBlock Text="TLS server name / SNI (HTTPS CONNECT or Hysteria2)"/><TextBox Name="ExtTLS" Margin="0,4,0,8" Padding="7"/>
    <Separator Margin="0,8"/>
    <TextBlock Text="External Server / Compare and Start Layer" FontWeight="SemiBold"/>
    <TextBlock Foreground="#A8B6D5" TextWrapping="Wrap" Text="Optional for WireGuard, AmneziaWG, Shadowsocks, Hysteria2 and authenticated SOCKS5 / HTTP(S). Server and Compare require a Router entry plus an HTTPS response probe on this server's public IP. Use only a Start Layer provisioned by that server; AES + XOR keeps authenticated encryption."/>
    <TextBlock Text="HTTPS response URL on this external server"/><TextBox Name="ExtResponseURL" Margin="0,4,0,8" Padding="7"/>
    <TextBlock Text="Response certificate server name (when needed)"/><TextBox Name="ExtResponseName" Margin="0,4,0,8" Padding="7"/>
    <TextBlock Text="External Start Layer"/><ComboBox Name="ExtStartLayer" SelectedIndex="0" Margin="0,4,0,8"><ComboBoxItem Content="Off" Tag="off"/><ComboBoxItem Content="AES-256-GCM" Tag="aes-256-gcm"/><ComboBoxItem Content="AES-256-GCM + XOR whitening" Tag="aes-256-gcm+xor-whitening"/></ComboBox>
    <TextBlock Text="Provisioned layer private API URL"/><TextBox Name="ExtLayerAPI" Margin="0,4,0,8" Padding="7"/>
    <TextBlock Text="Provisioned AES transport port"/><TextBox Name="ExtLayerPort" Margin="0,4,0,8" Padding="7"/>
    <TextBlock Text="Provisioned AES key (32-byte Base64)"/><PasswordBox Name="ExtLayerKey" Margin="0,4,0,8" Padding="7"/>
    <Separator Margin="0,8"/>
    <TextBlock Text="WireGuard / AmneziaWG peer" FontWeight="SemiBold"/>
    <TextBlock Text="Private key"/><PasswordBox Name="ExtWGPrivate" Margin="0,4,0,8" Padding="7"/>
    <TextBlock Text="Peer public key"/><TextBox Name="ExtWGPeer" Margin="0,4,0,8" Padding="7"/>
    <TextBlock Text="Preshared key (optional)"/><PasswordBox Name="ExtWGPSK" Margin="0,4,0,8" Padding="7"/>
    <TextBlock Text="Interface addresses — comma separated CIDRs"/><TextBox Name="ExtWGAddresses" Margin="0,4,0,8" Padding="7"/>
    <TextBlock Text="AllowedIPs — comma separated CIDRs"/><TextBox Name="ExtWGAllowed" Margin="0,4,0,8" Padding="7"/>
    <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="170"/></Grid.ColumnDefinitions><StackPanel Margin="0,0,6,0"><TextBlock Text="DNS IPs — comma separated"/><TextBox Name="ExtWGDNS" Margin="0,4,0,8" Padding="7"/></StackPanel><StackPanel Grid.Column="1" Margin="6,0,0,0"><TextBlock Text="MTU (optional)"/><TextBox Name="ExtWGMTU" Margin="0,4,0,8" Padding="7"/></StackPanel></Grid>
    <TextBlock Text="Keepalive seconds — 0–65535; blank means disabled"/><TextBox Name="ExtWGKeepalive" Margin="0,4,0,8" Padding="7"/>
    <TextBlock Text="AmneziaWG parameters — copy all 11 values from your provider"/>
    <TextBlock Foreground="#A8B6D5" TextWrapping="Wrap" Margin="0,4,0,4" Text="Use Jc=…; Jmin=…; Jmax=…; S1=…; S2=…; S3=…; S4=…; H1=…; H2=…; H3=…; H4=…. You can paste one key=value per line. Header ranges are preserved."/>
    <TextBox Name="ExtAWGParameters" AcceptsReturn="True" VerticalScrollBarVisibility="Auto" Height="100" Margin="0,4,0,8" Padding="7" MaxLength="4096"/>
    <TextBlock Text="Separate server peer — WireGuard / AmneziaWG Server and Compare" FontWeight="SemiBold" Margin="0,8,0,4"/>
    <TextBlock Foreground="#A8B6D5" TextWrapping="Wrap" Text="Optional for Local. Copy the public descriptor of the separate client peer provisioned on the Router entry. Its addresses and public identity must differ from this device. Keep its private key and preshared key on the server; the peer public key above still identifies the remote provider."/>
    <TextBlock Text="Server-side client public key"/><TextBox Name="ExtServerPeerPublic" Margin="0,4,0,8" Padding="7"/>
    <TextBlock Text="Server peer addresses — one CIDR per family, comma separated"/><TextBox Name="ExtServerPeerAddresses" Margin="0,4,0,8" Padding="7"/>
    <TextBlock Text="Server peer MTU — required with descriptor, 1280–9000"/><TextBox Name="ExtServerPeerMTU" Margin="0,4,0,8" Padding="7"/>
    <TextBlock Text="Server peer keepalive seconds — optional, 0–65535"/><TextBox Name="ExtServerPeerKeepalive" Margin="0,4,0,8" Padding="7"/>
    <TextBlock Foreground="#A8B6D5" TextWrapping="Wrap" Margin="0,6,0,8" Text="Plain HTTP CONNECT never accepts TLS metadata. HTTPS CONNECT and Hysteria2 require TLS/SNI. The typed maker never accepts executable paths, arbitrary sing-box JSON, Tor directives, or raw OpenVPN configuration."/>
    <TextBlock Name="ExtStatus" Foreground="#FFCC8A" TextWrapping="Wrap" Margin="0,0,0,10"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right"><Button Name="ExtSave" Content="Save node" Padding="14,8"/><Button Name="ExtClose" Content="Close" Margin="8,0,0,0" Padding="14,8"/></StackPanel>
  </StackPanel></ScrollViewer>
</Window>
"@
    $reader=New-Object System.Xml.XmlNodeReader $X;$D=[Windows.Markup.XamlReader]::Load($reader);$D.Owner=$W
    $Protocol=$D.FindName('ExtProtocol');$Protocol.SelectedIndex=0;$Status=$D.FindName('ExtStatus')
    $D.FindName('ExtClose').Add_Click({$D.Close()})
    $D.FindName('ExtSave').Add_Click({
        try{
            if(-not(TestUnifiedExternalMutationIdle)){throw 'VPN state changed while the external-node dialog was open. Nothing was saved.'}
            $ID=[string](($Protocol.SelectedItem).Tag)
            $PortText=[string]$D.FindName('ExtPort').Text;$Port=0;if($PortText.Trim()){$Port=[int]$PortText}
            $Body=@{name=[string]$D.FindName('ExtName').Text;protocol=$ID;server=[string]$D.FindName('ExtServer').Text;port=$Port;expected_public_ip=[string]$D.FindName('ExtExpected').Text}
            if($ID -in @('socks5','http-connect','https-connect')){$Body.username=[string]$D.FindName('ExtUser').Text;$Body.password=[string]$D.FindName('ExtPassword').Password}
            if($ID -eq 'https-connect'){$Body.tls_server_name=[string]$D.FindName('ExtTLS').Text}
            if($ID -eq 'shadowsocks'){$Body.method=[string]$D.FindName('ExtMethod').Text;$Body.secret=[string]$D.FindName('ExtSecret').Password}
            if($ID -eq 'hysteria2'){$Body.secret=[string]$D.FindName('ExtSecret').Password;$Body.tls_server_name=[string]$D.FindName('ExtTLS').Text}
            if($ID -in @('wireguard','amneziawg')){
                $Body.wg_private_key=[string]$D.FindName('ExtWGPrivate').Password
                $Body.wg_peer_public_key=[string]$D.FindName('ExtWGPeer').Text
                $Body.wg_addresses=@(SplitUnifiedExternalCsv ([string]$D.FindName('ExtWGAddresses').Text))
                $Body.wg_allowed_ips=@(SplitUnifiedExternalCsv ([string]$D.FindName('ExtWGAllowed').Text))
                $Body.wg_dns=@(SplitUnifiedExternalCsv ([string]$D.FindName('ExtWGDNS').Text))
                $PSK=[string]$D.FindName('ExtWGPSK').Password;if($PSK.Trim()){$Body.wg_preshared_key=$PSK}
                $MTUText=[string]$D.FindName('ExtWGMTU').Text;if($MTUText.Trim()){$MTU=[int]$MTUText;if($MTU -lt 1280 -or $MTU -gt 9000){throw 'WireGuard / AmneziaWG MTU must be 1280–9000.'};$Body.wg_mtu=$MTU}
                $KeepaliveText=[string]$D.FindName('ExtWGKeepalive').Text;if($KeepaliveText.Trim()){$Keepalive=[int]$KeepaliveText;if($Keepalive -lt 0 -or $Keepalive -gt 65535){throw 'Keepalive must be 0–65535 seconds.'};$Body.wg_keepalive=$Keepalive}
                if($ID -eq 'amneziawg'){$Body.awg_parameters=ParseUnifiedExternalAmneziaParameters ([string]$D.FindName('ExtAWGParameters').Text)}
            }
            AddUnifiedExternalServerPeer $Body $ID ([string]$D.FindName('ExtServerPeerPublic').Text) ([string]$D.FindName('ExtServerPeerAddresses').Text) ([string]$D.FindName('ExtServerPeerMTU').Text) ([string]$D.FindName('ExtServerPeerKeepalive').Text)
            AddUnifiedExternalTransportFields $Body $ID ([string]$D.FindName('ExtServer').Text) ([string]$D.FindName('ExtResponseURL').Text) ([string]$D.FindName('ExtResponseName').Text) ([string]$D.FindName('ExtStartLayer').SelectedItem.Tag) ([string]$D.FindName('ExtLayerAPI').Text) ([string]$D.FindName('ExtLayerPort').Text) ([string]$D.FindName('ExtLayerKey').Password)
            $R=Api '/api/external-profile/create' 'POST' $Body 25;$Status.Text='External node saved and selected. Use a Router entry for Home AdGuard, or choose a resolver in DNS for Direct.';Log ('External node saved: '+[string]$R.profile.name);RefreshProduct
        }catch{$Status.Text='External node rejected: '+$_.Exception.Message}
    })
    [void]$D.ShowDialog()
}
'@
    $ProductSource=$ProductSource.Replace($stateMarker,$functions+"`r`n"+$stateMarker)
    $eventMarker="(Control 'UnifiedNodesButton').Add_Click({OpenUnifiedDetail 1})"
    if(-not $ProductSource.Contains($eventMarker)){throw 'Windows external-node UI: unified node event seam drifted.'}
    $ProductSource=$ProductSource.Replace($eventMarker,$eventMarker+"`r`n(Control 'UnifiedExternalNodeButton').Add_Click({ShowUnifiedExternalNodeBuilder})`r`n(Control 'UnifiedExternalPathButton').Add_Click({ShowUnifiedExternalPath})")
    $pathMarker='<TextBlock Name="UnifiedComparisonText"'
    if(-not $ProductSource.Contains($pathMarker)){throw 'Windows external path: comparison row seam drifted.'}
    $ProductSource=$ProductSource.Replace($pathMarker,'<StackPanel Orientation="Horizontal" Margin="76,2,0,6"><Button Name="UnifiedExternalPathButton" Content="External path…" Padding="10,5"/><TextBlock Text="Direct / entry • Local / Server / Compare" VerticalAlignment="Center" Margin="8,0,0,0" Foreground="#A8B6D5"/></StackPanel>'+$pathMarker)
    foreach($marker in @('UnifiedExternalNodeButton','Add external node…','ShowUnifiedExternalNodeBuilder','/api/external-profile/create','wireguard','amneziawg','awg_parameters','socks5','http-connect','https-connect','shadowsocks','hysteria2','TestUnifiedExternalMutationIdle','VPN state changed while the external-node dialog was open','typed maker never accepts executable paths')){if(-not$ProductSource.Contains($marker)){throw "Windows external-node transform missing $marker"}}
    return $ProductSource
}

function Add-RouterVPNTorBridgeWindowsShell {
    param([Parameter(Mandatory=$true)][string]$ProductSource)

    $nodeOld = '<StackPanel Orientation="Horizontal"><TextBlock Text="Node" FontWeight="SemiBold" Margin="0,0,8,0" VerticalAlignment="Center"/><ComboBox Name="UnifiedNodeCombo" DisplayMemberPath="display_name" SelectedValuePath="id" MinWidth="260"/><Button Name="UnifiedNodesButton" Content="Add / manage nodes" Margin="8,0,0,0" Padding="10,5"/></StackPanel>'
    $nodeNew = '<StackPanel Orientation="Horizontal"><TextBlock Text="Node" FontWeight="SemiBold" Margin="0,0,8,0" VerticalAlignment="Center"/><ComboBox Name="UnifiedNodeCombo" DisplayMemberPath="display_name" SelectedValuePath="id" MinWidth="260"/><Button Name="UnifiedNodesButton" Content="Add / manage nodes" Margin="8,0,0,0" Padding="10,5"/><Button Name="UnifiedTorButton" Content="Tor bridges…" Margin="6,0,0,0" Padding="10,5"/></StackPanel>'
    if(-not $ProductSource.Contains($nodeOld)){throw 'Windows Tor bridge UI: unified node row drifted.'}
    $ProductSource=$ProductSource.Replace($nodeOld,$nodeNew)

    $stateMarker='$script:EventSeq=[uint64]0;$script:Busy=$false;$script:NodeSort=''current'';$script:DnsPolicySummary=''Saved DNS policy not loaded yet.'''
    if(-not $ProductSource.Contains($stateMarker)){throw 'Windows Tor bridge UI: product state marker drifted.'}
    $functions=@'
function ShowUnifiedTorBridgeBuilder{
    [xml]$X=@"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="Tor censorship circumvention" Width="760" Height="690" MinWidth="620" MinHeight="560" WindowStartupLocation="CenterOwner" Background="#0B1020" Foreground="#F5F7FF">
  <ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel Margin="22">
    <TextBlock Text="Tor bridges" FontSize="26" FontWeight="Bold"/>
    <TextBlock Margin="0,8,0,14" Foreground="#A8B6D5" TextWrapping="Wrap" Text="Choose how Tor gets through censorship. obfs4 disguises bridge traffic and resists active probing; meek uses HTTPS/CDN-style fronts; Snowflake uses brokers plus short-lived volunteer WebRTC proxies; WebTunnel resembles ordinary HTTPS web traffic. Auto / Custom accepts validated Tor-issued bridge lines. Tor's proved circuit—not homemade XOR—is the encrypted final path."/>
    <TextBlock Text="Node name"/><TextBox Name="TorName" Margin="0,4,0,10" Padding="8"/>
    <Grid Margin="0,0,0,10"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
      <StackPanel Margin="0,0,6,0"><TextBlock Text="Transport"/><ComboBox Name="TorTransport" Margin="0,4,0,0"><ComboBoxItem Content="obfs4" Tag="obfs4"/><ComboBoxItem Content="meek" Tag="meek_lite"/><ComboBoxItem Content="Snowflake" Tag="snowflake"/><ComboBoxItem Content="WebTunnel" Tag="webtunnel"/><ComboBoxItem Content="Auto / Custom" Tag="custom"/></ComboBox></StackPanel>
      <StackPanel Grid.Column="1" Margin="6,0,0,0"><TextBlock Text="Kill switch"/><ComboBox Name="TorKill" Margin="0,4,0,0"><ComboBoxItem Content="Off" Tag="off"/><ComboBoxItem Content="On connect" Tag="on-connect"/><ComboBoxItem Content="Always / strict" Tag="always"/></ComboBox></StackPanel>
    </Grid>
    <TextBlock Text="Tor bridge lines — one per line" FontWeight="SemiBold"/>
    <TextBox Name="TorLines" Height="230" Margin="0,4,0,8" Padding="8" AcceptsReturn="True" AcceptsTab="False" VerticalScrollBarVisibility="Auto" TextWrapping="NoWrap" FontFamily="Consolas"/>
    <TextBlock Foreground="#A8B6D5" TextWrapping="Wrap" Text="Paste current lines from Tor or a trusted bridge source. Before connecting a new Tor node, choose Custom TCP, DoT, DoH or Rescue in DNS. Updating a saved node keeps its DNS choice."/>
    <TextBlock Name="TorCapability" Margin="0,10,0,4" Foreground="#A8B6D5" TextWrapping="Wrap" Text="Checking Tor transport support…"/>
    <TextBlock Name="TorStatus" Foreground="#FFCC8A" TextWrapping="Wrap" Margin="0,0,0,10"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right"><Button Name="TorRefresh" Content="Refresh support" Padding="12,7"/><Button Name="TorSave" Content="Save Tor node" Margin="8,0,0,0" Padding="12,7"/><Button Name="TorClose" Content="Close" Margin="8,0,0,0" Padding="12,7"/></StackPanel>
  </StackPanel></ScrollViewer>
</Window>
"@
    $reader=New-Object System.Xml.XmlNodeReader $X;$D=[Windows.Markup.XamlReader]::Load($reader);$D.Owner=$W
    $Name=$D.FindName('TorName');$Transport=$D.FindName('TorTransport');$Kill=$D.FindName('TorKill');$Lines=$D.FindName('TorLines');$Capability=$D.FindName('TorCapability');$Status=$D.FindName('TorStatus');$Transport.SelectedIndex=0;$Kill.SelectedIndex=0
    $Caps=@{}
    $Refresh={
        try{
            $R=Api '/api/tor-bridge/capabilities' -Timeout 8
            $Caps=@{};foreach($C in @($R.transports)){$Caps[[string]$C.id]=$C}
            $ID=[string](($Transport.SelectedItem).Tag);$C=$Caps[$ID]
            if($C){
                $Availability=if([bool]$C.supported){'Available'}else{'Unavailable'}
                $Strict=if([bool]$C.strict_kill_switch){'supported'}else{'not currently safe'}
                $Capability.Text=$Availability+" • strict kill switch "+$Strict+"`n"+[string]$C.description
                $Why=[string]$C.reason;if($Why){$Capability.Text+="`nReason: "+$Why}
            }else{$Capability.Text="Support details unavailable for $ID."}
        }catch{$Capability.Text='Tor support check failed: '+$_.Exception.Message}
    }
    $Transport.Add_SelectionChanged({&$Refresh})
    $Kill.Add_SelectionChanged({$ID=[string](($Transport.SelectedItem).Tag);$C=$Caps[$ID];if($C -and -not[bool]$C.strict_kill_switch -and [string](($Kill.SelectedItem).Tag) -ne 'off'){$Status.Text='Dynamic CDN/STUN/WebRTC/bootstrap transports require Kill switch Off until process-scoped PT egress filtering exists.'}else{$Status.Text=''}})
    $D.FindName('TorRefresh').Add_Click({&$Refresh})
    $D.FindName('TorClose').Add_Click({$D.Close()})
    $D.FindName('TorSave').Add_Click({
        try{
            $Rows=@($Lines.Text -split "`r?`n"|ForEach-Object{$_.Trim()}|Where-Object{$_});if(-not$Rows){throw 'Paste at least one Tor bridge line.'}
            $ID=[string](($Transport.SelectedItem).Tag);$KillID=[string](($Kill.SelectedItem).Tag);$C=$Caps[$ID]
            if($C -and -not[bool]$C.strict_kill_switch -and $KillID -ne 'off'){throw 'This dynamic Tor transport requires Kill switch Off until Router VPN owns process-scoped PT egress.'}
            $R=Api '/api/tor-bridge/import' 'POST' @{name=[string]$Name.Text;transport=$ID;bridges=$Rows;kill_switch_policy=$KillID} 25
            $Status.Text='Tor node saved and selected. Before connecting, choose Custom TCP, DoT, DoH or Rescue in DNS. Transport availability is shown above.'
            Log ('Tor bridge profile saved: '+[string]$R.profile.name);RefreshProduct
        }catch{$Status.Text='Tor node rejected: '+$_.Exception.Message}
    })
    &$Refresh;[void]$D.ShowDialog()
}
'@
    $ProductSource=$ProductSource.Replace($stateMarker,$functions+"`r`n"+$stateMarker)

    $eventMarker="(Control 'UnifiedNodesButton').Add_Click({OpenUnifiedDetail 1})"
    if(-not $ProductSource.Contains($eventMarker)){throw 'Windows Tor bridge UI: unified node event seam drifted.'}
    $ProductSource=$ProductSource.Replace($eventMarker,$eventMarker+"`r`n(Control 'UnifiedTorButton').Add_Click({ShowUnifiedTorBridgeBuilder})")

    foreach($marker in @('UnifiedTorButton','Tor bridges…','ShowUnifiedTorBridgeBuilder','/api/tor-bridge/capabilities','/api/tor-bridge/import','meek_lite','Snowflake','WebTunnel','Auto / Custom','short-lived volunteer WebRTC proxies','choose Custom TCP, DoT, DoH or Rescue in DNS')){if(-not$ProductSource.Contains($marker)){throw "Windows Tor bridge transform missing $marker"}}
    $ProductSource=Add-RouterVPNExternalNodeWindowsShell -ProductSource $ProductSource
    return $ProductSource
}
