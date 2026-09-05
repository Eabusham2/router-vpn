Set-StrictMode -Version Latest

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
function ShowUnifiedExternalNodeBuilder{
    if(-not(TestUnifiedExternalMutationIdle)){Log 'Disconnect or let the active VPN transition finish before adding an external node. Unknown controller state fails closed.';return}
    [xml]$X=@"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="Add external node" Width="820" Height="760" MinWidth="680" MinHeight="600" WindowStartupLocation="CenterOwner" Background="#0B1020" Foreground="#F5F7FF">
  <ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel Margin="22">
    <TextBlock Text="Add external node" FontSize="26" FontWeight="Bold"/>
    <TextBlock Margin="0,8,0,14" Foreground="#A8B6D5" TextWrapping="Wrap" Text="Create a validated full-device external node. OpenVPN uses Import; Tor uses Tor bridges. Secrets stay in the private controller store. Relevant fields depend on the selected protocol and the controller validates the final profile before persistence."/>
    <TextBlock Text="Protocol"/><ComboBox Name="ExtProtocol" Margin="0,4,0,10"><ComboBoxItem Content="WireGuard" Tag="wireguard"/><ComboBoxItem Content="SOCKS5" Tag="socks5"/><ComboBoxItem Content="HTTP CONNECT" Tag="http-connect"/><ComboBoxItem Content="HTTPS CONNECT" Tag="https-connect"/><ComboBoxItem Content="Shadowsocks" Tag="shadowsocks"/><ComboBoxItem Content="Hysteria2" Tag="hysteria2"/></ComboBox>
    <TextBlock Text="Display name"/><TextBox Name="ExtName" Margin="0,4,0,8" Padding="7"/>
    <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="170"/></Grid.ColumnDefinitions><StackPanel Margin="0,0,6,0"><TextBlock Text="Server IP / hostname"/><TextBox Name="ExtServer" Margin="0,4,0,8" Padding="7"/></StackPanel><StackPanel Grid.Column="1" Margin="6,0,0,0"><TextBlock Text="Port"/><TextBox Name="ExtPort" Margin="0,4,0,8" Padding="7"/></StackPanel></Grid>
    <TextBlock Text="Expected public exit IP"/><TextBox Name="ExtExpected" Margin="0,4,0,8" Padding="7"/>
    <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions><StackPanel Margin="0,0,6,0"><TextBlock Text="Username (proxy only)"/><TextBox Name="ExtUser" Margin="0,4,0,8" Padding="7"/></StackPanel><StackPanel Grid.Column="1" Margin="6,0,0,0"><TextBlock Text="Password / proxy credential"/><PasswordBox Name="ExtPassword" Margin="0,4,0,8" Padding="7"/></StackPanel></Grid>
    <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions><StackPanel Margin="0,0,6,0"><TextBlock Text="Shadowsocks method"/><TextBox Name="ExtMethod" Margin="0,4,0,8" Padding="7"/></StackPanel><StackPanel Grid.Column="1" Margin="6,0,0,0"><TextBlock Text="Shadowsocks / Hysteria2 secret"/><PasswordBox Name="ExtSecret" Margin="0,4,0,8" Padding="7"/></StackPanel></Grid>
    <TextBlock Text="TLS server name / SNI (HTTPS CONNECT or Hysteria2)"/><TextBox Name="ExtTLS" Margin="0,4,0,8" Padding="7"/>
    <Separator Margin="0,8"/>
    <TextBlock Text="WireGuard fields" FontWeight="SemiBold"/>
    <TextBlock Text="Private key"/><PasswordBox Name="ExtWGPrivate" Margin="0,4,0,8" Padding="7"/>
    <TextBlock Text="Peer public key"/><TextBox Name="ExtWGPeer" Margin="0,4,0,8" Padding="7"/>
    <TextBlock Text="Preshared key (optional)"/><PasswordBox Name="ExtWGPSK" Margin="0,4,0,8" Padding="7"/>
    <TextBlock Text="Interface addresses — comma separated CIDRs"/><TextBox Name="ExtWGAddresses" Margin="0,4,0,8" Padding="7"/>
    <TextBlock Text="AllowedIPs — comma separated CIDRs"/><TextBox Name="ExtWGAllowed" Margin="0,4,0,8" Padding="7"/>
    <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="170"/></Grid.ColumnDefinitions><StackPanel Margin="0,0,6,0"><TextBlock Text="DNS IPs — comma separated"/><TextBox Name="ExtWGDNS" Margin="0,4,0,8" Padding="7"/></StackPanel><StackPanel Grid.Column="1" Margin="6,0,0,0"><TextBlock Text="MTU (optional)"/><TextBox Name="ExtWGMTU" Margin="0,4,0,8" Padding="7"/></StackPanel></Grid>
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
            if($ID -eq 'wireguard'){
                $Body.wg_private_key=[string]$D.FindName('ExtWGPrivate').Password
                $Body.wg_peer_public_key=[string]$D.FindName('ExtWGPeer').Text
                $Body.wg_addresses=@(SplitUnifiedExternalCsv ([string]$D.FindName('ExtWGAddresses').Text))
                $Body.wg_allowed_ips=@(SplitUnifiedExternalCsv ([string]$D.FindName('ExtWGAllowed').Text))
                $Body.wg_dns=@(SplitUnifiedExternalCsv ([string]$D.FindName('ExtWGDNS').Text))
                $PSK=[string]$D.FindName('ExtWGPSK').Password;if($PSK.Trim()){$Body.wg_preshared_key=$PSK}
                $MTUText=[string]$D.FindName('ExtWGMTU').Text;if($MTUText.Trim()){$Body.wg_mtu=[int]$MTUText}
            }
            $R=Api '/api/external-profile/create' 'POST' $Body 25;$Status.Text='External node saved and selected.';Log ('External node saved: '+[string]$R.profile.name);RefreshProduct
        }catch{$Status.Text='External node rejected: '+$_.Exception.Message}
    })
    [void]$D.ShowDialog()
}
'@
    $ProductSource=$ProductSource.Replace($stateMarker,$functions+"`r`n"+$stateMarker)
    $eventMarker="(Control 'UnifiedNodesButton').Add_Click({OpenUnifiedDetail 1})"
    if(-not $ProductSource.Contains($eventMarker)){throw 'Windows external-node UI: unified node event seam drifted.'}
    $ProductSource=$ProductSource.Replace($eventMarker,$eventMarker+"`r`n(Control 'UnifiedExternalNodeButton').Add_Click({ShowUnifiedExternalNodeBuilder})")
    foreach($marker in @('UnifiedExternalNodeButton','Add external node…','ShowUnifiedExternalNodeBuilder','/api/external-profile/create','wireguard','socks5','http-connect','https-connect','shadowsocks','hysteria2','TestUnifiedExternalMutationIdle','VPN state changed while the external-node dialog was open','typed maker never accepts executable paths')){if(-not$ProductSource.Contains($marker)){throw "Windows external-node transform missing $marker"}}
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
    <TextBlock Foreground="#A8B6D5" TextWrapping="Wrap" Text="Paste current lines from Tor or a trusted bridge source. Router VPN accepts only obfs4, meek_lite, Snowflake, and WebTunnel syntax. Profile data cannot inject ClientTransportPlugin commands, executable paths, or arbitrary torrc directives."/>
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
            $Status.Text='Tor node saved and selected. Connect availability follows the live Tor capability result shown above; Windows x64 can connect when the pinned Tor/Lyrebird runtime is present, while unsupported platforms stay unavailable with their exact reason.'
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

    foreach($marker in @('UnifiedTorButton','Tor bridges…','ShowUnifiedTorBridgeBuilder','/api/tor-bridge/capabilities','/api/tor-bridge/import','meek_lite','Snowflake','WebTunnel','Auto / Custom','short-lived volunteer WebRTC proxies','profile data cannot inject ClientTransportPlugin commands')){if(-not$ProductSource.Contains($marker)){throw "Windows Tor bridge transform missing $marker"}}
    $ProductSource=Add-RouterVPNExternalNodeWindowsShell -ProductSource $ProductSource
    return $ProductSource
}
