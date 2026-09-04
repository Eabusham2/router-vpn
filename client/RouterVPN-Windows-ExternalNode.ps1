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
    [xml]$X=@'
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
'@
    $reader=New-Object System.Xml.XmlNodeReader $X;$D=[Windows.Markup.XamlReader]::Load($reader);$D.Owner=$W
    $Protocol=$D.FindName('ExtProtocol');$Protocol.SelectedIndex=0;$Status=$D.FindName('ExtStatus')
    $D.FindName('ExtClose').Add_Click({$D.Close()})
    $D.FindName('ExtSave').Add_Click({
        try{
            if(-not(TestUnifiedExternalMutationIdle)){throw 'VPN state changed while the external-node dialog was open. Nothing was saved.'}
            $ID=[string](($Protocol.SelectedItem).Tag)
            $PortText=[string]$D.FindName('ExtPort').Text
            $Port=0;if($PortText.Trim()){ $Port=[int]$PortText }
            $Body=@{name=[string]$D.FindName('ExtName').Text;protocol=$ID;server=[string]$D.FindName('ExtServer').Text;port=$Port;expected_public_ip=[string]$D.FindName('ExtExpected').Text}
            if($ID -in @('socks5','http-connect','https-connect')){$Body.username=[string]$D.FindName('ExtUser').Text;$Body.password=[string]$D.FindName('ExtPassword').Password}
            if($ID -eq 'https-connect'){$Body.tls_server_name=[string]$D.FindName('ExtTLS').Text}
            if($ID -eq 'shadowsocks'){$Body.method=[string]$D.FindName('ExtMethod').Text;$Body.secret=[string]$D.FindName('ExtSecret').Password}
            if($ID -eq 'hysteria2'){$Body.secret=[string]$D.FindName('ExtSecret').Password;$Body.tls_server_name=[string]$D.FindName('ExtTLS').Text}
            if($ID -eq 'wireguard'){
                $Body.wg_private_key=[string]$D.FindName('ExtWGPrivate').Password;$Body.wg_peer_public_key=[string]$D.FindName('ExtWGPeer').Text;$Body.wg_addresses=@(SplitUnifiedExternalCsv ([string]$D.FindName('ExtWGAddresses').Text));$Body.wg_allowed_ips=@(SplitUnifiedExternalCsv ([string]$D.FindName('ExtWGAllowed').Text));$Body.wg_dns=@(SplitUnifiedExternalCsv ([string]$D.FindName('ExtWGDNS').Text)
                )
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
