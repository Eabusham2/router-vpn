Set-StrictMode -Version Latest

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
    [xml]$X=@'
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
'@
    $reader=New-Object System.Xml.XmlNodeReader $X;$D=[Windows.Markup.XamlReader]::Load($reader);$D.Owner=$W
    $Name=$D.FindName('TorName');$Transport=$D.FindName('TorTransport');$Kill=$D.FindName('TorKill');$Lines=$D.FindName('TorLines');$Capability=$D.FindName('TorCapability');$Status=$D.FindName('TorStatus');$Transport.SelectedIndex=0;$Kill.SelectedIndex=0
    $Caps=@{}
    $Refresh={
        try{$R=Api '/api/tor-bridge/capabilities' -Timeout 8;$Caps=@{};foreach($C in @($R.transports)){$Caps[[string]$C.id]=$C};$ID=[string](($Transport.SelectedItem).Tag);$C=$Caps[$ID];if($C){$Strict=if([bool]$C.strict_kill_switch){'supported'}else{'not currently safe'};$Why=[string]$C.reason;$Capability.Text=(if([bool]$C.supported){'Available'}else{'Unavailable'})+" • strict kill switch $Strict`n"+[string]$C.description+$(if($Why){"`nReason: $Why"}else{''})}else{$Capability.Text="Support details unavailable for $ID."}}
        catch{$Capability.Text='Tor support check failed: '+$_.Exception.Message}
    }
    $Transport.Add_SelectionChanged({&$Refresh})
    $Kill.Add_SelectionChanged({$ID=[string](($Transport.SelectedItem).Tag);$C=$Caps[$ID];if($C -and -not[bool]$C.strict_kill_switch -and [string](($Kill.SelectedItem).Tag) -ne 'off'){$Status.Text='Dynamic CDN/STUN/WebRTC/bootstrap transports require Kill switch Off until process-scoped PT egress filtering exists.'}else{$Status.Text=''}})
    $D.FindName('TorRefresh').Add_Click({&$Refresh})
    $D.FindName('TorClose').Add_Click({$D.Close()})
    $D.FindName('TorSave').Add_Click({
        try{$Rows=@($Lines.Text -split "`r?`n"|ForEach-Object{$_.Trim()}|Where-Object{$_});if(-not$Rows){throw 'Paste at least one Tor bridge line.'};$ID=[string](($Transport.SelectedItem).Tag);$KillID=[string](($Kill.SelectedItem).Tag);$C=$Caps[$ID];if($C -and -not[bool]$C.strict_kill_switch -and $KillID -ne 'off'){throw 'This dynamic Tor transport requires Kill switch Off until Router VPN owns process-scoped PT egress.'};$R=Api '/api/tor-bridge/import' 'POST' @{name=[string]$Name.Text;transport=$ID;bridges=$Rows;kill_switch_policy=$KillID} 25;$Status.Text='Tor node saved. Windows can store/manage it, but Connect stays unavailable until a real native Tor/Lyrebird full-device runtime is implemented for Windows.';Log ('Tor bridge profile saved: '+[string]$R.profile.name);RefreshProduct}catch{$Status.Text='Tor node rejected: '+$_.Exception.Message}
    })
    &$Refresh;[void]$D.ShowDialog()
}
'@
    $ProductSource=$ProductSource.Replace($stateMarker,$functions+"`r`n"+$stateMarker)

    $eventMarker="(Control 'UnifiedNodesButton').Add_Click({OpenUnifiedDetail 1})"
    if(-not $ProductSource.Contains($eventMarker)){throw 'Windows Tor bridge UI: unified node event seam drifted.'}
    $ProductSource=$ProductSource.Replace($eventMarker,$eventMarker+"`r`n(Control 'UnifiedTorButton').Add_Click({ShowUnifiedTorBridgeBuilder})")

    foreach($marker in @('UnifiedTorButton','Tor bridges…','ShowUnifiedTorBridgeBuilder','/api/tor-bridge/capabilities','/api/tor-bridge/import','meek_lite','Snowflake','WebTunnel','Auto / Custom','short-lived volunteer WebRTC proxies','profile data cannot inject ClientTransportPlugin commands')){if(-not$ProductSource.Contains($marker)){throw "Windows Tor bridge transform missing $marker"}}
    return $ProductSource
}
