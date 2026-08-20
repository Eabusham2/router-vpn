Set-StrictMode -Version Latest

function Add-RouterVPNTelemetryWindowsShell {
    param([Parameter(Mandatory=$true)][string]$ProductSource)

    $killOld='<CheckBox Name="UnifiedKillSwitch" Grid.Column="1" Content="Kill switch" VerticalAlignment="Center" Margin="14,0,0,0"/>'
    $killNew='<StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center" Margin="10,0,0,0"><ComboBox Name="UnifiedFastestNode" Width="150" DisplayMemberPath="display" SelectedValuePath="id" ToolTip="Connect fastest measured node or a specific Router VPN node"/><TextBlock Name="UnifiedLiveLatency" Text="-- ms" FontFamily="Consolas" FontWeight="SemiBold" Foreground="#A8B6D5" VerticalAlignment="Center" Margin="8,0"/><CheckBox Name="UnifiedKillSwitch" Content="Kill switch" VerticalAlignment="Center" Margin="4,0"/><Button Name="UnifiedForwardButton" Content="Forward" Margin="6,0,0,0" Padding="8,4"/></StackPanel>'
    if(-not $ProductSource.Contains($killOld)){throw 'Windows telemetry connect-row contract drifted.'}
    $ProductSource=$ProductSource.Replace($killOld,$killNew)

    $multiOld='<ComboBox Name="UnifiedExitMode" Grid.Column="5" Margin="6,0,0,0"><ComboBoxItem Content="Shadowsocks" Tag="shadowsocks"/><ComboBoxItem Content="Hysteria2" Tag="hysteria2"/></ComboBox></Grid>'
    $multiNew=$multiOld+'<TextBlock Name="UnifiedMultihopLatency" Text="" FontFamily="Consolas" FontSize="11" Foreground="#A8B6D5" Margin="76,0,0,4"/>'
    if(-not $ProductSource.Contains($multiOld)){throw 'Windows telemetry multihop-row contract drifted.'}
    $ProductSource=$ProductSource.Replace($multiOld,$multiNew)

    $settingsOld='<StackPanel Grid.Column="2" Orientation="Horizontal"><Button Name="UnifiedSettingsButton" Content="Open settings" Padding="10,5"/><Button Name="UnifiedMtuButton" Content="Retest MTU" Margin="6,0,0,0" Padding="10,5"/></StackPanel>'
    $settingsNew='<StackPanel Grid.Column="2" Orientation="Horizontal"><Button Name="UnifiedSettingsButton" Content="Open settings" Padding="10,5"/><Button Name="UnifiedPerformanceButton" Content="Performance" Margin="6,0,0,0" Padding="10,5"/><Button Name="UnifiedMtuButton" Content="Retest MTU" Margin="6,0,0,0" Padding="10,5"/></StackPanel>'
    if(-not $ProductSource.Contains($settingsOld)){throw 'Windows telemetry settings-row contract drifted.'}
    $ProductSource=$ProductSource.Replace($settingsOld,$settingsNew)

    $startup='$BaseCombo.SelectedIndex=0'
    if(-not $ProductSource.Contains($startup)){throw 'Windows telemetry startup seam drifted.'}
    $telemetry=@'
$script:UnifiedTelemetrySync=$false
function RefreshUnifiedFastestChoices{
 try{
  $Store=Api '/api/profiles' -Timeout 4
  $Values=New-Object System.Collections.ArrayList
  [void]$Values.Add([pscustomobject]@{id='fastest';display='⚡ Fastest'})
  $Routers=@($Store.profiles|Where-Object{(([string]$_.node_kind).ToLowerInvariant()-ne'external')}|Sort-Object @{Expression={if([double]$_.latency_trimmed_mean_ms-gt0){[double]$_.latency_trimmed_mean_ms}else{[double]::PositiveInfinity}}},name)
  foreach($P in $Routers){$Ms=[double]$P.latency_trimmed_mean_ms;$Label=if($Ms-gt0){'{0}  {1:N1} ms'-f [string]$P.name,$Ms}else{[string]$P.name};[void]$Values.Add([pscustomobject]@{id=[string]$P.id;display=$Label})}
  $script:UnifiedTelemetrySync=$true;(Control 'UnifiedFastestNode').ItemsSource=@($Values);(Control 'UnifiedFastestNode').SelectedValue='fastest';$script:UnifiedTelemetrySync=$false
 }catch{$script:UnifiedTelemetrySync=$false}
}
function RefreshUnifiedTelemetry{
 RefreshUnifiedFastestChoices
 try{$Live=Api '/api/connection/live-latency' -Timeout 4;(Control 'UnifiedLiveLatency').Text=('{0:N1} ms'-f [double]$Live.median_ms);(Control 'UnifiedLiveLatency').Foreground='#E8ECF8'}catch{(Control 'UnifiedLiveLatency').Text='-- ms';(Control 'UnifiedLiveLatency').Foreground='#A8B6D5'}
 try{
  if((Control 'UnifiedMultihop').IsChecked){$Entry=[string]$MultihopEntryCombo.SelectedValue;$Exit=[string]$MultihopExitCombo.SelectedValue;if($Entry-and$Exit-and$Entry-ne$Exit){$R=Api '/api/multihop/live-latency' 'POST' @{entry_id=$Entry;exit_id=$Exit;samples=2} 8;$Bits=@();if($R.entry){$Bits+=('IN {0:N1}'-f[double]$R.entry.median_ms)};if($R.exit){$Bits+=('OUT {0:N1}'-f[double]$R.exit.median_ms)};if($R.current_path){$Bits+=('PATH {0:N1} ms'-f[double]$R.current_path.median_ms)};(Control 'UnifiedMultihopLatency').Text=($Bits-join' • ')}}else{(Control 'UnifiedMultihopLatency').Text=''}
 }catch{(Control 'UnifiedMultihopLatency').Text=''}
}
function ShowUnifiedPerformance{
 [xml]$PX=@'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="Router VPN Performance" Width="650" Height="430" MinWidth="520" MinHeight="350" WindowStartupLocation="CenterOwner" Background="#0B1020" Foreground="#F5F7FF"><Grid Margin="20"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions><TextBlock Text="Latency &amp; path performance" FontSize="23" FontWeight="Bold"/><TextBlock Grid.Row="1" Margin="0,8,0,12" Foreground="#A8B6D5" TextWrapping="Wrap" Text="Live RTT uses the current private tunnel. The 50-sample test is the durable node benchmark. Throughput + Auto MTU uses the bounded private-node loss/RTT/throughput comparison and may update Auto MTU; it is not mislabeled as a passive speed test."/><TextBox Name="Result" Grid.Row="2" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" FontFamily="Consolas" Background="#101A2B" Foreground="#E8ECF8" Padding="10"/><WrapPanel Grid.Row="3" Margin="0,12,0,0"><Button Name="Live" Content="Live path RTT" Margin="4" Padding="11,6"/><Button Name="Durable" Content="50-sample selected node" Margin="4" Padding="11,6"/><Button Name="Throughput" Content="Throughput + Auto MTU" Margin="4" Padding="11,6"/><Button Name="Close" Content="Close" Margin="4" Padding="11,6"/></WrapPanel></Grid></Window>
'@
  $Reader=New-Object System.Xml.XmlNodeReader $PX;$D=[Windows.Markup.XamlReader]::Load($Reader);$D.Owner=$Window;$Result=$D.FindName('Result')
  $D.FindName('Live').Add_Click({try{$R=Api '/api/connection/live-latency' 'POST' @{samples=5} 12;$Result.Text=($R|ConvertTo-Json -Depth 6)}catch{$Result.Text=$_.Exception.Message}})
  $D.FindName('Durable').Add_Click({try{$P=SelectedNode;$R=Api '/api/profile/latency' 'POST' @{id=[string]$P.id;samples=50} 180;$Result.Text=($R|ConvertTo-Json -Depth 6);RefreshProduct}catch{$Result.Text=$_.Exception.Message}})
  $D.FindName('Throughput').Add_Click({try{$R=Api '/api/mtu/retest' 'POST' @{} 130;$Result.Text=($R|ConvertTo-Json -Depth 8);RefreshProduct}catch{$Result.Text=$_.Exception.Message}})
  $D.FindName('Close').Add_Click({$D.Close()});[void]$D.ShowDialog()
}
(Control 'UnifiedFastestNode').Add_SelectionChanged({if($script:UnifiedTelemetrySync){return};$ID=[string](Control 'UnifiedFastestNode').SelectedValue;if(-not$ID){return};try{if($ID-eq'fastest'){[void](Api '/api/profile/fastest' 'POST' @{samples=5;select=$true} 40)}else{[void](Api '/api/profile/select' 'POST' @{id=$ID} 10)};RefreshProduct;RefreshUnifiedTelemetry;UnifiedConnect}catch{Log ('Fast connect failed: '+$_.Exception.Message)}finally{$script:UnifiedTelemetrySync=$true;(Control 'UnifiedFastestNode').SelectedValue='fastest';$script:UnifiedTelemetrySync=$false}})
(Control 'UnifiedForwardButton').Add_Click({OpenUnifiedDetail 5})
(Control 'UnifiedPerformanceButton').Add_Click({ShowUnifiedPerformance})
'@
    $ProductSource=$ProductSource.Replace($startup,$telemetry+"`n"+$startup)

    $tick='$Timer.Add_Tick({RefreshProduct})'
    if($ProductSource.Contains($tick)){$ProductSource=$ProductSource.Replace($tick,'$Timer.Add_Tick({RefreshProduct;RefreshUnifiedTelemetry})')}
    $initial="RefreshProduct`n`$Timer.Start()"
    if($ProductSource.Contains($initial)){$ProductSource=$ProductSource.Replace($initial,"RefreshProduct`nRefreshUnifiedTelemetry`n`$Timer.Start()")}

    $ProductSource+="`n# Windows telemetry UX contract: fastest-node connect dropdown, live path RTT beside Connect/Disconnect, live multihop IN/OUT/PATH RTT, Performance panel, Forward shortcut, node-map median-ms refresh.`n"
    return $ProductSource
}
