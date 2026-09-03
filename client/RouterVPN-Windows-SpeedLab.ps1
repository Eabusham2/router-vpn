function Add-RouterVPNSpeedLabWindowsShell {
    param([Parameter(Mandatory=$true)][string]$ProductSource)
    Set-StrictMode -Version Latest

    $pattern='(?s)function ShowUnifiedPerformance\{.*?\r?\n\}\r?\n\(Control ''UnifiedFastestNode''\)\.Add_SelectionChanged'
    $match=[regex]::Match($ProductSource,$pattern)
    if(-not $match.Success){throw 'Windows Speed Lab performance seam drifted.'}
    $old=$match.Value
    $oldFunction=$old.Substring(0,$old.LastIndexOf("(Control 'UnifiedFastestNode')"))
    $advanced=$oldFunction.Replace('function ShowUnifiedPerformance{','function ShowUnifiedAdvancedPerformance{')

    $speedLab=@'
function ShowUnifiedSpeedLab{
 [xml]$SX=@"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="Router VPN Speed Lab" Width="940" Height="760" MinWidth="760" MinHeight="620" WindowStartupLocation="CenterOwner" Background="#08101F" Foreground="#F5F7FF">
 <Grid Margin="22">
  <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
  <StackPanel><TextBlock Text="SPEED LAB" Foreground="#66D9EF" FontWeight="SemiBold"/><TextBlock Text="Router VPN path performance" FontSize="28" FontWeight="Bold"/><TextBlock Text="Real HTTPS throughput + idle and loaded latency. Current path is default; Temporary builds a proven test-only path and restores your saved setup afterward." Foreground="#9EB0CE" TextWrapping="Wrap" Margin="0,5,0,0"/></StackPanel>
  <Grid Grid.Row="1" Margin="0,16,0,0"><Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition/><ColumnDefinition/></Grid.ColumnDefinitions>
   <Border Background="#101D33" CornerRadius="14" Margin="0,0,8,0" Padding="14"><StackPanel><TextBlock Text="IDLE LATENCY" Foreground="#92A5C5"/><TextBlock Name="IdleBig" Text="-- ms" FontSize="30" FontWeight="Bold"/><TextBlock Name="IdleDetail" Text="median • p90/max/jitter after test" Foreground="#7890B3"/></StackPanel></Border>
   <Border Grid.Column="1" Background="#10243A" CornerRadius="14" Margin="4,0" Padding="14"><StackPanel><TextBlock Text="DOWNLOAD" Foreground="#63D7FF"/><TextBlock Name="DownBig" Text="-- Mbps" FontSize="30" FontWeight="Bold"/><TextBlock Name="DownDetail" Text="loaded -- ms" Foreground="#8FC9E8"/></StackPanel></Border>
   <Border Grid.Column="2" Background="#1D1D38" CornerRadius="14" Margin="8,0,0,0" Padding="14"><StackPanel><TextBlock Text="UPLOAD" Foreground="#B799FF"/><TextBlock Name="UpBig" Text="-- Mbps" FontSize="30" FontWeight="Bold"/><TextBlock Name="UpDetail" Text="loaded -- ms" Foreground="#BDB1E8"/></StackPanel></Border>
  </Grid>
  <Border Grid.Row="2" Background="#0D1729" CornerRadius="14" Margin="0,12,0,0" Padding="12"><Grid><Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="160"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="180"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="180"/></Grid.ColumnDefinitions><Grid.RowDefinitions><RowDefinition/><RowDefinition/><RowDefinition/></Grid.RowDefinitions>
   <TextBlock Text="Test" VerticalAlignment="Center"/><ComboBox Name="Scope" Grid.Column="1" Margin="8,3"><ComboBoxItem Content="Current path" Tag="current" IsSelected="True"/><ComboBoxItem Content="Temporary config" Tag="temporary"/></ComboBox>
   <TextBlock Grid.Column="2" Text="Topology" VerticalAlignment="Center" Margin="12,0,0,0"/><ComboBox Name="Topology" Grid.Column="3" Margin="8,3"><ComboBoxItem Content="System direct" Tag="system-direct"/><ComboBoxItem Content="Router VPN node" Tag="router" IsSelected="True"/><ComboBoxItem Content="Multihop" Tag="multihop"/><ComboBoxItem Content="External exit / hop" Tag="external"/></ComboBox>
   <TextBlock Grid.Column="4" Text="Mode" VerticalAlignment="Center" Margin="12,0,0,0"/><ComboBox Name="Mode" Grid.Column="5" Margin="8,3" DisplayMemberPath="name" SelectedValuePath="id"/>
   <TextBlock Grid.Row="1" Text="Node / exit" VerticalAlignment="Center"/><ComboBox Name="Node" Grid.Row="1" Grid.Column="1" Margin="8,3" DisplayMemberPath="display" SelectedValuePath="id"/>
   <TextBlock Grid.Row="1" Grid.Column="2" Text="Entry" VerticalAlignment="Center" Margin="12,0,0,0"/><ComboBox Name="Entry" Grid.Row="1" Grid.Column="3" Margin="8,3" DisplayMemberPath="display" SelectedValuePath="id"/>
   <TextBlock Grid.Row="1" Grid.Column="4" Text="Exit" VerticalAlignment="Center" Margin="12,0,0,0"/><ComboBox Name="Exit" Grid.Row="1" Grid.Column="5" Margin="8,3" DisplayMemberPath="display" SelectedValuePath="id"/>
   <TextBlock Grid.Row="2" Text="Base" VerticalAlignment="Center"/><ComboBox Name="Base" Grid.Row="2" Grid.Column="1" Margin="8,3"><ComboBoxItem Content="Auto" Tag="auto" IsSelected="True"/><ComboBoxItem Content="WireGuard" Tag="wg"/><ComboBoxItem Content="AmneziaWG" Tag="awg"/></ComboBox>
   <TextBlock Grid.Row="2" Grid.Column="2" Text="Exit transport" VerticalAlignment="Center" Margin="12,0,0,0"/><ComboBox Name="ExitMode" Grid.Row="2" Grid.Column="3" Margin="8,3"><ComboBoxItem Content="Shadowsocks" Tag="shadowsocks" IsSelected="True"/><ComboBoxItem Content="Hysteria2" Tag="hysteria2"/></ComboBox>
   <TextBlock Grid.Row="2" Grid.Column="4" Text="CUSTOM layers" VerticalAlignment="Center" Margin="12,0,0,0"/><TextBox Name="Layers" Grid.Row="2" Grid.Column="5" Margin="8,3" ToolTip="Comma-separated exact layers; used only when Mode=CUSTOM"/>
  </Grid></Border>
  <Border Grid.Row="3" Background="#0D1729" CornerRadius="14" Margin="0,10,0,0" Padding="12"><Grid><Grid.ColumnDefinitions><ColumnDefinition Width="150"/><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><Grid.RowDefinitions><RowDefinition/><RowDefinition/><RowDefinition/></Grid.RowDefinitions>
   <ComboBox Name="DurationMode" Grid.Column="0" Margin="0,0,12,5"><ComboBoxItem Content="Auto timing" Tag="auto" IsSelected="True"/><ComboBoxItem Content="Custom timing" Tag="custom"/></ComboBox>
   <TextBlock Name="MinLabel" Grid.Column="1" Text="Min 4 s" Margin="0,0,8,0"/><TextBlock Name="MaxLabel" Grid.Column="2" Text="Max 12 s" Margin="8,0,0,0"/>
   <Slider Name="MinTime" Grid.Row="1" Grid.Column="1" Minimum="1" Maximum="60" Value="4" TickFrequency="1" IsSnapToTickEnabled="True" Margin="0,4,8,0"/><Slider Name="MaxTime" Grid.Row="1" Grid.Column="2" Minimum="1" Maximum="60" Value="12" TickFrequency="1" IsSnapToTickEnabled="True" Margin="8,4,0,0"/>
   <WrapPanel Grid.Row="2" Grid.ColumnSpan="4" Margin="0,8,0,0"><CheckBox Name="DAITA" Content="DAITA-like" Margin="0,0,14,0"/><CheckBox Name="Jumbo" Content="Jumbo" Margin="0,0,14,0"/><CheckBox Name="Encrypted" Content="Require encrypted AUTO" Margin="0,0,14,0"/><CheckBox Name="Obfuscated" Content="Require obfuscation AUTO"/></WrapPanel>
   <TextBlock Grid.Column="3" Grid.RowSpan="2" Text="Auto runs at least 4 s and up to 12 s per direction, stopping early only after throughput stabilizes. Custom allows 1–60 s." Width="260" TextWrapping="Wrap" Foreground="#8FA3C2" Margin="14,0,0,0"/>
  </Grid></Border>
  <TextBox Name="Detail" Grid.Row="4" Margin="0,10,0,0" Background="#091321" Foreground="#C9D6EA" BorderBrush="#243B59" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" FontFamily="Consolas" Padding="10" Text="Ready. Current path uses the path that is actually connected. Temporary config requires Router VPN to be disconnected."/>
  <Grid Grid.Row="5" Margin="0,12,0,0"><Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><TextBlock Name="Status" VerticalAlignment="Center" Foreground="#8FA3C2" Text="Cloudflare Speed Test edge • no Mbps derived from RTT"/><Button Name="Advanced" Grid.Column="1" Content="Advanced node tests" Padding="11,7" Margin="5,0"/><Button Name="Run" Grid.Column="2" Content="Run Speed Lab" Padding="16,7" Margin="5,0" IsDefault="True"/><Button Name="Close" Grid.Column="3" Content="Close" Padding="11,7" Margin="5,0"/></Grid>
 </Grid>
</Window>
"@
 $Reader=New-Object System.Xml.XmlNodeReader $SX;$D=[Windows.Markup.XamlReader]::Load($Reader);$D.Owner=$Window
 $Scope=$D.FindName('Scope');$Topology=$D.FindName('Topology');$Mode=$D.FindName('Mode');$Node=$D.FindName('Node');$Entry=$D.FindName('Entry');$Exit=$D.FindName('Exit');$Base=$D.FindName('Base');$ExitMode=$D.FindName('ExitMode');$Layers=$D.FindName('Layers');$DurationMode=$D.FindName('DurationMode');$MinTime=$D.FindName('MinTime');$MaxTime=$D.FindName('MaxTime');$MinLabel=$D.FindName('MinLabel');$MaxLabel=$D.FindName('MaxLabel');$Run=$D.FindName('Run');$Status=$D.FindName('Status');$Detail=$D.FindName('Detail')
 function SelectedTag($Combo){if($null-eq$Combo.SelectedItem){return''};return [string]$Combo.SelectedItem.Tag}
 function NodeItems($Values,[string]$Kind){$out=New-Object System.Collections.ArrayList;foreach($n in @($Values)){if($Kind-and([string]$n.node_kind).ToLowerInvariant()-ne$Kind){continue};$ms=if([double]$n.latency_trimmed_mean_ms-gt0){' • {0:N1} ms'-f[double]$n.latency_trimmed_mean_ms}else{''};[void]$out.Add([pscustomobject]@{id=[string]$n.id;display=([string]$n.name+$ms);kind=[string]$n.node_kind})};return @($out)}
 function RefreshSpeedLabControls{
  $temporary=(SelectedTag $Scope)-eq'temporary';foreach($c in @($Topology,$Mode,$Node,$Entry,$Exit,$Base,$ExitMode,$Layers,$D.FindName('DAITA'),$D.FindName('Jumbo'),$D.FindName('Encrypted'),$D.FindName('Obfuscated'))){$c.IsEnabled=$temporary}
  $custom=(SelectedTag $DurationMode)-eq'custom';$MinTime.IsEnabled=$custom;$MaxTime.IsEnabled=$custom
  $top=SelectedTag $Topology;$Entry.IsEnabled=$temporary-and($top-eq'multihop'-or$top-eq'external');$Exit.IsEnabled=$temporary-and$top-eq'multihop';$ExitMode.IsEnabled=$temporary-and$top-eq'multihop';$Layers.IsEnabled=$temporary-and([string]$Mode.SelectedValue)-eq'custom'
 }
 try{
  $Opt=Api '/api/speed-lab/options' -Timeout 10;$Mode.ItemsSource=@($Opt.logical_modes);if($Mode.Items.Count){$Mode.SelectedValue='smart-auto'}
  $Node.ItemsSource=NodeItems $Opt.nodes ''; $Entry.ItemsSource=NodeItems $Opt.nodes ''; $Exit.ItemsSource=NodeItems $Opt.nodes 'router-vpn'
  if($Node.Items.Count){$Node.SelectedIndex=0};if($Entry.Items.Count){$Entry.SelectedIndex=0};if($Exit.Items.Count-gt1){$Exit.SelectedIndex=1}elseif($Exit.Items.Count){$Exit.SelectedIndex=0}
 }catch{$Detail.Text='Could not load Speed Lab options: '+$_.Exception.Message;$Run.IsEnabled=$false}
 $DurationMode.Add_SelectionChanged({RefreshSpeedLabControls});$Scope.Add_SelectionChanged({RefreshSpeedLabControls});$Topology.Add_SelectionChanged({RefreshSpeedLabControls});$Mode.Add_SelectionChanged({RefreshSpeedLabControls})
 $MinTime.Add_ValueChanged({if($MinTime.Value-gt$MaxTime.Value){$MaxTime.Value=$MinTime.Value};$MinLabel.Text=('Min {0:N0} s'-f$MinTime.Value)})
 $MaxTime.Add_ValueChanged({if($MaxTime.Value-lt$MinTime.Value){$MinTime.Value=$MaxTime.Value};$MaxLabel.Text=('Max {0:N0} s'-f$MaxTime.Value)})
 RefreshSpeedLabControls
 $D.FindName('Advanced').Add_Click({ShowUnifiedAdvancedPerformance})
 $D.FindName('Close').Add_Click({$D.Close()})
 $Run.Add_Click({
  try{
   $Run.IsEnabled=$false;$Status.Text='Building/proving path and running download + upload…';$Detail.Text='Speed Lab running. Temporary paths are transactional and will be torn down/restored when the test completes.'
   $scope=SelectedTag $Scope;$top=SelectedTag $Topology;$duration=SelectedTag $DurationMode;$payload=@{scope=$scope;duration_mode=$duration}
   if($duration-eq'custom'){$payload.min_seconds=[Math]::Round($MinTime.Value);$payload.max_seconds=[Math]::Round($MaxTime.Value)}
   if($scope-eq'temporary'){
    $payload.topology=$top;$payload.node_id=[string]$Node.SelectedValue;$payload.entry_id=[string]$Entry.SelectedValue;$payload.exit_id=[string]$Exit.SelectedValue;$payload.mode=[string]$Mode.SelectedValue;$payload.base=SelectedTag $Base;$payload.exit_mode=SelectedTag $ExitMode
    if($payload.mode-eq'custom'){$payload.custom_layers=@(([string]$Layers.Text).Split(',')|ForEach-Object{$_.Trim()}|Where-Object{$_})}
    $payload.daita=[bool]$D.FindName('DAITA').IsChecked;$payload.jumbo=[bool]$D.FindName('Jumbo').IsChecked;$payload.require_encrypted=[bool]$D.FindName('Encrypted').IsChecked;$payload.require_obfuscation=[bool]$D.FindName('Obfuscated').IsChecked
   }
   $timeout=if($duration-eq'custom'){[Math]::Max(90,[int]($MaxTime.Value*2+75))}else{110};$R=Api '/api/speed-lab/run' 'POST' $payload $timeout;$S=$R.summary;$M=$R.measurement
   $D.FindName('IdleBig').Text=('{0:N1} ms'-f[double]$S.idle_ms);$D.FindName('DownBig').Text=('{0:N1} Mbps'-f[double]$S.download_mbps);$D.FindName('UpBig').Text=('{0:N1} Mbps'-f[double]$S.upload_mbps)
   $D.FindName('IdleDetail').Text=('p90 {0:N1} • max {1:N1} • jitter {2:N1} ms'-f[double]$M.idle_latency.p90_ms,[double]$M.idle_latency.max_ms,[double]$M.idle_latency.jitter_ms)
   $D.FindName('DownDetail').Text=('loaded {0:N1} ms • +{1:N1} bufferbloat • p90 {2:N1}'-f[double]$S.download_loaded_ms,[double]$S.download_bufferbloat_ms,[double]$M.download.loaded_latency.p90_ms)
   $D.FindName('UpDetail').Text=('loaded {0:N1} ms • +{1:N1} bufferbloat • p90 {2:N1}'-f[double]$S.upload_loaded_ms,[double]$S.upload_bufferbloat_ms,[double]$M.upload.loaded_latency.p90_ms)
   $Detail.Text=($R|ConvertTo-Json -Depth 12);$Status.Text=('Finished • {0} / {1} • {2}'-f[string]$R.path.scope,[string]$R.path.topology,[string]$M.provider)
  }catch{$Detail.Text=$_.Exception.Message;$Status.Text='Speed Lab failed closed; see details.'}finally{$Run.IsEnabled=$true}
 });[void]$D.ShowDialog()
}
'@

    $replacement=$advanced+"`n"+$speedLab+"`n(Control 'UnifiedFastestNode')"
    $ProductSource=$ProductSource.Substring(0,$match.Index)+$replacement+$ProductSource.Substring($match.Index+$match.Length)
    $ProductSource+="`n# Windows Speed Lab: /api/speed-lab/options + /api/speed-lab/run, real idle/download-loaded/upload-loaded latency, real HTTPS Mbps, bufferbloat/jitter, current or temporary direct/multihop/external graphs, Auto or custom min/max timing.`n"
    return $ProductSource
}
