function Add-RouterVPNSpeedLabWindowsShell {
    param([Parameter(Mandatory=$true)][string]$ProductSource)
    Set-StrictMode -Version Latest

    # Replace only the performance function, never the following event binding.
    $Functions=@([ScriptBlock]::Create($ProductSource).Ast.FindAll({
        param($Node)
        $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $Node.Name -eq 'ShowUnifiedPerformance'
    },$true))
    if($Functions.Count -ne 1){throw 'Windows Speed Lab performance seam drifted: expected one function.'}
    $Performance=$Functions[0].Extent
    $oldFunction=$Performance.Text
    $advanced=$oldFunction.Replace('function ShowUnifiedPerformance{','function ShowUnifiedAdvancedPerformance{')

    $speedLab=@'
function ShowUnifiedPerformance{ShowUnifiedSpeedLab}
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
  <Border Grid.Row="2" Background="#0D1729" CornerRadius="14" Margin="0,12,0,0" Padding="12"><Grid><Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="160"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="180"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="180"/></Grid.ColumnDefinitions><Grid.RowDefinitions><RowDefinition/><RowDefinition/><RowDefinition/><RowDefinition/></Grid.RowDefinitions>
   <TextBlock Text="Test" VerticalAlignment="Center"/><ComboBox Name="Scope" Grid.Column="1" Margin="8,3"><ComboBoxItem Content="Current path" Tag="current" IsSelected="True"/><ComboBoxItem Content="Temporary config" Tag="temporary"/></ComboBox>
   <TextBlock Grid.Column="2" Text="Topology" VerticalAlignment="Center" Margin="12,0,0,0"/><ComboBox Name="Topology" Grid.Column="3" Margin="8,3"><ComboBoxItem Content="System direct" Tag="system-direct"/><ComboBoxItem Content="Router VPN node" Tag="router" IsSelected="True"/><ComboBoxItem Content="Multihop" Tag="multihop"/><ComboBoxItem Content="External exit / hop" Tag="external"/></ComboBox>
   <TextBlock Grid.Column="4" Text="Mode" VerticalAlignment="Center" Margin="12,0,0,0"/><ComboBox Name="Mode" Grid.Column="5" Margin="8,3" DisplayMemberPath="name" SelectedValuePath="id"/>
   <TextBlock Grid.Row="1" Text="Node / exit" VerticalAlignment="Center"/><ComboBox Name="Node" Grid.Row="1" Grid.Column="1" Margin="8,3" DisplayMemberPath="display" SelectedValuePath="id"/>
   <TextBlock Grid.Row="1" Grid.Column="2" Text="Entry" VerticalAlignment="Center" Margin="12,0,0,0"/><ComboBox Name="Entry" Grid.Row="1" Grid.Column="3" Margin="8,3" DisplayMemberPath="display" SelectedValuePath="id"/>
   <TextBlock Grid.Row="1" Grid.Column="4" Text="Exit" VerticalAlignment="Center" Margin="12,0,0,0"/><ComboBox Name="Exit" Grid.Row="1" Grid.Column="5" Margin="8,3" DisplayMemberPath="display" SelectedValuePath="id"/>
   <TextBlock Grid.Row="2" Text="Base" VerticalAlignment="Center"/><ComboBox Name="Base" Grid.Row="2" Grid.Column="1" Margin="8,3"><ComboBoxItem Content="Auto" Tag="auto" IsSelected="True"/><ComboBoxItem Content="WireGuard" Tag="wg"/><ComboBoxItem Content="AmneziaWG" Tag="awg"/></ComboBox>
   <TextBlock Grid.Row="2" Grid.Column="2" Text="Exit transport" VerticalAlignment="Center" Margin="12,0,0,0"/><ComboBox Name="ExitMode" Grid.Row="2" Grid.Column="3" Margin="8,3"><ComboBoxItem Content="Shadowsocks" Tag="shadowsocks" IsSelected="True"/><ComboBoxItem Content="Hysteria2" Tag="hysteria2"/><ComboBoxItem Content="REALITY Vision" Tag="reality-vision"/><ComboBoxItem Content="PQ REALITY Vision" Tag="reality-pq-vision"/><ComboBoxItem Content="REALITY XHTTP" Tag="reality-xhttp"/><ComboBoxItem Content="Naive H2" Tag="naive-h2"/><ComboBoxItem Content="Naive H3" Tag="naive-h3"/><ComboBoxItem Content="WireGuard" Tag="wg"/><ComboBoxItem Content="AWG Fast" Tag="awg2-fast"/><ComboBoxItem Content="AWG Strong" Tag="awg2-strong"/><ComboBoxItem Content="SS/V2Ray" Tag="ss-v2ray"/><ComboBoxItem Content="Split" Tag="split"/><ComboBoxItem Content="MAX" Tag="max"/><ComboBoxItem Content="WG + PQ" Tag="wg-pq"/><ComboBoxItem Content="AWG + PQ" Tag="awg2-pq"/><ComboBoxItem Content="Complete MAX TLS / WG" Tag="max-tls-wg"/><ComboBoxItem Content="Complete MAX TLS / AWG" Tag="max-tls-awg"/><ComboBoxItem Content="Complete MAX QUIC / WG" Tag="max-quic-wg"/><ComboBoxItem Content="Complete MAX QUIC / AWG" Tag="max-quic-awg"/></ComboBox>
   <TextBlock Grid.Row="2" Grid.Column="4" Text="CUSTOM layers" VerticalAlignment="Center" Margin="12,0,0,0"/><TextBox Name="Layers" Grid.Row="2" Grid.Column="5" Margin="8,3" ToolTip="Comma-separated exact layers; used only when Mode=CUSTOM"/>
   <TextBlock Grid.Row="3" Text="Entry mode" VerticalAlignment="Center"/><ComboBox Name="EntryMode" Grid.Row="3" Grid.Column="1" Margin="8,3" DisplayMemberPath="name" SelectedValuePath="id"/>
   <TextBlock Grid.Row="3" Grid.Column="2" Text="Execution" VerticalAlignment="Center" Margin="12,0,0,0"/><ComboBox Name="Execution" Grid.Row="3" Grid.Column="3" Margin="8,3" DisplayMemberPath="name" SelectedValuePath="id" ToolTip="Server/Compare requires a Router entry, this exit's response probe, and separate packet/OpenVPN pairing. The controller proves the captured path before testing."/>
  </Grid></Border>
  <Border Grid.Row="3" Background="#0D1729" CornerRadius="14" Margin="0,10,0,0" Padding="12"><Grid><Grid.ColumnDefinitions><ColumnDefinition Width="150"/><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><Grid.RowDefinitions><RowDefinition/><RowDefinition/><RowDefinition/></Grid.RowDefinitions>
   <ComboBox Name="DurationMode" Grid.Column="0" Margin="0,0,12,5"><ComboBoxItem Content="Auto timing" Tag="auto" IsSelected="True"/><ComboBoxItem Content="Custom timing" Tag="custom"/></ComboBox>
   <TextBlock Name="MinLabel" Grid.Column="1" Text="Min 4 s" Margin="0,0,8,0"/><TextBlock Name="MaxLabel" Grid.Column="2" Text="Max 12 s" Margin="8,0,0,0"/>
   <Slider Name="MinTime" Grid.Row="1" Grid.Column="1" Minimum="1" Maximum="60" Value="4" TickFrequency="1" IsSnapToTickEnabled="True" Margin="0,4,8,0"/><Slider Name="MaxTime" Grid.Row="1" Grid.Column="2" Minimum="1" Maximum="60" Value="12" TickFrequency="1" IsSnapToTickEnabled="True" Margin="8,4,0,0"/>
   <WrapPanel Grid.Row="2" Grid.ColumnSpan="4" Margin="0,8,0,0"><CheckBox Name="DAITA" Content="DAITA-like" Margin="0,0,14,0"/><CheckBox Name="Jumbo" Content="Jumbo" Margin="0,0,14,0"/><CheckBox Name="Encrypted" Content="Require encrypted AUTO" Margin="0,0,14,0"/><CheckBox Name="Obfuscated" Content="Require obfuscation AUTO"/></WrapPanel>
   <TextBlock Grid.Column="3" Grid.RowSpan="2" Text="Auto runs at least 4 s and up to 12 s per direction, stopping early only after throughput stabilizes. Custom allows 1–60 s." Width="260" TextWrapping="Wrap" Foreground="#8FA3C2" Margin="14,0,0,0"/>
  </Grid></Border>
  <TextBox Name="Detail" Grid.Row="4" Margin="0,10,0,0" Background="#091321" Foreground="#C9D6EA" BorderBrush="#243B59" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" FontFamily="Consolas" Padding="10" Text="Ready. Current path uses the path that is actually connected. Temporary tests capture and restore the complete connected path and its proved execution choice."/>
  <Grid Grid.Row="5" Margin="0,12,0,0"><Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><TextBlock Name="Status" TextWrapping="Wrap" VerticalAlignment="Center" Foreground="#8FA3C2" Text="Cloudflare Speed Test edge • no Mbps derived from RTT"/><Button Name="Advanced" Grid.Column="1" Content="Advanced node tests" Padding="11,7" Margin="5,0"/><Button Name="Ordered" Grid.Column="2" Content="50 responses per hop" Padding="11,7" Margin="5,0"/><Button Name="Run" Grid.Column="3" Content="Run Speed Lab" Padding="16,7" Margin="5,0" IsDefault="True"/><Button Name="Close" Grid.Column="4" Content="Close" Padding="11,7" Margin="5,0"/></Grid>
 </Grid>
</Window>
"@
 $Reader=New-Object System.Xml.XmlNodeReader $SX;$D=[Windows.Markup.XamlReader]::Load($Reader);$D.Owner=$Window
 $Scope=$D.FindName('Scope');$Topology=$D.FindName('Topology');$Mode=$D.FindName('Mode');$Node=$D.FindName('Node');$Entry=$D.FindName('Entry');$Exit=$D.FindName('Exit');$Base=$D.FindName('Base');$ExitMode=$D.FindName('ExitMode');$EntryMode=$D.FindName('EntryMode');$Execution=$D.FindName('Execution');$Layers=$D.FindName('Layers');$DurationMode=$D.FindName('DurationMode');$MinTime=$D.FindName('MinTime');$MaxTime=$D.FindName('MaxTime');$MinLabel=$D.FindName('MinLabel');$MaxLabel=$D.FindName('MaxLabel');$Run=$D.FindName('Run');$Advanced=$D.FindName('Advanced');$Ordered=$D.FindName('Ordered');$Status=$D.FindName('Status');$Detail=$D.FindName('Detail');$D.Tag='initial'
 function SelectedTag($Combo){if($null-eq$Combo.SelectedItem){return''};return [string]$Combo.SelectedItem.Tag}
 $SpeedLabOptions=@{nodes=@();captured_profile_tokens=$null;router_vpn_entry_modes=@();supported_entry_modes=@();supported_exit_modes=@();current=$null;execution_choices=@();updating=$false}
 function SpeedLabValue($Item,[string]$Name,$Default=''){
  if($null-eq$Item){return $Default};if($Item-is[System.Collections.IDictionary]){if($Item.Contains($Name)-and$null-ne$Item[$Name]){return $Item[$Name]};return $Default};$P=$Item.PSObject.Properties[$Name];if($null-eq$P-or$null-eq$P.Value){return $Default};return $P.Value
 }
 function SpeedLabKind($Item){return [string](SpeedLabValue $Item 'node_kind' 'router-vpn')}
 function CaptureSpeedLabProfileTokens($Nodes){
  $tokens=[System.Collections.Hashtable]::new([StringComparer]::Ordinal)
  foreach($record in @($Nodes)){
   $id=SpeedLabValue $record 'id' $null;$token=SpeedLabValue $record 'profile_token' $null
   if($id-isnot[string]-or-not$id-or$tokens.ContainsKey($id)-or$token-isnot[string]-or$token-cnotmatch'^[a-f0-9]{64}$'){throw 'A Speed Lab node has no unique source identity. Reopen Speed Lab.'}
   $tokens[$id]=$token
  }
  return $tokens
 }
 function CaptureSpeedLabSelection{
  $enabled=[bool](Control 'UnifiedMultihop').IsChecked-and(SpeedLabKind $RouterCombo.SelectedItem)-ne'external'
  return [pscustomobject]@{selectedNodeID=[string]$RouterCombo.SelectedValue;selectedNodeToken=[string](SpeedLabValue $RouterCombo.SelectedItem 'profile_token');multihopEnabled=$enabled;entryID=$(if($enabled){[string]$MultihopEntryCombo.SelectedValue}else{''});exitID=$(if($enabled){[string]$MultihopExitCombo.SelectedValue}else{''});entryToken=$(if($enabled){[string](SpeedLabValue $MultihopEntryCombo.SelectedItem 'profile_token')}else{''});exitToken=$(if($enabled){[string](SpeedLabValue $MultihopExitCombo.SelectedItem 'profile_token')}else{''});entryMode=$(if($enabled){MultihopEntryModeChoice}else{''});exitMode=$(if($enabled){SelectedTag $MultihopExitModeCombo}else{''});execution=$(if($enabled){SelectedTag (Control 'UnifiedExecution')}else{''})}
 }
 function AssertSpeedLabSelection($Opt){
  $visible=CaptureSpeedLabSelection
  foreach($key in @('selectedNodeID','selectedNodeToken','multihopEnabled','entryID','exitID','entryToken','exitToken','entryMode','exitMode','execution')){if($visible.$key-cne$CapturedSpeedLabSelection.$key){throw 'The visible connection profile changed while Speed Lab loaded. Reopen Speed Lab for that selection.'}}
  if($CapturedSpeedLabSelection.selectedNodeID){
   $selected=@($Opt.nodes|Where-Object{[bool](SpeedLabValue $_ 'selected' $false)})
   $matching=@($Opt.nodes|Where-Object{[string]$_.id-ceq$CapturedSpeedLabSelection.selectedNodeID})
   if($selected.Count-ne1-or$matching.Count-ne1-or[string]$selected[0].id-cne$CapturedSpeedLabSelection.selectedNodeID){throw 'The selected node changed or disappeared while Speed Lab loaded. Reopen Speed Lab.'}
  }
  foreach($pair in @(@('selectedNodeID','selectedNodeToken'),@('entryID','entryToken'),@('exitID','exitToken'))){
   $token=[string]$CapturedSpeedLabSelection.($pair[1]);if(-not$token){continue};$id=[string]$CapturedSpeedLabSelection.($pair[0]);$found=@($Opt.nodes|Where-Object{[string]$_.id-ceq$id})
   if($found.Count-ne1-or[string](SpeedLabValue $found[0] 'profile_token')-cne$token){throw 'A captured node was removed or relinked while Speed Lab loaded. Reopen Speed Lab for its current identity.'}
  }
 }
 function SelectSpeedLabTag($Combo,[string]$ID){
  $Combo.SelectedIndex=-1;for($i=0;$i-lt$Combo.Items.Count;$i++){if([string]$Combo.Items[$i].Tag-ceq$ID){$Combo.SelectedIndex=$i;break}}
 }
 function ApplySpeedLabSelection{
  if(-not$CapturedSpeedLabSelection.multihopEnabled){return}
  $selected=SpeedLabFind 'nodes' $CapturedSpeedLabSelection.selectedNodeID
  if($null-eq$selected-or(SpeedLabKind $selected)-ne'router-vpn'){throw 'The captured multihop profile no longer belongs to a linked Router VPN node.'}
  $SpeedLabOptions.updating=$true
  try{
   SelectSpeedLabTag $Topology 'multihop';SelectSpeedLabChoice $Node $CapturedSpeedLabSelection.selectedNodeID
   SelectSpeedLabChoice $Entry $CapturedSpeedLabSelection.entryID;SelectSpeedLabChoice $Exit $CapturedSpeedLabSelection.exitID
   SetSpeedLabEntryMode
   SelectSpeedLabChoice $EntryMode $CapturedSpeedLabSelection.entryMode;SelectSpeedLabTag $ExitMode $CapturedSpeedLabSelection.exitMode;SelectSpeedLabChoice $Execution $CapturedSpeedLabSelection.execution
  }finally{$SpeedLabOptions.updating=$false}
 }
 # Detached values belong to this window. Later callbacks only compare the
 # current main controls to this snapshot; they never recapture its defaults.
 $CapturedSpeedLabSelection=CaptureSpeedLabSelection
 function SpeedLabFind([string]$Key,[string]$ID){
  if(-not$ID){return $null};$found=@($SpeedLabOptions[$Key]|Where-Object{[string]$_.id-ceq$ID});if($found.Count-ne1){return $null};return $found[0]
 }
 function NodeItems($Values,[string]$Kind){
  $out=New-Object System.Collections.ArrayList;foreach($n in @($Values)){if($Kind-and(SpeedLabKind $n)-ne$Kind){continue};$ms=[double](SpeedLabValue $n 'latency_trimmed_mean_ms' 0);$suffix=if($ms-gt0){' • {0:N1} ms'-f$ms}else{''};[void]$out.Add([pscustomobject]@{id=[string]$n.id;display=([string]$n.name+$suffix);kind=(SpeedLabKind $n)})};return @($out)
 }
 function SelectSpeedLabChoice($Combo,[string]$ID){
  $items=@($Combo.ItemsSource);if(@($items|Where-Object{[string]$_.id-ceq$ID}).Count-eq0){$Combo.ItemsSource=@($items)+@([pscustomobject]@{id=$ID;name=('Unavailable saved choice: '+$ID);display=('Unavailable saved choice: '+$ID)})};$Combo.SelectedValue=$ID
 }
 function SpeedLabNodeChoice($NodeValue,[string]$Key,[string]$ID){
  $values=@(SpeedLabValue $NodeValue $Key @());return $ID-and@($values|Where-Object{$_-is[string]-and$_-ceq$ID}).Count-eq1
 }
 function SetSpeedLabEntryMode{
  $entryValue=SpeedLabFind 'nodes' ([string]$Entry.SelectedValue);$nodeValue=SpeedLabFind 'nodes' ([string]$Node.SelectedValue)
  $previousExecution=[string]$Execution.SelectedValue;$Execution.ItemsSource=@($SpeedLabOptions.execution_choices)
  if((SelectedTag $Topology)-eq'multihop'){
   $paired=(SpeedLabKind $entryValue)-eq'router-vpn'
   $values=if($paired){@($SpeedLabOptions.supported_entry_modes)}else{@(SpeedLabValue $entryValue 'multihop_entry_modes' @())}
   $choices=@();if($paired){$choices+=@([pscustomobject]@{id='';name='Use saved entry mode / base'})}
   foreach($id in $values){if($id-is[string]-and$id){$label=[string](SpeedLabValue (SpeedLabFind 'router_vpn_entry_modes' $id) 'name' $id);$choices+=@([pscustomobject]@{id=$id;name=$label})}}
   $EntryMode.ItemsSource=$choices
   if(-not$paired){$Execution.ItemsSource=@($SpeedLabOptions.execution_choices|Where-Object{SpeedLabNodeChoice $entryValue 'multihop_execution_choices' ([string]$_.id)});$previousExecution='local'}
   SelectSpeedLabChoice $Execution $previousExecution
   $modeValue=if($paired){[string](SpeedLabValue $nodeValue 'multihop_entry_mode')}else{[string](SpeedLabValue $entryValue 'external_protocol')}
   SelectSpeedLabChoice $EntryMode $modeValue;return
  }
  SelectSpeedLabChoice $Execution $previousExecution
  $EntryMode.ItemsSource=@([pscustomobject]@{id='';name='Use saved entry mode / base'})+@($SpeedLabOptions.router_vpn_entry_modes)
  if($null-eq$entryValue-or(SpeedLabKind $entryValue)-ne'router-vpn'){$EntryMode.SelectedIndex=-1;return}
  $modeValue='';if($null-ne$nodeValue-and([string]$Entry.SelectedValue)-ceq([string](SpeedLabValue $nodeValue 'multihop_entry_id'))){$modeValue=[string](SpeedLabValue $nodeValue 'multihop_entry_mode')}
  if(-not$modeValue){$baseValue=[string](SpeedLabValue $entryValue 'base_tunnel');if($baseValue-notin@('wg','awg')){$baseValue=[string](SpeedLabValue $nodeValue 'base_tunnel')};$modeValue=if($baseValue-eq'awg'){'awg2-fast'}else{'wg'}}
  SelectSpeedLabChoice $EntryMode $modeValue
 }
 function SetSpeedLabDefaults{
  if($SpeedLabOptions.updating){return};$n=SpeedLabFind 'nodes' ([string]$Node.SelectedValue);if($null-eq$n){return}
  $SpeedLabOptions.updating=$true
  try{
   $saved=[bool](SpeedLabValue $n 'multihop_enabled' $false);$top=SelectedTag $Topology
   $baseValue=[string](SpeedLabValue $n 'base_tunnel' 'auto');if(-not$baseValue){$baseValue='auto'}
   $Base.SelectedIndex=-1;for($i=0;$i-lt$Base.Items.Count;$i++){if([string]$Base.Items[$i].Tag-ceq$baseValue){$Base.SelectedIndex=$i;break}}
   if($top-eq'external'){
    $entryValue=if($saved){[string](SpeedLabValue $n 'multihop_entry_id')}else{''};SelectSpeedLabChoice $Entry $entryValue
    $executionValue=if($saved){[string](SpeedLabValue $n 'multihop_execution' 'local')}else{'local'};if(-not$executionValue){$executionValue='local'};SelectSpeedLabChoice $Execution $executionValue;SetSpeedLabEntryMode
   }elseif($top-eq'multihop'){
    $entryValue=if($saved){[string](SpeedLabValue $n 'multihop_entry_id')}else{[string]$n.id};if(-not$entryValue){$entryValue=[string]$n.id};SelectSpeedLabChoice $Entry $entryValue
    $exitValue=[string](SpeedLabValue $n 'multihop_exit_id');if($saved-and$exitValue){SelectSpeedLabChoice $Exit $exitValue}
    if(([string](SpeedLabValue $SpeedLabOptions.current 'entry_id'))-ceq([string]$Entry.SelectedValue)-and([string](SpeedLabValue $SpeedLabOptions.current 'exit_id'))-ceq([string]$Exit.SelectedValue)){
     $exitModeValue=[string](SpeedLabValue $SpeedLabOptions.current 'exit_mode');$ExitMode.SelectedIndex=-1
     for($i=0;$i-lt$ExitMode.Items.Count;$i++){if([string]$ExitMode.Items[$i].Tag-ceq$exitModeValue){$ExitMode.SelectedIndex=$i;break}}
    }
    $executionValue=if($saved){[string](SpeedLabValue $n 'multihop_execution' 'local')}else{'local'};if(-not$executionValue){$executionValue='local'};SelectSpeedLabChoice $Execution $executionValue;SetSpeedLabEntryMode
   }
  }finally{$SpeedLabOptions.updating=$false}
 }
 function SpeedLabPathChanged([string]$Changed){
  if($SpeedLabOptions.updating){return}
  if($Changed-eq'entry'){
   $SpeedLabOptions.updating=$true
   try{SetSpeedLabEntryMode;$n=SpeedLabFind 'nodes' ([string]$Entry.SelectedValue);if($null-eq$n-or(SpeedLabKind $n)-ne'router-vpn'){SelectSpeedLabChoice $Execution 'local'}}finally{$SpeedLabOptions.updating=$false}
  }else{
   if($Changed-eq'topology'){
    $kind=if((SelectedTag $Topology)-eq'external'){'external'}else{'router-vpn'};$n=SpeedLabFind 'nodes' ([string]$Node.SelectedValue)
    if($null-eq$n-or(SpeedLabKind $n)-ne$kind){$SpeedLabOptions.updating=$true;try{$Node.SelectedIndex=-1;$first=@($SpeedLabOptions.nodes|Where-Object{(SpeedLabKind $_)-eq$kind});if($first.Count){$Node.SelectedValue=[string]$first[0].id}}finally{$SpeedLabOptions.updating=$false}}
   };SetSpeedLabDefaults
  };RefreshSpeedLabControls
 }
 function SpeedLabServerReady($NodeValue,[string]$Execution){
  $protocol=[string](SpeedLabValue $NodeValue 'external_protocol')
  if($protocol-cin@('tor','tor-bridge')){
   if($Execution-cnotin@('server','auto')){return $false}
   $field=if($Execution-ceq'auto'){'tor_compare_execution'}else{'tor_server_execution'}
   $available=SpeedLabValue $NodeValue $field $null
   if($available-isnot[bool]-or-not$available){return $false}
   if($Execution-ceq'auto'){$paired=SpeedLabValue $NodeValue 'tor_compare_requires_paired_source' $null;return $paired-is[bool]-and$paired}
   return $true
  }
  if(-not[bool](SpeedLabValue $NodeValue 'has_response_probe' $false)){return $false}
  if($protocol-in@('wireguard','amneziawg')){return [bool](SpeedLabValue $NodeValue 'has_server_peer' $false)}
  if($protocol-eq'openvpn'){return [bool](SpeedLabValue $NodeValue 'has_openvpn_pairing' $false)}
  return $protocol-in@('shadowsocks','hysteria2','socks5','http-connect','https-connect')
 }
 function SpeedLabTorCompareRequest($Payload){
  if((SpeedLabValue $Payload 'scope')-cne'temporary'-or(SpeedLabValue $Payload 'topology')-cne'external'-or(SpeedLabValue $Payload 'execution')-cne'auto'){return $false}
  $n=SpeedLabFind 'nodes' ([string](SpeedLabValue $Payload 'node_id'))
  return $null-ne$n-and(SpeedLabValue $n 'external_protocol') -cin@('tor','tor-bridge')
 }
 function SpeedLabRequestTimeout($Payload){
  if(SpeedLabTorCompareRequest $Payload){return 960}
  if((SpeedLabValue $Payload 'duration_mode')-ceq'custom'){return [Math]::Max(90,[int]([double](SpeedLabValue $Payload 'max_seconds' 0)*2+75))}
  return 110
 }
 function CompleteSpeedLabRequest($Payload){
  $ids=@($CapturedSpeedLabSelection.selectedNodeID)
  if($CapturedSpeedLabSelection.multihopEnabled){$ids+=@($CapturedSpeedLabSelection.entryID,$CapturedSpeedLabSelection.exitID)}
  if($Payload['scope']-eq'temporary'){
   if($Payload['topology']-ne'system-direct'){foreach($key in @('node_id','entry_id','exit_id')){$ids+=[string]$Payload[$key]}}
  }elseif([bool](SpeedLabValue $SpeedLabOptions.current 'connected' $false)){
   foreach($key in @('router_id','entry_id','exit_id')){$ids+=[string](SpeedLabValue $SpeedLabOptions.current $key)}
  }
  $tokens=[System.Collections.Hashtable]::new([StringComparer]::Ordinal)
  foreach($id in @($ids|Where-Object{$_})){
   $record=SpeedLabFind 'nodes' $id;$token=[string](SpeedLabValue $record 'profile_token')
   $captured=$SpeedLabOptions.captured_profile_tokens
   if($null-eq$record-or$token-cnotmatch'^[a-f0-9]{64}$'-or$null-eq$captured-or-not$captured.ContainsKey($id)-or$token-cne$captured[$id]){throw 'A test node was removed, relinked, or has no captured identity. Reopen Speed Lab before running this path.'}
   $tokens[$id]=$captured[$id]
  }
  $Payload.expected_selected_node_id=[string]$CapturedSpeedLabSelection.selectedNodeID;$Payload.expected_profile_tokens=$tokens
  if(SpeedLabTorCompareRequest $Payload){$Payload.comparison_request_id=[Guid]::NewGuid().ToString('N')}
  return $Payload
 }
 function NewSpeedLabRequest{
  AssertSpeedLabSelection $SpeedLabOptions
  $scope=SelectedTag $Scope;$top=SelectedTag $Topology;$duration=SelectedTag $DurationMode;$payload=@{scope=$scope;duration_mode=$duration}
  if($duration-eq'custom'){$payload.min_seconds=[Math]::Round($MinTime.Value);$payload.max_seconds=[Math]::Round($MaxTime.Value)}
  if($scope-ne'temporary'){return CompleteSpeedLabRequest $payload};$payload.topology=$top
  if($top-eq'system-direct'){return CompleteSpeedLabRequest $payload}
  $n=SpeedLabFind 'nodes' ([string]$Node.SelectedValue);$entryValue=SpeedLabFind 'nodes' ([string]$Entry.SelectedValue);$executionValue=[string]$Execution.SelectedValue
  if($top-eq'router'){
   if($null-eq$n-or(SpeedLabKind $n)-ne'router-vpn'){throw 'Select a linked Router VPN node.'}
   $payload.node_id=[string]$Node.SelectedValue;$payload.mode=[string]$Mode.SelectedValue;$payload.base=SelectedTag $Base
   if($payload.mode-eq'custom'){$payload.custom_layers=@(([string]$Layers.Text).Split(',')|ForEach-Object{$_.Trim()}|Where-Object{$_})}
  }elseif($top-eq'multihop'){
   $exitValue=SpeedLabFind 'nodes' ([string]$Exit.SelectedValue)
   if($null-eq$entryValue-or$null-eq$exitValue-or(SpeedLabKind $exitValue)-ne'router-vpn'-or([string]$Entry.SelectedValue)-ceq([string]$Exit.SelectedValue)){throw 'Select a linked entry and a different paired Router VPN final.'}
   $paired=(SpeedLabKind $entryValue)-eq'router-vpn';$modeValue=[string]$EntryMode.SelectedValue
   if((SelectedTag $ExitMode)-cnotin@($SpeedLabOptions.supported_exit_modes)){throw 'Select an exit transport supported by the installed runtime.'}
   if($paired){
    if($null-eq$EntryMode.SelectedItem-or($modeValue-and$modeValue-cnotin@($SpeedLabOptions.supported_entry_modes))){throw 'Select an entry mode supported by the installed runtime, or the saved entry mode / base.'}
   }else{
    if((SpeedLabKind $entryValue)-cne'external'-or$modeValue-cne[string](SpeedLabValue $entryValue 'external_protocol')-or-not(SpeedLabNodeChoice $entryValue 'multihop_entry_modes' $modeValue)){throw 'Select the original imported entry protocol.'}
    if($executionValue-cne'local'-or-not(SpeedLabNodeChoice $entryValue 'multihop_execution_choices' $executionValue)){throw 'This imported entry uses Local execution.'}
    if(-not(SpeedLabNodeChoice $entryValue 'multihop_exit_modes' (SelectedTag $ExitMode))){throw 'Select a compatible paired final transport for this imported entry.'}
   }
   $payload.entry_mode=$modeValue;$payload.entry_id=[string]$Entry.SelectedValue;$payload.exit_id=[string]$Exit.SelectedValue;$payload.base=$(if($paired){SelectedTag $Base}else{'auto'});$payload.exit_mode=SelectedTag $ExitMode;$payload.execution=$executionValue
  }elseif($top-eq'external'){
   if($null-eq$n-or(SpeedLabKind $n)-ne'external'){throw 'Select a linked external exit.'}
   $entryID=[string]$Entry.SelectedValue
   if($entryID-and($null-eq$entryValue-or$entryID-ceq([string]$Node.SelectedValue))){throw 'Select a different linked entry, or Direct.'}
   $payload.node_id=[string]$Node.SelectedValue;$payload.entry_id=$entryID;$payload.execution=$executionValue
   if($null-ne$entryValue-and(SpeedLabKind $entryValue)-eq'router-vpn'){
    $modeValue=[string]$EntryMode.SelectedValue;if($null-eq(SpeedLabFind 'router_vpn_entry_modes' $modeValue)){throw 'Select a supported Router entry mode.'};$payload.entry_mode=$modeValue
    if($executionValue-cne'local'-and(SpeedLabValue $n 'external_protocol') -cin@('tor','tor-bridge')-and((SpeedLabValue $entryValue 'external_protocol')-or$null-ne(SpeedLabValue $entryValue 'external' $null))){throw 'Tor Server/Compare requires a private Router entry source.'}
    if($executionValue-ne'local'-and-not(SpeedLabServerReady $n $executionValue)){throw "Tor Server/Compare requires advertised native support and a paired private Router entry. Other exits require their response probe and separate server pairing."}
   }elseif($executionValue-ne'local'){throw 'Direct and ordinary external entry paths use Local execution.'}
  }else{throw 'Select a supported test topology.'}
  if($top-in@('multihop','external')){if($executionValue-notin@('local','server','auto')-or$null-eq(SpeedLabFind 'execution_choices' $executionValue)){throw 'Select Local, Server, or Compare both from the current capabilities.'}}
  $payload.daita=[bool]$D.FindName('DAITA').IsChecked;$payload.jumbo=[bool]$D.FindName('Jumbo').IsChecked;$payload.require_encrypted=[bool]$D.FindName('Encrypted').IsChecked;$payload.require_obfuscation=[bool]$D.FindName('Obfuscated').IsChecked
  return CompleteSpeedLabRequest $payload
 }
 function RefreshSpeedLabControls{
  $temporary=(SelectedTag $Scope)-eq'temporary';foreach($c in @($Topology,$Mode,$Node,$Entry,$Exit,$Base,$ExitMode,$EntryMode,$Execution,$Layers,$D.FindName('DAITA'),$D.FindName('Jumbo'),$D.FindName('Encrypted'),$D.FindName('Obfuscated'))){$c.IsEnabled=$temporary}
  $custom=(SelectedTag $DurationMode)-eq'custom';$MinTime.IsEnabled=$custom;$MaxTime.IsEnabled=$custom
  $top=SelectedTag $Topology;$Entry.IsEnabled=$temporary-and($top-eq'multihop'-or$top-eq'external');$Exit.IsEnabled=$temporary-and$top-eq'multihop';$ExitMode.IsEnabled=$temporary-and$top-eq'multihop';$Layers.IsEnabled=$temporary-and$top-eq'router'-and([string]$Mode.SelectedValue)-eq'custom'
  $entryValue=SpeedLabFind 'nodes' ([string]$Entry.SelectedValue);$routerEntry=$null-ne$entryValue-and(SpeedLabKind $entryValue)-eq'router-vpn';$EntryMode.IsEnabled=$temporary-and($top-eq'multihop'-or$top-eq'external'-and$routerEntry);$Execution.IsEnabled=$temporary-and($top-eq'multihop'-or($top-eq'external'-and$routerEntry));$Mode.IsEnabled=$temporary-and$top-eq'router';$Node.IsEnabled=$temporary-and$top-in@('router','external');$Base.IsEnabled=$temporary-and($top-eq'router'-or$top-eq'multihop'-and$routerEntry)
 }
 $Run.IsEnabled=$false
 $D.Add_Loaded({
  if([string]$D.Tag-ne'initial'){return};$D.Tag='owned-options';$Status.Text='Loading Speed Lab paths…';$Detail.Text='Loading current node/mode capabilities without blocking the app.'
  $Success={param($Opt)
   if([string]$D.Tag-ne'owned-options'){return}
   try{AssertSpeedLabSelection $Opt;$capturedTokens=CaptureSpeedLabProfileTokens @($Opt.nodes)}catch{$Detail.Text=$_.Exception.Message;$Status.Text='Speed Lab selection changed.';$Run.IsEnabled=$false;$D.Tag='error';return}
   $SpeedLabOptions.updating=$true
   try{
    $SpeedLabOptions.supported_entry_modes=@(SpeedLabValue $Opt 'supported_entry_modes' @());$SpeedLabOptions.supported_exit_modes=@(SpeedLabValue $Opt 'supported_exit_modes' @());$SpeedLabOptions.current=SpeedLabValue $Opt 'current' $null
    $SpeedLabOptions.nodes=@($Opt.nodes);$SpeedLabOptions.captured_profile_tokens=$capturedTokens;$SpeedLabOptions.router_vpn_entry_modes=@(SpeedLabValue $Opt 'router_vpn_entry_modes' @());$SpeedLabOptions.execution_choices=@(SpeedLabValue $Opt 'execution_choices' @())
    $Mode.ItemsSource=@($Opt.logical_modes);if($Mode.Items.Count){$Mode.SelectedValue='smart-auto'}
    $EntryMode.ItemsSource=@([pscustomobject]@{id='';name='Use saved entry mode / base'})+@($SpeedLabOptions.router_vpn_entry_modes);$Execution.ItemsSource=@($SpeedLabOptions.execution_choices);SelectSpeedLabChoice $Execution 'local'
    $Node.ItemsSource=NodeItems $Opt.nodes ''; $Entry.ItemsSource=@([pscustomobject]@{id='';display='Direct / no entry';kind=''})+@(NodeItems $Opt.nodes ''); $Exit.ItemsSource=NodeItems $Opt.nodes 'router-vpn'
    if($Node.Items.Count){$Node.SelectedIndex=0};if($Exit.Items.Count-gt1){$Exit.SelectedIndex=1}elseif($Exit.Items.Count){$Exit.SelectedIndex=0}
    $selected=@($Opt.nodes|Where-Object{[bool](SpeedLabValue $_ 'selected' $false)});if($selected.Count-eq1){$Node.SelectedValue=[string]$selected[0].id}
    $selectedNode=SpeedLabFind 'nodes' ([string]$Node.SelectedValue);$topDefault=if($null-ne$selectedNode-and(SpeedLabKind $selectedNode)-eq'external'){'external'}elseif([bool](SpeedLabValue $selectedNode 'multihop_enabled' $false)){'multihop'}else{'router'}
    foreach($item in $Topology.Items){if([string]$item.Tag-ceq$topDefault){$Topology.SelectedItem=$item;break}}
   }finally{$SpeedLabOptions.updating=$false};SetSpeedLabDefaults
   try{ApplySpeedLabSelection}catch{$Detail.Text=$_.Exception.Message;$Status.Text='Speed Lab selection unavailable.';$Run.IsEnabled=$false;$D.Tag='error';return}
   $Run.IsEnabled=$true;$D.Tag='ready';$Status.Text='Cloudflare Speed Test edge • no Mbps derived from RTT';$Detail.Text='Ready. Current path uses the path that is actually connected. Temporary tests capture and restore the complete connected path and its proved execution choice.';RefreshSpeedLabControls
  }.GetNewClosure()
  $Failure={param($E)$Detail.Text='Could not load Speed Lab options: '+$E;$Status.Text='Speed Lab options unavailable.';$Run.IsEnabled=$false;$D.Tag='error'}.GetNewClosure()
  $Finally={if([string]$D.Tag-eq'owned-options'){$D.Tag='error'}}.GetNewClosure()
  if(-not(StartUnifiedApiAsync 'Loading Speed Lab options…' '/api/speed-lab/options' 'GET' $null 10 $Success $Failure $Finally)){$D.Tag='error';$Run.IsEnabled=$false}
 })
 $DurationMode.Add_SelectionChanged({RefreshSpeedLabControls});$Scope.Add_SelectionChanged({RefreshSpeedLabControls});$Topology.Add_SelectionChanged({SpeedLabPathChanged 'topology'});$Node.Add_SelectionChanged({SpeedLabPathChanged 'node'});$Entry.Add_SelectionChanged({SpeedLabPathChanged 'entry'});$Mode.Add_SelectionChanged({RefreshSpeedLabControls})
 $MinTime.Add_ValueChanged({if($MinTime.Value-gt$MaxTime.Value){$MaxTime.Value=$MinTime.Value};$MinLabel.Text=('Min {0:N0} s'-f$MinTime.Value)})
 $MaxTime.Add_ValueChanged({if($MaxTime.Value-lt$MinTime.Value){$MinTime.Value=$MaxTime.Value};$MaxLabel.Text=('Max {0:N0} s'-f$MaxTime.Value)})
 RefreshSpeedLabControls
 $Advanced.Add_Click({ShowUnifiedAdvancedPerformance})
 $Ordered.Add_Click({try{if(-not(UnifiedAsyncBusy)){$CapturedOrderedID=[string]$RouterCombo.SelectedValue;$CurrentOrderedSelection={return [string]$RouterCombo.SelectedValue-ceq$CapturedOrderedID}.GetNewClosure();Show-RouterVPNOrderedLatency -BaseUrl $BaseUrl -Owner $D -DisplayedProfileID $CapturedOrderedID -SelectionCurrent $CurrentOrderedSelection}}catch{$Detail.Text=$_.Exception.Message;$Status.Text='Hop measurements unavailable.'}})
 $D.FindName('Close').Add_Click({if(([string]$D.Tag).StartsWith('owned')-and(UnifiedAsyncBusy)){[void](CancelUnifiedApiAsync $false)};$D.Close()})
 $D.Add_Closed({$owned=([string]$D.Tag).StartsWith('owned');$D.Tag='closed';if($owned-and(UnifiedAsyncBusy)){[void](CancelUnifiedApiAsync $false)}})
 $Run.Add_Click({
  if([string]$D.Tag-ne'ready'){return}
  try{
   if(UnifiedAsyncBusy){throw 'Another Router VPN action is still running.'}
   $Run.IsEnabled=$false;$Advanced.IsEnabled=$false;$Ordered.IsEnabled=$false;$D.Tag='owned-run';$Status.Text='Building/proving path and running download + upload…';$Detail.Text='Speed Lab running. Temporary paths are transactional and will be torn down/restored when the test completes or is cancelled.'
   $payload=NewSpeedLabRequest;$duration=SelectedTag $DurationMode
   $timeout=SpeedLabRequestTimeout $payload
   if(SpeedLabTorCompareRequest $payload){$Status.Text='Comparing Local and Server Tor paths…';$Detail.Text='Each candidate measures Tor last-relay HTTP and the same external-server HTTP response. The lowest valid average is rechecked before throughput testing; the captured connection is restored afterward.'}
   $comparisonRequestID=[string](SpeedLabValue $payload 'comparison_request_id')
   $Comparison={param($Progress,[string]$Text)
    if([string]$D.Tag-cne'owned-run'-or-not(UnifiedComparisonProgressOwned $comparisonRequestID)){return}
    $Record=SpeedLabValue $Progress 'comparison' $null
    if((SpeedLabValue $Record 'request_id')-cne$comparisonRequestID){return}
    $Status.Text=if((SpeedLabValue $Record 'complete' $false)-ceq$true){if(SpeedLabValue $Record 'failure'){'Tor comparison failed; captured-path restoration continues…'}else{'Tor comparison complete; throughput testing and captured-path restoration continue…'}}else{'Comparing Local and Server Tor paths…'}
    $Detail.Text=$Text
   }.GetNewClosure()
   $Success={param($R)
    if([string]$D.Tag-cne'owned-run'){return}
    $S=$R.summary;$M=$R.measurement
    $D.FindName('IdleBig').Text=('{0:N1} ms'-f[double]$S.idle_ms);$D.FindName('DownBig').Text=('{0:N1} Mbps'-f[double]$S.download_mbps);$D.FindName('UpBig').Text=('{0:N1} Mbps'-f[double]$S.upload_mbps)
    $D.FindName('IdleDetail').Text=('p90 {0:N1} • max {1:N1} • jitter {2:N1} ms'-f[double]$M.idle_latency.p90_ms,[double]$M.idle_latency.max_ms,[double]$M.idle_latency.jitter_ms)
    $D.FindName('DownDetail').Text=('loaded {0:N1} ms • +{1:N1} bufferbloat • p90 {2:N1}'-f[double]$S.download_loaded_ms,[double]$S.download_bufferbloat_ms,[double]$M.download.loaded_latency.p90_ms)
    $D.FindName('UpDetail').Text=('loaded {0:N1} ms • +{1:N1} bufferbloat • p90 {2:N1}'-f[double]$S.upload_loaded_ms,[double]$S.upload_bufferbloat_ms,[double]$M.upload.loaded_latency.p90_ms)
    $HopLines=New-Object System.Collections.Generic.List[string]
    foreach($H in @($R.hops)){
     if($null-eq$H){continue};$role=([string]$H.role).ToUpperInvariant();$name=[string]$H.name;if([string]::IsNullOrWhiteSpace($name)){$name=[string]$H.router_id}
     $latLabel=[string](SpeedLabValue $H 'latency_label' 'HTTP response');$lat=$latLabel+' unavailable';$lp=$H.PSObject.Properties['latency'];if($lp-and$null-ne$lp.Value){$lat=('{0}: {1:N1} ms'-f$latLabel,[double]$lp.Value.median_ms)}elseif($H.PSObject.Properties['latency_error']){$lat=$latLabel+' unavailable: '+[string]$H.latency_error}
     $spdLabel=[string](SpeedLabValue $H 'speed_label' 'Transfer');$spd=$spdLabel+' unavailable';$sp=$H.PSObject.Properties['speed'];if($sp-and$null-ne$sp.Value){$spd=('{0}: ↓ {1:N1} / ↑ {2:N1} Mbps'-f$spdLabel,[double]$sp.Value.download_mbps,[double]$sp.Value.upload_mbps)}elseif($H.PSObject.Properties['speed_error']){$spd='speed unavailable: '+[string]$H.speed_error}
     [void]$HopLines.Add(('{0} • {1} • {2} • {3}'-f$role,$name,$lat,$spd))
    }
    $Json=$R|ConvertTo-Json -Depth 12;if($HopLines.Count){$Detail.Text="PER-HOP — SAME PROVED GRAPH$([Environment]::NewLine)"+($HopLines-join[Environment]::NewLine)+"$([Environment]::NewLine)$([Environment]::NewLine)FULL RESULT$([Environment]::NewLine)"+$Json}else{$Detail.Text=$Json}
    $hopSuffix=if($HopLines.Count){' • '+$HopLines.Count+' hop measurements'}else{''};$Status.Text=('Finished • {0} / {1} • {2}{3}'-f[string]$R.path.scope,[string]$R.path.topology,[string]$M.provider,$hopSuffix)
   }.GetNewClosure()
   $Failure={param($E)if([string]$D.Tag-cne'owned-run'){return};$Detail.Text=$E;$Status.Text='Speed Lab failed closed; see details.'}.GetNewClosure()
   $Finally={if([string]$D.Tag-cne'owned-run'){return};$Run.IsEnabled=$true;$Advanced.IsEnabled=$true;$Ordered.IsEnabled=$true;$D.Tag='ready';RefreshProduct;RefreshUnifiedTelemetry}.GetNewClosure()
   if(-not(StartUnifiedApiAsync 'Running Speed Lab…' '/api/speed-lab/run' 'POST' $payload $timeout $Success $Failure $Finally $Comparison)){$Run.IsEnabled=$true;$Advanced.IsEnabled=$true;$Ordered.IsEnabled=$true;$D.Tag='ready'}
  }catch{$Detail.Text=$_.Exception.Message;$Status.Text='Speed Lab failed closed; see details.';$Run.IsEnabled=$true;$Advanced.IsEnabled=$true;$Ordered.IsEnabled=$true;$D.Tag='ready'}
 })
 [void]$D.ShowDialog()
}
'@

    $replacement=$advanced+"`n"+$speedLab
    $ProductSource=$ProductSource.Substring(0,$Performance.StartOffset)+$replacement+$ProductSource.Substring($Performance.EndOffset)
    $ProductSource+="`n# Windows Speed Lab: /api/speed-lab/options + /api/speed-lab/run, real idle/download-loaded/upload-loaded latency, real HTTPS Mbps, exact multihop hop RTT/Mbps, bufferbloat/jitter, current or temporary direct/multihop/external graphs, Auto or custom min/max timing.`n"
    return $ProductSource
}

# A separate owned view measures the captured ordered route. These receipts
# never replace direct-node ranking fields or the ordinary six-sample speed test.
function global:Get-RouterVPNOrderedValue {
    param($Value,[string]$Name,$Default=$null)
    if($null-eq$Value){return ,$Default}
    if($Value-is[Collections.IDictionary]){if($Value.Contains($Name)){return ,$Value[$Name]};return ,$Default}
    $Property=$Value.PSObject.Properties[$Name];if($null-eq$Property){return ,$Default};return ,$Property.Value
}
function global:Test-RouterVPNOrderedText {
    param($Value,[int]$Maximum=128)
    return $Value-is[string]-and$Value.Length-gt0-and[Text.Encoding]::UTF8.GetByteCount($Value)-le$Maximum-and$Value-cnotmatch'[\x00-\x1f\x7f]'
}
function global:Test-RouterVPNOrderedNumber {
    param($Value,[double]$Minimum=0,[double]$Maximum=90000,[switch]$Integer)
    if($Value-isnot[ValueType]-or$Value-is[bool]){return $false}
    $Number=[double]$Value
    return -not[double]::IsNaN($Number)-and-not[double]::IsInfinity($Number)-and$Number-ge$Minimum-and$Number-le$Maximum-and(-not$Integer-or[Math]::Floor($Number)-eq$Number)
}
function global:Assert-RouterVPNOrderedCapture {
    param($Capture)
    $Session=Get-RouterVPNOrderedValue $Capture 'session_id'
    if(-not(Test-RouterVPNOrderedText (Get-RouterVPNOrderedValue $Capture 'profile_id'))-or$Session-isnot[string]-or$Session.Length-gt64-or$Session-cnotmatch'^session-[0-9]+-[0-9]+$'){throw 'The connected route has no complete measurement identity.'}
    foreach($Key in @('profile_token','source_sha256','config_sha256','generation_sha256')){
        $Value=Get-RouterVPNOrderedValue $Capture $Key;if($Value-isnot[string]-or$Value-cnotmatch'^[0-9a-f]{64}$'){throw 'The connected route lost its source identity.'}
    }
}
function global:Get-RouterVPNOrderedLabelKind {
    param($Node,[int]$Position,[int]$Count)
    $Public=[string](Get-RouterVPNOrderedValue $Node 'kind')-ceq'public-path'
    foreach($Execution in @('ordinary','local','server')){
        $Prefix=if($Execution-ceq'ordinary'){'Cumulative path'}else{'Cumulative '+$Execution+' path'}
        $Expected=if($Public){$Prefix+' through custom node 2 of 3 '+[char]0x2192+' Cloudflare edge'}else{$Prefix+' through node '+($Position+1)+' of '+$Count}
        if([string](Get-RouterVPNOrderedValue $Node 'label')-ceq$Expected){return $Execution}
    }
    return $null
}
function global:Assert-RouterVPNOrderedNode {
    param($Node,[int]$Position,[int]$Count=3)
    $Role=if($Position-eq0){'entry'}elseif($Position-eq($Count-1)){'exit'}else{'intermediate'}
    if($Count-lt2-or$Count-gt8-or$Position-lt0-or$Position-ge$Count-or-not(Test-RouterVPNOrderedText (Get-RouterVPNOrderedValue $Node 'node_id'))-or-not(Test-RouterVPNOrderedText (Get-RouterVPNOrderedValue $Node 'label') 256)-or-not(Test-RouterVPNOrderedNumber (Get-RouterVPNOrderedValue $Node 'position') $Position $Position -Integer)-or[string](Get-RouterVPNOrderedValue $Node 'role')-cne$Role){throw 'A measured hop changed its identity or position.'}
    $Kind=[string](Get-RouterVPNOrderedValue $Node 'kind');$Public=$Kind-ceq'public-path'
    $Method=if($Public){'routed-https-response-after-tls'}else{'routed-private-response-including-connection'}
    if(($Kind-cne'private-node'-and-not($Public-and$Count-eq3-and$Position-eq1))-or[string](Get-RouterVPNOrderedValue $Node 'measurement')-cne$Method-or$null-eq(Get-RouterVPNOrderedLabelKind $Node $Position $Count)){throw 'A measured hop changed its timing method.'}
}
function global:Assert-RouterVPNOrderedReceipt {
    param($Receipt,$Capture,$Node,[switch]$Current,[int]$Count=3)
    $Position=Get-RouterVPNOrderedValue $Node 'position';$ID=[string](Get-RouterVPNOrderedValue $Node 'node_id')
    Assert-RouterVPNOrderedNode $Node $Position $Count
    $Public=[string](Get-RouterVPNOrderedValue $Node 'kind')-ceq'public-path'
    foreach($Key in @('source_sha256','config_sha256')){if([string](Get-RouterVPNOrderedValue $Receipt $Key)-cne[string](Get-RouterVPNOrderedValue $Capture $Key)){throw 'Saved response times belong to another route.'}}
    $Generation=Get-RouterVPNOrderedValue $Receipt 'generation_sha256';$Request=Get-RouterVPNOrderedValue $Receipt 'request_id'
    if($Generation-isnot[string]-or$Generation-cnotmatch'^[0-9a-f]{64}$'-or($Current-and$Generation-cne[string](Get-RouterVPNOrderedValue $Capture 'generation_sha256'))-or$Request-isnot[string]-or$Request-cnotmatch'^[0-9a-f]{32}$'-or-not(Test-RouterVPNOrderedNumber (Get-RouterVPNOrderedValue $Receipt 'schema') 1 1 -Integer)-or-not(Test-RouterVPNOrderedNumber (Get-RouterVPNOrderedValue $Receipt 'position') $Position $Position -Integer)-or[string](Get-RouterVPNOrderedValue $Receipt 'node_id')-cne$ID){throw 'The response receipt lost its original owner.'}
    $Now=([DateTime]::UtcNow-[DateTime]::SpecifyKind([DateTime]'1970-01-01',[DateTimeKind]::Utc)).TotalMilliseconds
    if(-not(Test-RouterVPNOrderedNumber (Get-RouterVPNOrderedValue $Receipt 'measured_at') 1 ($Now+1000) -Integer)){throw 'Saved response times have an invalid measurement date.'}
    $Result=Get-RouterVPNOrderedValue $Receipt 'result';$Benchmark=Get-RouterVPNOrderedValue $Result 'benchmark';$Distribution=Get-RouterVPNOrderedValue $Benchmark 'distribution';$Ready=Get-RouterVPNOrderedValue $Result 'ready'
    foreach($Key in @('node_id','role','kind')){if([string](Get-RouterVPNOrderedValue $Result $Key)-cne[string](Get-RouterVPNOrderedValue $Node $Key)){throw 'The result describes another measured hop.'}}
    $Label=[string](Get-RouterVPNOrderedValue $Node 'label')
    if([string](Get-RouterVPNOrderedValue $Result 'label')-cne$Label){throw 'The receipt changed its measurement label.'}
    foreach($Key in @('idle','download','upload','response')){if($null-ne(Get-RouterVPNOrderedValue $Result $Key)){throw 'A response-time receipt contains a different measurement.'}}
    if($Ready-isnot[bool]-or-not$Ready-or[string](Get-RouterVPNOrderedValue $Result 'failure' '')-or-not(Test-RouterVPNOrderedNumber (Get-RouterVPNOrderedValue $Benchmark 'schema') 1 1 -Integer)-or-not(Test-RouterVPNOrderedNumber (Get-RouterVPNOrderedValue $Benchmark 'attempts') 50 50 -Integer)-or-not(Test-RouterVPNOrderedNumber (Get-RouterVPNOrderedValue $Benchmark 'failed') 0 0 -Integer)-or-not(Test-RouterVPNOrderedNumber (Get-RouterVPNOrderedValue $Distribution 'samples') 50 50 -Integer)-or[string](Get-RouterVPNOrderedValue $Benchmark 'measurement')-cne[string](Get-RouterVPNOrderedValue $Node 'measurement')){throw 'The result does not contain 50 valid responses from this hop.'}
    $Endpoint=[string](Get-RouterVPNOrderedValue $Benchmark 'endpoint' '');$Expected=if($Public){'https://speed.cloudflare.com/__down?bytes=1'}else{''};if($Endpoint-cne$Expected){throw 'The response timing used another endpoint.'}
    $Maximum=if($Public){5000}else{2000}
    foreach($Key in @('min_ms','median_ms','average_ms','p90_ms','max_ms')){if(-not(Test-RouterVPNOrderedNumber (Get-RouterVPNOrderedValue $Distribution $Key) ([double]::Epsilon) $Maximum)){throw 'The response distribution is invalid.'}}
    $Min=[double](Get-RouterVPNOrderedValue $Distribution 'min_ms');$Median=[double](Get-RouterVPNOrderedValue $Distribution 'median_ms');$P90=[double](Get-RouterVPNOrderedValue $Distribution 'p90_ms');$Max=[double](Get-RouterVPNOrderedValue $Distribution 'max_ms')
    if($Min-gt$Median-or$Median-gt$P90-or$P90-gt$Max-or-not(Test-RouterVPNOrderedNumber (Get-RouterVPNOrderedValue $Distribution 'average_ms') $Min $Max)-or-not(Test-RouterVPNOrderedNumber (Get-RouterVPNOrderedValue $Benchmark 'trimmed_mean_ms') $Min $Max)-or-not(Test-RouterVPNOrderedNumber (Get-RouterVPNOrderedValue $Distribution 'jitter_ms') 0 ($Max-$Min+1e-9))){throw 'The response distribution is not coherent.'}
}
function global:New-RouterVPNOrderedState {
    param([string]$BaseUrl,[string]$DisplayedProfileID)
    Assert-RouterVPNControllerBaseUrl $BaseUrl
    if(-not(Test-RouterVPNOrderedText $DisplayedProfileID)){throw 'Select the connected ordered route first.'}
    return @{BaseUrl=$BaseUrl.TrimEnd('/');Displayed=$DisplayedProfileID;Capture=$null;Nodes=@();History=@();Node=$null;Request='';Generation=[long]0;
        Drained=$true;Cancelled=$false;Closing=$false;Closed=$false;Invalid=$false;AllowClose=$false;Client=$null;Window=$null;Timer=$null;
        Owner=$null;OwnerClosing=$null;CloseOwner=$false;Jobs=[Collections.Generic.List[object]]::new();NextPoll=[DateTime]::MinValue;NextCancel=[DateTime]::MinValue;Deadline=[DateTime]::MaxValue;
        Status='Reading the connected ordered route...';Populated=$false}
}
function global:New-RouterVPNOrderedBody {
    param($State)
    Assert-RouterVPNOrderedCapture $State.Capture
    if($State.Request-cnotmatch'^[0-9a-f]{32}$'-or$null-eq$State.Node){throw 'The request has no captured hop.'}
    $Capture=@{};foreach($Key in @('session_id','profile_id','profile_token','source_sha256','config_sha256','generation_sha256')){$Capture[$Key]=[string](Get-RouterVPNOrderedValue $State.Capture $Key)}
    return @{capture=$Capture;node_id=[string](Get-RouterVPNOrderedValue $State.Node 'node_id');position=[int](Get-RouterVPNOrderedValue $State.Node 'position');request_id=$State.Request}
}
function global:Test-RouterVPNOrderedJob {
    param($State,[string]$Kind)
    foreach($Job in $State.Jobs){if($Job.Kind-ceq$Kind){return $true}};return $false
}
function global:New-RouterVPNOrderedRequest {
    param($State,[ValidateSet('info','start','poll','cancel')][string]$Kind)
    if($State.Closed-or$null-eq$State.Client){throw 'The hop measurement view is closed.'}
    $Path='/api/speed-lab/ordered-latency';$Body=$null
    if($Kind-ceq'poll'){if($State.Request-cnotmatch'^[0-9a-f]{32}$'){throw 'Missing captured request.'};$Path+='?request_id='+$State.Request}
    if($Kind-cin@('start','cancel')){$Body=New-RouterVPNOrderedBody $State;if($Kind-ceq'cancel'){$Path+='/cancel'}}
    $Method=if($null-eq$Body){[Net.Http.HttpMethod]::Get}else{[Net.Http.HttpMethod]::Post}
    $Request=[Net.Http.HttpRequestMessage]::new($Method,$State.BaseUrl+$Path);$Cts=[Threading.CancellationTokenSource]::new();$Cts.CancelAfter([TimeSpan]::FromSeconds(6))
    try{
        if($null-ne$Body){$Request.Content=[Net.Http.StringContent]::new(($Body|ConvertTo-Json -Depth 10 -Compress),[Text.Encoding]::UTF8,'application/json')}
        $Task=$State.Client.SendAsync($Request,$Cts.Token)
        $Job=@{Kind=$Kind;Generation=$State.Generation;Captured=$State.Request;Request=$Request;Cts=$Cts;Task=$Task};[void]$State.Jobs.Add($Job)
    }catch{$Request.Dispose();$Cts.Dispose();throw}
}
function global:Complete-RouterVPNOrderedRequest {
    param($Job)
    $Response=$null
    try{
        $Response=$Job.Task.GetAwaiter().GetResult();$Text=$Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if([Text.Encoding]::UTF8.GetByteCount($Text)-gt1048576){throw 'Measurement response exceeded its size limit.'}
        if(-not$Response.IsSuccessStatusCode){throw 'The local measurement request was not confirmed.'}
        return @{Value=($Text|ConvertFrom-Json);Error=''}
    }catch{return @{Value=$null;Error=$_.Exception.Message}}
    finally{if($null-ne$Response){$Response.Dispose()};$Job.Request.Dispose();$Job.Cts.Dispose()}
}
function global:Test-RouterVPNOrderedSelection {
    param($State)
    if($State.Invalid-or-not$State.ContainsKey('SelectionCurrent')-or$null-eq$State.SelectionCurrent){return}
    try{$Current=&$State.SelectionCurrent;if($Current-isnot[bool]-or-not$Current){throw 'The selected profile changed.'}}
    catch{$State.Invalid=$true;if(-not$State.Drained){$State.Cancelled=$true};$State.Status='The selected profile changed. Waiting for the original test to finish.'}
}
function global:Receive-RouterVPNOrderedStatus {
    param($State,$Value,[switch]$Initial)
    Test-RouterVPNOrderedSelection $State
    $Capture=Get-RouterVPNOrderedValue $Value 'capture';Assert-RouterVPNOrderedCapture $Capture
    $Status=Get-RouterVPNOrderedValue $Value 'status';$Complete=Get-RouterVPNOrderedValue $Status 'complete';$Drained=Get-RouterVPNOrderedValue $Status 'drained';$Stage=Get-RouterVPNOrderedValue $Status 'stage';$Request=Get-RouterVPNOrderedValue $Value 'request_id' ''; $Failure=Get-RouterVPNOrderedValue $Status 'failure' ''
    if(-not(Test-RouterVPNOrderedNumber (Get-RouterVPNOrderedValue $Value 'schema') 1 1 -Integer)-or$Complete-isnot[bool]-or$Drained-isnot[bool]-or($Drained-and-not$Complete)-or-not(Test-RouterVPNOrderedText $Stage 128)-or$Failure-isnot[string]-or$Failure.Length-gt512-or$Request-isnot[string]-or[string](Get-RouterVPNOrderedValue $Status 'request_id')-cne$Request){throw 'Invalid captured measurement status.'}
    if($Initial){
        if($State.Invalid){throw 'The selected profile changed. Reopen hop measurements.'}
        $Rows=Get-RouterVPNOrderedValue $Value 'nodes';$History=Get-RouterVPNOrderedValue $Value 'history' @()
        if($null-ne$State.Capture-or[string](Get-RouterVPNOrderedValue $Capture 'profile_id')-cne$State.Displayed-or$Request-or$Stage-cne'idle'-or-not$Complete-or-not$Drained-or$Rows-isnot[array]-or$Rows.Count-lt2-or$Rows.Count-gt8-or$History-isnot[array]-or$History.Count-gt128){throw 'Connect the selected ordered route, then reopen hop measurements.'}
        $IDs=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        for($Index=0;$Index-lt$Rows.Count;$Index++){Assert-RouterVPNOrderedNode $Rows[$Index] $Index $Rows.Count;if(-not$IDs.Add([string](Get-RouterVPNOrderedValue $Rows[$Index] 'node_id'))){throw 'Duplicate measured hop.'};if($Index-gt0-and(Get-RouterVPNOrderedLabelKind $Rows[$Index] $Index $Rows.Count)-cne(Get-RouterVPNOrderedLabelKind $Rows[0] 0 $Rows.Count)){throw 'Measured hops belong to different selected paths.'}}
        foreach($Record in $History){$Position=Get-RouterVPNOrderedValue $Record 'position';if(-not(Test-RouterVPNOrderedNumber $Position 0 ($Rows.Count-1) -Integer)){throw 'Invalid saved hop.'};Assert-RouterVPNOrderedReceipt $Record $Capture $Rows[[int]$Position] -Count $Rows.Count}
        $State.Capture=$Capture;$State.Nodes=$Rows;$State.History=$History;$State.Status='Choose a hop. Saved results show when that route was measured.';return
    }
    foreach($Key in @('session_id','profile_id','profile_token','source_sha256','config_sha256','generation_sha256')){if([string](Get-RouterVPNOrderedValue $Capture $Key)-cne[string](Get-RouterVPNOrderedValue $State.Capture $Key)){throw 'The response belongs to another captured route.'}}
    if(-not$State.Request-or$Request-cne$State.Request-or[string](Get-RouterVPNOrderedValue $Value 'node_id')-cne[string](Get-RouterVPNOrderedValue $State.Node 'node_id')-or-not(Test-RouterVPNOrderedNumber (Get-RouterVPNOrderedValue $Value 'position') (Get-RouterVPNOrderedValue $State.Node 'position') (Get-RouterVPNOrderedValue $State.Node 'position') -Integer)){throw 'The response belongs to another measurement.'}
    if($State.Drained){return}
    $Finished=$Complete-and$Drained;$Record=Get-RouterVPNOrderedValue $Value 'receipt'
    if($null-ne$Record){
        if(-not$Finished-or$Stage-cne'complete'-or$Failure-or[string](Get-RouterVPNOrderedValue $Record 'request_id')-cne$State.Request){throw 'An unfinished test cannot replace saved history.'}
        Assert-RouterVPNOrderedReceipt $Record $State.Capture $State.Node -Current -Count $State.Nodes.Count
        if($State.Invalid){$State.Status='The original test finished and saved its result for the previous profile. Reopen hop measurements for the selected profile.'}
        else{
            $State.History=@($State.History|Where-Object{[string](Get-RouterVPNOrderedValue $_ 'node_id')-cne[string](Get-RouterVPNOrderedValue $State.Node 'node_id')})+@($Record)
            $State.Status=if($State.Cancelled){'The test finished before cancellation; its 50 responses were saved.'}else{'Saved 50 responses for the selected hop.'}
        }
    }elseif($Finished){
        if($Stage-ceq'complete'-and-not$Failure){throw 'The completed measurement did not confirm its saved result.'}
        $State.Status=if($State.Cancelled-or$State.Closing){'Test cancelled. Previous saved results remain available.'}elseif($Failure){$Failure}else{'Measurement failed. Previous saved results remain available.'}
    }elseif(-not$State.Cancelled-and-not$State.Closing){$State.Status='Measuring 50 responses through the selected hop...'}
    if($Finished){$State.Drained=$true;if($Stage-cin@('invalidated','retired')){$State.Invalid=$true}}
}
function global:Start-RouterVPNOrderedLatency {
    param($State,[int]$Position)
    Test-RouterVPNOrderedSelection $State
    if($State.Closed-or$State.Closing-or$State.Invalid-or$null-eq$State.Capture-or-not$State.Drained-or$State.Jobs.Count-ne0-or$Position-lt0-or$Position-ge$State.Nodes.Count){return $false}
    $State.Generation++;$State.Node=$State.Nodes[$Position];$State.Request=[Guid]::NewGuid().ToString('N');$State.Drained=$false;$State.Cancelled=$false;$State.NextPoll=[DateTime]::MinValue;$State.NextCancel=[DateTime]::MinValue;$State.Deadline=[DateTime]::UtcNow.AddSeconds(100);$State.Status='Measuring 50 responses through the selected hop...'
    try{New-RouterVPNOrderedRequest $State 'start';return $true}catch{Cancel-RouterVPNOrderedLatency $State;$State.Status='Start was not confirmed. Cancelling this test and waiting for completion.';return $false}
}
function global:Cancel-RouterVPNOrderedLatency {
    param($State)
    if($State.Closed-or$State.Drained-or-not$State.Request){return}
    $State.Cancelled=$true;$State.Status='Cancelling the test. Waiting for it to finish...'
    if(-not(Test-RouterVPNOrderedJob $State 'cancel')-and[DateTime]::UtcNow-ge$State.NextCancel){$State.NextCancel=[DateTime]::UtcNow.AddSeconds(1);try{New-RouterVPNOrderedRequest $State 'cancel'}catch{}}
}
function global:Request-RouterVPNOrderedClose {
    param($State)
    if($State.Closed-or$State.AllowClose){return $true};$State.Closing=$true
    if(-not$State.Drained){Cancel-RouterVPNOrderedLatency $State}else{foreach($Job in $State.Jobs){$Job.Cts.Cancel()}}
    return $State.Drained-and$State.Jobs.Count-eq0
}
function global:Close-RouterVPNOrderedView {
    param($State)
    if($State.Closed){return $true};if(-not$State.Drained-or$State.Jobs.Count-ne0){return $false}
    $State.Closed=$true;if($null-ne$State.Timer){$State.Timer.Stop();$State.Timer=$null};if($null-ne$State.Client){$State.Client.Dispose();$State.Client=$null}
    $Owner=$State.Owner;$Closing=$State.OwnerClosing;$State.Owner=$null;$State.OwnerClosing=$null
    if($null-ne$Owner-and$null-ne$Closing){$Owner.Remove_Closing($Closing)}
    if($State.CloseOwner-and$null-ne$Owner){$State.CloseOwner=$false;$Owner.Close()};return $true
}
function global:Update-RouterVPNOrderedView {
    param($State)
    if($State.Closed){return}
    Test-RouterVPNOrderedSelection $State
    foreach($Job in @($State.Jobs.ToArray())){
        if(-not$Job.Task.IsCompleted){continue};[void]$State.Jobs.Remove($Job);$Reply=Complete-RouterVPNOrderedRequest $Job
        if($Job.Generation-ne$State.Generation-or$Job.Captured-cne$State.Request){continue}
        try{if($Reply.Error){throw $Reply.Error};Receive-RouterVPNOrderedStatus $State $Reply.Value -Initial:($Job.Kind-ceq'info')}
        catch{if($Job.Kind-ceq'info'){$State.Invalid=$true;$State.Status=$_.Exception.Message}else{$State.Cancelled=$true;$State.Status='The result was not confirmed. Cancelling this test and waiting for completion.'}}
    }
    if(-not$State.Drained){
        if([DateTime]::UtcNow-ge$State.Deadline){$State.Cancelled=$true}
        if($State.Cancelled-or$State.Closing-or$State.Invalid){Cancel-RouterVPNOrderedLatency $State}
        if(-not(Test-RouterVPNOrderedJob $State 'poll')-and[DateTime]::UtcNow-ge$State.NextPoll){$State.NextPoll=[DateTime]::UtcNow.AddMilliseconds(700);try{New-RouterVPNOrderedRequest $State 'poll'}catch{}}
    }
    if($null-ne$State.Window){
        $W=$State.Window;$W.FindName('Progress').Text=$State.Status;$Combo=$W.FindName('Hop')
        if(-not$State.Populated-and$State.Nodes.Count-eq3){$Rows=@();foreach($Node in $State.Nodes){$Rows+=@([pscustomobject]@{position=[int](Get-RouterVPNOrderedValue $Node 'position');display=('{0}. {1} - {2}'-f((Get-RouterVPNOrderedValue $Node 'position')+1),(Get-RouterVPNOrderedValue $Node 'label'),(Get-RouterVPNOrderedValue $Node 'role'))})};$State.Populated=$true;$Combo.ItemsSource=$Rows;$Combo.SelectedIndex=0}
        $Idle=$State.Drained-and$State.Jobs.Count-eq0-and-not$State.Closing-and-not$State.Closed-and-not$State.Invalid-and$null-ne$State.Capture
        $Combo.IsEnabled=[bool]$Idle;$W.FindName('Retest').IsEnabled=[bool]$Idle;$W.FindName('CancelTest').IsEnabled=[bool](-not$State.Drained-and-not$State.Cancelled)
        if($Combo.SelectedIndex-ge0-and$Combo.SelectedIndex-lt$State.Nodes.Count){
            $Node=$State.Nodes[$Combo.SelectedIndex];$Timing=if($Combo.SelectedIndex-eq1){'HTTPS response after TLS'}else{'HTTP response including connection'}
            $Records=@($State.History|Where-Object{[string](Get-RouterVPNOrderedValue $_ 'node_id')-ceq[string](Get-RouterVPNOrderedValue $Node 'node_id')}|Sort-Object {Get-RouterVPNOrderedValue $_ 'measured_at'} -Descending)
            $Detail=$Timing+"`r`n`r`nNo saved result for this route and hop."
            if($Records.Count){$R=$Records[0];$B=Get-RouterVPNOrderedValue (Get-RouterVPNOrderedValue $R 'result') 'benchmark';$D=Get-RouterVPNOrderedValue $B 'distribution';$Date=([DateTime]::SpecifyKind([DateTime]'1970-01-01',[DateTimeKind]::Utc)).AddMilliseconds([double](Get-RouterVPNOrderedValue $R 'measured_at')).ToLocalTime();$Detail=$Timing+"`r`n`r`nSaved "+$Date.ToString('g')+"`r`n"+('50 responses - median {0:N2} ms - trimmed mean {1:N2} ms'-f(Get-RouterVPNOrderedValue $D 'median_ms'),(Get-RouterVPNOrderedValue $B 'trimmed_mean_ms'))+"`r`n"+('Min {0:N2} - average {1:N2} - p90 {2:N2} - max {3:N2} - jitter {4:N2} ms'-f(Get-RouterVPNOrderedValue $D 'min_ms'),(Get-RouterVPNOrderedValue $D 'average_ms'),(Get-RouterVPNOrderedValue $D 'p90_ms'),(Get-RouterVPNOrderedValue $D 'max_ms'),(Get-RouterVPNOrderedValue $D 'jitter_ms'))}
            $W.FindName('Detail').Text=$Detail
        }
    }
    if($State.Closing-and$State.Drained-and$State.Jobs.Count-eq0){$State.AllowClose=$true;if($null-ne$State.Window){$State.Window.Close()}else{[void](Close-RouterVPNOrderedView $State)}}
}
function global:Show-RouterVPNOrderedLatency {
    param([string]$BaseUrl,$Owner,[string]$DisplayedProfileID,[scriptblock]$SelectionCurrent)
    if($null-ne(Get-Variable RouterVPNOrderedView -Scope Global -ErrorAction SilentlyContinue)){$Old=$global:RouterVPNOrderedView;if($null-ne$Old-and-not$Old.Closed){if($null-ne$Old.Window){[void]$Old.Window.Activate()};return}}
    if(-not(Get-Command New-RouterVPNControllerClient -ErrorAction SilentlyContinue)){Import-Module (Join-Path $PSScriptRoot 'RouterVPN-Windows-ControllerTransport.psm1') -Global -ErrorAction Stop}
    $State=New-RouterVPNOrderedState $BaseUrl $DisplayedProfileID;$State.Client=New-RouterVPNControllerClient -TimeoutMilliseconds 6000 -ResponseLimit 1048576;$State.Owner=$Owner;$State.SelectionCurrent=$SelectionCurrent
    [xml]$Xaml=@'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="Router VPN hop response times" Width="800" Height="460" MinWidth="600" MinHeight="400" WindowStartupLocation="CenterOwner" Background="#0B1020" Foreground="#F5F7FF">
<Grid Margin="20"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
<TextBlock Text="50 responses through each hop" FontSize="23" FontWeight="Bold"/>
<TextBlock Grid.Row="1" TextWrapping="Wrap" Foreground="#A8B6D5" Margin="0,10,0,12" Text="Select a hop on the connected route. Private-node HTTP timing includes connection setup; the public middle is timed after TLS. Saved results are historical and keep their measurement date."/>
<ComboBox Name="Hop" Grid.Row="2" DisplayMemberPath="display" SelectedValuePath="position" AutomationProperties.Name="Measured hop"/>
<TextBlock Name="Progress" Grid.Row="3" TextWrapping="Wrap" Margin="0,12" AutomationProperties.Name="Measurement progress"/>
<TextBox Name="Detail" Grid.Row="4" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" FontFamily="Consolas" Background="#101A2B" Foreground="#E8ECF8" Padding="10"/>
<WrapPanel Grid.Row="5" HorizontalAlignment="Right" Margin="0,12,0,0"><Button Name="Retest" Content="Retest 50 responses" Padding="12,7" Margin="4"/><Button Name="CancelTest" Content="Cancel test" Padding="12,7" Margin="4"/><Button Name="Close" Content="Close" Padding="12,7" Margin="4"/></WrapPanel>
</Grid></Window>
'@
    $Reader=[Xml.XmlNodeReader]::new($Xaml);$W=[Windows.Markup.XamlReader]::Load($Reader);$Reader.Dispose();$State.Window=$W;if($null-ne$Owner){$W.Owner=$Owner}
    $State.Timer=[Windows.Threading.DispatcherTimer]::new();$State.Timer.Interval=[TimeSpan]::FromMilliseconds(50);$State.Timer.Add_Tick({Update-RouterVPNOrderedView $State}.GetNewClosure())
    $W.FindName('Retest').Add_Click({try{[void](Start-RouterVPNOrderedLatency $State $State.Window.FindName('Hop').SelectedIndex)}catch{$State.Status=$_.Exception.Message};Update-RouterVPNOrderedView $State}.GetNewClosure())
    $W.FindName('CancelTest').Add_Click({Cancel-RouterVPNOrderedLatency $State;Update-RouterVPNOrderedView $State}.GetNewClosure())
    $W.FindName('Hop').Add_SelectionChanged({Update-RouterVPNOrderedView $State}.GetNewClosure())
    $W.FindName('Close').Add_Click({$State.Window.Close()}.GetNewClosure())
    $W.Add_Closing({param($Sender,$Event)if(-not(Request-RouterVPNOrderedClose $State)){$Event.Cancel=$true}}.GetNewClosure())
    $W.Add_Closed({$State.Window=$null;[void](Close-RouterVPNOrderedView $State)}.GetNewClosure())
    if($null-ne$Owner){$State.OwnerClosing=[ComponentModel.CancelEventHandler]({param($Sender,$Event)if(-not$State.Closed){if(-not(Request-RouterVPNOrderedClose $State)){$State.CloseOwner=$true;$Event.Cancel=$true}else{$State.CloseOwner=$false;$State.AllowClose=$true}}}.GetNewClosure());$Owner.Add_Closing($State.OwnerClosing)}
    $global:RouterVPNOrderedView=$State;New-RouterVPNOrderedRequest $State 'info';$State.Timer.Start();$W.Show();Update-RouterVPNOrderedView $State
}
