Set-StrictMode -Version Latest

$script:RouterVPNUnifiedModeKey = 'windows-selected-mode-v1.txt'
$script:RouterVPNUnifiedPresets = 'windows-custom-presets-v1.json'

function Add-RouterVPNUnifiedWindowsShell {
    param([Parameter(Mandatory=$true)][string]$ProductSource)

    $oldHeader = '<Grid Grid.Row="0" Margin="4,0,4,14">'
    if (-not $ProductSource.Contains($oldHeader)) { throw 'Windows unified shell: header contract drifted.' }
    $ProductSource = $ProductSource.Replace($oldHeader, '<Grid Grid.Row="0" Visibility="Collapsed" Margin="4,0,4,14">')

    $oldTabs = '<TabControl Grid.Row="1" Background="#0F172A" BorderBrush="#263452" Foreground="#E8ECF8">'
    if (-not $ProductSource.Contains($oldTabs)) { throw 'Windows unified shell: TabControl contract drifted.' }
    $shell = @'
<Grid Name="UnifiedShell" Grid.Row="1" Background="#08101E">
  <Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
  <Border Grid.Row="0" Background="#0E182B" CornerRadius="18" BorderBrush="#263A5A" BorderThickness="1" Margin="0,0,0,8">
    <Grid>
      <Canvas Name="UnifiedMapCanvas" ClipToBounds="True"/>
      <Border HorizontalAlignment="Left" VerticalAlignment="Top" Margin="14" Padding="10,7" CornerRadius="14" Background="#DD17243A">
        <StackPanel Orientation="Horizontal"><TextBlock Text="Node" FontWeight="SemiBold" Margin="0,0,8,0" VerticalAlignment="Center"/><ComboBox Name="UnifiedNodeCombo" DisplayMemberPath="display_name" SelectedValuePath="id" MinWidth="260"/><Button Name="UnifiedNodesButton" Content="Nodes" Margin="8,0,0,0" Padding="10,5"/></StackPanel>
      </Border>
      <Border HorizontalAlignment="Right" VerticalAlignment="Top" Margin="14" Padding="10,7" CornerRadius="14" Background="#DD17243A">
        <StackPanel><StackPanel Orientation="Horizontal"><Ellipse Name="UnifiedStateDot" Width="9" Height="9" Fill="#6B7280" Margin="0,0,7,0"/><TextBlock Name="UnifiedStateText" Text="Checking…" FontWeight="SemiBold"/></StackPanel><TextBlock Name="UnifiedStatusDetail" Text="Selected-path proof pending" FontSize="11" Foreground="#A8B6D5" MaxWidth="420" TextWrapping="Wrap"/></StackPanel>
      </Border>
    </Grid>
  </Border>
  <Border Grid.Row="1" Background="#F0162238" BorderBrush="#354968" BorderThickness="1" CornerRadius="22" Padding="16,8,16,14">
    <ScrollViewer MaxHeight="390" VerticalScrollBarVisibility="Auto"><StackPanel>
      <TextBlock Text="━━━━" HorizontalAlignment="Center" Foreground="#657794" FontSize="15"/>
      <TextBlock Name="UnifiedProofText" Text="Connected requires exact selected-node path proof." Foreground="#DDE7FF" TextWrapping="Wrap" Margin="0,0,0,7"/>
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,0,0,6"><Button Name="UnifiedProofButton" Content="Prove actual exit" Padding="10,5"/><Button Name="UnifiedEmergencyButton" Content="Emergency disconnect" Margin="6,0,0,0" Padding="10,5"/></StackPanel>
      <TextBlock Name="UnifiedLastError" Foreground="#FF9CA8" TextWrapping="Wrap" Margin="0,0,0,6"/>
      <Grid Margin="0,2,0,6"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><Button Name="UnifiedConnectButton" Content="Connect" FontSize="17" FontWeight="Bold" Padding="18,10" Background="#6857E5" Foreground="White"/><CheckBox Name="UnifiedKillSwitch" Grid.Column="1" Content="Kill switch" VerticalAlignment="Center" Margin="14,0,0,0"/></Grid>
      <Grid Margin="0,4"><Grid.ColumnDefinitions><ColumnDefinition Width="76"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><TextBlock Text="Multihop" FontWeight="SemiBold" VerticalAlignment="Center"/><CheckBox Name="UnifiedMultihop" Grid.Column="1" VerticalAlignment="Center" Margin="6,0"/><ComboBox Name="UnifiedEntryCombo" Grid.Column="2" DisplayMemberPath="name" SelectedValuePath="id" MinWidth="150"/><TextBlock Grid.Column="3" Text=" → " VerticalAlignment="Center"/><ComboBox Name="UnifiedExitCombo" Grid.Column="4" DisplayMemberPath="name" SelectedValuePath="id" MinWidth="150"/><ComboBox Name="UnifiedExitMode" Grid.Column="5" Margin="6,0,0,0"><ComboBoxItem Content="Shadowsocks" Tag="shadowsocks"/><ComboBoxItem Content="Hysteria2" Tag="hysteria2"/></ComboBox></Grid>
      <Grid Margin="0,4"><Grid.ColumnDefinitions><ColumnDefinition Width="76"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><TextBlock Text="Settings" FontWeight="SemiBold" VerticalAlignment="Center"/><TextBlock Name="UnifiedSettingsSummary" Grid.Column="1" Foreground="#A8B6D5" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/><StackPanel Grid.Column="2" Orientation="Horizontal"><Button Name="UnifiedSettingsButton" Content="Open settings" Padding="10,5"/><Button Name="UnifiedMtuButton" Content="Retest MTU" Margin="6,0,0,0" Padding="10,5"/></StackPanel></Grid>
      <Grid Margin="0,4"><Grid.ColumnDefinitions><ColumnDefinition Width="76"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><TextBlock Text="Mode" FontWeight="SemiBold" VerticalAlignment="Center"/><ComboBox Name="UnifiedModeCombo" Grid.Column="1" DisplayMemberPath="display" SelectedValuePath="id"/><Button Name="UnifiedPresetsButton" Grid.Column="2" Content="Presets / CUSTOM" Margin="6,0,0,0" Padding="10,5"/></Grid>
      <Grid Margin="0,4"><Grid.ColumnDefinitions><ColumnDefinition Width="76"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><TextBlock Text="DNS" FontWeight="SemiBold" VerticalAlignment="Center"/><ComboBox Name="UnifiedDnsCombo" Grid.Column="1"><ComboBoxItem Content="Home AdGuard" Tag="home"/><ComboBoxItem Content="Fastest measured" Tag="fastest"/><ComboBoxItem Content="Custom" Tag="custom"/><ComboBoxItem Content="DoT" Tag="dot"/><ComboBoxItem Content="DoH" Tag="doh"/><ComboBoxItem Content="DoH3" Tag="doh3"/><ComboBoxItem Content="Rescue" Tag="rescue"/></ComboBox><Button Name="UnifiedDnsDetailsButton" Grid.Column="2" Content="DNS details" Margin="6,0,0,0" Padding="10,5"/></Grid>
    </StackPanel></ScrollViewer>
  </Border>
</Grid>
<Button Name="UnifiedBackButton" Grid.Row="1" Content="← Back to map" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="12" Padding="12,6" Panel.ZIndex="50" Visibility="Collapsed"/>
<TabControl Name="LegacyDetailTabs" Visibility="Collapsed" Grid.Row="1" Background="#0F172A" BorderBrush="#263452" Foreground="#E8ECF8" Margin="0,48,0,0">
  <TabControl.Template><ControlTemplate TargetType="{x:Type TabControl}"><Border Background="#0F172A"><ContentPresenter ContentSource="SelectedContent"/></Border></ControlTemplate></TabControl.Template>
'@
    $ProductSource = $ProductSource.Replace($oldTabs, $shell)

    $oldFooter = '<TextBlock Grid.Row="2" Margin="4,12,4,0" Foreground="#7E90B6" Text="Native WPF; fixed local controller 127.0.0.1:8788; no browser or embedded web surface."/>'
    if ($ProductSource.Contains($oldFooter)) { $ProductSource = $ProductSource.Replace($oldFooter, '<TextBlock Grid.Row="2" Visibility="Collapsed" Text="Native WPF; fixed local controller 127.0.0.1:8788; no browser or embedded web surface."/>') }

    $bindingsOld = '$StateText=Control ''StateText'';$StateDot=Control ''StateDot'';$HeaderDetail=Control ''HeaderDetail'';$RouterCombo=Control ''RouterCombo'';$ModeCombo=Control ''ModeCombo'';$BaseCombo=Control ''BaseCombo'';$ConnectionDetail=Control ''ConnectionDetail'';$ProofText=Control ''ProofText'';$LastErrorText=Control ''LastErrorText'';$NodesGrid=Control ''NodesGrid'';$MapCanvas=Control ''MapCanvas'';'
    $bindingsNew = '$StateText=Control ''UnifiedStateText'';$StateDot=Control ''UnifiedStateDot'';$HeaderDetail=Control ''HeaderDetail'';$RouterCombo=Control ''UnifiedNodeCombo'';$ModeCombo=Control ''UnifiedModeCombo'';$BaseCombo=Control ''BaseCombo'';$ConnectionDetail=Control ''UnifiedStatusDetail'';$ProofText=Control ''UnifiedProofText'';$LastErrorText=Control ''UnifiedLastError'';$NodesGrid=Control ''NodesGrid'';$MapCanvas=Control ''UnifiedMapCanvas'';'
    if (-not $ProductSource.Contains($bindingsOld)) { throw 'Windows unified shell: control binding contract drifted.' }
    $ProductSource = $ProductSource.Replace($bindingsOld,$bindingsNew)

    $multiOld = '$MultihopEntryCombo=Control ''MultihopEntryCombo'';$MultihopExitCombo=Control ''MultihopExitCombo'';$MultihopExitModeCombo=Control ''MultihopExitModeCombo'';$MultihopSummary=Control ''MultihopSummary'''
    $multiNew = '$MultihopEntryCombo=Control ''UnifiedEntryCombo'';$MultihopExitCombo=Control ''UnifiedExitCombo'';$MultihopExitModeCombo=Control ''UnifiedExitMode'';$MultihopSummary=Control ''MultihopSummary'''
    if (-not $ProductSource.Contains($multiOld)) { throw 'Windows unified shell: multihop binding contract drifted.' }
    $ProductSource = $ProductSource.Replace($multiOld,$multiNew)

    $scriptMarker = '$script:EventSeq=[uint64]0;$script:Busy=$false;$script:NodeSort=''current'';$script:DnsPolicySummary=''Saved DNS policy not loaded yet.'''
    if (-not $ProductSource.Contains($scriptMarker)) { throw 'Windows unified shell: script-state marker drifted.' }
    $extraState = @'
$script:UnifiedModeStateFile=Join-Path $PSScriptRoot '.routervpn-state\windows-selected-mode-v1.txt'
$script:UnifiedPresetFile=Join-Path $PSScriptRoot '.routervpn-state\windows-custom-presets-v1.json'
$script:UnifiedModeChoices=@()
function GetUnifiedPresets{if(-not(Test-Path -LiteralPath $script:UnifiedPresetFile)){return @()};try{return @((Get-Content -LiteralPath $script:UnifiedPresetFile -Raw -Encoding UTF8|ConvertFrom-Json))}catch{return @()}}
function SaveUnifiedPresets($Values){[void](New-Item -ItemType Directory -Force -Path (Split-Path $script:UnifiedPresetFile));@($Values)|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $script:UnifiedPresetFile -Encoding UTF8}
function GetUnifiedModeID{if(Test-Path -LiteralPath $script:UnifiedModeStateFile){$v=(Get-Content -LiteralPath $script:UnifiedModeStateFile -Raw -Encoding UTF8).Trim();if($v){return $v}};return 'smart-auto'}
function SaveUnifiedModeID([string]$Value){[void](New-Item -ItemType Directory -Force -Path (Split-Path $script:UnifiedModeStateFile));Set-Content -LiteralPath $script:UnifiedModeStateFile -Value $Value -Encoding UTF8}
function RefreshUnifiedModeChoices($Modes){$Wanted=GetUnifiedModeID;$Values=New-Object System.Collections.ArrayList;[void]$Values.Add([pscustomobject]@{id='smart-auto';display='SMART AUTO — recommended';available=$true});[void]$Values.Add([pscustomobject]@{id='auto';display='AUTO — first proven path';available=$true});foreach($M in @($Modes)){$Reason=[string]$M.reason_text;$Label=if([bool]$M.available){[string]$M.name}else{"$($M.name) — unavailable: $Reason"};[void]$Values.Add([pscustomobject]@{id=[string]$M.id;display=$Label;available=[bool]$M.available})};foreach($P in @(GetUnifiedPresets)){[void]$Values.Add([pscustomobject]@{id=('custom:'+[string]$P.name);display=('CUSTOM • '+[string]$P.name);available=$true})};[void]$Values.Add([pscustomobject]@{id='custom:new';display='New CUSTOM preset…';available=$true});$script:UnifiedModeChoices=@($Values);$ModeCombo.ItemsSource=$script:UnifiedModeChoices;$ModeCombo.SelectedValue=$Wanted;if(-not$ModeCombo.SelectedItem){$ModeCombo.SelectedValue='smart-auto';SaveUnifiedModeID 'smart-auto'}}
function UnifiedSelectedProfile{try{$S=Api '/api/profiles' -Timeout 4;return @($S.profiles|Where-Object{[string]$_.id -eq [string]$S.selected_id}|Select-Object -First 1)}catch{return $null}}
function OpenUnifiedDetail([int]$Index){(Control 'UnifiedShell').Visibility='Collapsed';(Control 'LegacyDetailTabs').Visibility='Visible';(Control 'LegacyDetailTabs').SelectedIndex=$Index;(Control 'UnifiedBackButton').Visibility='Visible'}
function BackUnifiedMap{(Control 'LegacyDetailTabs').Visibility='Collapsed';(Control 'UnifiedBackButton').Visibility='Collapsed';(Control 'UnifiedShell').Visibility='Visible';RefreshProduct}
function UnifiedConnect{try{$Status=Api '/api/status' -Timeout 3;$Phase=[string]$Status.phase;if([bool]$Status.connected -or $Phase -match '^(starting|checking)|trying|proving'){[void](Api '/api/disconnect' 'POST' @{} 20);Log 'Disconnected';return};if((Control 'UnifiedMultihop').IsChecked){$Entry=[string]$MultihopEntryCombo.SelectedValue;$Exit=[string]$MultihopExitCombo.SelectedValue;if(-not $Entry -or -not $Exit -or $Entry -eq $Exit){throw 'Multihop requires different entry and exit nodes.'};$R=Api '/api/multihop/connect' 'POST' @{entry_id=$Entry;exit_id=$Exit;base='wg';exit_mode=(MultihopExitModeChoice)} 200;Log ("Multihop connected entry=$($R.entry_id) exit=$($R.exit_id)");return};$P=UnifiedSelectedProfile;if($P -and (([string]$P.node_kind).ToLowerInvariant() -eq 'external')){$R=Api '/api/external-profile/connect' 'POST' @{profile_id=[string]$P.id} 180;Log ('External connected: '+[string]$R.profile.name);return};$ID=[string]$ModeCombo.SelectedValue;if(-not $ID){$ID='smart-auto'};if($ID -eq 'custom:new'){ShowUnifiedCustomBuilder;return};if($ID -eq 'smart-auto'){$R=Api '/api/strategy/smart-auto' 'POST' @{} 240}elseif($ID -eq 'auto'){$R=Api '/api/strategy/auto' 'POST' @{} 200}elseif($ID.StartsWith('custom:')){$Name=$ID.Substring(7);$Preset=@(GetUnifiedPresets|Where-Object{[string]$_.name -eq $Name}|Select-Object -First 1);if(-not $Preset){throw 'Saved CUSTOM preset is missing.'};$R=Api '/api/strategy/custom' 'POST' @{layers=@($Preset.layers)} 240}else{$Choice=@($script:UnifiedModeChoices|Where-Object{[string]$_.id -eq $ID}|Select-Object -First 1);if($Choice -and -not [bool]$Choice.available){throw [string]$Choice.display};$R=Api '/api/connect-logical' 'POST' @{mode=$ID;base='auto'} 180};Log ("Connected winner: "+[string]$R.runtime_mode)}catch{Log ('Connect failed: '+$_.Exception.Message)}finally{RefreshProduct}}
function ShowUnifiedCustomBuilder{
 try{$Raw=@(Api '/api/logical-modes' -Timeout 12);$Layers=New-Object 'System.Collections.Generic.HashSet[string]';foreach($M in $Raw){foreach($V in @($M.variants.PSObject.Properties)){if($V.Value -and $V.Value.mode){foreach($L in @($V.Value.mode.layers)){if($L){[void]$Layers.Add([string]$L)}}}}};$LayerList=@($Layers|Sort-Object);if(-not $LayerList){throw 'No mode layers are available.'}
 [xml]$X=@"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="CUSTOM preset builder" Width="650" Height="640" MinWidth="520" MinHeight="460" WindowStartupLocation="CenterOwner" Background="#0B1020" Foreground="#F5F7FF"><Grid Margin="18"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions><TextBlock Text="Build a validated CUSTOM mode" FontSize="24" FontWeight="Bold"/><TextBox Name="PresetName" Grid.Row="1" Margin="0,12,0,10" Padding="8" ToolTip="Preset name"/><ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto"><StackPanel Name="LayerStack"/></ScrollViewer><StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,12,0,0"><Button Name="Delete" Content="Delete saved preset" Padding="10,6" Margin="4"/><Button Name="Cancel" Content="Cancel" Padding="10,6" Margin="4"/><Button Name="Save" Content="Save" Padding="12,6" Margin="4"/><Button Name="SaveConnect" Content="Save &amp; Connect" Padding="12,6" Margin="4"/></StackPanel></Grid></Window>
"@;$R=New-Object System.Xml.XmlNodeReader $X;$D=[Windows.Markup.XamlReader]::Load($R);$D.Owner=$Window;$Name=$D.FindName('PresetName');$Stack=$D.FindName('LayerStack');$Checks=@{};foreach($L in $LayerList){$C=New-Object Windows.Controls.CheckBox;$C.Content=$L;$C.Margin='2';$Checks[$L]=$C;[void]$Stack.Children.Add($C)};$Current=[string]$ModeCombo.SelectedValue;if($Current.StartsWith('custom:')){$N=$Current.Substring(7);$Old=@(GetUnifiedPresets|Where-Object{[string]$_.name -eq $N}|Select-Object -First 1);if($Old){$Name.Text=$N;foreach($L in @($Old.layers)){if($Checks.ContainsKey([string]$L)){$Checks[[string]$L].IsChecked=$true}}}}
 $SaveAction={param([bool]$Connect);$N=$Name.Text.Trim();$Selected=@($LayerList|Where-Object{$Checks[$_].IsChecked});if(-not $N -or $N.Length -gt 64 -or $Selected.Count -eq 0){[Windows.MessageBox]::Show('Enter a 1–64 character name and choose at least one exact layer.','CUSTOM')|Out-Null;return};$P=@(GetUnifiedPresets|Where-Object{[string]$_.name -ne $N});$P+=,[pscustomobject]@{name=$N;layers=$Selected};SaveUnifiedPresets $P;SaveUnifiedModeID ('custom:'+$N);$D.Tag=if($Connect){'connect'}else{'saved'};$D.Close()};$D.FindName('Save').Add_Click({&$SaveAction $false});$D.FindName('SaveConnect').Add_Click({&$SaveAction $true});$D.FindName('Cancel').Add_Click({$D.Close()});$D.FindName('Delete').Add_Click({$N=$Name.Text.Trim();if($N){SaveUnifiedPresets @(GetUnifiedPresets|Where-Object{[string]$_.name -ne $N});SaveUnifiedModeID 'smart-auto';$D.Tag='deleted';$D.Close()}});[void]$D.ShowDialog();RefreshProduct;if([string]$D.Tag -eq 'connect'){UnifiedConnect}
 }catch{Log ('CUSTOM builder failed: '+$_.Exception.Message)}}
'@
    $ProductSource = $ProductSource.Replace($scriptMarker, $scriptMarker + "`n" + $extraState)

    $modeRefreshOld = '$ModesGrid.ItemsSource=$Modes;$ModeCombo.ItemsSource=@($Modes|Where-Object{$_.available});if(-not$ModeCombo.SelectedValue-and$ModeCombo.Items.Count-gt0){$ModeCombo.SelectedIndex=0};'
    if (-not $ProductSource.Contains($modeRefreshOld)) { throw 'Windows unified shell: mode refresh contract drifted.' }
    $ProductSource = $ProductSource.Replace($modeRefreshOld, '$ModesGrid.ItemsSource=$Modes;RefreshUnifiedModeChoices $Modes;')

    $headerOld = '$HeaderDetail.Text="Native Windows product - $($Profiles.Count) linked node(s) - order $($script:NodeSort)";'
    $headerNew = '$HeaderDetail.Text="Native Windows product - $($Profiles.Count) linked node(s) - order $($script:NodeSort)";$ConnectionDetail.Text="Phase: $($Status.phase) • Logical: $($Status.logical_mode) • Runtime: $Runtime • Base: $($Status.base)";(Control ''UnifiedConnectButton'').Content=if($Connected -or ([string]$Status.phase -match ''starting|checking|trying|proving'')){''Disconnect''}else{''Connect''};$UnifiedSettings=(Control ''UnifiedSettingsSummary'');if($Selected.Count){$UnifiedSettings.Text="IPv6=$($Profile.ipv6_mode) • MTU=$($Profile.mtu_policy)/$($Profile.effective_mtu) • LAN=$($Profile.home_lan_access)"};'
    if (-not $ProductSource.Contains($headerOld)) { throw 'Windows unified shell: refresh header contract drifted.' }
    $ProductSource = $ProductSource.Replace($headerOld,$headerNew)

    $beforeShow = '$BaseCombo.SelectedIndex=0'
    if (-not $ProductSource.Contains($beforeShow)) { throw 'Windows unified shell: startup marker drifted.' }
    $handlers = @'
(Control 'UnifiedConnectButton').Add_Click({UnifiedConnect})
(Control 'UnifiedProofButton').Add_Click({try{$R=Api '/api/home-summary/prove-exit' 'POST' @{} 15;if([string]$R.actual_exit_status -ne 'proved' -or -not [string]$R.actual_exit_ip){throw 'Current-session public-exit proof did not return proved.'};$ProofText.Text="Actual public VPN exit: $($R.actual_exit_ip) • current session proved";Log ("Actual public VPN exit proved: "+[string]$R.actual_exit_ip)}catch{Log ('Exit proof failed: '+$_.Exception.Message)};RefreshProduct})
(Control 'UnifiedEmergencyButton').Add_Click({try{[void](Api '/api/emergency-stop' 'POST' @{} 20);Log 'Emergency disconnect completed'}catch{Log ('Emergency disconnect failed: '+$_.Exception.Message)};RefreshProduct})
(Control 'UnifiedNodesButton').Add_Click({OpenUnifiedDetail 1})
(Control 'UnifiedPresetsButton').Add_Click({OpenUnifiedDetail 2})
(Control 'UnifiedDnsDetailsButton').Add_Click({OpenUnifiedDetail 3})
(Control 'UnifiedSettingsButton').Add_Click({try{$Saved=Show-RouterVPNProfileSettingsDialog -BaseUrl $BaseUrl -Owner $Window;if($null -ne $Saved){Log 'Profile settings saved'}}catch{Log ('Settings failed: '+$_.Exception.Message)};RefreshProduct})
(Control 'UnifiedMtuButton').Add_Click({try{$Result=Api '/api/mtu/retest' 'POST' @{} 130;Log ("MTU Retest: effective=$($Result.effective_mtu) source=$($Result.effective_mtu_source)")}catch{Log ('MTU Retest failed: '+$_.Exception.Message)};RefreshProduct})
(Control 'UnifiedBackButton').Add_Click({BackUnifiedMap})
(Control 'UnifiedModeCombo').Add_SelectionChanged({if($ModeCombo.SelectedValue){$ID=[string]$ModeCombo.SelectedValue;if($ID -eq 'custom:new'){ShowUnifiedCustomBuilder}else{SaveUnifiedModeID $ID}}})
(Control 'UnifiedKillSwitch').Add_Click({try{$On=[bool](Control 'UnifiedKillSwitch').IsChecked;[void](Api '/api/profile/settings' 'POST' @{kill_switch_policy=if($On){'on-connect'}else{'off'}} 12);Log (if($On){'Kill switch enabled'}else{'Kill switch disabled'})}catch{Log ('Kill switch update failed: '+$_.Exception.Message)};RefreshProduct})
(Control 'UnifiedDnsCombo').Add_SelectionChanged({if(-not $script:Busy){$Tag=ComboTag (Control 'UnifiedDnsCombo') 'home';if($Tag -in @('custom','dot','doh','doh3')){OpenUnifiedDetail 3}else{try{[void](Api '/api/dns/policy' 'POST' @{mode=$Tag} 10);Log ('DNS selected: '+$Tag)}catch{Log ('DNS update failed: '+$_.Exception.Message)};RefreshDnsPolicy;RefreshProduct}}})
'@
    $ProductSource = $ProductSource.Replace($beforeShow, $handlers + "`n" + $beforeShow)

    $ProductSource += "`n# Unified Windows UX contract: map-first bottom control sheet Connect Disconnect quick kill switch Prove actual exit current-session proof Emergency disconnect Multihop Settings Mode DNS SMART AUTO default AUTO all presets CUSTOM visual preset builder saved delete Router node Custom external real coordinates color-coded hop roles IPv6 On Auto MTU Require encrypted Require obfuscation.`n"
    return $ProductSource
}
