function global:Get-RouterVPNProfileSettings {
    param([string]$BaseUrl)
    Invoke-RestMethod -Uri ($BaseUrl.TrimEnd('/') + '/api/profile/settings') -Method Get -TimeoutSec 5
}

function global:Save-RouterVPNProfileSettings {
    param([string]$BaseUrl,$Body)
    Invoke-RestMethod -Uri ($BaseUrl.TrimEnd('/') + '/api/profile/settings') -Method Post -ContentType 'application/json' -Body ($Body | ConvertTo-Json -Compress) -TimeoutSec 8
}

function global:Get-RouterVPNConnectionProfiles {
    param([string]$BaseUrl)
    $result=Invoke-RestMethod -Uri ($BaseUrl.TrimEnd('/') + '/api/connection-profiles') -Method Get -TimeoutSec 5
    return @($result.profiles)
}

function global:Get-RouterVPNCurrentModeSnapshot {
    $stateDir=Join-Path $PSScriptRoot '.routervpn-state'
    $modeFile=Join-Path $stateDir 'windows-selected-mode-v1.txt'
    $presetFile=Join-Path $stateDir 'windows-custom-presets-v1.json'
    $mode='smart-auto';if(Test-Path -LiteralPath $modeFile){try{$raw=(Get-Content -LiteralPath $modeFile -Raw -Encoding UTF8).Trim();if($raw){$mode=$raw}}catch{}}
    $layers=@()
    if($mode.StartsWith('custom:') -and (Test-Path -LiteralPath $presetFile)){
        $name=$mode.Substring(7)
        try{$preset=@((Get-Content -LiteralPath $presetFile -Raw -Encoding UTF8|ConvertFrom-Json)|Where-Object{[string]$_.name -eq $name}|Select-Object -First 1);if($preset){$layers=@($preset.layers)}}catch{}
    }
    [pscustomobject]@{mode=$mode;custom_layers=@($layers)}
}

function global:Set-RouterVPNLoadedModeSnapshot {
    param($Loaded)
    $mode=[string]$Loaded.mode;if([string]::IsNullOrWhiteSpace($mode)){$mode='smart-auto'}
    $stateDir=Join-Path $PSScriptRoot '.routervpn-state';[void](New-Item -ItemType Directory -Force -Path $stateDir)
    $modeFile=Join-Path $stateDir 'windows-selected-mode-v1.txt';Set-Content -LiteralPath $modeFile -Value $mode -Encoding UTF8
    if($mode.StartsWith('custom:')){
        $name=$mode.Substring(7);$layers=@($Loaded.custom_layers)
        if($name -and $layers.Count -gt 0){
            $presetFile=Join-Path $stateDir 'windows-custom-presets-v1.json';$values=@();if(Test-Path -LiteralPath $presetFile){try{$values=@(Get-Content -LiteralPath $presetFile -Raw -Encoding UTF8|ConvertFrom-Json)}catch{$values=@()}}
            $values=@($values|Where-Object{[string]$_.name -ne $name});$values+=,[pscustomobject]@{name=$name;layers=@($layers)};@($values)|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $presetFile -Encoding UTF8
        }
    }
}

function global:Get-RouterVPNVisibleConnectionSnapshot {
    param([System.Windows.Window]$Owner,[hashtable]$Provided)
    if($null -ne $Provided){return $Provided}
    $result=@{multihop_enabled=$false;multihop_entry_id='';multihop_exit_id='';multihop_exit_mode=''}
    if($null -eq $Owner){return $result}
    try{
        $toggle=$Owner.FindName('UnifiedMultihop');$entry=$Owner.FindName('UnifiedEntryCombo');$exit=$Owner.FindName('UnifiedExitCombo');$exitMode=$Owner.FindName('UnifiedExitMode')
        if($null -ne $toggle){$result.multihop_enabled=[bool]$toggle.IsChecked}
        if($result.multihop_enabled){
            if($null -ne $entry){$result.multihop_entry_id=[string]$entry.SelectedValue}
            if($null -ne $exit){$result.multihop_exit_id=[string]$exit.SelectedValue}
            if($null -ne $exitMode -and $null -ne $exitMode.SelectedItem){$result.multihop_exit_mode=[string]$exitMode.SelectedItem.Tag}
            if([string]::IsNullOrWhiteSpace([string]$result.multihop_exit_mode)){$result.multihop_exit_mode='shadowsocks'}
        }
    }catch{}
    return $result
}

function global:Apply-RouterVPNLoadedConnectionSnapshot {
    param([System.Windows.Window]$Owner,$Loaded)
    if($null -eq $Owner){return}
    try{
        $toggle=$Owner.FindName('UnifiedMultihop');$entry=$Owner.FindName('UnifiedEntryCombo');$exit=$Owner.FindName('UnifiedExitCombo');$exitMode=$Owner.FindName('UnifiedExitMode')
        $enabled=[bool]$Loaded.multihop_enabled
        if($null -ne $toggle){$toggle.IsChecked=$enabled}
        if($null -ne $entry -and -not [string]::IsNullOrWhiteSpace([string]$Loaded.multihop_entry_id)){$entry.SelectedValue=[string]$Loaded.multihop_entry_id}
        if($null -ne $exit -and -not [string]::IsNullOrWhiteSpace([string]$Loaded.multihop_exit_id)){$exit.SelectedValue=[string]$Loaded.multihop_exit_id}
        if($null -ne $exitMode -and $exitMode.Items.Count -gt 0){
            $want=[string]$Loaded.multihop_exit_mode;if([string]::IsNullOrWhiteSpace($want)){$want='shadowsocks'}
            for($i=0;$i-lt$exitMode.Items.Count;$i++){if([string]$exitMode.Items[$i].Tag -eq $want){$exitMode.SelectedIndex=$i;break}}
        }
    }catch{}
}

function global:Show-RouterVPNProfileSettingsDialog {
    param([string]$BaseUrl,[System.Windows.Window]$Owner,[hashtable]$ConnectionSnapshot,[scriptblock]$OnConnectionProfileLoaded)
    $current=$null;$settingsError=''
    try{$current=Get-RouterVPNProfileSettings -BaseUrl $BaseUrl}catch{$settingsError=$_.Exception.Message}
    [xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="Settings" Width="720" Height="850" MinWidth="560" MinHeight="620" WindowStartupLocation="CenterOwner" ResizeMode="CanResize" Background="#0B1020" Foreground="#F5F7FF">
<ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel Margin="20">
<TextBlock Text="Selected Router VPN node" FontSize="22" FontWeight="Bold"/><TextBlock Name="SettingsNote" Text="Disconnect before saving. SMART AUTO, IPv6 On and Auto measured MTU are the unified defaults. These are persistent node preferences for the next supported connection; a saved value is not runtime proof." TextWrapping="Wrap" Foreground="#A8B6D5" Margin="0,4,0,14"/>
<StackPanel Name="NodeSettings">
<CheckBox Name="LAN" Content="Allow home LAN access" Margin="0,5"/>
<TextBlock Text="Kill switch policy"/><ComboBox Name="Kill" Margin="0,3,0,10"><ComboBoxItem Content="Off" Tag="off"/><ComboBoxItem Content="On connect" Tag="on-connect"/><ComboBoxItem Content="Always / strict" Tag="always"/></ComboBox>
<TextBlock Text="IPv6 policy"/><ComboBox Name="IPv6" Margin="0,3,0,10"><ComboBoxItem Content="On — default" Tag="on"/><ComboBoxItem Content="Auto" Tag="auto"/><ComboBoxItem Content="Off" Tag="off"/></ComboBox>
<TextBlock Text="WG / AWG base preference"/><ComboBox Name="Base" Margin="0,3,0,5"><ComboBoxItem Content="Auto" Tag="auto"/><ComboBoxItem Content="WireGuard" Tag="wg"/><ComboBoxItem Content="AmneziaWG" Tag="awg"/></ComboBox><CheckBox Name="Fallback" Content="Allow compatible WG/AWG base fallback" Margin="0,0,0,10"/>
<TextBlock Text="AUTO / SMART AUTO filters" FontWeight="SemiBold" Margin="0,8,0,2"/><CheckBox Name="RequireEncrypted" Content="Require encrypted" Margin="0,3"/><CheckBox Name="RequireObfuscation" Content="Require obfuscation" Margin="0,3"/><TextBlock Text="Both are Off by default. Enabled filters remove non-matching candidates before AUTO tries them; SMART cannot simplify below the selected requirements." TextWrapping="Wrap" FontSize="11" Foreground="#A8B6D5" Margin="0,0,0,10"/>
<TextBlock Text="MTU policy"/><ComboBox Name="MTUPolicy" Margin="0,3,0,5"><ComboBoxItem Content="Auto measured — default" Tag="auto"/><ComboBoxItem Content="Fixed / manual" Tag="manual"/><ComboBoxItem Content="Runtime default" Tag="default"/></ComboBox><TextBox Name="ManualMTU" Margin="0,0,0,5" ToolTip="Fixed MTU 576–9000; ignored for Auto/Runtime default"/><TextBlock Name="Effective" TextWrapping="Wrap" FontSize="11" Foreground="#A8B6D5" Margin="0,0,0,10"/>
<CheckBox Name="DAITA" Content="DAITA-like traffic padding (bounded; supported modes only)" Margin="0,5"/><CheckBox Name="Jumbo" Content="Jumbo TUN / jumbo packet mode (compatible paths only)" Margin="0,5"/><CheckBox Name="Socks" Content="Enable private in-tunnel SOCKS5 utility" Margin="0,5"/>
<TextBlock Text="Startup / default mode" Margin="0,10,0,0"/><ComboBox Name="Startup" Margin="0,3,0,5"><ComboBoxItem Content="SMART AUTO — recommended" Tag="smart-auto"/><ComboBoxItem Content="AUTO" Tag="auto"/><ComboBoxItem Content="Last proven mode" Tag="last"/><ComboBoxItem Content="Manual / stay disconnected" Tag="manual"/></ComboBox><CheckBox Name="AutoConnect" Content="Auto-connect when the native app starts" Margin="0,0,0,10"/>
<StackPanel Orientation="Horizontal" Margin="0,4,0,10"><Button Name="MtuRetest" Content="Retest MTU for current config/path" Padding="10,6" Margin="0,0,8,0"/><Button Name="Forwarding" Content="Port forwarding / Protected DMZ…" Padding="10,6"/></StackPanel>
<TextBlock Text="Retest is path/config specific. A fixed MTU stays fixed until changed. Incoming forwarding is owned by the authenticated private home node and is available only to routable tunnel modes; proxy-only paths never claim arbitrary DNAT." TextWrapping="Wrap" FontSize="11" Foreground="#A8B6D5" Margin="0,0,0,12"/>
</StackPanel>
<Separator Margin="0,6,0,12"/>
<TextBlock Text="Connection profiles" FontSize="17" FontWeight="SemiBold"/><TextBlock Text="Save or restore the selected node plus current Mode/CUSTOM layers, DNS, kill switch, IPv6, MTU, and exact multihop entry → exit → exit-transport choice. Node keys, API tokens and external credentials are referenced by node ID and are never copied into a connection profile." TextWrapping="Wrap" Foreground="#A8B6D5" FontSize="11" Margin="0,3,0,8"/>
<TextBox Name="ConnectionProfileName" Margin="0,0,0,6" ToolTip="Name for Add or Update"/><ComboBox Name="ConnectionProfiles" DisplayMemberPath="display" SelectedValuePath="id" Margin="0,0,0,6"/>
<WrapPanel Margin="0,0,0,5"><Button Name="ProfileAdd" Content="Add profile" Padding="9,5" Margin="0,0,6,6"/><Button Name="ProfileLoad" Content="Load" Padding="9,5" Margin="0,0,6,6"/><Button Name="ProfileUpdate" Content="Update" Padding="9,5" Margin="0,0,6,6"/><Button Name="ProfileDelete" Content="Delete" Padding="9,5" Margin="0,0,6,6"/><Button Name="ProfileRefresh" Content="Refresh" Padding="9,5" Margin="0,0,6,6"/></WrapPanel>
<TextBlock Name="ProfileStatus" TextWrapping="Wrap" FontSize="11" Foreground="#A8B6D5" Margin="0,0,0,12"/>
<StackPanel Orientation="Horizontal" HorizontalAlignment="Right"><Button Name="Cancel" Content="Close" MinWidth="90" Margin="4"/><Button Name="Save" Content="Save node settings" MinWidth="150" Margin="4" IsDefault="True"/></StackPanel>
</StackPanel></ScrollViewer></Window>
'@
    $reader=New-Object System.Xml.XmlNodeReader $xaml; $dialog=[Windows.Markup.XamlReader]::Load($reader); if($Owner){$dialog.Owner=$Owner}
    function SetTag($combo,[string]$tag){for($i=0;$i-lt$combo.Items.Count;$i++){if([string]$combo.Items[$i].Tag-eq$tag){$combo.SelectedIndex=$i;return}};$combo.SelectedIndex=0}
    $nodeSettings=$dialog.FindName('NodeSettings');$settingsNote=$dialog.FindName('SettingsNote');$lan=$dialog.FindName('LAN');$kill=$dialog.FindName('Kill');$ipv6=$dialog.FindName('IPv6');$base=$dialog.FindName('Base');$fallback=$dialog.FindName('Fallback');$requireEncrypted=$dialog.FindName('RequireEncrypted');$requireObfuscation=$dialog.FindName('RequireObfuscation');$mtuPolicy=$dialog.FindName('MTUPolicy');$manual=$dialog.FindName('ManualMTU');$effective=$dialog.FindName('Effective');$daita=$dialog.FindName('DAITA');$jumbo=$dialog.FindName('Jumbo');$socks=$dialog.FindName('Socks');$startup=$dialog.FindName('Startup');$autoConnect=$dialog.FindName('AutoConnect');$profileName=$dialog.FindName('ConnectionProfileName');$profileCombo=$dialog.FindName('ConnectionProfiles');$profileStatus=$dialog.FindName('ProfileStatus')
    if($null -ne $current){
        $lan.IsChecked=[bool]$current.home_lan_access;SetTag $kill ([string]$current.kill_switch_policy);SetTag $ipv6 $(if([string]::IsNullOrWhiteSpace([string]$current.ipv6_mode)){'on'}else{[string]$current.ipv6_mode});SetTag $base ([string]$current.base_tunnel);$fallback.IsChecked=[bool]$current.base_fallback;$requireEncrypted.IsChecked=[bool]$current.auto_require_encrypted;$requireObfuscation.IsChecked=[bool]$current.auto_require_obfuscation;SetTag $mtuPolicy $(if([string]::IsNullOrWhiteSpace([string]$current.mtu_policy)){'auto'}else{[string]$current.mtu_policy});$manual.Text=if([int]$current.manual_mtu-gt0){[string]$current.manual_mtu}else{''};$daita.IsChecked=[bool]$current.daita_enabled;$jumbo.IsChecked=[bool]$current.jumbo_tun;$socks.IsChecked=[bool]$current.socks_enabled;SetTag $startup $(if([string]::IsNullOrWhiteSpace([string]$current.startup_mode)){'smart-auto'}else{[string]$current.startup_mode});$autoConnect.IsChecked=[bool]$current.auto_connect;$effective.Text="Current effective MTU: $(if([int]$current.effective_mtu-gt0){$current.effective_mtu}else{'not measured yet'}) • $(if([string]::IsNullOrWhiteSpace([string]$current.effective_mtu_source)){'Auto will use a valid path/config-specific value'}else{$current.effective_mtu_source})"
    }else{
        $nodeSettings.IsEnabled=$false;$dialog.FindName('Save').IsEnabled=$false;$settingsNote.Text='Selected node does not expose Router VPN node settings here (for example, a Custom/external node). Connection-profile Add / Load / Update / Delete remains available.';$effective.Text=$settingsError
    }
    $refreshProfiles={
        try{$items=New-Object System.Collections.ArrayList;foreach($p in @(Get-RouterVPNConnectionProfiles -BaseUrl $BaseUrl)){$label="$($p.name) • $($p.mode) • $($p.node_id)";[void]$items.Add([pscustomobject]@{id=[string]$p.id;display=$label;name=[string]$p.name;mode=[string]$p.mode;node_id=[string]$p.node_id})};$profileCombo.ItemsSource=@($items);if($items.Count -gt 0){$profileCombo.SelectedIndex=0};$profileStatus.Text="$($items.Count) saved connection profile(s)."}catch{$profileStatus.Text='Profile refresh failed: '+$_.Exception.Message}
    }
    $makeSetupBody={
        param([string]$Name,[string]$ID)
        $snap=Get-RouterVPNCurrentModeSnapshot
        $visible=Get-RouterVPNVisibleConnectionSnapshot -Owner $Owner -Provided $ConnectionSnapshot
        $body=@{name=$Name;mode=[string]$snap.mode;custom_layers=@($snap.custom_layers);multihop_enabled=[bool]$visible.multihop_enabled;multihop_entry_id=[string]$visible.multihop_entry_id;multihop_exit_id=[string]$visible.multihop_exit_id;multihop_exit_mode=[string]$visible.multihop_exit_mode}
        if($ID){$body.id=$ID}
        return $body
    }
    $profileCombo.Add_SelectionChanged({if($profileCombo.SelectedItem){$profileName.Text=[string]$profileCombo.SelectedItem.name}})
    $dialog.FindName('ProfileRefresh').Add_Click({& $refreshProfiles})
    $dialog.FindName('ProfileAdd').Add_Click({try{$name=$profileName.Text.Trim();if(-not$name){throw 'Enter a profile name.'};$body=& $makeSetupBody $name '';$r=Invoke-RestMethod -Uri ($BaseUrl.TrimEnd('/') + '/api/connection-profile/setup/save') -Method Post -ContentType 'application/json' -Body ($body|ConvertTo-Json -Depth 8 -Compress) -TimeoutSec 10;$profileStatus.Text="Added $($r.profile.name) • $($r.profile.mode) • exact hop setup saved";& $refreshProfiles}catch{$profileStatus.Text='Add failed: '+$_.Exception.Message}})
    $dialog.FindName('ProfileUpdate').Add_Click({try{if(-not$profileCombo.SelectedValue){throw 'Select a saved profile.'};$name=$profileName.Text.Trim();if(-not$name){throw 'Enter a profile name.'};$body=& $makeSetupBody $name ([string]$profileCombo.SelectedValue);$r=Invoke-RestMethod -Uri ($BaseUrl.TrimEnd('/') + '/api/connection-profile/setup/update') -Method Post -ContentType 'application/json' -Body ($body|ConvertTo-Json -Depth 8 -Compress) -TimeoutSec 10;$profileStatus.Text="Updated $($r.profile.name) • exact hop setup refreshed";& $refreshProfiles}catch{$profileStatus.Text='Update failed: '+$_.Exception.Message}})
    $dialog.FindName('ProfileLoad').Add_Click({try{if(-not$profileCombo.SelectedValue){throw 'Select a saved profile.'};$body=@{id=[string]$profileCombo.SelectedValue};$r=Invoke-RestMethod -Uri ($BaseUrl.TrimEnd('/') + '/api/connection-profile/setup/load') -Method Post -ContentType 'application/json' -Body ($body|ConvertTo-Json -Compress) -TimeoutSec 12;Set-RouterVPNLoadedModeSnapshot -Loaded $r;Apply-RouterVPNLoadedConnectionSnapshot -Owner $Owner -Loaded $r;if($null -ne $OnConnectionProfileLoaded){& $OnConnectionProfileLoaded $r};$profileStatus.Text="Loaded $($r.profile.name) • node $($r.selected_node_id) • mode $($r.mode) • exact hop setup restored. Connect separately to prove it."}catch{$profileStatus.Text='Load failed: '+$_.Exception.Message}})
    $dialog.FindName('ProfileDelete').Add_Click({try{if(-not$profileCombo.SelectedValue){throw 'Select a saved profile.'};$body=@{id=[string]$profileCombo.SelectedValue};[void](Invoke-RestMethod -Uri ($BaseUrl.TrimEnd('/') + '/api/connection-profile/setup/delete') -Method Post -ContentType 'application/json' -Body ($body|ConvertTo-Json -Compress) -TimeoutSec 10);$profileStatus.Text='Deleted saved connection profile and setup metadata.';& $refreshProfiles}catch{$profileStatus.Text='Delete failed: '+$_.Exception.Message}})
    & $refreshProfiles
    $dialog.FindName('MtuRetest').Add_Click({try{$r=Invoke-RestMethod -Uri ($BaseUrl.TrimEnd('/') + '/api/mtu/retest') -Method Post -ContentType 'application/json' -Body '{}' -TimeoutSec 130;$effective.Text="Current effective MTU: $($r.effective_mtu) • $($r.effective_mtu_source)"}catch{[System.Windows.MessageBox]::Show("MTU Retest failed: $($_.Exception.Message)",'Router VPN')|Out-Null}})
    $dialog.FindName('Forwarding').Add_Click({[System.Windows.MessageBox]::Show('Port forwarding / Protected DMZ is configured through the authenticated private home-node forwarding surface and must be validated off-LAN. Router VPN will not advertise arbitrary DNAT for proxy-only paths.','Router VPN forwarding')|Out-Null})
    $script:RVPNSettingsSave=$false;$dialog.FindName('Cancel').Add_Click({$dialog.Close()});$dialog.FindName('Save').Add_Click({$script:RVPNSettingsSave=$true;$dialog.Close()});[void]$dialog.ShowDialog();if(-not$script:RVPNSettingsSave -or $null -eq $current){return $null}
    $manualValue=0;if($manual.Text.Trim()){if(-not[int]::TryParse($manual.Text.Trim(),[ref]$manualValue)){throw 'Fixed MTU must be a number.'}}
    if([string]$mtuPolicy.SelectedItem.Tag-eq'manual'-and($manualValue-lt576-or$manualValue-gt9000)){throw 'Fixed MTU must be 576–9000.'};if([string]$mtuPolicy.SelectedItem.Tag-ne'manual'){$manualValue=0}
    $body=@{home_lan_access=[bool]$lan.IsChecked;kill_switch_policy=[string]$kill.SelectedItem.Tag;ipv6_mode=[string]$ipv6.SelectedItem.Tag;base_tunnel=[string]$base.SelectedItem.Tag;base_fallback=[bool]$fallback.IsChecked;auto_require_encrypted=[bool]$requireEncrypted.IsChecked;auto_require_obfuscation=[bool]$requireObfuscation.IsChecked;mtu_policy=[string]$mtuPolicy.SelectedItem.Tag;manual_mtu=$manualValue;daita_enabled=[bool]$daita.IsChecked;jumbo_tun=[bool]$jumbo.IsChecked;socks_enabled=[bool]$socks.IsChecked;startup_mode=[string]$startup.SelectedItem.Tag;auto_connect=[bool]$autoConnect.IsChecked}
    Save-RouterVPNProfileSettings -BaseUrl $BaseUrl -Body $body
}

# Safe unified settings contract: /api/profile/settings only for node preferences; connection profiles use
# /api/connection-profile/setup/* plus /api/connection-profiles and never duplicate node secrets.
# SMART AUTO default / IPv6 On default / Auto measured MTU / fixed override + Retest /
# Require encrypted + Require obfuscation default Off / DAITA-like traffic padding / Jumbo TUN /
# LAN / kill switch / WG-AWG base+fallback / private SOCKS5 / forwarding ownership / startup /
# connection profile Add + Load + Update + Delete with current mode/CUSTOM layers and exact visible multihop entry/exit/exit transport.
