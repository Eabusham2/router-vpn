function global:Get-RouterVPNProfileSettings {
    param([string]$BaseUrl)
    Invoke-RestMethod -Uri ($BaseUrl.TrimEnd('/') + '/api/profile/settings') -Method Get -TimeoutSec 5
}

function global:Save-RouterVPNProfileSettings {
    param([string]$BaseUrl,$Body)
    Invoke-RestMethod -Uri ($BaseUrl.TrimEnd('/') + '/api/profile/settings') -Method Post -ContentType 'application/json' -Body ($Body | ConvertTo-Json -Compress) -TimeoutSec 8
}

function global:Show-RouterVPNProfileSettingsDialog {
    param([string]$BaseUrl,[System.Windows.Window]$Owner)
    $current = Get-RouterVPNProfileSettings -BaseUrl $BaseUrl
    [xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="Router VPN profile settings" Width="650" Height="690" MinWidth="520" MinHeight="560" WindowStartupLocation="CenterOwner" ResizeMode="CanResize">
<ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel Margin="20">
<TextBlock Text="Selected Router VPN node" FontSize="22" FontWeight="Bold"/><TextBlock Text="Disconnect before saving. These are persistent node settings; saved values are applied on the next tunnel start and are not runtime proof by themselves." TextWrapping="Wrap" Margin="0,4,0,14"/>
<CheckBox Name="LAN" Content="Allow home LAN access" Margin="0,5"/>
<TextBlock Text="Kill switch policy"/><ComboBox Name="Kill" Margin="0,3,0,10"><ComboBoxItem Content="Off" Tag="off"/><ComboBoxItem Content="On connect" Tag="on-connect"/><ComboBoxItem Content="Always / strict" Tag="always"/></ComboBox>
<TextBlock Text="IPv6 policy"/><ComboBox Name="IPv6" Margin="0,3,0,10"><ComboBoxItem Content="Auto" Tag="auto"/><ComboBoxItem Content="On" Tag="on"/><ComboBoxItem Content="Off" Tag="off"/></ComboBox>
<TextBlock Text="Base tunnel preference"/><ComboBox Name="Base" Margin="0,3,0,5"><ComboBoxItem Content="Auto" Tag="auto"/><ComboBoxItem Content="WireGuard" Tag="wg"/><ComboBoxItem Content="AmneziaWG" Tag="awg"/></ComboBox><CheckBox Name="Fallback" Content="Allow WG/AWG base fallback" Margin="0,0,0,10"/>
<TextBlock Text="MTU policy"/><ComboBox Name="MTUPolicy" Margin="0,3,0,5"><ComboBoxItem Content="Default" Tag="default"/><ComboBoxItem Content="Auto measured" Tag="auto"/><ComboBoxItem Content="Manual" Tag="manual"/></ComboBox><TextBox Name="ManualMTU" Margin="0,0,0,10" ToolTip="Manual MTU 576–9000; ignored for Default/Auto"/>
<CheckBox Name="DAITA" Content="DAITA-like bounded cover traffic (supported modes only)" Margin="0,5"/><CheckBox Name="Jumbo" Content="Jumbo TUN (compatible TUN/proxy paths only)" Margin="0,5"/><CheckBox Name="Socks" Content="Enable private in-tunnel SOCKS5 utility" Margin="0,5"/>
<TextBlock Text="Startup behavior" Margin="0,10,0,0"/><ComboBox Name="Startup" Margin="0,3,0,5"><ComboBoxItem Content="Manual" Tag="manual"/><ComboBoxItem Content="AUTO" Tag="auto"/><ComboBoxItem Content="SMART AUTO" Tag="smart-auto"/><ComboBoxItem Content="Last mode" Tag="last"/></ComboBox><CheckBox Name="AutoConnect" Content="Auto-connect when the native app starts" Margin="0,0,0,10"/>
<TextBlock Name="Effective" TextWrapping="Wrap" Margin="0,4,0,12"/>
<StackPanel Orientation="Horizontal" HorizontalAlignment="Right"><Button Name="Cancel" Content="Cancel" MinWidth="90" Margin="4"/><Button Name="Save" Content="Save for next connection" MinWidth="150" Margin="4" IsDefault="True"/></StackPanel>
</StackPanel></ScrollViewer></Window>
'@
    $reader=New-Object System.Xml.XmlNodeReader $xaml; $dialog=[Windows.Markup.XamlReader]::Load($reader); if($Owner){$dialog.Owner=$Owner}
    function SetTag($combo,[string]$tag){for($i=0;$i-lt$combo.Items.Count;$i++){if([string]$combo.Items[$i].Tag-eq$tag){$combo.SelectedIndex=$i;return}};$combo.SelectedIndex=0}
    $lan=$dialog.FindName('LAN');$kill=$dialog.FindName('Kill');$ipv6=$dialog.FindName('IPv6');$base=$dialog.FindName('Base');$fallback=$dialog.FindName('Fallback');$mtuPolicy=$dialog.FindName('MTUPolicy');$manual=$dialog.FindName('ManualMTU');$daita=$dialog.FindName('DAITA');$jumbo=$dialog.FindName('Jumbo');$socks=$dialog.FindName('Socks');$startup=$dialog.FindName('Startup');$autoConnect=$dialog.FindName('AutoConnect');$effective=$dialog.FindName('Effective')
    $lan.IsChecked=[bool]$current.home_lan_access;SetTag $kill ([string]$current.kill_switch_policy);SetTag $ipv6 ([string]$current.ipv6_mode);SetTag $base ([string]$current.base_tunnel);$fallback.IsChecked=[bool]$current.base_fallback;SetTag $mtuPolicy ([string]$current.mtu_policy);$manual.Text=if([int]$current.manual_mtu-gt0){[string]$current.manual_mtu}else{''};$daita.IsChecked=[bool]$current.daita_enabled;$jumbo.IsChecked=[bool]$current.jumbo_tun;$socks.IsChecked=[bool]$current.socks_enabled;SetTag $startup ([string]$current.startup_mode);$autoConnect.IsChecked=[bool]$current.auto_connect;$effective.Text="Current effective MTU: $(if([int]$current.effective_mtu-gt0){$current.effective_mtu}else{'default/not measured'}) • $($current.effective_mtu_source)"
    $script:RVPNSettingsSave=$false;$dialog.FindName('Cancel').Add_Click({$dialog.Close()});$dialog.FindName('Save').Add_Click({$script:RVPNSettingsSave=$true;$dialog.Close()});[void]$dialog.ShowDialog();if(-not$script:RVPNSettingsSave){return $null}
    $manualValue=0;if($manual.Text.Trim()){if(-not[int]::TryParse($manual.Text.Trim(),[ref]$manualValue)){throw 'Manual MTU must be a number.'}}
    $body=@{home_lan_access=[bool]$lan.IsChecked;kill_switch_policy=[string]$kill.SelectedItem.Tag;ipv6_mode=[string]$ipv6.SelectedItem.Tag;base_tunnel=[string]$base.SelectedItem.Tag;base_fallback=[bool]$fallback.IsChecked;mtu_policy=[string]$mtuPolicy.SelectedItem.Tag;manual_mtu=$manualValue;daita_enabled=[bool]$daita.IsChecked;jumbo_tun=[bool]$jumbo.IsChecked;socks_enabled=[bool]$socks.IsChecked;startup_mode=[string]$startup.SelectedItem.Tag;auto_connect=[bool]$autoConnect.IsChecked}
    Save-RouterVPNProfileSettings -BaseUrl $BaseUrl -Body $body
}

# Safe settings contract: /api/profile/settings only; never POST redacted /api/profile.
# LAN Off / on-connect / always-strict kill switch / IPv6 / WG-AWG base+fallback /
# Default-Auto-Manual MTU / DAITA-like / Jumbo TUN / private SOCKS5 / startup/autoconnect.
