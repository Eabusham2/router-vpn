if(-not(Get-Command New-RouterVPNControllerClient -ErrorAction SilentlyContinue)){
    Import-Module (Join-Path $PSScriptRoot 'RouterVPN-Windows-ControllerTransport.psm1') -Global -ErrorAction Stop
}
if(-not(Get-Command Read-RouterVPNUIState -ErrorAction SilentlyContinue)){
    # App reads this UTF-8 source into a ScriptBlock, whose PSScriptRoot is
    # empty. The already imported transport retains the actual package root.
    $UIStateHelpers=Join-Path (Get-Command Get-RouterVPNControllerDataRoot -ErrorAction Stop).Module.ModuleBase 'RouterVPN-Windows-UIState.psm1'
    Import-Module $UIStateHelpers -Global -ErrorAction Stop
}

function global:Get-RouterVPNProfileSettings {
    param([string]$BaseUrl)
    Invoke-RouterVPNControllerRequest -Uri ($BaseUrl.TrimEnd('/') + '/api/profile/settings') -Method Get -TimeoutSec 5
}

function global:Save-RouterVPNProfileSettings {
    param([string]$BaseUrl,$Body)
    Invoke-RouterVPNControllerRequest -Uri ($BaseUrl.TrimEnd('/') + '/api/profile/settings') -Method Post -ContentType 'application/json' -Body ($Body | ConvertTo-Json -Compress) -TimeoutSec 8
}

function global:Get-RouterVPNProfileStartup {
    param([string]$BaseUrl)
    Invoke-RouterVPNControllerRequest -Uri ($BaseUrl.TrimEnd('/') + '/api/profile/startup') -Method Get -TimeoutSec 5
}

function global:Save-RouterVPNProfileStartup {
    param([string]$BaseUrl,$Captured,[string]$StartupMode,[bool]$AutoConnect)
    if($null -eq $Captured -or [string]::IsNullOrWhiteSpace([string]$Captured.profile_id) -or [string]::IsNullOrWhiteSpace([string]$Captured.profile_token)){throw 'Reopen Settings to capture the selected node.'}
    $body=@{profile_id=[string]$Captured.profile_id;profile_token=[string]$Captured.profile_token;startup_mode=$StartupMode;auto_connect=$AutoConnect}
    Invoke-RouterVPNControllerRequest -Uri ($BaseUrl.TrimEnd('/') + '/api/profile/startup') -Method Post -ContentType 'application/json' -Body ($body | ConvertTo-Json -Compress) -TimeoutSec 8
}

function global:Assert-RouterVPNProfileDeviceCapture {
    param($Captured,[string]$DisplayedProfileID)
    if($null -eq $Captured -or [string]::IsNullOrWhiteSpace($DisplayedProfileID) -or
       $Captured.profile_id -isnot [string] -or $Captured.profile_id -cne $DisplayedProfileID -or
       $Captured.profile_token -isnot [string] -or $Captured.profile_token -cnotmatch '\A[0-9a-f]{64}\z' -or
       [string]$Captured.node_kind -cne 'external' -or $Captured.device_policy_supported -isnot [bool]){
        throw 'The selected node changed or its device settings could not be captured. Reopen Settings.'
    }
    $jumbo=$Captured.PSObject.Properties['jumbo_tun'];$jumboSupport=$Captured.PSObject.Properties['jumbo_tun_supported']
    if(($null -ne $jumbo) -ne ($null -ne $jumboSupport) -or
       ($null -ne $jumbo -and ($jumbo.Value -isnot [bool] -or $jumboSupport.Value -isnot [bool]))){
        throw 'The captured Jumbo capability is incomplete or invalid. Reopen Settings.'
    }
    $cover=$Captured.PSObject.Properties['daita_enabled'];$rate=$Captured.PSObject.Properties['daita_rate_kbps'];$coverSupport=$Captured.PSObject.Properties['tor_cover_supported']
    $coverFields=@($cover,$rate,$coverSupport|Where-Object{$null-ne$_}).Count
    if($coverFields-ne0-and($coverFields-ne3-or$cover.Value-isnot[bool]-or$coverSupport.Value-isnot[bool]-or
       ($rate.Value-isnot[int]-and$rate.Value-isnot[long])-or($rate.Value-ne0-and($rate.Value-lt32-or$rate.Value-gt192))-or
       ($coverSupport.Value-and([string]$Captured.protocol-cnotin@('tor','tor-bridge')-or-not$Captured.device_policy_supported)))){
        throw 'The captured outgoing Tor cover policy is incomplete or invalid. Reopen Settings.'
    }
}

function global:Get-RouterVPNProfileDevice {
    param([string]$BaseUrl,[string]$DisplayedProfileID)
    $captured=Invoke-RouterVPNControllerRequest -Uri ($BaseUrl.TrimEnd('/') + '/api/profile/device') -Method Get -TimeoutSec 5
    Assert-RouterVPNProfileDeviceCapture -Captured $captured -DisplayedProfileID $DisplayedProfileID
    return $captured
}

function global:New-RouterVPNProfileDevicePayload {
    param($Captured,[string]$DisplayedProfileID,$HomeLANAccess,[string]$KillSwitchPolicy,[string]$IPv6Mode,[string]$MTUPolicy,$ManualMTU,$StartupMode,$AutoConnect,$JumboTUN,$DAITAEnabled,$DAITARateKbps)
    Assert-RouterVPNProfileDeviceCapture -Captured $Captured -DisplayedProfileID $DisplayedProfileID
    if(-not $Captured.device_policy_supported){throw 'This node cannot apply common device settings through its native runtime.'}
    if($HomeLANAccess -isnot [bool]){throw 'LAN access must be an explicit Boolean.'}
    if($KillSwitchPolicy -cnotin @('off','on-connect','always')){throw 'Choose Off, On connect, or Always protection.'}
    if($IPv6Mode -cnotin @('on','auto','off')){throw 'Choose On, Auto, or Off for IPv6.'}
    if($MTUPolicy -cnotin @('auto','default','manual')){throw 'Choose Auto, Runtime default, or Fixed MTU.'}
    if(($ManualMTU -isnot [string] -and $ManualMTU -isnot [int] -and $ManualMTU -isnot [long]) -or [string]$ManualMTU -cnotmatch '\A[0-9]{1,4}\z'){
        throw 'Fixed MTU must be a whole number from 1280 to 9000.'
    }
    $manualValue=[int]$ManualMTU
    if(($MTUPolicy -ceq 'manual' -and ($manualValue -lt 1280 -or $manualValue -gt 9000)) -or ($MTUPolicy -cne 'manual' -and $manualValue -ne 0)){
        throw 'Fixed MTU must be 1280 to 9000; Auto and Runtime default require zero.'
    }
    $jumboCapture=$Captured.PSObject.Properties['jumbo_tun'];$jumboSupport=$Captured.PSObject.Properties['jumbo_tun_supported']
    $jumboChanged=$false;$selectedJumbo=$null
    if($null -ne $jumboCapture){$selectedJumbo=$jumboCapture.Value}
    if($PSBoundParameters.ContainsKey('JumboTUN')){
        if($JumboTUN -isnot [bool]){throw 'Jumbo must be an explicit Boolean.'}
        $jumboChanged=$null -eq $jumboCapture -or $JumboTUN -ne $jumboCapture.Value
        if($jumboChanged -and ($null -eq $jumboSupport -or -not $jumboSupport.Value)){throw 'This captured native runtime cannot change Jumbo.'}
        $selectedJumbo=$JumboTUN
    }
    if($selectedJumbo -eq $true -and $MTUPolicy -ceq 'manual' -and $manualValue -ne 9000){
        throw 'Jumbo uses a 9000-byte virtual interface. Choose Fixed 9000 or disable Jumbo; no MTU choice was changed.'
    }
    $body=@{profile_id=$DisplayedProfileID;profile_token=[string]$Captured.profile_token;home_lan_access=$HomeLANAccess;kill_switch_policy=$KillSwitchPolicy;ipv6_mode=$IPv6Mode;mtu_policy=$MTUPolicy;manual_mtu=$manualValue}
    if($jumboChanged){$body.jumbo_tun=$JumboTUN}
    $hasCover=$PSBoundParameters.ContainsKey('DAITAEnabled');$hasRate=$PSBoundParameters.ContainsKey('DAITARateKbps')
    if($hasCover-ne$hasRate){throw 'Outgoing Tor cover On/Off and budget must be edited together.'}
    if($hasCover){
        $capturedCover=$Captured.PSObject.Properties['daita_enabled'];$capturedRate=$Captured.PSObject.Properties['daita_rate_kbps'];$coverSupport=$Captured.PSObject.Properties['tor_cover_supported']
        if($null-eq$capturedCover-or$null-eq$capturedRate-or$null-eq$coverSupport-or$DAITAEnabled-isnot[bool]-or
           ($DAITARateKbps-isnot[string]-and$DAITARateKbps-isnot[int]-and$DAITARateKbps-isnot[long])-or[string]$DAITARateKbps-cnotmatch'\A[0-9]{1,3}\z'){
            throw 'Outgoing Tor cover requires an explicit On/Off choice and a whole budget: 0 or 32–192 kbit/s.'
        }
        $coverRate=[int]$DAITARateKbps
        if($coverRate-ne0-and($coverRate-lt32-or$coverRate-gt192)){throw 'Outgoing Tor cover budget must be 0 or 32–192 kbit/s.'}
        $coverChanged=$DAITAEnabled-ne$capturedCover.Value-or$coverRate-ne$capturedRate.Value
        if($coverChanged-and-not$coverSupport.Value){throw 'This captured path cannot change outgoing Tor cover traffic. Use a saved Server path through a private Router entry.'}
        if($coverChanged){$body.daita_enabled=$DAITAEnabled;$body.daita_rate_kbps=$coverRate}
    }
    $hasMode=$PSBoundParameters.ContainsKey('StartupMode');$hasAutomatic=$PSBoundParameters.ContainsKey('AutoConnect')
    if($hasMode -ne $hasAutomatic){throw 'Startup mode and auto-connect must be edited together.'}
    if($hasMode){
        if($StartupMode -isnot [string] -or $StartupMode -cnotin @('manual','auto','smart-auto','last') -or $AutoConnect -isnot [bool] -or ($StartupMode -ceq 'manual' -and $AutoConnect)){
            throw 'Choose a valid startup mode; Manual must stay disconnected.'
        }
        if($Captured.startup_mode -isnot [string] -or $Captured.startup_mode -cnotin @('manual','auto','smart-auto','last') -or $Captured.auto_connect -isnot [bool]){
            throw 'The captured startup policy is invalid. Reopen Settings.'
        }
        $displayedStartup=if($Captured.startup_mode -ceq 'smart-auto'){'auto'}else{$Captured.startup_mode}
        $modeChanged=$StartupMode -cne $displayedStartup
        if($modeChanged -or $AutoConnect -ne $Captured.auto_connect){
            $body.startup_mode=if($modeChanged){$StartupMode}else{$Captured.startup_mode}
            $body.auto_connect=$AutoConnect
        }
    }
    return $body
}

function global:Save-RouterVPNProfileDevice {
    param([string]$BaseUrl,$Captured,[string]$DisplayedProfileID,$HomeLANAccess,[string]$KillSwitchPolicy,[string]$IPv6Mode,[string]$MTUPolicy,$ManualMTU,$StartupMode,$AutoConnect,$JumboTUN,$DAITAEnabled,$DAITARateKbps)
    $arguments=@{};foreach($key in $PSBoundParameters.Keys){if($key -cne 'BaseUrl'){$arguments[$key]=$PSBoundParameters[$key]}}
    $body=New-RouterVPNProfileDevicePayload @arguments
    if(Test-RouterVPNConnectionProfileBusy -BaseUrl $BaseUrl){throw 'Disconnect Router VPN before saving device settings.'}
    $saved=Invoke-RouterVPNControllerRequest -Uri ($BaseUrl.TrimEnd('/') + '/api/profile/device') -Method Post -ContentType 'application/json' -Body ($body | ConvertTo-Json -Compress) -TimeoutSec 8
    Assert-RouterVPNProfileDeviceCapture -Captured $saved -DisplayedProfileID $DisplayedProfileID
    if(-not $saved.device_policy_supported){throw 'The controller did not confirm native device support.'}
    foreach($key in @('home_lan_access')){
        if($saved.$key -isnot [bool] -or $saved.$key -ne $body[$key]){throw 'The controller did not confirm the selected device settings.'}
    }
    foreach($key in @('kill_switch_policy','ipv6_mode','mtu_policy')){
        if($saved.$key -isnot [string] -or $saved.$key -cne $body[$key]){throw 'The controller did not confirm the selected device settings.'}
    }
    if(($saved.manual_mtu -isnot [int] -and $saved.manual_mtu -isnot [long]) -or $saved.manual_mtu -ne $body.manual_mtu){throw 'The controller did not confirm the requested MTU.'}
    $expectedStartup=if($body.ContainsKey('startup_mode')){$body.startup_mode}else{$Captured.startup_mode}
    $expectedAutomatic=if($body.ContainsKey('auto_connect')){$body.auto_connect}else{$Captured.auto_connect}
    if($saved.startup_mode -isnot [string] -or $saved.startup_mode -cne $expectedStartup -or $saved.auto_connect -isnot [bool] -or $saved.auto_connect -ne $expectedAutomatic){throw 'The controller did not confirm the captured startup settings.'}
    $originalJumbo=$Captured.PSObject.Properties['jumbo_tun'];$savedJumbo=$saved.PSObject.Properties['jumbo_tun']
    if($null -ne $originalJumbo){
        $expectedJumbo=if($body.ContainsKey('jumbo_tun')){$body.jumbo_tun}else{$originalJumbo.Value}
        if($null -eq $savedJumbo -or $savedJumbo.Value -ne $expectedJumbo){throw 'The controller did not confirm the captured Jumbo setting.'}
    }
    if($body.ContainsKey('jumbo_tun') -and -not $saved.jumbo_tun_supported){throw 'The controller did not confirm native Jumbo support.'}
    if($null-ne$Captured.PSObject.Properties['daita_enabled']){
        $expectedCover=if($body.ContainsKey('daita_enabled')){$body.daita_enabled}else{$Captured.daita_enabled}
        $expectedRate=if($body.ContainsKey('daita_rate_kbps')){$body.daita_rate_kbps}else{$Captured.daita_rate_kbps}
        if($null-eq$saved.PSObject.Properties['daita_enabled']-or$saved.daita_enabled-ne$expectedCover-or$saved.daita_rate_kbps-ne$expectedRate-or
           ($body.ContainsKey('daita_enabled')-and-not$saved.tor_cover_supported)){
            throw 'The controller did not confirm the captured outgoing Tor cover choice and budget.'
        }
    }
    return $saved
}

function global:Set-RouterVPNProfileProtection {
    param([string]$BaseUrl,[string]$DisplayedProfileID,[bool]$Enabled)
    if([string]::IsNullOrWhiteSpace($DisplayedProfileID)){throw 'Select a node before changing protection.'}
    $captured=Invoke-RouterVPNControllerRequest -Uri ($BaseUrl.TrimEnd('/') + '/api/profile/protection') -Method Get -TimeoutSec 5
    if([string]$captured.profile_id -cne $DisplayedProfileID -or [string]::IsNullOrWhiteSpace([string]$captured.profile_token)){throw 'The selected node changed. Refresh before changing protection.'}
    $body=@{profile_id=$DisplayedProfileID;profile_token=[string]$captured.profile_token;kill_switch_policy=$(if($Enabled){'on-connect'}else{'off'})}
    Invoke-RouterVPNControllerRequest -Uri ($BaseUrl.TrimEnd('/') + '/api/profile/protection') -Method Post -ContentType 'application/json' -Body ($body | ConvertTo-Json -Compress) -TimeoutSec 8
}

function global:Get-RouterVPNStartLayerCapabilities {
    param([string]$BaseUrl)
    Invoke-RouterVPNControllerRequest -Uri ($BaseUrl.TrimEnd('/') + '/api/start-layer/capabilities') -Method Get -TimeoutSec 5
}

function global:Get-RouterVPNConnectionProfiles {
    param([string]$BaseUrl)
    $result=Invoke-RouterVPNControllerRequest -Uri ($BaseUrl.TrimEnd('/') + '/api/connection-profiles') -Method Get -TimeoutSec 5
    return @($result.profiles)
}

function global:Test-RouterVPNConnectionProfileBusy {
    param([string]$BaseUrl)
    try {
        $state=Invoke-RouterVPNControllerRequest -Uri ($BaseUrl.TrimEnd('/') + '/api/status') -Method Get -TimeoutSec 4
        $phase=([string]$state.phase).Trim().ToLowerInvariant()
        return [bool]$state.connected -or $phase -match 'connecting|starting|checking|trying|proving|disconnecting|stopping|switching|reconnecting'
    } catch {
        return $true
    }
}

function global:Get-RouterVPNCurrentModeSnapshot {
    $raw=Read-RouterVPNUIState -LegacyDirectory $PSScriptRoot -Name 'windows-selected-mode-v1.txt'
    $mode='smart-auto';if(-not[string]::IsNullOrWhiteSpace($raw)){$mode=$raw.Trim()}
    $layers=@()
    if($mode.StartsWith('custom:')){
        $name=$mode.Substring(7)
        $raw=Read-RouterVPNUIState -LegacyDirectory $PSScriptRoot -Name 'windows-custom-presets-v1.json'
        try{
            # Windows PowerShell 5.1 emits a JSON array as one pipeline item.
            # Materialize it before enumerating individual saved presets.
            $presets=ConvertFrom-Json -InputObject $raw
            foreach($preset in @($presets)){if([string]$preset.name -eq $name){$layers=@($preset.layers);break}}
        }catch{}
    }
    [pscustomobject]@{mode=$mode;custom_layers=@($layers)}
}

function global:Set-RouterVPNLoadedModeSnapshot {
    param($Loaded)
    $mode=[string]$Loaded.mode;if([string]::IsNullOrWhiteSpace($mode)){$mode='smart-auto'}
    Write-RouterVPNUIState -LegacyDirectory $PSScriptRoot -Name 'windows-selected-mode-v1.txt' -Text $mode
    if($mode.StartsWith('custom:')){
        $name=$mode.Substring(7);$layers=@($Loaded.custom_layers)
        if($name -and $layers.Count -gt 0){
            $raw=Read-RouterVPNUIState -LegacyDirectory $PSScriptRoot -Name 'windows-custom-presets-v1.json'
            $values=@();if($raw){try{$parsed=ConvertFrom-Json -InputObject $raw;$values=@($parsed)}catch{$values=@()}}
            $values=@($values|Where-Object{[string]$_.name -ne $name});$values+=,[pscustomobject]@{name=$name;layers=@($layers)}
            Write-RouterVPNUIState -LegacyDirectory $PSScriptRoot -Name 'windows-custom-presets-v1.json' -Text (ConvertTo-Json -InputObject @($values) -Depth 8)
        }
    }
}

function global:Get-RouterVPNVisibleConnectionSnapshot {
    param([System.Windows.Window]$Owner,[hashtable]$Provided)
    if($null -ne $Provided){return $Provided}
    $result=@{multihop_enabled=$false;multihop_entry_id='';multihop_exit_id='';multihop_exit_mode='';multihop_execution='';multihop_entry_mode=''}
    if($null -eq $Owner){return $result}
    $entryChoiceValid=$false
    try{
        $toggle=$Owner.FindName('UnifiedMultihop');$entry=$Owner.FindName('UnifiedEntryCombo');$entryMode=$Owner.FindName('UnifiedEntryMode');$exit=$Owner.FindName('UnifiedExitCombo');$exitMode=$Owner.FindName('UnifiedExitMode');$execution=$Owner.FindName('UnifiedExecution')
        if($null -ne $toggle){$result.multihop_enabled=[bool]$toggle.IsChecked}
        if($result.multihop_enabled){
            if($null -ne $entry){$result.multihop_entry_id=[string]$entry.SelectedValue}
            if($null-ne$entryMode-and$null-ne$entryMode.SelectedItem){$result.multihop_entry_mode=[string]$entryMode.SelectedItem.Tag;$entryChoiceValid=$true}
            if($null -ne $exit){$result.multihop_exit_id=[string]$exit.SelectedValue}
            if($null -ne $exitMode -and $null -ne $exitMode.SelectedItem){$result.multihop_exit_mode=[string]$exitMode.SelectedItem.Tag}
            $result.multihop_execution='local';if($null-ne$execution -and $null-ne$execution.SelectedItem){$result.multihop_execution=[string]$execution.SelectedItem.Tag}
        }
    }catch{}
    if($result.multihop_enabled-and(-not$entryChoiceValid-or([string]$result.multihop_entry_mode)-cnotin@('','wg','awg2-fast','awg2-strong','wg-pq','awg2-pq','shadowsocks','hysteria2','reality-vision','reality-pq-vision','reality-xhttp','naive-h2','naive-h3','ss-v2ray','split','max','max-tls-wg','max-tls-awg','max-quic-wg','max-quic-awg'))){throw 'Select a supported entry mode before saving the connection profile.'}
    if($result.multihop_enabled -and ([string]$result.multihop_exit_mode)-cnotin@('shadowsocks','hysteria2','reality-vision','reality-pq-vision','reality-xhttp','naive-h2','naive-h3','wg','awg2-fast','awg2-strong','ss-v2ray','split','max','wg-pq','awg2-pq','max-tls-wg','max-tls-awg','max-quic-wg','max-quic-awg')){throw 'Select a supported exit transport before saving the connection profile.'}
    return $result
}

function global:Apply-RouterVPNLoadedConnectionSnapshot {
    param([System.Windows.Window]$Owner,$Loaded)
    if($null -eq $Owner){return}
    try{
        $toggle=$Owner.FindName('UnifiedMultihop');$entry=$Owner.FindName('UnifiedEntryCombo');$entryMode=$Owner.FindName('UnifiedEntryMode');$exit=$Owner.FindName('UnifiedExitCombo');$exitMode=$Owner.FindName('UnifiedExitMode');$execution=$Owner.FindName('UnifiedExecution')
        if($null-ne$execution){$wanted=[string]$Loaded.multihop_execution;if($wanted-notin@('local','server','auto')){$wanted='local'};foreach($item in $execution.Items){if([string]$item.Tag-eq$wanted){$execution.SelectedItem=$item;break}}}
        $enabled=[bool]$Loaded.multihop_enabled
        if($null -ne $toggle){$toggle.IsChecked=$enabled}
        if($null -ne $entry -and -not [string]::IsNullOrWhiteSpace([string]$Loaded.multihop_entry_id)){$entry.SelectedValue=[string]$Loaded.multihop_entry_id}
        if($null -ne $exit -and -not [string]::IsNullOrWhiteSpace([string]$Loaded.multihop_exit_id)){$exit.SelectedValue=[string]$Loaded.multihop_exit_id}
        if($null-ne$entryMode){
            $wantEntry=''
            if($Loaded-is[System.Collections.IDictionary]){if($Loaded.Contains('multihop_entry_mode')){$wantEntry=[string]$Loaded['multihop_entry_mode']}}
            elseif($null-ne$Loaded.PSObject.Properties['multihop_entry_mode']){$wantEntry=[string]$Loaded.multihop_entry_mode}
            $entryMode.SelectedIndex=-1
            for($i=0;$i-lt$entryMode.Items.Count;$i++){if([string]$entryMode.Items[$i].Tag-ceq$wantEntry){$entryMode.SelectedIndex=$i;break}}
        }
        if($null -ne $exitMode -and $exitMode.Items.Count -gt 0){
            $want=[string]$Loaded.multihop_exit_mode;$exitMode.SelectedIndex=-1
            for($i=0;$i-lt$exitMode.Items.Count;$i++){if([string]$exitMode.Items[$i].Tag -eq $want){$exitMode.SelectedIndex=$i;break}}
        }
    }catch{}
}

function global:Show-RouterVPNProfileSettingsDialog {
    param([string]$BaseUrl,[System.Windows.Window]$Owner,[hashtable]$ConnectionSnapshot,[scriptblock]$OnConnectionProfileLoaded,[string]$DisplayedProfileID,[string]$DisplayedNodeKind)
    if([string]::IsNullOrWhiteSpace($DisplayedProfileID) -or $DisplayedNodeKind -cnotin @('router','external')){throw 'Select a node before opening Settings.'}
    $current=$null;$settingsError='';$startCaps=$null;$startCapsError='';$externalDevice=$null;$externalStartup=$null
    if($DisplayedNodeKind -ceq 'external'){
        $externalDevice=Get-RouterVPNProfileDevice -BaseUrl $BaseUrl -DisplayedProfileID $DisplayedProfileID
        if(-not $externalDevice.device_policy_supported){
            $captured=Get-RouterVPNProfileStartup -BaseUrl $BaseUrl
            if([string]$captured.node_kind -eq 'external' -and [string]$captured.profile_id -ceq $DisplayedProfileID -and [string]$captured.profile_token -cmatch '\A[0-9a-f]{64}\z'){$externalStartup=$captured}
            else{throw 'The selected node changed while capturing its startup settings.'}
        }
    }else{
        try{$current=Get-RouterVPNProfileSettings -BaseUrl $BaseUrl}catch{$settingsError=$_.Exception.Message}
        try{$startCaps=Get-RouterVPNStartLayerCapabilities -BaseUrl $BaseUrl}catch{$startCapsError=$_.Exception.Message}
    }
    [xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="Settings" Width="720" Height="850" MinWidth="560" MinHeight="620" WindowStartupLocation="CenterOwner" ResizeMode="CanResize" Background="#0B1020" Foreground="#F5F7FF">
<ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel Margin="20">
<TextBlock Text="Selected Router VPN node" FontSize="22" FontWeight="Bold"/><TextBlock Name="SettingsNote" Text="Disconnect before saving. SMART AUTO, IPv6 On and Auto MTU are the unified defaults. These are persistent node preferences for the next supported connection; a saved value is not runtime proof." TextWrapping="Wrap" Foreground="#A8B6D5" Margin="0,4,0,14"/>
<StackPanel Name="NodeSettings">
<CheckBox Name="LAN" Content="Allow home LAN access" Margin="0,5"/>
<TextBlock Text="Kill switch policy"/><ComboBox Name="Kill" Margin="0,3,0,10"><ComboBoxItem Content="Off" Tag="off"/><ComboBoxItem Content="On connect" Tag="on-connect"/><ComboBoxItem Content="Always / strict" Tag="always"/></ComboBox>
<TextBlock Text="IPv6 policy"/><ComboBox Name="IPv6" Margin="0,3,0,10"><ComboBoxItem Content="On — default" Tag="on"/><ComboBoxItem Content="Auto" Tag="auto"/><ComboBoxItem Content="Off" Tag="off"/></ComboBox>
<StackPanel Name="RouterTransportSettings">
<TextBlock Text="WG / AWG base preference"/><ComboBox Name="Base" Margin="0,3,0,5"><ComboBoxItem Content="Auto" Tag="auto"/><ComboBoxItem Content="WireGuard" Tag="wg"/><ComboBoxItem Content="AmneziaWG" Tag="awg"/></ComboBox><CheckBox Name="Fallback" Content="Allow compatible WG/AWG base fallback" Margin="0,0,0,10"/>
<TextBlock Text="AUTO / SMART AUTO filters" FontWeight="SemiBold" Margin="0,8,0,2"/><CheckBox Name="RequireEncrypted" Content="Require encrypted AUTO candidates" Margin="0,3"/><CheckBox Name="RequireObfuscation" Content="Require obfuscation for AUTO candidates" Margin="0,3"/><TextBlock Text="Both are Off by default. Enabled filters remove non-matching candidates before AUTO tries them; SMART cannot simplify below the selected requirements." TextWrapping="Wrap" FontSize="11" Foreground="#A8B6D5" Margin="0,0,0,10"/>
<TextBlock Text="Start encryption / obfuscation layer" FontWeight="SemiBold"/><ComboBox Name="StartLayer" Margin="0,3,0,4"><ComboBoxItem Content="Off — default" Tag="off"/><ComboBoxItem Content="AES-256-GCM — authenticated" Tag="aes-256-gcm"/><ComboBoxItem Content="AES-256-GCM + XOR whitening" Tag="aes-256-gcm+xor-whitening"/></ComboBox><TextBlock Name="StartLayerTruth" Text="AES uses vetted Shadowsocks 2022 AES-256-GCM. XOR is reversible whitening of already-authenticated ciphertext only; it is never counted as encryption. Unsupported runtime graphs fail closed." TextWrapping="Wrap" FontSize="11" Foreground="#A8B6D5" Margin="0,0,0,10"/>
</StackPanel>
<TextBlock Text="MTU policy"/><ComboBox Name="MTUPolicy" Margin="0,3,0,5"><ComboBoxItem Content="Auto — default" Tag="auto"/><ComboBoxItem Content="Fixed / manual" Tag="manual"/><ComboBoxItem Content="Runtime default" Tag="default"/></ComboBox><TextBox Name="ManualMTU" Margin="0,0,0,5" ToolTip="Fixed MTU 576–9000; ignored for Auto/Runtime default"/><TextBlock Name="Effective" TextWrapping="Wrap" FontSize="11" Foreground="#A8B6D5" Margin="0,0,0,10"/>
<CheckBox Name="Jumbo" Content="Jumbo virtual interface (9000)" Margin="0,5"/>
<StackPanel Name="TorCoverSettings" Visibility="Collapsed">
<CheckBox Name="TorCover" Content="Outgoing Tor cover traffic" Margin="0,5"/>
<TextBlock Text="Cover budget (kbit/s): 32–192; 0 keeps the default 192"/><TextBox Name="TorCoverRate" Text="0" Margin="0,3,0,5"/>
<TextBlock Name="TorCoverNote" TextWrapping="Wrap" Foreground="#A8B6D5" FontSize="11" Margin="0,0,0,10"/>
</StackPanel>
<StackPanel Name="RouterFeatureSettings">
<CheckBox Name="DAITA" Content="DAITA-like traffic padding (bounded; supported modes only)" Margin="0,5"/><CheckBox Name="Socks" Content="Enable private in-tunnel SOCKS5 utility" Margin="0,5"/>
<StackPanel Orientation="Horizontal" Margin="0,4,0,10"><Button Name="Forwarding" Content="Port forwarding / Protected DMZ…" Padding="10,6"/></StackPanel>
<TextBlock Text="Retest is path/config specific. A fixed MTU stays fixed until changed. Incoming forwarding is owned by the authenticated private home node and is available only to routable tunnel modes; proxy-only paths never claim arbitrary DNAT." TextWrapping="Wrap" FontSize="11" Foreground="#A8B6D5" Margin="0,0,0,12"/>
</StackPanel>
</StackPanel>
<StackPanel Name="StartupSettings">
<TextBlock Text="Startup / default mode" Margin="0,10,0,0"/><ComboBox Name="Startup" Margin="0,3,0,5"><ComboBoxItem Content="SMART AUTO — recommended" Tag="smart-auto"/><ComboBoxItem Content="AUTO" Tag="auto"/><ComboBoxItem Content="Last proven mode" Tag="last"/><ComboBoxItem Content="Manual / stay disconnected" Tag="manual"/></ComboBox><CheckBox Name="AutoConnect" Content="Auto-connect when the native app starts" Margin="0,0,0,10"/>
<TextBlock Name="StartupNote" TextWrapping="Wrap" FontSize="11" Foreground="#A8B6D5" Margin="0,0,0,10"/>
</StackPanel>
<Button Name="MtuRetest" Content="MTU progress / Retest / Cancel" HorizontalAlignment="Left" Padding="10,6" Margin="0,4,0,10"/>
<Separator Margin="0,6,0,12"/>
<TextBlock Text="Connection profiles" FontSize="17" FontWeight="SemiBold"/><TextBlock Text="Save or restore the selected node plus current Mode/CUSTOM layers, DNS, kill switch, IPv6, WG/AWG base/fallback, authenticated Start Layer, AUTO encryption/obfuscation requirements, MTU, and exact multihop entry → exit → exit-transport choice. Node keys, API tokens and external credentials are referenced by node ID and are never copied into a connection profile." TextWrapping="Wrap" Foreground="#A8B6D5" FontSize="11" Margin="0,3,0,8"/>
<TextBox Name="ConnectionProfileName" Margin="0,0,0,6" ToolTip="Name for Add or Update"/><ComboBox Name="ConnectionProfiles" DisplayMemberPath="display" SelectedValuePath="id" Margin="0,0,0,6"/>
<WrapPanel Margin="0,0,0,5"><Button Name="ProfileAdd" Content="Add profile" Padding="9,5" Margin="0,0,6,6"/><Button Name="ProfileLoad" Content="Load" Padding="9,5" Margin="0,0,6,6"/><Button Name="ProfileUpdate" Content="Update" Padding="9,5" Margin="0,0,6,6"/><Button Name="ProfileDelete" Content="Delete" Padding="9,5" Margin="0,0,6,6"/><Button Name="ProfileRefresh" Content="Refresh" Padding="9,5" Margin="0,0,6,6"/></WrapPanel>
<TextBlock Name="ProfileStatus" TextWrapping="Wrap" FontSize="11" Foreground="#A8B6D5" Margin="0,0,0,12"/>
<StackPanel Orientation="Horizontal" HorizontalAlignment="Right"><Button Name="Cancel" Content="Close" MinWidth="90" Margin="4"/><Button Name="Save" Content="Save node settings" MinWidth="150" Margin="4" IsDefault="True"/></StackPanel>
</StackPanel></ScrollViewer></Window>
'@
    $reader=New-Object System.Xml.XmlNodeReader $xaml; $dialog=[Windows.Markup.XamlReader]::Load($reader); if($Owner){$dialog.Owner=$Owner}
    function SetTag($combo,[string]$tag){for($i=0;$i-lt$combo.Items.Count;$i++){if([string]$combo.Items[$i].Tag-eq$tag){$combo.SelectedIndex=$i;return}};$combo.SelectedIndex=0}
    $startupSettings=$dialog.FindName('StartupSettings');$startupNote=$dialog.FindName('StartupNote')
    $nodeSettings=$dialog.FindName('NodeSettings');$settingsNote=$dialog.FindName('SettingsNote');$settingsSave=$dialog.FindName('Save');$lan=$dialog.FindName('LAN');$kill=$dialog.FindName('Kill');$ipv6=$dialog.FindName('IPv6');$base=$dialog.FindName('Base');$fallback=$dialog.FindName('Fallback');$requireEncrypted=$dialog.FindName('RequireEncrypted');$requireObfuscation=$dialog.FindName('RequireObfuscation');$startLayer=$dialog.FindName('StartLayer');$startLayerTruth=$dialog.FindName('StartLayerTruth');$mtuPolicy=$dialog.FindName('MTUPolicy');$manual=$dialog.FindName('ManualMTU');$effective=$dialog.FindName('Effective');$daita=$dialog.FindName('DAITA');$jumbo=$dialog.FindName('Jumbo');$socks=$dialog.FindName('Socks');$startup=$dialog.FindName('Startup');$autoConnect=$dialog.FindName('AutoConnect');$profileName=$dialog.FindName('ConnectionProfileName');$profileCombo=$dialog.FindName('ConnectionProfiles');$profileStatus=$dialog.FindName('ProfileStatus');$profileAdd=$dialog.FindName('ProfileAdd');$profileLoad=$dialog.FindName('ProfileLoad');$profileUpdate=$dialog.FindName('ProfileUpdate');$profileDelete=$dialog.FindName('ProfileDelete')
    if($null -ne $current){
        $lan.IsChecked=[bool]$current.home_lan_access;SetTag $kill ([string]$current.kill_switch_policy);SetTag $ipv6 $(if([string]::IsNullOrWhiteSpace([string]$current.ipv6_mode)){'on'}else{[string]$current.ipv6_mode});SetTag $base ([string]$current.base_tunnel);$fallback.IsChecked=[bool]$current.base_fallback;$requireEncrypted.IsChecked=[bool]$current.auto_require_encrypted;$requireObfuscation.IsChecked=[bool]$current.auto_require_obfuscation;SetTag $startLayer $(if([string]::IsNullOrWhiteSpace([string]$current.start_layer)){'off'}else{[string]$current.start_layer});SetTag $mtuPolicy $(if([string]::IsNullOrWhiteSpace([string]$current.mtu_policy)){'auto'}else{[string]$current.mtu_policy});$manual.Text=if([int]$current.manual_mtu-gt0){[string]$current.manual_mtu}else{''};$daita.IsChecked=[bool]$current.daita_enabled;$jumbo.IsChecked=[bool]$current.jumbo_tun;$socks.IsChecked=[bool]$current.socks_enabled;SetTag $startup $(if([string]::IsNullOrWhiteSpace([string]$current.startup_mode)){'smart-auto'}else{[string]$current.startup_mode});$autoConnect.IsChecked=[bool]$current.auto_connect;$effective.Text="Current effective MTU: $(if([int]$current.effective_mtu-gt0){$current.effective_mtu}else{'not measured yet'}) • $(if([string]::IsNullOrWhiteSpace([string]$current.effective_mtu_source)){'Auto will use a valid path/config-specific value'}else{$current.effective_mtu_source})"
        if($null -eq $startCaps){$startLayer.IsEnabled=$false;$startLayerTruth.Text='Start Layer capability check failed closed: '+$startCapsError}
        elseif(-not[bool]$startCaps.selected_node_supported){$startLayer.IsEnabled=$false;$startLayerTruth.Text=[string]$startCaps.selected_node_reason}
        else{$startLayer.IsEnabled=$true;$startLayer.ToolTip='Proved raw-mode composition: '+(@($startCaps.supported_raw_modes)-join ', ')}
        if(Test-RouterVPNConnectionProfileBusy -BaseUrl $BaseUrl){$nodeSettings.IsEnabled=$false;$settingsSave.IsEnabled=$false;$settingsNote.Text='Disconnect Router VPN or let the active transition finish before editing persistent node settings. Saved values are preferences, not runtime proof.'}
    }else{
        $nodeSettings.IsEnabled=$false;$settingsSave.IsEnabled=$false;$settingsNote.Text='Selected node does not expose Router VPN node settings here (for example, a Custom/external node). Connection-profile Add / Load / Update / Delete remains available.';$effective.Text=$settingsError
    }
    if($null -ne $externalDevice){
        $dialog.FindName('RouterTransportSettings').Visibility='Collapsed';$dialog.FindName('RouterFeatureSettings').Visibility='Collapsed'
        $lan.IsChecked=[bool]$externalDevice.home_lan_access;SetTag $kill ([string]$externalDevice.kill_switch_policy);SetTag $ipv6 ([string]$externalDevice.ipv6_mode);SetTag $mtuPolicy ([string]$externalDevice.mtu_policy)
        $manual.Text=if([int]$externalDevice.manual_mtu-gt0){[string]$externalDevice.manual_mtu}else{''}
        $manual.ToolTip='Fixed interface MTU 1280 to 9000; the native transport validates its actual limit.'
        $jumboCapture=$externalDevice.PSObject.Properties['jumbo_tun'];$jumboSupport=$externalDevice.PSObject.Properties['jumbo_tun_supported']
        $jumbo.IsChecked=$null -ne $jumboCapture -and [bool]$jumboCapture.Value
        $jumbo.IsEnabled=$null -ne $jumboSupport -and [bool]$jumboSupport.Value -and [bool]$externalDevice.device_policy_supported
        $effective.Text="Last recorded interface MTU: $(if([int]$externalDevice.effective_mtu-gt0){$externalDevice.effective_mtu}else{'not recorded'}) - $($externalDevice.mtu_source). This is historical interface readback."
        $nodeSettings.IsEnabled=[bool]$externalDevice.device_policy_supported
        $settingsSave.IsEnabled=[bool]$externalDevice.device_policy_supported -or $null -ne $externalStartup
        $settingsNote.Text=if($externalDevice.device_policy_supported){[string]$externalDevice.note}else{[string]$externalDevice.device_policy_reason}
        if([string]$externalDevice.protocol-cin@('tor','tor-bridge')-and$null-ne$externalDevice.PSObject.Properties['daita_enabled']){
            $dialog.FindName('TorCoverSettings').Visibility='Visible'
            $dialog.FindName('TorCover').IsChecked=[bool]$externalDevice.daita_enabled
            $dialog.FindName('TorCoverRate').Text=[string]$externalDevice.daita_rate_kbps
            $dialog.FindName('TorCover').IsEnabled=[bool]$externalDevice.tor_cover_supported-and[bool]$externalDevice.device_policy_supported
            $dialog.FindName('TorCoverRate').IsEnabled=$dialog.FindName('TorCover').IsEnabled
            $dialog.FindName('TorCoverNote').Text=[string]$externalDevice.tor_cover_note
        }
    }
    $startupCapture=if($null -ne $externalStartup){$externalStartup}else{$externalDevice}
    if($null -ne $startupCapture){
        $startup.Items.Clear()
        foreach($choice in @(@('Saved connection','auto'),@('Last proven connection','last'),@('Manual / stay disconnected','manual'))){$item=New-Object System.Windows.Controls.ComboBoxItem;$item.Content=$choice[0];$item.Tag=$choice[1];[void]$startup.Items.Add($item)}
        $startupMode=[string]$startupCapture.startup_mode;if($startupMode -eq 'smart-auto'){$startupMode='auto'};SetTag $startup $startupMode
        $autoConnect.IsChecked=[bool]$startupCapture.auto_connect
        $startupNote.Text='Saved connection uses the selected protocol and hop settings. Last keeps its previously proved Local/Server choice when it is still valid.'
    }
    if(($null -eq $current -and $null -eq $externalDevice -and $null -eq $externalStartup) -or (Test-RouterVPNConnectionProfileBusy -BaseUrl $BaseUrl)){$nodeSettings.IsEnabled=$false;$startupSettings.IsEnabled=$false;$settingsSave.IsEnabled=$false}
    $syncStartupControls={if([string]$startup.SelectedItem.Tag -ceq 'manual'){$autoConnect.IsChecked=$false;$autoConnect.IsEnabled=$false}else{$autoConnect.IsEnabled=$startupSettings.IsEnabled}}
    $startup.Add_SelectionChanged($syncStartupControls);& $syncStartupControls
    $syncManualControls={$manual.IsEnabled=$nodeSettings.IsEnabled -and [string]$mtuPolicy.SelectedItem.Tag -ceq 'manual'}
    $mtuPolicy.Add_SelectionChanged($syncManualControls);& $syncManualControls
    $syncProfileMutationState={
        $busy=Test-RouterVPNConnectionProfileBusy -BaseUrl $BaseUrl
        $profileName.IsEnabled=-not$busy;$profileCombo.IsEnabled=-not$busy;$profileAdd.IsEnabled=-not$busy;$profileLoad.IsEnabled=-not$busy;$profileUpdate.IsEnabled=-not$busy;$profileDelete.IsEnabled=-not$busy
        if($busy){$profileStatus.Text='Disconnect Router VPN or let the active transition finish before Add / Load / Update / Delete. Refresh remains available.'}
        return $busy
    }
    $refreshProfiles={
        try{$items=New-Object System.Collections.ArrayList;foreach($p in @(Get-RouterVPNConnectionProfiles -BaseUrl $BaseUrl)){$prefs=$p.preferences;$enc=$false;$obf=$false;if($null-ne$prefs){$enc=[bool]$prefs.auto_require_encrypted;$obf=[bool]$prefs.auto_require_obfuscation};$req=if($null-eq$prefs){'AUTO n/a'}elseif($enc-and$obf){'AUTO Encrypted+Obfuscation'}elseif($enc){'AUTO Encrypted'}elseif($obf){'AUTO Obfuscation'}else{'AUTO Off'};$label="$($p.name) • $($p.mode) • $($p.node_id) • $req";[void]$items.Add([pscustomobject]@{id=[string]$p.id;display=$label;name=[string]$p.name;mode=[string]$p.mode;node_id=[string]$p.node_id})};$profileCombo.ItemsSource=@($items);if($items.Count -gt 0){$profileCombo.SelectedIndex=0};$profileStatus.Text="$($items.Count) saved connection profile(s).";[void](& $syncProfileMutationState)}catch{$profileStatus.Text='Profile refresh failed: '+$_.Exception.Message;[void](& $syncProfileMutationState)}
    }
    $makeSetupBody={
        param([string]$Name,[string]$ID)
        $snap=Get-RouterVPNCurrentModeSnapshot
        $visible=Get-RouterVPNVisibleConnectionSnapshot -Owner $Owner -Provided $ConnectionSnapshot
        $body=@{name=$Name;mode=[string]$snap.mode;custom_layers=@($snap.custom_layers);multihop_enabled=[bool]$visible.multihop_enabled;multihop_entry_id=[string]$visible.multihop_entry_id;multihop_exit_id=[string]$visible.multihop_exit_id;multihop_exit_mode=[string]$visible.multihop_exit_mode;multihop_execution=[string]$visible.multihop_execution;multihop_entry_mode=[string]$visible.multihop_entry_mode}
        if($ID){$body.id=$ID}
        return $body
    }
    $profileCombo.Add_SelectionChanged({if($profileCombo.SelectedItem){$profileName.Text=[string]$profileCombo.SelectedItem.name}})
    $dialog.FindName('ProfileRefresh').Add_Click({& $refreshProfiles})
    $profileAdd.Add_Click({try{if(& $syncProfileMutationState){throw 'Disconnect Router VPN before adding a connection profile.'};$name=$profileName.Text.Trim();if(-not$name){throw 'Enter a profile name.'};$body=& $makeSetupBody $name '';$r=Invoke-RouterVPNControllerRequest -Uri ($BaseUrl.TrimEnd('/') + '/api/connection-profile/setup/save') -Method Post -ContentType 'application/json' -Body ($body|ConvertTo-Json -Depth 8 -Compress) -TimeoutSec 10;$profileStatus.Text="Added $($r.profile.name) • $($r.profile.mode) • exact hop setup saved";& $refreshProfiles}catch{$profileStatus.Text='Add failed: '+$_.Exception.Message}})
    $profileUpdate.Add_Click({try{if(& $syncProfileMutationState){throw 'Disconnect Router VPN before updating a connection profile.'};if(-not$profileCombo.SelectedValue){throw 'Select a saved profile.'};$name=$profileName.Text.Trim();if(-not$name){throw 'Enter a profile name.'};$body=& $makeSetupBody $name ([string]$profileCombo.SelectedValue);$r=Invoke-RouterVPNControllerRequest -Uri ($BaseUrl.TrimEnd('/') + '/api/connection-profile/setup/update') -Method Post -ContentType 'application/json' -Body ($body|ConvertTo-Json -Depth 8 -Compress) -TimeoutSec 10;$profileStatus.Text="Updated $($r.profile.name) • exact hop setup refreshed";& $refreshProfiles}catch{$profileStatus.Text='Update failed: '+$_.Exception.Message}})
    $profileLoad.Add_Click({try{if(& $syncProfileMutationState){throw 'Disconnect Router VPN before loading a connection profile.'};if(-not$profileCombo.SelectedValue){throw 'Select a saved profile.'};$body=@{id=[string]$profileCombo.SelectedValue};$r=Invoke-RouterVPNControllerRequest -Uri ($BaseUrl.TrimEnd('/') + '/api/connection-profile/setup/load') -Method Post -ContentType 'application/json' -Body ($body|ConvertTo-Json -Compress) -TimeoutSec 12;Set-RouterVPNLoadedModeSnapshot -Loaded $r;Apply-RouterVPNLoadedConnectionSnapshot -Owner $Owner -Loaded $r;if($null -ne $OnConnectionProfileLoaded){& $OnConnectionProfileLoaded $r};$profileStatus.Text="Loaded $($r.profile.name) • node $($r.selected_node_id) • mode $($r.mode) • exact hop setup restored. Connect separately to prove it."}catch{$profileStatus.Text='Load failed: '+$_.Exception.Message}})
    $profileDelete.Add_Click({try{if(& $syncProfileMutationState){throw 'Disconnect Router VPN before deleting a connection profile.'};if(-not$profileCombo.SelectedValue){throw 'Select a saved profile.'};$body=@{id=[string]$profileCombo.SelectedValue};[void](Invoke-RouterVPNControllerRequest -Uri ($BaseUrl.TrimEnd('/') + '/api/connection-profile/setup/delete') -Method Post -ContentType 'application/json' -Body ($body|ConvertTo-Json -Compress) -TimeoutSec 10);$profileStatus.Text='Deleted saved connection profile and setup metadata.';& $refreshProfiles}catch{$profileStatus.Text='Delete failed: '+$_.Exception.Message}})
    & $refreshProfiles
    $dialog.FindName('MtuRetest').Add_Click({Show-RouterVPNMTUDialog -BaseUrl $BaseUrl -Owner $dialog})
    $dialog.FindName('Forwarding').Add_Click({[System.Windows.MessageBox]::Show('Port forwarding / Protected DMZ is configured through the authenticated private home-node forwarding surface and must be validated off-LAN. Router VPN will not advertise arbitrary DNAT for proxy-only paths.','Router VPN forwarding')|Out-Null})
    $script:RVPNSettingsSave=$false;$dialog.FindName('Cancel').Add_Click({$dialog.Close()});$settingsSave.Add_Click({if(Test-RouterVPNConnectionProfileBusy -BaseUrl $BaseUrl){$settingsSave.IsEnabled=$false;$nodeSettings.IsEnabled=$false;$startupSettings.IsEnabled=$false;$settingsNote.Text='VPN is active or transitioning; persistent node settings remain locked until it is fully disconnected.';return};$script:RVPNSettingsSave=$true;$dialog.Close()});[void]$dialog.ShowDialog();if(-not$script:RVPNSettingsSave -or ($null -eq $current -and $null -eq $externalStartup -and $null -eq $externalDevice)){return $null}
    if(Test-RouterVPNConnectionProfileBusy -BaseUrl $BaseUrl){throw 'VPN became active or began transitioning before settings save; disconnect and try again.'}
    if($null -ne $externalDevice -and $externalDevice.device_policy_supported){
        $externalManual=if([string]$mtuPolicy.SelectedItem.Tag -ceq 'manual'){$manual.Text.Trim()}else{0}
        $jumboArguments=@{};if($null -ne $externalDevice.PSObject.Properties['jumbo_tun']){$jumboArguments.JumboTUN=[bool]$jumbo.IsChecked}
        if([string]$externalDevice.protocol-cin@('tor','tor-bridge')-and$null-ne$externalDevice.PSObject.Properties['daita_enabled']){
            $jumboArguments.DAITAEnabled=[bool]$dialog.FindName('TorCover').IsChecked
            $jumboArguments.DAITARateKbps=$dialog.FindName('TorCoverRate').Text.Trim()
        }
        return Save-RouterVPNProfileDevice @jumboArguments -BaseUrl $BaseUrl -Captured $externalDevice -DisplayedProfileID $DisplayedProfileID -HomeLANAccess ([bool]$lan.IsChecked) -KillSwitchPolicy ([string]$kill.SelectedItem.Tag) -IPv6Mode ([string]$ipv6.SelectedItem.Tag) -MTUPolicy ([string]$mtuPolicy.SelectedItem.Tag) -ManualMTU $externalManual -StartupMode ([string]$startup.SelectedItem.Tag) -AutoConnect ([bool]$autoConnect.IsChecked)
    }
    if($null -ne $externalStartup){
        $displayedStartup=if([string]$externalStartup.startup_mode -ceq 'smart-auto'){'auto'}else{[string]$externalStartup.startup_mode}
        $selectedStartup=[string]$startup.SelectedItem.Tag
        if($selectedStartup -ceq $displayedStartup){$selectedStartup=[string]$externalStartup.startup_mode}
        if($selectedStartup -ceq [string]$externalStartup.startup_mode -and [bool]$autoConnect.IsChecked -eq [bool]$externalStartup.auto_connect){return $null}
        return Save-RouterVPNProfileStartup -BaseUrl $BaseUrl -Captured $externalStartup -StartupMode $selectedStartup -AutoConnect ([bool]$autoConnect.IsChecked)
    }
    $manualValue=0;if($manual.Text.Trim()){if(-not[int]::TryParse($manual.Text.Trim(),[ref]$manualValue)){throw 'Fixed MTU must be a number.'}}
    if([string]$mtuPolicy.SelectedItem.Tag-eq'manual'-and($manualValue-lt576-or$manualValue-gt9000)){throw 'Fixed MTU must be 576–9000.'};if([string]$mtuPolicy.SelectedItem.Tag-ne'manual'){$manualValue=0}
    $freshStartCaps=Get-RouterVPNStartLayerCapabilities -BaseUrl $BaseUrl
    if([string]$startLayer.SelectedItem.Tag-ne'off'-and-not[bool]$freshStartCaps.selected_node_supported){$reason=[string]$freshStartCaps.selected_node_reason;if([string]::IsNullOrWhiteSpace($reason)){$reason='Selected node does not support Start Layer.'};throw $reason}
    $body=@{home_lan_access=[bool]$lan.IsChecked;kill_switch_policy=[string]$kill.SelectedItem.Tag;ipv6_mode=[string]$ipv6.SelectedItem.Tag;base_tunnel=[string]$base.SelectedItem.Tag;base_fallback=[bool]$fallback.IsChecked;auto_require_encrypted=[bool]$requireEncrypted.IsChecked;auto_require_obfuscation=[bool]$requireObfuscation.IsChecked;start_layer=[string]$startLayer.SelectedItem.Tag;mtu_policy=[string]$mtuPolicy.SelectedItem.Tag;manual_mtu=$manualValue;daita_enabled=[bool]$daita.IsChecked;jumbo_tun=[bool]$jumbo.IsChecked;socks_enabled=[bool]$socks.IsChecked;startup_mode=[string]$startup.SelectedItem.Tag;auto_connect=[bool]$autoConnect.IsChecked}
    Save-RouterVPNProfileSettings -BaseUrl $BaseUrl -Body $body
}

# Safe unified settings contract: /api/profile/settings only for node preferences; connection profiles use
# /api/connection-profile/setup/* plus /api/connection-profiles and never duplicate node secrets.
# SMART AUTO default / IPv6 On default / controller-verified authenticated AES/XOR-whitening Start Layer / Auto MTU / fixed override + supported Retest /
# Require encrypted + Require obfuscation default Off / DAITA-like traffic padding / Jumbo TUN /
# LAN / kill switch / WG-AWG base+fallback / private SOCKS5 / forwarding ownership / startup /
# connection profile Add + Load + Update + Delete with current mode/CUSTOM layers and exact visible multihop entry/exit/exit transport;
# profile mutation and persistent Settings Save fail closed while controller status is connected/transitioning or unavailable.
