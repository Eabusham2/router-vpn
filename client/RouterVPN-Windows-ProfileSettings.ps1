# Inspect loaded functions without discovering/importing unrelated modules.
# A missing UI-state function otherwise makes cold Get-Command scan the host.
if($null-eq${function:New-RouterVPNControllerClient}){
    Import-Module (Join-Path $PSScriptRoot 'RouterVPN-Windows-ControllerTransport.psm1') -Global -ErrorAction Stop
}
if($null-eq${function:Read-RouterVPNUIState}){
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
    $pendingProperty=$captured.PSObject.Properties['protection_status']
    if($Enabled -and $null-ne$pendingProperty -and @('off-pending','off-unsaved') -ccontains [string]$pendingProperty.Value){throw 'Finish the pending Off change before enabling the kill switch.'}
    $body=@{profile_id=$DisplayedProfileID;profile_token=[string]$captured.profile_token;kill_switch_policy=$(if($Enabled){'on-connect'}else{'off'})}
    try{
        $saved=Invoke-RouterVPNControllerRequest -Uri ($BaseUrl.TrimEnd('/') + '/api/profile/protection') -Method Post -ContentType 'application/json' -Body ($body | ConvertTo-Json -Compress) -TimeoutSec 30
    }catch{
        $failure=$_.Exception.Message;$pending=$null
        try{$pending=Invoke-RouterVPNControllerRequest -Uri ($BaseUrl.TrimEnd('/') + '/api/profile/protection') -Method Get -TimeoutSec 5}catch{}
        if($null-ne$pending -and [string]$pending.profile_id -ceq $DisplayedProfileID){
            $state=$pending.PSObject.Properties['protection_status'];$message=$pending.PSObject.Properties['message']
            if($null-ne$state -and @('off-pending','off-unsaved') -ccontains [string]$state.Value -and $null-ne$message -and -not[string]::IsNullOrWhiteSpace([string]$message.Value)){throw ([string]$message.Value)}
        }
        throw $failure
    }
    if($null-eq$saved -or [string]$saved.profile_id -cne $DisplayedProfileID -or [string]$saved.kill_switch_policy -cne [string]$body.kill_switch_policy -or [string]::IsNullOrWhiteSpace([string]$saved.profile_token)){throw 'The controller did not confirm the captured protection change.'}
    $savedState=$saved.PSObject.Properties['protection_status'];$effective=$saved.PSObject.Properties['effective_policy']
    if($null-ne$savedState -and @('off-pending','off-unsaved') -ccontains [string]$savedState.Value){throw 'The protection change is still pending. Refresh and finish Off.'}
    if(-not$Enabled -and $null-ne$effective -and [string]$effective.Value -cne 'off'){throw 'The controller has not confirmed that retained protection is off.'}
    return $saved
}

function global:Get-RouterVPNProtectionPresentation {
    param($Captured,[string]$DisplayedProfileID)
    $result=[pscustomobject]@{Valid=$false;Enabled=$false;Checked=$null;Pending=$false;Label='Kill switch';Message='Protection status is unavailable. Refresh before changing it.'}
    if($null-eq$Captured -or [string]::IsNullOrWhiteSpace($DisplayedProfileID) -or [string]$Captured.profile_id -cne $DisplayedProfileID -or [string]::IsNullOrWhiteSpace([string]$Captured.profile_token)){return $result}
    $policy=[string]$Captured.kill_switch_policy
    if(@('off','on-connect','always') -cnotcontains $policy){return $result}
    $stateProperty=$Captured.PSObject.Properties['protection_status'];$state=if($null-ne$stateProperty){[string]$stateProperty.Value}else{''}
    $effectiveProperty=$Captured.PSObject.Properties['effective_policy'];$effective=if($null-ne$effectiveProperty){[string]$effectiveProperty.Value}else{$policy}
    if(@('','retained','active','pending','off-pending','off-unsaved') -cnotcontains $state -or @('off','on-connect','always','unknown') -cnotcontains $effective){return $result}
    $result.Valid=$true;$result.Enabled=$true;$result.Message=''
    $messageProperty=$Captured.PSObject.Properties['message'];if($null-ne$messageProperty){$result.Message=[string]$messageProperty.Value}
    if(@('off-pending','off-unsaved') -ccontains $state){
        $result.Pending=$true;$result.Label='Finish Off';$result.Checked=$null
        if([string]::IsNullOrWhiteSpace($result.Message)){$result.Message='The Off change is pending. Select Finish Off to retry the same change.'}
        return $result
    }
    if($effective-ceq'unknown'){$result.Enabled=$false;$result.Checked=$null}else{$result.Checked=($effective-cne'off')}
    $ownerProperty=$Captured.PSObject.Properties['protection_profile_id']
    if($null-ne$ownerProperty -and -not[string]::IsNullOrWhiteSpace([string]$ownerProperty.Value) -and [string]$ownerProperty.Value-cne$DisplayedProfileID){$result.Enabled=$false}
    return $result
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

function global:Get-RouterVPNOrderedValue {
    param($Value,[string]$Name,$Default=$null)
    if($null-eq$Value){return $Default}
    if($Value-is[Collections.IDictionary]){if($Value.Contains($Name)){return $Value[$Name]};return $Default}
    $property=$Value.PSObject.Properties[$Name];if($null-ne$property){return $property.Value};return $Default
}

function global:Test-RouterVPNOrderedPrefixMode {
    param($Mode)
    return $Mode-is[string]-and@('wg','awg2-fast','awg2-strong')-ccontains$Mode
}

function global:Test-RouterVPNOrderedFinalMode {
    param($Mode)
    return $Mode-is[string]-and@('shadowsocks','hysteria2')-ccontains$Mode
}

function global:Get-RouterVPNOrderedFinalModes {
    param($Profile,$Prefixes)
    if($null-eq$Profile-or[string](Get-RouterVPNOrderedValue $Profile 'node_kind' '')-cnotin@('','router-vpn')){return @()}
    $choices=@('shadowsocks')
    $layer=Get-RouterVPNOrderedValue $Profile 'start_layer' ''
    $imported=@($Prefixes|Where-Object{(Get-RouterVPNOrderedValue $_ 'mode')-cin@('shadowsocks','socks5','http-connect','https-connect','openvpn')}).Count-gt0
    if($Prefixes.Count -lt 8 -and $layer-is[string]-and$layer-cin@('','off','aes-256-gcm','aes-256-gcm+xor-whitening')-and-not$imported){$choices+='hysteria2'}
    return $choices
}

function global:Get-RouterVPNOrderedModeTitle {
    param($Mode)
    switch -CaseSensitive ($Mode) {
        'wg' {return 'WireGuard'}
        'awg2-fast' {return 'AmneziaWG Fast'}
        'awg2-strong' {return 'AmneziaWG Strong'}
        'shadowsocks' {return 'Shadowsocks 2022'}
        'socks5' {return 'SOCKS5'}
        'http-connect' {return 'HTTP CONNECT'}
        'https-connect' {return 'HTTPS CONNECT'}
        'openvpn' {return 'OpenVPN'}
        'hysteria2' {return 'Hysteria2'}
        default {throw 'The ordered node has an unsupported exact transport.'}
    }
}

function global:Test-RouterVPNOrderedImportedPosition {
    param([string]$Mode,[int]$Position,[int]$Count)
    if($Mode-cin@('shadowsocks','socks5','http-connect','https-connect','openvpn')){return $Count-ge3-and$Count-le8-and$Position-eq($Count-2)}
    return $Count-eq3-and$Position-eq1
}

function global:Get-RouterVPNOrderedPhysicalTraversalDepth { return 96 }

function global:Test-RouterVPNOrderedExtendedLocalShape {
    param($Nodes)
    if($Nodes-isnot[Collections.IList]-or$Nodes.Count-le8-or$Nodes.Count-gt(Get-RouterVPNOrderedPhysicalTraversalDepth)){return $false}
    for($i=0;$i-lt$Nodes.Count;$i++){
        $mode=Get-RouterVPNOrderedValue $Nodes[$i] 'mode'
        if(($i-eq0-and$mode-cne'wg')-or($i-gt0-and$mode-cne'shadowsocks')){return $false}
    }
    return $true
}

function global:Test-RouterVPNOrderedPairedShape {
    param($Nodes)
    if($Nodes -isnot [Collections.IList] -or $Nodes.Count -le 8 -or $Nodes.Count -gt (Get-RouterVPNOrderedPhysicalTraversalDepth) -or $Nodes[-1].mode -cne 'shadowsocks'){return $false}
    for($i=0;$i -lt $Nodes.Count-1;$i++){if($Nodes[$i].mode -cne 'wg'){return $false}}
    return $true
}
function global:Test-RouterVPNOrderedPairedOff {
    param($Profile)
    if($null -eq $Profile){return $false}
    $layer=Get-RouterVPNOrderedValue $Profile 'start_layer' ''
    return (Get-RouterVPNOrderedValue $Profile 'node_kind' '') -cin @('','router-vpn') -and
        $null -eq (Get-RouterVPNOrderedValue $Profile 'external') -and $layer -is [string] -and $layer -cin @('','off')
}

function global:Test-RouterVPNOrderedLocalSSPosition {
    param([string]$Mode,[int]$Position,[int]$Count)
    return $Mode-ceq'shadowsocks'-and$Count-ge3-and$Count-le(Get-RouterVPNOrderedPhysicalTraversalDepth)-and$Position-gt0-and$Position-lt($Count-1)
}

function global:Test-RouterVPNOrderedCustomEntryShape {
    param($Nodes)
    if($Nodes-isnot[Collections.IList]-or$Nodes.Count-ne3){return $false}
    foreach($node in $Nodes){if((Get-RouterVPNOrderedValue $node 'mode')-cne'shadowsocks'){return $false}}
    return $true
}

function global:Copy-RouterVPNOrderedNodes {
    param($Nodes,[string]$ControlID)
    if($Nodes-isnot[Collections.IList]-or$Nodes.Count-lt2-or($Nodes.Count-gt8-and-not(Test-RouterVPNOrderedExtendedLocalShape $Nodes)-and-not(Test-RouterVPNOrderedPairedShape $Nodes))){throw 'Choose a supported ordered path. Longer Local routes support either paired WireGuard prefixes or a WireGuard entry and independent Shadowsocks interiors, followed by a paired Shadowsocks exit with each Start Layer Off.'}
    $seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $copy=New-Object 'Collections.Generic.List[object]'
    for($i=0;$i-lt$Nodes.Count;$i++){
        $id=Get-RouterVPNOrderedValue $Nodes[$i] 'id';$mode=Get-RouterVPNOrderedValue $Nodes[$i] 'mode'
        if($id-isnot[string]-or$id-cnotmatch'\A[A-Za-z0-9_-]{1,64}\z'-or-not$seen.Add($id)){throw 'Ordered nodes require distinct linked node IDs.'}
        if($mode-isnot[string]-or($i-lt$Nodes.Count-1-and-not(Test-RouterVPNOrderedPrefixMode $mode)-and-not(((Test-RouterVPNOrderedImportedPosition $mode $i $Nodes.Count)-or(Test-RouterVPNOrderedLocalSSPosition $mode $i $Nodes.Count)-or($i-eq0-and(Test-RouterVPNOrderedCustomEntryShape $Nodes)))-and$mode-cin@('shadowsocks','socks5','http-connect','https-connect','openvpn')-and(Get-RouterVPNOrderedValue $Nodes[-1] 'mode')-ceq'shadowsocks'))-or($i-eq$Nodes.Count-1-and-not(Test-RouterVPNOrderedFinalMode $mode))){throw 'Use paired packet prefixes, supported imported middle hops, or two distinct custom Shadowsocks hops before a paired Shadowsocks exit in Local. Keep SOCKS5, CONNECT and OpenVPN immediately before a Shadowsocks exit.'}
        [void]$copy.Add([pscustomobject]@{id=$id;mode=$mode})
    }
    if([string]::IsNullOrEmpty($ControlID)-or$copy[$copy.Count-1].id-cne$ControlID){throw 'The final ordered node must be the selected exit node.'}
    return $copy.ToArray()
}

function global:Get-RouterVPNOrderedImportedMode {
    param($Profile)
    $external=Get-RouterVPNOrderedValue $Profile 'external'
    $supported=Get-RouterVPNOrderedValue $external 'ordered_middle_supported' $false
    $protocol=Get-RouterVPNOrderedValue $external 'protocol'
    if([string](Get-RouterVPNOrderedValue $Profile 'node_kind')-cne'external'-or$supported-isnot[bool]-or-not$supported-or$protocol-isnot[string]-or$protocol-cnotin@('shadowsocks','socks5','http-connect','https-connect','openvpn')){return ''}
    return $protocol
}

function global:Test-RouterVPNOrderedImportedMiddle {
    param($Profile)
    return -not[string]::IsNullOrEmpty((Get-RouterVPNOrderedImportedMode $Profile))
}

function global:Test-RouterVPNOrderedMultipleImportedShape {
    param($Nodes)
    $count=@($Nodes).Count
    if($count-lt3-or($count-gt8-and-not(Test-RouterVPNOrderedExtendedLocalShape $Nodes))-or-not(Test-RouterVPNOrderedPrefixMode $Nodes[0].mode)-or$Nodes[-1].mode-cne'shadowsocks'){return $false}
    $independent=$false
    for($position=1;$position-lt$count-1;$position++){
        $mode=$Nodes[$position].mode
        if($mode-ceq'shadowsocks'){if($position-lt$count-2){$independent=$true}}
        elseif(-not(Test-RouterVPNOrderedPrefixMode $mode)){return $false}
    }
    return $independent
}

function global:Get-RouterVPNOrderedProfileIndex {
    param($Profiles)
    $index=[Collections.Hashtable]::new([StringComparer]::Ordinal)
    foreach($profile in $Profiles){
        $id=[string](Get-RouterVPNOrderedValue $profile 'id')
        if($index.ContainsKey($id)){$index[$id]=$null}
        else{$index.Add($id,$profile)}
    }
    return $index
}

function global:Test-RouterVPNOrderedLocalImportedPath {
    param($Nodes,$Profiles,[switch]$SelectedExecution,$ProfileIndex)
    if($SelectedExecution-and-not(Test-RouterVPNOrderedMultipleImportedShape $Nodes)){return $false}
    $hint=if($SelectedExecution){'ordered_multiple_imported_execution_supported'}else{'ordered_local_imported_nodes_supported'}
    if(@($Nodes).Count-lt3-or(@($Nodes).Count-gt8-and-not(Test-RouterVPNOrderedExtendedLocalShape $Nodes))-or$Nodes[-1].mode-cne'shadowsocks'){return $false}
    $seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    if($null-eq$ProfileIndex){$ProfileIndex=Get-RouterVPNOrderedProfileIndex $Profiles}
    $imports=0
    for($position=0;$position-lt$Nodes.Count;$position++){
        $row=$Nodes[$position]
        if($row.id-isnot[string]-or-not$seen.Add($row.id)){return $false}
        $profile=$ProfileIndex[$row.id]
        if($null-eq$profile){return $false}
        $kind=Get-RouterVPNOrderedValue $profile 'node_kind' ''
        if($Nodes.Count-gt8){
            $interior=$position-gt0-and$position-lt($Nodes.Count-1)
            $layer=Get-RouterVPNOrderedValue $profile 'start_layer' ''
            if($interior-ne($kind-ceq'external')-or$layer-cnotin@('','off')){return $false}
        }
        if($kind-ceq'external'){
            $external=Get-RouterVPNOrderedValue $profile 'external'
            $allowed=Get-RouterVPNOrderedValue $external $hint $false
            if((-not(Test-RouterVPNOrderedLocalSSPosition $row.mode $position $Nodes.Count)-and-not($position-eq0-and(Test-RouterVPNOrderedCustomEntryShape $Nodes)))-or(Get-RouterVPNOrderedImportedMode $profile)-cne'shadowsocks'-or$allowed-isnot[bool]-or-not$allowed){return $false}
            $imports++
        }elseif($kind-cnotin@('','router-vpn')-or$null-ne(Get-RouterVPNOrderedValue $profile 'external')-or($position-lt($Nodes.Count-1)-and-not(Test-RouterVPNOrderedPrefixMode $row.mode))){return $false}
    }
    return $imports-gt0
}

function global:Test-RouterVPNOrderedResponsePrefix {
    param($Nodes,[int]$Position,[string]$Execution,$Profiles)
    if($Execution -cne 'local' -or $Position -le 0 -or $Position -ge $Nodes.Count-1 -or $Nodes[0].mode -cne 'wg'){return $false}
    $index=Get-RouterVPNOrderedProfileIndex $Profiles
    if(-not(Test-RouterVPNOrderedLocalImportedPath $Nodes $Profiles -ProfileIndex $index) -or -not(Test-RouterVPNOrderedPairedOff $index[$Nodes[0].id])){return $false}
    $end=$Position
    if($Position -ge 7){
        if(-not(Test-RouterVPNOrderedExtendedLocalShape $Nodes) -or -not(Test-RouterVPNOrderedPairedOff $index[$Nodes[-1].id])){return $false}
        $end=$Nodes.Count-2
    }
    for($i=1;$i -le $end;$i++){
        $source=$index[$Nodes[$i].id]
        $literal=Get-RouterVPNOrderedValue (Get-RouterVPNOrderedValue $source 'external') 'ordered_local_imported_nodes_supported' $false
        $layer=Get-RouterVPNOrderedValue $source 'start_layer' ''
        if($Nodes[$i].mode -cne 'shadowsocks' -or (Get-RouterVPNOrderedImportedMode $source) -cne 'shadowsocks' -or
            $literal -isnot [bool] -or -not $literal -or $layer -isnot [string] -or $layer -cnotin @('','off')){return $false}
    }
    return $true
}

function global:Test-RouterVPNOrderedCandidatePosition {
    param($Nodes,[int]$Position,[string]$Execution,$Profiles)
    if($Position -lt 0 -or $Position -ge $Nodes.Count-1 -or $Nodes.Count -gt (Get-RouterVPNOrderedPhysicalTraversalDepth)){return $false}
    if($Nodes[$Position].mode -ceq 'shadowsocks'){return Test-RouterVPNOrderedResponsePrefix $Nodes $Position $Execution $Profiles}
    if(-not(Test-RouterVPNOrderedPrefixMode $Nodes[$Position].mode) -or $Nodes.Count -eq (Get-RouterVPNOrderedPhysicalTraversalDepth)){return $false}
    if($Execution -ceq 'local' -and @($Nodes|Select-Object -First ($Position+1)|Where-Object{-not(Test-RouterVPNOrderedPrefixMode $_.mode)}).Count){return $false}
    if($Nodes.Count -ge 8 -and ($Execution -cne 'local' -or $Nodes[-1].mode -cne 'shadowsocks' -or
        @($Nodes | Select-Object -SkipLast 1 | Where-Object {$_.mode -cne 'wg'}).Count)){return $false}
    return $true
}

function global:Get-RouterVPNOrderedExecutionCapability {
    param($Nodes,[string]$Execution)
    if($Execution-cne'local'-and(Test-RouterVPNOrderedMultipleImportedShape $Nodes)){return 'ordered_multiple_imported_executions'}
    if($Execution-cne'local'-and@($Nodes).Count-ge2-and@($Nodes).Count-le8-and$Nodes[-1].mode-ceq'hysteria2'){
        $pairedHysteria=$true
        for($position=0;$position-lt(@($Nodes).Count-1);$position++){if($Nodes[$position].mode-cnotin@('wg','awg2-fast','awg2-strong')){$pairedHysteria=$false}}
        if($pairedHysteria){return 'ordered_hysteria_executions'}
    }
    if($Execution-cne'local'-and@($Nodes).Count-ge3-and@($Nodes).Count-le8-and$Nodes[-2].mode-ceq'openvpn'){return 'ordered_openvpn_executions'}
    if($Execution-cne'local'-and@($Nodes).Count-ge3-and@($Nodes).Count-le8-and$Nodes[-2].mode-ceq'socks5'){return 'ordered_socks_trio_executions'}
    if($Execution-cne'local'-and@($Nodes).Count-ge3-and@($Nodes).Count-le8-and$Nodes[-2].mode-cin@('http-connect','https-connect')){return 'ordered_connect_trio_executions'}
    return 'ordered_executions'
}

function global:Test-RouterVPNOrderedSOCKSExecutionLayers {
    param($Nodes,$Profiles,$ProfileIndex)
    $socksCount=@($Nodes).Count
    if($socksCount-lt3-or$socksCount-gt8){return $false}
    if($null-eq$ProfileIndex){$ProfileIndex=Get-RouterVPNOrderedProfileIndex $Profiles}
    for($socksPosition=0;$socksPosition-lt$socksCount;$socksPosition++){
        $profile=$ProfileIndex[$Nodes[$socksPosition].id]
        if($null-eq$profile){return $false}
        $socksLayer=Get-RouterVPNOrderedValue $profile 'start_layer' ''
        if($socksLayer-isnot[string]){return $false}
        if($socksPosition-ne($socksCount-2)){if($socksLayer-cnotin@('','off','aes-256-gcm','aes-256-gcm+xor-whitening')){return $false}}
        elseif($socksLayer-cnotin@('','off')){return $false}
    }
    return $true
}

function global:Test-RouterVPNOrderedOpenVPNExecutionLayers {
    param($Nodes,$Profiles,$ProfileIndex)
    $openvpnCount=@($Nodes).Count
    if($openvpnCount-lt3-or$openvpnCount-gt8){return $false}
    if($null-eq$ProfileIndex){$ProfileIndex=Get-RouterVPNOrderedProfileIndex $Profiles}
    for($openvpnPosition=0;$openvpnPosition-lt$openvpnCount;$openvpnPosition++){
        $profile=$ProfileIndex[$Nodes[$openvpnPosition].id]
        if($null-eq$profile){return $false}
        $openvpnLayer=Get-RouterVPNOrderedValue $profile 'start_layer' ''
        if($openvpnLayer-isnot[string]){return $false}
        if($openvpnPosition-ne($openvpnCount-2)){if($openvpnLayer-cnotin@('','off','aes-256-gcm','aes-256-gcm+xor-whitening')){return $false}}
        elseif($openvpnLayer-cnotin@('','off')){return $false}
    }
    return $true
}

function global:New-RouterVPNOrderedConnectPayload {
    param($Draft,$Store)
    $control=[string](Get-RouterVPNOrderedValue $Draft 'control_id')
    if($control-cne[string](Get-RouterVPNOrderedValue $Store 'selected_id')){throw 'The selected exit changed. Reopen the ordered path editor.'}
    $nodes=@(Copy-RouterVPNOrderedNodes (Get-RouterVPNOrderedValue $Draft 'nodes') $control)
    $execution=[string](Get-RouterVPNOrderedValue $Draft 'execution' 'local')
    if($execution-cnotin@('local','server','auto')){throw 'Choose Local, Server or Compare for the complete ordered path.'}
    $profiles=@(Get-RouterVPNOrderedValue $Store 'profiles' @())
    # Each lookup uses the same captured catalog. Duplicate IDs stay ambiguous.
    $profileIndex=Get-RouterVPNOrderedProfileIndex $profiles
    $localImported=$execution-ceq'local'-and(Test-RouterVPNOrderedLocalImportedPath $nodes $profiles -ProfileIndex $profileIndex)
    $multipleImported=$execution-cne'local'-and(Test-RouterVPNOrderedLocalImportedPath $nodes $profiles -SelectedExecution -ProfileIndex $profileIndex)
    $paired=$execution -ceq 'local' -and (Test-RouterVPNOrderedPairedShape $nodes)
    if($nodes.Count-gt8-and-not($localImported-or$multipleImported-or$paired)){throw 'This extended route requires its supported execution and every original transport.'}
    if($execution-cne'local'-and(Test-RouterVPNOrderedMultipleImportedShape $nodes)-and-not$multipleImported){throw 'Each imported Shadowsocks interior must advertise support for this execution.'}
    $expected=Get-RouterVPNOrderedValue $Draft 'profile_tokens';$tokens=[Collections.Hashtable]::new([StringComparer]::Ordinal)
    for($position=0;$position-lt$nodes.Count;$position++){
        $node=$nodes[$position]
        $profile=$profileIndex[$node.id]
        if($null-eq$profile){throw 'An ordered node is missing.'}
        if($paired -and -not(Test-RouterVPNOrderedPairedOff $profile)){throw 'Extended paired WireGuard routes require linked Router nodes with Start Layer Off.'}
        $imported=Test-RouterVPNOrderedImportedMiddle $profile
        if($imported-and$execution-cne'local'-and-not$multipleImported){
            $connectMiddle=$node.mode-cin@('http-connect','https-connect')
            $socksMiddle=$node.mode-ceq'socks5'
            $openVPNMiddle=$node.mode-ceq'openvpn'
            $executionKey=if($openVPNMiddle){'ordered_openvpn_execution_middle_supported'}elseif($socksMiddle){'ordered_socks_execution_middle_supported'}elseif($connectMiddle){'ordered_connect_execution_middle_supported'}else{'ordered_execution_middle_supported'}
            $executionMiddle=Get-RouterVPNOrderedValue (Get-RouterVPNOrderedValue $profile 'external') $executionKey $false
            if(-not$connectMiddle-and-not$socksMiddle-and$node.mode-ceq'shadowsocks'){
                $hostnameMiddle=Get-RouterVPNOrderedValue (Get-RouterVPNOrderedValue $profile 'external') 'ordered_hostname_execution_middle_supported' $false
                if($executionMiddle-isnot[bool]-or$hostnameMiddle-isnot[bool]-or($executionMiddle-and$hostnameMiddle)){throw 'The imported execution capability changed.'}
                if(-not$executionMiddle-and$nodes.Count-ge4){$executionMiddle=$hostnameMiddle}
            }
            if($nodes.Count-lt3-or$nodes.Count-gt8-or$position-ne($nodes.Count-2)-or(-not$connectMiddle-and-not$socksMiddle-and-not$openVPNMiddle-and$node.mode-cne'shadowsocks')-or$nodes[-1].mode-cne'shadowsocks'-or-not(Test-RouterVPNOrderedPrefixMode $nodes[0].mode)-or$executionMiddle-isnot[bool]-or-not$executionMiddle){throw 'Server or Compare requires its original Shadowsocks prefix, a saved hostname resolver after two packet members, a complete CONNECT or SOCKS5 path, or an independently paired OpenVPN path.'}
            if($openVPNMiddle-and-not(Test-RouterVPNOrderedOpenVPNExecutionLayers $nodes $profiles $profileIndex)){throw 'OpenVPN execution retains every captured paired layer and an unlayered imported middle.'}
            if($socksMiddle-and-not(Test-RouterVPNOrderedSOCKSExecutionLayers $nodes $profiles $profileIndex)){throw 'SOCKS5 execution retains every captured paired layer and an unlayered imported middle.'}
            if($connectMiddle){
                for($connectPosition=0;$connectPosition-lt$nodes.Count-1;$connectPosition++){
                    $connectProfile=$profileIndex[$nodes[$connectPosition].id]
                    if($null-eq$connectProfile){throw 'The original CONNECT prefix source is missing.'}
                    $connectLayer=Get-RouterVPNOrderedValue $connectProfile 'start_layer' ''
                    if($connectLayer-isnot[string]){throw 'The original CONNECT prefix layer is invalid.'}
                    if($connectPosition-lt$nodes.Count-2){
                        if($connectLayer-cnotin@('','off','aes-256-gcm','aes-256-gcm+xor-whitening')){throw 'The original CONNECT prefix layer is invalid.'}
                    }elseif($connectLayer-cnotin@('','off')){throw 'The imported CONNECT member requires Start Layer Off.'}
                }
                $finalProfile=$profileIndex[$nodes[-1].id]
                if($null-eq$finalProfile){throw 'The original CONNECT final source is missing.'}
                $connectFinalLayer=Get-RouterVPNOrderedValue $finalProfile 'start_layer' ''
                if($connectFinalLayer-isnot[string]-or$connectFinalLayer-cnotin@('','off','aes-256-gcm','aes-256-gcm+xor-whitening')){throw 'The original CONNECT final layer is invalid.'}
            }
        }
        if($imported){if((-not(Test-RouterVPNOrderedImportedPosition $node.mode $position $nodes.Count)-and-not(($localImported-or$multipleImported)-and((Test-RouterVPNOrderedLocalSSPosition $node.mode $position $nodes.Count)-or($position-eq0-and(Test-RouterVPNOrderedCustomEntryShape $nodes)))))-or$node.mode-cne(Get-RouterVPNOrderedImportedMode $profile)){throw 'An imported node retains its exact Shadowsocks 2022, SOCKS5, HTTP(S) CONNECT or OpenVPN transport between the paired entry and final.'}}
        elseif([string](Get-RouterVPNOrderedValue $profile 'node_kind' '')-cnotin@('','router-vpn')-or($position-lt$nodes.Count-1-and-not(Test-RouterVPNOrderedPrefixMode $node.mode))){throw 'The ordered source kind or transport changed.'}
        if($position-eq$nodes.Count-1-and@(Get-RouterVPNOrderedFinalModes $profile @($nodes|Select-Object -SkipLast 1))-cnotcontains$node.mode){throw 'The selected final transport is incompatible with its captured Start Layer or imported middle.'}
        $token=Get-RouterVPNOrderedValue $expected $node.id
        if($token-isnot[string]-or$token-cnotmatch'\A[0-9a-f]{64}\z'-or[string](Get-RouterVPNOrderedValue $profile 'profile_token')-cne$token){throw 'An ordered node changed or was relinked. Reopen its editor before connecting.'}
        $tokens[$node.id]=$token
    }
    # Only references cross this UI boundary. Every private source is captured
    # independently by the original native controller before it owns a tunnel.
    return @{nodes=$nodes;execution=$execution;expected_selected_node_id=$control;expected_profile_tokens=$tokens}
}

function global:Get-RouterVPNOrderedConnectionSnapshot {
    param($Owner)
    if($null-eq$Owner){return $null}
    $toggle=$Owner.FindName('UnifiedOrdered');$multi=$Owner.FindName('UnifiedMultihop')
    if($null-eq$toggle-or-not$toggle.IsChecked-or$null-eq$multi-or-not$multi.IsChecked){return $null}
    $button=$Owner.FindName('UnifiedNodeChainButton');$selected=$Owner.FindName('UnifiedNodeCombo')
    if($null-eq$button-or$null-eq$button.Tag-or$null-eq$selected){throw 'Edit the complete ordered path before saving or connecting.'}
    if([string](Get-RouterVPNOrderedValue $button.Tag 'control_id')-cne[string]$selected.SelectedValue){throw 'The selected exit changed. Reopen the ordered path editor.'}
    $nodes=@(Copy-RouterVPNOrderedNodes (Get-RouterVPNOrderedValue $button.Tag 'nodes') ([string]$selected.SelectedValue))
    $choice=$Owner.FindName('UnifiedExecution')
    $execution=if($null-ne$choice-and$null-ne$choice.SelectedItem){[string]$choice.SelectedItem.Tag}else{[string](Get-RouterVPNOrderedValue $button.Tag 'execution' 'local')}
    if($execution-cnotin@('local','server','auto')){throw 'The ordered execution choice is unavailable.'}
    return @{multihop_enabled=$true;multihop_nodes=$nodes;multihop_execution=$execution;multihop_entry_id='';multihop_exit_id='';multihop_entry_mode='';multihop_exit_mode=''}
}

function global:Set-RouterVPNLoadedOrderedSnapshot {
    param($Owner,$Loaded)
    $raw=Get-RouterVPNOrderedValue $Loaded 'multihop_nodes'
    $hasNodes=$null-ne$raw-and@($raw).Count-gt0
    $toggle=$Owner.FindName('UnifiedOrdered');$button=$Owner.FindName('UnifiedNodeChainButton')
    if($hasNodes){
        $id=[string](Get-RouterVPNOrderedValue $Loaded 'selected_node_id')
        $nodes=@(Copy-RouterVPNOrderedNodes $raw $id)
        if(-not[bool](Get-RouterVPNOrderedValue $Loaded 'multihop_enabled' $false)-or[string](Get-RouterVPNOrderedValue $Loaded 'multihop_execution')-cnotin@('local','server','auto')){throw 'The loaded ordered path has an invalid execution choice.'}
        foreach($key in @('multihop_entry_id','multihop_exit_id','multihop_entry_mode','multihop_exit_mode')){if([string](Get-RouterVPNOrderedValue $Loaded $key)){throw 'The loaded profile mixes an ordered path with another entry or exit.'}}
        if($null-eq$toggle-or$null-eq$button){throw 'This window cannot display the complete loaded ordered path.'}
        $rawTokens=Get-RouterVPNOrderedValue $Loaded 'profile_tokens';$tokens=@{}
        foreach($node in $nodes){$token=Get-RouterVPNOrderedValue $rawTokens $node.id;if($token-isnot[string]-or$token-cnotmatch'\A[0-9a-f]{64}\z'){throw 'The loaded ordered path is missing a captured node source.'};$tokens[$node.id]=$token}
        $button.Tag=[pscustomobject]@{control_id=$id;nodes=$nodes;profile_tokens=$tokens;execution=[string]$Loaded.multihop_execution}
        $toggle.IsChecked=$true
    }else{
        if($null-ne$button){$button.Tag=$null};if($null-ne$toggle){$toggle.IsChecked=$false}
    }
}

function global:Get-RouterVPNVisibleConnectionSnapshot {
    param([System.Windows.Window]$Owner,[hashtable]$Provided)
    if($null -ne $Provided){return $Provided}
    $result=@{multihop_enabled=$false;multihop_entry_id='';multihop_exit_id='';multihop_exit_mode='';multihop_execution='';multihop_entry_mode=''}
    if($null -eq $Owner){return $result}
    $ordered=Get-RouterVPNOrderedConnectionSnapshot $Owner
    if($null-ne$ordered){return $ordered}
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
    if($result.multihop_enabled-and(-not$entryChoiceValid-or([string]$result.multihop_entry_mode)-cnotin@('','wg','awg2-fast','awg2-strong','wg-pq','awg2-pq','shadowsocks','hysteria2','reality-vision','reality-pq-vision','reality-xhttp','naive-h2','naive-h3','ss-v2ray','split','max','max-tls-wg','max-tls-awg','max-quic-wg','max-quic-awg','wireguard','amneziawg','socks5','http-connect','https-connect','openvpn'))){throw 'Select a supported entry mode before saving the connection profile.'}
    if($result.multihop_enabled -and ([string]$result.multihop_exit_mode)-cnotin@('shadowsocks','hysteria2','reality-vision','reality-pq-vision','reality-xhttp','naive-h2','naive-h3','wg','awg2-fast','awg2-strong','ss-v2ray','split','max','wg-pq','awg2-pq','max-tls-wg','max-tls-awg','max-quic-wg','max-quic-awg')){throw 'Select a supported exit transport before saving the connection profile.'}
    return $result
}

function global:Get-RouterVPNSetupGraphIDs {
    param($Graph,[string]$SelectedID)
    $ids=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    if($SelectedID-cnotmatch'\A[A-Za-z0-9_-]{1,64}\z'){throw 'Refresh the selected node before changing a connection profile.'}
    [void]$ids.Add($SelectedID)
    if((Get-RouterVPNOrderedValue $Graph 'multihop_enabled' $false)-eq$true){
        $raw=Get-RouterVPNOrderedValue $Graph 'multihop_nodes'
        if($null-ne$raw-and@($raw).Count-gt0){
            foreach($node in @(Copy-RouterVPNOrderedNodes $raw $SelectedID)){[void]$ids.Add($node.id)}
        }else{
            foreach($key in @('multihop_entry_id','multihop_exit_id')){
                $id=Get-RouterVPNOrderedValue $Graph $key
                if($id-isnot[string]-or$id-cnotmatch'\A[A-Za-z0-9_-]{1,64}\z'){throw 'The captured connection profile has an incomplete node selection.'}
                [void]$ids.Add($id)
            }
        }
    }
    return @($ids)
}

function global:Get-RouterVPNSetupViewKey {
    param($Owner)
    $view=[ordered]@{}
    foreach($name in @('UnifiedNodeCombo','UnifiedEntryCombo','UnifiedExitCombo')){
        $control=$Owner.FindName($name);$view[$name]=if($null-ne$control){[string]$control.SelectedValue}else{''}
    }
    foreach($name in @('UnifiedEntryMode','UnifiedExitMode','UnifiedExecution')){
        $control=$Owner.FindName($name);$view[$name]=if($null-ne$control-and$null-ne$control.SelectedItem){[string]$control.SelectedItem.Tag}else{''}
    }
    foreach($name in @('UnifiedMultihop','UnifiedOrdered')){
        $control=$Owner.FindName($name);$view[$name]=$null-ne$control-and[bool]$control.IsChecked
    }
    $draft=$Owner.FindName('UnifiedNodeChainButton');$view['ordered']=if($null-ne$draft){$draft.Tag}else{$null}
    $view['mode']=Get-RouterVPNCurrentModeSnapshot
    return ($view|ConvertTo-Json -Depth 16 -Compress)
}

function global:Get-RouterVPNSetupCapture {
    param($Owner,$Graph,[bool]$Loading)
    if($null-eq$Owner){throw 'Reopen Settings from the current Router VPN window.'}
    $selected=$Owner.FindName('UnifiedNodeCombo')
    if($null-eq$selected-or$null-eq$selected.Tag){throw 'Refresh the selected node before changing a connection profile.'}
    $id=[string]$selected.SelectedValue;$store=$selected.Tag
    if([string](Get-RouterVPNOrderedValue $store 'selected_id')-cne$id){throw 'The selected node changed. Refresh before changing a connection profile.'}
    $profiles=@(Get-RouterVPNOrderedValue $store 'profiles' @())
    $control=@($profiles|Where-Object{[string](Get-RouterVPNOrderedValue $_ 'id')-ceq$id})
    if($control.Count-ne1){throw 'The original selected node is no longer available.'}
    # Load protects the original saved catalog selection. An unsaved editor
    # draft must not replace that inventory; Save/Update protect their draft.
    $graphSource=if($Loading-or[string](Get-RouterVPNOrderedValue $control[0] 'node_kind')-ceq'external'){$control[0]}else{$Graph}
    $graphCopy=$graphSource|ConvertTo-Json -Depth 16|ConvertFrom-Json
    $tokens=@{};$ids=@(Get-RouterVPNSetupGraphIDs $graphCopy $id)
    $ordered=Get-RouterVPNOrderedValue $graphCopy 'multihop_nodes'
    $draftTokens=$null
    if(-not$Loading-and$null-ne$ordered-and@($ordered).Count-gt0){
        $draft=$Owner.FindName('UnifiedNodeChainButton')
        if($null-eq$draft-or$null-eq$draft.Tag){throw 'Reopen the complete ordered path before saving it.'}
        $checked=New-RouterVPNOrderedConnectPayload $draft.Tag $store
        if((@($checked.nodes.id)-join',')-cne(@($ordered.id)-join',')-or(@($checked.nodes.mode)-join',')-cne(@($ordered.mode)-join',')){throw 'The ordered draft changed before it could be captured.'}
        $draftTokens=$checked.expected_profile_tokens
    }
    foreach($member in $ids){
        $matches=@($profiles|Where-Object{[string](Get-RouterVPNOrderedValue $_ 'id')-ceq$member})
        if($matches.Count-ne1){throw 'A captured connection node is missing or duplicated.'}
        $token=Get-RouterVPNOrderedValue $matches[0] 'profile_token'
        if($token-isnot[string]-or$token-cnotmatch'\A[0-9a-f]{64}\z'-or($null-ne$draftTokens-and(Get-RouterVPNOrderedValue $draftTokens $member)-cne$token)){throw 'A captured node changed. Refresh before changing a connection profile.'}
        $tokens[$member]=$token
    }
    return [pscustomobject]@{SelectedID=$id;Tokens=$tokens;Graph=$graphCopy;Store=$store;ViewKey=(Get-RouterVPNSetupViewKey $Owner);Loading=$Loading}
}

function global:Confirm-RouterVPNSetupResponse {
    param($Owner,$Capture,$Response)
    $selected=$Owner.FindName('UnifiedNodeCombo')
    if($null-eq$selected-or[string]$selected.SelectedValue-cne$Capture.SelectedID-or-not[object]::ReferenceEquals($selected.Tag,$Capture.Store)-or(Get-RouterVPNSetupViewKey $Owner)-cne$Capture.ViewKey){throw 'The displayed selection changed while the profile request was completing. Refresh before continuing.'}
    foreach($id in $Capture.Tokens.Keys){
        $matches=@((Get-RouterVPNOrderedValue $selected.Tag 'profiles' @())|Where-Object{[string](Get-RouterVPNOrderedValue $_ 'id')-ceq$id})
        if($matches.Count-ne1-or(Get-RouterVPNOrderedValue $matches[0] 'profile_token')-cne$Capture.Tokens[$id]){throw 'A captured node changed while the profile request was completing.'}
    }
    $resultID=Get-RouterVPNOrderedValue $Response 'selected_node_id'
    if($resultID-isnot[string]-or(-not$Capture.Loading-and$resultID-cne$Capture.SelectedID)){throw 'The profile response did not confirm its original selected node.'}
    $ids=@(Get-RouterVPNSetupGraphIDs $Response $resultID)
    $rawTokens=Get-RouterVPNOrderedValue $Response 'profile_tokens';$tokens=@{}
    $keys=if($rawTokens-is[Collections.IDictionary]){@($rawTokens.Keys)}elseif($null-ne$rawTokens){@($rawTokens.PSObject.Properties.Name)}else{@()}
    if($keys.Count-ne$ids.Count){throw 'The profile response did not return its exact node source inventory.'}
    foreach($id in $ids){
        $token=Get-RouterVPNOrderedValue $rawTokens $id
        if($keys-cnotcontains$id-or$token-isnot[string]-or$token-cnotmatch'\A[0-9a-f]{64}\z'){throw 'The profile response contains an invalid node source receipt.'}
        if(-not$Capture.Loading-and$token-cne$Capture.Tokens[$id]){throw 'The saved profile response replaced an original node source.'}
        $tokens[$id]=$token
    }
    $nodes=Get-RouterVPNOrderedValue $Response 'multihop_nodes'
    if($null-ne$nodes-and@($nodes).Count-gt0){
        $nodes=@(Copy-RouterVPNOrderedNodes $nodes $resultID)
        $profile=Get-RouterVPNOrderedValue $Response 'profile'
        if((Get-RouterVPNOrderedValue $Response 'multihop_enabled')-isnot[bool]-or-not$Response.multihop_enabled-or(Get-RouterVPNOrderedValue $Response 'multihop_execution')-cnotin@('local','server','auto')-or(Get-RouterVPNOrderedValue $profile 'mode')-cne$nodes[-1].mode){throw 'The profile response changed the ordered execution or final mode.'}
        foreach($key in @('multihop_entry_id','multihop_exit_id','multihop_entry_mode','multihop_exit_mode')){if([string](Get-RouterVPNOrderedValue $Response $key)){throw 'The profile response mixes ordered and pair selections.'}}
    }
    if(-not$Capture.Loading){
        $expectedNodes=Get-RouterVPNOrderedValue $Capture.Graph 'multihop_nodes'
        if($null-ne$expectedNodes-and@($expectedNodes).Count-gt0-and(Get-RouterVPNOrderedValue $Response 'multihop_execution')-cne(Get-RouterVPNOrderedValue $Capture.Graph 'multihop_execution')){throw 'The saved profile response changed the requested ordered execution.'}
        if(($null-ne$nodes-and@($nodes).Count-gt0)-or($null-ne$expectedNodes-and@($expectedNodes).Count-gt0)){
            if($null-eq$nodes-or$null-eq$expectedNodes-or@($nodes).Count-ne@($expectedNodes).Count-or(@($nodes.id)-join',')-cne(@($expectedNodes.id)-join',')-or(@($nodes.mode)-join',')-cne(@($expectedNodes.mode)-join',')){throw 'The saved profile response changed the original ordered path.'}
        }
        if([bool](Get-RouterVPNOrderedValue $Response 'multihop_enabled' $false)-ne[bool](Get-RouterVPNOrderedValue $Capture.Graph 'multihop_enabled' $false)){throw 'The saved profile response changed the requested multihop choice.'}
        foreach($key in @('multihop_entry_id','multihop_exit_id')){if([string](Get-RouterVPNOrderedValue $Response $key)-cne[string](Get-RouterVPNOrderedValue $Capture.Graph $key)){throw 'The saved profile response changed the requested node selection.'}}
    }
    return $tokens
}

function global:Invoke-RouterVPNConnectionSetup {
    param([string]$BaseUrl,$Owner,[ValidateSet('save','update','load')][string]$Operation,[hashtable]$Body)
    $capture=Get-RouterVPNSetupCapture $Owner $Body ($Operation-ceq'load')
    $request=@{};foreach($key in $Body.Keys){$request[$key]=$Body[$key]}
    $request.expected_selected_node_id=$capture.SelectedID;$request.expected_profile_tokens=$capture.Tokens
    # Retire an older catalog request before publishing a new selection. The
    # existing refresh owner will drain it without applying its stale reply.
    if($null-ne${function:CancelUnifiedRefreshAsync}){[void](CancelUnifiedRefreshAsync)}
    try{
        $paths=@{save='/api/connection-profile/setup/save';update='/api/connection-profile/setup/update';load='/api/connection-profile/setup/load'}
        $response=Invoke-RouterVPNControllerRequest -Uri ($BaseUrl.TrimEnd('/')+$paths[$Operation]) -Method Post -ContentType 'application/json' -Body ($request|ConvertTo-Json -Depth 16 -Compress) -TimeoutSec 12
        $tokens=Confirm-RouterVPNSetupResponse $Owner $capture $response
        if($Operation-ceq'load'){
            $selected=$Owner.FindName('UnifiedNodeCombo')
            $catalog=$capture.Store|ConvertTo-Json -Depth 32|ConvertFrom-Json
            foreach($id in $tokens.Keys){
                $matches=@($catalog.profiles|Where-Object{[string]$_.id-ceq$id})
                if($matches.Count-ne1){throw 'The loaded profile contains a node outside this catalog. Refresh before continuing.'}
                $matches[0]|Add-Member -NotePropertyName profile_token -NotePropertyValue $tokens[$id] -Force
            }
            $resultID=[string]$response.selected_node_id
            $control=@($catalog.profiles|Where-Object{[string]$_.id-ceq$resultID})[0]
            foreach($key in @('multihop_enabled','multihop_nodes','multihop_entry_id','multihop_exit_id','multihop_entry_mode','multihop_exit_mode','multihop_execution')){
                $control|Add-Member -NotePropertyName $key -NotePropertyValue (Get-RouterVPNOrderedValue $response $key) -Force
            }
            $catalog.selected_id=$resultID
            $selected.Tag=$catalog;$selected.SelectedValue=$resultID
        }else{
            $nodes=Get-RouterVPNOrderedValue $response 'multihop_nodes'
            if($null-ne$nodes-and@($nodes).Count-gt0){Set-RouterVPNLoadedOrderedSnapshot $Owner $response}
        }
        return $response
    }catch{
        # The controller may have applied Load before a timeout or malformed
        # response. Retire only this original display, never a newer choice.
        $selected=$Owner.FindName('UnifiedNodeCombo')
        if($Operation-ceq'load'-and$null-ne$selected-and[string]$selected.SelectedValue-ceq$capture.SelectedID-and[object]::ReferenceEquals($selected.Tag,$capture.Store)-and(Get-RouterVPNSetupViewKey $Owner)-ceq$capture.ViewKey){$selected.SelectedValue=$null}
        throw
    }
}

function global:Apply-RouterVPNLoadedConnectionSnapshot {
    param([System.Windows.Window]$Owner,$Loaded)
    if($null -eq $Owner){return}
    Set-RouterVPNLoadedOrderedSnapshot $Owner $Loaded
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

function global:Show-RouterVPNDeviceMTU {
    param([string]$BaseUrl,$Owner)
    $uri=$BaseUrl.TrimEnd('/')+'/api/device/mtu'
    $policy=Invoke-RouterVPNControllerRequest -Uri $uri -Method Get -TimeoutSec 5
    if([string]$policy.token-cnotmatch '\A[0-9a-f]{64}\z'-or$policy.editable-isnot[bool]-or($policy.fixed_mtu-isnot[int]-and$policy.fixed_mtu-isnot[long])-or($policy.fixed_mtu-ne0-and($policy.fixed_mtu-lt1280-or$policy.fixed_mtu-gt9000))){throw 'Reopen Settings to capture the current device MTU.'}
    [xml]$x=@"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="MTU for this device" SizeToContent="WidthAndHeight" ResizeMode="NoResize" WindowStartupLocation="CenterOwner"><StackPanel Margin="18" Width="340"><ComboBox Name="Scope"><ComboBoxItem Content="Use the MTU set in each configuration"/><ComboBoxItem Content="Fixed for all connections"/></ComboBox><TextBlock Text="Fixed MTU in bytes (1280–9000)" Margin="0,12,0,4"/><TextBox Name="Value"/><TextBlock Name="Message" Margin="0,12" TextWrapping="Wrap"/><StackPanel Orientation="Horizontal" HorizontalAlignment="Right"><Button Name="Cancel" Content="Close" Padding="9,5"/><Button Name="Save" Content="Save device MTU" Margin="8,0,0,0" Padding="9,5"/></StackPanel></StackPanel></Window>
"@
    $dialog=[Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $x));$dialog.Owner=$Owner
    $scope=$dialog.FindName('Scope');$value=$dialog.FindName('Value');$save=$dialog.FindName('Save');$message=$dialog.FindName('Message')
    $scope.SelectedIndex=if($policy.fixed_mtu-eq0){0}else{1};$value.Text=if($policy.fixed_mtu-eq0){''}else{[string]$policy.fixed_mtu}
    $save.IsEnabled=$policy.editable;$scope.IsEnabled=$policy.editable;$value.IsEnabled=$policy.editable-and$scope.SelectedIndex-eq1
    $message.Text=if($policy.editable){'The device preference applies to the next connection.'}else{'Disconnect before changing the device MTU.'}
    $scope.Add_SelectionChanged({$value.IsEnabled=$policy.editable-and$scope.SelectedIndex-eq1})
    $dialog.FindName('Cancel').Add_Click({$dialog.Close()})
    $save.Add_Click({try{
        $wanted=0
        if($scope.SelectedIndex-eq1){$raw=$value.Text.Trim();if(-not[int]::TryParse($raw,[ref]$wanted)-or[string]$wanted-cne$raw-or$wanted-lt1280-or$wanted-gt9000){throw 'Enter an MTU from 1280 through 9000 bytes.'}}
        $body=@{token=[string]$policy.token;fixed_mtu=$wanted}|ConvertTo-Json -Compress
        $reply=Invoke-RouterVPNControllerRequest -Uri $uri -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 8
        if([string]$reply.token-cnotmatch '\A[0-9a-f]{64}\z'-or$reply.token-ceq$policy.token-or$reply.fixed_mtu-ne$wanted){throw 'The controller did not confirm the device MTU change.'}
        $save.IsEnabled=$false;$scope.IsEnabled=$false;$value.IsEnabled=$false
        $message.Text=if($wanted){'Device MTU set to '+$wanted+' bytes for the next connection.'}else{'Using the MTU and Retest settings for each configuration.'}
    }catch{$message.Text=$_.Exception.Message}})
    [void]$dialog.ShowDialog()
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
<Button Name="DeviceWideMTU" Content="MTU for all connections on this device…" HorizontalAlignment="Left" Padding="8,5" Margin="0,5,0,8"/>
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
    $dialog.FindName('DeviceWideMTU').Add_Click({try{Show-RouterVPNDeviceMTU -BaseUrl $BaseUrl -Owner $dialog}catch{[void][Windows.MessageBox]::Show($dialog,$_.Exception.Message,'Device MTU')}})
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
        if($visible.ContainsKey('multihop_nodes')){
            $body.multihop_nodes=@(Copy-RouterVPNOrderedNodes $visible.multihop_nodes ([string]$Owner.FindName('UnifiedNodeCombo').SelectedValue))
            $body.mode=[string]$body.multihop_nodes[-1].mode;$body.custom_layers=@()
            foreach($key in @('multihop_entry_id','multihop_exit_id','multihop_entry_mode','multihop_exit_mode')){[void]$body.Remove($key)}
        }
        if($ID){$body.id=$ID}
        return $body
    }
    $profileCombo.Add_SelectionChanged({if($profileCombo.SelectedItem){$profileName.Text=[string]$profileCombo.SelectedItem.name}})
    $dialog.FindName('ProfileRefresh').Add_Click({& $refreshProfiles})
    $profileAdd.Add_Click({try{if(& $syncProfileMutationState){throw 'Disconnect Router VPN before adding a connection profile.'};$name=$profileName.Text.Trim();if(-not$name){throw 'Enter a profile name.'};$body=& $makeSetupBody $name '';$r=Invoke-RouterVPNConnectionSetup -BaseUrl $BaseUrl -Owner $Owner -Operation 'save' -Body $body;$profileStatus.Text="Added $($r.profile.name) • $($r.profile.mode) • exact hop setup saved";& $refreshProfiles}catch{$profileStatus.Text='Add failed: '+$_.Exception.Message}})
    $profileUpdate.Add_Click({try{if(& $syncProfileMutationState){throw 'Disconnect Router VPN before updating a connection profile.'};if(-not$profileCombo.SelectedValue){throw 'Select a saved profile.'};$name=$profileName.Text.Trim();if(-not$name){throw 'Enter a profile name.'};$body=& $makeSetupBody $name ([string]$profileCombo.SelectedValue);$r=Invoke-RouterVPNConnectionSetup -BaseUrl $BaseUrl -Owner $Owner -Operation 'update' -Body $body;$profileStatus.Text="Updated $($r.profile.name) • exact hop setup refreshed";& $refreshProfiles}catch{$profileStatus.Text='Update failed: '+$_.Exception.Message}})
    $profileLoad.Add_Click({try{if(& $syncProfileMutationState){throw 'Disconnect Router VPN before loading a connection profile.'};if(-not$profileCombo.SelectedValue){throw 'Select a saved profile.'};$body=@{id=[string]$profileCombo.SelectedValue};$r=Invoke-RouterVPNConnectionSetup -BaseUrl $BaseUrl -Owner $Owner -Operation 'load' -Body $body;Set-RouterVPNLoadedModeSnapshot -Loaded $r;Apply-RouterVPNLoadedConnectionSnapshot -Owner $Owner -Loaded $r;if($null -ne $OnConnectionProfileLoaded){& $OnConnectionProfileLoaded $r};$profileStatus.Text="Loaded $($r.profile.name) • node $($r.selected_node_id) • mode $($r.mode) • exact hop setup restored. Connect separately to prove it."}catch{$profileStatus.Text='Load failed: '+$_.Exception.Message}})
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
