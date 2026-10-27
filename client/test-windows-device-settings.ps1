param([string]$Root=(Split-Path $PSScriptRoot -Parent),[string]$Source='', [string]$UnifiedSource='', [switch]$WPF)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2
if(-not $Source){$Source=Join-Path $Root 'client/RouterVPN-Windows-ProfileSettings.ps1'}
if(-not $UnifiedSource){$UnifiedSource=Join-Path $Root 'client/RouterVPN-Windows-UnifiedShell.ps1'}
$Text=[IO.File]::ReadAllText($Source,[Text.Encoding]::UTF8)
$Tokens=$null;$ParseErrors=$null
[void][Management.Automation.Language.Parser]::ParseInput($Text,[ref]$Tokens,[ref]$ParseErrors)
if($ParseErrors.Count){throw ('CONTROL whole-source parse: '+($ParseErrors.Message -join '; '))}
. ([ScriptBlock]::Create($Text))
$script:Checks=0
function Check([bool]$Condition,[string]$Message){if(-not $Condition){throw ('CONTROL '+$Message)};$script:Checks++}
function Reject([scriptblock]$Action,[string]$Message){$Caught=$false;try{[void](& $Action)}catch{$Caught=$true};Check $Caught $Message}
# Windows PowerShell 5.1 reads this BOM-less -File fixture through its ANSI
# code page. Keep the expected label ASCII in source, while still comparing
# the actual UTF-8 shipping XAML and rendered control to the exact em dash.
$script:AutoMTULabel='Auto '+[char]0x2014+' default'
$SettingsXAML=[regex]::Match($Text,"(?s)\[xml\]\`$xaml = @'\r?\n(.*?)\r?\n'@")
Check $SettingsXAML.Success 'shipping Settings XAML missing'
[xml]$SettingsXML=$SettingsXAML.Groups[1].Value
$AutoMTUItem=$SettingsXML.SelectSingleNode("//*[local-name()='ComboBox' and @Name='MTUPolicy']/*[local-name()='ComboBoxItem' and @Tag='auto']")
Check ($null -ne $AutoMTUItem -and [string]$AutoMTUItem.Content -ceq $script:AutoMTULabel) 'Tor Auto claimed a measured path'
function New-Capture {
    [pscustomobject]@{profile_id='node "quoted"';profile_token=('b'*64);node_kind='external';protocol='shadowsocks';jumbo_tun=$false;jumbo_tun_supported=$false;daita_enabled=$false;daita_rate_kbps=0;tor_cover_supported=$false;tor_cover_note='Outgoing Tor cells only; Connect requires a fresh server receipt.';device_policy_supported=$true;device_policy_reason='';home_lan_access=$true;kill_switch_policy='off';ipv6_mode='on';mtu_policy='auto';manual_mtu=0;effective_mtu=1420;mtu_source='historical fixture';startup_mode='smart-auto';auto_connect=$false;note='Save while disconnected.';password='never-copy';dns_host='keep-resolver';entry_id='independent-entry'}
}
function New-Arguments($Capture) {
    @{Captured=$Capture;DisplayedProfileID=$Capture.profile_id;HomeLANAccess=$false;KillSwitchPolicy='always';IPv6Mode='off';MTUPolicy='manual';ManualMTU=1412}
}
$script:Capture=New-Capture;$script:Busy=$false;$script:Unavailable=$false;$script:PostFailure=$false;$script:ResponseMutation=@{}
$script:Posts=[Collections.Generic.List[object]]::new();$script:Gets=[Collections.Generic.List[string]]::new()
function global:Invoke-RestMethod {
    param($Uri,$Method,$ContentType,$Body,$TimeoutSec)
    $Path=([uri]$Uri).AbsolutePath
    if($Method -eq 'Get'){
        [void]$script:Gets.Add($Path)
        switch($Path){
            '/api/status' {if($script:Unavailable){throw 'controller unavailable'};return [pscustomobject]@{connected=$script:Busy;phase=$(if($script:Busy){'connected'}else{'disconnected'})}}
            '/api/profile/device' {return $script:Capture}
            '/api/profile/startup' {return [pscustomobject]@{profile_id=$script:Capture.profile_id;profile_token=('c'*64);node_kind='external';startup_mode=$script:Capture.startup_mode;auto_connect=$script:Capture.auto_connect}}
            '/api/connection-profiles' {return [pscustomobject]@{profiles=@()}}
            default {throw ('unexpected GET '+$Path)}
        }
    }
    if($Method -ne 'Post' -or $Path -notin @('/api/profile/device','/api/profile/startup','/api/profile/settings')){throw 'unexpected POST route'}
    if($script:PostFailure){throw 'stale captured source'}
    $Value=$Body|ConvertFrom-Json
    Check (-not ($Path -ceq '/api/profile/settings' -and $null -ne $Value.PSObject.Properties['profile_token'])) 'device save did not use its own endpoint'
    [void]$script:Posts.Add([pscustomobject]@{Path=$Path;Body=$Value})
    if($Path -ceq '/api/profile/device'){
        $Response=@{};foreach($Property in $script:Capture.PSObject.Properties){$Response[$Property.Name]=$Property.Value}
        foreach($Property in $Value.PSObject.Properties){$Response[$Property.Name]=$Property.Value}
        $Response.profile_token='d'*64
        foreach($Key in $script:ResponseMutation.Keys){$Response[$Key]=$script:ResponseMutation[$Key]}
        return [pscustomobject]$Response
    }
    return $Value
}

$Captured=Get-RouterVPNProfileDevice -BaseUrl 'http://127.0.0.1:8788/' -DisplayedProfileID $script:Capture.profile_id
Check ($Captured.profile_token -ceq ('b'*64) -and $script:Gets[0] -ceq '/api/profile/device') 'captured GET route or source changed'
foreach($LAN in @($false,$true)){
    foreach($Kill in @('off','on-connect','always')){
        foreach($IPv6 in @('on','auto','off')){
            foreach($MTU in @('auto','default','manual')){
                $Manual=if($MTU -ceq 'manual'){1280}else{0}
                $Body=New-RouterVPNProfileDevicePayload -Captured $Captured -DisplayedProfileID $Captured.profile_id -HomeLANAccess $LAN -KillSwitchPolicy $Kill -IPv6Mode $IPv6 -MTUPolicy $MTU -ManualMTU $Manual
                Check (($Body.Keys|Sort-Object)-join ',' -ceq 'home_lan_access,ipv6_mode,kill_switch_policy,manual_mtu,mtu_policy,profile_id,profile_token') 'device payload copied unrelated or private fields'
                Check ($Body.profile_id -ceq $Captured.profile_id -and $Body.profile_token -ceq ('b'*64)) 'device payload replaced captured identity'
                Check ($Body.home_lan_access -is [bool] -and $Body.home_lan_access -eq $LAN -and $Body.kill_switch_policy -ceq $Kill -and $Body.ipv6_mode -ceq $IPv6) 'device payload changed selected protection policy'
                Check ($Body.manual_mtu -is [int] -and $Body.manual_mtu -eq $Manual -and $Body.mtu_policy -ceq $MTU) 'device payload changed requested MTU'
            }
        }
    }
}
$ArgsForSave=New-Arguments $Captured
$Body=New-RouterVPNProfileDevicePayload @ArgsForSave -StartupMode 'auto' -AutoConnect $false
Check ($Body.Count -eq 7 -and -not $Body.ContainsKey('startup_mode')) 'unchanged smart-auto display alias was overwritten'
$Body=New-RouterVPNProfileDevicePayload @ArgsForSave -StartupMode 'auto' -AutoConnect $true
Check ($Body.Count -eq 9 -and $Body.startup_mode -ceq 'smart-auto' -and $Body.auto_connect -is [bool] -and $Body.auto_connect) 'auto-connect edit lost captured startup alias'
$Body=New-RouterVPNProfileDevicePayload @ArgsForSave -StartupMode 'manual' -AutoConnect $false
Check ($Body.Count -eq 9 -and $Body.startup_mode -ceq 'manual' -and -not $Body.auto_connect) 'explicit startup edit did not form one atomic device payload'
Reject {New-RouterVPNProfileDevicePayload @ArgsForSave -StartupMode 'manual' -AutoConnect $true} 'manual auto-connect accepted'
Reject {New-RouterVPNProfileDevicePayload @ArgsForSave -StartupMode 'auto'} 'missing startup Boolean accepted'
Reject {New-RouterVPNProfileDevicePayload @ArgsForSave -AutoConnect $false} 'missing startup mode accepted'
Reject {New-RouterVPNProfileDevicePayload @ArgsForSave -StartupMode 'last' -AutoConnect 'false'} 'coerced startup Boolean accepted'
foreach($Bad in @(-1,0,1279,9001,'1.5','', $null,[double]1280,$true,'NaN','1e3','1280 ',"1280`n")){
    $Invalid=$ArgsForSave.Clone();$Invalid.ManualMTU=$Bad
    Reject {New-RouterVPNProfileDevicePayload @Invalid} 'invalid fixed MTU accepted'
}
foreach($Policy in @('auto','default')){
    $Invalid=$ArgsForSave.Clone();$Invalid.MTUPolicy=$Policy
    Reject {New-RouterVPNProfileDevicePayload @Invalid} 'unused fixed MTU entered Auto or Default payload'
}
foreach($Entry in @(@('HomeLANAccess','false'),@('KillSwitchPolicy','automatic'),@('IPv6Mode','ON'),@('MTUPolicy','fixed'),@('DisplayedProfileID','replacement'))){
    $Invalid=$ArgsForSave.Clone();$Invalid[$Entry[0]]=$Entry[1]
    Reject {New-RouterVPNProfileDevicePayload @Invalid} ('invalid device field accepted '+$Entry[0])
}
foreach($Field in @('profile_id','profile_token','node_kind','device_policy_supported')){
    $BadCapture=New-Capture
    switch($Field){'profile_id'{$BadCapture.profile_id='replacement'};'profile_token'{$BadCapture.profile_token='unbound'};'node_kind'{$BadCapture.node_kind='router'};'device_policy_supported'{$BadCapture.device_policy_supported='true'}}
    $script:Capture=$BadCapture
    Reject {Get-RouterVPNProfileDevice -BaseUrl 'http://127.0.0.1:8788' -DisplayedProfileID $Captured.profile_id} ('invalid GET capture accepted '+$Field)
}
$script:Capture=New-Capture;$script:Capture.profile_token=('b'*64)+"`n"
Reject {Get-RouterVPNProfileDevice -BaseUrl 'http://127.0.0.1:8788' -DisplayedProfileID $Captured.profile_id} 'noncanonical captured token accepted'
$script:Capture=New-Capture
$Unsupported=New-Capture;$Unsupported.device_policy_supported=$false
$Invalid=New-Arguments $Unsupported
Reject {New-RouterVPNProfileDevicePayload @Invalid} 'unsupported runtime received device policy'
$Before=$script:Posts.Count
$Result=Save-RouterVPNProfileDevice -BaseUrl 'http://127.0.0.1:8788/' @ArgsForSave -StartupMode 'auto' -AutoConnect $false
Check ($script:Posts.Count -eq $Before+1 -and $script:Posts[$Before].Path -ceq '/api/profile/device') 'device save did not use its own endpoint'
Check ($Result.profile_id -ceq $Captured.profile_id -and $Result.profile_token -ceq ('d'*64) -and $Result.manual_mtu -eq 1412) 'device save lost its confirmed captured policy'
foreach($Initial in @($false,$true)){
    foreach($Policy in @('auto','default','manual')){
        $Tor=New-Capture;$Tor.protocol='tor-bridge';$Tor.jumbo_tun=$Initial;$Tor.jumbo_tun_supported=$true
        $ArgsForJumbo=New-Arguments $Tor;$ArgsForJumbo.MTUPolicy=$Policy;$ArgsForJumbo.ManualMTU=if($Policy -ceq 'manual'){9000}else{0}
        foreach($Selected in @($false,$true)){
            $Body=New-RouterVPNProfileDevicePayload @ArgsForJumbo -JumboTUN $Selected
            Check ($Body.ContainsKey('jumbo_tun') -eq ($Selected -ne $Initial)) 'Jumbo payload lost explicit-edit ownership'
            if($Body.ContainsKey('jumbo_tun')){Check ($Body.jumbo_tun -is [bool] -and $Body.jumbo_tun -eq $Selected) 'Jumbo payload changed selected Boolean'}
            Check ($Body.mtu_policy -ceq $Policy -and $Body.manual_mtu -eq $ArgsForJumbo.ManualMTU) 'Jumbo silently rewrote requested MTU policy'
        }
    }
}
$Tor=New-Capture;$Tor.protocol='tor-bridge';$Tor.jumbo_tun_supported=$true
$ArgsForJumbo=New-Arguments $Tor
Reject {New-RouterVPNProfileDevicePayload @ArgsForJumbo -JumboTUN $true} 'Jumbo accepted conflicting Fixed MTU'
$ArgsForJumbo.MTUPolicy='auto';$ArgsForJumbo.ManualMTU=0
$Body=New-RouterVPNProfileDevicePayload @ArgsForJumbo -JumboTUN $true -StartupMode 'auto' -AutoConnect $true
Check ($Body.Count -eq 10 -and $Body.jumbo_tun -and $Body.startup_mode -ceq 'smart-auto') 'Jumbo lost atomic captured startup pair'
foreach($Bad in @('true',1,$null)){Reject {New-RouterVPNProfileDevicePayload @ArgsForJumbo -JumboTUN $Bad} 'Jumbo accepted a coerced Boolean'}
$Ordinary=New-Arguments (New-Capture);$Ordinary.MTUPolicy='auto';$Ordinary.ManualMTU=0
Reject {New-RouterVPNProfileDevicePayload @Ordinary -JumboTUN $true} 'unsupported Jumbo changed'
$Legacy=New-Capture;$Legacy.PSObject.Properties.Remove('jumbo_tun');$Legacy.PSObject.Properties.Remove('jumbo_tun_supported')
$LegacyArgs=New-Arguments $Legacy
Check (-not (New-RouterVPNProfileDevicePayload @LegacyArgs).ContainsKey('jumbo_tun')) 'missing Jumbo capability invented a write'
Reject {New-RouterVPNProfileDevicePayload @LegacyArgs -JumboTUN $false} 'missing Jumbo capability accepted explicit mutation'
foreach($Field in @('jumbo_tun','jumbo_tun_supported')){
    $Partial=New-Capture;$Partial.PSObject.Properties.Remove($Field)
    Reject {Assert-RouterVPNProfileDeviceCapture -Captured $Partial -DisplayedProfileID $Partial.profile_id} 'partial Jumbo capability accepted'
    foreach($Bad in @('true',1,$null)){
        $Malformed=New-Capture;$Malformed.$Field=$Bad
        Reject {Assert-RouterVPNProfileDeviceCapture -Captured $Malformed -DisplayedProfileID $Malformed.profile_id} 'malformed Jumbo capability accepted'
    }
}
$script:Capture=$Tor
foreach($Field in @('jumbo_tun','jumbo_tun_supported','home_lan_access','mtu_policy','profile_token')){
    $script:ResponseMutation=@{}
    $script:ResponseMutation[$Field]=switch($Field){'jumbo_tun'{$false};'jumbo_tun_supported'{$false};'home_lan_access'{$true};'mtu_policy'{'manual'};'profile_token'{'unbound'}}
    Reject {Save-RouterVPNProfileDevice -BaseUrl 'http://127.0.0.1:8788' @ArgsForJumbo -JumboTUN $true} ('unconfirmed saved policy announced success '+$Field)
}
$script:ResponseMutation=@{};$script:Capture=New-Capture
foreach($Protocol in @('tor','tor-bridge')){
    foreach($Initial in @($false,$true)){
        foreach($InitialRate in @(0,32,64,192)){
            $TorCover=New-Capture;$TorCover.protocol=$Protocol;$TorCover.tor_cover_supported=$true
            $TorCover.daita_enabled=$Initial;$TorCover.daita_rate_kbps=$InitialRate
            $CoverArguments=New-Arguments $TorCover;$script:Capture=$TorCover
            foreach($Selected in @($false,$true)){
                foreach($Rate in @(0,32,64,192)){
                    $Body=New-RouterVPNProfileDevicePayload @CoverArguments -DAITAEnabled $Selected -DAITARateKbps ([string]$Rate)
                    $Changed=$Selected-ne$Initial-or$Rate-ne$InitialRate
                    Check ($Body.ContainsKey('daita_enabled')-eq$Changed-and$Body.ContainsKey('daita_rate_kbps')-eq$Changed) 'cover pair lost explicit edit ownership'
                    Check ($Body.Count-eq$(if($Changed){9}else{7})-and$Body.profile_token-ceq('b'*64)) 'cover edit copied unrelated fields or replaced its token'
                    if($Changed){Check ($Body.daita_enabled-is[bool]-and$Body.daita_enabled-eq$Selected-and$Body.daita_rate_kbps-is[int]-and$Body.daita_rate_kbps-eq$Rate) 'cover flag or exact dormant budget was replaced'}
                    $Saved=Save-RouterVPNProfileDevice -BaseUrl 'http://127.0.0.1:8788' @CoverArguments -DAITAEnabled $Selected -DAITARateKbps ([string]$Rate)
                    Check ($Saved.daita_enabled-eq$Selected-and$Saved.daita_rate_kbps-eq$Rate) 'cover transaction lost the confirmed pair'
                }
            }
        }
    }
}
$TorCover=New-Capture;$TorCover.protocol='tor';$TorCover.tor_cover_supported=$true;$TorCover.daita_rate_kbps=64
$CoverArguments=New-Arguments $TorCover;$script:Capture=$TorCover
foreach($Rate in @(-1,1,31,193,999,1.5,'64.0','6.4e1','+64','', $null,$true)){
    Reject {New-RouterVPNProfileDevicePayload @CoverArguments -DAITAEnabled $true -DAITARateKbps $Rate} 'invalid cover budget was accepted'
}
foreach($Enabled in @('true',1,$null)){Reject {New-RouterVPNProfileDevicePayload @CoverArguments -DAITAEnabled $Enabled -DAITARateKbps 64} 'coerced cover Boolean was accepted'}
Reject {New-RouterVPNProfileDevicePayload @CoverArguments -DAITAEnabled $true} 'cover flag without budget was accepted'
Reject {New-RouterVPNProfileDevicePayload @CoverArguments -DAITARateKbps 64} 'cover budget without flag was accepted'
foreach($Field in @('daita_enabled','daita_rate_kbps','tor_cover_supported')){
    $Partial=New-Capture;$Partial.PSObject.Properties.Remove($Field)
    Reject {Assert-RouterVPNProfileDeviceCapture -Captured $Partial -DisplayedProfileID $Partial.profile_id} 'partial cover capture was accepted'
    foreach($Bad in @('false',$null)){
        $Malformed=New-Capture;$Malformed.$Field=$Bad
        Reject {Assert-RouterVPNProfileDeviceCapture -Captured $Malformed -DisplayedProfileID $Malformed.profile_id} 'malformed cover capture was accepted'
    }
}
foreach($BadRate in @(-1,31,193,64.5,$true)){
    $Malformed=New-Capture;$Malformed.daita_rate_kbps=$BadRate
    Reject {Assert-RouterVPNProfileDeviceCapture -Captured $Malformed -DisplayedProfileID $Malformed.profile_id} 'malformed captured cover budget was accepted'
}
$Malformed=New-Capture;$Malformed.tor_cover_supported=$true
Reject {Assert-RouterVPNProfileDeviceCapture -Captured $Malformed -DisplayedProfileID $Malformed.profile_id} 'ordinary node advertised Tor cover support'
$LocalCover=New-Capture;$LocalCover.protocol='tor';$LocalCover.daita_rate_kbps=64
$LocalArguments=New-Arguments $LocalCover
Check (-not (New-RouterVPNProfileDevicePayload @LocalArguments -DAITAEnabled $false -DAITARateKbps 64).ContainsKey('daita_enabled')) 'unchanged unsupported cover invented a write'
Reject {New-RouterVPNProfileDevicePayload @LocalArguments -DAITAEnabled $true -DAITARateKbps 64} 'unsupported path changed cover traffic'
Reject {New-RouterVPNProfileDevicePayload @LocalArguments -DAITAEnabled $false -DAITARateKbps 32} 'unsupported path changed dormant budget'
$LegacyCover=New-Capture;foreach($Field in @('daita_enabled','daita_rate_kbps','tor_cover_supported')){$LegacyCover.PSObject.Properties.Remove($Field)}
$LegacyArguments=New-Arguments $LegacyCover
Check (-not (New-RouterVPNProfileDevicePayload @LegacyArguments).ContainsKey('daita_enabled')) 'legacy capture invented cover settings'
Reject {New-RouterVPNProfileDevicePayload @LegacyArguments -DAITAEnabled $false -DAITARateKbps 0} 'legacy capture accepted cover mutation'
foreach($Field in @('daita_enabled','daita_rate_kbps','tor_cover_supported')){
    $script:ResponseMutation=@{};$script:ResponseMutation[$Field]=switch($Field){'daita_enabled'{$false};'daita_rate_kbps'{192};'tor_cover_supported'{$false}}
    Reject {Save-RouterVPNProfileDevice -BaseUrl 'http://127.0.0.1:8788' @CoverArguments -DAITAEnabled $true -DAITARateKbps 64} ('unconfirmed cover announced success '+$Field)
}
$script:ResponseMutation=@{daita_rate_kbps=192}
Reject {Save-RouterVPNProfileDevice -BaseUrl 'http://127.0.0.1:8788' @CoverArguments} 'omitted cover budget changed without confirmation'
$script:ResponseMutation=@{};$script:Capture=New-Capture
$script:Busy=$true;$Before=$script:Posts.Count
Reject {Save-RouterVPNProfileDevice -BaseUrl 'http://127.0.0.1:8788' @ArgsForSave} 'active device policy was submitted'
Check ($script:Posts.Count -eq $Before) 'active device save reached the server'
$script:Busy=$false;$script:Unavailable=$true
Reject {Save-RouterVPNProfileDevice -BaseUrl 'http://127.0.0.1:8788' @ArgsForSave} 'unavailable status permitted save'
Check ($script:Posts.Count -eq $Before) 'unavailable status submitted device policy'
$script:Unavailable=$false;$script:PostFailure=$true
Reject {Save-RouterVPNProfileDevice -BaseUrl 'http://127.0.0.1:8788' @ArgsForSave} 'server stale-source rejection was hidden'
$script:PostFailure=$false
[void](Save-RouterVPNProfileSettings -BaseUrl 'http://127.0.0.1:8788' -Body @{home_lan_access=$false})
Check ($script:Posts[$script:Posts.Count-1].Path -ceq '/api/profile/settings') 'Router settings endpoint changed'

# Materialize the launcher's shipping composition, then invoke its actual
# Settings callback. Only the controller and WPF boundary are replaced here.
$Client=Join-Path $Root 'client'
$Launcher=[IO.File]::ReadAllText((Join-Path $Client 'RouterVPN-Windows-App.ps1'),[Text.Encoding]::UTF8)
$HelpTransform=@([ScriptBlock]::Create($Launcher).Ast.FindAll({param($Node)$Node -is [Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq 'Set-RouterVPNProductHelpBinding'},$true))
Check ($HelpTransform.Count -eq 1) 'shipping Help transform missing'
. ([ScriptBlock]::Create($HelpTransform[0].Extent.Text))
$LoadStart=$Launcher.IndexOf('$ProfileSettingsHelpers=');$LoadEnd=$Launcher.IndexOf('# The shipping Windows product',$LoadStart)
$ComposeStart=$Launcher.IndexOf('$Product=Join-Path');$ComposeEnd=$Launcher.IndexOf('$ProductScript=[ScriptBlock]::Create($ProductSource)',$ComposeStart)
Check ($LoadStart-ge0-and$LoadEnd-gt$LoadStart-and$ComposeStart-ge0-and$ComposeEnd-gt$ComposeStart) 'shipping Settings composition seam changed'
. ([ScriptBlock]::Create($Launcher.Substring($LoadStart,$LoadEnd-$LoadStart).Replace('$PSScriptRoot','$Client')))
$UnifiedText=Convert-RouterVPNWindowsUnifiedSessionMutation -Source ([IO.File]::ReadAllText($UnifiedSource,[Text.Encoding]::UTF8))
. ([ScriptBlock]::Create($UnifiedText))
. ([ScriptBlock]::Create($Launcher.Substring($ComposeStart,$ComposeEnd-$ComposeStart).Replace('$PSScriptRoot','$Client')))
$Composed=[ScriptBlock]::Create($ProductSource).Ast
$Bindings=@($Composed.FindAll({param($Node)$Node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $Node.Member.Value -eq 'Add_Click' -and $Node.Expression.Extent.Text -match '^\(Control ''UnifiedSettingsButton''\)$'},$true))
Check ($Bindings.Count -eq 1) 'shipping Settings binding lost or duplicated'
$script:SettingsButton=[pscustomobject]@{Callback=$null}
$script:SettingsButton|Add-Member ScriptMethod Add_Click {param($Callback)$this.Callback=$Callback}
function Control([string]$Name){if($Name-cne'UnifiedSettingsButton'){throw 'unexpected composed control'};return $script:SettingsButton}
$script:Opened=[Collections.Generic.List[object]]::new()
function global:Show-RouterVPNProfileSettingsDialog {
    param($BaseUrl,$Owner,$DisplayedProfileID,$DisplayedNodeKind)
    [void]$script:Opened.Add([pscustomobject]@{ID=$DisplayedProfileID;Kind=$DisplayedNodeKind})
    return $null
}
function Log($Message){}
function RefreshProduct{}
$BaseUrl='http://127.0.0.1:8788';$Window=$null
$RouterCombo=[pscustomobject]@{SelectedValue='external-a'}
$Profiles=@([pscustomobject]@{id='external-a';node_kind='external'},[pscustomobject]@{id='router-b';node_kind='router'})
& ([ScriptBlock]::Create($Bindings[0].Extent.Text))
& $script:SettingsButton.Callback
Check ($script:Opened.Count -eq 1 -and $script:Opened[0].ID -ceq 'external-a' -and $script:Opened[0].Kind -ceq 'external') 'composed callback lost displayed external identity'
$RouterCombo.SelectedValue='router-b';& $script:SettingsButton.Callback
Check ($script:Opened.Count -eq 2 -and $script:Opened[1].ID -ceq 'router-b' -and $script:Opened[1].Kind -ceq 'router') 'composed callback changed Router identity'
$RouterCombo.SelectedValue=''; & $script:SettingsButton.Callback
Check ($script:Opened.Count -eq 2) 'composed callback opened settings without a selected node'
$RouterCombo.SelectedValue='external-a';$Profiles+=,[pscustomobject]@{id='external-a';node_kind='router'};& $script:SettingsButton.Callback
Check ($script:Opened.Count -eq 2) 'composed callback accepted ambiguous selected identity'

. ([ScriptBlock]::Create($Text))
if($WPF){
    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName PresentationCore
    Add-Type -AssemblyName WindowsBase
    if($null -eq [Windows.Application]::Current){$script:DeviceApplication=New-Object Windows.Application;$script:DeviceApplication.ShutdownMode='OnExplicitShutdown'}
    function Select-Tag($Combo,[string]$Tag){foreach($Item in $Combo.Items){if([string]$Item.Tag -ceq $Tag){$Combo.SelectedItem=$Item;return}};throw ('missing UI choice '+$Tag)}
    foreach($Scenario in @('save-common','tor-common','startup-unchanged','manual-startup','invalid-mtu','unsupported-startup','busy','jumbo-enable','jumbo-disable','jumbo-default','jumbo-fixed','jumbo-conflict','jumbo-unsupported','jumbo-legacy','cover-enable','cover-disable','cover-zero','cover-dormant','cover-unchanged','cover-invalid','cover-unsupported','cover-unavailable')){
        $script:Capture=New-Capture;$script:Busy=$Scenario-ceq'busy';$script:Posts.Clear();$script:WPFError='';$script:Scenario=$Scenario
        if($Scenario -ceq 'busy'){$script:Capture.protocol='tor-bridge';$script:Capture.jumbo_tun_supported=$true}
        if($Scenario -ceq 'unsupported-startup'){$script:Capture.device_policy_supported=$false;$script:Capture.device_policy_reason='Native common device policy unavailable.'}
        if($Scenario -ceq 'tor-common'){$script:Capture.protocol='tor-bridge';$script:Capture.note='Tor Auto uses a 1280-byte virtual interface. Retest is not yet implemented.'}
        if($Scenario -clike 'jumbo-*' -and $Scenario -cnotin @('jumbo-unsupported','jumbo-legacy')){$script:Capture.protocol='tor-bridge';$script:Capture.jumbo_tun_supported=$true}
        if($Scenario -ceq 'jumbo-disable'){$script:Capture.jumbo_tun=$true}
        if($Scenario -ceq 'jumbo-default'){$script:Capture.mtu_policy='default'}
        if($Scenario -ceq 'jumbo-legacy'){$script:Capture.PSObject.Properties.Remove('jumbo_tun');$script:Capture.PSObject.Properties.Remove('jumbo_tun_supported')}
        if($Scenario -clike 'cover-*'){
            $script:Capture.protocol='tor';$script:Capture.tor_cover_supported=$Scenario-cnotin@('cover-unsupported','cover-unavailable')
            $script:Capture.daita_rate_kbps=64
            $script:Capture.daita_enabled=$Scenario-cin@('cover-disable','cover-unavailable')
            if($Scenario-ceq'cover-unavailable'){$script:Capture.device_policy_supported=$false}
        }
        $Timer=New-Object Windows.Threading.DispatcherTimer;$Timer.Interval=[TimeSpan]::FromMilliseconds(20)
        $Timer.Add_Tick({
            $Dialog=@([Windows.Application]::Current.Windows|Where-Object{$_.Title -eq 'Settings'})
            if($Dialog.Count -ne 1){return}
            $Timer.Stop();$Dialog=$Dialog[0]
            try{
                Check ($Dialog.FindName('RouterTransportSettings').Visibility -eq 'Collapsed' -and $Dialog.FindName('RouterFeatureSettings').Visibility -eq 'Collapsed') 'external form exposed Router-only writes'
                Check ($Dialog.FindName('Effective').Text -match '^Last recorded interface MTU:' -and $Dialog.FindName('Effective').Text -notmatch 'Retest') 'external form claimed historical interface MTU was a fresh path test'
                $Save=$Dialog.FindName('Save');$Node=$Dialog.FindName('NodeSettings');$Startup=$Dialog.FindName('Startup');$Automatic=$Dialog.FindName('AutoConnect')
                switch($script:Scenario){
                    'busy' {Check (-not$Save.IsEnabled-and-not$Node.IsEnabled-and-not$Startup.IsEnabled-and-not$Dialog.FindName('Jumbo').IsEnabled) 'busy WPF form enabled persistent edits';$Dialog.FindName('Cancel').RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent));return}
                    'unsupported-startup' {Check (-not$Node.IsEnabled-and$Startup.IsEnabled-and$Save.IsEnabled) 'unsupported WPF form enabled common device fields or disabled startup';Select-Tag $Startup 'last';$Automatic.IsChecked=$true}
                    'save-common' {Check $Node.IsEnabled 'supported WPF form disabled common device fields';$Dialog.FindName('LAN').IsChecked=$false;Select-Tag ($Dialog.FindName('Kill')) 'always';Select-Tag ($Dialog.FindName('IPv6')) 'off';Select-Tag ($Dialog.FindName('MTUPolicy')) 'manual';$Dialog.FindName('ManualMTU').Text='1412'}
                    'tor-common' {Check $Node.IsEnabled 'supported Tor form disabled common device fields';Check ($Dialog.FindName('SettingsNote').Text -ceq $script:Capture.note) 'captured Tor capability note was replaced';Check ([string]$Dialog.FindName('MTUPolicy').SelectedItem.Content -ceq $script:AutoMTULabel) 'Tor Auto claimed a measured path'}
                    {$_ -clike 'cover-*'} {
                        $Cover=$Dialog.FindName('TorCover');$Rate=$Dialog.FindName('TorCoverRate')
                        Check ($Dialog.FindName('TorCoverSettings').Visibility-eq'Visible'-and[string]$Cover.Content-ceq'Outgoing Tor cover traffic') 'native cover control is hidden or mislabeled'
                        Check ($Cover.IsChecked-eq$script:Capture.daita_enabled-and$Rate.Text-ceq'64') 'native cover control replaced the captured flag or budget'
                        Check ($Cover.IsEnabled-eq$script:Capture.tor_cover_supported-and$Rate.IsEnabled-eq$script:Capture.tor_cover_supported) 'native cover capability was not enforced by form'
                        Check ($Dialog.FindName('TorCoverNote').Text-ceq$script:Capture.tor_cover_note) 'native cover note lost its receipt boundary'
                        if($script:Scenario-ceq'cover-unavailable'){$Dialog.FindName('Cancel').RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent));return}
                        if($script:Scenario-cin@('cover-enable','cover-zero','cover-invalid','cover-unsupported')){$Cover.IsChecked=$true}
                        if($script:Scenario-ceq'cover-disable'){$Cover.IsChecked=$false}
                        if($script:Scenario-ceq'cover-zero'){$Rate.Text='0'}
                        if($script:Scenario-ceq'cover-dormant'){$Rate.Text='32'}
                        if($script:Scenario-ceq'cover-invalid'){$Rate.Text='31'}
                    }
                    {$_ -cin @('jumbo-enable','jumbo-disable','jumbo-default','jumbo-fixed','jumbo-conflict','jumbo-unsupported','jumbo-legacy')} {
                        $Jumbo=$Dialog.FindName('Jumbo')
                        Check ([string]$Jumbo.Content -ceq 'Jumbo virtual interface (9000)') 'native Jumbo label changed its virtual-interface meaning'
                        Check ($Jumbo.IsEnabled -eq ($script:Scenario -cnotin @('jumbo-unsupported','jumbo-legacy'))) 'native Jumbo capability was not enforced by form'
                        if($script:Scenario -cne 'jumbo-legacy'){$Jumbo.IsChecked=$script:Scenario -cne 'jumbo-disable'}
                        if($script:Scenario -cin @('jumbo-fixed','jumbo-conflict')){Select-Tag ($Dialog.FindName('MTUPolicy')) 'manual';$Dialog.FindName('ManualMTU').Text=if($script:Scenario -ceq 'jumbo-fixed'){'9000'}else{'1400'}}
                    }
                    'manual-startup' {$Automatic.IsChecked=$true;Select-Tag $Startup 'manual';Check (-not$Automatic.IsChecked-and-not$Automatic.IsEnabled) 'manual WPF startup retained auto-connect'}
                    'invalid-mtu' {Select-Tag ($Dialog.FindName('MTUPolicy')) 'manual';$Dialog.FindName('ManualMTU').Text='1.5'}
                }
                $Save.RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent))
            }catch{$script:WPFError=$_.ToString();$Dialog.Close()}
        })
        $Timer.Start();$Failed=$false
        try{[void](Show-RouterVPNProfileSettingsDialog -BaseUrl $BaseUrl -DisplayedProfileID $script:Capture.profile_id -DisplayedNodeKind 'external')}catch{$Failed=$true;if($Scenario -cnotin @('invalid-mtu','jumbo-conflict','jumbo-unsupported','cover-invalid','cover-unsupported')){$script:WPFError=$_.ToString()}}finally{$Timer.Stop()}
        Check ([string]::IsNullOrEmpty($script:WPFError)) ('actual WPF form failed '+$Scenario+' '+$script:WPFError)
        if($Scenario -cin @('busy','invalid-mtu','jumbo-conflict','jumbo-unsupported','cover-invalid','cover-unsupported','cover-unavailable')){Check ($script:Posts.Count-eq0) ('rejected WPF edit posted '+$Scenario);if($Scenario-cin@('invalid-mtu','jumbo-conflict','jumbo-unsupported','cover-invalid','cover-unsupported')){Check $Failed 'WPF invalid policy was normalized'};continue}
        Check ($script:Posts.Count-eq1) ('WPF form did not save exactly one transaction '+$Scenario)
        $Sent=$script:Posts[0]
        if($Scenario-ceq'unsupported-startup'){
            Check ($Sent.Path-ceq'/api/profile/startup'-and$Sent.Body.profile_token-ceq('c'*64)-and@($Sent.Body.PSObject.Properties).Count-eq4) 'unsupported WPF startup reused common-device token or route'
        }else{
            Check ($Sent.Path-ceq'/api/profile/device'-and$Sent.Body.profile_token-ceq('b'*64)) 'WPF common save changed its captured route or source'
            if($Scenario-ceq'manual-startup'){Check (@($Sent.Body.PSObject.Properties).Count-eq9-and$Sent.Body.startup_mode-ceq'manual'-and-not$Sent.Body.auto_connect) 'WPF startup was not atomic'}
            elseif($Scenario -cin @('jumbo-enable','jumbo-disable','jumbo-default','jumbo-fixed')){
                Check (@($Sent.Body.PSObject.Properties).Count-eq8-and$Sent.Body.jumbo_tun -eq ($Scenario -cne 'jumbo-disable')) 'WPF Jumbo did not reach narrow atomic transaction'
                $ExpectedPolicy=if($Scenario-ceq'jumbo-default'){'default'}elseif($Scenario-ceq'jumbo-fixed'){'manual'}else{'auto'}
                Check ($Sent.Body.mtu_policy -ceq $ExpectedPolicy -and $Sent.Body.manual_mtu -eq $(if($ExpectedPolicy-ceq'manual'){9000}else{0})) 'WPF Jumbo silently changed MTU policy'
            }
            elseif($Scenario -cin @('cover-enable','cover-disable','cover-zero','cover-dormant')){
                $ExpectedCover=$Scenario-cin@('cover-enable','cover-zero')
                $ExpectedRate=if($Scenario-ceq'cover-zero'){0}elseif($Scenario-ceq'cover-dormant'){32}else{64}
                Check (@($Sent.Body.PSObject.Properties).Count-eq9-and$Sent.Body.daita_enabled-eq$ExpectedCover-and$Sent.Body.daita_rate_kbps-eq$ExpectedRate) 'WPF cover controls did not reach exact atomic pair'
            }
            else{Check (@($Sent.Body.PSObject.Properties).Count-eq7) 'WPF unchanged startup alias was serialized'}
            if($Scenario-ceq'save-common'){Check ($Sent.Body.manual_mtu-eq1412-and$Sent.Body.mtu_policy-ceq'manual'-and$Sent.Body.kill_switch_policy-ceq'always'-and$Sent.Body.ipv6_mode-ceq'off'-and-not$Sent.Body.home_lan_access) 'WPF selected common fields did not reach the real serializer'}
        }
    }
    $script:Busy=$false
}
Write-Output ("Windows device settings: $script:Checks checks passed; actual WPF="+[bool]$WPF)
