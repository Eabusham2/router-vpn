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
    [pscustomobject]@{profile_id='node "quoted"';profile_token=('b'*64);node_kind='external';protocol='shadowsocks';device_policy_supported=$true;device_policy_reason='';home_lan_access=$true;kill_switch_policy='off';ipv6_mode='on';mtu_policy='auto';manual_mtu=0;effective_mtu=1420;mtu_source='historical fixture';startup_mode='smart-auto';auto_connect=$false;note='Save while disconnected.';password='never-copy';dns_host='keep-resolver';entry_id='independent-entry'}
}
function New-Arguments($Capture) {
    @{Captured=$Capture;DisplayedProfileID=$Capture.profile_id;HomeLANAccess=$false;KillSwitchPolicy='always';IPv6Mode='off';MTUPolicy='manual';ManualMTU=1412}
}
$script:Capture=New-Capture;$script:Busy=$false;$script:Unavailable=$false;$script:PostFailure=$false
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
    [void]$script:Posts.Add([pscustomobject]@{Path=$Path;Body=$Value})
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
Check (@($Result.PSObject.Properties).Count -eq 7 -and $Result.profile_token -ceq $Captured.profile_token) 'device save changed its typed captured payload'
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
    foreach($Scenario in @('save-common','tor-common','startup-unchanged','manual-startup','invalid-mtu','unsupported-startup','busy')){
        $script:Capture=New-Capture;$script:Busy=$Scenario-ceq'busy';$script:Posts.Clear();$script:WPFError='';$script:Scenario=$Scenario
        if($Scenario -ceq 'unsupported-startup'){$script:Capture.device_policy_supported=$false;$script:Capture.device_policy_reason='Native common device policy unavailable.'}
        if($Scenario -ceq 'tor-common'){$script:Capture.protocol='tor-bridge';$script:Capture.note='Tor Auto uses a 1280-byte virtual interface. Retest is not yet implemented.'}
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
                    'busy' {Check (-not$Save.IsEnabled-and-not$Node.IsEnabled-and-not$Startup.IsEnabled) 'busy WPF form enabled persistent edits';$Dialog.FindName('Cancel').RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent));return}
                    'unsupported-startup' {Check (-not$Node.IsEnabled-and$Startup.IsEnabled-and$Save.IsEnabled) 'unsupported WPF form enabled common device fields or disabled startup';Select-Tag $Startup 'last';$Automatic.IsChecked=$true}
                    'save-common' {Check $Node.IsEnabled 'supported WPF form disabled common device fields';$Dialog.FindName('LAN').IsChecked=$false;Select-Tag ($Dialog.FindName('Kill')) 'always';Select-Tag ($Dialog.FindName('IPv6')) 'off';Select-Tag ($Dialog.FindName('MTUPolicy')) 'manual';$Dialog.FindName('ManualMTU').Text='1412'}
                    'tor-common' {Check $Node.IsEnabled 'supported Tor form disabled common device fields';Check ($Dialog.FindName('SettingsNote').Text -ceq $script:Capture.note) 'captured Tor capability note was replaced';Check ([string]$Dialog.FindName('MTUPolicy').SelectedItem.Content -ceq $script:AutoMTULabel) 'Tor Auto claimed a measured path'}
                    'manual-startup' {$Automatic.IsChecked=$true;Select-Tag $Startup 'manual';Check (-not$Automatic.IsChecked-and-not$Automatic.IsEnabled) 'manual WPF startup retained auto-connect'}
                    'invalid-mtu' {Select-Tag ($Dialog.FindName('MTUPolicy')) 'manual';$Dialog.FindName('ManualMTU').Text='1.5'}
                }
                $Save.RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent))
            }catch{$script:WPFError=$_.ToString();$Dialog.Close()}
        })
        $Timer.Start();$Failed=$false
        try{[void](Show-RouterVPNProfileSettingsDialog -BaseUrl $BaseUrl -DisplayedProfileID $script:Capture.profile_id -DisplayedNodeKind 'external')}catch{$Failed=$true;if($Scenario -cne 'invalid-mtu'){$script:WPFError=$_.ToString()}}finally{$Timer.Stop()}
        Check ([string]::IsNullOrEmpty($script:WPFError)) ('actual WPF form failed '+$Scenario+' '+$script:WPFError)
        if($Scenario -cin @('busy','invalid-mtu')){Check ($script:Posts.Count-eq0) ('rejected WPF edit posted '+$Scenario);if($Scenario-ceq'invalid-mtu'){Check $Failed 'WPF invalid fixed MTU was normalized'};continue}
        Check ($script:Posts.Count-eq1) ('WPF form did not save exactly one transaction '+$Scenario)
        $Sent=$script:Posts[0]
        if($Scenario-ceq'unsupported-startup'){
            Check ($Sent.Path-ceq'/api/profile/startup'-and$Sent.Body.profile_token-ceq('c'*64)-and@($Sent.Body.PSObject.Properties).Count-eq4) 'unsupported WPF startup reused common-device token or route'
        }else{
            Check ($Sent.Path-ceq'/api/profile/device'-and$Sent.Body.profile_token-ceq('b'*64)) 'WPF common save changed its captured route or source'
            if($Scenario-ceq'manual-startup'){Check (@($Sent.Body.PSObject.Properties).Count-eq9-and$Sent.Body.startup_mode-ceq'manual'-and-not$Sent.Body.auto_connect) 'WPF startup was not atomic'}
            else{Check (@($Sent.Body.PSObject.Properties).Count-eq7) 'WPF unchanged startup alias was serialized'}
            if($Scenario-ceq'save-common'){Check ($Sent.Body.manual_mtu-eq1412-and$Sent.Body.mtu_policy-ceq'manual'-and$Sent.Body.kill_switch_policy-ceq'always'-and$Sent.Body.ipv6_mode-ceq'off'-and-not$Sent.Body.home_lan_access) 'WPF selected common fields did not reach the real serializer'}
        }
    }
    $script:Busy=$false
}
Write-Output ("Windows device settings: $script:Checks checks passed; actual WPF="+[bool]$WPF)
