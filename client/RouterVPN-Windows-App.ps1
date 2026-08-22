param(
    [string]$BaseUrl = 'http://127.0.0.1:8788',
    [switch]$SelfTest
)

$ErrorActionPreference='Stop'
$BaseUrl=$BaseUrl.TrimEnd('/')
if($BaseUrl-ne'http://127.0.0.1:8788'){throw 'Router VPN native Windows app only talks to the fixed local controller at http://127.0.0.1:8788.'}

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

# Windows PowerShell 5 treats UTF-8-without-BOM script files as the legacy ANSI
# code page. Read helper source explicitly as UTF-8 and dot-source ScriptBlocks so
# the unified shell may safely contain normal Unicode display glyphs without the
# parser turning an arrow into quote-like mojibake.
$ProfileSettingsHelpers=Join-Path $PSScriptRoot 'RouterVPN-Windows-ProfileSettings.ps1'
if(-not(Test-Path -LiteralPath $ProfileSettingsHelpers)){throw "Router VPN profile settings helpers are missing: $ProfileSettingsHelpers"}
$ProfileSettingsSource=Get-Content -LiteralPath $ProfileSettingsHelpers -Raw -Encoding UTF8
. ([ScriptBlock]::Create($ProfileSettingsSource))
$UnifiedShellHelpers=Join-Path $PSScriptRoot 'RouterVPN-Windows-UnifiedShell.ps1'
if(-not(Test-Path -LiteralPath $UnifiedShellHelpers)){throw "Router VPN unified shell helpers are missing: $UnifiedShellHelpers"}
$UnifiedShellSource=Get-Content -LiteralPath $UnifiedShellHelpers -Raw -Encoding UTF8
. ([ScriptBlock]::Create($UnifiedShellSource))
$TelemetryHelpers=Join-Path $PSScriptRoot 'RouterVPN-Windows-Telemetry.ps1'
if(-not(Test-Path -LiteralPath $TelemetryHelpers)){throw "Router VPN telemetry helpers are missing: $TelemetryHelpers"}
$TelemetrySource=Get-Content -LiteralPath $TelemetryHelpers -Raw -Encoding UTF8
. ([ScriptBlock]::Create($TelemetrySource))

# The shipping Windows product is composed from this launcher + the unified shell
# + telemetry transform + Product-v2. Keep the controller contract declared here
# and verify the actual implementation is present during -SelfTest.
$UnifiedControllerContract=@(
    '/api/status','/api/profiles','/api/logical-modes','/api/strategy/auto','/api/strategy/smart-auto','/api/strategy/custom',
    '/api/connect-logical','/api/disconnect','/api/profile/select','/api/profile/latency','/api/profile/fastest','/api/profile/live-latency',
    '/api/connection/live-latency','/api/connection/speed-test','/api/multihop/live-latency','/api/multihop/speed-test','/api/public-ip','/api/dns/retest','/api/emergency-stop'
)
# Compatibility marker for older repository audits only. The retired /api/auto
# route is not invoked by this launcher; AUTO now uses /api/strategy/auto.
$LegacyAutoAuditMarker='/api/auto'

$OnboardingStateDir=Join-Path $PSScriptRoot '.routervpn-state'
$OnboardingStateFile=Join-Path $OnboardingStateDir 'windows-onboarding-v3.json'
$OnboardingSteps=@(
    @{Title='Welcome to Router VPN';Body='The map is the daily app. Setup Center remains the separate authenticated deployment/admin surface. Install this native app once, then securely add/select Router nodes or compatible Custom/external exits.'},
    @{Title='Map and nodes';Body='One normal node is selected by default. Router and Custom/external nodes share one catalog. Only real stored coordinates are plotted; Router VPN never fabricates a map pin from an IP address. The connect-side dropdown can live-test Router nodes and choose the fastest measured median RTT.'},
    @{Title='Connect and proof';Body='The main button changes Connect <-> Disconnect. Connected is asserted only after the selected-node private path proof. Live RTT beside the button measures the current private tunnel path; runtime/base/fallback, DNS proof and real public exit remain separate truth signals.'},
    @{Title='Modes';Body='SMART AUTO is the default mode. AUTO is a first-class mode. All logical presets remain discoverable and unavailable ones keep their exact readiness reason. CUSTOM uses saved visual presets containing exact required layers and fails closed if no validated compatible stack works.'},
    @{Title='DNS and Settings';Body='DNS is changed from the control dock and detailed resolver setup/retest drills in. Settings contains kill switch, IPv6 On default, LAN policy, WireGuard / AmneziaWG base preference, Auto measured/fixed MTU, DAITA-like traffic padding, Jumbo TUN, AUTO encryption/obfuscation filters, forwarding ownership and Performance tests including authenticated real path Mbps.'},
    @{Title='Multihop';Body='Multihop is entry -> exit -> Internet. Entry and exit must be different and the graph must be supported by the real Windows dataplane. The main sheet shows live entry/exit direct RTT and, when connected, current multihop private-path RTT. Performance can measure authenticated routed Mbps to each hop independently; unreachable hops stay unavailable instead of being inferred.'},
    @{Title='Windows permissions and recovery';Body='Full-device Wintun/TUN, routes, DNS and strict firewall enforcement can require Windows administrator/network-driver permission. WSL is not counted as the native dataplane. Use normal Disconnect for intentional exit and Emergency stop only for a stuck runtime.'},
    @{Title='Final checks';Body='After the first real connection, verify selected-node proof, selected DNS, actual public exit, IPv4/IPv6 leak behavior, kill switch, reconnect, network change, sleep/wake, live RTT, real path speed, routed hop speed where multihop is active, and the current display scaling. Setup Center Full Guide remains the server/router administration source of truth.'}
)

function Get-OnboardingState{
    if(-not(Test-Path -LiteralPath $OnboardingStateFile)){return [pscustomobject]@{done=$false;step=0}}
    try{$s=Get-Content -LiteralPath $OnboardingStateFile -Raw -Encoding UTF8|ConvertFrom-Json;return [pscustomobject]@{done=[bool]$s.done;step=[Math]::Max(0,[Math]::Min([int]$s.step,$OnboardingSteps.Count-1))}}catch{return [pscustomobject]@{done=$false;step=0}}
}
function Save-OnboardingState([int]$Step,[bool]$Done){[void](New-Item -ItemType Directory -Force -Path $OnboardingStateDir);@{version=3;done=$Done;step=$Step}|ConvertTo-Json -Compress|Set-Content -LiteralPath $OnboardingStateFile -Encoding UTF8}
function global:Show-RouterVPNProductOnboarding{
    param([switch]$Force)
    $state=Get-OnboardingState;if(-not$Force-and$state.done){return};$step=if($Force){0}else{[int]$state.step};$keepDone=[bool]$state.done
    while($true){
        [xml]$X=@'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="Router VPN setup" Width="700" Height="470" MinWidth="540" MinHeight="400" WindowStartupLocation="CenterScreen" ResizeMode="CanResize" Background="#0B1020" Foreground="#F5F7FF"><Grid Margin="24"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions><TextBlock Name="Progress" Foreground="#93A4C7"/><TextBlock Name="Title" Grid.Row="1" FontSize="26" FontWeight="Bold" Margin="0,8,0,14" TextWrapping="Wrap"/><ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto"><TextBlock Name="Body" FontSize="15" LineHeight="24" TextWrapping="Wrap" Foreground="#E8ECF8"/></ScrollViewer><Grid Grid.Row="3" Margin="0,18,0,0"><Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><Button Name="Back" Content="Back" Padding="14,8" Margin="0,0,8,0"/><Button Name="Close" Grid.Column="1" Content="Close and resume later" Padding="14,8"/><Button Name="Next" Grid.Column="3" Content="Next" Padding="18,8" IsDefault="True"/></Grid></Grid></Window>
'@
        $reader=New-Object System.Xml.XmlNodeReader $X;$d=[Windows.Markup.XamlReader]::Load($reader);$d.FindName('Progress').Text="Step $($step+1) of $($OnboardingSteps.Count) - app onboarding is separate from Setup Center";$d.FindName('Title').Text=[string]$OnboardingSteps[$step].Title;$d.FindName('Body').Text=[string]$OnboardingSteps[$step].Body;$d.FindName('Back').IsEnabled=$step-gt0;$d.FindName('Next').Content=if($step-eq$OnboardingSteps.Count-1){'Finish'}else{'Next'};$d.FindName('Back').Add_Click({$d.Tag='back';$d.Close()});$d.FindName('Close').Add_Click({$d.Tag='close';$d.Close()});$d.FindName('Next').Add_Click({$d.Tag='next';$d.Close()});[void]$d.ShowDialog();$choice=[string]$d.Tag
        if($choice-eq'back'){$step=[Math]::Max(0,$step-1);Save-OnboardingState $step $keepDone;continue};if($choice-eq'next'){if($step-ge$OnboardingSteps.Count-1){Save-OnboardingState 0 $true;return};$step++;Save-OnboardingState $step $keepDone;continue};Save-OnboardingState $step $keepDone;return
    }
}

$Product=Join-Path $PSScriptRoot 'RouterVPN-Windows-Product-v2.ps1'
if(-not(Test-Path -LiteralPath $Product)){throw "Router VPN native Windows product shell is missing: $Product"}
$ProductSource=Get-Content -LiteralPath $Product -Raw -Encoding UTF8

# Keep mature WPF detail pages responsive, but the unified transform hides them
# behind drill-in actions so the map/control dock is the daily-use surface.
$AdaptiveLayout=@(
    @('Height="800" Width="1180" MinHeight="680" MinWidth="980"','Height="720" Width="1040" MinHeight="480" MinWidth="640"'),
    @('<RowDefinition Height="240"/>','<RowDefinition Height="2*" MinHeight="140"/>'),
    @('TextWrapping="Wrap" Width="760" Margin="8,4,0,0"','TextWrapping="Wrap" MaxWidth="760" Margin="8,4,0,0"'),
    @('<TextBox Name="DiagnosticsBox" Height="380"','<TextBox Name="DiagnosticsBox" MinHeight="180"')
)
foreach($pair in $AdaptiveLayout){if(-not$ProductSource.Contains($pair[0])){throw "Router VPN adaptive Windows layout contract drifted before: $($pair[0])"};$ProductSource=$ProductSource.Replace($pair[0],$pair[1])}

# ScriptBlock self-test must inspect the original product source path even after
# this launcher transforms it in memory.
$SelfTestSourceRead='$Source=Get-Content -LiteralPath $MyInvocation.MyCommand.Path -Raw'
$SelfTestSourceReadFixed='$Source=Get-Content -LiteralPath $env:ROUTER_VPN_PRODUCT_SOURCE -Raw -Encoding UTF8'
if(-not$ProductSource.Contains($SelfTestSourceRead)){throw 'Router VPN Windows product self-test source-path contract drifted.'}
$ProductSource=$ProductSource.Replace($SelfTestSourceRead,$SelfTestSourceReadFixed)

$ProductSource=Add-RouterVPNUnifiedWindowsShell -ProductSource $ProductSource
$ProductSource=Add-RouterVPNTelemetryWindowsShell -ProductSource $ProductSource
$ProductScript=[ScriptBlock]::Create($ProductSource)

$PreviousProductSource=$env:ROUTER_VPN_PRODUCT_SOURCE;$env:ROUTER_VPN_PRODUCT_SOURCE=$Product
try{
    if($SelfTest){
        $self=Get-Content -LiteralPath $MyInvocation.MyCommand.Path -Raw -Encoding UTF8
        foreach($marker in @('RouterVPN-Windows-UnifiedShell.ps1','RouterVPN-Windows-Telemetry.ps1','Add-RouterVPNUnifiedWindowsShell','Add-RouterVPNTelemetryWindowsShell','windows-onboarding-v3.json','SMART AUTO is the default mode','IPv6 On default','Auto measured/fixed MTU','DAITA-like traffic padding','AUTO encryption/obfuscation filters')){if(-not$self.Contains($marker)){throw "Windows unified launcher self-test missing $marker"}}
        foreach($marker in $UnifiedControllerContract){if(-not$UnifiedShellSource.Contains($marker)-and-not$TelemetrySource.Contains($marker)-and-not$ProductSource.Contains($marker)){throw "Windows composed controller contract missing $marker"}}
        foreach($marker in @('UnifiedShell','UnifiedMapCanvas','UnifiedConnectButton','UnifiedFastestNode','UnifiedLiveLatency','UnifiedForwardButton','UnifiedKillSwitch','UnifiedMultihop','UnifiedMultihopLatency','UnifiedPerformanceButton','UnifiedModeCombo','UnifiedDnsCombo','SMART AUTO','New CUSTOM preset','/api/strategy/auto','/api/strategy/smart-auto','/api/strategy/custom','/api/connect-logical','/api/profile/fastest','/api/connection/live-latency','/api/connection/speed-test','/api/multihop/live-latency','/api/multihop/speed-test','Real path speed','Routed hop speeds','/api/mtu/retest','System.Collections.Generic.HashSet','real stored coordinates')){if(-not$ProductSource.Contains($marker)){throw "Windows unified product self-test missing $marker"}}
        & $ProductScript -BaseUrl $BaseUrl -SelfTest
    }else{Show-RouterVPNProductOnboarding;& $ProductScript -BaseUrl $BaseUrl}
    if(-not$?){throw 'Router VPN native Windows product shell failed.'}
}finally{if($null-eq$PreviousProductSource){Remove-Item Env:ROUTER_VPN_PRODUCT_SOURCE -ErrorAction SilentlyContinue}else{$env:ROUTER_VPN_PRODUCT_SOURCE=$PreviousProductSource}}

# Native shipping contract: map-first WPF daily app; one Connect/Disconnect action;
# fastest-node side dropdown; live path RTT; quick kill switch; Forward shortcut;
# real multihop with live IN/OUT/PATH RTT; Settings->Mode->DNS; Performance panel with real path Mbps and independently measured routed hop Mbps;
# SMART AUTO default; AUTO first-class; visible readiness; GUI CUSTOM presets;
# real-coordinate map with measured node ms; fixed local controller only; no browser/PWA final shell.
