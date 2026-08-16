param(
    [string]$BaseUrl = 'http://127.0.0.1:8788',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
$BaseUrl = $BaseUrl.TrimEnd('/')
if ($BaseUrl -ne 'http://127.0.0.1:8788') {
    throw 'Router VPN native Windows app only talks to the fixed local controller at http://127.0.0.1:8788.'
}

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

# App onboarding is deliberately separate from Setup Center onboarding. It is
# persistent, resumes from the last unfinished step, and is always rerunnable
# from the shipping product Help tab.
$OnboardingStateDir = Join-Path $PSScriptRoot '.routervpn-state'
$OnboardingStateFile = Join-Path $OnboardingStateDir 'windows-onboarding-v2.json'
$OnboardingSteps = @(
    @{ Title='Welcome to Router VPN'; Body='This is the daily native Windows VPN app. Setup Center deploys and administers the home node; this app connects to it. Install Router VPN once, then link one or many Router VPN or validated external nodes without reinstalling.' },
    @{ Title='Add or link a node'; Body='Use Pair home node with a short-lived one-time code from the authenticated private Setup Center, or Import node JSON / router-vpn-bundle.json. Select, remember, remove and relink nodes in Nodes / Map. Pairing is LAN-only; a node bundle is private data and must not be baked into the generic installer.' },
    @{ Title='Windows permissions and privacy'; Body='Full-device VPN, Wintun/TUN, route, DNS and strict-firewall work can require Windows administrator/network-driver permission. Router VPN is native Windows; WSL is not counted as the VPN dataplane. Never paste or upload WG/AWG private keys, PSKs, node secrets, admin tokens, SSH passwords or provider API secrets.' },
    @{ Title='Choose a node, logical mode and base'; Body='Choose the selected node, then a logical mode. Where compatible, Base can be Auto, WireGuard or AmneziaWG. AUTO tries the lightest eligible path and stops at the first proven healthy one. SMART AUTO simplifies only after connecting and restores the last-good path if a reduction fails. CUSTOM keeps only requested compatible layers. Unavailable modes stay unavailable and show the exact reason.' },
    @{ Title='DNS selection and measured RTT'; Body='DNS choices are Home AdGuard, Fastest measured, Custom UDP/TCP, DoT, DoH, DoH3 and Rescue, including common IPv4/IPv6 resolvers. Retest measures real A/AAAA DNS query RTT from the selected home node, not ICMP ping. Saving a resolver is not proof; the active session must prove the selected DNS path after reconnect.' },
    @{ Title='LAN access and strict kill switch'; Body='LAN access is an explicit shared policy. LAN Off must block ordinary private-LAN reachability while preserving the minimum safe control/recovery path. Strict kill switch is different from Emergency stop or an intentional Disconnect: it must prevent IPv4/IPv6 and DNS leaks during protected reconnect/failure, then release correctly after a deliberate disconnect.' },
    @{ Title='MTU, Auto MTU and Jumbo TUN'; Body='Advanced MTU state is shared with the node profile: default/manual/auto/effective MTU. Retest Auto MTU only on one connected Router VPN path and keep the result path/network specific. Jumbo TUN is an advanced option only for compatible TUN/proxy paths and never overrides the real Internet path MTU.' },
    @{ Title='Multihop and external exits'; Body='A real multihop is entry -> exit -> Internet; entry and exit must differ and the app must prove the actual exit. External WireGuard/OpenVPN/SOCKS5/Shadowsocks/Hysteria2 paths are used only where the Windows dataplane really supports them. Unsupported hop/protocol graphs fail closed instead of being labeled connected.' },
    @{ Title='Forwarding where it is actually routable'; Body='Incoming forwarding is administered by the authenticated private Setup Center/router-agent and is only advertised for routable tunnel modes. Proxy-only paths cannot fake arbitrary DNAT. Protected DMZ forwards only allowed unused ports and preserves Router VPN listeners plus SSH, DNS/admin, Portainer, Setup Center, SOCKS5 and other protected services.' },
    @{ Title='First connection and proof'; Body='Start with WireGuard Raw as the baseline when available, then try AUTO or another ready logical mode. Watch truthful connecting/attempt/fallback progress. Connected means selected-node private path proof passed; then verify the real public VPN exit IP, selected DNS proof and IPv4/IPv6 behavior. Generic Internet access by itself is not success.' },
    @{ Title='Diagnostics, recovery and clean disconnect'; Body='Diagnostics shows session phase, actual runtime/base/fallback, path proof, DNS proof and typed events. Use Emergency stop for a stuck runtime; use normal Disconnect for an intentional clean exit. Portable Router VPN must stop transports/controller, release files and leave no hidden process holding the portable folder.' },
    @{ Title='Full guide and rerun'; Body='Setup Center Full Guide remains the server/router administration source of truth. The app Help tab can run this onboarding again at any time. Physical leak, sleep/wake, network-change, off-LAN and visual/DPI tests are release proof gates; the app never turns a saved setting or a green-looking control into fake runtime proof.' }
)

function Get-RouterVPNOnboardingState {
    if (-not (Test-Path -LiteralPath $OnboardingStateFile)) {
        return [pscustomobject]@{ done=$false; step=0 }
    }
    try {
        $state = Get-Content -LiteralPath $OnboardingStateFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $step = [Math]::Max(0, [Math]::Min([int]$state.step, $OnboardingSteps.Count - 1))
        return [pscustomobject]@{ done=[bool]$state.done; step=$step }
    } catch {
        return [pscustomobject]@{ done=$false; step=0 }
    }
}

function Save-RouterVPNOnboardingState([int]$Step, [bool]$Done) {
    [void](New-Item -ItemType Directory -Force -Path $OnboardingStateDir)
    $tmp = "$OnboardingStateFile.tmp"
    @{ version=2; done=$Done; step=$Step } | ConvertTo-Json -Compress | Set-Content -LiteralPath $tmp -Encoding UTF8
    Move-Item -Force -LiteralPath $tmp -Destination $OnboardingStateFile
}

function global:Show-RouterVPNProductOnboarding {
    param([switch]$Force)
    $state = Get-RouterVPNOnboardingState
    if (-not $Force -and $state.done) { return }
    $step = if ($Force) { 0 } else { [int]$state.step }
    $keepDone = [bool]$state.done

    while ($true) {
        [xml]$TutorialXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="Router VPN setup" Width="720" Height="510" MinWidth="560" MinHeight="430" WindowStartupLocation="CenterScreen" ResizeMode="CanResize" Background="#0B1020" Foreground="#F5F7FF">
<Grid Margin="24"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
<TextBlock Name="Progress" Grid.Row="0" Foreground="#93A4C7" Margin="0,0,0,8"/>
<TextBlock Name="StepTitle" Grid.Row="1" FontSize="26" FontWeight="Bold" TextWrapping="Wrap" Margin="0,0,0,16"/>
<ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto"><TextBlock Name="StepBody" FontSize="15" LineHeight="24" TextWrapping="Wrap" Foreground="#E8ECF8"/></ScrollViewer>
<Grid Grid.Row="3" Margin="0,20,0,0"><Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
<Button Name="Back" Grid.Column="0" Content="Back" Padding="14,8" Margin="0,0,8,0"/>
<Button Name="Close" Grid.Column="1" Content="Close and resume later" Padding="14,8"/>
<Button Name="Next" Grid.Column="3" Content="Next" Padding="18,8" FontWeight="SemiBold" IsDefault="True"/>
</Grid></Grid></Window>
'@
        $reader = New-Object System.Xml.XmlNodeReader $TutorialXaml
        $dialog = [Windows.Markup.XamlReader]::Load($reader)
        $dialog.FindName('Progress').Text = "Step $($step + 1) of $($OnboardingSteps.Count) • app onboarding is separate from Setup Center onboarding"
        $dialog.FindName('StepTitle').Text = [string]$OnboardingSteps[$step].Title
        $dialog.FindName('StepBody').Text = [string]$OnboardingSteps[$step].Body
        $dialog.FindName('Back').IsEnabled = $step -gt 0
        $dialog.FindName('Next').Content = if ($step -eq $OnboardingSteps.Count - 1) { 'Finish' } else { 'Next' }
        $dialog.FindName('Back').Add_Click({ $dialog.Tag='back'; $dialog.Close() })
        $dialog.FindName('Close').Add_Click({ $dialog.Tag='close'; $dialog.Close() })
        $dialog.FindName('Next').Add_Click({ $dialog.Tag='next'; $dialog.Close() })
        [void]$dialog.ShowDialog()
        $choice = [string]$dialog.Tag
        if ($choice -eq 'back') { $step = [Math]::Max(0, $step - 1); Save-RouterVPNOnboardingState $step $keepDone; continue }
        if ($choice -eq 'next') {
            if ($step -ge $OnboardingSteps.Count - 1) { Save-RouterVPNOnboardingState 0 $true; return }
            $step++; Save-RouterVPNOnboardingState $step $keepDone; continue
        }
        Save-RouterVPNOnboardingState $step $keepDone
        return
    }
}

# Stable package/Portable entrypoint. Windows PowerShell 5.1 treats UTF-8 text
# without a BOM as the active ANSI code page when it parses a child .ps1 with
# the call operator. The native product intentionally contains Unicode UI text,
# so load it explicitly as UTF-8 before ScriptBlock parsing.
$Product = Join-Path $PSScriptRoot 'RouterVPN-Windows-Product-v2.ps1'
if (-not (Test-Path -LiteralPath $Product)) {
    throw "Router VPN native Windows product shell is missing: $Product"
}
$ProductSource = Get-Content -LiteralPath $Product -Raw -Encoding UTF8

# The product source keeps a roomy desktop default, but the shipped entrypoint
# must remain usable on small logical desktops created by high Windows scaling.
$AdaptiveLayout = @(
    @('Height="800" Width="1180" MinHeight="680" MinWidth="980"', 'Height="720" Width="1040" MinHeight="480" MinWidth="640"'),
    @('<RowDefinition Height="240"/>', '<RowDefinition Height="2*" MinHeight="140"/>'),
    @('TextWrapping="Wrap" Width="760" Margin="8,4,0,0"', 'TextWrapping="Wrap" MaxWidth="760" Margin="8,4,0,0"'),
    @('<TextBox Name="DiagnosticsBox" Height="380"', '<TextBox Name="DiagnosticsBox" MinHeight="180"')
)
foreach ($Pair in $AdaptiveLayout) {
    if (-not $ProductSource.Contains($Pair[0])) {
        throw "Router VPN adaptive Windows layout contract drifted before: $($Pair[0])"
    }
    $ProductSource = $ProductSource.Replace($Pair[0], $Pair[1])
}

# The product is parsed from an in-memory UTF-8 ScriptBlock, so give its
# self-test the authoritative on-disk product source path explicitly.
$SelfTestSourceRead = '$Source=Get-Content -LiteralPath $MyInvocation.MyCommand.Path -Raw'
$SelfTestSourceReadFixed = '$Source=Get-Content -LiteralPath $env:ROUTER_VPN_PRODUCT_SOURCE -Raw -Encoding UTF8'
if (-not $ProductSource.Contains($SelfTestSourceRead)) {
    throw 'Router VPN Windows product self-test source-path contract drifted.'
}
$ProductSource = $ProductSource.Replace($SelfTestSourceRead, $SelfTestSourceReadFixed)

# Replace the shipping Help button's old single-message tutorial with the same
# persistent first-run onboarding flow. Require exactly one replacement so a
# future product refactor cannot silently disconnect Help from onboarding.
$TutorialPattern = "(?s)\(Control 'TutorialButton'\)\.Add_Click\(\{\[System\.Windows\.MessageBox\]::Show\(.*?\)\|Out-Null\}\)"
$tutorialMatches = [regex]::Matches($ProductSource, $TutorialPattern)
if ($tutorialMatches.Count -ne 1) {
    throw "Router VPN Windows Help/onboarding contract drifted: expected one tutorial handler, found $($tutorialMatches.Count)."
}
$ProductSource = [regex]::Replace($ProductSource, $TutorialPattern, "(Control 'TutorialButton').Add_Click({Show-RouterVPNProductOnboarding -Force})", 1)
$ProductScript = [ScriptBlock]::Create($ProductSource)

$ApiContract = @(
    '/api/status', '/api/profiles', '/api/logical-modes', '/api/auto',
    '/api/connect-logical', '/api/disconnect', '/api/profile/select',
    '/api/profile/latency', '/api/public-ip', '/api/dns/retest', '/api/dns/policy',
    '/api/mtu/retest', '/api/emergency-stop', '/api/session', '/api/session/events'
)

$PreviousProductSource = $env:ROUTER_VPN_PRODUCT_SOURCE
$env:ROUTER_VPN_PRODUCT_SOURCE = $Product
try {
    if ($SelfTest) {
        foreach ($Marker in @(
            'windows-onboarding-v2.json','Close and resume later','Show-RouterVPNProductOnboarding',
            'Add or link a node','MTU, Auto MTU and Jumbo TUN','LAN access and strict kill switch',
            'Multihop and external exits','Forwarding where it is actually routable','Windows permissions and privacy',
            'Full guide and rerun','MinHeight="480" MinWidth="640"','Height="2*" MinHeight="140"',
            'MaxWidth="760"','MinHeight="180"','$env:ROUTER_VPN_PRODUCT_SOURCE'
        )) {
            if (-not ((Get-Content -LiteralPath $MyInvocation.MyCommand.Path -Raw -Encoding UTF8).Contains($Marker) -or $ProductSource.Contains($Marker))) {
                throw "Windows shipping onboarding/layout self-test missing $Marker"
            }
        }
        & $ProductScript -BaseUrl $BaseUrl -SelfTest
    } else {
        Show-RouterVPNProductOnboarding
        & $ProductScript -BaseUrl $BaseUrl
    }
    if (-not $?) { throw 'Router VPN native Windows product shell failed.' }
} finally {
    if ($null -eq $PreviousProductSource) {
        Remove-Item Env:ROUTER_VPN_PRODUCT_SOURCE -ErrorAction SilentlyContinue
    } else {
        $env:ROUTER_VPN_PRODUCT_SOURCE = $PreviousProductSource
    }
}

# Native product contract markers: SelfTest / ShowDialog() / explicit UTF-8 /
# adaptive layout / stable source path / persistent app onboarding lifecycle.
