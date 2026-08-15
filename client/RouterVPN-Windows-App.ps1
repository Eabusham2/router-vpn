param(
    [string]$BaseUrl = 'http://127.0.0.1:8788',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
$BaseUrl = $BaseUrl.TrimEnd('/')
if ($BaseUrl -ne 'http://127.0.0.1:8788') {
    throw 'Router VPN native Windows app only talks to the fixed local controller at http://127.0.0.1:8788.'
}

# Stable package/Portable entrypoint. Windows PowerShell 5.1 treats UTF-8 text
# without a BOM as the active ANSI code page when it parses a child .ps1 with
# the call operator. The native product intentionally contains Unicode UI text,
# so load it explicitly as UTF-8 before ScriptBlock parsing. This keeps the same
# native WPF product while making installed and Portable launches deterministic.
Add-Type -AssemblyName PresentationFramework
$Product = Join-Path $PSScriptRoot 'RouterVPN-Windows-Product-v2.ps1'
if (-not (Test-Path -LiteralPath $Product)) {
    throw "Router VPN native Windows product shell is missing: $Product"
}
$ProductSource = Get-Content -LiteralPath $Product -Raw -Encoding UTF8

# The product source keeps a roomy desktop default, but the shipped entrypoint
# must remain usable on small logical desktops created by high Windows scaling,
# remote sessions, compact laptops and portrait-like snapped windows. Apply only
# exact layout-contract substitutions; fail closed if the source drifts instead
# of doing a broad textual rewrite.
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
$ProductScript = [ScriptBlock]::Create($ProductSource)

# Static local-controller contract retained here for repository/package audits.
$ApiContract = @(
    '/api/status', '/api/profiles', '/api/logical-modes', '/api/auto',
    '/api/connect-logical', '/api/disconnect', '/api/profile/select',
    '/api/profile/latency', '/api/public-ip', '/api/dns/retest', '/api/dns/policy',
    '/api/mtu/retest', '/api/emergency-stop', '/api/session', '/api/session/events'
)

if ($SelfTest) {
    foreach ($Marker in @('MinHeight="480" MinWidth="640"','Height="2*" MinHeight="140"','MaxWidth="760"','MinHeight="180"')) {
        if (-not $ProductSource.Contains($Marker)) { throw "Adaptive Windows layout self-test missing $Marker" }
    }
    & $ProductScript -BaseUrl $BaseUrl -SelfTest
} else {
    & $ProductScript -BaseUrl $BaseUrl
}
if (-not $?) { throw 'Router VPN native Windows product shell failed.' }

# Native product contract markers: SelfTest / ShowDialog() / explicit UTF-8 /
# adaptive small-effective-resolution layout.
