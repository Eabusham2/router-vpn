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
$ProductScript = [ScriptBlock]::Create($ProductSource)

# Static local-controller contract retained here for repository/package audits.
$ApiContract = @(
    '/api/status', '/api/profiles', '/api/logical-modes', '/api/auto',
    '/api/connect-logical', '/api/disconnect', '/api/profile/select',
    '/api/profile/latency', '/api/public-ip', '/api/dns/retest', '/api/dns/policy',
    '/api/mtu/retest', '/api/emergency-stop', '/api/session', '/api/session/events'
)

if ($SelfTest) {
    & $ProductScript -BaseUrl $BaseUrl -SelfTest
} else {
    & $ProductScript -BaseUrl $BaseUrl
}
if (-not $?) { throw 'Router VPN native Windows product shell failed.' }

# Native product contract markers: SelfTest / ShowDialog() / explicit UTF-8.
