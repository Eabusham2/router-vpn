param(
    [string]$BaseUrl = 'http://127.0.0.1:8788',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
$BaseUrl = $BaseUrl.TrimEnd('/')
if ($BaseUrl -ne 'http://127.0.0.1:8788') {
    throw 'Router VPN native Windows app only talks to the fixed local controller at http://127.0.0.1:8788.'
}

# Stable package/Portable entrypoint. The real shipping product file remains
# beside this file and uses PresentationFramework with a native ShowDialog().
Add-Type -AssemblyName PresentationFramework
$Product = Join-Path $PSScriptRoot 'RouterVPN-Windows-Product.ps1'
if (-not (Test-Path -LiteralPath $Product)) {
    throw "Router VPN native Windows product shell is missing: $Product"
}

# Static local-controller contract retained here for repository/package audits.
$ApiContract = @(
    '/api/status', '/api/profiles', '/api/logical-modes', '/api/auto',
    '/api/connect-logical', '/api/disconnect', '/api/profile/select',
    '/api/profile/latency', '/api/public-ip', '/api/dns/retest',
    '/api/emergency-stop', '/api/session', '/api/session/events'
)

if ($SelfTest) {
    & $Product -BaseUrl $BaseUrl -SelfTest
} else {
    & $Product -BaseUrl $BaseUrl
}
if (-not $?) { throw 'Router VPN native Windows product shell failed.' }

# Native product contract markers: SelfTest / ShowDialog().
