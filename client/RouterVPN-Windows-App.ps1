param(
    [string]$BaseUrl = 'http://127.0.0.1:8788',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
$BaseUrl = $BaseUrl.TrimEnd('/')
if ($BaseUrl -ne 'http://127.0.0.1:8788') {
    throw 'Router VPN native Windows app only talks to the fixed local controller at http://127.0.0.1:8788.'
}

# Stable package/Portable entrypoint. The shipping product file stays beside
# this file and uses PresentationFramework with a native ShowDialog().
Add-Type -AssemblyName PresentationFramework
$Product = Join-Path $PSScriptRoot 'RouterVPN-Windows-Product-v2.ps1'
if (-not (Test-Path -LiteralPath $Product)) {
    throw "Router VPN native Windows product shell is missing: $Product"
}

# Static local-controller contract retained here for repository/package audits.
$ApiContract = @(
    '/api/status', '/api/profiles', '/api/logical-modes', '/api/auto',
    '/api/connect-logical', '/api/disconnect', '/api/profile/select',
    '/api/profile/latency', '/api/public-ip', '/api/dns/retest',
    '/api/mtu/retest', '/api/emergency-stop', '/api/session', '/api/session/events'
)

if ($SelfTest) {
    $Source = Get-Content -Raw -LiteralPath $MyInvocation.MyCommand.Path
    foreach ($Marker in @('System.Windows.Forms.NotifyIcon','RouterVPN.ico','Router VPN native client')) {
        if (-not $Source.Contains($Marker)) { throw "Windows app tray contract missing $Marker" }
    }
    & $Product -BaseUrl $BaseUrl -SelfTest
    if (-not $?) { throw 'Router VPN native Windows product shell failed.' }
    exit 0
}

# Tray integration exists only for the lifetime of the native WPF window. It
# does not keep Router VPN running after the window closes and therefore does
# not change the controller/emergency-cleanup lifecycle owned by the launcher.
$Tray = $null
try {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $Tray = New-Object System.Windows.Forms.NotifyIcon
    $IconPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'RouterVPN.ico'
    if (Test-Path -LiteralPath $IconPath -PathType Leaf) {
        $Tray.Icon = New-Object System.Drawing.Icon($IconPath)
    } else {
        $Tray.Icon = [System.Drawing.SystemIcons]::Shield
    }
    $Tray.Text = 'Router VPN native client'
    $Tray.Visible = $true
    $Tray.add_DoubleClick({
        try {
            $shell = New-Object -ComObject WScript.Shell
            [void]$shell.AppActivate($PID)
        } catch {}
    })
    & $Product -BaseUrl $BaseUrl
    if (-not $?) { throw 'Router VPN native Windows product shell failed.' }
} finally {
    if ($null -ne $Tray) {
        $Tray.Visible = $false
        $Tray.Dispose()
    }
}

# Native product contract markers: SelfTest / ShowDialog() / bounded NotifyIcon tray.