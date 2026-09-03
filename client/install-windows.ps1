param([string]$Bundle = (Get-Location).Path)
$ErrorActionPreference = 'Stop'
$Bundle = [IO.Path]::GetFullPath($Bundle)
foreach ($required in @('client.json','routers.json','modes.json','logical-modes.json','RouterVPN.exe','RouterVPN.ico','router-vpn-client.exe','router-vpn-update.exe')) {
    if (-not (Test-Path -LiteralPath (Join-Path $Bundle $required) -PathType Leaf)) {
        throw "Run this from an extracted RouterVPN-Windows package; missing $required"
    }
}
foreach ($requiredDir in @('modes','generated','client')) {
    if (-not (Test-Path -LiteralPath (Join-Path $Bundle $requiredDir) -PathType Container)) {
        throw "Router VPN package is missing $requiredDir/"
    }
}

$Root = Join-Path $env:ProgramData 'RouterVPN'
New-Item -Force -ItemType Directory $Root | Out-Null

# Immutable application/runtime material may be refreshed on upgrade.
Copy-Item (Join-Path $Bundle 'client.json'),(Join-Path $Bundle 'modes.json'),(Join-Path $Bundle 'logical-modes.json') $Root -Force
Copy-Item (Join-Path $Bundle 'modes'),(Join-Path $Bundle 'client') $Root -Recurse -Force
Copy-Item (Join-Path $Bundle 'router-vpn-client.exe') (Join-Path $Root 'router-vpn-client.exe') -Force
if (Test-Path -LiteralPath (Join-Path $Bundle 'router-vpn-dns.exe') -PathType Leaf) {
    Copy-Item (Join-Path $Bundle 'router-vpn-dns.exe') (Join-Path $Root 'router-vpn-dns.exe') -Force
}
Copy-Item (Join-Path $Bundle 'router-vpn-update.exe') (Join-Path $Root 'router-vpn-update.exe') -Force
Copy-Item (Join-Path $Bundle 'RouterVPN.exe') (Join-Path $Root 'RouterVPN.exe') -Force
Copy-Item (Join-Path $Bundle 'RouterVPN.ico') (Join-Path $Root 'RouterVPN.ico') -Force
if (Test-Path -LiteralPath (Join-Path $Bundle 'RouterVPN.png') -PathType Leaf) {
    Copy-Item (Join-Path $Bundle 'RouterVPN.png') (Join-Path $Root 'RouterVPN.png') -Force
}

# Private linked-node state is install-once data. Never replace a valid existing
# node store with the generic package's intentionally blank routers.json.
$InstalledRouters = Join-Path $Root 'routers.json'
if (-not (Test-Path -LiteralPath $InstalledRouters -PathType Leaf)) {
    Copy-Item (Join-Path $Bundle 'routers.json') $InstalledRouters -Force
}
$InstalledGenerated = Join-Path $Root 'generated'
if (-not (Test-Path -LiteralPath $InstalledGenerated -PathType Container)) {
    Copy-Item (Join-Path $Bundle 'generated') $InstalledGenerated -Recurse -Force
}

# Normal Windows application integration: Start Menu launches the native GUI
# launcher and uses the Router VPN icon. No browser/PWA/WSL shortcut is created.
$Programs = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'
New-Item -Force -ItemType Directory $Programs | Out-Null
$ShortcutPath = Join-Path $Programs 'Router VPN.lnk'
$Shell = New-Object -ComObject WScript.Shell
$Shortcut = $Shell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = Join-Path $Root 'RouterVPN.exe'
$Shortcut.WorkingDirectory = $Root
$Shortcut.IconLocation = (Join-Path $Root 'RouterVPN.ico') + ',0'
$Shortcut.Description = 'Router VPN native Windows client'
$Shortcut.Save()

$env:HOMEVPN_ROOT = $Root
$env:HOMEVPN_CLIENT_CONFIG = Join-Path $Root 'client.json'
Write-Host 'Router VPN installed in' $Root
Write-Host 'Start it from the Windows Start Menu: Router VPN'
Write-Host 'Existing linked Router VPN nodes were preserved if already present.'
Write-Host 'Raw WireGuard uses the official WireGuard for Windows tunnel service.'
Write-Host 'For native layered TUN modes, run client\Setup-Windows-Runtime.ps1 -PackageRoot' $Root
Write-Host 'Unsupported engines stay unavailable with an exact readiness reason; Router VPN does not use WSL as a substitute.'