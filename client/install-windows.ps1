param([string]$Bundle = (Get-Location).Path)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path "$Bundle\client.json") -or -not (Test-Path "$Bundle\routers.json")) { throw 'Run this from the extracted router-vpn-client-bundle folder.' }
$Root = "$env:ProgramData\RouterVPN"
New-Item -Force -ItemType Directory $Root | Out-Null
Copy-Item "$Bundle\client.json","$Bundle\routers.json","$Bundle\modes.json" $Root -Force
Copy-Item "$Bundle\modes","$Bundle\generated","$Bundle\client" $Root -Recurse -Force
Copy-Item "$Bundle\dist\router-vpn-client-windows-amd64.exe" "$Root\router-vpn-client.exe" -Force
$env:HOMEVPN_ROOT = $Root
$env:HOMEVPN_CLIENT_CONFIG = Join-Path $Root 'client.json'
Write-Host 'Windows controller installed in' $Root
Write-Host 'Raw WireGuard uses the official WireGuard for Windows tunnel service.'
Write-Host 'For native layered TUN modes, run client\Setup-Windows-Runtime.ps1 -PackageRoot' $Root
Write-Host 'Unsupported engines stay unavailable with an exact readiness reason; Router VPN does not use WSL as a substitute.'
