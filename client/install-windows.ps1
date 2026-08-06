param([string]$Bundle = (Get-Location).Path)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path "$Bundle\client.json") -or -not (Test-Path "$Bundle\routers.json")) { throw 'Run this from the extracted router-vpn-client-bundle folder.' }
$Root = "$env:ProgramData\RouterVPN"
New-Item -Force -ItemType Directory $Root | Out-Null
Copy-Item "$Bundle\client.json","$Bundle\routers.json","$Bundle\modes.json" $Root -Force
Copy-Item "$Bundle\modes","$Bundle\generated" $Root -Recurse -Force
Copy-Item "$Bundle\dist\router-vpn-client-windows-amd64.exe" "$Root\router-vpn-client.exe" -Force
Write-Host 'Windows controller installed. Raw WG/AWG profiles are in:' $Root'\generated'
Write-Host 'The unified all-engine Windows launcher requires WSL2. Run the Linux installer inside WSL2 for AUTO and proxy modes.'
