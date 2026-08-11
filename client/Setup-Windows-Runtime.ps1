param(
  [string]$PackageRoot = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'

function Test-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
if (-not $wsl) {
  throw 'wsl.exe is not present. Open an elevated PowerShell and run: wsl --install -d Ubuntu ; reboot if Windows asks, then run this setup again.'
}

$probe = & wsl.exe --exec sh -lc 'printf router-vpn-wsl-ready' 2>&1
if ($LASTEXITCODE -ne 0 -or (($probe -join '') -notmatch 'router-vpn-wsl-ready')) {
  if (Test-Administrator) {
    Write-Host 'No usable default WSL distro was found. Installing Ubuntu through WSL...'
    & wsl.exe --install -d Ubuntu
    Write-Host ''
    Write-Host 'WSL/Ubuntu installation was requested. If Windows asks for a reboot or Ubuntu first-run username setup, complete that, then run Setup-Windows-Runtime.ps1 again.'
    exit 2
  }
  throw 'WSL exists but no usable default Linux distro is ready. Re-run this script from an elevated PowerShell to install Ubuntu, then complete Ubuntu first-run setup.'
}

$engineScript = Join-Path $PSScriptRoot 'setup-windows-runtime.sh'
if (-not (Test-Path $engineScript)) {
  $engineScript = Join-Path $PSScriptRoot 'App\RouterVPN\client\setup-windows-runtime.sh'
}
if (-not (Test-Path $engineScript)) {
  throw "Missing Router VPN WSL engine installer under this package: $engineScript"
}

$wslScript = (& wsl.exe --exec wslpath -a -u $engineScript 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or -not $wslScript) {
  throw 'Could not translate the Router VPN engine setup path into WSL.'
}

$quoted = $wslScript.Replace("'", "'\"'\"'")
Write-Host 'Installing/verifying Router VPN tunnel engines inside WSL...'
& wsl.exe --exec bash -lc "sudo bash '$quoted'"
if ($LASTEXITCODE -ne 0) {
  throw 'Router VPN WSL runtime setup failed. Read the first MISSING/error line above; the app will not pretend those modes are ready.'
}

$required = 'wg','wg-quick','sing-box','xray','rosenpass','sslocal','v2ray-plugin','amneziawg-go','awg','awg-quick'
$verify = ($required | ForEach-Object { "command -v $_ >/dev/null || { echo MISSING:$_; exit 1; }" }) -join '; '
& wsl.exe --exec bash -lc $verify
if ($LASTEXITCODE -ne 0) {
  throw 'Runtime verification failed after setup.'
}

Write-Host ''
Write-Host 'Router VPN Windows runtime is ready.'
Write-Host 'Close and reopen RouterVPNPortable.exe (or Start-RouterVPN.ps1) so Router VPN regenerates/rechecks every Windows mode.'
