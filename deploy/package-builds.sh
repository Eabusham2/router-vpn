#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DIST="$ROOT/dist"
OUT="$DIST/packages"
rm -rf "$OUT"
mkdir -p "$OUT"

write_blank_routers(){
  cat >"$1" <<'JSON'
{
  "selected_id": "",
  "profiles": []
}
JSON
}

copy_runtime(){
  local dir=$1
  mkdir -p "$dir/modes" "$dir/generated"
  cp "$ROOT/configs/client/client.json.example" "$dir/client.json"
  cp "$ROOT/configs/client/modes.json" "$dir/modes.json"
  cp "$ROOT/configs/client/logical-modes.json" "$dir/logical-modes.json"
  cp -a "$ROOT/modes/." "$dir/modes/"
  write_blank_routers "$dir/routers.json"
  cp "$ROOT/docs/MODES.md" "$dir/MODES.md"
  cp "$ROOT/docs/CLIENT.md" "$dir/CLIENT.md"
  cp "$ROOT/SECURITY.md" "$dir/SECURITY.md"
}

package_zip(){
  local name=$1 dir=$2
  (cd "$(dirname "$dir")" && zip -qr "$OUT/$name.zip" "$(basename "$dir")")
}

package_tgz(){
  local name=$1 dir=$2
  tar -C "$(dirname "$dir")" -czf "$OUT/$name.tar.gz" "$(basename "$dir")"
}

write_windows_app_launcher(){
  local file=$1
  cat >"$file" <<'PS1'
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:HOMEVPN_ROOT = $Root
$env:HOMEVPN_CLIENT_CONFIG = Join-Path $Root 'client.json'
$client = Join-Path $Root 'router-vpn-client.exe'

function Test-RouterVPNReady {
  try {
    $r = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8788/api/status' -TimeoutSec 1
    return $r.StatusCode -ge 200 -and $r.StatusCode -lt 300
  } catch { return $false }
}

if (-not (Test-RouterVPNReady)) {
  Start-Process $client -WorkingDirectory $Root
}

$deadline = (Get-Date).AddSeconds(12)
while ((Get-Date) -lt $deadline -and -not (Test-RouterVPNReady)) {
  Start-Sleep -Milliseconds 200
}
if (-not (Test-RouterVPNReady)) { throw 'Router VPN controller did not become ready on 127.0.0.1:8788' }

$url = 'http://127.0.0.1:8788/'
$candidates = @(
  "$env:ProgramFiles(x86)\Microsoft\Edge\Application\msedge.exe",
  "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
  "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
  "$env:ProgramFiles(x86)\Google\Chrome\Application\chrome.exe",
  "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe",
  "$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe",
  "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\Application\brave.exe"
)
foreach ($browser in $candidates) {
  if ($browser -and (Test-Path $browser)) {
    Start-Process $browser -ArgumentList "--app=$url"
    exit 0
  }
}
Start-Process $url
PS1
}

# Windows controller packages. Full shell-engine operation uses the WSL runtime
# installed by Setup-Windows-Runtime.ps1 or matching native protocol apps.
for arch in amd64 arm64; do
  dir="$OUT/work/RouterVPN-Windows-$arch"
  mkdir -p "$dir"
  copy_runtime "$dir"
  cp "$DIST/client/router-vpn-client-windows-$arch.exe" "$dir/router-vpn-client.exe"
  cp "$DIST/dnsproxy/router-vpn-dns-windows-$arch.exe" "$dir/router-vpn-dns.exe"
  cp -a "$ROOT/client" "$dir/client"
  cp "$ROOT/client/install-windows.ps1" "$dir/install-windows.ps1"
  cp "$ROOT/client/Setup-Windows-Runtime.ps1" "$dir/Setup-Windows-Runtime.ps1"
  cp "$ROOT/client/setup-windows-runtime.sh" "$ROOT/client/install-xray.sh" "$dir/"
  write_windows_app_launcher "$dir/Start-RouterVPN.ps1"
  cat >"$dir/README-WINDOWS.txt" <<'TXT'
Run Start-RouterVPN.ps1 for the Router VPN controller/app window.
For full Router VPN shell-engine operation, run Setup-Windows-Runtime.ps1 once. It checks
WSL/Ubuntu, installs the required tunnel/proxy engines, and refuses to claim readiness when an
engine is still missing. Raw WireGuard/AmneziaWG profiles can also be imported into native apps.
TXT
  package_zip "RouterVPN-Windows-$arch" "$dir"
done

# Windows Portable + PortableApps packages. Static binaries/catalog/scripts live
# under App/RouterVPN. Writable/private state stays under Data. Both amd64 and
# arm64 use the same launcher and package model.
for arch in amd64 arm64; do
  root="$OUT/work/RouterVPNPortable-$arch"
  app="$root/App/RouterVPN"
  data="$root/Data"
  mkdir -p "$app" "$data/generated"
  copy_runtime "$app"
  cp -a "$ROOT/client" "$app/client"
  cp "$DIST/client/router-vpn-client-windows-$arch.exe" "$app/router-vpn-client.exe"
  cp "$DIST/dnsproxy/router-vpn-dns-windows-$arch.exe" "$app/router-vpn-dns.exe"
  cp "$DIST/client/RouterVPNPortable-$arch.exe" "$root/RouterVPNPortable.exe"
  cp "$ROOT/client/Setup-Windows-Runtime.ps1" "$root/Setup-Windows-Runtime.ps1"
  cat >"$root/README.txt" <<'TXT'
Double-click RouterVPNPortable.exe.

App/RouterVPN contains immutable Router VPN binaries, raw/logical mode catalogs, scripts and
runtime setup helpers. Data contains only writable settings, imported private router profiles,
state, generated per-router material and the dedicated portable browser profile.

For full shell-engine operation on Windows, run Setup-Windows-Runtime.ps1 once. The launcher
then routes Router VPN mode checks/runs through WSL with Windows paths translated automatically.
Move the whole RouterVPNPortable folder together; private imported profiles remain in Data.
TXT

  # Ordinary no-installer portable ZIP.
  package_zip "RouterVPN-Portable-Windows-$arch" "$root"

  # PortableApps.com-format metadata. Root executable + App/AppInfo + Data follows
  # the PortableApps directory model while preserving the same privacy boundary.
  mkdir -p "$root/App/AppInfo"
  cat >"$root/App/AppInfo/appinfo.ini" <<EOF
[Format]
Type=PortableApps.comFormat
Version=3.8

[Details]
Name=Router VPN Portable ($arch)
AppId=RouterVPNPortable$arch
Publisher=Eabusham2
Homepage=https://github.com/Eabusham2/router-vpn
Category=Internet
Description=Portable Router VPN controller, logical-mode selector, and private profile manager
Language=English

[Version]
PackageVersion=0.7.0.0
DisplayVersion=0.7.0-alpha

[Control]
Start=RouterVPNPortable.exe
EOF
  package_zip "RouterVPNPortable-$arch" "$root"
done

# macOS, Linux, BSD, and illumos packages.
while IFS= read -r binary; do
  file=$(basename "$binary")
  target=${file#router-vpn-client-}
  os=${target%%-*}
  rest=${target#*-}
  arch=${rest%.exe}
  case "$os" in
    windows) continue ;;
  esac
  name="RouterVPN-${os}-${arch}"
  dir="$OUT/work/$name"
  mkdir -p "$dir"
  copy_runtime "$dir"
  cp "$binary" "$dir/router-vpn-client"
  cp "$DIST/dnsproxy/router-vpn-dns-${os}-${arch}" "$dir/router-vpn-dns"
  chmod +x "$dir/router-vpn-client" "$dir/router-vpn-dns" "$dir/modes/"*.sh
  cat >"$dir/start-router-vpn.sh" <<'SH'
#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export HOMEVPN_ROOT="$ROOT"
export HOMEVPN_CLIENT_CONFIG="$ROOT/client.json"
cd "$ROOT"
exec ./router-vpn-client
SH
  chmod +x "$dir/start-router-vpn.sh"
  package_tgz "$name" "$dir"
done < <(find "$DIST/client" -maxdepth 1 -type f -name 'router-vpn-client-*' | sort)

cp "$DIST/SHA256SUMS" "$OUT/BINARY-SHA256SUMS"
(
  cd "$OUT"
  find . -maxdepth 1 -type f ! -name 'SHA256SUMS' -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)
rm -rf "$OUT/work"
printf 'Packaged artifacts in %s\n' "$OUT"
