#!/usr/bin/env bash
set -euo pipefail

BASE=${1:-/opt/router-vpn}
BUNDLE="$BASE/client-bundle"
OUT="$BASE/downloads"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$OUT"

copy_public(){
  local src=$1 name=${2:-$(basename "$1")}
  [[ -f "$src" ]] || return 0
  cp -f "$src" "$OUT/$name"
}

# Small direct downloads that do not depend on a platform package.
copy_public "$BUNDLE/router-vpn-bundle.json"
copy_public "$BUNDLE/CREDENTIALS.txt"
copy_public "$BUNDLE/router/asus-merlin-router-vpn-forwards.sh" "asus-merlin-router-vpn-forwards.sh"
copy_public "$BUNDLE/modes.json"
copy_public "$BUNDLE/logical-modes.json"

make_unix_bundle(){
  local os=$1 arch=$2 label=$3
  local client_bin="$BUNDLE/dist/router-vpn-client-${os}-${arch}"
  local dns_bin="$BUNDLE/dist/router-vpn-dns-${os}-${arch}"
  [[ -x "$client_bin" && -x "$dns_bin" ]] || {
    echo "warning: skipping $label mini bundle; matching binaries are missing" >&2
    return 0
  }
  local d="$TMP/$label/router-vpn"
  mkdir -p "$d/dist"
  cp -a "$BUNDLE/client" "$BUNDLE/modes" "$BUNDLE/generated" "$d/"
  cp -a "$BUNDLE/client.json" "$BUNDLE/routers.json" "$BUNDLE/modes.json" "$BUNDLE/router-vpn-bundle.json" "$d/"
  [[ -f "$BUNDLE/logical-modes.json" ]] && cp "$BUNDLE/logical-modes.json" "$d/"
  cp "$client_bin" "$dns_bin" "$d/dist/"
  mkdir -p "$d/router"
  cp "$BUNDLE/router/asus-merlin-router-vpn-forwards.sh" "$d/router/"
  if [[ $os == darwin ]]; then
    cat >"$d/INSTALL.txt" <<'TXT'
Router VPN macOS
1. Open Terminal and cd into this extracted router-vpn folder.
2. Run: bash client/install-macos-final.sh "$PWD"
3. Launch Router VPN from ~/Applications after installation.
4. If macOS warns about a locally-built Router VPN binary, verify the Setup Center checksum first, then use System Settings > Privacy & Security > Open Anyway. Never remove quarantine broadly from Downloads.
TXT
  else
    cat >"$d/INSTALL.txt" <<'TXT'
Router VPN Linux
1. Open a terminal and cd into this extracted router-vpn folder.
2. Run: sudo bash client/install-linux.sh "$PWD"
3. Start the installed Router VPN controller/app launcher.
TXT
  fi
  (
    cd "$TMP/$label"
    zip -qr "$OUT/$label.zip" router-vpn
  )
}

write_windows_launcher(){
  local file=$1 root_expr=$2 client_expr=$3
  cat >"$file" <<PS1
\$ErrorActionPreference = 'Stop'
\$Root = $root_expr
\$env:HOMEVPN_ROOT = \$Root
\$env:HOMEVPN_CLIENT_CONFIG = Join-Path \$Root 'client.json'
\$client = $client_expr
function Test-RouterVPNReady {
  try {
    \$r = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8788/api/status' -TimeoutSec 1
    return \$r.StatusCode -ge 200 -and \$r.StatusCode -lt 300
  } catch { return \$false }
}
if (-not (Test-RouterVPNReady)) { Start-Process \$client -WorkingDirectory \$Root }
\$deadline = (Get-Date).AddSeconds(12)
while ((Get-Date) -lt \$deadline -and -not (Test-RouterVPNReady)) { Start-Sleep -Milliseconds 200 }
if (-not (Test-RouterVPNReady)) { throw 'Router VPN controller did not become ready on 127.0.0.1:8788' }
\$url='http://127.0.0.1:8788/'
\$browsers=@(
  "\$env:ProgramFiles(x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "\$env:ProgramFiles\\Microsoft\\Edge\\Application\\msedge.exe",
  "\$env:ProgramFiles\\Google\\Chrome\\Application\\chrome.exe",
  "\$env:LOCALAPPDATA\\Google\\Chrome\\Application\\chrome.exe",
  "\$env:ProgramFiles\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
  "\$env:LOCALAPPDATA\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"
)
foreach (\$browser in \$browsers) {
  if (\$browser -and (Test-Path \$browser)) { Start-Process \$browser -ArgumentList "--app=\$url"; exit 0 }
}
Start-Process \$url
PS1
}

make_windows_bundle(){
  local arch=$1 label=$2
  local client_bin="$BUNDLE/dist/router-vpn-client-windows-${arch}.exe"
  local dns_bin="$BUNDLE/dist/router-vpn-dns-windows-${arch}.exe"
  [[ -f "$client_bin" && -f "$dns_bin" ]] || {
    echo "warning: skipping $label mini bundle; matching Windows binaries are missing" >&2
    return 0
  }
  local d="$TMP/$label/router-vpn"
  mkdir -p "$d/router"
  cp -a "$BUNDLE/modes" "$BUNDLE/generated" "$BUNDLE/client" "$d/"
  cp -a "$BUNDLE/client.json" "$BUNDLE/routers.json" "$BUNDLE/modes.json" "$BUNDLE/router-vpn-bundle.json" "$d/"
  [[ -f "$BUNDLE/logical-modes.json" ]] && cp "$BUNDLE/logical-modes.json" "$d/"
  cp "$client_bin" "$d/router-vpn-client.exe"
  cp "$dns_bin" "$d/router-vpn-dns.exe"
  [[ -f "$BUNDLE/client/install-windows.ps1" ]] && cp "$BUNDLE/client/install-windows.ps1" "$d/"
  [[ -f "$BUNDLE/client/Setup-Windows-Runtime.ps1" ]] && cp "$BUNDLE/client/Setup-Windows-Runtime.ps1" "$d/"
  [[ -f "$BUNDLE/client/setup-windows-runtime.sh" ]] && cp "$BUNDLE/client/setup-windows-runtime.sh" "$d/"
  [[ -f "$BUNDLE/client/install-xray.sh" ]] && cp "$BUNDLE/client/install-xray.sh" "$d/"
  cp "$BUNDLE/router/asus-merlin-router-vpn-forwards.sh" "$d/router/"
  write_windows_launcher "$d/Start-RouterVPN.ps1" '(Split-Path -Parent $MyInvocation.MyCommand.Path)' '(Join-Path $Root "router-vpn-client.exe")'
  cat >"$d/INSTALL.txt" <<TXT
Router VPN Windows $arch
1. Extract this folder.
2. Run Setup-Windows-Runtime.ps1 once for the full WSL tunnel/proxy engine set.
3. Run Start-RouterVPN.ps1. It starts the controller, waits until it answers, then opens Router VPN as an Edge/Chrome/Brave app window when possible.
4. This home-generated package is already linked to this Router VPN node and includes its generated profiles.
TXT
  (
    cd "$TMP/$label"
    zip -qr "$OUT/$label.zip" router-vpn
  )
}

make_windows_portable(){
  local arch=$1
  local client_bin="$BUNDLE/dist/router-vpn-client-windows-${arch}.exe"
  local dns_bin="$BUNDLE/dist/router-vpn-dns-windows-${arch}.exe"
  local launcher="$BUNDLE/dist/RouterVPNPortable-${arch}.exe"
  [[ -f "$client_bin" && -f "$dns_bin" && -f "$launcher" ]] || {
    echo "warning: skipping Windows portable $arch; required binaries are missing" >&2
    return 0
  }

  local root="$TMP/portable-$arch/RouterVPNPortable-$arch"
  local app="$root/App/RouterVPN"
  local data="$root/Data"
  mkdir -p "$app/modes" "$data/generated" "$root/Other"

  # Immutable application payload.
  cp -a "$BUNDLE/modes/." "$app/modes/"
  cp -a "$BUNDLE/client" "$app/client"
  cp "$BUNDLE/modes.json" "$app/modes.json"
  cp "$BUNDLE/logical-modes.json" "$app/logical-modes.json"
  cp "$BUNDLE/client.json" "$app/client.json"
  cp "$BUNDLE/routers.json" "$app/routers.json"
  cp "$BUNDLE/router-vpn-bundle.json" "$app/router-vpn-bundle.json"
  cp "$client_bin" "$app/router-vpn-client.exe"
  cp "$dns_bin" "$app/router-vpn-dns.exe"
  cp "$launcher" "$root/RouterVPNPortable.exe"
  cp "$BUNDLE/client/Setup-Windows-Runtime.ps1" "$root/Setup-Windows-Runtime.ps1"

  # This Setup Center package is private and node-specific, so pre-link its
  # mutable Data folder to the current home node. The generic GitHub artifact
  # intentionally keeps Data empty and requires an import instead.
  cp "$BUNDLE/routers.json" "$data/routers.json"
  cp -a "$BUNDLE/generated/." "$data/generated/"
  cat >"$root/README.txt" <<TXT
Router VPN Portable $arch — home-linked package
1. Run Setup-Windows-Runtime.ps1 once for full mode support.
2. Double-click RouterVPNPortable.exe.
App/RouterVPN contains immutable binaries/catalog/scripts.
Data contains this home node's private settings, generated profiles and portable browser state.
Move the whole RouterVPNPortable-$arch folder together; do not publish/share it.
TXT

  # Ordinary no-installer package keeps the root setup helper for convenience.
  (
    cd "$TMP/portable-$arch"
    zip -qr "$OUT/router-vpn-windows-portable-$arch.zip" "RouterVPNPortable-$arch"
  )

  # PortableApps.com Format 3.9 source. Keep the package root clean and expose
  # Windows engine setup as a second PortableApps Platform menu item.
  mkdir -p "$root/App/AppInfo" "$root/Other/Help"
  cp "$root/README.txt" "$root/Other/Help/readme.txt"
  rm -f "$root/README.txt" "$root/Setup-Windows-Runtime.ps1"
  cat >"$root/App/AppInfo/appinfo.ini" <<EOF
[Format]
Type=PortableApps.comFormat
Version=3.9

[Details]
Name=Router VPN Portable ($arch)
AppId=RouterVPNPortable${arch}Eabusham2
Publisher=Eabusham2
Homepage=https://github.com/Eabusham2/router-vpn
Category=Internet
Description=Portable Router VPN controller, logical-mode selector, and private node profile manager
Language=English

[License]
Shareable=true
OpenSource=false
Freeware=true
CommercialUse=false

[Version]
PackageVersion=0.7.0.0
DisplayVersion=0.7.0 Alpha

[Control]
Icons=2
Start=RouterVPNPortable.exe
Start1=RouterVPNPortable.exe
Name1=Router VPN Portable
Start2=powershell.exe -NoProfile -ExecutionPolicy Bypass -File App\RouterVPN\client\Setup-Windows-Runtime.ps1
Name2=Router VPN Portable - Setup Windows Runtime
ExtractIcon=RouterVPNPortable.exe
ExtractIcon1=RouterVPNPortable.exe
ExtractIcon2=RouterVPNPortable.exe
EOF
  cat >"$root/App/AppInfo/installer.ini" <<'EOF'
[MainDirectories]
RemoveAppDirectory=true
RemoveDataDirectory=false
RemoveOtherDirectory=true
EOF
  (
    cd "$TMP/portable-$arch"
    zip -qr "$OUT/router-vpn-portableapps-$arch.zip" "RouterVPNPortable-$arch"
  )
}

make_unix_bundle darwin arm64 router-vpn-macos-arm64
make_unix_bundle darwin amd64 router-vpn-macos-amd64
make_unix_bundle linux arm64 router-vpn-linux-arm64
make_unix_bundle linux amd64 router-vpn-linux-amd64
make_windows_bundle amd64 router-vpn-windows-amd64
make_windows_bundle arm64 router-vpn-windows-arm64
make_windows_portable amd64
make_windows_portable arm64

# Add Windows/portable downloads to the Setup Center without duplicating the
# large mode/QR HTML generator here.
python3 - "$BUNDLE/router-vpn-device-setup.html" "$BUNDLE/setup-assets.json" <<'PY'
from pathlib import Path
import json,sys
html=Path(sys.argv[1]); assets=Path(sys.argv[2])
text=html.read_text()
if 'router-vpn-windows-portable-amd64.zip' not in text:
    needle="['Linux x86-64','router-vpn-linux-amd64.zip','x86-64 Linux'],"
    extra=(
      "['Windows x64','router-vpn-windows-amd64.zip','Windows x86-64 controller/app package'],"
      "['Windows ARM64','router-vpn-windows-arm64.zip','Windows ARM64 controller/app package'],"
      "['Portable Windows x64','router-vpn-windows-portable-amd64.zip','No-install home-linked portable folder'],"
      "['Portable Windows ARM64','router-vpn-windows-portable-arm64.zip','No-install home-linked portable folder'],"
      "['PortableApps 3.9 x64 source','router-vpn-portableapps-amd64.zip','Home-linked PortableApps source folder with app + runtime setup menu entries; official .paf.exe comes from CI'],"
      "['PortableApps 3.9 ARM64 source','router-vpn-portableapps-arm64.zip','Home-linked PortableApps source folder with app + runtime setup menu entries; official .paf.exe comes from CI'],"
    )
    if needle not in text:
        raise SystemExit('Setup Center download marker changed; refusing to publish unlinked portable downloads')
    text=text.replace(needle, needle+''.join(extra), 1)
    html.write_text(text)
try:
    data=json.loads(assets.read_text())
except Exception:
    data={}
wanted=[
 'router-vpn-windows-amd64.zip','router-vpn-windows-arm64.zip',
 'router-vpn-windows-portable-amd64.zip','router-vpn-windows-portable-arm64.zip',
 'router-vpn-portableapps-amd64.zip','router-vpn-portableapps-arm64.zip'
]
arr=data.setdefault('downloads',[])
for item in wanted:
    if item not in arr: arr.append(item)
assets.write_text(json.dumps(data,indent=2)+'\n')
PY

# Publish the patched Setup Center after all download names are known.
copy_public "$BUNDLE/router-vpn-device-setup.html" "index.html"
copy_public "$BUNDLE/router-vpn-device-setup.html"
copy_public "$BUNDLE/setup-assets.json"

# Keep the complete bundle for advanced/offline use, but it is no longer the
# first/default download path.
rm -f "$OUT/router-vpn-client-bundle.zip"
(
  cd "$BUNDLE"
  zip -qr "$OUT/router-vpn-client-bundle.zip" .
)

(
  cd "$OUT"
  rm -f SHA256SUMS
  for f in \
    router-vpn-bundle.json \
    asus-merlin-router-vpn-forwards.sh \
    router-vpn-macos-*.zip \
    router-vpn-linux-*.zip \
    router-vpn-windows-*.zip \
    router-vpn-portableapps-*.zip \
    router-vpn-client-bundle.zip; do
    [[ -f $f ]] || continue
    sha256sum "$f" >> SHA256SUMS
  done
)

echo 'Published Setup Center, direct profile/helper downloads, macOS/Linux/Windows bundles, Windows Portable/PortableApps 3.9 x64+ARM64 with runtime setup, and full fallback bundle.'
