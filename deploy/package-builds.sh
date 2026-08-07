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
  cp -a "$ROOT/modes/." "$dir/modes/"
  write_blank_routers "$dir/routers.json"
  cp "$ROOT/docs/MODES.md" "$dir/MODES.md"
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

# Windows native controller packages. Full tunnel modes use WSL2 because the
# launchers and upstream engines are Unix-oriented.
for arch in amd64 arm64; do
  dir="$OUT/work/RouterVPN-Windows-$arch"
  mkdir -p "$dir"
  copy_runtime "$dir"
  cp "$DIST/client/router-vpn-client-windows-$arch.exe" "$dir/router-vpn-client.exe"
  cp "$DIST/dnsproxy/router-vpn-dns-windows-$arch.exe" "$dir/router-vpn-dns.exe"
  cp "$ROOT/client/install-windows.ps1" "$dir/install-windows.ps1"
  cat >"$dir/Start-RouterVPN.ps1" <<'PS1'
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:HOMEVPN_ROOT = $Root
$env:HOMEVPN_CLIENT_CONFIG = Join-Path $Root 'client.json'
Start-Process (Join-Path $Root 'router-vpn-client.exe') -WorkingDirectory $Root
Start-Sleep -Milliseconds 900
Start-Process 'http://127.0.0.1:8788'
PS1
  cat >"$dir/README-WINDOWS.txt" <<'TXT'
Run Start-RouterVPN.ps1 for the native controller and profile importer.
For full AUTO/tunnel engines, install WSL2 and run the Linux package inside WSL2.
Raw profile files can also be imported into matching native WireGuard/Amnezia clients.
TXT
  package_zip "RouterVPN-Windows-$arch" "$dir"
done

# PortableApps-style packages with a native launcher and writable Data folder.
for arch in amd64 arm64; do
  root="$OUT/work/RouterVPNPortable-$arch"
  app="$root/App/RouterVPN"
  data="$root/Data"
  mkdir -p "$app" "$data"
  copy_runtime "$data"
  cp "$DIST/client/router-vpn-client-windows-$arch.exe" "$app/router-vpn-client.exe"
  cp "$DIST/dnsproxy/router-vpn-dns-windows-$arch.exe" "$app/router-vpn-dns.exe"
  cp "$DIST/client/RouterVPNPortable-$arch.exe" "$root/RouterVPNPortable.exe"
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
Description=Portable Router VPN controller and profile importer
Language=English

[Version]
PackageVersion=0.6.0.0
DisplayVersion=0.6.0-alpha

[Control]
Start=RouterVPNPortable.exe
EOF
  cat >"$root/README.txt" <<'TXT'
Double-click RouterVPNPortable.exe. Settings and imported private profiles stay in Data.
The Windows-native package is a controller/importer. Full multi-engine VPN operation uses
WSL2 or matching native tunnel engines; do not expose the router SOCKS5 port to WAN.
TXT
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
