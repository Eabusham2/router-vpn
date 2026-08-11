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

# Small direct downloads: these are enough when the Router VPN app/controller is
# already installed and avoid the much larger all-platform private bundle.
copy_public "$BUNDLE/router-vpn-bundle.json"
copy_public "$BUNDLE/CREDENTIALS.txt"
copy_public "$BUNDLE/router-vpn-device-setup.html" "index.html"
copy_public "$BUNDLE/router-vpn-device-setup.html"
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
    cat >"$d/INSTALL.txt" <<TXT
Router VPN macOS $arch
1. Open Terminal and cd into this router-vpn folder.
2. Run: bash client/install-macos-final.sh "$PWD"
3. If macOS warns about a locally-built Router VPN binary, verify the included binary/checksum source, then use System Settings > Privacy & Security > Open Anyway. The Setup Center has detailed steps.
4. Open the Router VPN app/controller and import router-vpn-bundle.json or use home-LAN import when available.
TXT
  else
    cat >"$d/INSTALL.txt" <<TXT
Router VPN Linux $arch
1. Open a terminal and cd into this router-vpn folder.
2. Run: sudo bash client/install-linux.sh "$PWD"
3. Open the Router VPN app/controller and import router-vpn-bundle.json or use home-LAN import when available.
TXT
  fi
  (
    cd "$TMP/$label"
    zip -qr "$OUT/$label.zip" router-vpn
  )
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
  mkdir -p "$d/dist" "$d/router"
  cp -a "$BUNDLE/modes" "$BUNDLE/generated" "$d/"
  cp -a "$BUNDLE/client.json" "$BUNDLE/routers.json" "$BUNDLE/modes.json" "$BUNDLE/router-vpn-bundle.json" "$d/"
  [[ -f "$BUNDLE/logical-modes.json" ]] && cp "$BUNDLE/logical-modes.json" "$d/"
  cp "$client_bin" "$d/dist/router-vpn-client.exe"
  cp "$dns_bin" "$d/dist/router-vpn-dns.exe"
  [[ -f "$BUNDLE/client/install-windows.ps1" ]] && cp "$BUNDLE/client/install-windows.ps1" "$d/"
  cp "$BUNDLE/router/asus-merlin-router-vpn-forwards.sh" "$d/router/"
  cat >"$d/INSTALL.txt" <<TXT
Router VPN Windows $arch
1. Extract this folder.
2. Run install-windows.ps1 when present, or start the included Router VPN controller binary.
3. Import router-vpn-bundle.json or use home-LAN import when available.
4. Full multi-engine tunneling must only be shown as ready once the Windows native tunnel adapters are validated; matching native WireGuard/Amnezia profiles remain available in Setup Center.
TXT
  (
    cd "$TMP/$label"
    zip -qr "$OUT/$label.zip" router-vpn
  )
}

make_unix_bundle darwin arm64 router-vpn-macos-arm64
make_unix_bundle darwin amd64 router-vpn-macos-amd64
make_unix_bundle linux arm64 router-vpn-linux-arm64
make_unix_bundle linux amd64 router-vpn-linux-amd64
make_windows_bundle amd64 router-vpn-windows-amd64
make_windows_bundle arm64 router-vpn-windows-arm64

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
  for f in router-vpn-bundle.json asus-merlin-router-vpn-forwards.sh router-vpn-macos-*.zip router-vpn-linux-*.zip router-vpn-windows-*.zip router-vpn-client-bundle.zip; do
    [[ -f $f ]] || continue
    sha256sum "$f" >> SHA256SUMS
  done
)

echo 'Published Setup Center, direct router profile/helper downloads, macOS/Linux/Windows mini bundles, and full fallback bundle.'
