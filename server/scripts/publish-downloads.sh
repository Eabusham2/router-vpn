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
  cp "$client_bin" "$dns_bin" "$d/dist/"
  mkdir -p "$d/router"
  cp "$BUNDLE/router/asus-merlin-router-vpn-forwards.sh" "$d/router/"
  if [[ $os == darwin ]]; then
    cat >"$d/INSTALL.txt" <<TXT
Router VPN macOS $arch
1. Open Terminal and cd into this router-vpn folder.
2. Run: bash client/install-macos-final.sh "$PWD"
3. If macOS warns about a locally-built Router VPN binary, verify the included binary/checksum source, then use System Settings > Privacy & Security > Open Anyway. The Setup Center has detailed steps.
4. Open Router VPN from the installed app/PWA or http://127.0.0.1:8788 and import router-vpn-bundle.json.
TXT
  else
    cat >"$d/INSTALL.txt" <<TXT
Router VPN Linux $arch
1. Open a terminal and cd into this router-vpn folder.
2. Run: sudo bash client/install-linux.sh "$PWD"
3. Open the local Router VPN UI and import router-vpn-bundle.json.
TXT
  fi
  (
    cd "$TMP/$label"
    zip -qr "$OUT/$label.zip" router-vpn
  )
}

make_unix_bundle darwin arm64 router-vpn-macos-arm64
make_unix_bundle darwin amd64 router-vpn-macos-amd64
make_unix_bundle linux arm64 router-vpn-linux-arm64
make_unix_bundle linux amd64 router-vpn-linux-amd64

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
  for f in router-vpn-bundle.json asus-merlin-router-vpn-forwards.sh router-vpn-macos-*.zip router-vpn-linux-*.zip router-vpn-client-bundle.zip; do
    [[ -f $f ]] || continue
    sha256sum "$f" >> SHA256SUMS
  done
)

echo 'Published Setup Center, direct router profile/helper downloads, per-platform mini bundles, and full fallback bundle.'
