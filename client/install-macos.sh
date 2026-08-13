#!/usr/bin/env bash
set -euo pipefail
BUNDLE=${1:-$(pwd)}
[[ -f "$BUNDLE/client.json" && -f "$BUNDLE/routers.json" && -d "$BUNDLE/generated" ]] || { echo 'Run from the extracted Router VPN platform bundle folder.'; exit 1; }
command -v brew >/dev/null || { echo 'Install Homebrew first from brew.sh, then rerun.'; exit 1; }

# Keep the normal install small. Heavy Rust/LLVM build dependencies are only
# installed when this Mac actually needs a local Rosenpass build.
brew install wireguard-tools go make git python sing-box shadowsocks-rust || true
"$BUNDLE/client/install-xray.sh"

ROOT=/opt/router-vpn-client
sudo mkdir -p "$ROOT" "$ROOT/client" /usr/local/bin
sudo cp -a "$BUNDLE/client.json" "$BUNDLE/routers.json" "$BUNDLE/modes.json" "$BUNDLE/modes" "$BUNDLE/generated" "$ROOT/"
[[ -f "$BUNDLE/client/native-multihop-darwin.sh" ]] || { echo 'This bundle is missing the native macOS multihop helper.' >&2; exit 1; }
sudo install -m 755 "$BUNDLE/client/native-multihop-darwin.sh" "$ROOT/client/native-multihop-darwin.sh"
ARCH=$(uname -m)
case "$ARCH" in
  arm64)
    BIN="$BUNDLE/dist/router-vpn-client-darwin-arm64"
    DNS_BIN="$BUNDLE/dist/router-vpn-dns-darwin-arm64"
    ;;
  x86_64)
    BIN="$BUNDLE/dist/router-vpn-client-darwin-amd64"
    DNS_BIN="$BUNDLE/dist/router-vpn-dns-darwin-amd64"
    ;;
  *) echo "Unsupported Mac architecture: $ARCH"; exit 1;;
esac
[[ -x "$BIN" && -x "$DNS_BIN" ]] || { echo 'This platform bundle is missing the matching macOS binaries.' >&2; exit 1; }
sudo install -m 755 "$BIN" /usr/local/bin/router-vpn-client
sudo install -m 755 "$DNS_BIN" /usr/local/bin/router-vpn-dns

if ! command -v rosenpass >/dev/null; then
  echo 'Installing build dependencies for Rosenpass PQ support...'
  brew install rust cmake llvm pkg-config libsodium || true
  echo 'Building Rosenpass for PQ-WireGuard/PQ-AmneziaWG...'
  TMP_RP=$(mktemp -d)
  if git clone --filter=blob:none https://github.com/rosenpass/rosenpass "$TMP_RP/rosenpass" \
    && (cd "$TMP_RP/rosenpass" && git checkout 00569eb273016a10d2e75e5142236f06f7c3d4b3 && cargo build --release --bin rosenpass) \
    && [[ -x "$TMP_RP/rosenpass/target/release/rosenpass" ]]; then
    sudo install -m 755 "$TMP_RP/rosenpass/target/release/rosenpass" /usr/local/bin/rosenpass
  else
    echo 'Warning: Rosenpass build failed. Normal modes still work; PQ-WG/PQ-AWG remain disabled.' >&2
  fi
  rm -rf "$TMP_RP"
fi

if ! command -v v2ray-plugin >/dev/null; then
  echo 'Building V2Ray SIP003 plugin for SS+V2Ray TLS...'
  TMP_V2=$(mktemp -d)
  if git clone --filter=blob:none https://github.com/shadowsocks/v2ray-plugin "$TMP_V2/v2ray-plugin" \
    && (cd "$TMP_V2/v2ray-plugin" && git checkout e9af1cdd2549d528deb20a4ab8d61c5fbe51f306 && GOTOOLCHAIN=auto go build -trimpath -ldflags='-s -w' -o v2ray-plugin .); then
    sudo install -m 755 "$TMP_V2/v2ray-plugin/v2ray-plugin" /usr/local/bin/v2ray-plugin
  else
    echo 'Warning: V2Ray-plugin build failed; SS+V2Ray TLS remains disabled.' >&2
  fi
  rm -rf "$TMP_V2"
fi

if ! command -v amneziawg-go >/dev/null || ! command -v awg >/dev/null || ! command -v awg-quick >/dev/null; then
  TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
  echo 'Building AmneziaWG userspace engine...'
  git clone https://github.com/amnezia-vpn/amneziawg-go "$TMP/amneziawg-go"
  (cd "$TMP/amneziawg-go" && git checkout 0527dfa47639714dd8f5c9ffbd9d40d19083f0ba && GOTOOLCHAIN=auto go mod download && GOTOOLCHAIN=auto go mod verify && GOTOOLCHAIN=auto go build -trimpath -o amneziawg-go .)
  sudo install -m 755 "$TMP/amneziawg-go/amneziawg-go" /usr/local/bin/amneziawg-go

  git init "$TMP/amneziawg-tools"
  git -C "$TMP/amneziawg-tools" remote add origin https://github.com/amnezia-vpn/amneziawg-tools.git
  git -C "$TMP/amneziawg-tools" fetch --depth=1 origin 05434cab7d91bbbc607d18ec5fade91f4b83774c
  git -C "$TMP/amneziawg-tools" checkout --detach FETCH_HEAD
  make -C "$TMP/amneziawg-tools/src" WITH_WGQUICK=yes
  sudo make -C "$TMP/amneziawg-tools/src" install WITH_WGQUICK=yes PREFIX=/usr/local
  rm -rf "$TMP"; trap - EXIT
fi

sudo chmod +x "$ROOT/modes/"*.sh 2>/dev/null || true
cat <<TXT
Installed Router VPN client engines.
The service installer starts the local controller automatically at http://127.0.0.1:8788.
If macOS quarantines a locally-built Router VPN binary, first verify its checksum, then use System Settings > Privacy & Security > Open Anyway. The Setup Center also includes the exact quarantine-removal command for trusted files.
TXT
