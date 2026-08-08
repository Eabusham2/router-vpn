#!/usr/bin/env bash
set -euo pipefail
BUNDLE=${1:-$(pwd)}
[[ -f "$BUNDLE/client.json" && -f "$BUNDLE/routers.json" && -d "$BUNDLE/generated" ]] || { echo 'Run from the extracted router-vpn-client-bundle folder.'; exit 1; }
command -v brew >/dev/null || { echo 'Install Homebrew first from brew.sh, then rerun.'; exit 1; }
brew install wireguard-tools go make git python sing-box rust cmake llvm pkg-config libsodium shadowsocks-rust || true
"$BUNDLE/client/install-xray.sh"
ROOT=/opt/router-vpn-client
sudo mkdir -p "$ROOT" /usr/local/bin
sudo cp -a "$BUNDLE/client.json" "$BUNDLE/routers.json" "$BUNDLE/modes.json" "$BUNDLE/modes" "$BUNDLE/generated" "$ROOT/"
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
sudo install -m 755 "$BIN" /usr/local/bin/router-vpn-client
sudo install -m 755 "$DNS_BIN" /usr/local/bin/router-vpn-dns
if ! command -v rosenpass >/dev/null; then
  echo 'Building Rosenpass for PQ-WireGuard/PQ-AmneziaWG...'
  TMP_RP=$(mktemp -d)
  if git clone https://github.com/rosenpass/rosenpass "$TMP_RP/rosenpass" \
    && (cd "$TMP_RP/rosenpass" && git checkout 00569eb && cargo build --release --bin rosenpass) \
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
  if git clone https://github.com/shadowsocks/v2ray-plugin "$TMP_V2/v2ray-plugin" \
    && (cd "$TMP_V2/v2ray-plugin" && git checkout e9af1cdd2549d528deb20a4ab8d61c5fbe51f306 && GOTOOLCHAIN=auto go build -trimpath -ldflags='-s -w' -o v2ray-plugin .); then
    sudo install -m 755 "$TMP_V2/v2ray-plugin/v2ray-plugin" /usr/local/bin/v2ray-plugin
  else
    echo 'Warning: V2Ray-plugin build failed; SS+V2Ray TLS remains disabled.' >&2
  fi
  rm -rf "$TMP_V2"
fi
if ! command -v amneziawg-go >/dev/null || ! command -v awg-quick >/dev/null; then
  TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
  git clone --branch v3.0.2 --depth 1 https://github.com/amnezia-vpn/amneziawg-go "$TMP/amneziawg-go"
  (cd "$TMP/amneziawg-go" && GOTOOLCHAIN=auto go mod download && GOTOOLCHAIN=auto go mod verify && GOTOOLCHAIN=auto go build -trimpath -o amneziawg-go .)
  sudo install -m 755 "$TMP/amneziawg-go/amneziawg-go" /usr/local/bin/amneziawg-go
  git clone https://github.com/amnezia-vpn/amneziawg-tools "$TMP/amneziawg-tools"
  (cd "$TMP/amneziawg-tools" && git checkout 05434cab7d91bbbc607d18ec5fade91f4b83774c)
  make -C "$TMP/amneziawg-tools/src" WITH_WGQUICK=yes
  sudo make -C "$TMP/amneziawg-tools/src" install WITH_WGQUICK=yes PREFIX=/usr/local
fi
sudo chmod +x "$ROOT/modes/"*.sh 2>/dev/null || true
cat <<TXT
Installed. Start with:
  cd $ROOT
  sudo HOMEVPN_ROOT=$ROOT HOMEVPN_CLIENT_CONFIG=$ROOT/client.json /usr/local/bin/router-vpn-client
Then open http://127.0.0.1:8788
TXT
