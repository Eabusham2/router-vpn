#!/usr/bin/env bash
set -euo pipefail
BUNDLE=${1:-$(pwd)}
[[ -f "$BUNDLE/client.json" && -f "$BUNDLE/routers.json" && -d "$BUNDLE/generated" ]] || { echo 'Run from the extracted router-vpn-client-bundle folder.'; exit 1; }
command -v brew >/dev/null || { echo 'Install Homebrew first from brew.sh, then rerun.'; exit 1; }
brew install wireguard-tools go make git python sing-box rust cmake llvm pkg-config libsodium || true
"$BUNDLE/client/install-xray.sh"
ROOT=/opt/router-vpn-client
sudo mkdir -p "$ROOT" /usr/local/bin
sudo cp -a "$BUNDLE/client.json" "$BUNDLE/routers.json" "$BUNDLE/modes.json" "$BUNDLE/modes" "$BUNDLE/generated" "$ROOT/"
ARCH=$(uname -m)
case "$ARCH" in arm64) BIN="$BUNDLE/dist/router-vpn-client-darwin-arm64";; x86_64) BIN="$BUNDLE/dist/router-vpn-client-darwin-amd64";; *) echo "Unsupported Mac architecture: $ARCH"; exit 1;; esac
sudo install -m 755 "$BIN" /usr/local/bin/router-vpn-client
if ! command -v rosenpass >/dev/null; then
  echo 'Building Rosenpass for PQ-WireGuard/PQ-AmneziaWG...'
  TMP_RP=$(mktemp -d)
  if git clone --depth 1 https://github.com/rosenpass/rosenpass "$TMP_RP/rosenpass" \
    && (cd "$TMP_RP/rosenpass" && cargo build --release --bin rosenpass) \
    && [[ -x "$TMP_RP/rosenpass/target/release/rosenpass" ]]; then
    sudo install -m 755 "$TMP_RP/rosenpass/target/release/rosenpass" /usr/local/bin/rosenpass
  else
    echo 'Warning: Rosenpass build failed. Normal modes still work; PQ-WG/PQ-AWG remain disabled.' >&2
  fi
  rm -rf "$TMP_RP"
fi
if ! command -v amneziawg-go >/dev/null || ! command -v awg-quick >/dev/null; then
  TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
  git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-go "$TMP/amneziawg-go"
  make -C "$TMP/amneziawg-go"
  sudo install -m 755 "$TMP/amneziawg-go/amneziawg-go" /usr/local/bin/amneziawg-go
  git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-tools "$TMP/amneziawg-tools"
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
