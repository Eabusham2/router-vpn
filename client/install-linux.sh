#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run with sudo.'; exit 1; }
BUNDLE=${1:-$(pwd)}
[[ -f "$BUNDLE/client.json" && -f "$BUNDLE/routers.json" && -d "$BUNDLE/generated" ]] || { echo 'Run from the extracted router-vpn-client-bundle folder.'; exit 1; }
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard-tools git make gcc libc6-dev golang-go curl python3 tar
"$BUNDLE/client/install-xray.sh"
ROOT=/opt/router-vpn-client
mkdir -p "$ROOT" /usr/local/bin
cp -a "$BUNDLE/client.json" "$BUNDLE/routers.json" "$BUNDLE/modes.json" "$BUNDLE/modes" "$BUNDLE/generated" "$ROOT/"
ARCH=$(uname -m)
case "$ARCH" in aarch64|arm64) BIN="$BUNDLE/dist/router-vpn-client-linux-arm64";; x86_64|amd64) BIN="$BUNDLE/dist/router-vpn-client-linux-amd64";; *) echo "Unsupported Linux architecture: $ARCH"; exit 1;; esac
install -m 755 "$BIN" /usr/local/bin/router-vpn-client
if ! command -v sing-box >/dev/null; then
  SB_VER=1.13.12
  case "$ARCH" in aarch64|arm64) SB_ARCH=arm64;; x86_64|amd64) SB_ARCH=amd64;; esac
  TMP_SB=$(mktemp -d)
  curl -fsSL "https://github.com/SagerNet/sing-box/releases/download/v${SB_VER}/sing-box-${SB_VER}-linux-${SB_ARCH}.tar.gz" | tar -xz -C "$TMP_SB"
  install -m 755 "$TMP_SB/sing-box-${SB_VER}-linux-${SB_ARCH}/sing-box" /usr/local/bin/sing-box
  rm -rf "$TMP_SB"
fi
if ! command -v amneziawg-go >/dev/null || ! command -v awg-quick >/dev/null; then
  TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
  git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-go "$TMP/amneziawg-go"
  make -C "$TMP/amneziawg-go"
  install -m 755 "$TMP/amneziawg-go/amneziawg-go" /usr/local/bin/amneziawg-go
  git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-tools "$TMP/amneziawg-tools"
  make -C "$TMP/amneziawg-tools/src" WITH_WGQUICK=yes
  make -C "$TMP/amneziawg-tools/src" install WITH_WGQUICK=yes PREFIX=/usr/local
fi
cat >/etc/systemd/system/router-vpn-client.service <<UNIT
[Unit]
Description=Router VPN client controller
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
Environment=HOMEVPN_ROOT=$ROOT
Environment=HOMEVPN_CLIENT_CONFIG=$ROOT/client.json
WorkingDirectory=$ROOT
ExecStart=/usr/local/bin/router-vpn-client
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now router-vpn-client
printf 'Open http://127.0.0.1:8788\n'
