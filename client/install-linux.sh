#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run with sudo.'; exit 1; }
BUNDLE=${1:-$(pwd)}
[[ -f "$BUNDLE/client.json" && -f "$BUNDLE/routers.json" && -d "$BUNDLE/generated" ]] || { echo 'Run from the extracted router-vpn-client-bundle folder.'; exit 1; }
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard-tools resolvconf nftables git make gcc libc6-dev golang-go curl python3 tar cmake clang pkg-config libsodium-dev cargo rustc
"$BUNDLE/client/install-xray.sh"
ROOT=/opt/router-vpn-client
mkdir -p "$ROOT" /usr/local/bin /usr/local/lib /usr/local/sbin
cp -a "$BUNDLE/client.json" "$BUNDLE/routers.json" "$BUNDLE/modes.json" "$BUNDLE/modes" "$BUNDLE/generated" "$ROOT/"
ARCH=$(uname -m)
case "$ARCH" in
  aarch64|arm64)
    BIN="$BUNDLE/dist/router-vpn-client-linux-arm64"
    DNS_BIN="$BUNDLE/dist/router-vpn-dns-linux-arm64"
    SB_ARCH=arm64
    ;;
  x86_64|amd64)
    BIN="$BUNDLE/dist/router-vpn-client-linux-amd64"
    DNS_BIN="$BUNDLE/dist/router-vpn-dns-linux-amd64"
    SB_ARCH=amd64
    ;;
  *) echo "Unsupported Linux architecture: $ARCH"; exit 1;;
esac
install -m 755 "$BIN" /usr/local/bin/router-vpn-client
install -m 755 "$DNS_BIN" /usr/local/bin/router-vpn-dns

# Official no-suffix Linux sing-box releases include libcronet.so, which Naive H2/H3
# needs at runtime. Refresh both pieces when either is missing.
if ! command -v sing-box >/dev/null || [[ ! -s /usr/local/lib/libcronet.so && ! -s /usr/local/bin/libcronet.so ]]; then
  SB_VER=1.13.12
  TMP_SB=$(mktemp -d)
  SB_TGZ="$TMP_SB/sing-box.tar.gz"
case "$SB_ARCH" in
  arm64) SB_SHA256=1ffa3b48ad6fa98f9fd810482e39bdd5b6157782ef11ce37d67bdcfd9338547a ;;
  amd64) SB_SHA256=1540533adb3df24f5ad5f14b5c7ca3dbc2401b10a1c1eb278fcadcada47ec6c4 ;;
  *) echo "Unsupported sing-box architecture: $SB_ARCH" >&2; exit 1 ;;
esac
curl --proto '=https' --tlsv1.2 -fL "https://github.com/SagerNet/sing-box/releases/download/v${SB_VER}/sing-box-${SB_VER}-linux-${SB_ARCH}.tar.gz" -o "$SB_TGZ"
printf '%s  %s\n' "$SB_SHA256" "$SB_TGZ" | sha256sum -c -
python3 - "$SB_TGZ" <<'PYARCHIVE'
import pathlib,sys,tarfile
p=pathlib.Path(sys.argv[1])
if p.stat().st_size>256*1024*1024: raise SystemExit('archive too large')
c=0; total=0
with tarfile.open(p,'r:gz') as tf:
    for m in tf.getmembers():
        c+=1; total+=max(0,m.size); q=pathlib.PurePosixPath(m.name)
        if q.is_absolute() or '..' in q.parts: raise SystemExit('unsafe archive path')
        if m.issym() or m.islnk() or m.isdev() or m.isfifo(): raise SystemExit('unsafe archive member')
        if not (m.isdir() or m.isfile()): raise SystemExit('unsupported archive member')
        if c>4096 or total>1024*1024*1024: raise SystemExit('archive expansion too large')
PYARCHIVE
tar --no-same-owner --no-same-permissions -xzf "$SB_TGZ" -C "$TMP_SB"
  SB_DIR="$TMP_SB/sing-box-${SB_VER}-linux-${SB_ARCH}"
  install -m 755 "$SB_DIR/sing-box" /usr/local/bin/sing-box
  CRONET=$(find "$SB_DIR" -type f -name libcronet.so -print -quit)
  if [[ -n "$CRONET" && -s "$CRONET" ]]; then
    install -m 755 "$CRONET" /usr/local/lib/libcronet.so
    command -v ldconfig >/dev/null 2>&1 && ldconfig || true
  else
    echo 'Warning: official sing-box archive did not contain libcronet.so; Naive H2/H3 will remain disabled.' >&2
  fi
  rm -rf "$TMP_SB"
fi

if ! command -v rosenpass >/dev/null; then
  echo 'Installing Rosenpass for PQ-WireGuard/PQ-AmneziaWG...'
  TMP_RP=$(mktemp -d)
  if git clone https://github.com/rosenpass/rosenpass "$TMP_RP/rosenpass" \
    && (cd "$TMP_RP/rosenpass" && git checkout 00569eb273016a10d2e75e5142236f06f7c3d4b3 && [[ $(git rev-parse HEAD) == 00569eb273016a10d2e75e5142236f06f7c3d4b3 ]] && cargo build --release --bin rosenpass) \
    && [[ -x "$TMP_RP/rosenpass/target/release/rosenpass" ]]; then
    install -m 755 "$TMP_RP/rosenpass/target/release/rosenpass" /usr/local/bin/rosenpass
  else
    echo 'Warning: Rosenpass build failed. Normal modes still work; PQ-WG/PQ-AWG remain disabled.' >&2
  fi
  rm -rf "$TMP_RP"
fi
if ! command -v sslocal >/dev/null; then
  echo 'Installing Shadowsocks-rust for SS+V2Ray TLS...'
  if cargo install --locked --version 1.24.0 shadowsocks-rust; then
    install -m 755 "${CARGO_HOME:-/root/.cargo}/bin/sslocal" /usr/local/bin/sslocal
  else
    echo 'Warning: Shadowsocks-rust install failed; SS+V2Ray TLS remains disabled.' >&2
  fi
fi
if ! command -v v2ray-plugin >/dev/null; then
  echo 'Installing V2Ray SIP003 plugin...'
  TMP_V2=$(mktemp -d)
  if git clone https://github.com/shadowsocks/v2ray-plugin "$TMP_V2/v2ray-plugin" \
    && (cd "$TMP_V2/v2ray-plugin" && git checkout e9af1cdd2549d528deb20a4ab8d61c5fbe51f306 && GOTOOLCHAIN=auto go build -trimpath -ldflags='-s -w' -o v2ray-plugin .); then
    install -m 755 "$TMP_V2/v2ray-plugin/v2ray-plugin" /usr/local/bin/v2ray-plugin
  else
    echo 'Warning: V2Ray-plugin build failed; SS+V2Ray TLS remains disabled.' >&2
  fi
  rm -rf "$TMP_V2"
fi
if ! command -v amneziawg-go >/dev/null || ! command -v awg-quick >/dev/null; then
  TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
  git clone --filter=blob:none --no-checkout https://github.com/amnezia-vpn/amneziawg-go "$TMP/amneziawg-go"
  git -C "$TMP/amneziawg-go" fetch --depth=1 origin 0527dfa47639714dd8f5c9ffbd9d40d19083f0ba
  git -C "$TMP/amneziawg-go" checkout --detach 0527dfa47639714dd8f5c9ffbd9d40d19083f0ba
  [[ $(git -C "$TMP/amneziawg-go" rev-parse HEAD) == 0527dfa47639714dd8f5c9ffbd9d40d19083f0ba ]]
  (cd "$TMP/amneziawg-go" && GOTOOLCHAIN=auto go mod download && GOTOOLCHAIN=auto go mod verify && GOTOOLCHAIN=auto go build -trimpath -o amneziawg-go .)
  install -m 755 "$TMP/amneziawg-go/amneziawg-go" /usr/local/bin/amneziawg-go
  git clone https://github.com/amnezia-vpn/amneziawg-tools "$TMP/amneziawg-tools"
  (cd "$TMP/amneziawg-tools" && git checkout 05434cab7d91bbbc607d18ec5fade91f4b83774c)
  make -C "$TMP/amneziawg-tools/src" WITH_WGQUICK=yes
  make -C "$TMP/amneziawg-tools/src" install WITH_WGQUICK=yes PREFIX=/usr/local
fi
chmod +x "$ROOT/modes/"*.sh 2>/dev/null || true

# `always` must exist before normal networking, not merely after the GUI starts.
# RequiredBy + Before makes a failed persistent reassertion stop network-pre from
# completing instead of booting into an unprotected state. With no selected
# always policy the helper exits successfully and networking proceeds normally.
cat >/etc/systemd/system/router-vpn-killswitch-early.service <<UNIT
[Unit]
Description=Router VPN persistent always kill switch
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target

[Service]
Type=oneshot
Environment=HOMEVPN_ROOT=$ROOT
ExecStart=/usr/bin/python3 $ROOT/modes/kill-switch.py reassert

[Install]
RequiredBy=network-pre.target
UNIT

cat >/usr/local/sbin/router-vpn-killswitch-recovery <<'RECOVERY'
#!/usr/bin/env sh
set -eu
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
export HOMEVPN_ROOT="$ROOT"
python3 "$ROOT/modes/kill-switch.py" force-off
systemctl reset-failed router-vpn-killswitch-early.service 2>/dev/null || true
printf '%s\n' 'Router VPN persistent kill switch force-disabled. Reboot or restart networking when ready.'
RECOVERY
chmod 755 /usr/local/sbin/router-vpn-killswitch-recovery

cat >/etc/systemd/system/router-vpn-client.service <<UNIT
[Unit]
Description=Router VPN client controller
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
Environment=HOMEVPN_ROOT=$ROOT
Environment=HOMEVPN_CLIENT_CONFIG=$ROOT/client.json
Environment=LD_LIBRARY_PATH=/usr/local/lib
WorkingDirectory=$ROOT
ExecStart=/usr/local/bin/router-vpn-client
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable router-vpn-killswitch-early.service
# Starting this after package installation reconciles an existing selected
# `always` policy immediately. A failure is intentional and must stop install
# rather than silently claiming persistent protection.
systemctl start router-vpn-killswitch-early.service
systemctl enable --now router-vpn-client
printf 'Open http://127.0.0.1:8788\n'
printf 'Emergency local recovery: sudo router-vpn-killswitch-recovery\n'
