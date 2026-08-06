#!/usr/bin/env bash
set -euo pipefail
MODE=${1:?mode}
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
PROFILE_ID=$(printf '%s' "${HOMEVPN_PROFILE_ID:-router}" | tr -cd 'A-Za-z0-9_.-')
PROFILE_ID=${PROFILE_ID:-router}
CONF="$ROOT/generated/$PROFILE_ID/$MODE"
[[ -d "$CONF" ]] || CONF="$ROOT/generated/$MODE"
need_bin(){ command -v "$1" >/dev/null 2>&1 || { echo "missing command: $1"; exit 1; }; }
need_file(){ [[ -f "$1" ]] || { echo "missing profile: $1"; exit 1; }; }
case "$MODE" in
  wg) need_bin wg-quick; need_file "$CONF/wg.conf" ;;
  awg2-fast|awg2-strong) need_bin amneziawg-go; need_bin awg; need_bin awg-quick; need_file "$CONF/awg.conf" ;;
  wg-pq) need_bin wg-quick; need_bin rosenpass; need_file "$CONF/wg.conf"; need_file "$CONF/rosenpass.toml" ;;
  awg2-pq) need_bin amneziawg-go; need_bin awg; need_bin rosenpass; need_file "$CONF/awg.conf"; need_file "$CONF/rosenpass.toml" ;;
  reality-vision|hysteria2|shadowsocks|ss-v2ray|naive-h2|naive-h3) need_bin sing-box; need_file "$CONF/sing-box.json" ;;
  reality-pq-vision) need_bin xray; need_bin sing-box; need_file "$CONF/xray.json"; need_file "$CONF/sing-box.json" ;;
  reality-xhttp) need_bin xray; need_file "$CONF/xray.json" ;;
  wg-quic) need_bin gotatun; need_file "$CONF/gotatun.json" ;;
  wg-ss-v2ray) need_bin wg-quick; need_bin sing-box; need_file "$CONF/wg.conf"; need_file "$CONF/sing-box.json" ;;
  max-tls|max-quic) need_bin wg-quick; need_bin rosenpass; need_bin sing-box; need_bin xray; need_file "$CONF/chain.env" ;;
  *) echo "unknown mode: $MODE"; exit 2 ;;
esac
printf 'ready'
