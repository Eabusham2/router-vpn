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
check_max(){
  local mode=$1 base=$2 dir="$ROOT/generated/$PROFILE_ID/$mode"
  [[ -d "$dir" ]] || dir="$ROOT/generated/$mode"
  need_file "$dir/chain.env"
  # shellcheck disable=SC1090
  source "$dir/chain.env"
  [[ ${CHAIN_READY:-0} == 1 ]] || { echo "profile generation did not validate this chain"; exit 1; }
  need_bin sing-box
  need_file "$dir/middle-sing-box.json"
  case "${OUTER_ENGINE:-}" in
    xray)
      need_bin xray
      need_file "$dir/outer-xray.json"
      ;;
    sing-box|none) ;;
    *) echo "invalid OUTER_ENGINE in $dir/chain.env"; exit 1 ;;
  esac
  case "$base" in
    wg)
      need_bin wg-quick
      need_file "$dir/wg.conf"
      need_file "$dir/wg-socks.conf"
      ;;
    awg)
      need_bin amneziawg-go
      need_bin awg
      need_bin awg-quick
      need_file "$dir/awg.conf"
      need_file "$dir/awg-socks.conf"
      ;;
  esac
  if [[ -f "$dir/rosenpass.toml" ]]; then need_bin rosenpass; fi
}
case "$MODE" in
  wg) need_bin wg-quick; need_file "$CONF/wg.conf" ;;
  awg2-fast|awg2-strong) need_bin amneziawg-go; need_bin awg; need_bin awg-quick; need_file "$CONF/awg.conf" ;;
  wg-pq) need_bin wg-quick; need_bin rosenpass; need_file "$CONF/wg.conf"; need_file "$CONF/rosenpass.toml" ;;
  awg2-pq) need_bin amneziawg-go; need_bin awg; need_bin awg-quick; need_bin rosenpass; need_file "$CONF/awg.conf"; need_file "$CONF/rosenpass.toml" ;;
  reality-vision|hysteria2|shadowsocks|ss-v2ray|naive-h2) need_bin sing-box; need_file "$CONF/sing-box.json" ;;
  reality-pq-vision) need_bin xray; need_bin sing-box; need_file "$CONF/xray.json"; need_file "$CONF/sing-box.json" ;;
  reality-xhttp) need_bin xray; need_file "$CONF/xray.json" ;;
  max-tls-wg|max-quic-wg) check_max "$MODE" wg ;;
  max-tls-awg|max-quic-awg) check_max "$MODE" awg ;;
  all)
    for candidate in max-tls-wg max-tls-awg max-quic-wg max-quic-awg; do
      if "$0" "$candidate" >/dev/null 2>&1; then printf 'ready'; exit 0; fi
    done
    echo "no validated MAX TLS or MAX QUIC branch is installed" >&2
    exit 1
    ;;
  *) echo "unknown mode: $MODE"; exit 2 ;;
esac
printf 'ready'
