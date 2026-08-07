#!/usr/bin/env bash
set -euo pipefail
MODE=${1:?mode}
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
PROFILE_ID=$(printf '%s' "${HOMEVPN_PROFILE_ID:-router}" | tr -cd 'A-Za-z0-9_.-')
PROFILE_ID=${PROFILE_ID:-router}
CONF="$ROOT/generated/$PROFILE_ID/$MODE"
[[ -d "$CONF" ]] || CONF="$ROOT/generated/$MODE"
need_bin(){ command -v "$1" >/dev/null 2>&1 || { echo "missing command: $1"; exit 1; }; }
need_file(){ [[ -s "$1" ]] || { echo "missing profile: $1"; exit 1; }; }
check_sing(){
  local dir=$1 file=$2
  need_bin sing-box
  need_file "$dir/$file"
  sing-box check -D "$dir" -c "$dir/$file" >/dev/null
}
check_naive(){
  local dir=$1
  need_bin sing-box
  sing-box version 2>&1 | grep -q 'with_naive_outbound' || { echo 'installed sing-box build lacks Naive outbound support'; exit 1; }
  case "$(uname -s 2>/dev/null || true)" in
    Linux)
      [[ -s /usr/local/lib/libcronet.so || -s /usr/local/bin/libcronet.so || -n ${LD_LIBRARY_PATH:-} && -s "${LD_LIBRARY_PATH%%:*}/libcronet.so" ]] || {
        echo 'Naive on Linux requires libcronet.so from the official sing-box release'; exit 1;
      }
      ;;
  esac
  check_sing "$dir" sing-box.json
}
check_xray(){
  local file=$1
  need_bin xray
  need_file "$file"
  xray run -test -c "$file" >/dev/null
}
check_rosenpass(){
  local dir=$1
  need_bin rosenpass
  need_file "$dir/rosenpass.toml"
  need_file "$dir/rosenpass.env"
  need_file "$dir/rosenpass-client-public"
  need_file "$dir/rosenpass-client-secret"
  need_file "$dir/rosenpass-server-public"
}
check_max(){
  local mode=$1 base=$2 dir="$ROOT/generated/$PROFILE_ID/$mode"
  [[ -d "$dir" ]] || dir="$ROOT/generated/$mode"
  need_file "$dir/chain.env"
  # shellcheck disable=SC1090
  source "$dir/chain.env"
  [[ ${CHAIN_READY:-0} == 1 ]] || { echo "profile generation did not validate this chain"; exit 1; }
  check_sing "$dir" middle-sing-box.json
  case "${OUTER_ENGINE:-}" in
    xray) check_xray "$dir/outer-xray.json" ;;
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
  if [[ -f "$dir/rosenpass.toml" ]]; then check_rosenpass "$dir"; fi
}
case "$MODE" in
  wg) need_bin wg-quick; need_file "$CONF/wg.conf" ;;
  awg2-fast|awg2-strong) need_bin amneziawg-go; need_bin awg; need_bin awg-quick; need_file "$CONF/awg.conf" ;;
  wg-pq) need_bin wg-quick; need_file "$CONF/wg.conf"; need_file "$CONF/wg-socks.conf"; check_rosenpass "$CONF" ;;
  awg2-pq) need_bin amneziawg-go; need_bin awg; need_bin awg-quick; need_file "$CONF/awg.conf"; need_file "$CONF/awg-socks.conf"; check_rosenpass "$CONF" ;;
  hysteria2|shadowsocks) check_sing "$CONF" sing-box.json ;;
  naive-h2|naive-h3) check_naive "$CONF" ;;
  ss-v2ray)
    need_bin sslocal
    need_bin v2ray-plugin
    need_file "$CONF/sslocal.json"
    check_sing "$CONF" sing-box.json
    ;;
  reality-vision|reality-pq-vision) check_xray "$CONF/xray.json"; check_sing "$CONF" sing-box.json ;;
  reality-xhttp) check_xray "$CONF/xray.json"; check_sing "$CONF" sing-box.json ;;
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
