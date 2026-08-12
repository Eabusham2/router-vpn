#!/usr/bin/env bash
set -euo pipefail
MODE=${1:?mode}
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/profile-id.sh"
PROFILE_ID=$(homevpn_profile_id)
CONF="$ROOT/generated/$PROFILE_ID/$MODE"
[[ -d "$CONF" ]] || CONF="$ROOT/generated/$MODE"
need_bin(){ command -v "$1" >/dev/null 2>&1 || { echo "missing command: $1"; exit 1; }; }
need_file(){ [[ -s "$1" ]] || { echo "missing profile: $1"; exit 1; }; }
env_value(){
  local file=${1:?env file} key=${2:?env key}
  sed -n "s/^${key}=//p" "$file" | tail -n 1
}
check_sing(){
  local dir=${1:?sing-box dir} file=${2:?sing-box config}
  need_bin sing-box
  need_file "$dir/$file"
  (cd "$dir" && sing-box check -D "$dir" -c "$file" >/dev/null)
}
check_naive(){
  local dir=${1:?naive dir}
  need_bin sing-box
  sing-box version 2>&1 | grep -q 'with_naive_outbound' || { echo 'installed sing-box build lacks Naive outbound support'; exit 1; }
  case "$(uname -s 2>/dev/null || true)" in
    Linux)
      [[ -s /usr/local/lib/libcronet.so || -s /usr/local/bin/libcronet.so || -n ${LD_LIBRARY_PATH:-} && -s "${LD_LIBRARY_PATH%%:*}/libcronet.so" ]] || { echo 'Naive on Linux requires libcronet.so from the official sing-box release'; exit 1; }
      ;;
  esac
  check_sing "$dir" sing-box.json
}
check_xray(){ local file=${1:?xray config}; need_bin xray; need_file "$file"; xray run -test -c "$file" >/dev/null; }
check_rosenpass(){ local dir=${1:?Rosenpass dir}; need_bin rosenpass; need_file "$dir/rosenpass.toml"; need_file "$dir/rosenpass.env"; need_file "$dir/rosenpass-client-public"; need_file "$dir/rosenpass-client-secret"; need_file "$dir/rosenpass-server-public"; }
check_max(){
  local mode=${1:-} base=${2:-}
  [[ -n $mode && -n $base ]] || { echo 'MAX checker requires mode and base'; exit 2; }
  local dir="$ROOT/generated/$PROFILE_ID/$mode"
  [[ -d "$dir" ]] || dir="$ROOT/generated/$mode"
  need_file "$dir/chain.env"
  local chain_ready outer_engine pq_base
  chain_ready=$(env_value "$dir/chain.env" CHAIN_READY)
  outer_engine=$(env_value "$dir/chain.env" OUTER_ENGINE)
  pq_base=$(env_value "$dir/chain.env" PQ_BASE)
  [[ $chain_ready == 1 ]] || { echo 'profile generation did not validate this MAX chain'; exit 1; }
  [[ $pq_base == 1 ]] || { echo 'MAX chain is missing its Rosenpass-PQ base marker'; exit 1; }
  check_sing "$dir" middle-sing-box.json
  case "$outer_engine" in xray) check_xray "$dir/outer-xray.json" ;; sing-box|none) ;; *) echo "invalid OUTER_ENGINE in $dir/chain.env"; exit 1 ;; esac
  case "$base" in
    wg) need_bin wg-quick; need_file "$dir/wg.conf"; need_file "$dir/wg-socks.conf" ;;
    awg) need_bin amneziawg-go; need_bin awg; need_bin awg-quick; need_file "$dir/awg.conf"; need_file "$dir/awg-socks.conf" ;;
    *) echo "unknown MAX base: $base"; exit 2 ;;
  esac
  check_rosenpass "$dir"
}
case "$MODE" in
  wg) need_bin wg-quick; need_file "$CONF/wg.conf" ;;
  awg2-fast|awg2-strong) need_bin amneziawg-go; need_bin awg; need_bin awg-quick; need_file "$CONF/awg.conf" ;;
  wg-pq) need_bin wg-quick; need_file "$CONF/wg.conf"; need_file "$CONF/wg-socks.conf"; check_rosenpass "$CONF" ;;
  awg2-pq) need_bin amneziawg-go; need_bin awg; need_bin awg-quick; need_file "$CONF/awg.conf"; need_file "$CONF/awg-socks.conf"; check_rosenpass "$CONF" ;;
  hysteria2|shadowsocks) check_sing "$CONF" sing-box.json ;;
  naive-h2|naive-h3) check_naive "$CONF" ;;
  ss-v2ray) need_bin sslocal; need_bin v2ray-plugin; need_file "$CONF/sslocal.json"; check_sing "$CONF" sing-box.json ;;
  reality-vision|reality-pq-vision) check_xray "$CONF/xray.json"; check_sing "$CONF" sing-box.json ;;
  reality-xhttp) check_xray "$CONF/xray.json"; check_sing "$CONF" sing-box.json ;;
  max-tls-wg|max-quic-wg) check_max "$MODE" wg ;;
  max-tls-awg|max-quic-awg) check_max "$MODE" awg ;;
  all)
    for candidate in max-tls-wg max-tls-awg max-quic-wg max-quic-awg; do
      if HOMEVPN_PROFILE_ID="$PROFILE_ID" "$0" "$candidate" >/dev/null 2>&1; then printf 'ready'; exit 0; fi
    done
    echo 'no validated MAX TLS or MAX QUIC branch is installed' >&2; exit 1 ;;
  *) echo "unknown mode: $MODE"; exit 2 ;;
esac
printf 'ready'
