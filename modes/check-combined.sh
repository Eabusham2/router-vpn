#!/usr/bin/env bash
set -euo pipefail
MODE=${1:?combined mode}
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
PROFILE_ID=$(printf '%s' "${HOMEVPN_PROFILE_ID:-router}" | tr -cd 'A-Za-z0-9_.-')
PROFILE_ID=${PROFILE_ID:-router}
CONF="$ROOT/generated/$PROFILE_ID/$MODE"
[[ -d "$CONF" ]] || CONF="$ROOT/generated/$MODE"
need_bin(){ command -v "$1" >/dev/null 2>&1 || { echo "missing command: $1"; exit 1; }; }
need_file(){ [[ -s "$1" ]] || { echo "missing profile: $1"; exit 1; }; }
case "$MODE" in
  split|max)
    need_bin xray
    need_bin sing-box
    need_file "$CONF/xray.json"
    need_file "$CONF/sing-box.json"
    need_file "$CONF/cert.pem"
    xray run -test -c "$CONF/xray.json" >/dev/null
    # The Hysteria2 UDP outbound references cert.pem relatively. Some sing-box
    # builds resolve that relative to CWD instead of -D, so validate from CONF.
    (cd "$CONF" && sing-box check -D "$CONF" -c sing-box.json >/dev/null)
    ;;
  *) echo "unknown combined mode: $MODE" >&2; exit 2 ;;
esac
printf 'ready'
