#!/usr/bin/env bash
set -euo pipefail
MODE=${1:?combined mode}
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/profile-id.sh"
PROFILE_ID=$(homevpn_profile_id)
PRIMARY="$ROOT/generated/$PROFILE_ID/$MODE"
LEGACY="$ROOT/generated/$MODE"
if [[ -d "$PRIMARY" ]]; then
  CONF="$PRIMARY"
elif [[ $PROFILE_ID == router && -d "$LEGACY" ]]; then
  CONF="$LEGACY"
else
  echo "linked Router VPN profile '$PROFILE_ID' is missing its own generated '$MODE' combined runtime; cross-node readiness fallback is forbidden" >&2
  exit 1
fi
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
    (cd "$CONF" && sing-box check -D "$CONF" -c sing-box.json >/dev/null)
    ;;
  *) echo "unknown combined mode: $MODE" >&2; exit 2 ;;
esac
printf 'ready'
