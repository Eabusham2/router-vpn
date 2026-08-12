#!/usr/bin/env bash
set -euo pipefail
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
PROFILE_ID=$(printf '%s' "${HOMEVPN_PROFILE_ID:-router}" | tr -cd 'A-Za-z0-9_.-')
PROFILE_ID=${PROFILE_ID:-router}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HEALTH_URL=${HOMEVPN_HEALTH_URL:-http://10.77.0.1:8787/health}
TEST_SECONDS=${HOMEVPN_AUTO_TEST_SECONDS:-6}
BASE=${HOMEVPN_BASE:-auto}
RESULT_FILE=${HOMEVPN_ALL_RESULT_FILE:-}

if [[ -n $RESULT_FILE ]]; then
  mkdir -p "$(dirname -- "$RESULT_FILE")"
  probe="${RESULT_FILE}.probe.$$"
  : > "$probe"
  rm -f "$probe" "$RESULT_FILE"
fi

if [[ $BASE == auto ]]; then
  BASE=$(python3 - "$ROOT/routers.json" "$PROFILE_ID" <<'PY'
import json,sys
try: x=json.load(open(sys.argv[1]))
except Exception: print('wg'); raise SystemExit
p=next((p for p in x.get('profiles',[]) if p.get('id')==sys.argv[2]),{})
print(str(p.get('base_tunnel') or 'wg').lower())
PY
  )
fi
case "$BASE" in
  awg|amnezia|amneziawg|amneziawg2) candidates=(max-tls-awg max-tls-wg max-quic-awg max-quic-wg) ;;
  *) candidates=(max-tls-wg max-tls-awg max-quic-wg max-quic-awg) ;;
esac

health(){
  python3 - "$HEALTH_URL" "$TEST_SECONDS" <<'PY'
import ipaddress,sys,urllib.request
from urllib.parse import urlparse
url=sys.argv[1].strip(); timeout=float(sys.argv[2])
try:
    parsed=urlparse(url)
    host=(parsed.hostname or '').rstrip('.').lower()
    if parsed.scheme not in {'http','https'} or not host:
        raise SystemExit(1)
    trusted = host == 'localhost' or host.endswith('.localhost') or host.endswith('.local') or host.endswith('.home.arpa')
    if not trusted:
        try:
            ip=ipaddress.ip_address(host)
            trusted=ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            trusted=False
    if not trusted:
        raise SystemExit(1)
    with urllib.request.urlopen(url,timeout=timeout) as r:
        body=r.read(4096)
        if 200 <= r.status < 300 and b'"ok"' in body and b'true' in body.lower():
            raise SystemExit(0)
except SystemExit:
    raise
except Exception:
    pass
raise SystemExit(1)
PY
}

for candidate in "${candidates[@]}"; do
  if ! HOMEVPN_PROFILE_ID="$PROFILE_ID" HOMEVPN_ROOT="$ROOT" "$SCRIPT_DIR/check-mode.sh" "$candidate" >/dev/null 2>&1; then
    continue
  fi
  echo "ALL trying $candidate" >&2
  bash "$SCRIPT_DIR/run-max.sh" "$candidate" &
  pid=$!
  sleep 2
  if kill -0 "$pid" >/dev/null 2>&1 && health; then
    if [[ -n $RESULT_FILE ]]; then
      tmp="${RESULT_FILE}.tmp.$$"
      printf '%s\n' "$candidate" > "$tmp"
      mv -f "$tmp" "$RESULT_FILE"
    fi
    echo "ALL connected with $candidate" >&2
    wait "$pid"
    exit $?
  fi
  kill "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true
  HOMEVPN_ROOT="$ROOT" bash "$SCRIPT_DIR/stop-mode.sh" >/dev/null 2>&1 || true
  sleep 0.3
done

echo 'ALL could not establish any validated MAX TLS or MAX QUIC branch.' >&2
exit 1
