#!/usr/bin/env bash
set -euo pipefail
BASE=${1:-/opt/router-vpn}
CONFIG="$BASE/config"
GEN="$BASE/client-bundle/generated"
PRIVATE_DIR=/src/server/scripts/private-directory.py
PRIVATE_WRITE=/src/server/scripts/atomic-private-write.py
PRIVATE_BATCH=/src/server/scripts/atomic-private-batch.py
VERIFIED_READ=/src/server/scripts/verified-regular-read.py
python3 "$PRIVATE_DIR" "$CONFIG"
python3 "$PRIVATE_DIR" "$GEN"

CORE_MARKER="$CONFIG/.core-transports-xray-v2"
ADV_MARKER="$CONFIG/.advanced-profiles-v2"
TLS_MARKER="$CONFIG/.tls-alternates-v1"

private_ok(){ python3 "$VERIFIED_READ" --private "$1" >/dev/null 2>&1; }
private_text(){ python3 "$VERIFIED_READ" --private "$1"; }
write_marker(){ local path=$1 value=$2; printf '%s\n' "$value" | python3 "$PRIVATE_WRITE" "$path"; }
clear_marker(){
  local path=$1
  if [[ -e "$path" || -L "$path" ]]; then
    python3 "$PRIVATE_BATCH" --delete "$path"
  fi
}

verified_json_tags(){
  local xray=$1 transports=${2:-}
  python3 - "$VERIFIED_READ" "$xray" "$transports" <<'PY'
import json,runpy,sys
read=runpy.run_path(sys.argv[1])["read_verified_regular"]
def load(path):
    return json.loads(read(path, private=True).decode("utf-8"))
x=load(sys.argv[2]); xtags={i.get("tag") for i in x.get("inbounds",[]) if isinstance(i,dict)}
if sys.argv[3]:
    s=load(sys.argv[3]); stags={i.get("tag") for i in s.get("inbounds",[]) if isinstance(i,dict)}
    raise SystemExit(0 if {"reality-in","pq-reality-in"} <= xtags and {"hy2-in","ss-in"} <= stags and "reality-in" not in stags else 1)
raise SystemExit(0 if "max-xhttp-in" in xtags else 1)
PY
}

core_current(){
  local f
  for f in \
    "$CONFIG/transports/server.json" "$CONFIG/transports/generated-secrets.json" \
    "$CONFIG/xray/server.json" "$CONFIG/xray/generated-secrets.json" \
    "$GEN/reality-vision/xray.json" "$GEN/reality-vision/sing-box.json" \
    "$GEN/reality-pq-vision/xray.json" "$GEN/reality-pq-vision/sing-box.json"; do
    private_ok "$f" || return 1
  done
  verified_json_tags "$CONFIG/xray/server.json" "$CONFIG/transports/server.json"
}

advanced_current(){
  local f d env
  for f in \
    "$CONFIG/xray/server.json" "$CONFIG/xray/advanced-secrets.json" \
    "$GEN/reality-xhttp/xray.json" "$GEN/reality-xhttp/sing-box.json"; do
    private_ok "$f" || return 1
  done
  verified_json_tags "$CONFIG/xray/server.json" || return 1
  for d in max-tls-wg max-tls-awg max-quic-wg max-quic-awg; do
    env="$GEN/$d/chain.env"
    private_ok "$env" || return 1
    private_text "$env" | grep -q '^CHAIN_READY=1$' || return 1
    private_text "$env" | grep -q '^PQ_BASE=1$' || return 1
    private_ok "$GEN/$d/rosenpass.toml" || return 1
    private_ok "$GEN/$d/rosenpass-client-secret" || return 1
  done
}

tls_current(){
  local f
  for f in \
    "$CONFIG/tls/settings.env" "$CONFIG/tls/generated.json" \
    "$GEN/ss-v2ray/sslocal.json" "$GEN/ss-v2ray/sing-box.json" \
    "$GEN/naive-h2/sing-box.json" "$GEN/naive-h3/sing-box.json"; do
    private_ok "$f" || return 1
  done
}

# Existing state is the source of truth. Markers are repaired/created only after
# the complete corresponding private generation proves current; stale markers
# are removed transactionally instead of being trusted by existence alone.
if core_current; then
  write_marker "$CORE_MARKER" 'core-transports-xray-v2'
  echo 'Adopted/re-proved current core transport credentials.'
else
  clear_marker "$CORE_MARKER"
fi

if advanced_current; then
  write_marker "$ADV_MARKER" 'advanced-profiles-v2'
  echo 'Adopted/re-proved current complete MAX/XHTTP runtime.'
else
  clear_marker "$ADV_MARKER"
fi

if tls_current; then
  write_marker "$TLS_MARKER" 'tls-alternates-v1'
  echo 'Adopted/re-proved current automatic TLS credentials.'
else
  clear_marker "$TLS_MARKER"
fi
