#!/usr/bin/env bash
set -euo pipefail
BASE=${1:-/opt/router-vpn}
ENDPOINT=${2:-router.invalid}
ADGUARD4=${3:-192.168.50.133}
WG_PORT=${4:-51820}
AWG_PORT=${5:-585}
REALITY_PORT=${6:-443}
HY2_PORT=${7:-8443}
SS_PORT=${8:-8388}
XRAY_PQ_PORT=${9:-10443}
XHTTP_PORT=${10:-11443}
SS_V2RAY_PORT=${11:-12443}
NAIVE_PORT=${12:-13443}
REALITY_TARGET=${13:-www.microsoft.com:443}

CONFIG="$BASE/config"
GENERATED="$BASE/client-bundle/generated"
PRIVATE_DIR=/src/server/scripts/private-directory.py
PRIVATE_WRITE=/src/server/scripts/atomic-private-write.py
PRIVATE_BATCH=/src/server/scripts/atomic-private-batch.py
VERIFIED_READ=/src/server/scripts/verified-regular-read.py
python3 "$PRIVATE_DIR" "$CONFIG"
python3 "$PRIVATE_DIR" "$GENERATED"

CORE_MARKER="$CONFIG/.core-transports-xray-v2"
ADV_MARKER="$CONFIG/.advanced-profiles-v2"
TLS_MARKER="$CONFIG/.tls-alternates-v1"
CORE_REBUILT=0

private_ok(){
  python3 "$VERIFIED_READ" --private "$1" >/dev/null 2>&1
}

private_text(){
  python3 "$VERIFIED_READ" --private "$1"
}

marker_ok(){
  local path=$1 expected=$2 value
  value=$(private_text "$path" 2>/dev/null) || return 1
  [[ "$value" == "$expected" ]]
}

write_marker(){
  local path=$1 value=$2
  printf '%s\n' "$value" | python3 "$PRIVATE_WRITE" "$path"
  marker_ok "$path" "$value"
}

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
x=load(sys.argv[2])
xtags={i.get("tag") for i in x.get("inbounds",[]) if isinstance(i,dict)}
if sys.argv[3]:
    s=load(sys.argv[3])
    stags={i.get("tag") for i in s.get("inbounds",[]) if isinstance(i,dict)}
    raise SystemExit(0 if {"reality-in","pq-reality-in"} <= xtags and {"hy2-in","ss-in"} <= stags and "reality-in" not in stags else 1)
raise SystemExit(0 if "max-xhttp-in" in xtags else 1)
PY
}

core_ready(){
  local f
  for f in \
    "$CONFIG/transports/server.json" \
    "$CONFIG/transports/generated-secrets.json" \
    "$CONFIG/xray/server.json" \
    "$CONFIG/xray/generated-secrets.json" \
    "$GENERATED/hysteria2/sing-box.json" \
    "$GENERATED/shadowsocks/sing-box.json" \
    "$GENERATED/reality-vision/xray.json" \
    "$GENERATED/reality-vision/sing-box.json" \
    "$GENERATED/reality-pq-vision/xray.json" \
    "$GENERATED/reality-pq-vision/sing-box.json"; do
    private_ok "$f" || return 1
  done
  verified_json_tags "$CONFIG/xray/server.json" "$CONFIG/transports/server.json"
}

advanced_credentials_ready(){
  local f
  for f in \
    "$CONFIG/xray/server.json" \
    "$CONFIG/xray/advanced-secrets.json" \
    "$GENERATED/max-tls-wg/chain.env" \
    "$GENERATED/max-tls-awg/chain.env" \
    "$GENERATED/max-quic-wg/chain.env" \
    "$GENERATED/max-quic-awg/chain.env" \
    "$GENERATED/reality-xhttp/xray.json"; do
    private_ok "$f" || return 1
  done
  verified_json_tags "$CONFIG/xray/server.json"
}

advanced_runtime_ready(){
  advanced_credentials_ready || return 1
  private_ok "$GENERATED/reality-xhttp/sing-box.json" || return 1
  local d env
  for d in max-tls-wg max-tls-awg max-quic-wg max-quic-awg; do
    env="$GENERATED/$d/chain.env"
    private_ok "$env" || return 1
    private_text "$env" | grep -q '^CHAIN_READY=1$' || return 1
    private_text "$env" | grep -q '^PQ_BASE=1$' || return 1
    private_ok "$GENERATED/$d/rosenpass.toml" || return 1
    private_ok "$GENERATED/$d/rosenpass-client-secret" || return 1
  done
}

tls_ready(){
  local f
  for f in \
    "$CONFIG/tls/settings.env" \
    "$CONFIG/tls/generated.json" \
    "$GENERATED/ss-v2ray/sslocal.json" \
    "$GENERATED/ss-v2ray/sing-box.json" \
    "$GENERATED/naive-h2/sing-box.json" \
    "$GENERATED/naive-h3/sing-box.json"; do
    private_ok "$f" || return 1
  done
}

# Marker files are derived readiness attestations only. The real private state is
# always re-proved first; a marker can never make an incomplete profile Ready.
if ! core_ready; then
  echo 'Generating/migrating core transport profiles (one-time credential version)...'
  bash /src/server/scripts/generate-transports.sh \
    "$BASE" "$ENDPOINT" "$ADGUARD4" "$REALITY_PORT" "$HY2_PORT" "$SS_PORT" "$REALITY_TARGET"
  bash /src/server/scripts/generate-xray-pq.sh \
    "$BASE" "$ENDPOINT" "$ADGUARD4" "$XRAY_PQ_PORT" "$REALITY_TARGET" "$REALITY_PORT"
  if ! core_ready; then
    clear_marker "$CORE_MARKER"
    echo 'Core transport validation failed.' >&2
    exit 1
  fi
  CORE_REBUILT=1
  # A changed core candidate invalidates dependent readiness attestations. The
  # dependent identities themselves are preserved/validated by their generators.
  clear_marker "$ADV_MARKER"
  clear_marker "$TLS_MARKER"
else
  echo 'Keeping existing core transport credentials.'
fi
write_marker "$CORE_MARKER" 'core-transports-xray-v2'

# Combined profiles are transactionally generated and own no independent
# long-lived credentials. A failed rebuild therefore leaves the previous proven
# generation untouched; do not delete that known-good state after a failed try.
if ! python3 /src/server/scripts/generate-stack-profiles.py "$BASE"; then
  echo 'Warning: dual-transport profile refresh failed; preserving the prior transactional generation.' >&2
fi

# Generate advanced identity only when the actual credential set is not already
# self-consistent. A readiness marker is published later, only after PQ base and
# the full-tunnel XHTTP wrapper both prove current.
if ! advanced_credentials_ready; then
  echo 'Generating/migrating advanced MAX/XHTTP credentials...'
  if ! bash /src/server/scripts/generate-advanced-profiles.sh \
    "$BASE" "$ENDPOINT" "$ADGUARD4" "$WG_PORT" "$AWG_PORT" \
    "$SS_PORT" "$HY2_PORT" "$XHTTP_PORT" "$REALITY_TARGET"; then
    clear_marker "$ADV_MARKER"
    echo 'Warning: advanced MAX/XHTTP credential generation failed; existing identity was not declared Ready.' >&2
  fi
else
  echo 'Keeping existing MAX/XHTTP credentials.'
fi

if advanced_credentials_ready; then
  pq_ok=1
  xhttp_ok=1
  if ! python3 /src/server/scripts/enhance-max-pq.py "$BASE"; then
    pq_ok=0
    echo 'Warning: Rosenpass enhancement refresh failed; preserving prior transactional files and re-proving readiness.' >&2
  fi
  if ! python3 /src/server/scripts/wrap-xhttp-tun.py "$BASE" "$ADGUARD4"; then
    xhttp_ok=0
    echo 'Warning: XHTTP wrapper refresh failed; preserving prior transactional file and re-proving readiness.' >&2
  fi
  if advanced_runtime_ready; then
    write_marker "$ADV_MARKER" 'advanced-profiles-v2'
    if (( pq_ok == 0 || xhttp_ok == 0 )); then
      echo 'Advanced refresh had an error, but the prior complete private runtime still re-proved Ready.' >&2
    fi
  else
    clear_marker "$ADV_MARKER"
    echo 'Warning: advanced runtime is incomplete; MAX/XHTTP remains unavailable until a full successful redeploy.' >&2
  fi
else
  clear_marker "$ADV_MARKER"
fi

export SS_V2RAY_PORT NAIVE_PORT
if ! tls_ready; then
  echo 'Generating/migrating automatic TLS alternate credentials...'
  if ! bash /src/server/scripts/generate-tls-alternates.sh "$BASE" "$ENDPOINT" "$ADGUARD4"; then
    echo 'Warning: automatic TLS alternate refresh failed; re-proving any prior transactional generation.' >&2
  fi
else
  echo 'Keeping existing automatic TLS credentials and certificate identity.'
fi
if tls_ready; then
  write_marker "$TLS_MARKER" 'tls-alternates-v1'
else
  clear_marker "$TLS_MARKER"
  echo 'Warning: TLS alternate runtime is incomplete; it will retry next redeploy.' >&2
fi

if (( CORE_REBUILT )); then
  echo 'Core credential migration completed; dependent readiness was re-proved against the refreshed core.'
fi
