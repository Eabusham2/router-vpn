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
mkdir -p "$CONFIG" "$GENERATED"
CORE_MARKER="$CONFIG/.core-transports-xray-v2"
ADV_MARKER="$CONFIG/.advanced-profiles-v2"
TLS_MARKER="$CONFIG/.tls-alternates-v1"
CORE_REBUILT=0

core_ready(){
  [[ -s "$CONFIG/transports/server.json" \
    && -s "$CONFIG/transports/generated-secrets.json" \
    && -s "$CONFIG/xray/server.json" \
    && -s "$CONFIG/xray/generated-secrets.json" \
    && -s "$GENERATED/hysteria2/sing-box.json" \
    && -s "$GENERATED/shadowsocks/sing-box.json" \
    && -s "$GENERATED/reality-vision/xray.json" \
    && -s "$GENERATED/reality-vision/sing-box.json" \
    && -s "$GENERATED/reality-pq-vision/xray.json" \
    && -s "$GENERATED/reality-pq-vision/sing-box.json" ]] || return 1
  python3 - "$CONFIG/xray/server.json" "$CONFIG/transports/server.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); s=json.load(open(sys.argv[2]))
xtags={i.get('tag') for i in x.get('inbounds',[]) if isinstance(i,dict)}
stags={i.get('tag') for i in s.get('inbounds',[]) if isinstance(i,dict)}
raise SystemExit(0 if {'reality-in','pq-reality-in'} <= xtags and {'hy2-in','ss-in'} <= stags and 'reality-in' not in stags else 1)
PY
}

advanced_ready(){
  [[ -s "$CONFIG/xray/advanced-secrets.json" \
    && -s "$GENERATED/max-tls-wg/chain.env" \
    && -s "$GENERATED/max-tls-awg/chain.env" \
    && -s "$GENERATED/max-quic-wg/chain.env" \
    && -s "$GENERATED/max-quic-awg/chain.env" \
    && -s "$GENERATED/reality-xhttp/xray.json" ]] || return 1
  python3 - "$CONFIG/xray/server.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]))
tags={i.get('tag') for i in x.get('inbounds',[]) if isinstance(i,dict)}
raise SystemExit(0 if 'max-xhttp-in' in tags else 1)
PY
}

tls_ready(){
  [[ -s "$CONFIG/tls/settings.env" \
    && -s "$CONFIG/tls/generated.json" \
    && -s "$GENERATED/ss-v2ray/sslocal.json" \
    && -s "$GENERATED/ss-v2ray/sing-box.json" \
    && -s "$GENERATED/naive-h2/sing-box.json" \
    && -s "$GENERATED/naive-h3/sing-box.json" ]] || return 1
}

# One-time credential migration. Later redeploys keep the same secrets unless the
# underlying files are missing/broken. A core rebuild invalidates dependent profiles,
# so their markers are cleared in the same transaction and they are rebuilt once too.
if [[ ! -s "$CORE_MARKER" ]] || ! core_ready; then
  echo 'Generating/migrating core transport profiles (one-time credential version)...'
  bash /src/server/scripts/generate-transports.sh \
    "$BASE" "$ENDPOINT" "$ADGUARD4" "$REALITY_PORT" "$HY2_PORT" "$SS_PORT" "$REALITY_TARGET"
  bash /src/server/scripts/generate-xray-pq.sh \
    "$BASE" "$ENDPOINT" "$ADGUARD4" "$XRAY_PQ_PORT" "$REALITY_TARGET" "$REALITY_PORT"
  core_ready || { rm -f "$CORE_MARKER"; echo 'Core transport validation failed.' >&2; exit 1; }
  printf '%s\n' 'core-transports-xray-v2' >"$CORE_MARKER"
  chmod 600 "$CORE_MARKER"
  CORE_REBUILT=1
  rm -f "$ADV_MARKER" "$TLS_MARKER"
else
  echo 'Keeping existing core transport credentials.'
fi

# Combined profiles contain no independent long-lived credentials, so rebuild them
# every deploy from the stable core profiles to pick up launcher/schema improvements.
if ! python3 /src/server/scripts/generate-stack-profiles.py "$BASE"; then
  echo 'Warning: dual-transport profiles were not generated.' >&2
  rm -rf "$GENERATED/split" "$GENERATED/max"
fi

if [[ ! -s "$ADV_MARKER" ]] || ! advanced_ready; then
  echo 'Generating/migrating advanced MAX/XHTTP credentials...'
  if bash /src/server/scripts/generate-advanced-profiles.sh \
    "$BASE" "$ENDPOINT" "$ADGUARD4" "$WG_PORT" "$AWG_PORT" \
    "$SS_PORT" "$HY2_PORT" "$XHTTP_PORT" "$REALITY_TARGET"; then
    if advanced_ready; then
      printf '%s\n' 'advanced-profiles-v2' >"$ADV_MARKER"
      chmod 600 "$ADV_MARKER"
    else
      rm -f "$ADV_MARKER"
      echo 'Warning: advanced profile validation failed; it will retry next redeploy.' >&2
    fi
  else
    echo 'Warning: advanced MAX/XHTTP credential generation failed; it will retry next redeploy.' >&2
    rm -f "$ADV_MARKER"
  fi
else
  echo 'Keeping existing MAX/XHTTP credentials.'
fi

# These steps do not rotate advanced outer credentials. They add current wrappers
# and PQ base material and can be safely retried on every redeploy.
if advanced_ready; then
  if ! python3 /src/server/scripts/enhance-max-pq.py "$BASE"; then
    echo 'Warning: live Rosenpass enhancement failed; MAX modes remain unavailable until a later successful redeploy.' >&2
    for dir in "$GENERATED"/max-{tls,quic}-{wg,awg}; do
      if [[ -s "$dir/chain.env" ]]; then
        if grep -q '^PQ_BASE=' "$dir/chain.env"; then sed -i 's/^PQ_BASE=.*/PQ_BASE=0/' "$dir/chain.env"; else echo 'PQ_BASE=0' >>"$dir/chain.env"; fi
      fi
    done
  fi
  if ! python3 /src/server/scripts/wrap-xhttp-tun.py "$BASE" "$ADGUARD4"; then
    echo 'Warning: XHTTP full-tunnel wrapper failed validation; XHTTP remains unavailable until a later successful redeploy.' >&2
    rm -f "$GENERATED/reality-xhttp/sing-box.json"
  fi
fi

export SS_V2RAY_PORT NAIVE_PORT
if [[ ! -s "$TLS_MARKER" ]] || ! tls_ready; then
  echo 'Generating/migrating automatic TLS alternate credentials...'
  if bash /src/server/scripts/generate-tls-alternates.sh "$BASE" "$ENDPOINT" "$ADGUARD4"; then
    if tls_ready; then
      printf '%s\n' 'tls-alternates-v1' >"$TLS_MARKER"
      chmod 600 "$TLS_MARKER"
    else
      rm -f "$TLS_MARKER"
      echo 'Warning: TLS alternate validation failed; it will retry next redeploy.' >&2
    fi
  else
    echo 'Warning: automatic TLS alternate generation failed; it will retry next redeploy.' >&2
    rm -f "$TLS_MARKER"
  fi
else
  echo 'Keeping existing automatic TLS credentials and certificate identity.'
fi

if (( CORE_REBUILT )); then
  echo 'Core credential migration completed; dependent profile credentials were refreshed in the same migration.'
fi
