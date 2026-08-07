#!/usr/bin/env bash
set -euo pipefail
BASE=${1:-/opt/router-vpn}
CONFIG="$BASE/config"
GEN="$BASE/client-bundle/generated"
mkdir -p "$CONFIG"

core_current(){
  [[ -s "$CONFIG/transports/server.json" \
    && -s "$CONFIG/transports/generated-secrets.json" \
    && -s "$CONFIG/xray/server.json" \
    && -s "$CONFIG/xray/generated-secrets.json" \
    && -s "$GEN/reality-vision/xray.json" \
    && -s "$GEN/reality-vision/sing-box.json" \
    && -s "$GEN/reality-pq-vision/xray.json" \
    && -s "$GEN/reality-pq-vision/sing-box.json" ]] || return 1
  python3 - "$CONFIG/xray/server.json" "$CONFIG/transports/server.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); s=json.load(open(sys.argv[2]))
xtags={i.get('tag') for i in x.get('inbounds',[]) if isinstance(i,dict)}
stags={i.get('tag') for i in s.get('inbounds',[]) if isinstance(i,dict)}
raise SystemExit(0 if {'reality-in','pq-reality-in'} <= xtags and {'hy2-in','ss-in'} <= stags and 'reality-in' not in stags else 1)
PY
}

advanced_current(){
  [[ -s "$CONFIG/xray/advanced-secrets.json" \
    && -s "$GEN/reality-xhttp/xray.json" \
    && -s "$GEN/reality-xhttp/sing-box.json" ]] || return 1
  python3 - "$CONFIG/xray/server.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); tags={i.get('tag') for i in x.get('inbounds',[]) if isinstance(i,dict)}
raise SystemExit(0 if 'max-xhttp-in' in tags else 1)
PY
  for d in max-tls-wg max-tls-awg max-quic-wg max-quic-awg; do
    [[ -s "$GEN/$d/chain.env" ]] || return 1
    grep -q '^CHAIN_READY=1$' "$GEN/$d/chain.env" || return 1
    grep -q '^PQ_BASE=1$' "$GEN/$d/chain.env" || return 1
    [[ -s "$GEN/$d/rosenpass.toml" && -s "$GEN/$d/rosenpass-client-secret" ]] || return 1
  done
}

tls_current(){
  [[ -s "$CONFIG/tls/settings.env" \
    && -s "$CONFIG/tls/generated.json" \
    && -s "$GEN/ss-v2ray/sslocal.json" \
    && -s "$GEN/ss-v2ray/sing-box.json" \
    && -s "$GEN/naive-h2/sing-box.json" \
    && -s "$GEN/naive-h3/sing-box.json" ]]
}

if [[ ! -s "$CONFIG/.core-transports-xray-v2" ]] && core_current; then
  printf '%s\n' 'core-transports-xray-v2' >"$CONFIG/.core-transports-xray-v2"
  chmod 600 "$CONFIG/.core-transports-xray-v2"
  echo 'Adopted current core transport credentials.'
fi
if [[ ! -s "$CONFIG/.advanced-profiles-v2" ]] && advanced_current; then
  printf '%s\n' 'advanced-profiles-v2' >"$CONFIG/.advanced-profiles-v2"
  chmod 600 "$CONFIG/.advanced-profiles-v2"
  echo 'Adopted current MAX/XHTTP credentials.'
fi
if [[ ! -s "$CONFIG/.tls-alternates-v1" ]] && tls_current; then
  printf '%s\n' 'tls-alternates-v1' >"$CONFIG/.tls-alternates-v1"
  chmod 600 "$CONFIG/.tls-alternates-v1"
  echo 'Adopted current automatic TLS credentials.'
fi
