#!/usr/bin/env bash
set -uo pipefail
BASE=${BASE:-/opt/router-vpn}
PASS=0
WARN=0
FAIL=0

ok(){ printf '✓ %s\n' "$*"; PASS=$((PASS+1)); }
warn(){ printf '! %s\n' "$*"; WARN=$((WARN+1)); }
bad(){ printf '✗ %s\n' "$*"; FAIL=$((FAIL+1)); }

printf 'Router VPN doctor\n=================\n'

for f in \
  "$BASE/.initialized" \
  "$BASE/.finalized" \
  "$BASE/.env" \
  "$BASE/config/router-agent.json" \
  "$BASE/config/wireguard/wg0.conf" \
  "$BASE/config/awg2/awg0.conf" \
  "$BASE/config/transports/server.json" \
  "$BASE/config/xray/server.json" \
  "$BASE/client-bundle/modes.json" \
  "$BASE/client-bundle/setup-assets.json" \
  "$BASE/client-bundle/router-vpn-device-setup.html" \
  "$BASE/downloads/router-vpn-client-bundle.zip" \
  "$BASE/downloads/router-vpn-device-setup.html"; do
  [[ -s "$f" ]] && ok "$(basename "$f") present" || bad "missing $f"
done

for marker in \
  "$BASE/config/.core-transports-xray-v2" \
  "$BASE/config/.advanced-profiles-v2" \
  "$BASE/config/.tls-alternates-v1"; do
  [[ -s "$marker" ]] && ok "profile marker $(basename "$marker")" || warn "profile marker not present yet: $(basename "$marker")"
done

for f in "$BASE/config/aux/overtls-server.json" "$BASE/config/aux/ssr-server.json" "$BASE/config/aux/generated.json"; do
  [[ -s "$f" ]] && ok "$(basename "$f") present" || warn "aux compatibility profile unavailable: $f"
done

containers=(
  router-vpn-agent router-vpn-wireguard router-vpn-awg2 router-vpn-rosenpass
  router-vpn-transports router-vpn-xray router-vpn-naive router-vpn-ss-v2ray
  router-vpn-bundle-web router-vpn-socks5 router-vpn-aux
)
if command -v docker >/dev/null 2>&1; then
  for c in "${containers[@]}"; do
    if docker inspect "$c" >/dev/null 2>&1; then
      state=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || true)
      [[ $state == running ]] && ok "$c running" || warn "$c state: ${state:-unknown}"
    else
      warn "$c not created"
    fi
  done
  if docker exec router-vpn-xray xray run -test -c /etc/xray/config.json >/dev/null 2>&1; then ok 'Xray server config validates'; else bad 'Xray server config validation failed'; fi
  if docker exec router-vpn-transports sing-box check -c /etc/sing-box/config.json >/dev/null 2>&1; then ok 'sing-box transport server config validates'; else bad 'sing-box transport server config validation failed'; fi
  if docker inspect router-vpn-aux >/dev/null 2>&1; then
    docker exec router-vpn-aux overtls-bin --version >/dev/null 2>&1 && ok 'OverTLS binary available' || bad 'OverTLS binary unavailable'
    docker exec router-vpn-aux ssr-server -h >/dev/null 2>&1 && ok 'SSR binary available' || bad 'SSR binary unavailable'
  fi
else
  bad 'docker command missing'
fi

python3 - "$BASE" <<'PY'
import json,sys
from pathlib import Path
base=Path(sys.argv[1]); errors=[]
try:
    x=json.load(open(base/'config/xray/server.json')); tags={i.get('tag') for i in x.get('inbounds',[]) if isinstance(i,dict)}
    for tag in ('reality-in','pq-reality-in'):
        if tag not in tags: errors.append('missing Xray inbound '+tag)
except Exception as e: errors.append('Xray JSON: '+str(e))
try:
    s=json.load(open(base/'config/transports/server.json')); tags={i.get('tag') for i in s.get('inbounds',[]) if isinstance(i,dict)}
    for tag in ('hy2-in','ss-in'):
        if tag not in tags: errors.append('missing transport inbound '+tag)
    if 'reality-in' in tags: errors.append('stale sing-box REALITY inbound still present')
except Exception as e: errors.append('transport JSON: '+str(e))
try:
    socks=json.load(open(base/'config/socks5.json'))
    for inbound in socks.get('inbounds',[]):
        if inbound.get('type')=='socks' and inbound.get('users'): errors.append('SOCKS5 still has authentication users')
except Exception as e: errors.append('SOCKS JSON: '+str(e))
try:
    a=json.load(open(base/'config/aux/overtls-server.json')); s=a.get('server_settings',{})
    if s.get('listen_host')!='127.0.0.1': errors.append('OverTLS backend is not loopback-only')
    if s.get('disable_tls') is not True: errors.append('OverTLS backend must disable TLS only behind Caddy')
except Exception as e: errors.append('OverTLS JSON: '+str(e))
try:
    a=json.load(open(base/'config/aux/ssr-server.json'))
    if not a.get('udp'): errors.append('SSR UDP is disabled')
except Exception as e: errors.append('SSR JSON: '+str(e))
try:
    a=json.load(open(base/'client-bundle/setup-assets.json')); ids={x.get('id') for x in a.get('methods',[])}
    for item in ('wireguard','shadowsocks','overtls','shadowsocksr','socks5'):
        if item not in ids: errors.append('setup method missing '+item)
except Exception as e: errors.append('setup assets: '+str(e))
if errors:
    print('\n'.join('CONFIG_ERROR:'+e for e in errors)); raise SystemExit(1)
print('CONFIG_OK')
PY
case $? in 0) ok 'generated server/setup profile structure is current' ;; *) bad 'generated server/setup profile structure has errors' ;; esac

required_modes=(wg awg2-fast wg-pq awg2-pq reality-vision reality-pq-vision hysteria2 shadowsocks split max reality-xhttp max-tls-wg max-tls-awg max-quic-wg max-quic-awg)
for mode in "${required_modes[@]}"; do [[ -d "$BASE/client-bundle/generated/$mode" ]] && ok "generated/$mode" || warn "generated/$mode unavailable"; done
for mode in ss-v2ray naive-h2 naive-h3; do [[ -d "$BASE/client-bundle/generated/$mode" ]] && ok "generated/$mode" || warn "optional TLS mode unavailable: $mode"; done
for mode in overtls shadowsocksr; do [[ -d "$BASE/client-bundle/generated/$mode" ]] && ok "generated/$mode compatibility profile" || warn "compatibility profile unavailable: $mode"; done

for mode in max-tls-wg max-tls-awg max-quic-wg max-quic-awg; do
  env="$BASE/client-bundle/generated/$mode/chain.env"
  if [[ -s "$env" ]] && grep -q '^CHAIN_READY=1$' "$env" && grep -q '^PQ_BASE=1$' "$env"; then ok "$mode validated with PQ base"; else warn "$mode is not validated with PQ base"; fi
done

if command -v unzip >/dev/null 2>&1 && unzip -tq "$BASE/downloads/router-vpn-client-bundle.zip" >/dev/null 2>&1; then ok 'private client ZIP integrity passes'; else bad 'private client ZIP integrity failed'; fi

if command -v ss >/dev/null 2>&1; then
  listeners=$(ss -lntuH 2>/dev/null || true)
  for port in 443 585 8388 8443 10443 11443 12443 13443 14443 14444 15443 51820 51822; do
    if grep -Eq "[:.]${port}[[:space:]]" <<<"$listeners"; then ok "listener $port present"; else warn "listener $port not seen (may be custom/optional)"; fi
  done
  grep -Eq '[:.]1080[[:space:]]' <<<"$listeners" && ok 'SOCKS5 listener 1080 present' || warn 'SOCKS5 listener 1080 not seen'
fi

if command -v nft >/dev/null 2>&1; then
  rules=$(nft list table inet router_vpn_guard 2>/dev/null || true)
  [[ -n $rules ]] && ok 'WAN guard nftables table present' || bad 'WAN guard nftables table missing'
  grep -q 'dport 1080.*accept' <<<"$rules" && bad 'SOCKS5 1080 appears allowed from WAN' || ok 'SOCKS5 1080 is not explicitly allowed from WAN'
  grep -q 'dport 14444.*accept' <<<"$rules" && bad 'OverTLS loopback backend 14444 appears allowed from WAN' || ok 'OverTLS loopback 14444 is not explicitly allowed from WAN'
else
  warn 'nft command unavailable for firewall check'
fi

printf '\nResult: %d passed, %d warnings, %d failed\n' "$PASS" "$WARN" "$FAIL"
(( FAIL == 0 ))
