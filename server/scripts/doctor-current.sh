#!/usr/bin/env bash
set -uo pipefail
BASE=${BASE:-/opt/router-vpn}
VERIFIED_READ=/src/server/scripts/verified-regular-read.py
[[ -f "$VERIFIED_READ" && ! -L "$VERIFIED_READ" ]] || { echo 'verified private-state reader missing or unsafe' >&2; exit 1; }
verified_private(){ python3 "$VERIFIED_READ" --private "$1" >/dev/null 2>&1; }
verified_private_text(){ python3 "$VERIFIED_READ" --private "$1" 2>/dev/null; }
verified_regular(){ python3 "$VERIFIED_READ" "$1" >/dev/null 2>&1; }
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
  "$BASE/config/socks5.json" \
  "$BASE/config/wireguard/wg0.conf" \
  "$BASE/config/awg2/awg0.conf" \
  "$BASE/config/transports/server.json" \
  "$BASE/config/xray/server.json" \
  "$BASE/client-bundle/setup-assets.json" \
  "$BASE/client-bundle/router-vpn-device-setup.html" \
  "$BASE/client-bundle/router-vpn-bundle.json"; do
  verified_private "$f" && ok "$(basename "$f") verified private" || bad "missing/unsafe private file $f"
done
for f in \
  "$BASE/client-bundle/modes.json" \
  "$BASE/downloads/index.html" \
  "$BASE/downloads/router-vpn-device-setup.html" \
  "$BASE/downloads/setup-assets.json" \
  "$BASE/downloads/download-policy.json"; do
  verified_regular "$f" && ok "$(basename "$f") verified regular" || bad "missing/unsafe file $f"
done

for leaked in \
  "$BASE/downloads/router-vpn-bundle.json" \
  "$BASE/downloads/router-vpn-client-bundle.zip" \
  "$BASE/downloads/CREDENTIALS.txt" \
  "$BASE/router-vpn-client-bundle.zip"; do
  [[ ! -e "$leaked" && ! -L "$leaked" ]] && ok "private material not publicly cached: $(basename "$leaked")" || bad "private Router VPN material leaked/cached at $leaked"
done

for spec in \
  "$BASE/config/.core-transports-xray-v2|core-transports-xray-v2" \
  "$BASE/config/.advanced-profiles-v2|advanced-profiles-v2" \
  "$BASE/config/.tls-alternates-v1|tls-alternates-v1"; do
  marker=${spec%%|*}; expected=${spec#*|}
  value=$(verified_private_text "$marker" || true)
  [[ "$value" == "$expected" ]] \
    && ok "profile marker $(basename "$marker") verified" \
    || warn "profile marker missing/unsafe/stale: $(basename "$marker")"
done
for f in "$BASE/config/aux/overtls-server.json" "$BASE/config/aux/ssr-server.json" "$BASE/config/aux/generated.json"; do
  verified_private "$f" && ok "$(basename "$f") verified private" || warn "aux compatibility profile unavailable/unsafe: $f"
done

containers=(router-vpn-agent router-vpn-wireguard router-vpn-awg2 router-vpn-rosenpass router-vpn-transports router-vpn-xray router-vpn-naive router-vpn-ss-v2ray router-vpn-bundle-web router-vpn-socks5 router-vpn-aux)
if command -v docker >/dev/null 2>&1; then
  for c in "${containers[@]}"; do
    if docker inspect "$c" >/dev/null 2>&1; then
      state=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || true)
      [[ $state == running ]] && ok "$c running" || warn "$c state: ${state:-unknown}"
    else
      warn "$c not created"
    fi
  done
  docker exec router-vpn-xray xray run -test -c /etc/xray/config.json >/dev/null 2>&1 && ok 'Xray server config validates' || bad 'Xray server config validation failed'
  docker exec router-vpn-transports sing-box check -c /etc/sing-box/config.json >/dev/null 2>&1 && ok 'sing-box transport server config validates' || bad 'sing-box transport server config validation failed'
  if docker inspect router-vpn-aux >/dev/null 2>&1; then
    docker exec router-vpn-aux overtls-bin --version >/dev/null 2>&1 && ok 'OverTLS binary available' || bad 'OverTLS binary unavailable'
    docker exec router-vpn-aux ssr-server -h >/dev/null 2>&1 && ok 'SSR binary available' || bad 'SSR binary unavailable'
  fi
else
  bad 'docker command missing'
fi

if command -v curl >/dev/null 2>&1; then
  health=$(curl -fsS --max-time 3 http://127.0.0.1:8786/healthz 2>/dev/null || true)
  [[ $health == ok ]] && ok 'Setup Center broker healthz passes' || bad 'Setup Center broker healthz failed'
  policy=$(curl -fsS --max-time 3 http://127.0.0.1:8786/api/download-policy 2>/dev/null || true)
  if POLICY="$policy" python3 - <<'PY'
import json,os
try: d=json.loads(os.environ.get('POLICY',''))
except Exception: raise SystemExit(1)
raise SystemExit(0 if d.get('mode')=='on-demand' and d.get('server_cache') is False and d.get('github_exact_sha_required') is True else 1)
PY
  then ok 'download broker reports on-demand/no-cache/exact-SHA policy'; else bad 'download broker policy is missing or stale'; fi
else
  warn 'curl unavailable; broker HTTP checks skipped'
fi

python3 - "$BASE" <<'PY'
import json,runpy,sys
from pathlib import Path
base=Path(sys.argv[1]); errors=[]
read_verified_regular=runpy.run_path(sys.argv[2])["read_verified_regular"]
def load_private_json(rel):
    return json.loads(read_verified_regular(base/rel, private=True).decode("utf-8"))
try:
    x=load_private_json('config/xray/server.json'); tags={i.get('tag') for i in x.get('inbounds',[]) if isinstance(i,dict)}
    for tag in ('reality-in','pq-reality-in'):
        if tag not in tags: errors.append('missing Xray inbound '+tag)
except Exception as e: errors.append('Xray JSON: '+str(e))
try:
    s=load_private_json('config/transports/server.json'); tags={i.get('tag') for i in s.get('inbounds',[]) if isinstance(i,dict)}
    for tag in ('hy2-in','ss-in'):
        if tag not in tags: errors.append('missing transport inbound '+tag)
    if 'reality-in' in tags: errors.append('stale sing-box REALITY inbound still present')
except Exception as e: errors.append('transport JSON: '+str(e))
try:
    socks=load_private_json('config/socks5.json')
    for inbound in socks.get('inbounds',[]):
        if inbound.get('type')=='socks' and inbound.get('users'): errors.append('SOCKS5 still has authentication users')
except Exception as e: errors.append('SOCKS JSON: '+str(e))
try:
    a=load_private_json('config/aux/overtls-server.json'); s=a.get('server_settings',{})
    if s.get('listen_host')!='127.0.0.1': errors.append('OverTLS backend is not loopback-only')
    if s.get('disable_tls') is not True: errors.append('OverTLS backend must disable TLS only behind Caddy')
    if 'client_settings' in a: errors.append('OverTLS server config still contains client_settings')
except Exception as e: errors.append('OverTLS JSON: '+str(e))
try:
    a=load_private_json('config/aux/ssr-server.json')
    if not a.get('udp'): errors.append('SSR UDP is disabled')
    if a.get('method')!='aes-256-ctr': errors.append('SSR compatibility cipher is not aes-256-ctr')
except Exception as e: errors.append('SSR JSON: '+str(e))
try:
    a=load_private_json('client-bundle/setup-assets.json'); ids={x.get('id') for x in a.get('methods',[])}
    for item in ('wireguard','shadowsocks','overtls','shadowsocksr','socks5'):
        if item not in ids: errors.append('setup method missing '+item)
except Exception as e: errors.append('setup assets: '+str(e))
if errors:
    print('\n'.join('CONFIG_ERROR:'+e for e in errors)); raise SystemExit(1)
print('CONFIG_OK')
PY
case $? in 0) ok 'generated server/setup profile structure is current' ;; *) bad 'generated server/setup profile structure has errors' ;; esac

required_modes=(wg awg2-fast wg-pq awg2-pq reality-vision reality-pq-vision hysteria2 shadowsocks split max reality-xhttp max-tls-wg max-tls-awg max-quic-wg max-quic-awg)
for mode in "${required_modes[@]}"; do [[ -d "$BASE/client-bundle/generated/$mode" && ! -L "$BASE/client-bundle/generated/$mode" ]] && ok "generated/$mode" || warn "generated/$mode unavailable/redirected"; done
for mode in ss-v2ray naive-h2 naive-h3; do [[ -d "$BASE/client-bundle/generated/$mode" && ! -L "$BASE/client-bundle/generated/$mode" ]] && ok "generated/$mode" || warn "optional TLS mode unavailable/redirected: $mode"; done
for mode in overtls shadowsocksr; do [[ -d "$BASE/client-bundle/generated/$mode" && ! -L "$BASE/client-bundle/generated/$mode" ]] && ok "generated/$mode compatibility profile" || warn "compatibility profile unavailable/redirected: $mode"; done
for mode in max-tls-wg max-tls-awg max-quic-wg max-quic-awg; do
  env="$BASE/client-bundle/generated/$mode/chain.env"
  if verified_private "$env" && grep -q '^CHAIN_READY=1done

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
  for port in 22 53 1080 3000 8786 8787 8788 8789 8790 8791 8792 8793 9443 14444 45999; do
    if grep -Eq "dport[[:space:]]+${port}([^0-9]|$).*accept" <<<"$rules"; then
      bad "private/control port $port appears allowed from WAN"
    else
      ok "private/control port $port is not explicitly allowed from WAN"
    fi
  done
else
  warn 'nft command unavailable for firewall check'
fi

printf '\nResult: %d passed, %d warnings, %d failed\n' "$PASS" "$WARN" "$FAIL"
(( FAIL == 0 ))
 "$env" && grep -q '^PQ_BASE=1done

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
  for port in 22 53 1080 3000 8786 8787 8788 8789 8790 8791 8792 8793 9443 14444 45999; do
    if grep -Eq "dport[[:space:]]+${port}([^0-9]|$).*accept" <<<"$rules"; then
      bad "private/control port $port appears allowed from WAN"
    else
      ok "private/control port $port is not explicitly allowed from WAN"
    fi
  done
else
  warn 'nft command unavailable for firewall check'
fi

printf '\nResult: %d passed, %d warnings, %d failed\n' "$PASS" "$WARN" "$FAIL"
(( FAIL == 0 ))
 "$env"; then ok "$mode validated with PQ base"; else warn "$mode is not validated with PQ base or state is unsafe"; fi
done

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
  for port in 22 53 1080 3000 8786 8787 8788 8789 8790 8791 8792 8793 9443 14444 45999; do
    if grep -Eq "dport[[:space:]]+${port}([^0-9]|$).*accept" <<<"$rules"; then
      bad "private/control port $port appears allowed from WAN"
    else
      ok "private/control port $port is not explicitly allowed from WAN"
    fi
  done
else
  warn 'nft command unavailable for firewall check'
fi

printf '\nResult: %d passed, %d warnings, %d failed\n' "$PASS" "$WARN" "$FAIL"
(( FAIL == 0 ))
