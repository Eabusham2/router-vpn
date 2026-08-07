#!/usr/bin/env bash
set -euo pipefail
BASE=${1:?base directory}
ENDPOINT=${2:?public IP, hostname, or placeholder}
ADGUARD4=${3:?AdGuard IPv4}
WG_PORT=${4:-51820}
AWG_PORT=${5:-585}
SS_PORT=${6:-8388}
HY2_PORT=${7:-8443}
XHTTP_PORT=${8:-11443}
REALITY_TARGET=${9:-www.microsoft.com:443}
LOCAL_RELAY_PORT=${LOCAL_RELAY_PORT:-51830}
XHTTP_PATH=${XHTTP_PATH:-/assets/sync}

SING_BOX_IMAGE=${SING_BOX_IMAGE:-ghcr.io/sagernet/sing-box:1.13.12}
XRAY_IMAGE=${XRAY_IMAGE:-ghcr.io/xtls/xray-core:latest}
sb(){ if command -v sing-box >/dev/null 2>&1; then sing-box "$@"; else docker run --rm -v "$BASE:$BASE" "$SING_BOX_IMAGE" "$@"; fi; }
xr(){ if command -v xray >/dev/null 2>&1; then xray "$@"; else docker run --rm -v "$BASE:$BASE" "$XRAY_IMAGE" "$@"; fi; }

for required in \
  "$BASE/config/xray/server.json" \
  "$BASE/config/xray/generated-secrets.json" \
  "$BASE/client-bundle/generated/wg/wg.conf" \
  "$BASE/client-bundle/generated/wg/wg-socks.conf" \
  "$BASE/client-bundle/generated/awg2-strong/awg.conf" \
  "$BASE/client-bundle/generated/awg2-strong/awg-socks.conf" \
  "$BASE/client-bundle/generated/shadowsocks/sing-box.json" \
  "$BASE/client-bundle/generated/hysteria2/sing-box.json" \
  "$BASE/client-bundle/generated/hysteria2/cert.pem"; do
  [[ -s $required ]] || { echo "Missing prerequisite: $required" >&2; exit 1; }
done

TARGET_HOST=${REALITY_TARGET%:*}
TARGET_PORT=${REALITY_TARGET##*:}
[[ $TARGET_PORT =~ ^[0-9]+$ ]] || { TARGET_HOST=$REALITY_TARGET; TARGET_PORT=443; }
UUID=$(xr uuid | awk 'NF{print $1; exit}')
PAIR=$(xr x25519)
REALITY_PRIVATE=$(printf '%s\n' "$PAIR" | awk -F': *' 'tolower($1) ~ /privatekey/ {print $2; exit}')
REALITY_PASSWORD=$(printf '%s\n' "$PAIR" | awk -F': *' 'tolower($1) ~ /password|publickey/ {print $2; exit}')
SHORT_ID=$(openssl rand -hex 8)
FINALMASK_PASSWORD=$(openssl rand -hex 16)
for value in UUID REALITY_PRIVATE REALITY_PASSWORD SHORT_ID; do
  [[ -n ${!value} ]] || { echo "Failed generating $value" >&2; exit 1; }
done

python3 - "$BASE" "$ENDPOINT" "$ADGUARD4" "$WG_PORT" "$AWG_PORT" "$SS_PORT" "$HY2_PORT" "$XHTTP_PORT" "$TARGET_HOST" "$TARGET_PORT" "$UUID" "$REALITY_PRIVATE" "$REALITY_PASSWORD" "$SHORT_ID" "$FINALMASK_PASSWORD" "$LOCAL_RELAY_PORT" "$XHTTP_PATH" <<'PY'
from pathlib import Path
import copy,json,re,shutil,sys
(base,endpoint,dns,wgp,awgp,ssp,hp,xp,target,tp,uuid,rpriv,rpub,shortid,maskpass,relay,path)=sys.argv[1:]
base=Path(base); wgp,awgp,ssp,hp,xp,tp,relay=map(int,(wgp,awgp,ssp,hp,xp,tp,relay))
root=base/'client-bundle'/'generated'
server_path=base/'config'/'xray'/'server.json'
secrets_path=base/'config'/'xray'/'generated-secrets.json'
server=json.load(open(server_path))
secrets=json.load(open(secrets_path))
client_enc=secrets.get('vless_encryption','none')
server_dec='none'
for inbound in server.get('inbounds',[]):
    value=inbound.get('settings',{}).get('decryption')
    if value:
        server_dec=value
        break

server['inbounds']=[x for x in server.get('inbounds',[]) if x.get('tag')!='max-xhttp-in']
finalmask={
 'tcp':[{
   'type':'fragment',
   'settings':{'packets':'tlshello','length':'100-300','delay':'10-30','maxSplit':'3-7'}
 }]
}
server['inbounds'].append({
 'tag':'max-xhttp-in','listen':'::','port':xp,'protocol':'vless',
 'settings':{'clients':[{'id':uuid,'email':'router-vpn-max'}],'decryption':server_dec},
 'streamSettings':{
   'network':'xhttp','security':'reality',
   'xhttpSettings':{'path':path,'mode':'auto'},
   'realitySettings':{'show':False,'target':f'{target}:{tp}','xver':0,'serverNames':[target],'privateKey':rpriv,'shortIds':[shortid]},
   'finalmask':finalmask
 },
 'sniffing':{'enabled':True,'destOverride':['http','tls','quic'],'routeOnly':True}
})
json.dump(server,open(server_path,'w'),indent=2); open(server_path,'a').write('\n')

outer_xray={
 'log':{'loglevel':'warning'},
 'inbounds':[{'tag':'local-outer-socks','listen':'127.0.0.1','port':1090,'protocol':'socks','settings':{'auth':'noauth','udp':True}}],
 'outbounds':[{
   'tag':'proxy','protocol':'vless',
   'settings':{'vnext':[{'address':endpoint,'port':xp,'users':[{'id':uuid,'encryption':client_enc}]}]},
   'streamSettings':{
     'network':'xhttp','security':'reality',
     'xhttpSettings':{'path':path,'mode':'auto'},
     'realitySettings':{'serverName':target,'fingerprint':'chrome','password':rpub,'shortId':shortid},
     'finalmask':finalmask
   }
 }]
}

ss_doc=json.load(open(root/'shadowsocks'/'sing-box.json'))
hy_doc=json.load(open(root/'hysteria2'/'sing-box.json'))
ss=copy.deepcopy(next(x for x in ss_doc['outbounds'] if x.get('tag')=='proxy'))
hy=copy.deepcopy(next(x for x in hy_doc['outbounds'] if x.get('tag')=='proxy'))

# The Xray outer terminates at home. Destinations 127.0.0.1 below therefore
# mean the loopback interface on the home AI Board, not the travel device.
def middle_tls(remote_port):
    outer={'type':'socks','tag':'outer','server':'127.0.0.1','server_port':1090,'version':'5'}
    hop=copy.deepcopy(ss); hop['tag']='ss-hop'; hop['server']='127.0.0.1'; hop['server_port']=ssp; hop['detour']='outer'
    return {
      'log':{'level':'warn'},
      'inbounds':[{'type':'direct','tag':'base-relay','listen':'127.0.0.1','listen_port':relay,'network':'udp','override_address':'127.0.0.1','override_port':remote_port}],
      'outbounds':[outer,hop],
      'route':{'final':'ss-hop'}
    }

def middle_quic(remote_port):
    outer=copy.deepcopy(hy); outer['tag']='outer'; outer['server']=endpoint; outer['server_port']=hp
    hop=copy.deepcopy(ss); hop['tag']='ss-hop'; hop['server']='127.0.0.1'; hop['server_port']=ssp; hop['detour']='outer'
    return {
      'log':{'level':'warn'},
      'inbounds':[{'type':'direct','tag':'base-relay','listen':'127.0.0.1','listen_port':relay,'network':'udp','override_address':'127.0.0.1','override_port':remote_port}],
      'outbounds':[outer,hop],
      'route':{'final':'ss-hop'}
    }

def localize_endpoint(src,dst):
    text=Path(src).read_text()
    text=re.sub(r'(?m)^(Endpoint\s*=\s*).*:(\d+)\s*$',lambda m:f'{m.group(1)}127.0.0.1:{relay}',text)
    Path(dst).write_text(text)

def write_branch(name,base_kind,transport):
    d=root/name
    if d.exists(): shutil.rmtree(d)
    d.mkdir(parents=True)
    if base_kind=='wg':
        localize_endpoint(root/'wg'/'wg.conf',d/'wg.conf')
        localize_endpoint(root/'wg'/'wg-socks.conf',d/'wg-socks.conf')
        remote=wgp
    else:
        localize_endpoint(root/'awg2-strong'/'awg.conf',d/'awg.conf')
        localize_endpoint(root/'awg2-strong'/'awg-socks.conf',d/'awg-socks.conf')
        remote=awgp
    if transport=='tls':
        json.dump(outer_xray,open(d/'outer-xray.json','w'),indent=2); open(d/'outer-xray.json','a').write('\n')
        middle=middle_tls(remote); outer_engine='xray'
        layers='base>shadowsocks2022>xray-vless-pq-reality-xhttp-finalmask'
    else:
        middle=middle_quic(remote); outer_engine='sing-box'
        shutil.copy2(root/'hysteria2'/'cert.pem',d/'cert.pem')
        layers='base>shadowsocks2022>hysteria2-quic'
    json.dump(middle,open(d/'middle-sing-box.json','w'),indent=2); open(d/'middle-sing-box.json','a').write('\n')
    (d/'chain.env').write_text(f'CHAIN_READY=0\nOUTER_ENGINE={outer_engine}\nCHAIN_LAYERS={layers}\nLOCAL_RELAY_PORT={relay}\n')
    return d

branches=[
 ('max-tls-wg','wg','tls'),('max-tls-awg','awg','tls'),
 ('max-quic-wg','wg','quic'),('max-quic-awg','awg','quic')]
for args in branches: write_branch(*args)

# Standalone XHTTP/REALITY/FinalMask mode uses the same validated outer profile.
xdir=root/'reality-xhttp'; xdir.mkdir(parents=True,exist_ok=True)
json.dump(outer_xray,open(xdir/'xray.json','w'),indent=2); open(xdir/'xray.json','a').write('\n')

advanced={
 'xhttp_port':xp,'xhttp_path':path,'xhttp_uuid':uuid,'xhttp_short_id':shortid,
 'xhttp_reality_public':rpub,'finalmask_password':maskpass,
 'max_local_relay_port':relay
}
json.dump(advanced,open(base/'config'/'xray'/'advanced-secrets.json','w'),indent=2); open(base/'config'/'xray'/'advanced-secrets.json','a').write('\n')
PY

validate_branch(){
  local name=$1 dir="$BASE/client-bundle/generated/$1"
  if [[ -f $dir/outer-xray.json ]]; then xr run -test -c "$dir/outer-xray.json" >/dev/null; fi
  sb check -D "$dir" -c "$dir/middle-sing-box.json" >/dev/null
  sed -i 's/^CHAIN_READY=0$/CHAIN_READY=1/' "$dir/chain.env"
}

# Validate the combined server before exposing the new TCP listener.
xr run -test -c "$BASE/config/xray/server.json" >/dev/null
for branch in max-tls-wg max-tls-awg max-quic-wg max-quic-awg; do validate_branch "$branch"; done
xr run -test -c "$BASE/client-bundle/generated/reality-xhttp/xray.json" >/dev/null
chmod 600 "$BASE/config/xray/"*.json "$BASE/client-bundle/generated/"*/chain.env "$BASE/client-bundle/generated/"*/middle-sing-box.json 2>/dev/null || true
printf 'Generated and validated MAX TLS/QUIC branches on standard WireGuard and AmneziaWG bases.\n'
