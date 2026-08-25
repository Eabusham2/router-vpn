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
PRIVATE_BATCH=/src/server/scripts/atomic-private-batch.py

SING_BOX_IMAGE=${SING_BOX_IMAGE:-ghcr.io/sagernet/sing-box:v1.13.12}
XRAY_IMAGE=${XRAY_IMAGE:-ghcr.io/xtls/xray-core:26.7.11}
sb(){ if command -v sing-box >/dev/null 2>&1; then sing-box "$@"; else docker run --rm -v "$BASE:$BASE" "$SING_BOX_IMAGE" "$@"; fi; }
xr(){ if command -v xray >/dev/null 2>&1; then xray "$@"; else docker run --rm -v "$BASE:$BASE" "$XRAY_IMAGE" "$@"; fi; }
umask 077

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
  [[ -s $required && ! -L $required ]] || { echo "Missing/unsafe prerequisite: $required" >&2; exit 1; }
done

TARGET_HOST=${REALITY_TARGET%:*}
TARGET_PORT=${REALITY_TARGET##*:}
[[ $TARGET_PORT =~ ^[0-9]+$ ]] || { TARGET_HOST=$REALITY_TARGET; TARGET_PORT=443; }
ADVANCED_SECRETS="$BASE/config/xray/advanced-secrets.json"
ADVANCED_PRESENT=0
if [[ -e "$ADVANCED_SECRETS" || -d "$BASE/client-bundle/generated/reality-xhttp" \
   || -d "$BASE/client-bundle/generated/max-tls-wg" || -d "$BASE/client-bundle/generated/max-tls-awg" \
   || -d "$BASE/client-bundle/generated/max-quic-wg" || -d "$BASE/client-bundle/generated/max-quic-awg" ]]; then
  ADVANCED_PRESENT=1
elif grep -Fq '"max-xhttp-in"' "$BASE/config/xray/server.json"; then
  ADVANCED_PRESENT=1
fi
if (( ADVANCED_PRESENT )); then
  if ! PRESERVED=$(python3 /src/server/scripts/preserve-generated-state.py advanced "$BASE"); then
    echo 'Existing XHTTP/MAX identity is corrupt/incomplete; refusing silent REALITY credential rotation.' >&2
    exit 1
  fi
  eval "$PRESERVED"
  echo 'Preserving existing XHTTP REALITY identity for same-deployment upgrade.' >&2
else
  UUID=$(xr uuid | awk 'NF{print $1; exit}')
  PAIR=$(xr x25519)
  REALITY_PRIVATE=$(printf '%s\n' "$PAIR" | awk -F': *' 'tolower($1) ~ /privatekey/ {print $2; exit}')
  REALITY_PASSWORD=$(printf '%s\n' "$PAIR" | awk -F': *' 'tolower($1) ~ /password|publickey/ {print $2; exit}')
  SHORT_ID=$(openssl rand -hex 8)
fi
for value in UUID REALITY_PRIVATE REALITY_PASSWORD SHORT_ID; do
  [[ -n ${!value} ]] || { echo "Failed generating/preserving $value" >&2; exit 1; }
done

GEN_TMP=$(mktemp -d "$BASE/config/xray/.advanced.XXXXXX")
trap 'rm -rf "${GEN_TMP:-}"' EXIT
python3 - "$BASE" "$GEN_TMP" "$ENDPOINT" "$ADGUARD4" "$WG_PORT" "$AWG_PORT" "$SS_PORT" "$HY2_PORT" "$XHTTP_PORT" "$TARGET_HOST" "$TARGET_PORT" "$UUID" "$REALITY_PRIVATE" "$REALITY_PASSWORD" "$SHORT_ID" "$LOCAL_RELAY_PORT" "$XHTTP_PATH" <<'PY'
from pathlib import Path
import copy,json,os,re,shutil,stat,sys
(base,tmp,endpoint,dns,wgp,awgp,ssp,hp,xp,target,tp,uuid,rpriv,rpub,shortid,relay,path)=sys.argv[1:]
base=Path(base); tmp=Path(tmp); wgp,awgp,ssp,hp,xp,tp,relay=map(int,(wgp,awgp,ssp,hp,xp,tp,relay))
root=base/'client-bundle'/'generated'
outroot=tmp/'generated'; outroot.mkdir()
server_path=base/'config'/'xray'/'server.json'
secrets_path=base/'config'/'xray'/'generated-secrets.json'

def read_json_regular(path: Path):
    info=path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f'refusing non-regular/symlink source {path}')
    return json.loads(path.read_text(encoding='utf-8'))

server=read_json_regular(server_path)
secrets=read_json_regular(secrets_path)
client_enc=secrets.get('vless_encryption','none')
server_dec='none'
for inbound in server.get('inbounds',[]):
    value=inbound.get('settings',{}).get('decryption')
    if value:
        server_dec=value
        break
server['inbounds']=[x for x in server.get('inbounds',[]) if x.get('tag')!='max-xhttp-in']
finalmask={'tcp':[{'type':'fragment','settings':{'packets':'tlshello','length':'100-300','delay':'10-30','maxSplit':'3-7'}}]}
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
(tmp/'server.json').write_text(json.dumps(server,indent=2)+'\n',encoding='utf-8')

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
ss_doc=read_json_regular(root/'shadowsocks'/'sing-box.json')
hy_doc=read_json_regular(root/'hysteria2'/'sing-box.json')
ss=copy.deepcopy(next(x for x in ss_doc['outbounds'] if x.get('tag')=='proxy'))
hy=copy.deepcopy(next(x for x in hy_doc['outbounds'] if x.get('tag')=='proxy'))

def middle_tls(remote_port):
    outer={'type':'socks','tag':'outer','server':'127.0.0.1','server_port':1090,'version':'5'}
    hop=copy.deepcopy(ss); hop['tag']='ss-hop'; hop['server']='127.0.0.1'; hop['server_port']=ssp; hop['detour']='outer'
    return {'log':{'level':'warn'},'inbounds':[{'type':'direct','tag':'base-relay','listen':'127.0.0.1','listen_port':relay,'network':'udp','override_address':'127.0.0.1','override_port':remote_port}],'outbounds':[outer,hop],'route':{'final':'ss-hop'}}

def middle_quic(remote_port):
    outer=copy.deepcopy(hy); outer['tag']='outer'; outer['server']=endpoint; outer['server_port']=hp
    hop=copy.deepcopy(ss); hop['tag']='ss-hop'; hop['server']='127.0.0.1'; hop['server_port']=ssp; hop['detour']='outer'
    return {'log':{'level':'warn'},'inbounds':[{'type':'direct','tag':'base-relay','listen':'127.0.0.1','listen_port':relay,'network':'udp','override_address':'127.0.0.1','override_port':remote_port}],'outbounds':[outer,hop],'route':{'final':'ss-hop'}}

def localize_endpoint(src: Path,dst: Path):
    info=src.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f'refusing unsafe base profile {src}')
    text=src.read_text(encoding='utf-8')
    text=re.sub(r'(?m)^(Endpoint\s*=\s*).*:(\d+)\s*$',lambda m:f'{m.group(1)}127.0.0.1:{relay}',text)
    dst.write_text(text,encoding='utf-8')

def write_branch(name,base_kind,transport):
    d=outroot/name; d.mkdir(parents=True)
    if base_kind=='wg':
        localize_endpoint(root/'wg'/'wg.conf',d/'wg.conf')
        localize_endpoint(root/'wg'/'wg-socks.conf',d/'wg-socks.conf')
        remote=wgp
    else:
        localize_endpoint(root/'awg2-strong'/'awg.conf',d/'awg.conf')
        localize_endpoint(root/'awg2-strong'/'awg-socks.conf',d/'awg-socks.conf')
        remote=awgp
    if transport=='tls':
        (d/'outer-xray.json').write_text(json.dumps(outer_xray,indent=2)+'\n',encoding='utf-8')
        middle=middle_tls(remote); outer_engine='xray'
        layers='base>shadowsocks2022>xray-vless-pq-reality-xhttp-finalmask'
    else:
        middle=middle_quic(remote); outer_engine='sing-box'
        cert=root/'hysteria2'/'cert.pem'; info=cert.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode): raise RuntimeError('unsafe Hysteria2 certificate')
        shutil.copy2(cert,d/'cert.pem')
        layers='base>shadowsocks2022>hysteria2-quic'
    (d/'middle-sing-box.json').write_text(json.dumps(middle,indent=2)+'\n',encoding='utf-8')
    (d/'chain.env').write_text(f'CHAIN_READY=0\nOUTER_ENGINE={outer_engine}\nCHAIN_LAYERS={layers}\nLOCAL_RELAY_PORT={relay}\n',encoding='utf-8')

for args in [('max-tls-wg','wg','tls'),('max-tls-awg','awg','tls'),('max-quic-wg','wg','quic'),('max-quic-awg','awg','quic')]: write_branch(*args)
xdir=outroot/'reality-xhttp'; xdir.mkdir()
(xdir/'xray.json').write_text(json.dumps(outer_xray,indent=2)+'\n',encoding='utf-8')
advanced={'xhttp_port':xp,'xhttp_path':path,'xhttp_uuid':uuid,'xhttp_short_id':shortid,'xhttp_reality_public':rpub,'max_local_relay_port':relay}
(tmp/'advanced-secrets.json').write_text(json.dumps(advanced,indent=2)+'\n',encoding='utf-8')
for p in tmp.rglob('*'):
    if p.is_file(): os.chmod(p,0o600)
PY

# Validate the entire candidate tree before changing current Xray or branch files.
xr run -test -c "$GEN_TMP/server.json" >/dev/null
for branch in max-tls-wg max-tls-awg max-quic-wg max-quic-awg; do
  dir="$GEN_TMP/generated/$branch"
  if [[ -f $dir/outer-xray.json ]]; then xr run -test -c "$dir/outer-xray.json" >/dev/null; fi
  sb check -D "$dir" -c "$dir/middle-sing-box.json" >/dev/null
  sed -i 's/^CHAIN_READY=0$/CHAIN_READY=1/' "$dir/chain.env"
  grep -Fxq 'CHAIN_READY=1' "$dir/chain.env"
done
xr run -test -c "$GEN_TMP/generated/reality-xhttp/xray.json" >/dev/null

mkdir -p \
  "$BASE/client-bundle/generated/max-tls-wg" "$BASE/client-bundle/generated/max-tls-awg" \
  "$BASE/client-bundle/generated/max-quic-wg" "$BASE/client-bundle/generated/max-quic-awg" \
  "$BASE/client-bundle/generated/reality-xhttp"
python3 "$PRIVATE_BATCH" \
  "$BASE/config/xray/server.json=$GEN_TMP/server.json" \
  "$BASE/config/xray/advanced-secrets.json=$GEN_TMP/advanced-secrets.json" \
  "$BASE/client-bundle/generated/max-tls-wg/wg.conf=$GEN_TMP/generated/max-tls-wg/wg.conf" \
  "$BASE/client-bundle/generated/max-tls-wg/wg-socks.conf=$GEN_TMP/generated/max-tls-wg/wg-socks.conf" \
  "$BASE/client-bundle/generated/max-tls-wg/outer-xray.json=$GEN_TMP/generated/max-tls-wg/outer-xray.json" \
  "$BASE/client-bundle/generated/max-tls-wg/middle-sing-box.json=$GEN_TMP/generated/max-tls-wg/middle-sing-box.json" \
  "$BASE/client-bundle/generated/max-tls-wg/chain.env=$GEN_TMP/generated/max-tls-wg/chain.env" \
  "$BASE/client-bundle/generated/max-tls-awg/awg.conf=$GEN_TMP/generated/max-tls-awg/awg.conf" \
  "$BASE/client-bundle/generated/max-tls-awg/awg-socks.conf=$GEN_TMP/generated/max-tls-awg/awg-socks.conf" \
  "$BASE/client-bundle/generated/max-tls-awg/outer-xray.json=$GEN_TMP/generated/max-tls-awg/outer-xray.json" \
  "$BASE/client-bundle/generated/max-tls-awg/middle-sing-box.json=$GEN_TMP/generated/max-tls-awg/middle-sing-box.json" \
  "$BASE/client-bundle/generated/max-tls-awg/chain.env=$GEN_TMP/generated/max-tls-awg/chain.env" \
  "$BASE/client-bundle/generated/max-quic-wg/wg.conf=$GEN_TMP/generated/max-quic-wg/wg.conf" \
  "$BASE/client-bundle/generated/max-quic-wg/wg-socks.conf=$GEN_TMP/generated/max-quic-wg/wg-socks.conf" \
  "$BASE/client-bundle/generated/max-quic-wg/cert.pem=$GEN_TMP/generated/max-quic-wg/cert.pem" \
  "$BASE/client-bundle/generated/max-quic-wg/middle-sing-box.json=$GEN_TMP/generated/max-quic-wg/middle-sing-box.json" \
  "$BASE/client-bundle/generated/max-quic-wg/chain.env=$GEN_TMP/generated/max-quic-wg/chain.env" \
  "$BASE/client-bundle/generated/max-quic-awg/awg.conf=$GEN_TMP/generated/max-quic-awg/awg.conf" \
  "$BASE/client-bundle/generated/max-quic-awg/awg-socks.conf=$GEN_TMP/generated/max-quic-awg/awg-socks.conf" \
  "$BASE/client-bundle/generated/max-quic-awg/cert.pem=$GEN_TMP/generated/max-quic-awg/cert.pem" \
  "$BASE/client-bundle/generated/max-quic-awg/middle-sing-box.json=$GEN_TMP/generated/max-quic-awg/middle-sing-box.json" \
  "$BASE/client-bundle/generated/max-quic-awg/chain.env=$GEN_TMP/generated/max-quic-awg/chain.env" \
  "$BASE/client-bundle/generated/reality-xhttp/xray.json=$GEN_TMP/generated/reality-xhttp/xray.json"
rm -rf "$GEN_TMP"
GEN_TMP=
trap - EXIT
printf 'Generated and validated MAX TLS/QUIC branches on standard WireGuard and AmneziaWG bases as one private transaction.\n'
