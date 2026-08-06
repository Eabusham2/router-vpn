#!/usr/bin/env bash
set -euo pipefail
BASE=${1:-/opt/router-vpn}
NEW=${2:-AUTO}
if [[ $NEW == AUTO ]]; then NEW=$(curl -4fsS --max-time 10 https://api.ipify.org); fi
[[ -n $NEW ]] || { echo 'Could not determine endpoint.' >&2; exit 1; }
python3 - "$BASE" "$NEW" <<'PY'
from pathlib import Path
import sys,re
base=Path(sys.argv[1]); endpoint=sys.argv[2]
for p in (base/'client-bundle/generated').rglob('*'):
    if not p.is_file(): continue
    try: s=p.read_text()
    except UnicodeDecodeError: continue
    s=re.sub(r'(?m)^Endpoint = [^:]+:', f'Endpoint = {endpoint}:', s)
    s=re.sub(r'("server"\s*:\s*")[^"]+("\s*,)', rf'\g<1>{endpoint}\2', s)
    s=re.sub(r'("address"\s*:\s*")[^"]+("\s*,)', rf'\g<1>{endpoint}\2', s)
    p.write_text(s)
cred=base/'client-bundle/CREDENTIALS.txt'
if cred.exists(): cred.write_text(re.sub(r'(?m)^Endpoint: .*$', f'Endpoint: {endpoint}', cred.read_text()))
PY
cd "$BASE/client-bundle"
zip -qr "$BASE/downloads/router-vpn-client-bundle.zip" .
cp "$BASE/downloads/router-vpn-client-bundle.zip" "$BASE/router-vpn-client-bundle.zip"
echo "Updated client endpoint to $NEW. Download the new client bundle before leaving home."
