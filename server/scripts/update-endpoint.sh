#!/usr/bin/env bash
set -euo pipefail
BASE=${1:-/opt/router-vpn}
NEW=${2:-AUTO}

detect_public_ipv4() {
  python3 - <<'PY'
import ipaddress
import urllib.request

sources = [
    ("https://1.1.1.1/cdn-cgi/trace", "trace"),
    ("https://checkip.amazonaws.com", "plain"),
    ("https://icanhazip.com", "plain"),
    ("https://api.ipify.org", "plain"),
]

for url, kind in sources:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "router-vpn/1"})
        body = urllib.request.urlopen(req, timeout=4).read().decode().strip()
        if kind == "trace":
            value = next((line[3:].strip() for line in body.splitlines() if line.startswith("ip=")), "")
        else:
            value = body.splitlines()[0].strip() if body else ""
        ip = ipaddress.ip_address(value)
        if ip.version == 4 and ip.is_global:
            print(value)
            raise SystemExit(0)
    except Exception:
        continue
raise SystemExit(1)
PY
}

if [[ $NEW == AUTO ]]; then
  NEW=$(detect_public_ipv4 || true)
fi
[[ -n $NEW ]] || { echo 'Could not determine endpoint from any public IPv4 provider.' >&2; exit 1; }
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
