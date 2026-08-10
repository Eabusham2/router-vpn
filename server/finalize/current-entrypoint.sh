#!/usr/bin/env bash
set -euo pipefail

if [[ -z ${ENDPOINT:-} || ${ENDPOINT:-} == router.invalid ]]; then
  detected=$(python3 - <<'PY'
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
            break
    except Exception:
        continue
PY
  )

  if [[ -n $detected ]]; then
    export ENDPOINT=$detected
    echo "Detected public IPv4 for runtime profiles: $ENDPOINT"
  else
    echo 'Warning: public IPv4 auto-detection failed across all providers; generated profiles will keep a placeholder until an endpoint is supplied.' >&2
  fi
fi

bash /src/server/finalize/adopt-current-markers.sh
exec bash /src/server/finalize/upgrade-safe.sh
