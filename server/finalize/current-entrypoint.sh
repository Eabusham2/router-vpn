#!/usr/bin/env bash
set -euo pipefail
if [[ -z ${ENDPOINT:-} || ${ENDPOINT:-} == router.invalid ]]; then
  detected=$(python3 - <<'PY'
import ipaddress, urllib.request
try:
    value=urllib.request.urlopen('https://api.ipify.org',timeout=4).read().decode().strip()
    ip=ipaddress.ip_address(value)
    if ip.version == 4 and ip.is_global:
        print(value)
except Exception:
    pass
PY
  )
  if [[ -z $detected ]] && command -v curl >/dev/null 2>&1; then
    candidate=$(curl -4fsS --max-time 4 https://api.ipify.org 2>/dev/null || true)
    if python3 - "$candidate" <<'PY' >/dev/null 2>&1
import ipaddress,sys
ip=ipaddress.ip_address(sys.argv[1].strip())
raise SystemExit(0 if ip.version == 4 and ip.is_global else 1)
PY
    then
      detected=$candidate
    fi
  fi
  if [[ -n $detected ]]; then
    export ENDPOINT=$detected
    echo "Detected public IPv4 for runtime profiles: $ENDPOINT"
  else
    echo 'Warning: public IPv4 auto-detection failed; generated profiles will keep a placeholder until an endpoint is supplied.' >&2
  fi
fi
bash /src/server/finalize/adopt-current-markers.sh
exec bash /src/server/finalize/upgrade-safe.sh
