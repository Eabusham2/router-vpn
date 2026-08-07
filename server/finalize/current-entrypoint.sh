#!/usr/bin/env bash
set -euo pipefail
if [[ -z ${ENDPOINT:-} || ${ENDPOINT:-} == router.invalid ]]; then
  detected=$(python3 - <<'PY'
import urllib.request
try:
    print(urllib.request.urlopen('https://api.ipify.org',timeout=4).read().decode().strip())
except Exception:
    pass
PY
  )
  if [[ -n $detected ]]; then
    export ENDPOINT=$detected
    echo "Detected public IPv4 for runtime profiles: $ENDPOINT"
  fi
fi
bash /src/server/finalize/adopt-current-markers.sh
exec bash /src/server/finalize/upgrade-safe.sh
