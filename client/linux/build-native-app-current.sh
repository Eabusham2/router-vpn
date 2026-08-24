#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BASE="$ROOT/client/linux/build-native-app.sh"
REQ="$ROOT/client/linux/routervpn-auto-requirements-v11.inc"
[[ -s "$BASE" && -s "$REQ" ]] || { echo 'Missing Linux native base builder or AUTO requirements include.' >&2; exit 2; }
for marker in 'routervpn-auto-requirements-v11.inc' 'AUTO / SMART requirements' 'G_CALLBACK(on_linux_auto_requirements_v11)' 'router-vpn-auto-requirements-v11'; do
  grep -Fq "$marker" "$BASE" || { echo "Canonical Linux builder missing $marker" >&2; exit 2; }
done
for marker in '/api/profile/settings' 'auto_require_encrypted' 'auto_require_obfuscation' 'Require encrypted AUTO candidates' 'Require obfuscation for AUTO candidates'; do
  grep -Fq "$marker" "$REQ" || { echo "Linux AUTO requirements include missing $marker" >&2; exit 2; }
done
exec bash "$BASE" "$@"
