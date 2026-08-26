#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BASE="$ROOT/client/linux/build-native-app.sh"
REQ="$ROOT/client/linux/routervpn-auto-requirements-v11.inc"
[[ -s "$BASE" && -s "$REQ" ]] || { echo 'Missing Linux native base builder or AUTO requirements include.' >&2; exit 2; }

# The canonical builder injects the AUTO requirements include into its generated
# shipping C source. The callback/UI implementation lives in the include itself,
# so do not require implementation strings to be duplicated in the builder.
for marker in 'routervpn-auto-requirements-v11.inc' 'AUTO_REQ_INC='; do
  grep -Fq "$marker" "$BASE" || { echo "Canonical Linux builder missing $marker" >&2; exit 2; }
done
for marker in \
  '/api/profile/settings' \
  'auto_require_encrypted' \
  'auto_require_obfuscation' \
  'Require encrypted AUTO candidates' \
  'Require obfuscation for AUTO candidates' \
  'on_linux_auto_requirements_v11' \
  'AUTO / SMART requirements' \
  'Save requirements'; do
  grep -Fq "$marker" "$REQ" || { echo "Linux AUTO requirements include missing $marker" >&2; exit 2; }
done
exec bash "$BASE" "$@"
