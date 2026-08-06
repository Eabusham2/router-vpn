#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/mnt/data/router-vpn.zip}
cd "$ROOT"
./deploy/build-client.sh
find . -type f -name '*.sh' -exec chmod +x {} +
find . -type f -not -path './.git/*' -print | sort > PACKAGE-MANIFEST.txt
sha256sum dist/* > BINARY-SHA256SUMS.txt
rm -f "$OUT"
cd "$(dirname "$ROOT")"
zip -qr "$OUT" "$(basename "$ROOT")" -x 'router-vpn/.git/*' 'router-vpn/*.zip'
sha256sum "$OUT" > "$OUT.sha256"
echo "$OUT"
