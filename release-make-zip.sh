#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/tmp/router-vpn.zip}
OUT=$(python3 - "$OUT" <<'PY'
import os,sys
print(os.path.abspath(sys.argv[1]))
PY
)

cd "$ROOT"
chmod +x deploy/build-client.sh deploy/package-builds.sh
./deploy/build-client.sh
./deploy/package-builds.sh

find . -type d -name '__pycache__' -prune -exec rm -rf {} +
find . -type f \( -name '*.pyc' -o -name '.DS_Store' \) -delete
find . -type f -name '*.sh' -exec chmod +x {} +

# Generate metadata from the tree that will actually be shipped.
find . -type f \
  -not -path './.git/*' \
  -not -name 'PACKAGE-MANIFEST.txt' \
  -not -name 'BINARY-SHA256SUMS.txt' \
  -not -name '*.zip.sha256' \
  -print | sort > PACKAGE-MANIFEST.txt
printf '%s\n' './PACKAGE-MANIFEST.txt' './BINARY-SHA256SUMS.txt' >> PACKAGE-MANIFEST.txt
sort -u -o PACKAGE-MANIFEST.txt PACKAGE-MANIFEST.txt

find dist -type f \
  -not -name 'SHA256SUMS' \
  -print0 | sort -z | xargs -0 sha256sum > BINARY-SHA256SUMS.txt

# Verify the per-platform package set before wrapping the full project.
if [[ -f dist/packages/SHA256SUMS ]]; then
  (cd dist/packages && sha256sum -c SHA256SUMS)
fi
for archive in dist/packages/*.zip; do
  [[ -e "$archive" ]] || continue
  unzip -tq "$archive" >/dev/null
done
for archive in dist/packages/*.tar.gz; do
  [[ -e "$archive" ]] || continue
  tar -tzf "$archive" >/dev/null
done

mkdir -p "$(dirname "$OUT")"
rm -f "$OUT" "$OUT.sha256"
PARENT=$(dirname "$ROOT")
NAME=$(basename "$ROOT")
(
  cd "$PARENT"
  zip -qr "$OUT" "$NAME" \
    -x "$NAME/.git/*" \
       "$NAME/*.zip" \
       "$NAME/**/*.zip" \
       "$NAME/**/__pycache__/*" \
       "$NAME/**/*.pyc"
)
unzip -tq "$OUT" >/dev/null
sha256sum "$OUT" > "$OUT.sha256"
printf '%s\n' "$OUT"
