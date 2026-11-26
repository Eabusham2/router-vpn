#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
OUT=${1:?usage: build-native-app.sh OUT_BINARY}
SRC="$ROOT/client/linux/routervpn-gtk-product-v5.c"
mkdir -p "$(dirname "$OUT")"
gcc -O2 -Wall -Wextra -Werror -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
  -I"$ROOT/client/linux" "$SRC" -o "$OUT" \
  $(pkg-config --cflags --libs gtk+-3.0 libcurl json-glib-1.0) -lm -pthread
chmod 755 "$OUT"
"$OUT" --self-test
echo "Built native Linux GTK Router VPN: $OUT"
