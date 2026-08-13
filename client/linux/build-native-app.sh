#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
OUT=${1:?usage: build-native-app.sh OUT_BINARY}
SRC="$ROOT/client/linux/routervpn-gtk-product.c"

for pkg in gtk+-3.0 libcurl json-glib-1.0; do
  pkg-config --exists "$pkg" || { echo "Missing native Linux app build dependency: $pkg" >&2; exit 2; }
done
mkdir -p "$(dirname "$OUT")"

gcc -O2 -Wall -Wextra -Werror -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
  "$SRC" -o "$OUT" \
  $(pkg-config --cflags --libs gtk+-3.0 libcurl json-glib-1.0) -lm
chmod 755 "$OUT"

file "$OUT"
ldd "$OUT" | grep -q 'libgtk-3'
ldd "$OUT" | grep -q 'libjson-glib'
# Runner pkg-config may choose dynamic or static libcurl. Require the API symbol,
# not one particular linkage form.
if ! nm -a "$OUT" 2>/dev/null | grep -q 'curl_easy_init' && ! nm -D "$OUT" 2>/dev/null | grep -q 'curl_easy_init'; then
  echo 'Native Linux app does not contain/reference required libcurl API.' >&2
  exit 1
fi
! ldd "$OUT" | grep -Ei 'webkit|cef|chromium|electron'
! grep -Eqi 'WebKit|WebView|chromium|electron|xdg-open|sensible-browser' "$SRC"
grep -Fq 'gtk_window_new' "$SRC"
grep -Fq 'gtk_notebook_new' "$SRC"
grep -Fq 'http://127.0.0.1:8788' "$SRC"
grep -Fq '/api/connect-logical' "$SRC"
grep -Fq '/api/emergency-stop' "$SRC"
grep -Fq '/api/session/events' "$SRC"
grep -Fq 'latitude' "$SRC"
grep -Fq 'longitude' "$SRC"
grep -Fq 'Nodes & Map' "$SRC"
grep -Fq 'Forwarding' "$SRC"
grep -Fq 'Settings' "$SRC"
grep -Fq 'Help' "$SRC"
grep -Fq 'ensure_controller' "$SRC"
grep -Fq 'shutdown_controller' "$SRC"
"$OUT" --self-test

echo "Built native Linux GTK Router VPN product shell at $OUT"
