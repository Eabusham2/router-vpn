#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
OUT=${1:?usage: build-native-app.sh OUT_BINARY}
SRC="$ROOT/client/linux/routervpn-gtk-product-v4.c"
LEGACY="$ROOT/client/linux/routervpn-gtk-product-v3.c"
CORE="$ROOT/client/linux/routervpn-gtk-product.c"
SHIPPED=("$SRC" "$LEGACY" "$CORE")

for pkg in gtk+-3.0 libcurl json-glib-1.0; do
  pkg-config --exists "$pkg" || { echo "Missing native Linux app build dependency: $pkg" >&2; exit 2; }
done
mkdir -p "$(dirname "$OUT")"

gcc -O2 -Wall -Wextra -Werror -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
  "$SRC" -o "$OUT" \
  $(pkg-config --cflags --libs gtk+-3.0 libcurl json-glib-1.0) -lm
chmod 755 "$OUT"

file "$OUT"
# Capture producer output before matching it. With pipefail, `producer | grep -q`
# can report a false failure when grep exits after its first match and the
# producer receives SIGPIPE. These are strict content checks, not pipeline tests.
LINKAGE=$(ldd "$OUT")
grep -q 'libgtk-3' <<<"$LINKAGE"
grep -q 'libjson-glib' <<<"$LINKAGE"
# Runner pkg-config may choose dynamic or static libcurl. Require the API symbol,
# not one particular linkage form.
SYMBOLS=$(nm -a "$OUT" 2>/dev/null || true)
DYNAMIC_SYMBOLS=$(nm -D "$OUT" 2>/dev/null || true)
if ! grep -q 'curl_easy_init' <<<"$SYMBOLS" && ! grep -q 'curl_easy_init' <<<"$DYNAMIC_SYMBOLS"; then
  echo 'Native Linux app does not contain/reference required libcurl API.' >&2
  exit 1
fi
# v4 is the shipping translation unit and intentionally composes v3 -> core via
# source includes. Contract checks must therefore inspect the whole composed
# source graph instead of only v4 + core, or inherited native features are
# falsely reported missing.
! grep -Eqi 'WebKit|WebView|chromium|electron|xdg-open|sensible-browser' "${SHIPPED[@]}"
grep -Fq 'gtk_window_new' "${SHIPPED[@]}"
grep -Fq 'gtk_notebook_new' "${SHIPPED[@]}"
grep -Fq 'http://127.0.0.1:8788' "${SHIPPED[@]}"
grep -Fq '/api/connect-logical' "${SHIPPED[@]}"
grep -Fq '/api/emergency-stop' "${SHIPPED[@]}"
grep -Fq '/api/session/events' "${SHIPPED[@]}"
grep -Fq '/api/profile/pair' "${SHIPPED[@]}"
grep -Fq '/api/profile/import' "${SHIPPED[@]}"
grep -Fq '/api/profile/delete' "${SHIPPED[@]}"
grep -Fq '/api/profile/latency' "${SHIPPED[@]}"
grep -Fq '/api/external-profile/import' "$SRC"
grep -Fq '/api/external-profile/connect' "$SRC"
grep -Fq '/api/nodes' "$SRC"
grep -Fq 'latitude' "${SHIPPED[@]}"
grep -Fq 'longitude' "${SHIPPED[@]}"
grep -Fq 'Nodes & Map' "${SHIPPED[@]}"
grep -Fq 'Forwarding' "${SHIPPED[@]}"
grep -Fq 'Settings' "${SHIPPED[@]}"
grep -Fq 'Help' "${SHIPPED[@]}"
grep -Fq 'ensure_controller' "${SHIPPED[@]}"
grep -Fq 'shutdown_controller' "${SHIPPED[@]}"
"$OUT" --self-test

echo "Built native Linux GTK Router VPN product shell at $OUT"
