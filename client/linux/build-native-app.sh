#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
OUT=${1:?usage: build-native-app.sh OUT_BINARY}
SRC="$ROOT/client/linux/routervpn-gtk-product-v5.c"
V4="$ROOT/client/linux/routervpn-gtk-product-v4.c"
V3="$ROOT/client/linux/routervpn-gtk-product-v3.c"
CORE="$ROOT/client/linux/routervpn-gtk-product.c"
SHIPPED=("$SRC" "$V4" "$V3" "$CORE")
BUILD_DIR=$(mktemp -d "${TMPDIR:-/tmp}/router-vpn-linux-v5.XXXXXX")
EMBEDDED_V4="$BUILD_DIR/routervpn-gtk-product-v4-embedded.c"
trap 'rm -rf "$BUILD_DIR"' EXIT

for pkg in gtk+-3.0 libcurl json-glib-1.0; do
  pkg-config --exists "$pkg" || { echo "Missing native Linux app build dependency: $pkg" >&2; exit 2; }
done
mkdir -p "$(dirname "$OUT")"

# v5 extends the already-shipping v4 translation unit without duplicating it.
# v4's final standalone main() is the only section omitted; all v4/v3/core
# static functions remain in the same translation unit for v5 to reuse.
grep -Fq 'int main(int argc, char **argv) {' "$V4"
awk '/^int main\(int argc, char \*\*argv\) \{$/{found=1; exit} {print} END{if(!found) exit 7}' "$V4" > "$EMBEDDED_V4"
! grep -Fq 'int main(int argc, char **argv) {' "$EMBEDDED_V4"

gcc -O2 -Wall -Wextra -Werror -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
  -I"$BUILD_DIR" -I"$ROOT/client/linux" \
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
# v5 is the shipping translation unit and intentionally composes v4 -> v3 ->
# core. Inspect the complete checked-in source graph so inherited native
# contracts remain release-gated while v5-specific onboarding/diagnostics are
# required explicitly.
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
grep -Fq '/api/external-profile/import' "${SHIPPED[@]}"
grep -Fq '/api/external-profile/connect' "${SHIPPED[@]}"
grep -Fq '/api/nodes' "${SHIPPED[@]}"
grep -Fq 'latitude' "${SHIPPED[@]}"
grep -Fq 'longitude' "${SHIPPED[@]}"
grep -Fq 'Nodes & Map' "${SHIPPED[@]}"
grep -Fq 'Forwarding' "${SHIPPED[@]}"
grep -Fq 'Settings' "${SHIPPED[@]}"
grep -Fq 'Help' "${SHIPPED[@]}"
grep -Fq 'ensure_controller' "${SHIPPED[@]}"
grep -Fq 'shutdown_controller' "${SHIPPED[@]}"
# Visual QA contract discovered post-GitHub: the shipping app must own a
# persistent native first-run tutorial and a dedicated Diagnostics surface.
grep -Fq '#include "routervpn-gtk-product-v4-embedded.c"' "$SRC"
grep -Fq 'linux-onboarding-v5.done' "$SRC"
grep -Fq 'Run Tutorial' "$SRC"
grep -Fq 'Diagnostics' "$SRC"
grep -Fq '/api/session/events?after=0' "$SRC"
"$OUT" --self-test

echo "Built native Linux GTK Router VPN product shell at $OUT"
