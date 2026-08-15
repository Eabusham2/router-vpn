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
# v4's final standalone main() is omitted. Its old top-level build_ui_v4()
# remains inherited for source-contract continuity but is intentionally replaced
# by build_ui_v5(), so mark only that generated copy as retained. All other
# -Wunused-function findings remain fatal under -Werror.
python3 - "$V4" "$EMBEDDED_V4" <<'PY'
from pathlib import Path
import sys
src = Path(sys.argv[1]).read_text()
main = 'int main(int argc, char **argv) {'
if src.count(main) != 1:
    raise SystemExit('expected exactly one v4 main')
body = src.split(main, 1)[0]
old = 'static void build_ui_v4(App *app) {'
new = 'static void __attribute__((used)) build_ui_v4(App *app) {'
if body.count(old) != 1:
    raise SystemExit('expected exactly one v4 build_ui_v4')
body = body.replace(old, new, 1)
Path(sys.argv[2]).write_text(body)
PY
! grep -Fq 'int main(int argc, char **argv) {' "$EMBEDDED_V4"
grep -Fq 'static void __attribute__((used)) build_ui_v4(App *app) {' "$EMBEDDED_V4"

gcc -O2 -Wall -Wextra -Werror -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
  -I"$BUILD_DIR" -I"$ROOT/client/linux" \
  "$SRC" -o "$OUT" \
  $(pkg-config --cflags --libs gtk+-3.0 libcurl json-glib-1.0) -lm
chmod 755 "$OUT"

file "$OUT"
LINKAGE=$(ldd "$OUT")
grep -q 'libgtk-3' <<<"$LINKAGE"
grep -q 'libjson-glib' <<<"$LINKAGE"
SYMBOLS=$(nm -a "$OUT" 2>/dev/null || true)
DYNAMIC_SYMBOLS=$(nm -D "$OUT" 2>/dev/null || true)
if ! grep -q 'curl_easy_init' <<<"$SYMBOLS" && ! grep -q 'curl_easy_init' <<<"$DYNAMIC_SYMBOLS"; then
  echo 'Native Linux app does not contain/reference required libcurl API.' >&2
  exit 1
fi
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
# persistent native first-run tutorial, a dedicated Diagnostics surface,
# truthful empty-state action availability and a small-screen-safe default.
grep -Fq '#include "routervpn-gtk-product-v4-embedded.c"' "$SRC"
grep -Fq 'linux-onboarding-v5.done' "$SRC"
grep -Fq 'Run Tutorial' "$SRC"
grep -Fq 'Diagnostics' "$SRC"
grep -Fq '/api/session/events?after=0' "$SRC"
grep -Fq 'apply_action_sensitivity_v5' "$SRC"
grep -Fq 'gtk_widget_set_sensitive' "$SRC"
grep -Fq 'truthful-empty-state-actions' "$SRC"
grep -Fq 'gtk_window_set_default_size(GTK_WINDOW(app->window), 960, 680);' "$SRC"
# MTU Retest must be a real native action against the fixed local controller,
# not an inert label or external helper launcher.
grep -Fq '/api/mtu/retest' "$SRC"
grep -Fq 'Retest MTU' "$SRC"
grep -Fq '130000' "$SRC"
grep -Fq 'router-vpn-advanced-mtu-v5' "$SRC"
"$OUT" --self-test

echo "Built native Linux GTK Router VPN product shell at $OUT"