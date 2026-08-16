#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
OUT=${1:?usage: build-native-app.sh OUT_BINARY}
SRC="$ROOT/client/linux/routervpn-gtk-product-v5.c"
ONBOARDING_INC="$ROOT/client/linux/routervpn-product-onboarding-v6.inc"
V4="$ROOT/client/linux/routervpn-gtk-product-v4.c"
V3="$ROOT/client/linux/routervpn-gtk-product-v3.c"
CORE="$ROOT/client/linux/routervpn-gtk-product.c"
SHIPPED=("$SRC" "$ONBOARDING_INC" "$V4" "$V3" "$CORE")
BUILD_DIR=$(mktemp -d "${TMPDIR:-/tmp}/router-vpn-linux-v5.XXXXXX")
EMBEDDED_V4="$BUILD_DIR/routervpn-gtk-product-v4-embedded.c"
BUILD_SRC="$BUILD_DIR/routervpn-gtk-product-v5-shipping.c"
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

# The tracked v5 product already owns the real GTK assistant. Build a guarded
# shipping view that swaps only the tutorial content and lifecycle seam: the
# complete retained topics come from a tracked include, and closing/cancelling
# saves the current page so first-run onboarding genuinely resumes. DNS/runtime
# code is not rewritten and still compiles under -Wall -Wextra -Werror.
python3 - "$SRC" "$BUILD_SRC" <<'PY'
from pathlib import Path
import sys
src_path, out_path = map(Path, sys.argv[1:3])
text = src_path.read_text(encoding='utf-8')

finish_old = '''static void onboarding_finish_v5(GtkAssistant *assistant, gpointer data) {
    (void)data;
    const char *path = g_object_get_data(G_OBJECT(assistant), "router-vpn-onboarding-marker");
    if (path != NULL) (void)g_file_set_contents(path, "done\\n", -1, NULL);
    gtk_widget_destroy(GTK_WIDGET(assistant));
}

static void onboarding_cancel_v5(GtkAssistant *assistant, gpointer data) {
    (void)data;
    gtk_widget_destroy(GTK_WIDGET(assistant));
}
'''
finish_new = '''static char *onboarding_step_path_v6(const char *done_path) {
    return done_path != NULL ? g_strconcat(done_path, ".step", NULL) : NULL;
}

static int onboarding_read_step_v6(const char *done_path) {
    char *path = onboarding_step_path_v6(done_path);
    char *raw = NULL;
    gsize length = 0;
    int step = 0;
    if (path != NULL && g_file_get_contents(path, &raw, &length, NULL) && raw != NULL) {
        step = (int)g_ascii_strtoll(raw, NULL, 10);
    }
    g_free(raw);
    g_free(path);
    return step;
}

static void onboarding_write_step_v6(const char *done_path, int step) {
    char *path = onboarding_step_path_v6(done_path);
    char *raw = g_strdup_printf("%d\\n", step < 0 ? 0 : step);
    if (path != NULL) (void)g_file_set_contents(path, raw, -1, NULL);
    g_free(raw);
    g_free(path);
}

static void onboarding_finish_v5(GtkAssistant *assistant, gpointer data) {
    (void)data;
    const char *path = g_object_get_data(G_OBJECT(assistant), "router-vpn-onboarding-marker");
    if (path != NULL) {
        (void)g_file_set_contents(path, "done\\n", -1, NULL);
        onboarding_write_step_v6(path, 0);
    }
    gtk_widget_destroy(GTK_WIDGET(assistant));
}

static void onboarding_cancel_v5(GtkAssistant *assistant, gpointer data) {
    (void)data;
    const char *path = g_object_get_data(G_OBJECT(assistant), "router-vpn-onboarding-marker");
    if (path != NULL) onboarding_write_step_v6(path, gtk_assistant_get_current_page(assistant));
    gtk_widget_destroy(GTK_WIDGET(assistant));
}
'''
if text.count(finish_old) != 1:
    raise SystemExit('Linux onboarding callback contract drifted')
text = text.replace(finish_old, finish_new, 1)

start = text.find('    static const char *const titles[] = {')
assistant = text.find('    GtkWidget *assistant = gtk_assistant_new();', start)
if start < 0 or assistant < 0:
    raise SystemExit('Linux onboarding content seam drifted')
text = text[:start] + '    #include "routervpn-product-onboarding-v6.inc"\n' + text[assistant:]

signal_old = '''    g_signal_connect(assistant, "apply", G_CALLBACK(onboarding_finish_v5), app);
    g_signal_connect(assistant, "close", G_CALLBACK(onboarding_finish_v5), app);
    g_signal_connect(assistant, "cancel", G_CALLBACK(onboarding_cancel_v5), app);
    gtk_widget_show_all(assistant);'''
signal_new = '''    if (!force) {
        int saved_step = onboarding_read_step_v6(path);
        if (saved_step >= 0 && saved_step < (int)G_N_ELEMENTS(titles))
            gtk_assistant_set_current_page(GTK_ASSISTANT(assistant), saved_step);
    }
    g_signal_connect(assistant, "apply", G_CALLBACK(onboarding_finish_v5), app);
    g_signal_connect(assistant, "close", G_CALLBACK(onboarding_cancel_v5), app);
    g_signal_connect(assistant, "cancel", G_CALLBACK(onboarding_cancel_v5), app);
    gtk_widget_show_all(assistant);'''
if text.count(signal_old) != 1:
    raise SystemExit('Linux onboarding signal contract drifted')
text = text.replace(signal_old, signal_new, 1)

for marker in (
    '#include "routervpn-product-onboarding-v6.inc"',
    'onboarding_read_step_v6(path)',
    'gtk_assistant_set_current_page',
    'onboarding_write_step_v6(path, gtk_assistant_get_current_page(assistant))',
    'g_signal_connect(assistant, "close", G_CALLBACK(onboarding_cancel_v5), app)',
):
    if marker not in text:
        raise SystemExit(f'missing Linux shipping onboarding marker: {marker}')
out_path.write_text(text, encoding='utf-8')
PY

# Keep the concrete DNS cleanup regressions caught by -Werror from returning.
grep -Fq 'if (working) {' "$SRC"
grep -Fq 'g_string_append_printf(detail, "%s • %s • %.2f ms\n"' "$SRC"
grep -Fq 'json_node_free(root);' "$SRC"
grep -Fq 'free(out.data);' "$SRC"
grep -Fq 'g_free(err);' "$SRC"
! grep -Fq 'working ? g_strdup_printf' "$SRC"
! grep -Fq 'if (root != NULL) json_node_free(root); free(out.data); g_free(err);' "$SRC"

gcc -O2 -Wall -Wextra -Werror -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
  -I"$BUILD_DIR" -I"$ROOT/client/linux" \
  "$BUILD_SRC" -o "$OUT" \
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

# Shipping app onboarding lifecycle and complete topic contract.
grep -Fq '#include "routervpn-product-onboarding-v6.inc"' "$BUILD_SRC"
grep -Fq 'gtk_assistant_set_current_page' "$BUILD_SRC"
grep -Fq 'onboarding_write_step_v6' "$BUILD_SRC"
grep -Fq 'linux-onboarding-v5.done' "$SRC"
grep -Fq 'Run Tutorial' "$SRC"
for marker in 'pairing' 'router-vpn-bundle.json' 'AUTO' 'WireGuard' 'AmneziaWG' 'DNS' 'LAN Off' 'MTU/Jumbo' 'kill-switch' 'Multihop' 'forwarding' 'permissions' 'Disconnect' 'private identity/path proof' 'Public exit' 'Diagnostics' 'Emergency stop' 'Setup Center Full Guide' 'Run Tutorial'; do
  grep -Fq "$marker" "$ONBOARDING_INC"
done

grep -Fq 'Diagnostics' "$SRC"
grep -Fq '/api/session/events?after=0' "$SRC"
grep -Fq 'apply_action_sensitivity_v5' "$SRC"
grep -Fq 'gtk_widget_set_sensitive' "$SRC"
grep -Fq 'truthful-empty-state-actions' "$SRC"
grep -Fq 'gtk_window_set_default_size(GTK_WINDOW(app->window), 960, 680);' "$SRC"
grep -Fq '/api/mtu/retest' "$SRC"
grep -Fq 'Retest MTU' "$SRC"
grep -Fq '130000' "$SRC"
grep -Fq 'router-vpn-advanced-mtu-v5' "$SRC"
"$OUT" --self-test

echo "Built native Linux GTK Router VPN product shell with resumable complete app onboarding at $OUT"
