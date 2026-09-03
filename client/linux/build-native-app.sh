#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
OUT=${1:?usage: build-native-app.sh OUT_BINARY}
SRC="$ROOT/client/linux/routervpn-gtk-product-v5.c"
ONBOARDING_INC="$ROOT/client/linux/routervpn-product-onboarding-v6.inc"
HOME_INC="$ROOT/client/linux/routervpn-home-summary-v1.inc"
SETTINGS_INC="$ROOT/client/linux/routervpn-profile-settings-v1.inc"
AUTO_REQ_INC="$ROOT/client/linux/routervpn-auto-requirements-v11.inc"
UNIFIED_INC="$ROOT/client/linux/routervpn-unified-shell-v8.inc"
TELEMETRY_INC="$ROOT/client/linux/routervpn-telemetry-v9.inc"
SPEED_LAB_INC="$ROOT/client/linux/routervpn-speed-lab-v12.inc"
GLOBE_INC="$ROOT/client/linux/routervpn-globe-v10.inc"
V4="$ROOT/client/linux/routervpn-gtk-product-v4.c"
V3="$ROOT/client/linux/routervpn-gtk-product-v3.c"
CORE="$ROOT/client/linux/routervpn-gtk-product.c"
SESSION_MUTATION="$ROOT/client/linux/apply-session-mutation.py"
SHIPPED=("$SRC" "$ONBOARDING_INC" "$HOME_INC" "$SETTINGS_INC" "$AUTO_REQ_INC" "$UNIFIED_INC" "$TELEMETRY_INC" "$SPEED_LAB_INC" "$GLOBE_INC" "$V4" "$V3" "$CORE")
BUILD_DIR=$(mktemp -d "${TMPDIR:-/tmp}/router-vpn-linux-v10.XXXXXX")
EMBEDDED_V4="$BUILD_DIR/routervpn-gtk-product-v4-embedded.c"
BUILD_SRC="$BUILD_DIR/routervpn-gtk-product-v10-shipping.c"
HARDENED_V4="$BUILD_DIR/routervpn-gtk-product-v4.c"
HARDENED_V3="$BUILD_DIR/routervpn-gtk-product-v3.c"
HARDENED_CORE="$BUILD_DIR/routervpn-gtk-product.c"
HARDENED_SETTINGS="$BUILD_DIR/routervpn-profile-settings-v1.inc"
HARDENED_UNIFIED="$BUILD_DIR/routervpn-unified-shell-v8.inc"
trap 'rm -rf "$BUILD_DIR"' EXIT

for pkg in gtk+-3.0 libcurl json-glib-1.0; do
  pkg-config --exists "$pkg" || { echo "Missing native Linux app build dependency: $pkg" >&2; exit 2; }
done
for source in "$ONBOARDING_INC" "$HOME_INC" "$SETTINGS_INC" "$AUTO_REQ_INC" "$UNIFIED_INC" "$TELEMETRY_INC" "$SPEED_LAB_INC" "$GLOBE_INC"; do
  [[ -s "$source" ]] || { echo "Missing Linux shipping include: $source" >&2; exit 2; }
done
mkdir -p "$(dirname "$OUT")"
[[ -s "$SESSION_MUTATION" ]] || { echo "Missing Linux session-mutation transformer: $SESSION_MUTATION" >&2; exit 2; }
python3 "$SESSION_MUTATION" \
  "$V4" "$HARDENED_V4" \
  "$V3" "$HARDENED_V3" \
  "$CORE" "$HARDENED_CORE" \
  "$SETTINGS_INC" "$HARDENED_SETTINGS" \
  "$UNIFIED_INC" "$HARDENED_UNIFIED"

python3 - "$HARDENED_V4" "$EMBEDDED_V4" <<'PY'
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
body = '#define draw_map routervpn_flat_map_v9\n' + body + '\n#undef draw_map\n'
Path(sys.argv[2]).write_text(body)
PY
! grep -Fq 'int main(int argc, char **argv) {' "$EMBEDDED_V4"
grep -Fq 'static void __attribute__((used)) build_ui_v4(App *app) {' "$EMBEDDED_V4"
grep -Fq '#define draw_map routervpn_flat_map_v9' "$EMBEDDED_V4"
grep -Fq '#undef draw_map' "$EMBEDDED_V4"

python3 - "$SRC" "$BUILD_SRC" <<'PY'
from pathlib import Path
import sys
src_path, out_path = map(Path, sys.argv[1:3])
text = src_path.read_text(encoding='utf-8')
include_old = '#include "routervpn-gtk-product-v4-embedded.c"\n'
include_new = '#include "routervpn-gtk-product-v4-embedded.c"\n#include "routervpn-home-summary-v1.inc"\n#include "routervpn-profile-settings-v1.inc"\n#include "routervpn-auto-requirements-v11.inc"\n'
if text.count(include_old) != 1: raise SystemExit('Linux v5 include seam drifted')
text = text.replace(include_old, include_new, 1)
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
    if (path != NULL && g_file_get_contents(path, &raw, &length, NULL) && raw != NULL) step = (int)g_ascii_strtoll(raw, NULL, 10);
    g_free(raw); g_free(path); return step;
}

static void onboarding_write_step_v6(const char *done_path, int step) {
    char *path = onboarding_step_path_v6(done_path);
    char *raw = g_strdup_printf("%d\\n", step < 0 ? 0 : step);
    if (path != NULL) (void)g_file_set_contents(path, raw, -1, NULL);
    g_free(raw); g_free(path);
}

static void onboarding_finish_v5(GtkAssistant *assistant, gpointer data) {
    (void)data;
    const char *path = g_object_get_data(G_OBJECT(assistant), "router-vpn-onboarding-marker");
    if (path != NULL) { (void)g_file_set_contents(path, "done\\n", -1, NULL); onboarding_write_step_v6(path, 0); }
    gtk_widget_destroy(GTK_WIDGET(assistant));
}

static void onboarding_cancel_v5(GtkAssistant *assistant, gpointer data) {
    (void)data;
    const char *path = g_object_get_data(G_OBJECT(assistant), "router-vpn-onboarding-marker");
    if (path != NULL) onboarding_write_step_v6(path, gtk_assistant_get_current_page(assistant));
    gtk_widget_destroy(GTK_WIDGET(assistant));
}
'''
if text.count(finish_old) != 1: raise SystemExit('Linux onboarding callback contract drifted')
text = text.replace(finish_old, finish_new, 1)
start = text.find('    static const char *const titles[] = {')
assistant = text.find('    GtkWidget *assistant = gtk_assistant_new();', start)
if start < 0 or assistant < 0: raise SystemExit('Linux onboarding content seam drifted')
text = text[:start] + '    #include "routervpn-product-onboarding-v6.inc"\n' + text[assistant:]
signal_old = '''    g_signal_connect(assistant, "apply", G_CALLBACK(onboarding_finish_v5), app);
    g_signal_connect(assistant, "close", G_CALLBACK(onboarding_finish_v5), app);
    g_signal_connect(assistant, "cancel", G_CALLBACK(onboarding_cancel_v5), app);
    gtk_widget_show_all(assistant);'''
signal_new = '''    if (!force) {
        int saved_step = onboarding_read_step_v6(path);
        if (saved_step >= 0 && saved_step < (int)G_N_ELEMENTS(titles)) gtk_assistant_set_current_page(GTK_ASSISTANT(assistant), saved_step);
    }
    g_signal_connect(assistant, "apply", G_CALLBACK(onboarding_finish_v5), app);
    g_signal_connect(assistant, "close", G_CALLBACK(onboarding_cancel_v5), app);
    g_signal_connect(assistant, "cancel", G_CALLBACK(onboarding_cancel_v5), app);
    gtk_widget_show_all(assistant);'''
if text.count(signal_old) != 1: raise SystemExit('Linux onboarding signal contract drifted')
text = text.replace(signal_old, signal_new, 1)
sensitivity_old = '    set_remembered_sensitive_v5(app, "router-vpn-advanced-mtu-v5", connected);'
sensitivity_new = '    set_remembered_sensitive_v5(app, "router-vpn-advanced-settings-v7", has_node && !connected);\n    set_remembered_sensitive_v5(app, "router-vpn-advanced-mtu-v5", connected);'
if text.count(sensitivity_old) != 1: raise SystemExit('Linux profile settings sensitivity seam drifted')
text = text.replace(sensitivity_old, sensitivity_new, 1)
home_refresh_old = '    apply_action_sensitivity_v5(app, connected);'
home_refresh_new = '    apply_action_sensitivity_v5(app, connected);\n    refresh_home_summary_v6(app);'
if text.count(home_refresh_old) != 1: raise SystemExit('Linux Home refresh seam drifted')
text = text.replace(home_refresh_old, home_refresh_new, 1)
advanced_old = '''    GtkWidget *advanced = build_advanced_page_v5(app);
    add_tab(tabs, advanced, "Advanced");
    remember_button_v5(app, advanced, "router-vpn-advanced-mtu-v5", "Retest MTU");'''
advanced_new = '''    GtkWidget *advanced = build_advanced_page_v5(app);
    GtkWidget *settings_v7 = make_button("Edit profile settings", G_CALLBACK(on_profile_settings_v7), app);
    gtk_box_pack_start(GTK_BOX(advanced), settings_v7, FALSE, FALSE, 0);
    add_tab(tabs, advanced, "Advanced");
    remember_button_v5(app, advanced, "router-vpn-advanced-settings-v7", "Edit profile settings");
    remember_button_v5(app, advanced, "router-vpn-advanced-mtu-v5", "Retest MTU");'''
if text.count(advanced_old) != 1: raise SystemExit('Linux Advanced profile settings seam drifted')
text = text.replace(advanced_old, advanced_new, 1)
home_old = '    GtkWidget *home = build_home_page(app);\n    add_tab(tabs, home, "Home / Connect");'
home_new = '''    GtkWidget *home = build_home_page(app);
    GtkWidget *home_exit_v6 = find_button_v5(home, "Prove public VPN exit");
    if (home_exit_v6 == NULL) { g_error("Router VPN shipping Home public-exit button contract drifted"); }
    g_signal_handlers_disconnect_by_func(home_exit_v6, G_CALLBACK(on_public_ip), app);
    gtk_button_set_label(GTK_BUTTON(home_exit_v6), "Prove actual exit");
    g_signal_connect(home_exit_v6, "clicked", G_CALLBACK(on_home_exit_v6), app);
    add_tab(tabs, home, "Home / Connect");'''
if text.count(home_old) != 1: raise SystemExit('Linux Home button seam drifted')
text = text.replace(home_old, home_new, 1)
initial_old = '    refresh_all(&app);\n    refresh_mode_details_v5(&app);'
initial_new = '    refresh_all(&app);\n    refresh_home_summary_v6(&app);\n    refresh_mode_details_v5(&app);'
if text.count(initial_old) != 1: raise SystemExit('Linux initial Home refresh seam drifted')
text = text.replace(initial_old, initial_new, 1)
legacy_builder = 'static void build_ui_v5(App *app) {'
if text.count(legacy_builder) != 1: raise SystemExit('Linux unified shell could not find exactly one legacy v5 builder')
text = text.replace(legacy_builder, 'static void build_ui_legacy_v5(App *app) {', 1)
self_test_marker = 'static int self_test_v5(void) {'
if text.count(self_test_marker) != 1: raise SystemExit('Linux unified shell could not find v5 self-test seam')
text = text.replace(self_test_marker, '#include "routervpn-unified-shell-v8.inc"\n#include "routervpn-telemetry-v9.inc"\n#include "routervpn-speed-lab-v12.inc"\n#include "routervpn-globe-v10.inc"\n\n' + self_test_marker, 1)
install_old = '    build_ui_v5(&app);\n    g_signal_connect(app.window, "destroy", G_CALLBACK(on_destroy), &app);'
install_new = '    build_ui_v5(&app);\n    linux_install_telemetry_v9(&app);\n    linux_install_speed_lab_v12(&app);\n    linux_install_globe_v10(&app);\n    g_signal_connect(app.window, "destroy", G_CALLBACK(on_destroy), &app);'
if text.count(install_old) != 1: raise SystemExit('Linux telemetry/globe installer seam drifted')
text = text.replace(install_old, install_new, 1)
for marker in ('#include "routervpn-product-onboarding-v6.inc"','#include "routervpn-home-summary-v1.inc"','#include "routervpn-profile-settings-v1.inc"','#include "routervpn-auto-requirements-v11.inc"','#include "routervpn-unified-shell-v8.inc"','#include "routervpn-telemetry-v9.inc"','#include "routervpn-speed-lab-v12.inc"','#include "routervpn-globe-v10.inc"','onboarding_read_step_v6(path)','gtk_assistant_set_current_page','refresh_home_summary_v6(app)','gtk_button_set_label(GTK_BUTTON(home_exit_v6), "Prove actual exit")','G_CALLBACK(on_home_exit_v6)','Edit profile settings','G_CALLBACK(on_profile_settings_v7)','router-vpn-advanced-settings-v7','static void build_ui_legacy_v5(App *app) {','linux_install_telemetry_v9(&app);','linux_install_speed_lab_v12(&app);','linux_install_globe_v10(&app);'):
    if marker not in text: raise SystemExit(f'missing Linux shipping marker: {marker}')
out_path.write_text(text, encoding='utf-8')
PY

grep -Fq 'if (working) {' "$SRC"
grep -Fq 'g_string_append_printf(detail, "%s • %s • %.2f ms\n"' "$SRC"
grep -Fq 'json_node_free(root);' "$SRC"; grep -Fq 'free(out.data);' "$SRC"; grep -Fq 'g_free(err);' "$SRC"
! grep -Fq 'working ? g_strdup_printf' "$SRC"
! grep -Fq 'if (root != NULL) json_node_free(root); free(out.data); g_free(err);' "$SRC"

gcc -O2 -Wall -Wextra -Werror -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
  -I"$BUILD_DIR" -I"$ROOT/client/linux" "$BUILD_SRC" -o "$OUT" \
  $(pkg-config --cflags --libs gtk+-3.0 libcurl json-glib-1.0) -lm
chmod 755 "$OUT"
file "$OUT"
LINKAGE=$(ldd "$OUT"); grep -q 'libgtk-3' <<<"$LINKAGE"; grep -q 'libjson-glib' <<<"$LINKAGE"
SYMBOLS=$(nm -a "$OUT" 2>/dev/null || true); DYNAMIC_SYMBOLS=$(nm -D "$OUT" 2>/dev/null || true)
if ! grep -q 'curl_easy_init' <<<"$SYMBOLS" && ! grep -q 'curl_easy_init' <<<"$DYNAMIC_SYMBOLS"; then echo 'Native Linux app does not contain/reference required libcurl API.' >&2; exit 1; fi
! grep -Eqi 'WebKit|WebView|chromium|electron|xdg-open|sensible-browser' "${SHIPPED[@]}"
for marker in 'gtk_window_new' 'gtk_notebook_new' 'http://127.0.0.1:8788' '/api/connect-logical' '/api/emergency-stop' '/api/session/events' '/api/profile/pair' '/api/profile/import' '/api/profile/delete' '/api/profile/latency' '/api/external-profile/import' '/api/external-profile/connect' '/api/nodes' 'latitude' 'longitude' 'Nodes & Map' 'Forwarding' 'Settings' 'Help' 'ensure_controller' 'shutdown_controller'; do grep -Fq "$marker" "${SHIPPED[@]}"; done
for marker in 'pairing' 'router-vpn-bundle.json' 'AUTO' 'WireGuard' 'AmneziaWG' 'DNS' 'LAN Off' 'MTU/Jumbo' 'kill-switch' 'Multihop' 'forwarding' 'permissions' 'Disconnect' 'private identity/path proof' 'Public exit' 'Diagnostics' 'Emergency stop' 'Setup Center Full Guide' 'Run Tutorial'; do grep -Fq "$marker" "$ONBOARDING_INC"; done
for marker in '/api/home-summary' '/api/home-summary/prove-exit' 'Actual public VPN exit' 'Node measured latency' 'LAN access' 'Kill switch' 'Effective MTU' 'Warnings'; do grep -Fq "$marker" "$HOME_INC"; done
for marker in '/api/profile/settings' 'Allow home LAN access' 'Always / strict' 'AmneziaWG' 'Auto measured' 'DAITA-like' 'Jumbo TUN' 'SOCKS5' 'startup' 'autoconnect'; do grep -Fiq "$marker" "$SETTINGS_INC"; done
for marker in '/api/profile/settings' 'Require encrypted AUTO candidates' 'Require obfuscation for AUTO candidates' 'Save requirements' 'Disconnect before saving'; do grep -Fq "$marker" "$AUTO_REQ_INC"; done
grep -Fq '/api/multihop/connect' "$SETTINGS_INC"
for marker in '#include "routervpn-product-onboarding-v6.inc"' '#include "routervpn-home-summary-v1.inc"' '#include "routervpn-profile-settings-v1.inc"' '#include "routervpn-auto-requirements-v11.inc"' '#include "routervpn-unified-shell-v8.inc"' '#include "routervpn-telemetry-v9.inc"' '#include "routervpn-speed-lab-v12.inc"' '#include "routervpn-globe-v10.inc"' 'gtk_assistant_set_current_page' 'onboarding_write_step_v6' 'refresh_home_summary_v6' 'Prove actual exit' 'G_CALLBACK(on_home_exit_v6)' 'Edit profile settings' 'G_CALLBACK(on_profile_settings_v7)' 'router-vpn-advanced-settings-v7' 'static void build_ui_legacy_v5(App *app) {' 'linux_install_telemetry_v9(&app);' 'linux_install_speed_lab_v12(&app);' 'linux_install_globe_v10(&app);'; do grep -Fq "$marker" "$BUILD_SRC"; done
for marker in 'build_ui_v5(App *app)' 'map-first' 'Connect' 'Disconnect' 'Kill switch' 'Multihop' 'Settings' 'Mode' 'DNS' 'SMART AUTO — recommended' 'AUTO — first proven path' 'New CUSTOM preset…' 'CUSTOM preset builder' '/api/strategy/auto' '/api/strategy/smart-auto' '/api/strategy/custom' '/api/connect-logical' '/api/mtu/retest' 'real stored coordinates'; do grep -Fq "$marker" "$UNIFIED_INC"; done
for marker in 'LinuxTelemetryV9' '⚡ Fastest' '/api/profile/fastest' '/api/connection/live-latency' '/api/multihop/live-latency' '/api/forwarding/master' 'Forward ON' 'Forward OFF' 'Performance' 'Throughput + Auto MTU'; do grep -Fq "$marker" "$TELEMETRY_INC"; done
for marker in 'LinuxSpeedLabV12' '/api/speed-lab/options' '/api/speed-lab/run' 'Current path' 'Temporary config' 'System direct' 'External exit / hop' 'Auto timing' 'Custom timing' 'download_loaded_ms' 'upload_loaded_ms' 'bufferbloat' 'linux_install_speed_lab_v12'; do grep -Fq "$marker" "$SPEED_LAB_INC"; done
for marker in 'LinuxGlobeV10' 'ROUTER VPN GLOBE' 'linux_globe_draw_v10' 'linux_globe_click_v10' 'routervpn_flat_map_v9' 'entry blue' 'exit orange' 'external pink' 'animated packet' 'PATH %.1f ms' 'device location is not fabricated' '/api/multihop/live-latency'; do grep -Fq "$marker" "$GLOBE_INC"; done
grep -Fq 'Diagnostics' "$SRC"; grep -Fq '/api/session/events?after=0' "$SRC"; grep -Fq 'apply_action_sensitivity_v5' "$SRC"; grep -Fq 'gtk_widget_set_sensitive' "$SRC"; grep -Fq 'truthful-empty-state-actions' "$SRC"; grep -Fq 'gtk_window_set_default_size(GTK_WINDOW(app->window), 960, 680);' "$SRC"
grep -Fq '/api/mtu/retest' "$SRC"; grep -Fq 'Retest MTU' "$SRC"; grep -Fq '130000' "$SRC"; grep -Fq 'router-vpn-advanced-mtu-v5' "$SRC"
"$OUT" --self-test

echo "Built native Linux GTK Router VPN product with map-first unified shell, animated VPN globe, fastest-node connect, live path/multihop telemetry, native Speed Lab with loaded latency, real forwarding master, truthful Home state, editable profile settings and resumable onboarding at $OUT"

# Session-mutation hardening is applied only to temporary build copies; source baselines remain reviewable.
# apply-session-mutation.py baseline-hash checks fail closed before compilation on source drift.
