/* Execute the shipping GTK widgets and callbacks; the controller transaction
 * itself has Go ownership/persistence tests. No network success is fabricated. */
#include <gtk/gtk.h>
#include <json-glib/json-glib.h>
#include <stdlib.h>
#include <string.h>
typedef struct { GtkWidget *window; const char *selected; } App;
typedef struct { char *data; size_t size; } Buffer;
static gboolean idle = TRUE, reject_save = FALSE, replace_during_read = FALSE;
static guint checks = 0, posts = 0, gets = 0, diagnostics = 0;
static char *last_body = NULL, *get_body = NULL;
static App *active_app = NULL;
static const char *active_router_id(App *app) { return app->selected; }
static gboolean routervpn_mutation_busy(App *app) { (void)app; return !idle; }
static gboolean routervpn_require_mutation_idle(App *app, const char *reason) { (void)app; (void)reason; return idle; }
static void append_diag(App *app, const char *message) { (void)app; (void)message; diagnostics++; }
static JsonNode *parse_json(const char *raw) {
    JsonParser *parser = json_parser_new();
    JsonNode *node = json_parser_load_from_data(parser, raw, -1, NULL) ? json_node_copy(json_parser_get_root(parser)) : NULL;
    g_object_unref(parser); return node;
}
static void check(gboolean value, const char *message) {
    checks++;
    if (!value) { g_printerr("GTK device settings check failed: %s\n", message); exit(1); }
}
static gboolean api_request(const char *path, const char *method, const char *body, long timeout, Buffer *out, char **error) {
    check(g_strcmp0(path, "/api/profile/device") == 0, "wrong controller route");
    check(timeout > 0 && timeout <= 8000, "unbounded request");
    if (g_strcmp0(method, "GET") == 0) {
        gets++; out->data = g_strdup(get_body);
        if (replace_during_read) active_app->selected = "replacement";
        return TRUE;
    }
    check(g_strcmp0(method, "POST") == 0, "unexpected controller method");
    posts++; g_free(last_body); last_body = g_strdup(body);
    if (reject_save) { *error = g_strdup("Captured source changed; settings were not saved."); return FALSE; }
    out->data = g_strdup("{\"ok\":true}"); return TRUE;
}
#include "routervpn-device-settings-v1.inc"

static JsonNode *fixture(void) {
    return parse_json("{\"profile_id\":\"exit-\\\"quoted\\\"\",\"profile_token\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\","
        "\"node_kind\":\"external\",\"protocol\":\"wireguard\",\"home_lan_access\":false,\"kill_switch_policy\":\"always\","
        "\"ipv6_mode\":\"on\",\"mtu_policy\":\"auto\",\"manual_mtu\":0,\"startup_mode\":\"auto\",\"auto_connect\":false,"
        "\"effective_mtu\":1392,\"mtu_source\":\"past path\",\"device_policy_supported\":true,\"device_policy_reason\":\"\","
        "\"password\":\"must-not-copy\",\"entry_id\":\"independent-entry\",\"dns_resolver\":\"preserve\"}");
}
static gboolean modal_save(gpointer data) {
    (void)data;
    GList *windows = gtk_window_list_toplevels();
    for (GList *p = windows; p != NULL; p = p->next) {
        LinuxDeviceSettingsV1 *s = g_object_get_data(G_OBJECT(p->data), "router-vpn-device-settings-v1");
        if (s == NULL) continue;
        check(g_strcmp0(s->profile, active_app->selected) == 0, "modal replaced displayed owner");
        gtk_dialog_response(GTK_DIALOG(s->dialog), GTK_RESPONSE_OK);
        g_list_free(windows); return G_SOURCE_REMOVE;
    }
    g_list_free(windows); check(FALSE, "actual modal never opened"); return G_SOURCE_REMOVE;
}
int main(int argc, char **argv) {
    gtk_init(&argc, &argv);
    App app = {gtk_window_new(GTK_WINDOW_TOPLEVEL), "exit-\"quoted\""}; active_app = &app;
    JsonNode *tor_root = fixture(); JsonObject *tor_capture = json_node_get_object(tor_root);
    const char *tor_note = "Tor Auto uses a 1280-byte virtual interface. Retest is not yet implemented.";
    json_object_set_string_member(tor_capture, "protocol", "tor-bridge");
    json_object_set_string_member(tor_capture, "note", tor_note);
    LinuxDeviceSettingsV1 tor_settings = {0};
    check(linux_device_build_v1(&tor_settings, &app, tor_capture, app.selected), "supported Tor device panel rejected");
    char *auto_label = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(tor_settings.mtu));
    check(g_strcmp0(auto_label, "Auto") == 0, "Tor Auto claimed a measured path"); g_free(auto_label);
    check(g_strcmp0(gtk_label_get_text(GTK_LABEL(tor_settings.message)), tor_note) == 0, "captured Tor capability note was replaced");
    linux_device_clear_v1(&tor_settings); json_node_free(tor_root);
    JsonNode *root = fixture(); JsonObject *captured = json_node_get_object(root);
    LinuxDeviceSettingsV1 s = {0};
    check(linux_device_build_v1(&s, &app, captured, app.selected), "valid device panel rejected");
    check(!gtk_widget_get_sensitive(s.manual), "Auto exposed fixed input");
    for (guint k = 0; k < 3; k++) for (guint v = 0; v < 3; v++) for (guint m = 0; m < 3; m++) {
        gboolean lan = (k + v + m) % 2, automatic = (k + m) % 2 && (k + v) % 3 != 2;
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(s.lan), lan);
        gtk_combo_box_set_active_id(GTK_COMBO_BOX(s.kill), linux_device_kill_ids_v1[k]);
        gtk_combo_box_set_active_id(GTK_COMBO_BOX(s.ipv6), linux_device_ipv6_ids_v1[v]);
        gtk_combo_box_set_active_id(GTK_COMBO_BOX(s.mtu), linux_device_mtu_ids_v1[m]);
        gtk_entry_set_text(GTK_ENTRY(s.manual), m == 1 ? "1420" : "stale-invalid-fixed-input");
        gtk_combo_box_set_active_id(GTK_COMBO_BOX(s.startup), linux_device_startup_ids_v1[(k + v) % 3]);
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(s.automatic), automatic);
        check(gtk_widget_get_sensitive(s.manual) == (m == 1), "MTU input sensitivity mismatch");
        check(linux_device_save_v1(&s), "valid controls did not save");
        JsonNode *saved = parse_json(last_body); check(saved != NULL, "save did not encode JSON");
        JsonObject *body = json_node_get_object(saved);
        gboolean changed_startup = (k + v) % 3 != 0 || automatic;
        check(json_object_get_size(body) == (changed_startup ? 9 : 7), "copied private/unrelated settings or rewrote unchanged startup");
        check(g_strcmp0(linux_device_string_v1(body, "profile_id"), app.selected) == 0 &&
            g_strcmp0(linux_device_string_v1(body, "profile_token"), s.token) == 0, "lost captured identity");
        check(json_object_get_boolean_member(body, "home_lan_access") == lan, "lost LAN choice");
        check(g_strcmp0(linux_device_string_v1(body, "kill_switch_policy"), linux_device_kill_ids_v1[k]) == 0, "lost protection choice");
        check(g_strcmp0(linux_device_string_v1(body, "ipv6_mode"), linux_device_ipv6_ids_v1[v]) == 0, "lost IPv6 choice");
        check(g_strcmp0(linux_device_string_v1(body, "mtu_policy"), linux_device_mtu_ids_v1[m]) == 0, "lost MTU choice");
        check(json_object_get_int_member(body, "manual_mtu") == (m == 1 ? 1420 : 0), "stale fixed MTU leaked into auto/default");
        check(!changed_startup || (g_strcmp0(linux_device_string_v1(body, "startup_mode"), linux_device_startup_ids_v1[(k + v) % 3]) == 0 &&
            json_object_get_boolean_member(body, "auto_connect") == automatic), "edited startup not in atomic save");
        check(gtk_widget_get_sensitive(s.automatic) == ((k + v) % 3 != 2), "Manual allowed auto-connect");
        json_node_free(saved);
    }
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(s.mtu), "manual");
    const char *bad[] = {"", "1279", "9001", "1420junk", "1420.0", "+1420", " 1420", "9999999999999999", "0x590"};
    for (guint i = 0; i < G_N_ELEMENTS(bad); i++) {
        guint before = posts; gtk_entry_set_text(GTK_ENTRY(s.manual), bad[i]);
        check(!linux_device_save_v1(&s) && posts == before, "invalid fixed MTU was saved or substituted");
    }
    gtk_entry_set_text(GTK_ENTRY(s.manual), "1280"); check(linux_device_save_v1(&s), "valid lower MTU rejected");
    gtk_entry_set_text(GTK_ENTRY(s.manual), "9000"); check(linux_device_save_v1(&s), "valid interface MTU rejected before transport check");
    guint before = posts; app.selected = "replacement";
    check(!linux_device_save_v1(&s) && posts == before, "replaced selected node was saved"); app.selected = s.profile;
    idle = FALSE; check(!linux_device_save_v1(&s) && posts == before, "new connection did not revoke Save"); idle = TRUE;
    s.supported = FALSE; check(!linux_device_save_v1(&s) && posts == before, "unsupported controls saved"); s.supported = TRUE;
    reject_save = TRUE; check(!linux_device_save_v1(&s), "controller refusal was reported as saved");
    check(strstr(gtk_label_get_text(GTK_LABEL(s.message)), "not saved") != NULL, "controller refusal missing from dialog"); reject_save = FALSE;
    app.selected = "exit-\"quoted\"";
    if (argc == 3 && g_strcmp0(argv[1], "--screenshot") == 0) {
        linux_device_message_v1(&s, "Save applies these device and startup choices together. DNS and hop settings are retained.");
        while (gtk_events_pending()) gtk_main_iteration();
        GdkWindow *window = gtk_widget_get_window(s.dialog); int w = gdk_window_get_width(window), h = gdk_window_get_height(window);
        GdkPixbuf *pixels = gdk_pixbuf_get_from_window(window, 0, 0, w, h);
        check(pixels != NULL && gdk_pixbuf_save(pixels, argv[2], "png", NULL, NULL), "screenshot failed"); g_object_unref(pixels);
    }
    linux_device_clear_v1(&s);
    const char *bad_fields[] = {"profile_token", "home_lan_access", "auto_connect", "device_policy_supported", "manual_mtu", "kill_switch_policy", "ipv6_mode", "mtu_policy", "startup_mode"};
    for (guint i = 0; i < G_N_ELEMENTS(bad_fields); i++) {
        JsonNode *wrong = fixture(); JsonObject *o = json_node_get_object(wrong);
        json_object_set_string_member(o, bad_fields[i], "invalid");
        check(!linux_device_build_v1(&s, &app, o, app.selected), "malformed captured policy became editable"); json_node_free(wrong);
    }
    check(!linux_device_build_v1(&s, &app, captured, "wrong-opening-node"), "GET adopted another displayed node");
    json_object_set_string_member(captured, "startup_mode", "smart-auto");
    check(linux_device_build_v1(&s, &app, captured, app.selected), "legacy SMART AUTO not displayed");
    char *unchanged = linux_device_payload_v1(&s); JsonNode *unchanged_root = parse_json(unchanged);
    check(json_object_get_size(json_node_get_object(unchanged_root)) == 7, "unchanged SMART AUTO rewritten by device Save");
    json_node_free(unchanged_root); g_free(unchanged); linux_device_clear_v1(&s);
    json_object_set_string_member(captured, "startup_mode", "auto");
    idle = FALSE; check(linux_device_build_v1(&s, &app, captured, app.selected), "connected settings could not be inspected");
    check(!gtk_widget_get_sensitive(s.kill) && !gtk_widget_get_sensitive(s.lan) &&
        !gtk_widget_get_sensitive(gtk_dialog_get_widget_for_response(GTK_DIALOG(s.dialog), GTK_RESPONSE_OK)), "connected controls remained editable");
    before = posts; check(!linux_device_save_v1(&s) && posts == before, "initially busy form saved"); linux_device_clear_v1(&s); idle = TRUE;
    json_object_set_boolean_member(captured, "device_policy_supported", FALSE);
    json_object_set_string_member(captured, "device_policy_reason", "Captured graph requires a native policy adapter.");
    check(linux_device_build_v1(&s, &app, captured, app.selected), "unsupported policy not inspectable");
    check(!gtk_widget_get_sensitive(s.ipv6) && !gtk_widget_get_sensitive(s.startup) &&
        strstr(gtk_label_get_text(GTK_LABEL(s.message)), "native policy adapter") != NULL, "support boundary was hidden");
    linux_device_clear_v1(&s); json_object_set_boolean_member(captured, "device_policy_supported", TRUE);
    JsonGenerator *gen = json_generator_new(); json_generator_set_root(gen, root); get_body = json_generator_to_data(gen, NULL); g_object_unref(gen);
    replace_during_read = TRUE; before = posts; guint before_get = gets;
    check(linux_device_settings_open_v1(&app) && posts == before && gets == before_get + 1, "GET completion retargeted the opening click");
    replace_during_read = FALSE; app.selected = "exit-\"quoted\""; before = posts;
    g_idle_add(modal_save, NULL);
    check(linux_device_settings_open_v1(&app) && posts == before + 1, "actual modal response did not reach atomic Save");
    check(linux_device_build_v1(&s, &app, captured, app.selected), "parent-close fixture failed");
    before = posts; gtk_widget_destroy(app.window); linux_device_clear_v1(&s);
    check(posts == before, "parent close saved settings");
    json_node_free(root); g_free(last_body); g_free(get_body);
    g_print("GTK device settings: %u checks, %u actual atomic Save callbacks; captured node, policy and close behavior passed\n", checks, posts);
    return 0;
}
