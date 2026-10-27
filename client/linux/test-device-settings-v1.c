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
static gboolean reply_jumbo = FALSE, reply_jumbo_supported = FALSE;
static const char *reply_fault = NULL;
static JsonNode *reply_original = NULL;
static App *active_app = NULL;
static JsonNode *fixture(void);
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
    JsonNode *saved = fixture(), *sent = parse_json(body);
    JsonObject *result = json_node_get_object(saved), *request = json_node_get_object(sent);
    if (reply_original != NULL) {
        // Copy members into an independent response object. json_node_copy on
        // an object retains the same JsonObject and would mutate the capture.
        JsonObject *original = json_node_get_object(reply_original);
        GList *original_members = json_object_get_members(original);
        for (GList *p = original_members; p != NULL; p = p->next)
            json_object_set_member(result, p->data, json_node_copy(json_object_get_member(original, p->data)));
        g_list_free(original_members);
    }
    json_object_set_boolean_member(result, "jumbo_tun", reply_jumbo);
    json_object_set_boolean_member(result, "jumbo_tun_supported", reply_jumbo_supported);
    GList *members = json_object_get_members(request);
    for (GList *p = members; p != NULL; p = p->next)
        json_object_set_member(result, p->data, json_node_copy(json_object_get_member(request, p->data)));
    g_list_free(members);
    json_object_set_string_member(result, "profile_token", "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
    if (g_strcmp0(reply_fault, "jumbo") == 0) json_object_set_boolean_member(result, "jumbo_tun", FALSE);
    if (g_strcmp0(reply_fault, "capability") == 0) json_object_set_boolean_member(result, "jumbo_tun_supported", FALSE);
    if (g_strcmp0(reply_fault, "profile") == 0) json_object_set_string_member(result, "profile_id", "replacement");
    if (g_strcmp0(reply_fault, "startup") == 0) json_object_set_string_member(result, "startup_mode", "manual");
    if (g_strcmp0(reply_fault, "mtu") == 0) json_object_set_int_member(result, "manual_mtu", 8999);
    if (g_strcmp0(reply_fault, "cover-flag") == 0) json_object_set_boolean_member(result, "daita_enabled", FALSE);
    if (g_strcmp0(reply_fault, "cover-rate") == 0) json_object_set_int_member(result, "daita_rate_kbps", 192);
    if (g_strcmp0(reply_fault, "cover-capability") == 0) json_object_set_boolean_member(result, "tor_cover_supported", FALSE);
    if (g_strcmp0(reply_fault, "cover-partial") == 0) json_object_remove_member(result, "daita_rate_kbps");
    if (g_strcmp0(reply_fault, "cover-protocol") == 0) json_object_set_string_member(result, "protocol", "socks5");
    JsonGenerator *generator = json_generator_new(); json_generator_set_root(generator, saved);
    out->data = json_generator_to_data(generator, NULL);
    g_object_unref(generator); json_node_free(saved); json_node_free(sent); return TRUE;
}
#include "routervpn-device-settings-v1.inc"

static JsonNode *fixture(void) {
    return parse_json("{\"profile_id\":\"exit-\\\"quoted\\\"\",\"profile_token\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\","
        "\"node_kind\":\"external\",\"protocol\":\"wireguard\",\"home_lan_access\":false,\"kill_switch_policy\":\"always\","
        "\"ipv6_mode\":\"on\",\"mtu_policy\":\"auto\",\"manual_mtu\":0,\"startup_mode\":\"auto\",\"auto_connect\":false,"
        "\"effective_mtu\":1392,\"mtu_source\":\"past path\",\"device_policy_supported\":true,\"device_policy_reason\":\"\","
        "\"jumbo_tun\":false,\"jumbo_tun_supported\":false,"
        "\"daita_enabled\":false,\"daita_rate_kbps\":0,\"tor_cover_supported\":false,\"tor_cover_note\":\"Outgoing Tor cells only; Connect requires a fresh server receipt.\","
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
    for (guint initial = 0; initial < 2; initial++) for (guint policy = 0; policy < 3; policy++) {
        JsonNode *jumbo_root = fixture(); JsonObject *jumbo_capture = json_node_get_object(jumbo_root);
        json_object_set_string_member(jumbo_capture, "protocol", "tor-bridge");
        json_object_set_boolean_member(jumbo_capture, "jumbo_tun", initial);
        json_object_set_boolean_member(jumbo_capture, "jumbo_tun_supported", TRUE);
        json_object_set_string_member(jumbo_capture, "mtu_policy", linux_device_mtu_ids_v1[policy]);
        json_object_set_int_member(jumbo_capture, "manual_mtu", policy == 1 ? 9000 : 0);
        reply_jumbo = initial; reply_jumbo_supported = TRUE;
        LinuxDeviceSettingsV1 jumbo_settings = {0};
        check(linux_device_build_v1(&jumbo_settings, &app, jumbo_capture, app.selected), "valid Tor Jumbo form rejected");
        check(gtk_widget_get_sensitive(jumbo_settings.jumbo) &&
            gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(jumbo_settings.jumbo)) == (gboolean)initial &&
            g_strcmp0(gtk_button_get_label(GTK_BUTTON(jumbo_settings.jumbo)), "Jumbo virtual interface (9000)") == 0, "Jumbo control lost captured support/value");
        for (guint selected = 0; selected < 2; selected++) {
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(jumbo_settings.jumbo), selected);
            check(linux_device_save_v1(&jumbo_settings), "actual Jumbo checkbox did not save");
            JsonNode *posted = parse_json(last_body); JsonObject *payload = json_node_get_object(posted);
            check(json_object_has_member(payload, "jumbo_tun") == (selected != initial), "Jumbo payload lost explicit-edit ownership");
            if (selected != initial) check(json_object_get_boolean_member(payload, "jumbo_tun") == (gboolean)selected, "Jumbo Boolean was replaced");
            check(g_strcmp0(linux_device_string_v1(payload, "mtu_policy"), linux_device_mtu_ids_v1[policy]) == 0 &&
                json_object_get_int_member(payload, "manual_mtu") == (policy == 1 ? 9000 : 0), "Jumbo silently changed saved MTU policy");
            json_node_free(posted);
        }
        if (!initial && policy == 0) {
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(jumbo_settings.jumbo), TRUE);
            const char *faults[] = {"jumbo", "capability", "profile", "startup", "mtu"};
            for (guint f = 0; f < G_N_ELEMENTS(faults); f++) {
                reply_fault = faults[f]; check(!linux_device_save_v1(&jumbo_settings), "unconfirmed Jumbo/device policy announced as saved");
            }
            reply_fault = NULL;
            gtk_combo_box_set_active_id(GTK_COMBO_BOX(jumbo_settings.mtu), "manual"); gtk_entry_set_text(GTK_ENTRY(jumbo_settings.manual), "1400");
            guint before = posts;
            check(!linux_device_save_v1(&jumbo_settings) && posts == before, "conflicting Fixed MTU was silently rewritten for Jumbo");
        }
        linux_device_clear_v1(&jumbo_settings);
        idle = FALSE;
        check(linux_device_build_v1(&jumbo_settings, &app, jumbo_capture, app.selected), "busy Jumbo cannot be inspected");
        check(!gtk_widget_get_sensitive(jumbo_settings.jumbo), "busy Jumbo control remained editable");
        linux_device_clear_v1(&jumbo_settings); idle = TRUE;
        json_node_free(jumbo_root);
    }
    reply_jumbo = FALSE; reply_jumbo_supported = FALSE;
    const char *cover_protocols[] = {"tor", "tor-bridge"};
    const gint64 cover_rates[] = {0, 32, 64, 192};
    for (guint p = 0; p < G_N_ELEMENTS(cover_protocols); p++) for (guint initial = 0; initial < 2; initial++) {
        for (guint initial_rate = 0; initial_rate < G_N_ELEMENTS(cover_rates); initial_rate++) {
            JsonNode *cover_root = fixture(); JsonObject *capture = json_node_get_object(cover_root);
            json_object_set_string_member(capture, "protocol", cover_protocols[p]);
            json_object_set_boolean_member(capture, "daita_enabled", initial);
            json_object_set_int_member(capture, "daita_rate_kbps", cover_rates[initial_rate]);
            json_object_set_boolean_member(capture, "tor_cover_supported", TRUE);
            reply_original = cover_root;
            LinuxDeviceSettingsV1 cover_settings = {0};
            check(linux_device_build_v1(&cover_settings, &app, capture, app.selected), "valid captured Tor cover form rejected");
            char *rate_text = g_strdup_printf("%" G_GINT64_FORMAT, cover_rates[initial_rate]);
            check(gtk_widget_get_sensitive(cover_settings.cover) && gtk_widget_get_sensitive(cover_settings.cover_rate) &&
                gtk_widget_get_visible(gtk_widget_get_parent(cover_settings.cover)) &&
                gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(cover_settings.cover)) == (gboolean)initial &&
                g_strcmp0(gtk_entry_get_text(GTK_ENTRY(cover_settings.cover_rate)), rate_text) == 0,
                "cover controls lost captured capability, flag or dormant budget"); g_free(rate_text);
            check(g_strcmp0(gtk_button_get_label(GTK_BUTTON(cover_settings.cover)), "Outgoing Tor cover traffic") == 0,
                "Tor cover was mislabeled as bidirectional DAITA");
            for (guint selected = 0; selected < 2; selected++) for (guint r = 0; r < G_N_ELEMENTS(cover_rates); r++) {
                gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cover_settings.cover), selected);
                rate_text = g_strdup_printf("%" G_GINT64_FORMAT, cover_rates[r]);
                gtk_entry_set_text(GTK_ENTRY(cover_settings.cover_rate), rate_text); g_free(rate_text);
                gboolean cover_saved = linux_device_save_v1(&cover_settings);
                if (!cover_saved) g_printerr("Cover %s initial=%u/%" G_GINT64_FORMAT " selected=%u/%" G_GINT64_FORMAT ": %s; request=%s\n",
                    cover_protocols[p], initial, cover_rates[initial_rate], selected, cover_rates[r],
                    gtk_label_get_text(GTK_LABEL(cover_settings.message)), last_body != NULL ? last_body : "none");
                check(cover_saved, "real cover controls did not save an exact transaction");
                JsonNode *sent = parse_json(last_body); JsonObject *payload = json_node_get_object(sent);
                gboolean changed = selected != initial || r != initial_rate;
                check(json_object_get_size(payload) == (changed ? 9 : 7) &&
                    json_object_has_member(payload, "daita_enabled") == changed && json_object_has_member(payload, "daita_rate_kbps") == changed,
                    "cover pair lost explicit edit ownership");
                if (changed) check(json_object_get_boolean_member(payload, "daita_enabled") == (gboolean)selected &&
                    json_object_get_int_member(payload, "daita_rate_kbps") == cover_rates[r], "cover flag or exact dormant budget was replaced");
                check(g_strcmp0(linux_device_string_v1(payload, "profile_token"), cover_settings.token) == 0,
                    "cover edit replaced captured entry ownership");
                json_node_free(sent);
            }
            linux_device_clear_v1(&cover_settings); reply_original = NULL; json_node_free(cover_root);
        }
    }
    JsonNode *cover_root = fixture(); JsonObject *cover_capture = json_node_get_object(cover_root);
    json_object_set_string_member(cover_capture, "protocol", "tor");
    json_object_set_boolean_member(cover_capture, "tor_cover_supported", TRUE);
    json_object_set_int_member(cover_capture, "daita_rate_kbps", 64);
    reply_original = cover_root;
    LinuxDeviceSettingsV1 cover_settings = {0};
    check(linux_device_build_v1(&cover_settings, &app, cover_capture, app.selected), "cover rejection fixture rejected");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cover_settings.cover), TRUE);
    const char *bad_rates[] = {"", "31", "193", "-1", "+64", "64.0", "6.4e1", "0x40", "64 "};
    for (guint r = 0; r < G_N_ELEMENTS(bad_rates); r++) {
        guint before = posts; gtk_entry_set_text(GTK_ENTRY(cover_settings.cover_rate), bad_rates[r]);
        check(!linux_device_save_v1(&cover_settings) && posts == before, "invalid cover budget reached persistence");
    }
    gtk_entry_set_text(GTK_ENTRY(cover_settings.cover_rate), "64");
    const char *cover_faults[] = {"cover-flag", "cover-rate", "cover-capability", "cover-partial", "cover-protocol"};
    for (guint f = 0; f < G_N_ELEMENTS(cover_faults); f++) {
        reply_fault = cover_faults[f]; check(!linux_device_save_v1(&cover_settings), "unconfirmed cover was announced as saved");
    }
    reply_fault = "cover-rate"; gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cover_settings.cover), FALSE);
    check(!linux_device_save_v1(&cover_settings), "omitted cover budget changed without confirmation"); reply_fault = NULL;
    linux_device_clear_v1(&cover_settings);
    json_object_set_boolean_member(cover_capture, "tor_cover_supported", FALSE);
    check(linux_device_build_v1(&cover_settings, &app, cover_capture, app.selected), "unsupported cover cannot be inspected");
    check(!gtk_widget_get_sensitive(cover_settings.cover) && !gtk_widget_get_sensitive(cover_settings.cover_rate), "unsupported cover controls became editable");
    check(linux_device_save_v1(&cover_settings), "unchanged unsupported cover pair was not retained");
    guint cover_before = posts;
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cover_settings.cover), TRUE);
    check(!linux_device_save_v1(&cover_settings) && posts == cover_before, "unsupported cover traffic changed");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cover_settings.cover), FALSE); gtk_entry_set_text(GTK_ENTRY(cover_settings.cover_rate), "32");
    check(!linux_device_save_v1(&cover_settings) && posts == cover_before, "unsupported dormant cover budget changed");
    linux_device_clear_v1(&cover_settings);
    json_object_set_boolean_member(cover_capture, "daita_enabled", TRUE);
    json_object_set_boolean_member(cover_capture, "device_policy_supported", FALSE);
    check(linux_device_build_v1(&cover_settings, &app, cover_capture, app.selected), "unavailable saved cover state cannot be inspected");
    check(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(cover_settings.cover)) &&
        g_strcmp0(gtk_entry_get_text(GTK_ENTRY(cover_settings.cover_rate)), "64") == 0 && !gtk_widget_get_sensitive(cover_settings.cover),
        "unavailable saved cover state was silently reset");
    linux_device_clear_v1(&cover_settings);
    json_object_set_boolean_member(cover_capture, "device_policy_supported", TRUE);
    json_object_set_boolean_member(cover_capture, "tor_cover_supported", TRUE); idle = FALSE;
    check(linux_device_build_v1(&cover_settings, &app, cover_capture, app.selected), "busy saved cover state cannot be inspected");
    check(!gtk_widget_get_sensitive(cover_settings.cover) && !gtk_widget_get_sensitive(cover_settings.cover_rate), "busy cover controls became editable");
    linux_device_clear_v1(&cover_settings); idle = TRUE;
    reply_original = NULL; json_node_free(cover_root);
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
    check(!gtk_widget_get_sensitive(s.jumbo), "unsupported Jumbo checkbox enabled");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(s.jumbo), TRUE);
    guint unsupported_before = posts;
    check(!linux_device_save_v1(&s) && posts == unsupported_before, "unsupported Jumbo was posted");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(s.jumbo), FALSE);
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
    const char *bad_fields[] = {"profile_token", "home_lan_access", "auto_connect", "device_policy_supported", "manual_mtu", "kill_switch_policy", "ipv6_mode", "mtu_policy", "startup_mode", "jumbo_tun", "jumbo_tun_supported", "daita_enabled", "daita_rate_kbps", "tor_cover_supported"};
    for (guint i = 0; i < G_N_ELEMENTS(bad_fields); i++) {
        JsonNode *wrong = fixture(); JsonObject *o = json_node_get_object(wrong);
        json_object_set_string_member(o, bad_fields[i], "invalid");
        check(!linux_device_build_v1(&s, &app, o, app.selected), "malformed captured policy became editable"); json_node_free(wrong);
    }
    const char *cover_fields[] = {"daita_enabled", "daita_rate_kbps", "tor_cover_supported"};
    for (guint field = 0; field < G_N_ELEMENTS(cover_fields); field++) {
        JsonNode *partial = fixture(); JsonObject *o = json_node_get_object(partial);
        json_object_remove_member(o, cover_fields[field]);
        check(!linux_device_build_v1(&s, &app, o, app.selected), "partial cover capture enabled a form");
        json_node_free(partial);
    }
    JsonNode *legacy_cover = fixture(); JsonObject *legacy_cover_capture = json_node_get_object(legacy_cover);
    for (guint field = 0; field < G_N_ELEMENTS(cover_fields); field++) json_object_remove_member(legacy_cover_capture, cover_fields[field]);
    check(linux_device_build_v1(&s, &app, legacy_cover_capture, app.selected) && !gtk_widget_get_sensitive(s.cover), "legacy capture invented cover support");
    char *legacy_cover_body = linux_device_payload_v1(&s); JsonNode *legacy_cover_posted = parse_json(legacy_cover_body);
    check(!json_object_has_member(json_node_get_object(legacy_cover_posted), "daita_enabled"), "legacy capture invented cover write");
    g_free(legacy_cover_body); json_node_free(legacy_cover_posted); linux_device_clear_v1(&s); json_node_free(legacy_cover);
    for (guint missing = 0; missing < 2; missing++) {
        JsonNode *partial = fixture(); JsonObject *o = json_node_get_object(partial);
        json_object_remove_member(o, missing == 0 ? "jumbo_tun" : "jumbo_tun_supported");
        check(!linux_device_build_v1(&s, &app, o, app.selected), "partial Jumbo capability enabled a form"); json_node_free(partial);
    }
    JsonNode *legacy = fixture(); JsonObject *legacy_capture = json_node_get_object(legacy);
    json_object_remove_member(legacy_capture, "jumbo_tun"); json_object_remove_member(legacy_capture, "jumbo_tun_supported");
    check(linux_device_build_v1(&s, &app, legacy_capture, app.selected) && !gtk_widget_get_sensitive(s.jumbo), "missing Jumbo capability invented support");
    char *legacy_body = linux_device_payload_v1(&s); JsonNode *legacy_posted = parse_json(legacy_body);
    check(!json_object_has_member(json_node_get_object(legacy_posted), "jumbo_tun"), "missing Jumbo capability invented a write");
    g_free(legacy_body); json_node_free(legacy_posted); linux_device_clear_v1(&s); json_node_free(legacy);
    check(!linux_device_build_v1(&s, &app, captured, "wrong-opening-node"), "GET adopted another displayed node");
    json_object_set_string_member(captured, "startup_mode", "smart-auto");
    check(linux_device_build_v1(&s, &app, captured, app.selected), "legacy SMART AUTO not displayed");
    char *unchanged = linux_device_payload_v1(&s); JsonNode *unchanged_root = parse_json(unchanged);
    check(json_object_get_size(json_node_get_object(unchanged_root)) == 7, "unchanged SMART AUTO rewritten by device Save");
    json_node_free(unchanged_root); g_free(unchanged);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(s.automatic), TRUE);
    check(linux_device_save_v1(&s), "auto-connect-only saved alias failed");
    JsonNode *alias = parse_json(last_body);
    check(g_strcmp0(linux_device_string_v1(json_node_get_object(alias), "startup_mode"), "smart-auto") == 0, "auto-connect-only edit replaced original startup alias");
    json_node_free(alias); linux_device_clear_v1(&s);
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
