/* Drive the shipping GTK dialog, Update toggle and Save/Cancel responses.
 * Controller replies here are explicit UI doubles. The emitted callback bodies
 * are independently replayed through the actual Go importer and source guards. */
#include <gtk/gtk.h>
#include <json-glib/json-glib.h>
#include <glib/gstdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { GtkWidget *window; const char *selected; } App;
typedef struct { char *data; size_t size; } Buffer;
static guint checks, posts, node_reads, status_reads, refreshes, diagnostics, dialogs;
static gboolean idle = TRUE, unavailable_nodes = FALSE, refuse_post = FALSE;
static char *last_body;
static JsonNode *source_catalog, *source_always, *source_capabilities, *source_lines, *source_fixed_sets, *current_catalog, *capabilities;
static const char *directory, *source_prefix;
static App *active_app;

static void check(gboolean okay, const char *message) {
    checks++;
    if (!okay) { g_printerr("GTK Tor update check failed: %s\n", message); exit(1); }
}
static const char *active_router_id(App *app) { return app->selected; }
static void append_diag(App *app, const char *text) { (void)app; (void)text; diagnostics++; }
static void refresh_all(App *app) { (void)app; refreshes++; }
static JsonNode *parse_json(const char *raw) {
    JsonParser *parser = json_parser_new();
    JsonNode *node = raw != NULL && json_parser_load_from_data(parser, raw, -1, NULL) ? json_node_copy(json_parser_get_root(parser)) : NULL;
    g_object_unref(parser); return node;
}
static const char *obj_string(JsonObject *object, const char *key) {
    JsonNode *node = object != NULL && json_object_has_member(object, key) ? json_object_get_member(object, key) : NULL;
    return node != NULL && JSON_NODE_HOLDS_VALUE(node) && json_node_get_value_type(node) == G_TYPE_STRING ? json_node_get_string(node) : "";
}
static char *encoded(JsonNode *node) {
    JsonGenerator *generator = json_generator_new(); json_generator_set_root(generator, node);
    char *raw = json_generator_to_data(generator, NULL); g_object_unref(generator); return raw;
}
static gboolean api_request(const char *path, const char *method, const char *body, long timeout, Buffer *out, char **error) {
    check(timeout > 0 && timeout <= 25000, "controller request lost its bounded timeout");
    if (g_strcmp0(path, "/api/status") == 0) {
        check(g_strcmp0(method, "GET") == 0 && body == NULL, "status was not a read"); status_reads++;
        out->data = g_strdup(idle ? "{\"connected\":false,\"phase\":\"off\"}" : "{\"connected\":true,\"phase\":\"connected\"}");
        return TRUE;
    }
    if (g_strcmp0(path, "/api/tor-bridge/capabilities") == 0) {
        check(g_strcmp0(method, "GET") == 0 && body == NULL, "capabilities were not a read");
        out->data = encoded(capabilities); return TRUE;
    }
    if (g_strcmp0(path, "/api/nodes") == 0) {
        check(g_strcmp0(method, "GET") == 0 && body == NULL, "source catalog was not a read"); node_reads++;
        if (unavailable_nodes) { *error = g_strdup("test controller catalog unavailable"); return FALSE; }
        out->data = encoded(current_catalog); return TRUE;
    }
    check(g_strcmp0(path, "/api/tor-bridge/import") == 0 && g_strcmp0(method, "POST") == 0, "editor used a different mutation route");
    posts++; g_free(last_body); last_body = g_strdup(body);
    if (refuse_post) { *error = g_strdup("captured source changed at commit; nothing was saved"); return FALSE; }
    out->data = g_strdup("{\"ok\":true,\"profile\":{\"id\":\"tor-edit\",\"name\":\"UI test reply\"}}"); return TRUE;
}

/* HELPERS */
#include "routervpn-tor-bridge-v13.inc"

typedef struct {
    const char *transport, *kill, *fault;
    gboolean update, expect_post, cancelled, reached, finished;
    GtkWidget *dialog, *name, *toggle, *transport_widget, *kill_widget, *lines, *status;
    guint entries, toggles, combos, textviews, empty_labels, followup;
} Trial;

static JsonObject *node_in(JsonNode *catalog, const char *id) {
    return external_source_profile_v24(catalog != NULL && JSON_NODE_HOLDS_OBJECT(catalog) ? json_node_get_object(catalog) : NULL, id);
}
static JsonArray *nodes_in(JsonNode *catalog) { return json_object_get_array_member(json_node_get_object(catalog), "profiles"); }
static void change_token(JsonNode *catalog, const char *id) {
    JsonObject *node = node_in(catalog, id); check(node != NULL, "negative target absent from fixture");
    const char *old = obj_string(node, "profile_token");
    check(strlen(old) == 64, "negative requires an original opaque revision");
    char token[65]; memcpy(token, old, sizeof token); token[0] = token[0] == 'a' ? 'b' : 'a';
    json_object_set_string_member(node, "profile_token", token);
}
static void remove_node(JsonNode *catalog, const char *id) {
    JsonArray *nodes = nodes_in(catalog);
    for (guint i = 0; i < json_array_get_length(nodes); i++) {
        JsonObject *node = json_array_get_object_element(nodes, i);
        if (g_strcmp0(obj_string(node, "id"), id) == 0) { json_array_remove_element(nodes, i); return; }
    }
    check(FALSE, "missing-node negative did not remove its target");
}
static void inspect_widgets(GtkWidget *widget, Trial *trial) {
    if (GTK_IS_ENTRY(widget)) { trial->entries++; trial->name = widget; }
    if (GTK_IS_CHECK_BUTTON(widget)) { trial->toggles++; trial->toggle = widget; }
    if (GTK_IS_COMBO_BOX_TEXT(widget)) {
        trial->combos++;
        const char *id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(widget));
        if (g_strcmp0(id, "obfs4") == 0) trial->transport_widget = widget;
        else if (g_strcmp0(id, "off") == 0) trial->kill_widget = widget;
    }
    if (GTK_IS_TEXT_VIEW(widget)) { trial->textviews++; trial->lines = widget; }
    if (GTK_IS_LABEL(widget) && gtk_label_get_text(GTK_LABEL(widget))[0] == '\0') { trial->empty_labels++; trial->status = widget; }
    if (GTK_IS_CONTAINER(widget)) {
        GList *children = gtk_container_get_children(GTK_CONTAINER(widget));
        for (GList *child = children; child != NULL; child = child->next) inspect_widgets(GTK_WIDGET(child->data), trial);
        g_list_free(children);
    }
}
static gboolean cancel_rejected(gpointer data) {
    Trial *trial = data; trial->followup = 0;
    check(posts == (g_strcmp0(trial->fault, "controller-refusal") == 0 ? 1u : 0u), "rejected form reached a controller mutation");
    check(refreshes == 0, "rejected update announced successful persistence");
    check(gtk_label_get_text(GTK_LABEL(trial->status))[0] != '\0', "rejected update did not explain the failure");
    trial->finished = TRUE;
    gtk_button_clicked(GTK_BUTTON(gtk_dialog_get_widget_for_response(GTK_DIALOG(trial->dialog), GTK_RESPONSE_CANCEL)));
    return G_SOURCE_REMOVE;
}
static gboolean drive_dialog(gpointer data) {
    Trial *trial = data;
    GList *windows = gtk_window_list_toplevels();
    for (GList *item = windows; item != NULL; item = item->next) {
        GtkWidget *widget = item->data;
        if (GTK_IS_DIALOG(widget) && g_strcmp0(gtk_window_get_title(GTK_WINDOW(widget)), "Tor censorship circumvention") == 0) {
            check(trial->dialog == NULL, "multiple Tor dialogs acquired the same trial"); trial->dialog = widget;
        }
    }
    g_list_free(windows); check(trial->dialog != NULL, "actual Tor dialog did not open");
    inspect_widgets(gtk_dialog_get_content_area(GTK_DIALOG(trial->dialog)), trial);
    check(trial->entries == 1 && trial->toggles == 1 && trial->combos == 2 && trial->textviews == 1 && trial->empty_labels == 1, "shipping Tor control shape changed");
    check(trial->transport_widget != NULL && trial->kill_widget != NULL, "actual transport/protection widgets were missing");
    trial->reached = TRUE; dialogs++;
    check(gtk_widget_get_sensitive(trial->toggle), "captured selected Tor cannot be explicitly updated");
    JsonObject *opened_profile = node_in(source_catalog, "tor-edit");
    gboolean saved_plain = g_strcmp0(external_path_string_v4(external_path_object_v4(opened_profile, "external"), "protocol"), "tor") == 0;
    if (saved_plain && trial->update) gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(trial->lines)), "retained pasted bridge text", -1);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(trial->toggle), trial->update);
    if (saved_plain && trial->update) {
        check(g_strcmp0(gtk_combo_box_get_active_id(GTK_COMBO_BOX(trial->transport_widget)), "tor") == 0, "Saved Plain Tor reopened as a bridge transport");
        char *retained = linux_tor_text_v13(trial->lines);
        check(g_strcmp0(retained, "retained pasted bridge text") == 0, "Loading Plain Tor silently discarded pasted bridge lines");
        g_free(retained);
    }
    if (g_strcmp0(trial->fault, "saved-always") == 0)
        check(g_strcmp0(gtk_combo_box_get_active_id(GTK_COMBO_BOX(trial->kill_widget)), "always") == 0, "Update disabled saved Always protection before any user edit");
    if (g_strcmp0(trial->fault, "invalid-saved-kill") == 0 || g_strcmp0(trial->fault, "missing-saved-kill") == 0)
        check(gtk_combo_box_get_active_id(GTK_COMBO_BOX(trial->kill_widget)) == NULL, "unavailable saved protection silently became Off");
    check(gtk_combo_box_set_active_id(GTK_COMBO_BOX(trial->transport_widget), trial->transport), "requested transport not offered by actual widget");
    if (trial->kill != NULL) check(gtk_combo_box_set_active_id(GTK_COMBO_BOX(trial->kill_widget), trial->kill), "requested protection not offered by actual widget");
    const char *fixed_count = g_str_has_prefix(trial->fault, "fixed-") ? trial->fault + strlen("fixed-") : NULL;
    gboolean fixed_mixed = g_str_has_prefix(trial->fault, "fixed-mixed-");
    JsonArray *lines = fixed_count != NULL ? json_object_get_array_member(json_node_get_object(source_fixed_sets), fixed_mixed ? "1" : g_strcmp0(fixed_count, "oversized") == 0 ? "8" : fixed_count) :
        json_object_get_array_member(json_node_get_object(source_lines), g_str_has_prefix(trial->fault, "ordinary-mixed-udp") || g_strcmp0(trial->fault, "plain-lines") == 0 ? "obfs4" : trial->transport);
    GString *text = g_string_new("");
    for (guint i = 0; i < json_array_get_length(lines); i++) {
        if (i) g_string_append_c(text, '\n');
        g_string_append(text, json_array_get_string_element(lines, i));
    }
    if (fixed_mixed || g_strcmp0(trial->fault, "fixed-oversized") == 0) {
        JsonArray *extra = fixed_mixed ? json_object_get_array_member(json_node_get_object(source_lines), trial->fault + strlen("fixed-mixed-")) : json_object_get_array_member(json_node_get_object(source_fixed_sets), "1");
        for (guint i = 0; i < json_array_get_length(extra); i++) { g_string_append_c(text, '\n'); g_string_append(text, json_array_get_string_element(extra, i)); }
    }
    if (g_str_has_prefix(trial->fault, "ordinary-mixed-udp")) {
        JsonArray *udp = json_object_get_array_member(json_node_get_object(source_lines), "snowflake");
        for (guint i = 0; i < json_array_get_length(udp); i++) {
            const char *line = json_array_get_string_element(udp, i);
            check(g_str_has_prefix(line, "Bridge snowflake "), "mixed UDP negative lost its real optional Bridge prefix");
            g_string_append_c(text, '\n');
            if (g_str_has_suffix(trial->fault, "-bare")) g_string_append(text, line + strlen("Bridge "));
            else if (g_str_has_suffix(trial->fault, "-unicode")) {
                g_string_append(text, "bRiDgE\302\240SnOwFlAkE\302\240"); g_string_append(text, line + strlen("Bridge snowflake "));
            } else g_string_append(text, line);
        }
    }
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(trial->lines)), g_strcmp0(trial->fault, "empty-lines") == 0 ? "" : text->str, -1);
    g_string_free(text, TRUE);
    if (g_strcmp0(trial->fault, "stale-exit") == 0) change_token(current_catalog, "tor-edit");
    if (g_strcmp0(trial->fault, "stale-entry") == 0) change_token(current_catalog, "entry");
    if (g_strcmp0(trial->fault, "missing-exit") == 0) remove_node(current_catalog, "tor-edit");
    if (g_strcmp0(trial->fault, "missing-entry") == 0) remove_node(current_catalog, "entry");
    if (g_strcmp0(trial->fault, "selected") == 0) json_object_set_string_member(json_node_get_object(current_catalog), "selected_id", "entry");
    if (g_strcmp0(trial->fault, "duplicate-entry") == 0) {
        JsonObject *duplicate = json_object_ref(node_in(current_catalog, "entry"));
        json_array_add_object_element(nodes_in(current_catalog), duplicate);
    }
    if (g_strcmp0(trial->fault, "mutated-rendered") == 0) {
        JsonNode *displayed = g_object_get_data(G_OBJECT(active_app->window), "router-vpn-source-catalog-v24");
        change_token(displayed, "entry"); change_token(current_catalog, "entry");
    }
    if (g_strcmp0(trial->fault, "busy-after-open") == 0) idle = FALSE;
    if (trial->cancelled) {
        trial->finished = TRUE;
        gtk_button_clicked(GTK_BUTTON(gtk_dialog_get_widget_for_response(GTK_DIALOG(trial->dialog), GTK_RESPONSE_CANCEL)));
        return G_SOURCE_REMOVE;
    }
    if (!trial->expect_post || refuse_post) trial->followup = g_idle_add(cancel_rejected, trial);
    gtk_button_clicked(GTK_BUTTON(gtk_dialog_get_widget_for_response(GTK_DIALOG(trial->dialog), GTK_RESPONSE_ACCEPT)));
    return G_SOURCE_REMOVE;
}
static gboolean watchdog(gpointer ignored) { (void)ignored; check(FALSE, "actual GTK dialog failed its bounded completion"); return G_SOURCE_REMOVE; }

static void reset_fixture(App *app, const char *fault) {
    posts = node_reads = status_reads = refreshes = diagnostics = 0;
    idle = TRUE; unavailable_nodes = g_strcmp0(fault, "nodes-unavailable") == 0; refuse_post = g_strcmp0(fault, "controller-refusal") == 0;
    g_clear_pointer(&last_body, g_free);
    g_clear_pointer(&current_catalog, json_node_free); g_clear_pointer(&capabilities, json_node_free);
    JsonNode *displayed = copy_public_source_value_v24(g_strcmp0(fault, "saved-always") == 0 ? source_always : source_catalog);
    JsonObject *profile = node_in(displayed, "tor-edit");
    if (g_strcmp0(fault, "invalid-saved-kill") == 0) json_object_set_string_member(profile, "kill_switch_policy", "unavailable-policy");
    if (g_strcmp0(fault, "missing-saved-kill") == 0) json_object_remove_member(profile, "kill_switch_policy");
    if (g_strcmp0(fault, "direct-strict") == 0) json_object_set_boolean_member(profile, "multihop_enabled", FALSE);
    if (g_strcmp0(fault, "compare-strict") == 0 || g_strcmp0(fault, "compare-off") == 0) {
        json_object_set_string_member(profile, "multihop_execution", "auto");
        json_object_set_boolean_member(profile, "multihop_enabled", FALSE);
    }
    if (g_strcmp0(fault, "server-direct-strict") == 0 || g_strcmp0(fault, "server-direct-off") == 0) {
        json_object_set_string_member(profile, "multihop_execution", "server");
        json_object_set_boolean_member(profile, "multihop_enabled", FALSE);
    }
    gboolean server_external = g_strcmp0(fault, "server-external-strict") == 0 || g_strcmp0(fault, "server-external-off") == 0;
    if (server_external) json_object_set_string_member(profile, "multihop_execution", "server");
    if (g_strcmp0(fault, "external-entry-strict") == 0 || server_external) {
        JsonObject *entry = node_in(displayed, "entry"), *external = json_object_new();
        json_object_set_string_member(entry, "node_kind", "external"); json_object_set_string_member(external, "protocol", "socks5");
        json_object_set_object_member(entry, "external", external);
    }
    if (g_strcmp0(fault, "ordinary-mode") == 0 || g_strcmp0(fault, "ordinary-fixed-bypass") == 0)
        json_object_set_string_member(profile, "multihop_entry_mode", "unrelated-mode");
    if (g_strcmp0(fault, "ordinary-public-proof") == 0)
        json_object_set_string_member(json_object_get_object_member(node_in(displayed, "entry"), "external"), "expected_public_ip", "");
    if (g_strcmp0(fault, "missing-token") == 0) json_object_remove_member(node_in(displayed, "entry"), "profile_token");
    current_catalog = copy_public_source_value_v24(displayed); capabilities = copy_public_source_value_v24(source_capabilities);
    if (g_str_has_prefix(fault, "dynamic-")) {
        JsonArray *rows = json_object_get_array_member(json_node_get_object(capabilities), "transports");
        for (guint i = 0; i < json_array_get_length(rows); i++) {
            JsonObject *row = json_array_get_object_element(rows, i);
            json_object_set_boolean_member(row, "strict_dynamic_direct_kill_switch", g_strcmp0(fault, "dynamic-missing") != 0);
            json_object_set_boolean_member(row, "supported", g_strcmp0(fault, "dynamic-unverified") != 0);
        }
    }
    if (g_strcmp0(fault, "no-capability") == 0) json_object_set_boolean_member(json_node_get_object(capabilities), "profile_update_source_preconditions", FALSE);
    if (g_strcmp0(fault, "ordinary-capability") == 0) {
        JsonArray *rows = json_object_get_array_member(json_node_get_object(capabilities), "transports");
        for (guint i = 0; i < json_array_get_length(rows); i++)
            json_object_set_boolean_member(json_array_get_object_element(rows, i), "strict_external_entry_kill_switch", FALSE);
    }
    g_object_set_data_full(G_OBJECT(app->window), "router-vpn-source-catalog-v24", displayed, (GDestroyNotify)json_node_free);
    app->selected = "tor-edit";
}
static void verify_post(Trial *trial) {
    check(posts == 1 && refreshes == 1 && diagnostics == 1, "successful actual Save did not commit exactly one UI mutation");
    JsonNode *posted = parse_json(last_body); check(posted != NULL && JSON_NODE_HOLDS_OBJECT(posted), "Save did not emit one JSON object");
    JsonObject *body = json_node_get_object(posted);
    check(g_strcmp0(obj_string(body, "transport"), trial->transport) == 0, "actual transport changed before Save");
    const char *expected_kill = g_strcmp0(trial->fault, "saved-always") == 0 ? "always" : trial->kill;
    check(g_strcmp0(obj_string(body, "kill_switch_policy"), expected_kill) == 0, "actual protection changed before Save");
    check(g_strcmp0(obj_string(body, "name"), trial->update ? "Captured Tor exit" : "") == 0, "Update did not preserve the captured name before any user edit");
    check(json_object_get_size(body) == (trial->update ? 7u : 4u), "bridge form copied unrelated controls or private node settings");
    const char *forbidden[] = {"profile_id", "entry_id", "entry_mode", "base", "direct", "execution", "api_token", "private_key", "external", "comparison_request_id"};
    for (guint i = 0; i < G_N_ELEMENTS(forbidden); i++) check(!json_object_has_member(body, forbidden[i]), "Tor import escaped its bridge-only edit contract");
    if (trial->update) {
        check(node_reads == 1 && g_strcmp0(obj_string(body, "id"), "tor-edit") == 0 && g_strcmp0(obj_string(body, "expected_selected_node_id"), "tor-edit") == 0, "Update lost its opened source identity");
        JsonObject *tokens = json_object_get_object_member(body, "expected_profile_tokens");
        check(tokens != NULL && json_object_get_size(tokens) == 2, "Update lost the exact exit/entry token set");
        for (guint i = 0; i < 2; i++) {
            const char *id = i ? "entry" : "tor-edit";
            JsonNode *expected_catalog = g_strcmp0(trial->fault, "saved-always") == 0 ? source_always : source_catalog;
            check(g_strcmp0(obj_string(tokens, id), obj_string(node_in(expected_catalog, id), "profile_token")) == 0, "Update adopted a fresh or fabricated source revision");
        }
    } else {
        check(node_reads == 0 && !json_object_has_member(body, "id") && !json_object_has_member(body, "expected_profile_tokens") && !json_object_has_member(body, "expected_selected_node_id"), "Add silently became an update of the selected Tor node");
        if (g_str_has_prefix(trial->fault, "fixed-")) {
            JsonArray *expected = json_object_get_array_member(json_node_get_object(source_fixed_sets), trial->fault + strlen("fixed-"));
            JsonArray *actual = json_object_get_array_member(body, "bridges");
            check(actual != NULL && json_array_get_length(actual) == json_array_get_length(expected), "Direct fixed Add changed its complete bridge list");
            for (guint i = 0; i < json_array_get_length(expected); i++) check(g_strcmp0(json_array_get_string_element(actual, i), json_array_get_string_element(expected, i)) == 0, "Direct fixed Add substituted captured bridge credentials or order");
        }
    }
    json_node_free(posted);
}
static void run_trial(App *app, const char *transport, const char *kill, gboolean update, const char *fault, gboolean expect_post, gboolean cancelled, gboolean emit) {
    reset_fixture(app, fault);
    Trial trial = {.transport = transport, .kill = kill, .fault = fault, .update = update, .expect_post = expect_post, .cancelled = cancelled};
    guint driver = g_idle_add(drive_dialog, &trial), limit = g_timeout_add_seconds(10, watchdog, NULL);
    on_linux_tor_bridge_v13(NULL, app);
    g_source_remove(limit);
    check(trial.reached, "actual on_linux_tor_bridge_v13 did not enter its modal callback");
    (void)driver;
    if (trial.followup) { g_source_remove(trial.followup); trial.followup = 0; }
    if (expect_post && !refuse_post) verify_post(&trial);
    else {
        gboolean rejected = trial.finished && posts == (refuse_post ? 1u : 0u) && refreshes == 0;
        if (!rejected) g_printerr("Rejected trial identity: %s\n", fault);
        check(rejected, "cancelled/rejected modal escaped its owned callback");
    }
    if (emit) {
        char *name = !update ? (g_strcmp0(fault, "dynamic-direct") == 0 ? g_strdup_printf("tor-create-dynamic-%s-%s.json", transport, kill) : g_str_has_prefix(fault, "fixed-") ? g_strdup_printf("tor-create-fixed-%s-%s-%s.json", transport, fault + strlen("fixed-"), kill) : g_strdup("tor-create-plain.json")) : g_strcmp0(fault, "saved-always") == 0 ? g_strdup_printf("tor-update-%spreserved-protection.json", source_prefix) : g_strdup_printf("tor-update-%s%s-%s.json", source_prefix, transport, kill);
        char *path = g_build_filename(directory, name, NULL);
        check(g_file_set_contents(path, last_body, -1, NULL) && g_chmod(path, 0600) == 0, "actual callback payload could not be saved privately");
        g_free(path); g_free(name);
    }
}
static JsonNode *read_fixture(const char *name) {
    char *path = g_build_filename(directory, name, NULL), *raw = NULL;
    check(g_file_get_contents(path, &raw, NULL, NULL), "Go-generated source fixture is missing");
    JsonNode *node = parse_json(raw); check(node != NULL && JSON_NODE_HOLDS_OBJECT(node), "Go-generated source fixture is malformed");
    g_free(raw); g_free(path); return node;
}
int main(int argc, char **argv) {
    gtk_init(&argc, &argv); check(argc == 2, "expected private Go fixture directory"); directory = argv[1];
    source_capabilities = read_fixture("tor-update-capabilities.json"); source_lines = read_fixture("tor-update-input-lines.json"); source_fixed_sets = read_fixture("tor-fixed-input-sets.json");
    check(strstr(obj_string(json_node_get_object(source_capabilities), "test_fixture_runtime_availability"), "simulated") != NULL, "UI fixture must label simulated runtime availability");
    App app = {gtk_window_new(GTK_WINDOW_TOPLEVEL), "tor-edit"}; active_app = &app;
    const char *transports[] = {"obfs4", "meek_lite", "snowflake", "webtunnel", "tor"}, *kills[] = {"off", "on-connect", "always"};
    const char *selections[] = {"local", "server", "auto", "ordinary-wireguard", "ordinary-amneziawg", "ordinary-socks5", "ordinary-http-connect", "ordinary-https-connect", "ordinary-shadowsocks", "ordinary-hysteria2", "ordinary-openvpn"};
    for (guint plain = 0; plain < 2; plain++) for (guint execution = 0; execution < G_N_ELEMENTS(selections); execution++) {
    const char *selection = selections[execution];
    gboolean ordinary = g_str_has_prefix(selection, "ordinary-");
    gboolean tcp_only = g_strcmp0(selection, "ordinary-socks5") == 0 || g_strcmp0(selection, "ordinary-http-connect") == 0 || g_strcmp0(selection, "ordinary-https-connect") == 0;
    char *prefix = plain ? g_strdup_printf("plain-%s-", selection) : g_strcmp0(selection, "local") == 0 ? g_strdup("") : g_strdup_printf("%s-", selection);
    source_prefix = prefix;
    char *catalog_name = g_strdup_printf("tor-update-%ssource-catalog.json", prefix), *always_name = g_strdup_printf("tor-update-%salways-source-catalog.json", prefix);
    source_catalog = read_fixture(catalog_name); source_always = read_fixture(always_name);
    g_free(catalog_name); g_free(always_name);
    check(g_strcmp0(obj_string(node_in(source_catalog, "tor-edit"), "multihop_execution"), ordinary ? "local" : selection) == 0,
          "native editor did not receive the actual execution-bound Go source catalog");
    for (guint t = 0; t < G_N_ELEMENTS(transports); t++) for (guint k = 0; k < G_N_ELEMENTS(kills); k++) {
        gboolean eligible = !(tcp_only && g_strcmp0(transports[t], "snowflake") == 0 && k > 0);
        run_trial(&app, transports[t], kills[k], TRUE, eligible ? "none" : "ordinary-udp", eligible, FALSE, eligible);
    }
    const char *preserved = plain ? "tor" : ordinary ? "meek_lite" : "snowflake";
    run_trial(&app, preserved, NULL, TRUE, "saved-always", TRUE, FALSE, TRUE);
    run_trial(&app, preserved, NULL, TRUE, "invalid-saved-kill", FALSE, FALSE, FALSE);
    run_trial(&app, preserved, NULL, TRUE, "missing-saved-kill", FALSE, FALSE, FALSE);
    const char *failures[] = {"stale-exit", "stale-entry", "missing-exit", "missing-entry", "selected", "duplicate-entry", "mutated-rendered", "busy-after-open", "nodes-unavailable", "missing-token", "no-capability", "direct-strict", "compare-strict", "external-entry-strict", "server-direct-strict", "server-external-strict", "controller-refusal"};
    for (guint i = 0; i < G_N_ELEMENTS(failures); i++) run_trial(&app, preserved, "always", TRUE, failures[i], FALSE, FALSE, FALSE);
    run_trial(&app, "obfs4", "always", TRUE, "empty-lines", FALSE, FALSE, FALSE);
    run_trial(&app, "tor", "always", TRUE, "plain-lines", FALSE, FALSE, FALSE);
    run_trial(&app, "tor", "always", FALSE, "plain-direct-strict", FALSE, FALSE, FALSE);
    const char *unprotected[] = {"compare-off", "server-direct-off", "server-external-off"};
    for (guint i = 0; i < G_N_ELEMENTS(unprotected); i++) run_trial(&app, "obfs4", "off", TRUE, unprotected[i], FALSE, FALSE, FALSE);
    if (ordinary) {
        const char *ordinary_failures[] = {"ordinary-mode", "ordinary-public-proof", "ordinary-capability"};
        for (guint i = 0; i < G_N_ELEMENTS(ordinary_failures); i++) run_trial(&app, "meek_lite", "always", TRUE, ordinary_failures[i], FALSE, FALSE, FALSE);
        run_trial(&app, "obfs4", "always", TRUE, "ordinary-fixed-bypass", FALSE, FALSE, FALSE);
        if (tcp_only) {
            const char *udp_failures[] = {"ordinary-mixed-udp", "ordinary-mixed-udp-bare", "ordinary-mixed-udp-unicode"};
            for (guint i = 0; i < G_N_ELEMENTS(udp_failures); i++) run_trial(&app, "custom", "always", TRUE, udp_failures[i], FALSE, FALSE, FALSE);
        }
    }
    run_trial(&app, preserved, "always", TRUE, "cancel", FALSE, TRUE, FALSE);
    for (guint t = 0; t < G_N_ELEMENTS(transports); t++) run_trial(&app, transports[t], "off", FALSE, "add", TRUE, FALSE, g_strcmp0(transports[t], "tor") == 0);
    if (plain == 0 && execution == 0) {
        for (guint t = 1; t < G_N_ELEMENTS(transports); t++) for (guint k = 1; k < G_N_ELEMENTS(kills); k++) {
            run_trial(&app, transports[t], kills[k], FALSE, "dynamic-direct", TRUE, FALSE, TRUE);
            run_trial(&app, transports[t], kills[k], FALSE, "dynamic-missing", FALSE, FALSE, FALSE);
            run_trial(&app, transports[t], kills[k], FALSE, "dynamic-unverified", FALSE, FALSE, FALSE);
        }
        const char *fixed_transports[] = {"obfs4", "custom"}, *fixed_counts[] = {"fixed-1", "fixed-2", "fixed-8"};
        for (guint t = 0; t < G_N_ELEMENTS(fixed_transports); t++) for (guint n = 0; n < G_N_ELEMENTS(fixed_counts); n++) for (guint k = 1; k < G_N_ELEMENTS(kills); k++)
            run_trial(&app, fixed_transports[t], kills[k], FALSE, fixed_counts[n], TRUE, FALSE, TRUE);
        const char *mixed[] = {"fixed-mixed-meek_lite", "fixed-mixed-snowflake", "fixed-mixed-webtunnel", "fixed-oversized"};
        for (guint i = 0; i < G_N_ELEMENTS(mixed); i++) run_trial(&app, "custom", "always", FALSE, mixed[i], FALSE, FALSE, FALSE);
    }
    reset_fixture(&app, "initial-busy"); idle = FALSE; guint before = dialogs;
    on_linux_tor_bridge_v13(NULL, &app); check(dialogs == before && posts == 0 && status_reads == 1 && diagnostics == 1, "busy application opened a Tor mutation dialog");
    json_node_free(source_catalog); json_node_free(source_always); g_free(prefix); source_prefix = NULL;
    }
    gtk_widget_destroy(app.window); g_clear_pointer(&last_body, g_free);
    json_node_free(source_capabilities); json_node_free(source_lines); json_node_free(source_fixed_sets); json_node_free(current_catalog); json_node_free(capabilities);
    g_print("Actual GTK Tor dialog/Update/Save/Cancel callbacks: %u checks across %u dialogs PASS\n", checks, dialogs);
    return 0;
}
