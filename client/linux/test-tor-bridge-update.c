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
static JsonNode *source_catalog, *source_always, *source_capabilities, *source_lines, *current_catalog, *capabilities;
static const char *directory;
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
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(trial->toggle), trial->update);
    if (g_strcmp0(trial->fault, "saved-always") == 0)
        check(g_strcmp0(gtk_combo_box_get_active_id(GTK_COMBO_BOX(trial->kill_widget)), "always") == 0, "Update disabled saved Always protection before any user edit");
    if (g_strcmp0(trial->fault, "invalid-saved-kill") == 0 || g_strcmp0(trial->fault, "missing-saved-kill") == 0)
        check(gtk_combo_box_get_active_id(GTK_COMBO_BOX(trial->kill_widget)) == NULL, "unavailable saved protection silently became Off");
    check(gtk_combo_box_set_active_id(GTK_COMBO_BOX(trial->transport_widget), trial->transport), "requested transport not offered by actual widget");
    if (trial->kill != NULL) check(gtk_combo_box_set_active_id(GTK_COMBO_BOX(trial->kill_widget), trial->kill), "requested protection not offered by actual widget");
    JsonArray *lines = json_object_get_array_member(json_node_get_object(source_lines), trial->transport);
    GString *text = g_string_new("");
    for (guint i = 0; i < json_array_get_length(lines); i++) {
        if (i) g_string_append_c(text, '\n');
        g_string_append(text, json_array_get_string_element(lines, i));
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
    if (g_strcmp0(fault, "server-strict") == 0) json_object_set_string_member(profile, "multihop_execution", "server");
    if (g_strcmp0(fault, "external-entry-strict") == 0) {
        JsonObject *entry = node_in(displayed, "entry"), *external = json_object_new();
        json_object_set_string_member(entry, "node_kind", "external"); json_object_set_string_member(external, "protocol", "socks5");
        json_object_set_object_member(entry, "external", external);
    }
    if (g_strcmp0(fault, "missing-token") == 0) json_object_remove_member(node_in(displayed, "entry"), "profile_token");
    current_catalog = copy_public_source_value_v24(displayed); capabilities = copy_public_source_value_v24(source_capabilities);
    if (g_strcmp0(fault, "no-capability") == 0) json_object_set_boolean_member(json_node_get_object(capabilities), "profile_update_source_preconditions", FALSE);
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
    const char *forbidden[] = {"profile_id", "entry_id", "entry_mode", "base", "direct", "execution", "api_token", "private_key", "external"};
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
    else check(trial.finished && posts == (refuse_post ? 1u : 0u) && refreshes == 0, "cancelled/rejected modal escaped its owned callback");
    if (emit) {
        char *name = g_strcmp0(fault, "saved-always") == 0 ? g_strdup("tor-update-preserved-protection.json") : g_strdup_printf("tor-update-%s-%s.json", transport, kill);
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
    source_catalog = read_fixture("tor-update-source-catalog.json"); source_capabilities = read_fixture("tor-update-capabilities.json"); source_lines = read_fixture("tor-update-input-lines.json");
    source_always = read_fixture("tor-update-always-source-catalog.json");
    check(strstr(obj_string(json_node_get_object(source_capabilities), "test_fixture_runtime_availability"), "simulated") != NULL, "UI fixture must label simulated runtime availability");
    App app = {gtk_window_new(GTK_WINDOW_TOPLEVEL), "tor-edit"}; active_app = &app;
    const char *transports[] = {"obfs4", "meek_lite", "snowflake", "webtunnel"}, *kills[] = {"off", "on-connect", "always"};
    for (guint t = 0; t < G_N_ELEMENTS(transports); t++) for (guint k = 0; k < G_N_ELEMENTS(kills); k++)
        run_trial(&app, transports[t], kills[k], TRUE, "none", TRUE, FALSE, TRUE);
    run_trial(&app, "snowflake", NULL, TRUE, "saved-always", TRUE, FALSE, TRUE);
    run_trial(&app, "snowflake", NULL, TRUE, "invalid-saved-kill", FALSE, FALSE, FALSE);
    run_trial(&app, "snowflake", NULL, TRUE, "missing-saved-kill", FALSE, FALSE, FALSE);
    const char *failures[] = {"stale-exit", "stale-entry", "missing-exit", "missing-entry", "selected", "duplicate-entry", "mutated-rendered", "busy-after-open", "nodes-unavailable", "missing-token", "no-capability", "empty-lines", "direct-strict", "server-strict", "external-entry-strict", "controller-refusal"};
    for (guint i = 0; i < G_N_ELEMENTS(failures); i++) run_trial(&app, "snowflake", "always", TRUE, failures[i], FALSE, FALSE, FALSE);
    run_trial(&app, "snowflake", "always", TRUE, "cancel", FALSE, TRUE, FALSE);
    for (guint t = 0; t < G_N_ELEMENTS(transports); t++) run_trial(&app, transports[t], "off", FALSE, "add", TRUE, FALSE, FALSE);
    reset_fixture(&app, "initial-busy"); idle = FALSE; guint before = dialogs;
    on_linux_tor_bridge_v13(NULL, &app); check(dialogs == before && posts == 0 && status_reads == 1 && diagnostics == 1, "busy application opened a Tor mutation dialog");
    gtk_widget_destroy(app.window); g_clear_pointer(&last_body, g_free);
    json_node_free(source_catalog); json_node_free(source_always); json_node_free(source_capabilities); json_node_free(source_lines); json_node_free(current_catalog); json_node_free(capabilities);
    g_print("Actual GTK Tor dialog/Update/Save/Cancel callbacks: %u checks across %u dialogs PASS\n", checks, dialogs);
    return 0;
}
