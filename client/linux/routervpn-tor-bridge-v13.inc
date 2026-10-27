/* Linux native Tor censorship-circumvention panel.
 *
 * This UI only builds validated external Tor bridge profiles through the local
 * controller API. It never accepts executable paths or raw torrc directives.
 * Runtime truth remains owned by /api/tor-bridge/capabilities and the controller.
 */

typedef struct {
    App *app;
    GtkWidget *dialog;
    GtkWidget *name;
    GtkWidget *update_selected;
    GtkWidget *transport;
    GtkWidget *kill;
    GtkWidget *lines;
    GtkWidget *capability;
    GtkWidget *status;
    JsonNode *opened;
    JsonNode *capabilities;
} LinuxTorBridgeV13;

static JsonObject *linux_tor_update_profile_v13(LinuxTorBridgeV13 *state) {
    JsonObject *store = state->opened != NULL && JSON_NODE_HOLDS_OBJECT(state->opened) ? json_node_get_object(state->opened) : NULL;
    JsonObject *profile = external_source_profile_v24(store, external_source_selection_v24(store));
    return g_strcmp0(external_path_string_v4(profile, "node_kind"), "external") == 0 &&
        g_strcmp0(external_path_string_v4(external_path_object_v4(profile, "external"), "protocol"), "tor-bridge") == 0 ? profile : NULL;
}

static gboolean linux_tor_router_path_v13(LinuxTorBridgeV13 *state, JsonObject *profile) {
    const char *id = external_path_string_v4(profile, "id"), *entry_id = external_path_string_v4(profile, "multihop_entry_id");
    const char *execution = external_path_string_v4(profile, "multihop_execution");
    if (!external_path_flag_v4(profile, "multihop_enabled") || !entry_id[0] || g_strcmp0(id, entry_id) == 0 ||
        g_strcmp0(id, external_path_string_v4(profile, "multihop_exit_id")) != 0 || (execution[0] && g_strcmp0(execution, "local") != 0 && g_strcmp0(execution, "server") != 0)) return FALSE;
    JsonObject *store = state->opened != NULL && JSON_NODE_HOLDS_OBJECT(state->opened) ? json_node_get_object(state->opened) : NULL;
    JsonObject *entry = external_source_profile_v24(store, entry_id);
    const char *kind = external_path_string_v4(entry, "node_kind");
    return entry != NULL && (!kind[0] || g_strcmp0(kind, "router-vpn") == 0) && !json_object_has_member(entry, "external");
}

static char *linux_tor_text_v13(GtkWidget *view) {
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
    GtkTextIter start, end;
    gtk_text_buffer_get_bounds(buffer, &start, &end);
    return gtk_text_buffer_get_text(buffer, &start, &end, FALSE);
}

static void linux_tor_status_v13(LinuxTorBridgeV13 *state, const char *text) {
    if (state == NULL || state->status == NULL) return;
    gtk_label_set_text(GTK_LABEL(state->status), text != NULL ? text : "");
}

static void linux_tor_update_changed_v13(GtkToggleButton *button, gpointer data) {
    LinuxTorBridgeV13 *state = data;
    if (!gtk_toggle_button_get_active(button)) {
        gtk_combo_box_set_active_id(GTK_COMBO_BOX(state->kill), "off");
        linux_tor_status_v13(state, "Adding a new Tor node. Choose its protection and paste bridge lines.");
        return;
    }
    JsonObject *profile = linux_tor_update_profile_v13(state);
    const char *policy = external_path_string_v4(profile, "kill_switch_policy");
    gtk_combo_box_set_active(GTK_COMBO_BOX(state->kill), -1);
    gboolean loaded = gtk_combo_box_set_active_id(GTK_COMBO_BOX(state->kill), policy);
    if (profile != NULL) gtk_entry_set_text(GTK_ENTRY(state->name), external_path_string_v4(profile, "name"));
    linux_tor_status_v13(state, loaded ? "Loaded the captured node name and kill-switch policy. Paste replacement bridge lines; the saved path and DNS remain attached to this node." : "The saved kill-switch policy is unavailable. Choose a policy explicitly before saving.");
}

static gboolean linux_tor_mutation_idle_v13(App *app, char **reason) {
    if (reason != NULL) *reason = NULL;
    if (app == NULL) {
        if (reason != NULL) *reason = g_strdup("Tor profile mutation is unavailable.");
        return FALSE;
    }
    Buffer out = {0};
    char *err = NULL;
    if (!api_request("/api/status", "GET", NULL, 4000, &out, &err)) {
        if (reason != NULL) *reason = g_strdup_printf("Controller/status unavailable • Tor profile mutation locked%s%s", err != NULL && err[0] ? ": " : "", err != NULL ? err : "");
        g_free(err);
        free(out.data);
        return FALSE;
    }
    JsonNode *root = parse_json(out.data);
    gboolean idle = FALSE;
    const char *phase = "";
    gboolean connected = FALSE;
    if (root != NULL && JSON_NODE_HOLDS_OBJECT(root)) {
        JsonObject *obj = json_node_get_object(root);
        connected = json_object_has_member(obj, "connected") && json_object_get_boolean_member(obj, "connected");
        phase = obj_string(obj, "phase");
        idle = !connected && (phase[0] == '\0' || g_ascii_strcasecmp(phase, "off") == 0 || g_ascii_strcasecmp(phase, "failed") == 0);
    }
    if (!idle && reason != NULL) {
        *reason = g_strdup_printf("Disconnect or let the active VPN transition finish before adding or updating a Tor bridge. Current phase: %s", phase[0] ? phase : "unknown");
    }
    if (root != NULL) json_node_free(root);
    g_free(err);
    free(out.data);
    return idle;
}

static void linux_tor_refresh_caps_v13(LinuxTorBridgeV13 *state) {
    if (state == NULL) return;
    g_clear_pointer(&state->capabilities, json_node_free);
    Buffer out = {0};
    char *err = NULL;
    GString *summary = g_string_new("");
    if (!api_request("/api/tor-bridge/capabilities", "GET", NULL, 8000, &out, &err)) {
        g_string_printf(summary, "Tor support check failed: %s", err != NULL ? err : "unknown error");
    } else {
        JsonNode *root = parse_json(out.data);
        JsonObject *obj = root != NULL && JSON_NODE_HOLDS_OBJECT(root) ? json_node_get_object(root) : NULL;
        JsonArray *items = obj != NULL && json_object_has_member(obj, "transports") ? json_object_get_array_member(obj, "transports") : NULL;
        if (items == NULL) {
            g_string_assign(summary, "Tor transport capability response is unavailable.");
        } else {
            state->capabilities = copy_public_source_value_v24(root);
            for (guint i = 0; i < json_array_get_length(items); i++) {
                JsonObject *item = json_array_get_object_element(items, i);
                if (item == NULL) continue;
                const char *id = obj_string(item, "id");
                const char *description = obj_string(item, "description");
                const char *reason = obj_string(item, "reason");
                gboolean supported = !json_object_has_member(item, "supported") || json_object_get_boolean_member(item, "supported");
                gboolean strict = json_object_has_member(item, "strict_kill_switch") && json_object_get_boolean_member(item, "strict_kill_switch");
                gboolean router_strict = external_path_flag_v4(item, "strict_router_entry_kill_switch");
                if (summary->len) g_string_append_c(summary, '\n');
                g_string_append_printf(summary, "%s — %s • strict protection %s", id[0] ? id : "unknown", supported ? "available" : "unavailable", strict ? "Direct with one fixed bridge" : router_strict ? "with a saved Router entry using Local or Server execution" : "unavailable for this transport");
                if (description[0]) g_string_append_printf(summary, "\n  %s", description);
                if (reason[0]) g_string_append_printf(summary, "\n  Reason: %s", reason);
            }
        }
        if (root != NULL) json_node_free(root);
    }
    gtk_label_set_text(GTK_LABEL(state->capability), summary->str);
    g_string_free(summary, TRUE);
    g_free(err);
    free(out.data);
}

static char *linux_tor_payload_v13(LinuxTorBridgeV13 *state, JsonNode *current, char **validation_error) {
    if (validation_error != NULL) *validation_error = NULL;
    const char *name = gtk_entry_get_text(GTK_ENTRY(state->name));
    const char *transport = gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->transport));
    const char *kill = gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->kill));
    const char *update_id = NULL;
    JsonObject *profile = NULL;
    JsonObject *caps = state->capabilities != NULL && JSON_NODE_HOLDS_OBJECT(state->capabilities) ? json_node_get_object(state->capabilities) : NULL;
    if (state->update_selected != NULL && gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(state->update_selected))) {
        profile = linux_tor_update_profile_v13(state);
        update_id = external_path_string_v4(profile, "id");
        if (profile == NULL || !external_path_flag_v4(caps, "profile_update_source_preconditions")) {
            if (validation_error != NULL) *validation_error = g_strdup("Open this dialog with a Tor node selected and a controller that supports captured updates.");
            return NULL;
        }
    }
    char *raw = linux_tor_text_v13(state->lines);
    gchar **rows = g_strsplit(raw != NULL ? raw : "", "\n", -1);
    GPtrArray *bridges = g_ptr_array_new_with_free_func(g_free);
    for (guint i = 0; rows != NULL && rows[i] != NULL; i++) {
        char *line = g_strdup(rows[i]);
        g_strstrip(line);
        if (line[0] != '\0') g_ptr_array_add(bridges, line); else g_free(line);
    }
    g_strfreev(rows);
    g_free(raw);
    if (bridges->len < 1 || bridges->len > 8) {
        if (validation_error != NULL) *validation_error = g_strdup("Paste between one and eight Tor bridge lines.");
        g_ptr_array_unref(bridges);
        return NULL;
    }
    if (transport == NULL || kill == NULL || (g_strcmp0(kill, "off") != 0 && g_strcmp0(kill, "on-connect") != 0 && g_strcmp0(kill, "always") != 0)) {
        if (validation_error != NULL) *validation_error = g_strdup("Choose a Tor transport and kill-switch policy.");
        g_ptr_array_unref(bridges);
        return NULL;
    }

    JsonNode *transport_node = caps != NULL && json_object_has_member(caps, "transports") ? json_object_get_member(caps, "transports") : NULL;
    JsonArray *transports = transport_node != NULL && JSON_NODE_HOLDS_ARRAY(transport_node) ? json_node_get_array(transport_node) : NULL;
    JsonObject *capability = NULL; guint matches = 0;
    for (guint i = 0; transports != NULL && i < json_array_get_length(transports); i++) {
        JsonNode *item = json_array_get_element(transports, i);
        JsonObject *row = item != NULL && JSON_NODE_HOLDS_OBJECT(item) ? json_node_get_object(item) : NULL;
        if (g_strcmp0(external_path_string_v4(row, "id"), transport) == 0) { capability = row; matches++; }
    }
    gboolean direct = external_path_flag_v4(capability, "strict_kill_switch") && bridges->len == 1;
    gboolean router_path = profile != NULL && linux_tor_router_path_v13(state, profile);
    const char *execution = external_path_string_v4(profile, "multihop_execution");
    if (profile != NULL && ((execution[0] && g_strcmp0(execution, "local") != 0 && g_strcmp0(execution, "server") != 0) ||
                            (g_strcmp0(execution, "server") == 0 && !router_path))) {
        if (validation_error != NULL) *validation_error = g_strdup("Tor bridge updates require Local execution or explicit Server execution through a saved Router entry. Compare both requires separate measured candidate paths.");
        g_ptr_array_unref(bridges); return NULL;
    }
    gboolean router = router_path && external_path_flag_v4(capability, "strict_router_entry_kill_switch");
    if (matches != 1 || (g_strcmp0(kill, "off") != 0 && !direct && !router)) {
        if (validation_error != NULL) *validation_error = g_strdup(matches != 1 ? "Refresh Tor transport support before saving." : "This bridge selection needs a saved Router entry using Local or Server execution for strict protection. Save a new Direct node with Kill switch Off, then configure its entry before enabling protection in Settings.");
        g_ptr_array_unref(bridges); return NULL;
    }

    JsonBuilder *builder = json_builder_new();
    json_builder_begin_object(builder);
    if (update_id != NULL) {
        json_builder_set_member_name(builder, "profile_id");
        json_builder_add_string_value(builder, update_id);
    }
    json_builder_set_member_name(builder, "name");
    json_builder_add_string_value(builder, name != NULL ? name : "");
    json_builder_set_member_name(builder, "transport");
    json_builder_add_string_value(builder, transport);
    json_builder_set_member_name(builder, "kill_switch_policy");
    json_builder_add_string_value(builder, kill);
    json_builder_set_member_name(builder, "bridges");
    json_builder_begin_array(builder);
    for (guint i = 0; i < bridges->len; i++) json_builder_add_string_value(builder, g_ptr_array_index(bridges, i));
    json_builder_end_array(builder);
    json_builder_end_object(builder);
    JsonNode *root = json_builder_get_root(builder);
    JsonGenerator *generator = json_generator_new();
    json_generator_set_root(generator, root);
    char *payload = json_generator_to_data(generator, NULL);
    g_object_unref(generator);
    json_node_free(root);
    g_object_unref(builder);
    g_ptr_array_unref(bridges);
    if (update_id != NULL) {
        char *captured = external_captured_body_v24(payload, state->opened, current, validation_error);
        g_free(payload);
        if (captured == NULL) return NULL;
        g_autoptr(JsonNode) captured_node = parse_json(captured); g_free(captured);
        JsonObject *captured_object = json_node_get_object(captured_node);
        json_object_remove_member(captured_object, "profile_id");
        json_object_set_string_member(captured_object, "id", update_id);
        generator = json_generator_new(); json_generator_set_root(generator, captured_node);
        payload = json_generator_to_data(generator, NULL); g_object_unref(generator);
    }
    return payload;
}

static gboolean linux_tor_save_v13(LinuxTorBridgeV13 *state) {
    char *validation = NULL;
    if (!linux_tor_mutation_idle_v13(state->app, &validation)) {
        linux_tor_status_v13(state, validation != NULL ? validation : "Disconnect before updating Tor bridges."); g_free(validation); return FALSE;
    }
    char *payload = linux_tor_payload_v13(state, NULL, &validation);
    if (payload == NULL) {
        linux_tor_status_v13(state, validation != NULL ? validation : "Invalid Tor bridge form.");
        g_free(validation);
        return FALSE;
    }
    Buffer out = {0};
    char *err = NULL;
    if (state->update_selected != NULL && gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(state->update_selected))) {
        gboolean read = api_request("/api/nodes", "GET", NULL, 5000, &out, &err);
        g_autoptr(JsonNode) current = read ? parse_json(out.data) : NULL;
        free(out.data); out = (Buffer){0}; g_free(err); err = NULL;
        g_free(payload); payload = NULL;
        if (current != NULL) payload = linux_tor_payload_v13(state, current, &validation);
        if (payload == NULL) {
            linux_tor_status_v13(state, validation != NULL ? validation : "The current node catalog is unavailable. Nothing was saved."); g_free(validation); return FALSE;
        }
    }
    gboolean ok = api_request("/api/tor-bridge/import", "POST", payload, 25000, &out, &err);
    g_free(payload);
    if (!ok) {
        char *message = g_strdup_printf("Tor node rejected: %s", err != NULL ? err : "unknown error");
        linux_tor_status_v13(state, message);
        g_free(message);
        g_free(err);
        free(out.data);
        return FALSE;
    }
    gboolean updating = state->update_selected != NULL && gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(state->update_selected));
    linux_tor_status_v13(state, updating ? "Selected Tor bridge node updated. Its DNS choice is preserved." : "Tor bridge node saved. Before connecting, choose Custom TCP, DoT, DoH or Rescue in DNS.");
    append_diag(state->app, updating ? "Updated selected Tor censorship bridge profile without exposing prior private relay lines." : "Saved validated Tor censorship bridge profile (obfs4/meek/Snowflake/WebTunnel/Custom).");
    refresh_all(state->app);
    g_free(err);
    free(out.data);
    return TRUE;
}

static void on_linux_tor_bridge_v13(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    if (app == NULL) return;
    char *blocked_reason = NULL;
    if (!linux_tor_mutation_idle_v13(app, &blocked_reason)) {
        append_diag(app, blocked_reason != NULL ? blocked_reason : "Tor profile mutation is locked while Router VPN is connected or transitioning.");
        g_free(blocked_reason);
        return;
    }
    g_free(blocked_reason);

    LinuxTorBridgeV13 state = {0};
    state.app = app;
    JsonNode *displayed = app->window != NULL ? g_object_get_data(G_OBJECT(app->window), "router-vpn-source-catalog-v24") : NULL;
    state.opened = displayed != NULL ? copy_public_source_value_v24(displayed) : NULL;
    if (state.opened != NULL && JSON_NODE_HOLDS_OBJECT(state.opened) && g_strcmp0(external_source_selection_v24(json_node_get_object(state.opened)), active_router_id(app)) != 0) {
        append_diag(app, "Refresh the displayed node selection before opening Tor bridge controls."); json_node_free(state.opened); return;
    }
    state.dialog = gtk_dialog_new_with_buttons(
        "Tor censorship circumvention", GTK_WINDOW(app->window),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "Cancel", GTK_RESPONSE_CANCEL,
        "Refresh support", 1001,
        "Save Tor node", GTK_RESPONSE_ACCEPT,
        NULL);
    gtk_window_set_default_size(GTK_WINDOW(state.dialog), 760, 730);
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(state.dialog));
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(box), 16);

    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<span size='xx-large' weight='bold'>Tor bridges</span>");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_box_pack_start(GTK_BOX(box), title, FALSE, FALSE, 0);
    GtkWidget *intro = gtk_label_new("Choose how Tor gets through censorship. obfs4 disguises bridge traffic; meek uses HTTPS fronts; Snowflake uses volunteer proxies; WebTunnel resembles HTTPS traffic. Auto / Custom accepts Tor-issued bridge sets. Before connecting a new Tor node, choose Custom TCP, DoT, DoH or Rescue in DNS. Updating a saved node keeps its DNS choice.");
    gtk_label_set_line_wrap(GTK_LABEL(intro), TRUE);
    gtk_label_set_xalign(GTK_LABEL(intro), 0.0f);
    gtk_box_pack_start(GTK_BOX(box), intro, FALSE, FALSE, 0);

    state.name = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(state.name), "Node name (optional)");
    gtk_box_pack_start(GTK_BOX(box), state.name, FALSE, FALSE, 0);
    JsonObject *captured_profile = linux_tor_update_profile_v13(&state);
    g_autofree char *update_label = captured_profile != NULL ? g_strdup_printf("Update %s (paste replacement bridge lines below)", external_path_string_v4(captured_profile, "name")) : g_strdup("Update the Tor node selected when this dialog opened");
    state.update_selected = gtk_check_button_new_with_label(update_label);
    gtk_widget_set_sensitive(state.update_selected, captured_profile != NULL);
    gtk_widget_set_tooltip_text(state.update_selected, "Updates retain the displayed Tor node and entry revisions. Reopen this dialog after changing or relinking either node. Paste replacement bridge lines; existing private lines are never read back.");
    gtk_box_pack_start(GTK_BOX(box), state.update_selected, FALSE, FALSE, 0);

    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    state.transport = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.transport), "obfs4", "obfs4");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.transport), "meek_lite", "meek / meek_lite");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.transport), "snowflake", "Snowflake");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.transport), "webtunnel", "WebTunnel");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.transport), "custom", "Auto / Custom");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(state.transport), "obfs4");
    gtk_box_pack_start(GTK_BOX(row), state.transport, TRUE, TRUE, 0);
    state.kill = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.kill), "off", "Kill switch Off");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.kill), "on-connect", "Kill switch On connect");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.kill), "always", "Kill switch Always / strict");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(state.kill), "off");
    gtk_box_pack_start(GTK_BOX(row), state.kill, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(box), row, FALSE, FALSE, 0);

    GtkWidget *line_label = gtk_label_new("Tor bridge lines — one per line");
    gtk_label_set_xalign(GTK_LABEL(line_label), 0.0f);
    gtk_box_pack_start(GTK_BOX(box), line_label, FALSE, FALSE, 0);
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(scroll, -1, 230);
    state.lines = gtk_text_view_new();
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(state.lines), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(state.lines), GTK_WRAP_NONE);
    gtk_container_add(GTK_CONTAINER(scroll), state.lines);
    gtk_box_pack_start(GTK_BOX(box), scroll, TRUE, TRUE, 0);

    GtkWidget *safety = gtk_label_new("Paste current lines from Tor or a trusted bridge source. Router VPN accepts only obfs4, meek_lite, Snowflake, and WebTunnel syntax. Dynamic transports use a saved Router entry with Local or Server execution for strict protection. Save new Direct nodes with Kill switch Off, then configure their entry before enabling protection in Settings.");
    gtk_label_set_line_wrap(GTK_LABEL(safety), TRUE);
    gtk_label_set_xalign(GTK_LABEL(safety), 0.0f);
    gtk_box_pack_start(GTK_BOX(box), safety, FALSE, FALSE, 0);

    state.capability = gtk_label_new("Checking Tor transport support…");
    gtk_label_set_line_wrap(GTK_LABEL(state.capability), TRUE);
    gtk_label_set_xalign(GTK_LABEL(state.capability), 0.0f);
    gtk_box_pack_start(GTK_BOX(box), state.capability, FALSE, FALSE, 0);
    state.status = gtk_label_new("");
    gtk_label_set_line_wrap(GTK_LABEL(state.status), TRUE);
    gtk_label_set_xalign(GTK_LABEL(state.status), 0.0f);
    gtk_box_pack_start(GTK_BOX(box), state.status, FALSE, FALSE, 0);
    g_signal_connect(state.update_selected, "toggled", G_CALLBACK(linux_tor_update_changed_v13), &state);

    gtk_box_pack_start(GTK_BOX(content), box, TRUE, TRUE, 0);
    gtk_widget_show_all(state.dialog);
    linux_tor_refresh_caps_v13(&state);
    while (TRUE) {
        int response = gtk_dialog_run(GTK_DIALOG(state.dialog));
        if (response == 1001) {
            linux_tor_refresh_caps_v13(&state);
            continue;
        }
        if (response == GTK_RESPONSE_ACCEPT) {
            if (linux_tor_save_v13(&state)) break;
            continue;
        }
        break;
    }
    gtk_widget_destroy(state.dialog);
    g_clear_pointer(&state.opened, json_node_free);
    g_clear_pointer(&state.capabilities, json_node_free);
}
