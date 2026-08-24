/* Full non-secret connection profile CRUD for the Linux map-first shell. */
static gboolean linux_profile_selection_v11(gboolean *enabled, char **entry, char **exit, char **mode) {
    GKeyFile *key = linux_unified_load_keyfile_v8();
    GError *error = NULL;
    gboolean on = g_key_file_get_boolean(key, "connection-profile-selection", "enabled", &error);
    if (error != NULL) {
        g_error_free(error);
        error = NULL;
        on = FALSE;
    }
    char *a = g_key_file_get_string(key, "connection-profile-selection", "entry", NULL);
    char *b = g_key_file_get_string(key, "connection-profile-selection", "exit", NULL);
    char *m = g_key_file_get_string(key, "connection-profile-selection", "exit_mode", NULL);
    g_key_file_unref(key);
    if (m == NULL || (g_strcmp0(m, "shadowsocks") != 0 && g_strcmp0(m, "hysteria2") != 0)) {
        g_free(m);
        m = g_strdup("shadowsocks");
    }
    if (a == NULL) {
        a = g_strdup("");
    }
    if (b == NULL) {
        b = g_strdup("");
    }
    if (enabled != NULL) *enabled = on;
    if (entry != NULL) *entry = a; else g_free(a);
    if (exit != NULL) *exit = b; else g_free(b);
    if (mode != NULL) *mode = m; else g_free(m);
    return on;
}

static void linux_profile_store_selection_v11(gboolean enabled, const char *entry, const char *exit, const char *mode) {
    GKeyFile *key = linux_unified_load_keyfile_v8();
    g_key_file_set_boolean(key, "connection-profile-selection", "enabled", enabled);
    g_key_file_set_string(key, "connection-profile-selection", "entry", enabled && entry != NULL ? entry : "");
    g_key_file_set_string(key, "connection-profile-selection", "exit", enabled && exit != NULL ? exit : "");
    const char *safe_mode = mode != NULL && g_strcmp0(mode, "hysteria2") == 0 ? "hysteria2" : "shadowsocks";
    g_key_file_set_string(key, "connection-profile-selection", "exit_mode", enabled ? safe_mode : "shadowsocks");
    linux_unified_save_keyfile_v8(key);
    g_key_file_unref(key);
}

static GtkWidget *linux_profile_find_button_v11(GtkWidget *root, const char *label) {
    if (root == NULL) return NULL;
    if (GTK_IS_BUTTON(root) && g_strcmp0(gtk_button_get_label(GTK_BUTTON(root)), label) == 0) return root;
    if (!GTK_IS_CONTAINER(root)) return NULL;
    GList *children = gtk_container_get_children(GTK_CONTAINER(root));
    GtkWidget *found = NULL;
    for (GList *it = children; it != NULL && found == NULL; it = it->next) {
        found = linux_profile_find_button_v11(GTK_WIDGET(it->data), label);
    }
    g_list_free(children);
    return found;
}

static void linux_profile_apply_custom_v11(const char *mode, JsonArray *layers) {
    if (mode == NULL || !g_str_has_prefix(mode, "custom:") || layers == NULL || json_array_get_length(layers) == 0) return;
    const char *name = mode + strlen("custom:");
    if (name[0] == '\0') return;
    GString *joined = g_string_new("");
    for (guint i = 0; i < json_array_get_length(layers); i++) {
        const char *layer = json_array_get_string_element(layers, i);
        if (layer == NULL || layer[0] == '\0') continue;
        if (joined->len) g_string_append_c(joined, ',');
        g_string_append(joined, layer);
    }
    if (joined->len) {
        GKeyFile *key = linux_unified_load_keyfile_v8();
        char *group = g_strdup_printf("preset:%s", name);
        g_key_file_set_string(key, group, "layers", joined->str);
        linux_unified_save_keyfile_v8(key);
        g_key_file_unref(key);
        g_free(group);
    }
    g_string_free(joined, TRUE);
}

static char *linux_profile_setup_body_v11(LinuxUnifiedV8 *state, const char *name, const char *id, gboolean multihop, const char *entry, const char *exit, const char *exit_mode) {
    const char *selected_mode = gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->mode));
    if (selected_mode == NULL || selected_mode[0] == '\0' || g_strcmp0(selected_mode, "custom:new") == 0) selected_mode = "smart-auto";
    char *layers = linux_unified_custom_layers_for_mode_v8(selected_mode);
    JsonBuilder *builder = json_builder_new();
    json_builder_begin_object(builder);
    if (id != NULL && id[0]) {
        json_builder_set_member_name(builder, "id");
        json_builder_add_string_value(builder, id);
    }
    json_builder_set_member_name(builder, "name"); json_builder_add_string_value(builder, name != NULL ? name : "");
    json_builder_set_member_name(builder, "mode"); json_builder_add_string_value(builder, selected_mode);
    json_builder_set_member_name(builder, "custom_layers"); json_builder_begin_array(builder);
    if (layers != NULL) {
        gchar **parts = g_strsplit(layers, ",", -1);
        for (guint i = 0; parts != NULL && parts[i] != NULL; i++) {
            g_strstrip(parts[i]);
            if (parts[i][0]) json_builder_add_string_value(builder, parts[i]);
        }
        g_strfreev(parts);
    }
    json_builder_end_array(builder);
    json_builder_set_member_name(builder, "multihop_enabled"); json_builder_add_boolean_value(builder, multihop);
    json_builder_set_member_name(builder, "multihop_entry_id"); json_builder_add_string_value(builder, multihop && entry != NULL ? entry : "");
    json_builder_set_member_name(builder, "multihop_exit_id"); json_builder_add_string_value(builder, multihop && exit != NULL ? exit : "");
    json_builder_set_member_name(builder, "multihop_exit_mode"); json_builder_add_string_value(builder, multihop && g_strcmp0(exit_mode, "hysteria2") == 0 ? "hysteria2" : (multihop ? "shadowsocks" : ""));
    json_builder_end_object(builder);
    JsonNode *root = json_builder_get_root(builder);
    JsonGenerator *gen = json_generator_new();
    json_generator_set_root(gen, root);
    char *body = json_generator_to_data(gen, NULL);
    g_object_unref(gen);
    json_node_free(root);
    g_object_unref(builder);
    g_free(layers);
    return body;
}

static void linux_profile_populate_nodes_v11(GtkWidget *entry, GtkWidget *exit, const char *want_entry, const char *want_exit) {
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(entry));
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(exit));
    Buffer out = {0};
    char *err = NULL;
    if (api_request("/api/multihop/status", "GET", NULL, 6000, &out, &err)) {
        JsonNode *root = parse_json(out.data);
        if (root != NULL && JSON_NODE_HOLDS_OBJECT(root)) {
            JsonObject *obj = json_node_get_object(root);
            JsonArray *nodes = json_object_has_member(obj, "nodes") ? json_object_get_array_member(obj, "nodes") : NULL;
            for (guint i = 0; nodes != NULL && i < json_array_get_length(nodes); i++) {
                JsonObject *n = json_array_get_object_element(nodes, i);
                if (n == NULL) continue;
                const char *node_id = obj_string(n, "id");
                if (!node_id[0]) continue;
                const char *node_name = obj_string(n, "name");
                gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(entry), node_id, node_name[0] ? node_name : node_id);
                gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(exit), node_id, node_name[0] ? node_name : node_id);
            }
            json_node_free(root);
        }
    }
    g_free(err);
    free(out.data);
    if (want_entry != NULL && want_entry[0]) gtk_combo_box_set_active_id(GTK_COMBO_BOX(entry), want_entry); else gtk_combo_box_set_active(GTK_COMBO_BOX(entry), 0);
    if (want_exit != NULL && want_exit[0]) gtk_combo_box_set_active_id(GTK_COMBO_BOX(exit), want_exit); else gtk_combo_box_set_active(GTK_COMBO_BOX(exit), 1);
}

static void linux_profile_populate_saved_v11(GtkWidget *combo) {
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(combo));
    Buffer out = {0};
    char *err = NULL;
    if (api_request("/api/connection-profiles", "GET", NULL, 5000, &out, &err)) {
        JsonNode *root = parse_json(out.data);
        if (root != NULL && JSON_NODE_HOLDS_OBJECT(root)) {
            JsonObject *obj = json_node_get_object(root);
            JsonArray *profiles = json_object_has_member(obj, "profiles") ? json_object_get_array_member(obj, "profiles") : NULL;
            for (guint i = 0; profiles != NULL && i < json_array_get_length(profiles); i++) {
                JsonObject *p = json_array_get_object_element(profiles, i);
                if (p == NULL) continue;
                const char *id = obj_string(p, "id");
                if (!id[0]) continue;
                char *label = g_strdup_printf("%s • %s • %s", obj_string(p, "name"), obj_string(p, "mode"), obj_string(p, "node_id"));
                gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo), id, label);
                g_free(label);
            }
            json_node_free(root);
        }
    }
    g_free(err);
    free(out.data);
    if (gtk_tree_model_iter_n_children(gtk_combo_box_get_model(GTK_COMBO_BOX(combo)), NULL) > 0) gtk_combo_box_set_active(GTK_COMBO_BOX(combo), 0);
}

static void linux_profile_manager_v11(GtkButton *button, gpointer data) {
    (void)button;
    LinuxUnifiedV8 *state = data;
    if (state == NULL) return;
    GtkWidget *dialog = gtk_dialog_new_with_buttons("Connection profiles", GTK_WINDOW(state->app->window), GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT, "Close", GTK_RESPONSE_CLOSE, "Delete", 4, "Update", 3, "Add current", 2, "Load", 1, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 650, 430);
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(box), 14);
    GtkWidget *note = gtk_label_new("Profiles save the selected node plus current Mode/CUSTOM layers, DNS, kill switch, IPv6, WG/AWG base/fallback, AUTO encryption/obfuscation requirements, MTU and an exact staged multihop Entry -> Exit -> exit transport. Node keys/API tokens/credentials stay in the linked private node stores. Load never connects automatically.");
    gtk_label_set_line_wrap(GTK_LABEL(note), TRUE);
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    gtk_box_pack_start(GTK_BOX(box), note, FALSE, FALSE, 0);
    GtkWidget *name = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(name), "Profile name");
    gtk_box_pack_start(GTK_BOX(box), name, FALSE, FALSE, 0);
    GtkWidget *saved = gtk_combo_box_text_new();
    linux_profile_populate_saved_v11(saved);
    gtk_box_pack_start(GTK_BOX(box), saved, FALSE, FALSE, 0);
    gboolean staged = FALSE;
    char *staged_entry = NULL, *staged_exit = NULL, *staged_mode = NULL;
    linux_profile_selection_v11(&staged, &staged_entry, &staged_exit, &staged_mode);
    GtkWidget *multi = gtk_check_button_new_with_label("Save/restore exact multihop graph");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(multi), staged || gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(state->multihop)));
    gtk_box_pack_start(GTK_BOX(box), multi, FALSE, FALSE, 0);
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 6);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    GtkWidget *entry = gtk_combo_box_text_new();
    GtkWidget *exit = gtk_combo_box_text_new();
    GtkWidget *mode = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(mode), "shadowsocks", "Shadowsocks exit");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(mode), "hysteria2", "Hysteria2 exit");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(mode), g_strcmp0(staged_mode, "hysteria2") == 0 ? "hysteria2" : "shadowsocks");
    linux_profile_populate_nodes_v11(entry, exit, staged_entry, staged_exit);
    profile_settings_grid_row_v7(grid, 0, "Entry", entry);
    profile_settings_grid_row_v7(grid, 1, "Exit", exit);
    profile_settings_grid_row_v7(grid, 2, "Exit transport", mode);
    gtk_box_pack_start(GTK_BOX(box), grid, FALSE, FALSE, 0);
    GtkWidget *status = gtk_label_new("Choose Add/Load/Update/Delete. Connect remains separate.");
    gtk_label_set_xalign(GTK_LABEL(status), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(status), TRUE);
    gtk_box_pack_start(GTK_BOX(box), status, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(content), box, TRUE, TRUE, 0);
    gtk_widget_show_all(dialog);

    for (;;) {
        int response = gtk_dialog_run(GTK_DIALOG(dialog));
        if (response == GTK_RESPONSE_CLOSE || response == GTK_RESPONSE_DELETE_EVENT) break;
        const char *id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(saved));
        const char *profile_name = gtk_entry_get_text(GTK_ENTRY(name));
        gboolean on = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(multi));
        const char *entry_id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(entry));
        const char *exit_id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(exit));
        const char *exit_mode = gtk_combo_box_get_active_id(GTK_COMBO_BOX(mode));
        Buffer out = {0};
        char *err = NULL;
        char *body = NULL;
        const char *path = NULL;
        if (response == 1) {
            if (id == NULL || !id[0]) { gtk_label_set_text(GTK_LABEL(status), "Select a saved profile first."); continue; }
            body = json_string_body("id", id);
            path = "/api/connection-profile/setup/load";
        } else if (response == 4) {
            if (id == NULL || !id[0]) { gtk_label_set_text(GTK_LABEL(status), "Select a saved profile first."); continue; }
            body = json_string_body("id", id);
            path = "/api/connection-profile/setup/delete";
        } else {
            if (profile_name == NULL || profile_name[0] == '\0') { gtk_label_set_text(GTK_LABEL(status), "Enter a profile name."); continue; }
            if (response == 3 && (id == NULL || !id[0])) { gtk_label_set_text(GTK_LABEL(status), "Select a profile to update."); continue; }
            body = linux_profile_setup_body_v11(state, profile_name, response == 3 ? id : NULL, on, entry_id, exit_id, exit_mode);
            path = response == 3 ? "/api/connection-profile/setup/update" : "/api/connection-profile/setup/save";
        }
        if (api_request(path, "POST", body, 15000, &out, &err)) {
            if (response == 1) {
                JsonNode *root = parse_json(out.data);
                if (root != NULL && JSON_NODE_HOLDS_OBJECT(root)) {
                    JsonObject *obj = json_node_get_object(root);
                    const char *loaded_mode = obj_string(obj, "mode");
                    gboolean loaded_on = json_object_has_member(obj, "multihop_enabled") && json_object_get_boolean_member(obj, "multihop_enabled");
                    const char *loaded_entry = obj_string(obj, "multihop_entry_id");
                    const char *loaded_exit = obj_string(obj, "multihop_exit_id");
                    const char *loaded_exit_mode = obj_string(obj, "multihop_exit_mode");
                    JsonArray *layers = json_object_has_member(obj, "custom_layers") ? json_object_get_array_member(obj, "custom_layers") : NULL;
                    linux_profile_apply_custom_v11(loaded_mode, layers);
                    linux_unified_store_mode_v8(loaded_mode[0] ? loaded_mode : "smart-auto");
                    linux_profile_store_selection_v11(loaded_on, loaded_entry, loaded_exit, loaded_exit_mode);
                    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(state->multihop), loaded_on);
                    linux_unified_refresh_mode_combo_v8(state);
                    linux_unified_refresh_v8(state);
                    gtk_label_set_text(GTK_LABEL(status), "Loaded exact choices. Connect separately to establish and prove the real path.");
                    json_node_free(root);
                } else {
                    gtk_label_set_text(GTK_LABEL(status), "Loaded profile response was invalid; staged UI state was not changed.");
                    if (root != NULL) json_node_free(root);
                }
            } else if (response == 4) {
                linux_profile_populate_saved_v11(saved);
                gtk_label_set_text(GTK_LABEL(status), "Deleted reusable profile; linked nodes were not removed.");
            } else {
                linux_profile_store_selection_v11(on, entry_id, exit_id, exit_mode);
                gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(state->multihop), on);
                linux_profile_populate_saved_v11(saved);
                gtk_label_set_text(GTK_LABEL(status), response == 3 ? "Updated exact setup." : "Added exact setup.");
            }
        } else {
            gtk_label_set_text(GTK_LABEL(status), err != NULL ? err : "Connection profile operation failed.");
        }
        free(out.data);
        g_free(err);
        g_free(body);
    }
    gtk_widget_destroy(dialog);
    g_free(staged_entry);
    g_free(staged_exit);
    g_free(staged_mode);
}

static void linux_profile_choose_hops_v11(GtkButton *button, gpointer data) {
    LinuxUnifiedV8 *state = data;
    linux_profile_store_selection_v11(FALSE, "", "", "shadowsocks");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(state->multihop), TRUE);
    linux_unified_multihop_v8(button, state);
}

static gboolean linux_profile_runtime_active_v11(void) {
    Buffer out = {0};
    char *err = NULL;
    gboolean active = FALSE;
    if (api_request("/api/status", "GET", NULL, 3500, &out, &err)) {
        JsonNode *root = parse_json(out.data);
        if (root != NULL && JSON_NODE_HOLDS_OBJECT(root)) {
            JsonObject *obj = json_node_get_object(root);
            gboolean connected = json_object_has_member(obj, "connected") && json_object_get_boolean_member(obj, "connected");
            const char *phase = obj_string(obj, "phase");
            active = connected || g_str_has_prefix(phase, "starting") || g_str_has_prefix(phase, "checking") || strstr(phase, "trying") != NULL || strstr(phase, "proving") != NULL;
            json_node_free(root);
        }
    }
    g_free(err);
    free(out.data);
    return active;
}

static void linux_profile_connect_v11(GtkButton *button, gpointer data) {
    LinuxUnifiedV8 *state = data;
    if (state == NULL) return;
    /* Active/transitioning always delegates to the mature Connect/Disconnect path first. */
    if (linux_profile_runtime_active_v11()) {
        linux_unified_connect_v8(button, data);
        return;
    }
    if (!gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(state->multihop))) {
        linux_unified_connect_v8(button, data);
        return;
    }
    gboolean enabled = FALSE;
    char *entry = NULL, *exit = NULL, *mode = NULL;
    linux_profile_selection_v11(&enabled, &entry, &exit, &mode);
    if (!enabled || entry == NULL || exit == NULL || !entry[0] || !exit[0] || g_strcmp0(entry, exit) == 0) {
        g_free(entry); g_free(exit); g_free(mode);
        linux_unified_connect_v8(button, data);
        return;
    }
    JsonBuilder *builder = json_builder_new();
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "entry_id"); json_builder_add_string_value(builder, entry);
    json_builder_set_member_name(builder, "exit_id"); json_builder_add_string_value(builder, exit);
    json_builder_set_member_name(builder, "exit_mode"); json_builder_add_string_value(builder, g_strcmp0(mode, "hysteria2") == 0 ? "hysteria2" : "shadowsocks");
    json_builder_end_object(builder);
    JsonNode *root = json_builder_get_root(builder);
    JsonGenerator *gen = json_generator_new();
    json_generator_set_root(gen, root);
    char *body = json_generator_to_data(gen, NULL);
    post_and_log(state->app, "/api/multihop/connect", body, 180000, "Loaded connection-profile multihop");
    g_free(body);
    g_object_unref(gen);
    json_node_free(root);
    g_object_unref(builder);
    g_free(entry); g_free(exit); g_free(mode);
}

static void linux_install_connection_profiles_v11(App *app) {
    LinuxUnifiedV8 *state = app != NULL ? g_object_get_data(G_OBJECT(app->window), "linux-unified-v8") : NULL;
    if (state == NULL) return;
    GtkWidget *settings = linux_profile_find_button_v11(state->stack, "Open settings");
    if (settings != NULL && gtk_widget_get_parent(settings) != NULL) {
        gtk_box_pack_start(GTK_BOX(gtk_widget_get_parent(settings)), make_button("Profiles", G_CALLBACK(linux_profile_manager_v11), state), FALSE, FALSE, 0);
    }
    GtkWidget *choose = linux_profile_find_button_v11(state->stack, "Choose hops");
    if (choose != NULL) {
        g_signal_handlers_disconnect_by_func(choose, G_CALLBACK(linux_unified_multihop_v8), state);
        g_signal_connect(choose, "clicked", G_CALLBACK(linux_profile_choose_hops_v11), state);
    }
    g_signal_handlers_disconnect_by_func(state->connect, G_CALLBACK(linux_unified_connect_v8), state);
    g_signal_connect(state->connect, "clicked", G_CALLBACK(linux_profile_connect_v11), state);
    gboolean enabled = FALSE;
    char *entry = NULL, *exit = NULL, *mode = NULL;
    linux_profile_selection_v11(&enabled, &entry, &exit, &mode);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(state->multihop), enabled);
    g_free(entry); g_free(exit); g_free(mode);
}

/* Linux v11 Profiles contract: Add/Load/Update/Delete exact non-secret setup; current Mode/CUSTOM layers;
 * staged exact entry/exit/exit-transport survives load and main Connect uses it directly; opening Choose hops clears staged profile ownership;
 * active/transitioning Connect always delegates to mature Disconnect handling; loading never auto-connects;
 * node secrets remain in the linked private Router/custom stores. */
