/* CUSTOM choices and selected mode share one checked, atomic file publication.
 * This builder never changes node credentials and never treats Save as Connect. */
#include <errno.h>
#include <glib/gstdio.h>

static gboolean linux_custom_publish_v18(const char *editing, const char *name,
                                         const char *layers, gboolean deleting, GError **error) {
    char *path = linux_unified_preset_path_v8();
    GKeyFile *key = g_key_file_new();
    gboolean ok = FALSE;
    struct stat st;
    if (g_lstat(path, &st) == 0) {
        if (!S_ISREG(st.st_mode) || st.st_uid != getuid() || st.st_size > 512 * 1024) {
            g_set_error_literal(error, G_FILE_ERROR, G_FILE_ERROR_INVAL, "CUSTOM store is not an owned regular file.");
            goto done;
        }
        if (!g_key_file_load_from_file(key, path, G_KEY_FILE_KEEP_COMMENTS, error)) goto done;
        if (g_chmod(path, 0600) != 0) {
            g_set_error_literal(error, G_FILE_ERROR, G_FILE_ERROR_ACCES, "Cannot protect CUSTOM store permissions.");
            goto done;
        }
    } else if (errno != ENOENT) {
        g_set_error_literal(error, G_FILE_ERROR, G_FILE_ERROR_FAILED, "Cannot inspect CUSTOM store.");
        goto done;
    }
    if (editing != NULL && (deleting || g_strcmp0(editing, name) != 0)) {
        char *group = g_strconcat("preset:", editing, NULL);
        g_key_file_remove_group(key, group, NULL);
        g_free(group);
    }
    if (deleting) g_key_file_set_string(key, "state", "selected_mode", "smart-auto");
    else {
        char *group = g_strconcat("preset:", name, NULL);
        char *mode = g_strconcat("custom:", name, NULL);
        g_key_file_set_string(key, group, "layers", layers);
        g_key_file_set_string(key, "state", "selected_mode", mode);
        g_free(group); g_free(mode);
    }
    gsize length = 0;
    char *data = g_key_file_to_data(key, &length, error);
    if (data != NULL) {
        /* Also fsync a newly created file; do not start a connection after a
         * failed or unconfirmed write. GLib 2.66+ is present on build targets. */
        ok = g_file_set_contents_full(path, data, (gssize)length,
            G_FILE_SET_CONTENTS_CONSISTENT | G_FILE_SET_CONTENTS_DURABLE, 0600, error);
        g_free(data);
    }
done:
    g_key_file_unref(key); g_free(path);
    return ok;
}

static gboolean linux_custom_name_valid_v18(const char *name) {
    if (name == NULL || !g_utf8_validate(name, -1, NULL) || !name[0] ||
        g_utf8_strlen(name, -1) > 64 || g_ascii_strcasecmp(name, "new") == 0) return FALSE;
    for (const char *p = name; *p; p = g_utf8_next_char(p))
        if (g_unichar_iscntrl(g_utf8_get_char(p)) || strchr(":[]", *p) != NULL) return FALSE;
    return TRUE;
}

/* Inspect the authoritative selected node, not a stale combo box or an external
 * fallback. CUSTOM's single-node solver must not silently replace a hop graph. */
static gboolean linux_custom_connect_v18(LinuxUnifiedV8 *state, const char *layers) {
    if (!routervpn_require_mutation_idle(state->app, "starting the saved CUSTOM preset")) return FALSE;
    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(state->multihop))) {
        append_diag(state->app, "Preset saved. Save & Connect requires Multihop off; the selected hop graph was not replaced.");
        return FALSE;
    }
    Buffer out = {0}; char *error = NULL;
    gboolean linked = FALSE;
    if (api_request("/api/profiles", "GET", NULL, 3500, &out, &error)) {
        JsonNode *root = parse_json(out.data);
        if (root != NULL && JSON_NODE_HOLDS_OBJECT(root)) {
            JsonObject *obj = json_node_get_object(root);
            const char *selected = obj_string(obj, "selected_id");
            JsonNode *rows = json_object_get_member(obj, "profiles");
            JsonArray *profiles = rows && JSON_NODE_HOLDS_ARRAY(rows) ? json_node_get_array(rows) : NULL;
            for (guint i = 0; profiles && i < json_array_get_length(profiles); i++) {
                JsonNode *node = json_array_get_element(profiles, i);
                if (!JSON_NODE_HOLDS_OBJECT(node)) continue;
                JsonObject *profile = json_node_get_object(node);
                const char *kind = obj_string(profile, "node_kind");
                if (selected[0] && g_strcmp0(selected, obj_string(profile, "id")) == 0 &&
                    (!kind[0] || g_ascii_strcasecmp(kind, "router-vpn") == 0)) linked = TRUE;
            }
        }
        if (root != NULL) json_node_free(root);
    }
    g_free(error); free(out.data);
    if (!linked) {
        append_diag(state->app, "Preset saved. Select a verified Router VPN node before Save & Connect; no external or direct fallback was started.");
        return FALSE;
    }
    if (!routervpn_require_mutation_idle(state->app, "starting the saved CUSTOM preset")) return FALSE;
    char *body = strategy_custom_body_v7(layers);
    guint64 request = body ? linux_async_request_v17(state->app, "/api/strategy/custom", body,
        240000, "Saved CUSTOM preset; exact required layers", FALSE) : 0;
    g_free(body);
    if (request == 0) append_diag(state->app, "Preset saved, but its CUSTOM connection was not started.");
    return request != 0;
}

static void linux_custom_builder_v18(LinuxUnifiedV8 *state) {
    const char *id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->mode));
    char *selected = g_strdup(id ? id : "smart-auto");
    char *editing = g_str_has_prefix(selected, "custom:") && strcmp(selected, "custom:new") != 0 ? g_strdup(selected + 7) : NULL;
    char *old_layers = editing ? linux_unified_custom_layers_for_mode_v8(selected) : NULL;
    g_free(selected);
    GHashTable *old = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    if (old_layers) {
        char **parts = g_strsplit(old_layers, ",", -1);
        for (guint i = 0; parts[i]; i++) if (g_strstrip(parts[i])[0]) g_hash_table_add(old, g_strdup(parts[i]));
        g_strfreev(parts);
    }
    GtkWidget *dialog = gtk_dialog_new_with_buttons("CUSTOM preset builder", GTK_WINDOW(state->app->window),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT, "Cancel", GTK_RESPONSE_CANCEL,
        "Save", GTK_RESPONSE_ACCEPT, "Save & Connect", GTK_RESPONSE_APPLY, NULL);
    g_object_ref(dialog); g_object_ref(state->app->window);
    if (editing) gtk_dialog_add_button(GTK_DIALOG(dialog), "Delete", GTK_RESPONSE_REJECT);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 620, 620);
    GtkWidget *box = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_container_set_border_width(GTK_CONTAINER(box), 14);
    GtkWidget *note = gtk_label_new("Choose exact required layers. Only compatible native stacks passing selected-node proof may connect. Save never connects; Save & Connect requires a Router VPN node with Multihop off.");
    gtk_label_set_line_wrap(GTK_LABEL(note), TRUE); gtk_label_set_max_width_chars(GTK_LABEL(note), 60);
    gtk_box_pack_start(GTK_BOX(box), note, FALSE, FALSE, 8);
    GtkWidget *name = gtk_entry_new(); gtk_entry_set_placeholder_text(GTK_ENTRY(name), "Preset name");
    if (editing) gtk_entry_set_text(GTK_ENTRY(name), editing);
    gtk_box_pack_start(GTK_BOX(box), name, FALSE, FALSE, 6);
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL), *flow = gtk_flow_box_new();
    gtk_flow_box_set_selection_mode(GTK_FLOW_BOX(flow), GTK_SELECTION_NONE);
    gtk_flow_box_set_min_children_per_line(GTK_FLOW_BOX(flow), 1); gtk_flow_box_set_max_children_per_line(GTK_FLOW_BOX(flow), 3);
    gtk_container_add(GTK_CONTAINER(scroll), flow); gtk_box_pack_start(GTK_BOX(box), scroll, TRUE, TRUE, 6);
    GPtrArray *checks = g_ptr_array_new();
    for (guint i = 0; linux_custom_layers_v8[i]; i++) {
        GtkWidget *check = gtk_check_button_new_with_label(linux_custom_layers_v8[i]);
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(check), g_hash_table_contains(old, linux_custom_layers_v8[i]));
        g_object_set_data_full(G_OBJECT(check), "custom-layer-v18", g_strdup(linux_custom_layers_v8[i]), g_free);
        g_ptr_array_add(checks, check); gtk_container_add(GTK_CONTAINER(flow), check);
    }
    /* Editing on a different catalog must not silently discard required layers.
     * Keep unknown saved layers selected, label them, and let the user remove
     * them explicitly. Connection still requires the exact server solver. */
    GHashTableIter old_iter; gpointer old_layer;
    g_hash_table_iter_init(&old_iter, old);
    while (g_hash_table_iter_next(&old_iter, &old_layer, NULL)) {
        gboolean known = FALSE;
        for (guint i = 0; linux_custom_layers_v8[i]; i++) if (g_strcmp0(old_layer, linux_custom_layers_v8[i]) == 0) known = TRUE;
        if (known) continue;
        char *label = g_strdup_printf("%s — not in this catalog", (const char *)old_layer);
        GtkWidget *check = gtk_check_button_new_with_label(label); g_free(label);
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(check), TRUE);
        g_object_set_data_full(G_OBJECT(check), "custom-layer-v18", g_strdup(old_layer), g_free);
        g_ptr_array_add(checks, check); gtk_container_add(GTK_CONTAINER(flow), check);
    }
    /* Stable handles let the shipping UI acceptance drive these actual widgets. */
    g_object_set_data(G_OBJECT(dialog), "custom-name-v18", name);
    g_object_set_data(G_OBJECT(dialog), "custom-checks-v18", checks);
    gtk_widget_show_all(dialog);
    char *connect_layers = NULL;
    for (;;) {
        int response = gtk_dialog_run(GTK_DIALOG(dialog));
        if (response != GTK_RESPONSE_ACCEPT && response != GTK_RESPONSE_APPLY && response != GTK_RESPONSE_REJECT) break;
        if (!routervpn_require_mutation_idle(state->app, response == GTK_RESPONSE_REJECT ? "deleting a CUSTOM preset" : "saving a CUSTOM preset")) break;
        gboolean deleting = response == GTK_RESPONSE_REJECT;
        char *clean = g_strdup(gtk_entry_get_text(GTK_ENTRY(name))); g_strstrip(clean);
        GString *layers = g_string_new("");
        for (guint i = 0; i < checks->len; i++) if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(g_ptr_array_index(checks, i)))) {
            if (layers->len) g_string_append_c(layers, ',');
            g_string_append(layers, g_object_get_data(G_OBJECT(g_ptr_array_index(checks, i)), "custom-layer-v18"));
        }
        gboolean valid = deleting ? editing != NULL : linux_custom_name_valid_v18(clean) && layers->len != 0;
        GError *error = NULL;
        gboolean saved = valid && linux_custom_publish_v18(editing, clean, layers->str, deleting, &error);
        if (!saved) {
            const char *message = error ? error->message : "Use a safe 1–64 character name (not new) and at least one exact layer.";
            gtk_label_set_text(GTK_LABEL(note), message); append_diag(state->app, message);
        } else {
            append_diag(state->app, deleting ? "CUSTOM preset deleted." : "CUSTOM preset saved; choices only, never private node credentials.");
            if (response == GTK_RESPONSE_APPLY) connect_layers = g_strdup(layers->str);
        }
        g_clear_error(&error); g_free(clean); g_string_free(layers, TRUE);
        if (saved) break;
    }
    gtk_widget_destroy(dialog); g_ptr_array_unref(checks); g_hash_table_unref(old); g_free(editing); g_free(old_layers);
    LinuxAsyncActionsV16 *owner = linux_async_state_v16(state->app);
    if (owner != NULL && !owner->closed) {
        linux_unified_refresh_mode_combo_v8(state);
        if (connect_layers != NULL) (void)linux_custom_connect_v18(state, connect_layers);
    }
    g_free(connect_layers);
    g_object_unref(dialog); g_object_unref(state->app->window);
}
