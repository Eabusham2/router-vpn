/* Public references for the native ordered path. Private sources remain in the
 * controller. This include is composed after the unified shell, before Profiles. */
typedef struct {
    char *control;
    JsonArray *nodes;
    JsonObject *tokens;
} LinuxOrderedSelectionV1;

typedef struct {
    LinuxUnifiedV8 *unified;
    LinuxOrderedSelectionV1 *selection;
    GtkWidget *node, *mode, *multihop;
    guint64 generation;
    gboolean invalid, applying;
} LinuxOrderedStateV1;

static const char *linux_ordered_string_v1(JsonObject *object, const char *key) {
    JsonNode *value = object != NULL && json_object_has_member(object, key) ? json_object_get_member(object, key) : NULL;
    return value != NULL && JSON_NODE_HOLDS_VALUE(value) && json_node_get_value_type(value) == G_TYPE_STRING ? json_node_get_string(value) : "";
}

static gboolean linux_ordered_flag_v1(JsonObject *object, const char *key) {
    JsonNode *value = object != NULL && json_object_has_member(object, key) ? json_object_get_member(object, key) : NULL;
    return value != NULL && JSON_NODE_HOLDS_VALUE(value) && json_node_get_value_type(value) == G_TYPE_BOOLEAN && json_node_get_boolean(value);
}

static JsonObject *linux_ordered_object_v1(JsonObject *object, const char *key) {
    JsonNode *value = object != NULL && json_object_has_member(object, key) ? json_object_get_member(object, key) : NULL;
    return value != NULL && JSON_NODE_HOLDS_OBJECT(value) ? json_node_get_object(value) : NULL;
}

static JsonArray *linux_ordered_array_v1(JsonObject *object, const char *key) {
    JsonNode *value = object != NULL && json_object_has_member(object, key) ? json_object_get_member(object, key) : NULL;
    return value != NULL && JSON_NODE_HOLDS_ARRAY(value) ? json_node_get_array(value) : NULL;
}

static char *linux_ordered_json_v1(JsonObject *object) {
    JsonNode *root = json_node_new(JSON_NODE_OBJECT);
    json_node_set_object(root, object);
    JsonGenerator *generator = json_generator_new();
    json_generator_set_root(generator, root);
    char *raw = json_generator_to_data(generator, NULL);
    g_object_unref(generator); json_node_free(root);
    return raw;
}

static gboolean linux_ordered_prefix_v1(const char *mode) {
    return g_strcmp0(mode, "wg") == 0 || g_strcmp0(mode, "awg2-fast") == 0 || g_strcmp0(mode, "awg2-strong") == 0;
}

static gboolean linux_ordered_final_v1(const char *mode) {
    return g_strcmp0(mode, "shadowsocks") == 0 || g_strcmp0(mode, "hysteria2") == 0;
}

static const char *linux_ordered_mode_name_v1(const char *mode) {
    if (g_strcmp0(mode, "wg") == 0) return "WireGuard";
    if (g_strcmp0(mode, "awg2-fast") == 0) return "AWG2 Fast";
    if (g_strcmp0(mode, "awg2-strong") == 0) return "AWG2 Strong";
    if (g_strcmp0(mode, "shadowsocks") == 0) return "Shadowsocks 2022";
    if (g_strcmp0(mode, "socks5") == 0) return "SOCKS5";
    if (g_strcmp0(mode, "hysteria2") == 0) return "Hysteria2";
    return "Unavailable transport";
}

static void linux_ordered_selection_free_v1(LinuxOrderedSelectionV1 *selection) {
    if (selection == NULL) return;
    g_free(selection->control);
    json_array_unref(selection->nodes); json_object_unref(selection->tokens); g_free(selection);
}

static gboolean linux_ordered_rows_v1(JsonArray *nodes, const char *control) {
    guint count = nodes != NULL ? json_array_get_length(nodes) : 0;
    if (count < 2 || count > 8 || !external_source_id_v24(control)) return FALSE;
    gboolean imported_middle = FALSE;
    for (guint i = 0; i < count; i++) {
        JsonNode *value = json_array_get_element(nodes, i);
        if (value == NULL || !JSON_NODE_HOLDS_OBJECT(value)) return FALSE;
        JsonObject *row = json_node_get_object(value);
        const char *id = linux_ordered_string_v1(row, "id"), *mode = linux_ordered_string_v1(row, "mode");
        if (json_object_get_size(row) != 2 || !external_source_id_v24(id) ||
            (i + 1 == count ? !linux_ordered_final_v1(mode) || strcmp(id, control) != 0 : !linux_ordered_prefix_v1(mode) && !(count == 3 && i == 1 && (strcmp(mode, "shadowsocks") == 0 || strcmp(mode, "socks5") == 0)))) return FALSE;
        if (i + 1 < count && (strcmp(mode, "shadowsocks") == 0 || strcmp(mode, "socks5") == 0)) imported_middle = TRUE;
        for (guint j = 0; j < i; j++)
            if (strcmp(id, linux_ordered_string_v1(json_array_get_object_element(nodes, j), "id")) == 0) return FALSE;
    }
    return !imported_middle || strcmp(linux_ordered_string_v1(json_array_get_object_element(nodes, count - 1), "mode"), "shadowsocks") == 0;
}

static LinuxOrderedSelectionV1 *linux_ordered_selection_v1(const char *control, JsonArray *nodes, JsonObject *tokens) {
    if (!linux_ordered_rows_v1(nodes, control) || tokens == NULL || json_object_get_size(tokens) != json_array_get_length(nodes)) return NULL;
    LinuxOrderedSelectionV1 *selection = g_new0(LinuxOrderedSelectionV1, 1);
    selection->control = g_strdup(control); selection->nodes = json_array_new(); selection->tokens = json_object_new();
    for (guint i = 0; i < json_array_get_length(nodes); i++) {
        JsonObject *row = json_array_get_object_element(nodes, i);
        const char *id = linux_ordered_string_v1(row, "id"), *token = linux_ordered_string_v1(tokens, id);
        if (!external_source_token_v24(token)) { linux_ordered_selection_free_v1(selection); return NULL; }
        JsonObject *copy = json_object_new();
        json_object_set_string_member(copy, "id", id); json_object_set_string_member(copy, "mode", linux_ordered_string_v1(row, "mode"));
        json_array_add_object_element(selection->nodes, copy);
        json_object_set_string_member(selection->tokens, id, token);
    }
    return selection;
}

static LinuxOrderedSelectionV1 *linux_ordered_decode_v1(JsonObject *object) {
    if (object == NULL || json_object_get_size(object) != 3) return NULL;
    return linux_ordered_selection_v1(linux_ordered_string_v1(object, "selected_node_id"),
        linux_ordered_array_v1(object, "nodes"), linux_ordered_object_v1(object, "profile_tokens"));
}

static gboolean linux_ordered_router_v1(JsonObject *profile) {
    if (profile == NULL || json_object_has_member(profile, "external")) return FALSE;
    if (!json_object_has_member(profile, "node_kind")) return TRUE;
    JsonNode *kind = json_object_get_member(profile, "node_kind");
    if (kind == NULL || !JSON_NODE_HOLDS_VALUE(kind) || json_node_get_value_type(kind) != G_TYPE_STRING) return FALSE;
    const char *value = json_node_get_string(kind);
    return value != NULL && (!value[0] || strcmp(value, "router-vpn") == 0);
}

static gboolean linux_ordered_final_profile_v1(JsonObject *profile, const char *mode) {
    if (!linux_ordered_router_v1(profile) || !linux_ordered_final_v1(mode)) return FALSE;
    if (strcmp(mode, "shadowsocks") == 0) return TRUE;
    if (!json_object_has_member(profile, "start_layer")) return TRUE;
    JsonNode *layer = json_object_get_member(profile, "start_layer");
    if (layer == NULL || !JSON_NODE_HOLDS_VALUE(layer) || json_node_get_value_type(layer) != G_TYPE_STRING) return FALSE;
    const char *value = json_node_get_string(layer);
    return value != NULL && (!value[0] || strcmp(value, "off") == 0);
}

static const char *linux_ordered_imported_mode_v1(JsonObject *profile) {
    JsonObject *external = linux_ordered_object_v1(profile, "external");
    const char *protocol = linux_ordered_string_v1(external, "protocol");
    if (strcmp(linux_ordered_string_v1(profile, "node_kind"), "external") != 0 ||
        !linux_ordered_flag_v1(external, "ordered_middle_supported") ||
        (strcmp(protocol, "shadowsocks") != 0 && strcmp(protocol, "socks5") != 0)) return "";
    return protocol;
}

static gboolean linux_ordered_imported_v1(JsonObject *profile) {
    return linux_ordered_imported_mode_v1(profile)[0] != '\0';
}

static JsonObject *linux_ordered_value_v1(const LinuxOrderedSelectionV1 *selection) {
    JsonObject *value = json_object_new();
    json_object_set_string_member(value, "selected_node_id", selection->control);
    json_object_set_array_member(value, "nodes", json_array_ref(selection->nodes));
    json_object_set_object_member(value, "profile_tokens", json_object_ref(selection->tokens));
    return value;
}

static gboolean linux_ordered_current_v1(const LinuxOrderedSelectionV1 *selection, JsonObject *catalog) {
    if (selection == NULL || strcmp(selection->control, linux_ordered_string_v1(catalog, "selected_id")) != 0) return FALSE;
    for (guint i = 0; i < json_array_get_length(selection->nodes); i++) {
        const char *id = linux_ordered_string_v1(json_array_get_object_element(selection->nodes, i), "id");
        JsonObject *profile = external_source_profile_v24(catalog, id);
        const char *mode = linux_ordered_string_v1(json_array_get_object_element(selection->nodes, i), "mode");
        gboolean imported = linux_ordered_imported_v1(profile);
        gboolean admitted = imported ? json_array_get_length(selection->nodes) == 3 && i == 1 && strcmp(mode, linux_ordered_imported_mode_v1(profile)) == 0 : linux_ordered_router_v1(profile) && (i + 1 == json_array_get_length(selection->nodes) || linux_ordered_prefix_v1(mode));
        if (!admitted || (i + 1 == json_array_get_length(selection->nodes) && !linux_ordered_final_profile_v1(profile, mode)) ||
            strcmp(linux_ordered_string_v1(profile, "profile_token"), linux_ordered_string_v1(selection->tokens, id)) != 0) return FALSE;
    }
    return TRUE;
}

static JsonNode *linux_ordered_read_v1(const char *path) {
    Buffer out = {0}; char *error = NULL; JsonNode *root = NULL;
    if (api_request(path, "GET", NULL, 5000, &out, &error) && out.data != NULL && strlen(out.data) <= (1u << 20)) root = parse_json(out.data);
    g_free(error); free(out.data);
    if (root != NULL && !JSON_NODE_HOLDS_OBJECT(root)) { json_node_free(root); root = NULL; }
    return root;
}

static void linux_ordered_changed_v1(GtkWidget *widget, gpointer data) {
    LinuxOrderedStateV1 *owned = data;
    if (owned->applying || owned->unified->syncing) return;
    owned->generation++;
    if (widget == owned->multihop && (owned->selection != NULL || owned->invalid)) {
        gboolean enabled = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget));
        GKeyFile *key = linux_unified_load_keyfile_v8();
        g_key_file_set_boolean(key, "connection-profile-selection", "enabled", enabled);
        linux_unified_save_keyfile_v8(key); g_key_file_unref(key);
        key = linux_unified_load_keyfile_v8(); GError *error = NULL;
        gboolean retained = g_key_file_get_boolean(key, "connection-profile-selection", "enabled", &error);
        if (error != NULL || retained != enabled) { owned->invalid = TRUE; append_diag(owned->unified->app, "The multihop choice could not be retained. Reload the exact ordered profile before connecting it."); }
        if (error != NULL) g_error_free(error);
        g_key_file_unref(key);
    }
}

static void linux_ordered_state_free_v1(gpointer data) {
    LinuxOrderedStateV1 *owned = data;
    GtkWidget *controls[] = {owned->node, owned->mode, owned->multihop};
    for (guint i = 0; i < G_N_ELEMENTS(controls); i++) {
        g_signal_handlers_disconnect_by_data(controls[i], owned);
        g_object_unref(controls[i]);
    }
    linux_ordered_selection_free_v1(owned->selection); g_free(owned);
}

static LinuxOrderedStateV1 *linux_ordered_state_v1(LinuxUnifiedV8 *unified) {
    LinuxOrderedStateV1 *owned = g_object_get_data(G_OBJECT(unified->app->window), "linux-ordered-nodes-v1");
    if (owned != NULL) return owned;
    owned = g_new0(LinuxOrderedStateV1, 1); owned->unified = unified; owned->generation = 1;
    owned->node = g_object_ref(unified->node); owned->mode = g_object_ref(unified->mode); owned->multihop = g_object_ref(unified->multihop);
    GKeyFile *key = linux_unified_load_keyfile_v8();
    char *raw = g_key_file_get_string(key, "connection-profile-selection", "ordered_selection", NULL);
    g_key_file_unref(key);
    if (raw != NULL) {
        JsonNode *root = strlen(raw) <= 32768 ? parse_json(raw) : NULL;
        owned->selection = root != NULL && JSON_NODE_HOLDS_OBJECT(root) ? linux_ordered_decode_v1(json_node_get_object(root)) : NULL;
        owned->invalid = owned->selection == NULL;
        if (root != NULL) json_node_free(root);
        g_free(raw);
    }
    g_object_set_data_full(G_OBJECT(unified->app->window), "linux-ordered-nodes-v1", owned, linux_ordered_state_free_v1);
    g_signal_connect(unified->node, "changed", G_CALLBACK(linux_ordered_changed_v1), owned);
    g_signal_connect(unified->mode, "changed", G_CALLBACK(linux_ordered_changed_v1), owned);
    g_signal_connect(unified->multihop, "toggled", G_CALLBACK(linux_ordered_changed_v1), owned);
    return owned;
}

static gboolean linux_ordered_store_v1(LinuxOrderedStateV1 *owned, LinuxOrderedSelectionV1 *selection, gboolean enabled) {
    GKeyFile *key = linux_unified_load_keyfile_v8();
    char *expected = NULL;
    if (selection != NULL) {
        JsonObject *value = linux_ordered_value_v1(selection); char *raw = linux_ordered_json_v1(value);
        expected = g_strdup(raw);
        g_key_file_set_string(key, "connection-profile-selection", "ordered_selection", raw);
        g_key_file_set_boolean(key, "connection-profile-selection", "enabled", enabled);
        const char *fields[] = {"entry", "exit", "entry_mode", "exit_mode"};
        for (guint i = 0; i < G_N_ELEMENTS(fields); i++) g_key_file_set_string(key, "connection-profile-selection", fields[i], "");
        g_key_file_set_string(key, "state", "multihop_execution", "local");
        g_free(raw); json_object_unref(value);
    } else g_key_file_remove_key(key, "connection-profile-selection", "ordered_selection", NULL);
    linux_unified_save_keyfile_v8(key); g_key_file_unref(key);
    GKeyFile *readback = linux_unified_load_keyfile_v8();
    char *actual = g_key_file_get_string(readback, "connection-profile-selection", "ordered_selection", NULL);
    gboolean persisted = g_strcmp0(expected, actual) == 0;
    if (selection != NULL) {
        char *execution = g_key_file_get_string(readback, "state", "multihop_execution", NULL);
        GError *error = NULL;
        gboolean on = g_key_file_get_boolean(readback, "connection-profile-selection", "enabled", &error);
        persisted = persisted && error == NULL && on == enabled && g_strcmp0(execution, "local") == 0;
        if (error != NULL) g_error_free(error);
        g_free(execution);
        const char *fields[] = {"entry", "exit", "entry_mode", "exit_mode"};
        for (guint i = 0; i < G_N_ELEMENTS(fields); i++) {
            char *value = g_key_file_get_string(readback, "connection-profile-selection", fields[i], NULL);
            persisted = persisted && g_strcmp0(value, "") == 0; g_free(value);
        }
    }
    g_free(expected); g_free(actual); g_key_file_unref(readback);
    if (!persisted) { linux_ordered_selection_free_v1(selection); owned->invalid = TRUE; owned->generation++; return FALSE; }
    linux_ordered_selection_free_v1(owned->selection); owned->selection = selection; owned->invalid = FALSE; owned->generation++;
    return TRUE;
}

static gboolean linux_ordered_owns_v1(LinuxOrderedStateV1 *owned, guint64 generation, const char *control) {
    return owned->generation == generation && g_strcmp0(gtk_combo_box_get_active_id(GTK_COMBO_BOX(owned->unified->node)), control) == 0;
}

static char *linux_ordered_connect_body_v1(const LinuxOrderedSelectionV1 *selection) {
    JsonObject *body = json_object_new();
    json_object_set_array_member(body, "nodes", json_array_ref(selection->nodes));
    json_object_set_string_member(body, "execution", "local");
    json_object_set_string_member(body, "expected_selected_node_id", selection->control);
    json_object_set_object_member(body, "expected_profile_tokens", json_object_ref(selection->tokens));
    char *raw = linux_ordered_json_v1(body); json_object_unref(body); return raw;
}

static char *linux_ordered_setup_body_v1(LinuxUnifiedV8 *unified, const char *name, const char *id) {
    LinuxOrderedStateV1 *owned = linux_ordered_state_v1(unified);
    if (owned->invalid || owned->selection == NULL || name == NULL || !name[0]) return NULL;
    LinuxOrderedSelectionV1 *selection = owned->selection;
    JsonNode *displayed = g_object_get_data(G_OBJECT(unified->app->window), "router-vpn-source-catalog-v24");
    if (!linux_ordered_owns_v1(owned, owned->generation, selection->control) || displayed == NULL ||
        !JSON_NODE_HOLDS_OBJECT(displayed) || !linux_ordered_current_v1(selection, json_node_get_object(displayed))) return NULL;
    JsonObject *body = json_object_new();
    if (id != NULL && id[0]) json_object_set_string_member(body, "id", id);
    json_object_set_string_member(body, "name", name);
    json_object_set_string_member(body, "mode", linux_ordered_string_v1(json_array_get_object_element(selection->nodes, json_array_get_length(selection->nodes) - 1), "mode"));
    json_object_set_boolean_member(body, "multihop_enabled", TRUE);
    json_object_set_array_member(body, "multihop_nodes", json_array_ref(selection->nodes));
    json_object_set_string_member(body, "multihop_execution", "local");
    json_object_set_string_member(body, "expected_selected_node_id", selection->control);
    json_object_set_object_member(body, "expected_profile_tokens", json_object_ref(selection->tokens));
    char *raw = linux_ordered_json_v1(body); json_object_unref(body); return raw;
}

/* Load protects the controller's CURRENT saved graph. The saved target's
 * independent source inventory is validated by the controller transaction.
 * An unsaved local editor draft is deliberately not an input to this capture. */
static char *linux_ordered_load_capture_v1(JsonObject *catalog, const char *control, const char *id) {
    JsonObject *profile = external_source_profile_v24(catalog, control);
    const char *token = linux_ordered_string_v1(profile, "profile_token");
    if (!external_source_id_v24(id) || profile == NULL || !external_source_token_v24(token) ||
        g_strcmp0(control, linux_ordered_string_v1(catalog, "selected_id")) != 0) return NULL;
    JsonNode *enabled = json_object_has_member(profile, "multihop_enabled") ? json_object_get_member(profile, "multihop_enabled") : NULL;
    if (enabled != NULL && (!JSON_NODE_HOLDS_VALUE(enabled) || json_node_get_value_type(enabled) != G_TYPE_BOOLEAN)) return NULL;
    GPtrArray *references = g_ptr_array_new(); g_ptr_array_add(references, (gpointer)control);
    gboolean valid = TRUE;
    if (linux_ordered_flag_v1(profile, "multihop_enabled")) {
        JsonNode *value = json_object_has_member(profile, "multihop_nodes") ? json_object_get_member(profile, "multihop_nodes") : NULL;
        JsonArray *nodes = linux_ordered_array_v1(profile, "multihop_nodes");
        if (value != NULL && !JSON_NODE_HOLDS_NULL(value) && nodes == NULL) valid = FALSE;
        guint count = nodes != NULL ? json_array_get_length(nodes) : 0;
        if (count != 0) {
            valid = valid && count >= 2 && count <= 8;
            for (guint i = 0; valid && i < count; i++) {
                JsonNode *element = json_array_get_element(nodes, i);
                JsonObject *row = element != NULL && JSON_NODE_HOLDS_OBJECT(element) ? json_node_get_object(element) : NULL;
                const char *member = linux_ordered_string_v1(row, "id");
                valid = row != NULL && json_object_get_size(row) == 2 && external_source_id_v24(member) && linux_ordered_string_v1(row, "mode")[0];
                for (guint j = 1; valid && j < references->len; j++) valid = strcmp(member, g_ptr_array_index(references, j)) != 0;
                if (valid) g_ptr_array_add(references, (gpointer)member);
            }
        } else {
            g_ptr_array_add(references, (gpointer)linux_ordered_string_v1(profile, "multihop_entry_id"));
            g_ptr_array_add(references, (gpointer)linux_ordered_string_v1(profile, "multihop_exit_id"));
        }
    }
    JsonObject *body = json_object_new(), *tokens = json_object_new();
    for (guint i = 0; valid && i < references->len; i++) {
        const char *member = g_ptr_array_index(references, i);
        JsonObject *source = external_source_profile_v24(catalog, member);
        const char *revision = linux_ordered_string_v1(source, "profile_token");
        valid = source != NULL && external_source_id_v24(member) && external_source_token_v24(revision);
        if (valid) json_object_set_string_member(tokens, member, revision);
    }
    g_ptr_array_unref(references);
    if (!valid) { json_object_unref(body); json_object_unref(tokens); return NULL; }
    json_object_set_string_member(body, "id", id); json_object_set_string_member(body, "expected_selected_node_id", control);
    json_object_set_object_member(body, "expected_profile_tokens", tokens);
    char *raw = linux_ordered_json_v1(body); json_object_unref(body); return raw;
}

static char *linux_ordered_load_body_v1(LinuxUnifiedV8 *unified, const char *id) {
    JsonNode *displayed = g_object_get_data(G_OBJECT(unified->app->window), "router-vpn-source-catalog-v24");
    JsonObject *catalog = displayed != NULL && JSON_NODE_HOLDS_OBJECT(displayed) ? json_node_get_object(displayed) : NULL;
    return linux_ordered_load_capture_v1(catalog, gtk_combo_box_get_active_id(GTK_COMBO_BOX(unified->node)), id);
}

static gboolean linux_ordered_response_present_v1(JsonObject *payload) {
    JsonNode *nodes = payload != NULL && json_object_has_member(payload, "multihop_nodes") ? json_object_get_member(payload, "multihop_nodes") : NULL;
    return nodes != NULL && !JSON_NODE_HOLDS_NULL(nodes) && (!JSON_NODE_HOLDS_ARRAY(nodes) || json_array_get_length(json_node_get_array(nodes)) != 0);
}

static LinuxOrderedSelectionV1 *linux_ordered_response_v1(JsonObject *payload) {
    JsonArray *nodes = linux_ordered_array_v1(payload, "multihop_nodes");
    const char *control = linux_ordered_string_v1(payload, "selected_node_id");
    if (!linux_ordered_rows_v1(nodes, control) || !linux_ordered_flag_v1(payload, "multihop_enabled") ||
        strcmp(linux_ordered_string_v1(payload, "multihop_execution"), "local") != 0 ||
        strcmp(linux_ordered_string_v1(payload, "mode"), linux_ordered_string_v1(json_array_get_object_element(nodes, json_array_get_length(nodes) - 1), "mode")) != 0) return NULL;
    const char *pair[] = {"multihop_entry_id", "multihop_exit_id", "multihop_entry_mode", "multihop_exit_mode"};
    for (guint i = 0; i < G_N_ELEMENTS(pair); i++) if (linux_ordered_string_v1(payload, pair[i])[0]) return NULL;
    JsonObject *supplied = linux_ordered_object_v1(payload, "profile_tokens");
    if (supplied == NULL || json_object_get_size(supplied) != json_array_get_length(nodes)) return NULL;
    JsonObject *tokens = json_object_new();
    for (guint i = 0; i < json_array_get_length(nodes); i++) {
        const char *id = linux_ordered_string_v1(json_array_get_object_element(nodes, i), "id");
        json_object_set_string_member(tokens, id, linux_ordered_string_v1(supplied, id));
    }
    LinuxOrderedSelectionV1 *selection = linux_ordered_selection_v1(control, nodes, tokens);
    json_object_unref(tokens); return selection;
}

static char *linux_ordered_summary_v1(const LinuxOrderedSelectionV1 *selection) {
    if (selection == NULL) return g_strdup("No complete ordered path is captured.");
    GString *text = g_string_new("Local ordered path: ");
    for (guint i = 0; i < json_array_get_length(selection->nodes); i++) {
        JsonObject *row = json_array_get_object_element(selection->nodes, i);
        if (i) g_string_append(text, " → ");
        g_string_append_printf(text, "%s (%s)", linux_ordered_string_v1(row, "id"), linux_ordered_mode_name_v1(linux_ordered_string_v1(row, "mode")));
    }
    return g_string_free(text, FALSE);
}

static gboolean linux_ordered_connect_v1(LinuxUnifiedV8 *unified) {
    LinuxOrderedStateV1 *owned = linux_ordered_state_v1(unified);
    if (owned->selection == NULL && !owned->invalid) return FALSE;
    if (owned->invalid) { append_diag(unified->app, "The saved ordered path is invalid. Explicitly create a new path; no pair fallback was selected."); return TRUE; }
    LinuxOrderedSelectionV1 *selection = linux_ordered_selection_v1(owned->selection->control, owned->selection->nodes, owned->selection->tokens);
    guint64 generation = owned->generation;
    gboolean valid = routervpn_require_mutation_idle(unified->app, "starting the captured ordered path") &&
        linux_ordered_owns_v1(owned, generation, selection->control);
    JsonNode *capabilities = valid ? linux_ordered_read_v1("/api/multihop/status") : NULL;
    valid = valid && capabilities != NULL && linux_ordered_flag_v1(json_node_get_object(capabilities), "ordered_nodes_supported");
    JsonNode *current = valid ? linux_ordered_read_v1("/api/profiles") : NULL;
    valid = valid && current != NULL && linux_ordered_current_v1(selection, json_node_get_object(current)) &&
        linux_ordered_owns_v1(owned, generation, selection->control) && routervpn_require_mutation_idle(unified->app, "dispatching the captured ordered path");
    if (valid) {
        char *body = linux_ordered_connect_body_v1(selection);
        post_and_log(unified->app, "/api/multihop/connect", body, 180000, "Captured ordered native path"); g_free(body);
    } else append_diag(unified->app, "The captured ordered path changed or this controller has not enabled it. No connection was started. Reopen the editor or reload the exact saved profile.");
    if (capabilities != NULL) json_node_free(capabilities);
    if (current != NULL) json_node_free(current);
    linux_ordered_selection_free_v1(selection); return TRUE;
}

typedef struct {
    LinuxOrderedStateV1 *owned;
    guint64 generation;
    char *control, *final_mode;
    JsonNode *catalog;
    GPtrArray *ids, *modes;
    GtkWidget *dialog, *list, *candidate, *transport, *status, *add, *remove, *up, *down;
    gboolean syncing, closed;
} LinuxOrderedEditorV1;

static const char *linux_ordered_editor_final_mode_v1(LinuxOrderedEditorV1 *editor) {
    return editor->final_mode != NULL ? editor->final_mode : "shadowsocks";
}

static gboolean linux_ordered_editor_final_allowed_v1(LinuxOrderedEditorV1 *editor, const char *mode) {
    if (!linux_ordered_final_profile_v1(external_source_profile_v24(json_node_get_object(editor->catalog), editor->control), mode)) return FALSE;
    if (g_strcmp0(mode, "hysteria2") == 0) for (guint i = 0; i < editor->modes->len; i++)
        if (g_strcmp0(g_ptr_array_index(editor->modes, i), "shadowsocks") == 0 || g_strcmp0(g_ptr_array_index(editor->modes, i), "socks5") == 0) return FALSE;
    return TRUE;
}

static const char *linux_ordered_name_v1(LinuxOrderedEditorV1 *editor, const char *id) {
    const char *name = linux_ordered_string_v1(external_source_profile_v24(json_node_get_object(editor->catalog), id), "name");
    return name[0] ? name : id;
}

static int linux_ordered_index_v1(LinuxOrderedEditorV1 *editor) {
    GtkListBoxRow *row = gtk_list_box_get_selected_row(GTK_LIST_BOX(editor->list));
    return row != NULL ? gtk_list_box_row_get_index(row) : -1;
}

static gboolean linux_ordered_editable_v1(LinuxOrderedEditorV1 *editor) {
    return !editor->closed && linux_ordered_owns_v1(editor->owned, editor->generation, editor->control) &&
        !linux_async_busy_v16(editor->owned->unified->app);
}

static void linux_ordered_selected_v1(GtkListBox *box, GtkListBoxRow *row, gpointer data) {
    (void)box; (void)row;
    LinuxOrderedEditorV1 *editor = data;
    int index = linux_ordered_index_v1(editor); gboolean valid = linux_ordered_editable_v1(editor);
    gboolean prefix = index >= 0 && (guint)index < editor->ids->len;
    editor->syncing = TRUE;
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(editor->transport), prefix ? g_ptr_array_index(editor->modes, index) : linux_ordered_editor_final_mode_v1(editor));
    editor->syncing = FALSE;
    gtk_widget_set_sensitive(editor->transport, valid && index >= 0 && (guint)index <= editor->ids->len);
    gtk_widget_set_sensitive(editor->remove, valid && prefix);
    gtk_widget_set_sensitive(editor->up, valid && prefix && index > 0);
    gtk_widget_set_sensitive(editor->down, valid && prefix && (guint)(index + 1) < editor->ids->len);
    gtk_widget_set_sensitive(editor->add, valid && editor->ids->len < 7);
    gtk_widget_set_sensitive(gtk_dialog_get_widget_for_response(GTK_DIALOG(editor->dialog), GTK_RESPONSE_APPLY), valid && editor->ids->len > 0 && editor->ids->len <= 7);
}

static void linux_ordered_render_v1(LinuxOrderedEditorV1 *editor, int selected) {
    GList *children = gtk_container_get_children(GTK_CONTAINER(editor->list));
    for (GList *it = children; it != NULL; it = it->next) gtk_widget_destroy(GTK_WIDGET(it->data));
    g_list_free(children);
    for (guint i = 0; i <= editor->ids->len; i++) {
        gboolean final = i == editor->ids->len;
        const char *id = final ? editor->control : g_ptr_array_index(editor->ids, i);
        const char *mode = final ? linux_ordered_editor_final_mode_v1(editor) : g_ptr_array_index(editor->modes, i);
        char *text = g_strdup_printf("%u. %s — %s%s", i + 1, linux_ordered_name_v1(editor, id), linux_ordered_mode_name_v1(mode), final ? " • selected final exit" : "");
        GtkWidget *label = gtk_label_new(text); gtk_label_set_xalign(GTK_LABEL(label), 0); gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
        gtk_container_add(GTK_CONTAINER(editor->list), label); g_free(text);
    }
    gtk_widget_show_all(editor->list);
    gtk_list_box_select_row(GTK_LIST_BOX(editor->list), gtk_list_box_get_row_at_index(GTK_LIST_BOX(editor->list), selected));
    linux_ordered_selected_v1(NULL, NULL, editor);
}

static void linux_ordered_add_v1(GtkButton *button, gpointer data) {
    (void)button; LinuxOrderedEditorV1 *editor = data;
    const char *id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(editor->candidate));
    if (!linux_ordered_editable_v1(editor) || id == NULL || editor->ids->len >= 7 || strcmp(id, editor->control) == 0) return;
    JsonObject *profile = external_source_profile_v24(json_node_get_object(editor->catalog), id);
    if ((!linux_ordered_router_v1(profile) && !linux_ordered_imported_v1(profile)) || !external_source_token_v24(linux_ordered_string_v1(profile, "profile_token"))) return;
    if (linux_ordered_imported_v1(profile) && strcmp(linux_ordered_editor_final_mode_v1(editor), "shadowsocks") != 0) {
        gtk_label_set_text(GTK_LABEL(editor->status), "Choose a Shadowsocks 2022 exit before adding an imported middle."); return;
    }
    for (guint i = 0; i < editor->ids->len; i++) if (strcmp(g_ptr_array_index(editor->ids, i), id) == 0) return;
    g_ptr_array_add(editor->ids, g_strdup(id)); g_ptr_array_add(editor->modes, g_strdup(linux_ordered_imported_v1(profile) ? linux_ordered_imported_mode_v1(profile) : "wg"));
    linux_ordered_render_v1(editor, (int)editor->ids->len - 1);
}

static void linux_ordered_remove_v1(GtkButton *button, gpointer data) {
    (void)button; LinuxOrderedEditorV1 *editor = data; int index = linux_ordered_index_v1(editor);
    if (!linux_ordered_editable_v1(editor) || index < 0 || (guint)index >= editor->ids->len) return;
    g_ptr_array_remove_index(editor->ids, index); g_ptr_array_remove_index(editor->modes, index);
    linux_ordered_render_v1(editor, MIN(index, (int)editor->ids->len));
}

static void linux_ordered_move_v1(GtkButton *button, gpointer data) {
    LinuxOrderedEditorV1 *editor = data; int index = linux_ordered_index_v1(editor);
    int offset = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(button), "ordered-offset")), target = index + offset;
    if (!linux_ordered_editable_v1(editor) || (offset != -1 && offset != 1) || index < 0 || target < 0 || (guint)index >= editor->ids->len || (guint)target >= editor->ids->len) return;
    gpointer id = editor->ids->pdata[index], mode = editor->modes->pdata[index];
    editor->ids->pdata[index] = editor->ids->pdata[target]; editor->modes->pdata[index] = editor->modes->pdata[target];
    editor->ids->pdata[target] = id; editor->modes->pdata[target] = mode;
    linux_ordered_render_v1(editor, target);
}

static void linux_ordered_mode_v1(GtkComboBox *combo, gpointer data) {
    LinuxOrderedEditorV1 *editor = data; int index = linux_ordered_index_v1(editor);
    const char *mode = gtk_combo_box_get_active_id(combo);
    if (editor->syncing || !linux_ordered_editable_v1(editor)) return;
    if (index >= 0 && (guint)index == editor->ids->len) {
        if (!linux_ordered_editor_final_allowed_v1(editor, mode)) {
            linux_ordered_selected_v1(NULL, NULL, editor);
            gtk_label_set_text(GTK_LABEL(editor->status), "Choose Shadowsocks 2022, or Hysteria2 with Start Layer Off and paired packet prefixes."); return;
        }
        char *copy = g_strdup(mode); g_free(editor->final_mode); editor->final_mode = copy;
        linux_ordered_render_v1(editor, index); return;
    }
    gboolean imported = index >= 0 && (guint)index < editor->ids->len && linux_ordered_imported_v1(external_source_profile_v24(json_node_get_object(editor->catalog), g_ptr_array_index(editor->ids, index)));
    if (index < 0 || (guint)index >= editor->ids->len || (imported ? g_strcmp0(mode, linux_ordered_imported_mode_v1(external_source_profile_v24(json_node_get_object(editor->catalog), g_ptr_array_index(editor->ids, index)))) != 0 : !linux_ordered_prefix_v1(mode))) {
        linux_ordered_selected_v1(NULL, NULL, editor);
        gtk_label_set_text(GTK_LABEL(editor->status), "Entry and intermediate hops use WireGuard, AWG2 Fast or AWG2 Strong. The paired final uses Shadowsocks 2022 or Hysteria2 with Start Layer Off.");
        return;
    }
    char *copy = g_strdup(mode); g_free(editor->modes->pdata[index]); editor->modes->pdata[index] = copy;
    linux_ordered_render_v1(editor, index);
}

static LinuxOrderedSelectionV1 *linux_ordered_editor_selection_v1(LinuxOrderedEditorV1 *editor) {
    JsonArray *nodes = json_array_new(); JsonObject *tokens = json_object_new();
    for (guint i = 0; i <= editor->ids->len; i++) {
        const char *id = i == editor->ids->len ? editor->control : g_ptr_array_index(editor->ids, i);
        const char *mode = i == editor->ids->len ? linux_ordered_editor_final_mode_v1(editor) : g_ptr_array_index(editor->modes, i);
        JsonObject *row = json_object_new(); json_object_set_string_member(row, "id", id); json_object_set_string_member(row, "mode", mode);
        json_array_add_object_element(nodes, row);
        json_object_set_string_member(tokens, id, linux_ordered_string_v1(external_source_profile_v24(json_node_get_object(editor->catalog), id), "profile_token"));
    }
    LinuxOrderedSelectionV1 *selection = linux_ordered_selection_v1(editor->control, nodes, tokens);
    json_array_unref(nodes); json_object_unref(tokens); return selection;
}

static gboolean linux_ordered_apply_v1(LinuxOrderedEditorV1 *editor) {
    if (!linux_ordered_editable_v1(editor) || !routervpn_require_mutation_idle(editor->owned->unified->app, "applying the ordered path")) return FALSE;
    LinuxOrderedSelectionV1 *selection = linux_ordered_editor_selection_v1(editor);
    JsonNode *current = selection != NULL ? linux_ordered_read_v1("/api/profiles") : NULL;
    gboolean valid = current != NULL && linux_ordered_current_v1(selection, json_node_get_object(current)) && linux_ordered_editable_v1(editor) &&
        routervpn_require_mutation_idle(editor->owned->unified->app, "retaining the original ordered sources");
    if (current != NULL) json_node_free(current);
    if (!valid) { linux_ordered_selection_free_v1(selection); gtk_label_set_text(GTK_LABEL(editor->status), "The selected exit or an original node changed. No path was applied; reopen the editor."); return FALSE; }
    if (!linux_ordered_store_v1(editor->owned, selection, TRUE)) {
        gtk_label_set_text(GTK_LABEL(editor->status), "The complete ordered path could not be retained on disk. No successful Apply is claimed; reload or retry before connecting.");
        return FALSE;
    }
    editor->owned->applying = TRUE;
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(editor->owned->unified->multihop), TRUE);
    editor->owned->applying = FALSE;
    return TRUE;
}

static void linux_ordered_closed_v1(GtkWidget *widget, gpointer data) {
    (void)widget;
    ((LinuxOrderedEditorV1 *)data)->closed = TRUE;
}

static void linux_ordered_editor_v1(LinuxUnifiedV8 *unified, gboolean fresh) {
    if (!routervpn_require_mutation_idle(unified->app, "editing an ordered path")) return;
    LinuxOrderedStateV1 *owned = linux_ordered_state_v1(unified);
    JsonNode *displayed = g_object_get_data(G_OBJECT(unified->app->window), "router-vpn-source-catalog-v24");
    JsonNode *catalog = displayed != NULL ? copy_public_source_value_v24(displayed) : NULL;
    JsonObject *store = catalog != NULL && JSON_NODE_HOLDS_OBJECT(catalog) ? json_node_get_object(catalog) : NULL;
    const char *control = gtk_combo_box_get_active_id(GTK_COMBO_BOX(unified->node));
    JsonObject *profile = external_source_profile_v24(store, control);
    gboolean valid = linux_ordered_router_v1(profile) &&
        external_source_token_v24(linux_ordered_string_v1(profile, "profile_token")) && g_strcmp0(control, linux_ordered_string_v1(store, "selected_id")) == 0;
    if (!fresh && (owned->invalid || (owned->selection != NULL && !linux_ordered_current_v1(owned->selection, store)))) valid = FALSE;
    if (!valid) {
        append_diag(unified->app, "The captured exit or ordered source is unavailable. Refresh the node list, reload its exact profile, or explicitly start a new ordered path.");
        if (catalog != NULL) json_node_free(catalog);
        return;
    }
    LinuxOrderedEditorV1 editor = {.owned=owned, .generation=owned->generation, .control=g_strdup(control), .catalog=catalog,
        .ids=g_ptr_array_new_with_free_func(g_free), .modes=g_ptr_array_new_with_free_func(g_free), .final_mode=g_strdup("shadowsocks")};
    if (!fresh && owned->selection != NULL) {
        g_free(editor.final_mode); editor.final_mode=g_strdup(linux_ordered_string_v1(json_array_get_object_element(owned->selection->nodes, json_array_get_length(owned->selection->nodes)-1), "mode"));
    }
    if (!fresh && owned->selection != NULL) for (guint i = 0; i + 1 < json_array_get_length(owned->selection->nodes); i++) {
        JsonObject *row = json_array_get_object_element(owned->selection->nodes, i);
        g_ptr_array_add(editor.ids, g_strdup(linux_ordered_string_v1(row, "id"))); g_ptr_array_add(editor.modes, g_strdup(linux_ordered_string_v1(row, "mode")));
    }
    editor.dialog = gtk_dialog_new_with_buttons("Ordered native path", GTK_WINDOW(unified->app->window), GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "Cancel", GTK_RESPONSE_CANCEL, "Apply path", GTK_RESPONSE_APPLY, NULL);
    g_object_ref(unified->app->window); g_object_ref_sink(editor.dialog);
    gulong parent_closed = g_signal_connect(unified->app->window, "destroy", G_CALLBACK(linux_ordered_closed_v1), &editor);
    g_signal_connect(editor.dialog, "destroy", G_CALLBACK(linux_ordered_closed_v1), &editor);
    gtk_window_set_default_size(GTK_WINDOW(editor.dialog), 660, 480);
    GtkWidget *box = gtk_dialog_get_content_area(GTK_DIALOG(editor.dialog)); gtk_container_set_border_width(GTK_CONTAINER(box), 12);
    GtkWidget *note = gtk_label_new("Choose the entry and each intermediate hop in order. Use paired WireGuard or AWG2 prefixes and choose Shadowsocks 2022 or unlayered Hysteria2 for the paired final. An imported Shadowsocks 2022 middle requires a Shadowsocks 2022 final. Apply retains choices; Connect proves the path separately.");
    gtk_label_set_line_wrap(GTK_LABEL(note), TRUE); gtk_box_pack_start(GTK_BOX(box), note, FALSE, FALSE, 6);
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL); gtk_widget_set_size_request(scroll, -1, 190);
    editor.list = gtk_list_box_new(); gtk_container_add(GTK_CONTAINER(scroll), editor.list); gtk_box_pack_start(GTK_BOX(box), scroll, TRUE, TRUE, 6);
    editor.candidate = gtk_combo_box_text_new();
    gtk_widget_set_name(editor.candidate, "ordered-node-candidate");
    JsonArray *profiles = linux_ordered_array_v1(store, "profiles");
    for (guint i = 0; profiles != NULL && i < json_array_get_length(profiles); i++) {
        JsonNode *value = json_array_get_element(profiles, i); if (value == NULL || !JSON_NODE_HOLDS_OBJECT(value)) continue;
        JsonObject *candidate = json_node_get_object(value); const char *id = linux_ordered_string_v1(candidate, "id");
        if (external_source_profile_v24(store, id) == candidate && strcmp(id, editor.control) != 0 && (linux_ordered_router_v1(candidate) || linux_ordered_imported_v1(candidate)) &&
            external_source_token_v24(linux_ordered_string_v1(candidate, "profile_token")))
            gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(editor.candidate), id, linux_ordered_name_v1(&editor, id));
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(editor.candidate), -1);
    GtkWidget *add_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6); gtk_box_pack_start(GTK_BOX(add_row), editor.candidate, TRUE, TRUE, 0);
    editor.add = make_button("Add entry / hop", G_CALLBACK(linux_ordered_add_v1), &editor); gtk_box_pack_start(GTK_BOX(add_row), editor.add, FALSE, FALSE, 0); gtk_box_pack_start(GTK_BOX(box), add_row, FALSE, FALSE, 6);
    GtkWidget *actions = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    editor.up = make_button("Move up", G_CALLBACK(linux_ordered_move_v1), &editor); g_object_set_data(G_OBJECT(editor.up), "ordered-offset", GINT_TO_POINTER(-1));
    editor.down = make_button("Move down", G_CALLBACK(linux_ordered_move_v1), &editor); g_object_set_data(G_OBJECT(editor.down), "ordered-offset", GINT_TO_POINTER(1));
    editor.remove = make_button("Remove", G_CALLBACK(linux_ordered_remove_v1), &editor);
    editor.transport = gtk_combo_box_text_new(); const char *modes[] = {"wg", "awg2-fast", "awg2-strong", "shadowsocks", "socks5", "hysteria2"};
    gtk_widget_set_name(editor.transport, "ordered-prefix-transport");
    for (guint i = 0; i < G_N_ELEMENTS(modes); i++) gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(editor.transport), modes[i], linux_ordered_mode_name_v1(modes[i]));
    GtkWidget *buttons[] = {editor.up, editor.down, editor.remove, editor.transport};
    for (guint i = 0; i < G_N_ELEMENTS(buttons); i++) gtk_box_pack_start(GTK_BOX(actions), buttons[i], FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), actions, FALSE, FALSE, 6);
    editor.status = gtk_label_new("Local execution • final exit is pinned to the original selected node"); gtk_label_set_line_wrap(GTK_LABEL(editor.status), TRUE); gtk_box_pack_start(GTK_BOX(box), editor.status, FALSE, FALSE, 6);
    g_signal_connect(editor.list, "row-selected", G_CALLBACK(linux_ordered_selected_v1), &editor);
    g_signal_connect(editor.transport, "changed", G_CALLBACK(linux_ordered_mode_v1), &editor);
    linux_ordered_render_v1(&editor, 0); gtk_widget_show_all(editor.dialog);
    while (gtk_dialog_run(GTK_DIALOG(editor.dialog)) == GTK_RESPONSE_APPLY) if (linux_ordered_apply_v1(&editor)) break;
    editor.closed = TRUE; gtk_widget_destroy(editor.dialog);
    if (g_signal_handler_is_connected(unified->app->window, parent_closed))
        g_signal_handler_disconnect(unified->app->window, parent_closed);
    g_object_unref(editor.dialog); g_object_unref(unified->app->window);
    g_ptr_array_unref(editor.ids); g_ptr_array_unref(editor.modes); g_free(editor.control); g_free(editor.final_mode); json_node_free(editor.catalog);
}
