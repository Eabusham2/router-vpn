/* Capture public opaque revisions; private credentials stay in the controller. */
static gboolean external_source_id_v24(const char *id) {
    if (id == NULL || !id[0] || strlen(id) > 64) return FALSE;
    for (const char *p = id; *p; p++)
        if (!g_ascii_isalnum(*p) && *p != '_' && *p != '-') return FALSE;
    return TRUE;
}

static gboolean external_source_token_v24(const char *token) {
    if (token == NULL || strlen(token) != 64) return FALSE;
    for (const char *p = token; *p; p++)
        if (!g_ascii_isdigit(*p) && (*p < 'a' || *p > 'f')) return FALSE;
    return TRUE;
}

static JsonObject *external_source_profile_v24(JsonObject *store, const char *id) {
    JsonNode *list = store != NULL && json_object_has_member(store, "profiles") ? json_object_get_member(store, "profiles") : NULL;
    if (list == NULL || !JSON_NODE_HOLDS_ARRAY(list) || !external_source_id_v24(id)) return NULL;
    JsonArray *profiles = json_node_get_array(list);
    JsonObject *found = NULL;
    for (guint i = 0; i < json_array_get_length(profiles); i++) {
        JsonNode *item = json_array_get_element(profiles, i);
        if (item == NULL || !JSON_NODE_HOLDS_OBJECT(item)) return NULL;
        JsonObject *profile = json_node_get_object(item);
        if (g_strcmp0(external_path_string_v4(profile, "id"), id) == 0) {
            if (found != NULL) return NULL;
            found = profile;
        }
    }
    return found;
}

static const char *external_source_selection_v24(JsonObject *store) {
    JsonNode *value = store != NULL && json_object_has_member(store, "selected_id") ? json_object_get_member(store, "selected_id") : NULL;
    if (value == NULL || !JSON_NODE_HOLDS_VALUE(value) || json_node_get_value_type(value) != G_TYPE_STRING) return NULL;
    const char *id = json_node_get_string(value);
    return id != NULL && (!id[0] || external_source_id_v24(id)) ? id : NULL;
}

static char *external_captured_body_v24(const char *body, JsonNode *opened, JsonNode *current, char **error) {
    const char *message = NULL;
    g_autoptr(JsonNode) payload = body != NULL ? parse_json(body) : NULL;
    JsonObject *request = payload != NULL && JSON_NODE_HOLDS_OBJECT(payload) ? json_node_get_object(payload) : NULL;
    JsonObject *store = opened != NULL && JSON_NODE_HOLDS_OBJECT(opened) ? json_node_get_object(opened) : NULL;
    JsonObject *now = current != NULL && JSON_NODE_HOLDS_OBJECT(current) ? json_node_get_object(current) : NULL;
    const char *selected = external_source_selection_v24(store), *id = external_path_string_v4(request, "profile_id");
    JsonObject *exit = external_source_profile_v24(store, id);
    if (request == NULL || selected == NULL || exit == NULL) message = "The captured external node selection is invalid. Refresh the node list.";
    if (message == NULL && current != NULL && (now == NULL || g_strcmp0(selected, external_source_selection_v24(now)) != 0))
        message = "The selected node changed while this dialog was open. Nothing was connected.";
    const char *entry = "";
    if (message == NULL && !external_path_flag_v4(request, "direct")) {
        entry = external_path_string_v4(request, "entry_id");
        if (!entry[0] && external_path_flag_v4(exit, "multihop_enabled")) entry = external_path_string_v4(exit, "multihop_entry_id");
        if (entry[0] && g_strcmp0(entry, id) == 0) message = "External entry and exit must be different nodes.";
    }
    JsonObject *tokens = json_object_new();
    const char *ids[] = {id, selected, entry};
    for (guint i = 0; message == NULL && i < G_N_ELEMENTS(ids); i++) {
        if (ids[i] == NULL || !ids[i][0]) continue;
        JsonObject *profile = external_source_profile_v24(store, ids[i]);
        const char *token = external_path_string_v4(profile, "profile_token");
        if (profile == NULL || !external_source_token_v24(token)) {
            message = "A captured node revision is unavailable or ambiguous. Refresh the node list.";
            break;
        }
        if (current != NULL) {
            JsonObject *fresh = external_source_profile_v24(now, ids[i]);
            if (fresh == NULL || g_strcmp0(token, external_path_string_v4(fresh, "profile_token")) != 0) {
                message = "A path node was changed or relinked. Reopen its path settings.";
                break;
            }
        }
        json_object_set_string_member(tokens, ids[i], token);
    }
    if (message != NULL) {
        json_object_unref(tokens);
        if (error != NULL) *error = g_strdup(message);
        return NULL;
    }
    json_object_set_string_member(request, "expected_selected_node_id", selected);
    json_object_set_object_member(request, "expected_profile_tokens", tokens);
    JsonGenerator *generator = json_generator_new(); json_generator_set_root(generator, payload);
    char *result = json_generator_to_data(generator, NULL); g_object_unref(generator);
    return result;
}

static gboolean external_source_capability_v24(void) {
    Buffer out = {0}; char *error = NULL; gboolean supported = FALSE;
    if (api_request("/api/external-profile/capabilities", "GET", NULL, 5000, &out, &error)) {
        g_autoptr(JsonNode) root = parse_json(out.data);
        if (root != NULL && JSON_NODE_HOLDS_OBJECT(root))
            supported = external_path_flag_v4(json_node_get_object(root), "profile_source_preconditions");
    }
    g_free(error); free(out.data);
    return supported;
}

static char *external_primary_captured_body_v24(JsonNode *opened, const char *id, gboolean direct, char **error) {
    JsonObject *store = opened != NULL && JSON_NODE_HOLDS_OBJECT(opened) ? json_node_get_object(opened) : NULL;
    JsonObject *profile = external_source_profile_v24(store, id);
    if (profile == NULL || g_strcmp0(external_path_string_v4(profile, "node_kind"), "external") != 0 ||
        (!direct && g_strcmp0(id, external_source_selection_v24(store)) != 0)) {
        if (error != NULL) *error = g_strdup("The displayed external node is unavailable. Refresh the node list.");
        return NULL;
    }
    g_autofree char *plain = json_external_hop_body(id, "", direct ? "local" : external_saved_execution_v4(profile), direct);
    g_autofree char *captured = external_captured_body_v24(plain, opened, NULL, error);
    if (captured == NULL) return NULL;
    if (!external_source_capability_v24()) {
        if (error != NULL) *error = g_strdup("Update the local controller before connecting this captured external path.");
        return NULL;
    }
    Buffer out = {0}; char *read_error = NULL;
    gboolean read = api_request("/api/nodes", "GET", NULL, 5000, &out, &read_error);
    g_autoptr(JsonNode) current = read ? parse_json(out.data) : NULL;
    g_free(read_error); free(out.data);
    if (current == NULL) {
        if (error != NULL) *error = g_strdup("The current node catalog is unavailable. Nothing was connected.");
        return NULL;
    }
    return external_captured_body_v24(plain, opened, current, error);
}

static char *external_primary_body_v24(App *app, const char *id, gboolean direct, char **error) {
    JsonNode *displayed = app != NULL && app->window != NULL ? g_object_get_data(G_OBJECT(app->window), "router-vpn-source-catalog-v24") : NULL;
    g_autoptr(JsonNode) opened = displayed != NULL ? copy_public_source_value_v24(displayed) : NULL;
    return external_primary_captured_body_v24(opened, id, direct, error);
}
