/* Public references for the native ordered path. Private sources remain in the
 * controller. This include is composed after the unified shell, before Profiles. */
enum { ROUTERVPN_PHYSICAL_TRAVERSAL_DEPTH = 96 };

typedef struct {
    char *control, *execution;
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

static gboolean linux_ordered_imported_position_v1(const char *mode, guint position, guint count) {
    if (g_strcmp0(mode, "shadowsocks") == 0 || g_strcmp0(mode, "socks5") == 0 || g_strcmp0(mode, "http-connect") == 0 || g_strcmp0(mode, "https-connect") == 0 || g_strcmp0(mode, "openvpn") == 0)
        return count >= 3 && count <= 8 && position == count - 2;
    return count == 3 && position == 1;
}

static gboolean linux_ordered_local_ss_position_v1(const char *mode, guint position, guint count) {
    return g_strcmp0(mode, "shadowsocks") == 0 && count >= 3 && count <= ROUTERVPN_PHYSICAL_TRAVERSAL_DEPTH && position > 0 && position + 1 < count;
}

static gboolean linux_ordered_custom_entry_shape_v1(JsonArray *nodes) {
    if (nodes == NULL || json_array_get_length(nodes) != 3) return FALSE;
    for (guint i = 0; i < 3; i++) {
        JsonNode *row = json_array_get_element(nodes, i);
        if (row == NULL || !JSON_NODE_HOLDS_OBJECT(row) ||
            strcmp(linux_ordered_string_v1(json_node_get_object(row), "mode"), "shadowsocks") != 0) return FALSE;
    }
    return TRUE;
}

static gboolean linux_ordered_final_v1(const char *mode) {
    return g_strcmp0(mode, "shadowsocks") == 0 || g_strcmp0(mode, "hysteria2") == 0 || linux_ordered_prefix_v1(mode);
}

static const char *linux_ordered_mode_name_v1(const char *mode) {
    if (g_strcmp0(mode, "wg") == 0) return "WireGuard";
    if (g_strcmp0(mode, "awg2-fast") == 0) return "AWG2 Fast";
    if (g_strcmp0(mode, "awg2-strong") == 0) return "AWG2 Strong";
    if (g_strcmp0(mode, "shadowsocks") == 0) return "Shadowsocks 2022";
    if (g_strcmp0(mode, "socks5") == 0) return "SOCKS5";
    if (g_strcmp0(mode, "http-connect") == 0) return "HTTP CONNECT";
    if (g_strcmp0(mode, "https-connect") == 0) return "HTTPS CONNECT";
    if (g_strcmp0(mode, "hysteria2") == 0) return "Hysteria2";
    if (g_strcmp0(mode, "openvpn") == 0) return "OpenVPN";
    return "Unavailable transport";
}

static void linux_ordered_selection_free_v1(LinuxOrderedSelectionV1 *selection) {
    if (selection == NULL) return;
    g_free(selection->control); g_free(selection->execution);
    json_array_unref(selection->nodes); json_object_unref(selection->tokens); g_free(selection);
}

static gboolean linux_ordered_extended_shape_v1(JsonArray *nodes) {
    guint count = nodes == NULL ? 0 : json_array_get_length(nodes);
    if (count <= 8 || count > ROUTERVPN_PHYSICAL_TRAVERSAL_DEPTH) return FALSE;
    for (guint i = 0; i < count; i++) {
        JsonNode *row = json_array_get_element(nodes, i);
        if (row == NULL || !JSON_NODE_HOLDS_OBJECT(row) ||
            g_strcmp0(linux_ordered_string_v1(json_node_get_object(row), "mode"), i == 0 ? "wg" : "shadowsocks") != 0)
            return FALSE;
    }
    return TRUE;
}

static gboolean linux_ordered_extended_selected_shape_v1(JsonArray *nodes) {
    guint count = nodes == NULL ? 0 : json_array_get_length(nodes);
    if (count <= 8 || count > ROUTERVPN_PHYSICAL_TRAVERSAL_DEPTH) return FALSE;
    for (guint i = 0; i < count; i++) {
        JsonNode *row = json_array_get_element(nodes, i);
        if (row == NULL || !JSON_NODE_HOLDS_OBJECT(row)) return FALSE;
        const char *mode = linux_ordered_string_v1(json_node_get_object(row), "mode");
        if (i == 0 ? !linux_ordered_prefix_v1(mode) : g_strcmp0(mode, "shadowsocks") != 0) return FALSE;
    }
    return TRUE;
}

static gboolean linux_ordered_extended_paired_shape_v1(JsonArray *nodes) {
    guint count = nodes == NULL ? 0 : json_array_get_length(nodes);
    if (count <= 8 || count > ROUTERVPN_PHYSICAL_TRAVERSAL_DEPTH) return FALSE;
    for (guint i = 0; i < count; i++) {
        JsonNode *row = json_array_get_element(nodes, i);
        if (row == NULL || !JSON_NODE_HOLDS_OBJECT(row) ||
            g_strcmp0(linux_ordered_string_v1(json_node_get_object(row), "mode"), i + 1 == count ? "shadowsocks" : "wg") != 0)
            return FALSE;
    }
    return TRUE;
}

static gboolean linux_ordered_hysteria_local_shape_v1(JsonArray *nodes) {
    guint count = nodes ? json_array_get_length(nodes) : 0;
    if (count < 3 || count > ROUTERVPN_PHYSICAL_TRAVERSAL_DEPTH) return FALSE;
    gboolean retained = FALSE;
    for (guint i = 0; i < count; i++) {
        JsonNode *raw = json_array_get_element(nodes, i);
        if (!raw || !JSON_NODE_HOLDS_OBJECT(raw)) return FALSE;
        const char *mode = linux_ordered_string_v1(json_node_get_object(raw), "mode");
        if (i == 0) {
            if (!linux_ordered_prefix_v1(mode)) return FALSE;
        } else if (i + 1 == count) {
            if (strcmp(mode, "shadowsocks") && strcmp(mode, "hysteria2")) return FALSE;
        } else {
            if (!linux_ordered_prefix_v1(mode) && strcmp(mode, "shadowsocks") && strcmp(mode, "hysteria2")) return FALSE;
            retained = retained || !strcmp(mode, "hysteria2");
        }
    }
    return retained;
}

static gboolean linux_ordered_proxy_mode_v1(const char *mode) {
    return !g_strcmp0(mode, "shadowsocks") || !g_strcmp0(mode, "hysteria2");
}

static gboolean linux_ordered_paired_proxy_entry_shape_v1(JsonArray *nodes) {
    guint count = nodes ? json_array_get_length(nodes) : 0;
    if (count < 2 || count > ROUTERVPN_PHYSICAL_TRAVERSAL_DEPTH) return FALSE;
    for (guint i = 0; i < count; i++) {
        JsonNode *raw = json_array_get_element(nodes, i);
        if (!raw || !JSON_NODE_HOLDS_OBJECT(raw)) return FALSE;
        const char *mode = linux_ordered_string_v1(json_node_get_object(raw), "mode");
        if (i == 0 || i + 1 == count) {
            if (!linux_ordered_proxy_mode_v1(mode)) return FALSE;
        } else if (!linux_ordered_prefix_v1(mode) && !linux_ordered_proxy_mode_v1(mode)) return FALSE;
    }
    return TRUE;
}

static guint linux_ordered_imported_packet_prefixes_v1(JsonArray *nodes) {
    guint count = nodes == NULL ? 0 : json_array_get_length(nodes), prefixes = 0;
    if (count < 3 || count > ROUTERVPN_PHYSICAL_TRAVERSAL_DEPTH) return 0;
    gboolean imported = FALSE;
    for (guint i = 0; i < count; i++) {
        JsonNode *raw = json_array_get_element(nodes, i);
        if (!raw || !JSON_NODE_HOLDS_OBJECT(raw)) return 0;
        const char *mode = linux_ordered_string_v1(json_node_get_object(raw), "mode");
        if (i + 1 == count) {
            if (strcmp(mode, "shadowsocks")) return 0;
        } else if (linux_ordered_prefix_v1(mode) && !imported) prefixes++;
        else if (!strcmp(mode, "shadowsocks") && prefixes > 0) imported = TRUE;
        else return 0;
    }
    return imported ? prefixes : 0;
}

static gboolean linux_ordered_extended_mixed_shape_v1(JsonArray *nodes) {
    return nodes && json_array_get_length(nodes) > 8 && linux_ordered_imported_packet_prefixes_v1(nodes) > 0;
}

static gboolean linux_ordered_external_final_shape_v1(JsonArray *nodes, const char *control) {
    guint count = nodes ? json_array_get_length(nodes) : 0;
    if (count < 3 || count > ROUTERVPN_PHYSICAL_TRAVERSAL_DEPTH) return FALSE;
    for (guint i = 0; i < count; i++) {
        JsonNode *raw = json_array_get_element(nodes, i);
        if (!raw || !JSON_NODE_HOLDS_OBJECT(raw)) return FALSE;
        JsonObject *row = json_node_get_object(raw);
        const char *mode = linux_ordered_string_v1(row, "mode");
        if (i == 0 ? g_strcmp0(linux_ordered_string_v1(row, "id"), control) || !linux_ordered_prefix_v1(mode)
                   : g_strcmp0(mode, "shadowsocks") != 0) return FALSE;
    }
    return TRUE;
}

static gboolean linux_ordered_rows_v1(JsonArray *nodes, const char *control) {
    guint count = nodes != NULL ? json_array_get_length(nodes) : 0;
    gboolean paired_hysteria = linux_ordered_hysteria_local_shape_v1(nodes);
    gboolean paired_proxy = linux_ordered_paired_proxy_entry_shape_v1(nodes);
    if (count < 2 || (count > 8 && !paired_hysteria && !paired_proxy && !linux_ordered_extended_shape_v1(nodes) && !linux_ordered_extended_paired_shape_v1(nodes) && !linux_ordered_extended_mixed_shape_v1(nodes)) || !external_source_id_v24(control)) return FALSE;
    gboolean external_final = linux_ordered_external_final_shape_v1(nodes, control);
    gboolean imported_middle = FALSE;
    for (guint i = 0; i < count; i++) {
        JsonNode *value = json_array_get_element(nodes, i);
        if (value == NULL || !JSON_NODE_HOLDS_OBJECT(value)) return FALSE;
        JsonObject *row = json_node_get_object(value);
        const char *id = linux_ordered_string_v1(row, "id"), *mode = linux_ordered_string_v1(row, "mode");
        if (json_object_get_size(row) != 2 || !external_source_id_v24(id) ||
            (i + 1 == count ? !linux_ordered_final_v1(mode) || (!external_final && strcmp(id, control) != 0) : !linux_ordered_prefix_v1(mode) && !paired_hysteria && !paired_proxy && !((linux_ordered_imported_position_v1(mode, i, count) || linux_ordered_local_ss_position_v1(mode, i, count) || (i == 0 && linux_ordered_custom_entry_shape_v1(nodes))) && (strcmp(mode, "shadowsocks") == 0 || strcmp(mode, "socks5") == 0 || strcmp(mode, "http-connect") == 0 || strcmp(mode, "https-connect") == 0 || strcmp(mode, "openvpn") == 0)))) return FALSE;
        if (i + 1 < count && (strcmp(mode, "shadowsocks") == 0 || strcmp(mode, "socks5") == 0 || strcmp(mode, "http-connect") == 0 || strcmp(mode, "https-connect") == 0 || strcmp(mode, "openvpn") == 0)) imported_middle = TRUE;
        for (guint j = 0; j < i; j++)
            if (strcmp(id, linux_ordered_string_v1(json_array_get_object_element(nodes, j), "id")) == 0) return FALSE;
    }
    return paired_hysteria || paired_proxy || !imported_middle || strcmp(linux_ordered_string_v1(json_array_get_object_element(nodes, count - 1), "mode"), "shadowsocks") == 0;
}

static LinuxOrderedSelectionV1 *linux_ordered_selection_v1(const char *control, JsonArray *nodes, JsonObject *tokens) {
    if (!linux_ordered_rows_v1(nodes, control) || tokens == NULL || json_object_get_size(tokens) != json_array_get_length(nodes)) return NULL;
    LinuxOrderedSelectionV1 *selection = g_new0(LinuxOrderedSelectionV1, 1);
    selection->control = g_strdup(control); selection->execution = g_strdup("local"); selection->nodes = json_array_new(); selection->tokens = json_object_new();
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

static gboolean linux_ordered_multiple_imported_shape_v1(JsonArray *nodes) {
    guint count = nodes == NULL ? 0 : json_array_get_length(nodes);
    if (count < 3 || (count > 8 && !linux_ordered_extended_selected_shape_v1(nodes)) || !linux_ordered_prefix_v1(linux_ordered_string_v1(json_array_get_object_element(nodes, 0), "mode")) ||
        strcmp(linux_ordered_string_v1(json_array_get_object_element(nodes, count - 1), "mode"), "shadowsocks") != 0) return FALSE;
    gboolean independent = FALSE;
    for (guint position = 1; position + 1 < count; position++) {
        const char *mode = linux_ordered_string_v1(json_array_get_object_element(nodes, position), "mode");
        if (strcmp(mode, "shadowsocks") == 0) {
            if (position + 2 < count) independent = TRUE;
        } else if (!linux_ordered_prefix_v1(mode)) return FALSE;
    }
    return independent;
}

static gboolean linux_ordered_execution_v1(LinuxOrderedSelectionV1 *selection, const char *execution) {
    if (selection == NULL || (g_strcmp0(execution, "local") != 0 && g_strcmp0(execution, "server") != 0 && g_strcmp0(execution, "auto") != 0)) return FALSE;
    guint count = json_array_get_length(selection->nodes);
    if (strcmp(execution, "local") && linux_ordered_hysteria_local_shape_v1(selection->nodes)) return FALSE;
    if (strcmp(execution, "local") && linux_ordered_prefix_v1(linux_ordered_string_v1(json_array_get_object_element(selection->nodes, count-1), "mode"))) return FALSE;
    if (json_array_get_length(selection->nodes) > 8 && !linux_ordered_extended_selected_shape_v1(selection->nodes) &&
        ((!linux_ordered_hysteria_local_shape_v1(selection->nodes) && !linux_ordered_paired_proxy_entry_shape_v1(selection->nodes) && !linux_ordered_extended_paired_shape_v1(selection->nodes) && !linux_ordered_extended_mixed_shape_v1(selection->nodes)) || strcmp(execution, "local") != 0)) return FALSE;
    if (strcmp(execution, "local") != 0 && !linux_ordered_multiple_imported_shape_v1(selection->nodes)) for (guint i = 0; i + 1 < json_array_get_length(selection->nodes); i++) {
        const char *mode = linux_ordered_string_v1(json_array_get_object_element(selection->nodes, i), "mode");
        if (!linux_ordered_prefix_v1(mode) && !(i + 2 == json_array_get_length(selection->nodes) && (strcmp(mode, "shadowsocks") == 0 || strcmp(mode, "http-connect") == 0 || strcmp(mode, "https-connect") == 0 || strcmp(mode, "socks5") == 0 || strcmp(mode, "openvpn") == 0) && strcmp(linux_ordered_string_v1(json_array_get_object_element(selection->nodes, json_array_get_length(selection->nodes) - 1), "mode"), "shadowsocks") == 0)) return FALSE;
    }
    char *copy = g_strdup(execution); g_free(selection->execution); selection->execution = copy; return TRUE;
}

static LinuxOrderedSelectionV1 *linux_ordered_decode_v1(JsonObject *object) {
    if (object == NULL || (json_object_get_size(object) != 3 && json_object_get_size(object) != 4)) return NULL;
    /* The original three-field record represented Local only. New records
     * require the canonical explicit execution field; no unknown fallback. */
    if (json_object_get_size(object) == 4 && !json_object_has_member(object, "execution")) return NULL;
    LinuxOrderedSelectionV1 *selection = linux_ordered_selection_v1(linux_ordered_string_v1(object, "selected_node_id"),
        linux_ordered_array_v1(object, "nodes"), linux_ordered_object_v1(object, "profile_tokens"));
    const char *execution = json_object_get_size(object) == 3 ? "local" : linux_ordered_string_v1(object, "execution");
    if (!linux_ordered_execution_v1(selection, execution)) { linux_ordered_selection_free_v1(selection); return NULL; }
    return selection;
}

static gboolean linux_ordered_router_v1(JsonObject *profile) {
    if (profile == NULL || json_object_has_member(profile, "external")) return FALSE;
    if (!json_object_has_member(profile, "node_kind")) return TRUE;
    JsonNode *kind = json_object_get_member(profile, "node_kind");
    if (kind == NULL || !JSON_NODE_HOLDS_VALUE(kind) || json_node_get_value_type(kind) != G_TYPE_STRING) return FALSE;
    const char *value = json_node_get_string(kind);
    return value != NULL && (!value[0] || strcmp(value, "router-vpn") == 0);
}

static gboolean linux_ordered_paired_layer_v1(JsonObject *profile, gboolean allow_authenticated) {
    if (!linux_ordered_router_v1(profile)) return FALSE;
    if (!json_object_has_member(profile, "start_layer")) return TRUE;
    JsonNode *layer = json_object_get_member(profile, "start_layer");
    if (layer == NULL || !JSON_NODE_HOLDS_VALUE(layer) || json_node_get_value_type(layer) != G_TYPE_STRING) return FALSE;
    const char *value = json_node_get_string(layer);
    return value != NULL && (!value[0] || strcmp(value, "off") == 0 ||
        (allow_authenticated && (!strcmp(value, "aes-256-gcm") || !strcmp(value, "aes-256-gcm+xor-whitening"))));
}

static gboolean linux_ordered_paired_off_v1(JsonObject *profile) {
    return linux_ordered_paired_layer_v1(profile, FALSE);
}

/* Callers selecting paired SS/HY2 membership require literal endpoints here. */
static gboolean linux_ordered_paired_proxy_member_v1(JsonObject *profile, const char *mode) {
    return linux_ordered_paired_off_v1(profile) &&
        (linux_ordered_proxy_mode_v1(mode) ? g_hostname_is_ip_address(linux_ordered_string_v1(profile, "endpoint")) :
         linux_ordered_prefix_v1(mode));
}

static gboolean linux_ordered_extended_paired_path_v1(const LinuxOrderedSelectionV1 *selection, JsonObject *catalog) {
    if (selection == NULL || strcmp(selection->execution, "local") != 0 || !linux_ordered_extended_paired_shape_v1(selection->nodes)) return FALSE;
    for (guint i = 0; i < json_array_get_length(selection->nodes); i++) {
        const char *id = linux_ordered_string_v1(json_array_get_object_element(selection->nodes, i), "id");
        if (!linux_ordered_paired_off_v1(external_source_profile_v24(catalog, id))) return FALSE;
    }
    return TRUE;
}

static gboolean linux_ordered_hysteria_local_path_v1(const LinuxOrderedSelectionV1 *selection, JsonObject *catalog) {
    if (!selection || g_strcmp0(selection->execution, "local") || !linux_ordered_hysteria_local_shape_v1(selection->nodes)) return FALSE;
    for (guint i = 0; i < json_array_get_length(selection->nodes); i++) {
        const char *id = linux_ordered_string_v1(json_array_get_object_element(selection->nodes, i), "id");
        if (!linux_ordered_paired_off_v1(external_source_profile_v24(catalog, id))) return FALSE;
    }
    return TRUE;
}

static gboolean linux_ordered_paired_proxy_entry_source_v1(JsonArray *nodes, JsonObject *catalog) {
    if (!linux_ordered_paired_proxy_entry_shape_v1(nodes)) return FALSE;
    const char *id = linux_ordered_string_v1(json_array_get_object_element(nodes, 0), "id");
    return linux_ordered_router_v1(external_source_profile_v24(catalog, id));
}

static gboolean linux_ordered_paired_proxy_entry_path_v1(const LinuxOrderedSelectionV1 *selection, JsonObject *catalog) {
    if (!selection || g_strcmp0(selection->execution, "local") ||
        !linux_ordered_paired_proxy_entry_source_v1(selection->nodes, catalog)) return FALSE;
    for (guint i = 0; i < json_array_get_length(selection->nodes); i++) {
        JsonObject *row = json_array_get_object_element(selection->nodes, i);
        const char *id = linux_ordered_string_v1(row, "id"), *mode = linux_ordered_string_v1(row, "mode");
        if (!linux_ordered_paired_proxy_member_v1(external_source_profile_v24(catalog, id), mode)) return FALSE;
    }
    return TRUE;
}

static gboolean linux_ordered_final_profile_v1(JsonObject *profile, const char *mode) {
    if (!linux_ordered_router_v1(profile) || !linux_ordered_final_v1(mode)) return FALSE;
    if (strcmp(mode, "shadowsocks") == 0) return TRUE;
    if (linux_ordered_prefix_v1(mode)) return linux_ordered_paired_off_v1(profile);
    if (!json_object_has_member(profile, "start_layer")) return TRUE;
    JsonNode *layer = json_object_get_member(profile, "start_layer");
    if (layer == NULL || !JSON_NODE_HOLDS_VALUE(layer) || json_node_get_value_type(layer) != G_TYPE_STRING) return FALSE;
    const char *value = json_node_get_string(layer);
    return value != NULL && (!value[0] || strcmp(value, "off") == 0 || strcmp(value, "aes-256-gcm") == 0 || strcmp(value, "aes-256-gcm+xor-whitening") == 0);
}

static const char *linux_ordered_imported_mode_v1(JsonObject *profile) {
    JsonObject *external = linux_ordered_object_v1(profile, "external");
    const char *protocol = linux_ordered_string_v1(external, "protocol");
    if (strcmp(linux_ordered_string_v1(profile, "node_kind"), "external") != 0 ||
        !linux_ordered_flag_v1(external, "ordered_middle_supported") ||
        (strcmp(protocol, "shadowsocks") != 0 && strcmp(protocol, "socks5") != 0 && strcmp(protocol, "http-connect") != 0 && strcmp(protocol, "https-connect") != 0 && strcmp(protocol, "openvpn") != 0)) return "";
    return protocol;
}

static gboolean linux_ordered_imported_v1(JsonObject *profile) {
    return linux_ordered_imported_mode_v1(profile)[0] != '\0';
}

static gboolean linux_ordered_literal_import_off_v1(JsonObject *profile) {
    if (strcmp(linux_ordered_imported_mode_v1(profile), "shadowsocks") ||
        !linux_ordered_flag_v1(linux_ordered_object_v1(profile, "external"), "ordered_local_imported_nodes_supported")) return FALSE;
    JsonNode *layer = json_object_has_member(profile, "start_layer") ? json_object_get_member(profile, "start_layer") : NULL;
    const char *value = linux_ordered_string_v1(profile, "start_layer");
    return (!layer || (JSON_NODE_HOLDS_VALUE(layer) && json_node_get_value_type(layer) == G_TYPE_STRING)) && (!value[0] || !strcmp(value, "off"));
}


static gboolean linux_ordered_hostname_import_off_v1(JsonObject *profile);

/* This capability came from the captured Custom TCP source compiler. */
static gboolean linux_ordered_append_import_off_v1(JsonObject *profile) {
    return !strcmp(linux_ordered_imported_mode_v1(profile), "shadowsocks") &&
        (linux_ordered_literal_import_off_v1(profile) || linux_ordered_hostname_import_off_v1(profile));
}

/* Prefix-only append has its own source family; complete-route modes stay unchanged. */
static gboolean linux_ordered_append_member_v1(JsonObject *profile, const char *mode, guint position) {
    if (!mode) return FALSE;
    if (linux_ordered_prefix_v1(mode)) return linux_ordered_paired_layer_v1(profile, TRUE);
    if (linux_ordered_proxy_mode_v1(mode) && linux_ordered_paired_off_v1(profile)) return TRUE;
    return position > 0 && !strcmp(mode, "shadowsocks") && linux_ordered_append_import_off_v1(profile);
}

static gboolean linux_ordered_append_family_member_v1(JsonObject *profile, const char *mode, guint position, gboolean proxy_entry) {
    return (!proxy_entry || linux_ordered_paired_proxy_member_v1(profile, mode)) && linux_ordered_append_member_v1(profile, mode, position);
}

static gboolean linux_ordered_external_final_profile_v1(JsonObject *profile) {
    return linux_ordered_literal_import_off_v1(profile) &&
        linux_ordered_flag_v1(linux_ordered_object_v1(profile, "external"), "ordered_external_final");
}

static gboolean linux_ordered_hostname_import_off_v1(JsonObject *profile) {
    JsonObject *external = linux_ordered_object_v1(profile, "external");
    if (!external || !linux_ordered_flag_v1(external,"ordered_hostname_execution_middle_supported")) return FALSE;
    const char *literal[] = {"ordered_execution_middle_supported","ordered_local_imported_nodes_supported"};
    for (guint i=0;i<G_N_ELEMENTS(literal);i++) {
        JsonNode *v = json_object_get_member(external,literal[i]);
        if (!v || !JSON_NODE_HOLDS_VALUE(v) || json_node_get_value_type(v)!=G_TYPE_BOOLEAN || json_node_get_boolean(v)) return FALSE;
    }
    JsonNode *layer = json_object_get_member(profile,"start_layer");
    return !layer || (JSON_NODE_HOLDS_VALUE(layer) && json_node_get_value_type(layer)==G_TYPE_STRING &&
        (!*json_node_get_string(layer) || !strcmp(json_node_get_string(layer),"off")));
}

static gboolean linux_ordered_local_imported_path_v1(const LinuxOrderedSelectionV1 *selection, JsonObject *catalog) {
    if (selection == NULL) return FALSE;
    gboolean selected = strcmp(selection->execution, "local") != 0;
    if (selected && !linux_ordered_multiple_imported_shape_v1(selection->nodes)) return FALSE;
    const char *hint = selected ? "ordered_multiple_imported_execution_supported" : "ordered_local_imported_nodes_supported";
    guint count = json_array_get_length(selection->nodes), imports = 0;
    if (count < 3 || (count > 8 && !(selected ? linux_ordered_extended_selected_shape_v1(selection->nodes) : linux_ordered_extended_shape_v1(selection->nodes)) && (selected || !linux_ordered_extended_mixed_shape_v1(selection->nodes))) || strcmp(linux_ordered_string_v1(json_array_get_object_element(selection->nodes, count - 1), "mode"), "shadowsocks") != 0) return FALSE;
    guint packet_prefixes = linux_ordered_imported_packet_prefixes_v1(selection->nodes);
    gboolean paired_stream = FALSE, all_off = TRUE;
    guint hostname_position = 0;
    for (guint position = 0; position < count; position++) {
        JsonObject *row = json_array_get_object_element(selection->nodes, position);
        const char *mode = linux_ordered_string_v1(row, "mode");
        JsonObject *profile = external_source_profile_v24(catalog, linux_ordered_string_v1(row, "id"));
        if (profile == NULL) return FALSE;
        gboolean first_stream = position == packet_prefixes && (position + 2 < count || count > 8);
        gboolean later_stream = packet_prefixes == 1 && position > packet_prefixes && position + 1 < count;
        gboolean host_here = !selected && count >= 4 && !hostname_position && packet_prefixes > 0 &&
            (first_stream || later_stream) && linux_ordered_hostname_import_off_v1(profile);
        all_off = all_off && (host_here || linux_ordered_paired_off_v1(profile) || linux_ordered_literal_import_off_v1(profile));
        if (count > 8) {
            gboolean interior = position >= packet_prefixes && position + 1 < count;
            gboolean imported = strcmp(linux_ordered_string_v1(profile, "node_kind"), "external") == 0;
            JsonNode *raw_layer = json_object_has_member(profile, "start_layer") ? json_object_get_member(profile, "start_layer") : NULL;
            const char *layer = linux_ordered_string_v1(profile, "start_layer");
            if (!packet_prefixes || (!interior && imported) || (raw_layer && (!JSON_NODE_HOLDS_VALUE(raw_layer) || json_node_get_value_type(raw_layer) != G_TYPE_STRING)) ||
                (layer[0] && strcmp(layer, "off") != 0)) return FALSE;
        }
        if (strcmp(linux_ordered_string_v1(profile, "node_kind"), "external") == 0) {
            if ((!linux_ordered_local_ss_position_v1(mode, position, count) && !(position == 0 && linux_ordered_custom_entry_shape_v1(selection->nodes))) || strcmp(linux_ordered_imported_mode_v1(profile), "shadowsocks") != 0 ||
                (!host_here && !linux_ordered_flag_v1(linux_ordered_object_v1(profile, "external"), hint))) return FALSE;
            JsonObject *external = linux_ordered_object_v1(profile,"external");
            JsonNode *source_host = json_object_get_member(external,"ordered_hostname_execution_middle_supported");
            if (source_host && (!JSON_NODE_HOLDS_VALUE(source_host) || json_node_get_value_type(source_host)!=G_TYPE_BOOLEAN || (json_node_get_boolean(source_host) && !host_here))) return FALSE;
            if (host_here) hostname_position = position;
            imports++;
        } else {
            if (!linux_ordered_router_v1(profile)) return FALSE;
            if (position + 1 < count && !linux_ordered_prefix_v1(mode)) {
                if (!packet_prefixes || position < packet_prefixes || strcmp(mode,"shadowsocks")) return FALSE;
                if (selected && (position < 2 || packet_prefixes != 1 ||
                    !linux_ordered_prefix_v1(linux_ordered_string_v1(json_array_get_object_element(selection->nodes, 0), "mode")))) return FALSE;
                paired_stream = TRUE;
            }
        }
    }
    if (hostname_position > packet_prefixes && imports != count - 2) return FALSE;
    return imports > 0 && (!(paired_stream || hostname_position) || all_off);
}

static JsonObject *linux_ordered_value_v1(const LinuxOrderedSelectionV1 *selection) {
    JsonObject *value = json_object_new();
    json_object_set_string_member(value, "selected_node_id", selection->control);
    json_object_set_string_member(value, "execution", selection->execution);
    json_object_set_array_member(value, "nodes", json_array_ref(selection->nodes));
    json_object_set_object_member(value, "profile_tokens", json_object_ref(selection->tokens));
    return value;
}

static gboolean linux_ordered_socks_execution_layers_v1(const LinuxOrderedSelectionV1 *selection, JsonObject *catalog) {
    guint socks_count = json_array_get_length(selection->nodes);
    if (socks_count < 3 || socks_count > 8) return FALSE;
    for (guint socks_position = 0; socks_position < socks_count; socks_position++) {
        const char *id = linux_ordered_string_v1(json_array_get_object_element(selection->nodes, socks_position), "id");
        JsonObject *profile = external_source_profile_v24(catalog, id);
        if (profile == NULL) return FALSE;
        if (!json_object_has_member(profile, "start_layer")) continue;
        JsonNode *raw = json_object_get_member(profile, "start_layer");
        if (raw == NULL || !JSON_NODE_HOLDS_VALUE(raw) || json_node_get_value_type(raw) != G_TYPE_STRING) return FALSE;
        const char *socks_layer = json_node_get_string(raw);
        if (socks_layer == NULL) return FALSE;
        if (socks_position + 2 != socks_count) {
            if (strcmp(socks_layer, "") != 0 && strcmp(socks_layer, "off") != 0 && strcmp(socks_layer, "aes-256-gcm") != 0 && strcmp(socks_layer, "aes-256-gcm+xor-whitening") != 0) return FALSE;
        } else if (strcmp(socks_layer, "") != 0 && strcmp(socks_layer, "off") != 0) return FALSE;
    }
    return TRUE;
}

static gboolean linux_ordered_openvpn_execution_layers_v1(const LinuxOrderedSelectionV1 *selection, JsonObject *catalog) {
    guint openvpn_count = json_array_get_length(selection->nodes);
    if (openvpn_count < 3 || openvpn_count > 8) return FALSE;
    for (guint openvpn_position = 0; openvpn_position < openvpn_count; openvpn_position++) {
        const char *id = linux_ordered_string_v1(json_array_get_object_element(selection->nodes, openvpn_position), "id");
        JsonObject *profile = external_source_profile_v24(catalog, id);
        if (profile == NULL) return FALSE;
        if (!json_object_has_member(profile, "start_layer")) continue;
        JsonNode *raw = json_object_get_member(profile, "start_layer");
        if (raw == NULL || !JSON_NODE_HOLDS_VALUE(raw) || json_node_get_value_type(raw) != G_TYPE_STRING) return FALSE;
        const char *openvpn_layer = json_node_get_string(raw);
        if (openvpn_layer == NULL) return FALSE;
        if (openvpn_position + 2 != openvpn_count) {
            if (strcmp(openvpn_layer, "") != 0 && strcmp(openvpn_layer, "off") != 0 && strcmp(openvpn_layer, "aes-256-gcm") != 0 && strcmp(openvpn_layer, "aes-256-gcm+xor-whitening") != 0) return FALSE;
        } else if (strcmp(openvpn_layer, "") != 0 && strcmp(openvpn_layer, "off") != 0) return FALSE;
    }
    return TRUE;
}

static gboolean linux_ordered_current_v1(const LinuxOrderedSelectionV1 *selection, JsonObject *catalog) {
    if (selection == NULL || strcmp(selection->control, linux_ordered_string_v1(catalog, "selected_id")) != 0) return FALSE;
    if (linux_ordered_external_final_shape_v1(selection->nodes, selection->control)) {
        if (strcmp(selection->execution, "local") && strcmp(selection->execution, "server") && strcmp(selection->execution, "auto")) return FALSE;
        guint count = json_array_get_length(selection->nodes);
        for (guint i = 0; i < count; i++) {
            JsonObject *row = json_array_get_object_element(selection->nodes, i);
            const char *id = linux_ordered_string_v1(row, "id");
            JsonObject *profile = external_source_profile_v24(catalog, id);
            gboolean eligible = !i ? linux_ordered_paired_layer_v1(profile, TRUE) : i + 1 == count ?
                linux_ordered_external_final_profile_v1(profile) : linux_ordered_literal_import_off_v1(profile);
            if (!eligible || strcmp(linux_ordered_string_v1(profile, "profile_token"), linux_ordered_string_v1(selection->tokens, id))) return FALSE;
        }
        return TRUE;
    }
    guint count = json_array_get_length(selection->nodes);
    if (count < 2) return FALSE;
    gboolean packet_final = linux_ordered_prefix_v1(linux_ordered_string_v1(json_array_get_object_element(selection->nodes, count-1), "mode"));
    if (packet_final && (strcmp(selection->execution, "local") || count > 8)) return FALSE;
    gboolean local_imported = linux_ordered_local_imported_path_v1(selection, catalog);
    gboolean paired_extended = linux_ordered_extended_paired_path_v1(selection, catalog);
    gboolean paired_hysteria = linux_ordered_hysteria_local_path_v1(selection, catalog);
    gboolean paired_proxy = linux_ordered_paired_proxy_entry_path_v1(selection, catalog);
    if (linux_ordered_paired_proxy_entry_source_v1(selection->nodes, catalog) && !paired_proxy) return FALSE;
    if (linux_ordered_hysteria_local_shape_v1(selection->nodes) && !paired_hysteria) return FALSE;
    gboolean multiple_imported = strcmp(selection->execution, "local") != 0 && linux_ordered_multiple_imported_shape_v1(selection->nodes);
    if ((multiple_imported || json_array_get_length(selection->nodes) > 8) && !local_imported && !paired_extended && !paired_hysteria && !paired_proxy) return FALSE;
    for (guint i = 0; i < json_array_get_length(selection->nodes); i++) {
        const char *id = linux_ordered_string_v1(json_array_get_object_element(selection->nodes, i), "id");
        JsonObject *profile = external_source_profile_v24(catalog, id);
        const char *mode = linux_ordered_string_v1(json_array_get_object_element(selection->nodes, i), "mode");
        if (packet_final && (!linux_ordered_prefix_v1(mode) || !linux_ordered_paired_off_v1(profile))) return FALSE;
        gboolean imported = linux_ordered_imported_v1(profile);
        gboolean connect_execution = strcmp(mode, "http-connect") == 0 || strcmp(mode, "https-connect") == 0;
        gboolean socks_execution = strcmp(mode, "socks5") == 0;
        gboolean openvpn_execution = strcmp(mode, "openvpn") == 0;
        if (imported && strcmp(selection->execution, "local") != 0 && !multiple_imported) {
            const char *capability = openvpn_execution ? "ordered_openvpn_execution_middle_supported" : (socks_execution ? "ordered_socks_execution_middle_supported" : (connect_execution ? "ordered_connect_execution_middle_supported" : "ordered_execution_middle_supported"));
            gboolean execution_middle = linux_ordered_flag_v1(linux_ordered_object_v1(profile, "external"), capability);
            if (!connect_execution && !socks_execution && strcmp(mode, "shadowsocks") == 0) {
                JsonObject *external = linux_ordered_object_v1(profile, "external");
                JsonNode *literal = external != NULL && json_object_has_member(external, capability) ? json_object_get_member(external, capability) : NULL;
                JsonNode *hostname = external != NULL && json_object_has_member(external, "ordered_hostname_execution_middle_supported") ? json_object_get_member(external, "ordered_hostname_execution_middle_supported") : NULL;
                if (literal == NULL || !JSON_NODE_HOLDS_VALUE(literal) || json_node_get_value_type(literal) != G_TYPE_BOOLEAN ||
                    (hostname != NULL && (!JSON_NODE_HOLDS_VALUE(hostname) || json_node_get_value_type(hostname) != G_TYPE_BOOLEAN))) return FALSE;
                gboolean hostname_middle = hostname != NULL && json_node_get_boolean(hostname);
                if (execution_middle && hostname_middle) return FALSE;
                if (!execution_middle && json_array_get_length(selection->nodes) >= 4) execution_middle = hostname_middle;
            }
            if (i + 2 != json_array_get_length(selection->nodes) || (!connect_execution && !socks_execution && !openvpn_execution && strcmp(mode, "shadowsocks") != 0) ||
                !execution_middle) return FALSE;
            if (socks_execution && !linux_ordered_socks_execution_layers_v1(selection, catalog)) return FALSE;
            if (openvpn_execution && !linux_ordered_openvpn_execution_layers_v1(selection, catalog)) return FALSE;
            if (connect_execution) {
                for (guint position = 0; position + 1 < json_array_get_length(selection->nodes); position++) {
                    const char *prefix_id = linux_ordered_string_v1(json_array_get_object_element(selection->nodes, position), "id");
                    JsonObject *prefix_profile = external_source_profile_v24(catalog, prefix_id);
                    if (prefix_profile == NULL) return FALSE;
                    if (!json_object_has_member(prefix_profile, "start_layer")) continue;
                    JsonNode *raw = json_object_get_member(prefix_profile, "start_layer");
                    if (raw == NULL || !JSON_NODE_HOLDS_VALUE(raw) || json_node_get_value_type(raw) != G_TYPE_STRING) return FALSE;
                    const char *connect_layer = json_node_get_string(raw);
                    if (connect_layer == NULL) return FALSE;
                    if (position + 2 < json_array_get_length(selection->nodes)) {
                        if (strcmp(connect_layer, "") != 0 && strcmp(connect_layer, "off") != 0 && strcmp(connect_layer, "aes-256-gcm") != 0 && strcmp(connect_layer, "aes-256-gcm+xor-whitening") != 0) return FALSE;
                    } else if (strcmp(connect_layer, "") != 0 && strcmp(connect_layer, "off") != 0) return FALSE;
                }
                const char *final_id = linux_ordered_string_v1(json_array_get_object_element(selection->nodes, json_array_get_length(selection->nodes) - 1), "id");
                JsonObject *final_profile = external_source_profile_v24(catalog, final_id);
                if (final_profile != NULL && json_object_has_member(final_profile, "start_layer")) {
                    JsonNode *raw_layer = json_object_get_member(final_profile, "start_layer");
                    if (!JSON_NODE_HOLDS_VALUE(raw_layer) || json_node_get_value_type(raw_layer) != G_TYPE_STRING) return FALSE;
                }
                const char *layer = linux_ordered_string_v1(final_profile, "start_layer");
                if (strcmp(layer, "") != 0 && strcmp(layer, "off") != 0 && strcmp(layer, "aes-256-gcm") != 0 && strcmp(layer, "aes-256-gcm+xor-whitening") != 0) return FALSE;
            }
        }
        gboolean admitted = imported ? (linux_ordered_imported_position_v1(mode, i, json_array_get_length(selection->nodes)) || (local_imported && (linux_ordered_local_ss_position_v1(mode, i, json_array_get_length(selection->nodes)) || (i == 0 && linux_ordered_custom_entry_shape_v1(selection->nodes))))) && strcmp(mode, linux_ordered_imported_mode_v1(profile)) == 0 : linux_ordered_router_v1(profile) && (i + 1 == json_array_get_length(selection->nodes) || linux_ordered_prefix_v1(mode) || paired_hysteria || paired_proxy || (local_imported && !strcmp(mode,"shadowsocks")));
        if (!admitted || (i + 1 == json_array_get_length(selection->nodes) && !linux_ordered_final_profile_v1(profile, mode)) ||
            strcmp(linux_ordered_string_v1(profile, "profile_token"), linux_ordered_string_v1(selection->tokens, id)) != 0) return FALSE;
    }
    return TRUE;
}

static const char *linux_ordered_prepared_candidate_mode_v1(const LinuxOrderedSelectionV1 *selection, JsonObject *catalog, int position) {
    if (!selection || position<0) return "";
    guint count=json_array_get_length(selection->nodes);
    gboolean selected=!strcmp(selection->execution,"auto") || !strcmp(selection->execution,"server");
    if (strcmp(selection->execution,"local") && !selected) return "";
    if (selected && (count<3 || (guint)position+2>=count)) return "";
    if (count<2 || count>ROUTERVPN_PHYSICAL_TRAVERSAL_DEPTH || (guint)position+1>=count) return "";
    const char *final=linux_ordered_string_v1(json_array_get_object_element(selection->nodes,count-1),"mode");
    if (strcmp(final,"shadowsocks") && strcmp(final,"hysteria2") &&
        !((guint)position+2==count && count<=8 && linux_ordered_prefix_v1(final))) return "";
    gboolean packet_replacement=(guint)position+2<count;
    for (guint i=0;i<count;i++) {
        JsonObject *node=json_array_get_object_element(selection->nodes,i);
        JsonObject *profile=external_source_profile_v24(catalog,linux_ordered_string_v1(node,"id"));
        const char *mode=linux_ordered_string_v1(node,"mode");
        if (!strcmp(linux_ordered_string_v1(profile,"node_kind"),"external")) {
            if (!packet_replacement || count>8 || i==0 || i==count-1 || i==(guint)position+1 ||
                strcmp(mode,"shadowsocks") || strcmp(final,"shadowsocks") || !linux_ordered_literal_import_off_v1(profile)) return "";
            continue;
        }
        if (!linux_ordered_paired_layer_v1(profile,packet_replacement && count<=8 && i<=(guint)position) ||
            (i+1<count && !linux_ordered_prefix_v1(mode)) || (count>8 && strcmp(mode,i+1==count?"shadowsocks":"wg"))) return "";
    }
    if (packet_replacement) return linux_ordered_string_v1(json_array_get_object_element(selection->nodes,position+1),"mode");
    return count<=8 && strcmp(final,"shadowsocks") ? final:"";
}

static gboolean linux_ordered_measurement_prefix_v1(const LinuxOrderedSelectionV1 *selection, JsonObject *catalog, int position) {
    if (!selection || position < 0 || !linux_ordered_current_v1(selection, catalog)) return FALSE;
    guint count = json_array_get_length(selection->nodes);
    if ((guint)position + 1 >= count) return FALSE;
    if (linux_ordered_external_final_shape_v1(selection->nodes, selection->control)) {
        return !strcmp(selection->execution, "local") ||
               (position >= 1 && (!strcmp(selection->execution, "server") || !strcmp(selection->execution, "auto")));
    }
    if (*linux_ordered_prepared_candidate_mode_v1(selection,catalog,position)) return TRUE;
    const char *mode = linux_ordered_string_v1(json_array_get_object_element(selection->nodes, position), "mode");
    if (!strcmp(mode, "shadowsocks")) {
        JsonObject *first = json_array_get_object_element(selection->nodes, 0), *final = json_array_get_object_element(selection->nodes, count - 1);
        JsonObject *selected = external_source_profile_v24(catalog, linux_ordered_string_v1(json_array_get_object_element(selection->nodes, position), "id"));
        JsonObject *external = linux_ordered_object_v1(selected, "external");
        if (linux_ordered_flag_v1(external, "ordered_hostname_execution_middle_supported") &&
            (linux_ordered_flag_v1(external, "ordered_execution_middle_supported") || linux_ordered_flag_v1(external, "ordered_local_imported_nodes_supported"))) return FALSE;
        gboolean complete = linux_ordered_local_imported_path_v1(selection, catalog);
        if ((!strcmp(selection->execution,"auto") || !strcmp(selection->execution,"server")) && position >= 1 &&
            linux_ordered_prefix_v1(linux_ordered_string_v1(first,"mode")) && !strcmp(linux_ordered_string_v1(final,"mode"),"shadowsocks")) {
            if (count >= 4) {
                gboolean insert = (guint)position + 2 < count;
                if (!complete || (insert && count >= 96)) return FALSE;
                for (guint i = 0; i < count; i++) {
                    JsonObject *row = json_array_get_object_element(selection->nodes,i);
                    JsonObject *profile = external_source_profile_v24(catalog,linux_ordered_string_v1(row,"id"));
                    JsonNode *layer = json_object_get_member(profile,"start_layer");
                    if ((i && strcmp(linux_ordered_string_v1(row,"mode"),"shadowsocks")) ||
                        (layer && (!JSON_NODE_HOLDS_VALUE(layer) || json_node_get_value_type(layer) != G_TYPE_STRING ||
                         (*json_node_get_string(layer) && strcmp(json_node_get_string(layer),"off"))))) return FALSE;
                }
                return TRUE;
            }
            return count == 3 && linux_ordered_paired_off_v1(external_source_profile_v24(catalog,linux_ordered_string_v1(first,"id"))) &&
                linux_ordered_paired_off_v1(external_source_profile_v24(catalog,linux_ordered_string_v1(final,"id"))) &&
                linux_ordered_literal_import_off_v1(selected) && linux_ordered_flag_v1(external,"ordered_execution_middle_supported") &&
                !linux_ordered_flag_v1(external,"ordered_hostname_execution_middle_supported");
        }
        gboolean hostname = !complete && count >= 3 && count <= 8 && (guint)position + 2 == count &&
            linux_ordered_flag_v1(external, "ordered_hostname_execution_middle_supported") &&
            !linux_ordered_flag_v1(external, "ordered_execution_middle_supported") &&
            !linux_ordered_flag_v1(external, "ordered_local_imported_nodes_supported");
        if (position < 1 || (count > 8 && !linux_ordered_extended_shape_v1(selection->nodes) && !linux_ordered_extended_mixed_shape_v1(selection->nodes)) || strcmp(selection->execution, "local") || (!hostname && !complete) ||
            !linux_ordered_prefix_v1(linux_ordered_string_v1(first, "mode")) || strcmp(linux_ordered_string_v1(final, "mode"), "shadowsocks") ||
            !linux_ordered_paired_off_v1(external_source_profile_v24(catalog, linux_ordered_string_v1(first, "id"))) ||
            !linux_ordered_paired_off_v1(external_source_profile_v24(catalog, linux_ordered_string_v1(final, "id")))) return FALSE;
        gboolean imported = FALSE;
        for (int i = 1; i <= (count > 8 ? (int)count - 2 : position); i++) {
            JsonObject *row = json_array_get_object_element(selection->nodes, i);
            const char *protocol = linux_ordered_string_v1(row, "mode");
            JsonObject *source = external_source_profile_v24(catalog, linux_ordered_string_v1(row, "id"));
            if (!strcmp(protocol, "shadowsocks")) {
                imported = TRUE;
                if (hostname && i != position) return FALSE;
                if (!hostname && linux_ordered_paired_off_v1(source)) {
                    // local_imported_path above validated each original private and public stream.
                    continue;
                }
                if (strcmp(linux_ordered_imported_mode_v1(source), "shadowsocks")) return FALSE;
                if (!hostname && !linux_ordered_literal_import_off_v1(source) &&
                    !linux_ordered_hostname_import_off_v1(source)) return FALSE;
                JsonNode *layer = json_object_has_member(source, "start_layer") ? json_object_get_member(source, "start_layer") : NULL;
                if (layer && (!JSON_NODE_HOLDS_VALUE(layer) || json_node_get_value_type(layer) != G_TYPE_STRING)) return FALSE;
                const char *value = linux_ordered_string_v1(source, "start_layer");
                if (value[0] && strcmp(value, "off")) return FALSE;
            } else if (imported || !linux_ordered_prefix_v1(protocol) || !linux_ordered_paired_off_v1(source)) return FALSE;
        }
        return imported;
    }
    if (!linux_ordered_prefix_v1(mode)) return FALSE;
    if (count < 8) return TRUE;
    if (count >= ROUTERVPN_PHYSICAL_TRAVERSAL_DEPTH || strcmp(selection->execution, "local")) return FALSE;
    JsonObject *final = json_array_get_object_element(selection->nodes, count - 1);
    if (strcmp(linux_ordered_string_v1(final, "mode"), "shadowsocks") ||
        !linux_ordered_paired_off_v1(external_source_profile_v24(catalog, linux_ordered_string_v1(final, "id")))) return FALSE;
    guint packet_prefixes = linux_ordered_imported_packet_prefixes_v1(selection->nodes);
    gboolean paired = TRUE, imported = packet_prefixes > 0 && (guint)position < packet_prefixes;
    for (guint i = 0; i + 1 < count; i++) {
        JsonObject *row = json_array_get_object_element(selection->nodes, i);
        JsonObject *source = external_source_profile_v24(catalog, linux_ordered_string_v1(row, "id"));
        const char *protocol = linux_ordered_string_v1(row, "mode");
        paired = paired && !strcmp(protocol, "wg") && linux_ordered_paired_off_v1(source);
        if (i < packet_prefixes) imported = imported && linux_ordered_prefix_v1(protocol) && linux_ordered_paired_off_v1(source);
        else {
            JsonNode *layer = source && json_object_has_member(source, "start_layer") ? json_object_get_member(source, "start_layer") : NULL;
            imported = imported && !strcmp(protocol, "shadowsocks") && linux_ordered_literal_import_off_v1(source) &&
                (!layer || (JSON_NODE_HOLDS_VALUE(layer) && json_node_get_value_type(layer) == G_TYPE_STRING)) &&
                (!linux_ordered_string_v1(source, "start_layer")[0] || !strcmp(linux_ordered_string_v1(source, "start_layer"), "off"));
        }
    }
    return paired || imported;
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
        g_key_file_set_string(key, "state", "multihop_execution", selection->execution);
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
        persisted = persisted && error == NULL && on == enabled && g_strcmp0(execution, selection->execution) == 0;
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
    if (linux_ordered_external_final_shape_v1(selection->nodes, selection->control))
        json_object_set_boolean_member(body, "external_final", TRUE);
    json_object_set_array_member(body, "nodes", json_array_ref(selection->nodes));
    json_object_set_string_member(body, "execution", selection->execution);
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
    json_object_set_string_member(body, "multihop_execution", selection->execution);
    json_object_set_string_member(body, "expected_selected_node_id", selection->control);
    json_object_set_object_member(body, "expected_profile_tokens", json_object_ref(selection->tokens));
    char *raw = linux_ordered_json_v1(body); json_object_unref(body); return raw;
}

/* Load protects the controller's CURRENT saved graph. The saved target's
 * independent source inventory is validated by the controller transaction.
 * An unsaved local editor draft is deliberately not an input to this capture. */
static char *linux_ordered_load_capture_v1(JsonObject *catalog, const char *control, const char *id, const char *expected_mode) {
    JsonObject *profile = external_source_profile_v24(catalog, control);
    const char *token = linux_ordered_string_v1(profile, "profile_token");
    if (!expected_mode || !expected_mode[0] || !external_source_id_v24(id) || profile == NULL || !external_source_token_v24(token) ||
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
            valid = valid && count >= 2 && (count <= 8 || linux_ordered_hysteria_local_shape_v1(nodes) || linux_ordered_extended_shape_v1(nodes) || linux_ordered_extended_paired_shape_v1(nodes) || linux_ordered_extended_mixed_shape_v1(nodes));
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
    json_object_set_string_member(body, "id", id); json_object_set_string_member(body, "expected_mode", expected_mode); json_object_set_string_member(body, "expected_selected_node_id", control);
    json_object_set_object_member(body, "expected_profile_tokens", tokens);
    char *raw = linux_ordered_json_v1(body); json_object_unref(body); return raw;
}

static char *linux_ordered_load_body_v1(LinuxUnifiedV8 *unified, const char *id, const char *expected_mode) {
    JsonNode *displayed = g_object_get_data(G_OBJECT(unified->app->window), "router-vpn-source-catalog-v24");
    JsonObject *catalog = displayed != NULL && JSON_NODE_HOLDS_OBJECT(displayed) ? json_node_get_object(displayed) : NULL;
    return linux_ordered_load_capture_v1(catalog, gtk_combo_box_get_active_id(GTK_COMBO_BOX(unified->node)), id, expected_mode);
}

static gboolean linux_ordered_response_present_v1(JsonObject *payload) {
    JsonNode *nodes = payload != NULL && json_object_has_member(payload, "multihop_nodes") ? json_object_get_member(payload, "multihop_nodes") : NULL;
    return nodes != NULL && !JSON_NODE_HOLDS_NULL(nodes) && (!JSON_NODE_HOLDS_ARRAY(nodes) || json_array_get_length(json_node_get_array(nodes)) != 0);
}

static LinuxOrderedSelectionV1 *linux_ordered_response_v1(JsonObject *payload) {
    JsonArray *nodes = linux_ordered_array_v1(payload, "multihop_nodes");
    const char *control = linux_ordered_string_v1(payload, "selected_node_id");
    if (!linux_ordered_rows_v1(nodes, control) || !linux_ordered_flag_v1(payload, "multihop_enabled") ||
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
    if (!linux_ordered_execution_v1(selection, linux_ordered_string_v1(payload, "multihop_execution"))) { linux_ordered_selection_free_v1(selection); selection = NULL; }
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

/* A Save/Update response must retain the requested complete path and choice. */
static gboolean linux_ordered_same_path_v1(const LinuxOrderedSelectionV1 *committed, const LinuxOrderedSelectionV1 *original) {
    if (committed == NULL || original == NULL || strcmp(committed->control, original->control) != 0 ||
        strcmp(committed->execution, original->execution) != 0 ||
        json_array_get_length(committed->nodes) != json_array_get_length(original->nodes)) return FALSE;
    for (guint i = 0; i < json_array_get_length(committed->nodes); i++) {
        JsonObject *a = json_array_get_object_element(committed->nodes, i), *b = json_array_get_object_element(original->nodes, i);
        if (strcmp(linux_ordered_string_v1(a, "id"), linux_ordered_string_v1(b, "id")) != 0 ||
            strcmp(linux_ordered_string_v1(a, "mode"), linux_ordered_string_v1(b, "mode")) != 0) return FALSE;
    }
    return TRUE;
}

static const char *linux_ordered_execution_capability_v1(const LinuxOrderedSelectionV1 *selection) {
    if (linux_ordered_external_final_shape_v1(selection->nodes, selection->control)) return "ordered_external_final_executions";
    if (strcmp(selection->execution, "local") != 0 && linux_ordered_multiple_imported_shape_v1(selection->nodes)) return "ordered_multiple_imported_executions";
    guint count = json_array_get_length(selection->nodes);
    if (strcmp(selection->execution, "local") != 0 && count >= 2 && count <= 8 &&
        strcmp(linux_ordered_string_v1(json_array_get_object_element(selection->nodes, count - 1), "mode"), "hysteria2") == 0) {
        gboolean paired_hysteria = TRUE;
        for (guint position = 0; position + 1 < count; position++) {
            if (!linux_ordered_prefix_v1(linux_ordered_string_v1(json_array_get_object_element(selection->nodes, position), "mode"))) paired_hysteria = FALSE;
        }
        if (paired_hysteria) return "ordered_hysteria_executions";
    }
    if (strcmp(selection->execution, "local") != 0 && count >= 3 && count <= 8) {
        const char *middle = linux_ordered_string_v1(json_array_get_object_element(selection->nodes, count - 2), "mode");
        if (strcmp(middle, "openvpn") == 0) return "ordered_openvpn_executions";
        if (strcmp(middle, "socks5") == 0) return "ordered_socks_trio_executions";
        if (strcmp(middle, "http-connect") == 0 || strcmp(middle, "https-connect") == 0) return "ordered_connect_trio_executions";
    }
    return "ordered_executions";
}

static gboolean linux_ordered_connect_v1(LinuxUnifiedV8 *unified) {
    LinuxOrderedStateV1 *owned = linux_ordered_state_v1(unified);
    if (owned->selection == NULL && !owned->invalid) return FALSE;
    if (owned->invalid) { append_diag(unified->app, "The saved ordered path is invalid. Explicitly create a new path; no pair fallback was selected."); return TRUE; }
    LinuxOrderedSelectionV1 *selection = linux_ordered_selection_v1(owned->selection->control, owned->selection->nodes, owned->selection->tokens);
    if (!linux_ordered_execution_v1(selection, owned->selection->execution)) { linux_ordered_selection_free_v1(selection); return TRUE; }
    guint64 generation = owned->generation;
    gboolean valid = routervpn_require_mutation_idle(unified->app, "starting the captured ordered path") &&
        linux_ordered_owns_v1(owned, generation, selection->control);
    JsonNode *capabilities = valid ? linux_ordered_read_v1("/api/multihop/status") : NULL;
    valid = valid && capabilities != NULL && linux_ordered_flag_v1(json_node_get_object(capabilities), "ordered_nodes_supported");
    JsonArray *executions = valid ? linux_ordered_array_v1(json_node_get_object(capabilities), linux_ordered_execution_capability_v1(selection)) : NULL;
    gboolean admitted = FALSE;
    for (guint i = 0; executions != NULL && i < json_array_get_length(executions); i++) {
        JsonNode *value = json_array_get_element(executions, i);
        if (value == NULL || !JSON_NODE_HOLDS_VALUE(value) || json_node_get_value_type(value) != G_TYPE_STRING) {
            valid = FALSE;
            break;
        }
        if (g_strcmp0(json_node_get_string(value), selection->execution) == 0) admitted = TRUE;
    }
    valid = valid && admitted;
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
    char *control, *final_mode, *external_exit;
    JsonNode *catalog;
    GPtrArray *ids, *modes;
    GtkWidget *dialog, *list, *candidate, *transport, *execution, *status, *add, *remove, *up, *down;
    gboolean syncing, closed, append_only;
    char append_revision[33];
    GtkWidget *append_mode, *prefix_only, *complete_prefix;
    char *offered_draft;
    guint next_measurement;
    int next_position;
    char *next_draft;
} LinuxOrderedEditorV1;

static void linux_ordered_cancel_next_v1(LinuxOrderedEditorV1 *editor) {
    if (editor->next_measurement) {
        g_source_remove(editor->next_measurement);
        editor->next_measurement = 0;
    }
    g_clear_pointer(&editor->next_draft, g_free);
}

static char *linux_ordered_append_body_v1(LinuxOrderedEditorV1 *editor);
static gboolean linux_ordered_can_complete_v1(LinuxOrderedEditorV1 *editor);
static gboolean linux_ordered_append_current_v1(LinuxOrderedEditorV1 *editor, JsonArray *nodes, JsonObject *tokens, JsonObject *current);
static gboolean linux_ordered_adopt_append_v1(LinuxOrderedEditorV1 *editor, const char *captured, int position, JsonObject *response);
static gboolean linux_ordered_continue_measured_v1(gpointer data);
static void linux_ordered_measure_next_v1(GtkButton *button, gpointer data);

static gboolean linux_ordered_editor_proxy_entry_v1(const LinuxOrderedEditorV1 *editor) {
    return editor->ids->len > 0 && editor->ids->len == editor->modes->len &&
        linux_ordered_proxy_mode_v1(g_ptr_array_index(editor->modes, 0)) &&
        linux_ordered_router_v1(external_source_profile_v24(json_node_get_object(editor->catalog), g_ptr_array_index(editor->ids, 0)));
}

static const char *linux_ordered_append_requested_v1(const char *choice) {
    if (!g_strcmp0(choice,"server-wg") || !g_strcmp0(choice,"server-awg2-fast") ||
        !g_strcmp0(choice,"server-awg2-strong") || !g_strcmp0(choice,"server-shadowsocks") || !g_strcmp0(choice,"server-hysteria2")) return "server";
    if (!g_strcmp0(choice,"auto-wg") || !g_strcmp0(choice,"auto-awg2-fast") ||
        !g_strcmp0(choice,"auto-awg2-strong") || !g_strcmp0(choice,"auto-shadowsocks") || !g_strcmp0(choice,"auto-hysteria2")) return "auto";
    return "local";
}
static const char *linux_ordered_append_mode_v1(const char *choice) {
    if (!g_strcmp0(choice,"server-wg") || !g_strcmp0(choice,"auto-wg")) return "wg";
    if (!g_strcmp0(choice,"server-awg2-fast") || !g_strcmp0(choice,"auto-awg2-fast")) return "awg2-fast";
    if (!g_strcmp0(choice,"server-awg2-strong") || !g_strcmp0(choice,"auto-awg2-strong")) return "awg2-strong";
    if (!g_strcmp0(choice,"server-hysteria2") || !g_strcmp0(choice,"auto-hysteria2")) return "hysteria2";
    if (!g_strcmp0(choice,"server-shadowsocks") || !g_strcmp0(choice,"auto-shadowsocks") ||
        !g_strcmp0(choice,"external-shadowsocks")) return "shadowsocks";
    return choice;
}
static gboolean linux_ordered_execution_append_v1(const LinuxOrderedEditorV1 *editor, const char *next_mode) {
    if (!linux_ordered_prefix_v1(next_mode) && g_strcmp0(next_mode,"shadowsocks") && g_strcmp0(next_mode,"hysteria2")) return FALSE;
    if (!editor->append_only || editor->external_exit || editor->ids->len < 1 || editor->ids->len > 95 || editor->ids->len != editor->modes->len) return FALSE;
    JsonObject *catalog=json_node_get_object(editor->catalog);
    if (!g_strcmp0(g_ptr_array_index(editor->modes,0),"shadowsocks")) {
        if (g_strcmp0(next_mode,"shadowsocks")) return FALSE;
        for (guint i=0;i<editor->ids->len;i++) {
            JsonObject *profile=external_source_profile_v24(catalog,g_ptr_array_index(editor->ids,i));
            const char *mode=g_ptr_array_index(editor->modes,i);
            if (g_strcmp0(mode,"shadowsocks") || !linux_ordered_router_v1(profile) || !linux_ordered_paired_proxy_member_v1(profile,mode)) return FALSE;
        }
        return TRUE;
    }
    for (guint i=0;i<editor->ids->len;i++) {
        JsonObject *profile=external_source_profile_v24(catalog,g_ptr_array_index(editor->ids,i));
        const char *mode=g_ptr_array_index(editor->modes,i);
        if (!linux_ordered_router_v1(profile) || !linux_ordered_paired_off_v1(profile)) return FALSE;
        if (!linux_ordered_prefix_v1(mode)) {
            if (i==0 || (strcmp(mode,"shadowsocks") && strcmp(mode,"hysteria2")) || !linux_ordered_paired_proxy_member_v1(profile,mode)) return FALSE;
        }
    }
    return TRUE;
}

static const char *linux_ordered_editor_final_mode_v1(LinuxOrderedEditorV1 *editor) {
    return editor->final_mode != NULL ? editor->final_mode : "shadowsocks";
}

static const char *linux_ordered_editor_exit_v1(const LinuxOrderedEditorV1 *editor) {
    return editor->external_exit ? editor->external_exit : editor->control;
}

static gboolean linux_ordered_editor_hysteria_v1(LinuxOrderedEditorV1 *editor, int position, const char *id,
                                                   const char *mode, const char *final_mode) {
    const char *execution = editor->execution ? gtk_combo_box_get_active_id(GTK_COMBO_BOX(editor->execution)) : NULL;
    if (editor->external_exit || !final_mode || g_strcmp0(execution, "local") || position < -1 ||
        position > (int)editor->ids->len || (position >= 0 && (!id || !mode))) return FALSE;
    guint final = editor->ids->len + (position == (int)editor->ids->len);
    g_autoptr(JsonArray) nodes = json_array_new();
    for (guint i = 0; i <= final; i++) {
        JsonObject *row = json_object_new();
        const char *source = i == final ? editor->control : (int)i == position ? id : g_ptr_array_index(editor->ids, i);
        const char *transport = i == final ? final_mode : (int)i == position ? mode : g_ptr_array_index(editor->modes, i);
        json_object_set_string_member(row, "id", source);
        json_object_set_string_member(row, "mode", transport);
        json_array_add_object_element(nodes, row);
    }
    LinuxOrderedSelectionV1 proposal = {.nodes = nodes, .execution = (char *)execution};
    return linux_ordered_rows_v1(nodes, editor->control) &&
        (linux_ordered_hysteria_local_path_v1(&proposal, json_node_get_object(editor->catalog)) ||
         linux_ordered_paired_proxy_entry_path_v1(&proposal, json_node_get_object(editor->catalog)));
}

static gboolean linux_ordered_editor_final_allowed_v1(LinuxOrderedEditorV1 *editor, const char *mode) {
    if (editor->external_exit) return !strcmp(mode, "shadowsocks");
    if (linux_ordered_editor_hysteria_v1(editor, -1, NULL, NULL, mode)) return TRUE;
    if (!linux_ordered_final_profile_v1(external_source_profile_v24(json_node_get_object(editor->catalog), editor->control), mode)) return FALSE;
    if (linux_ordered_prefix_v1(mode)) {
        const char *execution = editor->execution ? gtk_combo_box_get_active_id(GTK_COMBO_BOX(editor->execution)) : NULL;
        if (g_strcmp0(execution, "local") || editor->ids->len < 1 || editor->ids->len > 7) return FALSE;
        JsonObject *catalog = json_node_get_object(editor->catalog);
        for (guint i = 0; i < editor->ids->len; i++) {
            if (!linux_ordered_prefix_v1(g_ptr_array_index(editor->modes, i)) ||
                !linux_ordered_paired_off_v1(external_source_profile_v24(catalog, g_ptr_array_index(editor->ids, i)))) return FALSE;
        }
    }
    if (g_strcmp0(mode, "hysteria2") == 0) for (guint i = 0; i < editor->modes->len; i++)
        if (g_strcmp0(g_ptr_array_index(editor->modes, i), "shadowsocks") == 0 || g_strcmp0(g_ptr_array_index(editor->modes, i), "socks5") == 0 || g_strcmp0(g_ptr_array_index(editor->modes, i), "http-connect") == 0 || g_strcmp0(g_ptr_array_index(editor->modes, i), "https-connect") == 0 || g_strcmp0(g_ptr_array_index(editor->modes, i), "openvpn") == 0) return FALSE;
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

static void linux_ordered_queue_append_v1(LinuxOrderedEditorV1 *editor) {
    linux_ordered_cancel_next_v1(editor);
    if (!editor->append_only || !linux_ordered_editable_v1(editor) || editor->ids->len<1 || editor->ids->len>95) return;
    editor->next_draft=linux_ordered_append_body_v1(editor);
    if (!editor->next_draft) return;
    editor->next_position=(int)editor->ids->len-1;
    editor->next_measurement=g_idle_add(linux_ordered_continue_measured_v1,editor);
}

/* Check the proposed stream against the complete displayed catalog, including
 * its paired final, before adding an intermediate or changing its transport. */
static gboolean linux_ordered_editor_stream_v1(LinuxOrderedEditorV1 *editor, guint position, const char *id) {
    const char *execution = editor->execution ? gtk_combo_box_get_active_id(GTK_COMBO_BOX(editor->execution)) : NULL;
    if (!execution || !id || position > editor->ids->len) return FALSE;
    gboolean selected = !strcmp(execution, "server") || !strcmp(execution, "auto");
    if (!selected && (strcmp(execution, "local") || strcmp(linux_ordered_imported_mode_v1(
        external_source_profile_v24(json_node_get_object(editor->catalog), id)), "shadowsocks"))) return FALSE;
    guint final = editor->ids->len + (position == editor->ids->len);
    g_autoptr(JsonArray) nodes = json_array_new();
    for (guint i = 0; i <= final; i++) {
        JsonObject *row = json_object_new();
        const char *source = i == final ? editor->control : i == position ? id : g_ptr_array_index(editor->ids, i);
        const char *mode = i == final ? linux_ordered_editor_final_mode_v1(editor) :
            i == position ? "shadowsocks" : g_ptr_array_index(editor->modes, i);
        json_object_set_string_member(row, "id", source);
        json_object_set_string_member(row, "mode", mode);
        json_array_add_object_element(nodes, row);
    }
    LinuxOrderedSelectionV1 proposal = {.nodes = nodes, .execution = (char *)execution};
    return linux_ordered_rows_v1(nodes, editor->control) && linux_ordered_local_imported_path_v1(&proposal, json_node_get_object(editor->catalog));
}

static gboolean linux_ordered_editor_can_extend_v1(LinuxOrderedEditorV1 *editor) {
    if (editor->append_only) {
        const char *id=gtk_combo_box_get_active_id(GTK_COMBO_BOX(editor->candidate));
        if(!id || editor->ids->len>=95)return FALSE;
        JsonObject *profile=external_source_profile_v24(json_node_get_object(editor->catalog),id);
        if(!linux_ordered_append_family_member_v1(profile,"wg",editor->ids->len,linux_ordered_editor_proxy_entry_v1(editor)) &&
           !linux_ordered_append_family_member_v1(profile,"shadowsocks",editor->ids->len,linux_ordered_editor_proxy_entry_v1(editor)))return FALSE;
        for(guint i=0;i<editor->ids->len;i++)if(!strcmp(id,g_ptr_array_index(editor->ids,i)))return FALSE;
        return TRUE;
    }
    if (editor->external_exit) {
        const char *id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(editor->candidate));
        return editor->ids->len + 1 < ROUTERVPN_PHYSICAL_TRAVERSAL_DEPTH && id && strcmp(id, editor->external_exit) &&
            linux_ordered_literal_import_off_v1(external_source_profile_v24(json_node_get_object(editor->catalog), id));
    }
    if (linux_ordered_editor_hysteria_v1(editor, (int)editor->ids->len,
        gtk_combo_box_get_active_id(GTK_COMBO_BOX(editor->candidate)), "wg", linux_ordered_editor_final_mode_v1(editor))) return TRUE;
    if (editor->ids->len < 7) return TRUE;
    if (linux_ordered_editor_stream_v1(editor, editor->ids->len,
        gtk_combo_box_get_active_id(GTK_COMBO_BOX(editor->candidate)))) return TRUE;
    if (editor->ids->len + 1 >= ROUTERVPN_PHYSICAL_TRAVERSAL_DEPTH ||
        g_strcmp0(gtk_combo_box_get_active_id(GTK_COMBO_BOX(editor->execution)), "local") != 0 ||
        g_strcmp0(linux_ordered_editor_final_mode_v1(editor), "shadowsocks") != 0) return FALSE;
    const char *id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(editor->candidate));
    if (id == NULL) return FALSE;
    JsonObject *catalog = json_node_get_object(editor->catalog);
    JsonObject *profile = external_source_profile_v24(catalog, id);
    gboolean paired = linux_ordered_paired_off_v1(profile) && linux_ordered_paired_off_v1(external_source_profile_v24(catalog, editor->control));
    gboolean mixed = linux_ordered_literal_import_off_v1(profile) && linux_ordered_paired_off_v1(external_source_profile_v24(catalog, editor->control));
    gboolean stream = FALSE;
    for (guint i = 0; i < editor->modes->len; i++) {
        const char *mode = g_ptr_array_index(editor->modes, i);
        JsonObject *source = external_source_profile_v24(catalog, g_ptr_array_index(editor->ids, i));
        paired = paired && g_strcmp0(mode, "wg") == 0 && linux_ordered_paired_off_v1(external_source_profile_v24(catalog, g_ptr_array_index(editor->ids, i)));
        if (!strcmp(mode, "shadowsocks") && i > 0) { stream = TRUE; mixed = mixed && linux_ordered_literal_import_off_v1(source); }
        else mixed = mixed && !stream && linux_ordered_prefix_v1(mode) && linux_ordered_paired_off_v1(source);
    }
    return paired || mixed;
}

static void linux_ordered_selected_v1(GtkListBox *box, GtkListBoxRow *row, gpointer data) {
    (void)box; (void)row;
    LinuxOrderedEditorV1 *editor = data;
    int index = linux_ordered_index_v1(editor); gboolean valid = linux_ordered_editable_v1(editor);
    gboolean prefix = index >= 0 && (guint)index < editor->ids->len;
    editor->syncing = TRUE;
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(editor->transport), prefix ? g_ptr_array_index(editor->modes, index) : linux_ordered_editor_final_mode_v1(editor));
    editor->syncing = FALSE;
    gtk_widget_set_sensitive(editor->transport, (!editor->external_exit || index == 0) && valid && index >= 0 && (guint)index <= editor->ids->len);
    gtk_widget_set_sensitive(editor->remove, valid && prefix && (!editor->external_exit || index > 0));
    gtk_widget_set_sensitive(editor->up, valid && prefix && index > (editor->external_exit ? 1 : 0));
    gtk_widget_set_sensitive(editor->down, valid && prefix && (!editor->external_exit || index > 0) && (guint)(index + 1) < editor->ids->len);
    gtk_widget_set_sensitive(editor->add, valid && linux_ordered_editor_can_extend_v1(editor));
    gtk_widget_set_sensitive(gtk_dialog_get_widget_for_response(GTK_DIALOG(editor->dialog), GTK_RESPONSE_APPLY), valid && !editor->append_only && editor->ids->len > 0 && editor->ids->len < ROUTERVPN_PHYSICAL_TRAVERSAL_DEPTH);
}

static void linux_ordered_candidate_changed_v1(GtkComboBox *combo, gpointer data) {
    (void)combo;
    LinuxOrderedEditorV1 *editor = data;
    gtk_widget_set_sensitive(editor->add, linux_ordered_editable_v1(editor) && linux_ordered_editor_can_extend_v1(editor));
}

static void linux_ordered_render_v1(LinuxOrderedEditorV1 *editor, int selected) {
    linux_ordered_cancel_next_v1(editor);
    GList *children = gtk_container_get_children(GTK_CONTAINER(editor->list));
    for (GList *it = children; it != NULL; it = it->next) gtk_widget_destroy(GTK_WIDGET(it->data));
    g_list_free(children);
    for (guint i = 0; i < editor->ids->len+(editor->append_only?0u:1u); i++) {
        gboolean final = !editor->append_only && i == editor->ids->len;
        const char *id = final ? linux_ordered_editor_exit_v1(editor) : g_ptr_array_index(editor->ids, i);
        const char *mode = final ? linux_ordered_editor_final_mode_v1(editor) : g_ptr_array_index(editor->modes, i);
        char *text = g_strdup_printf("%u. %s — %s%s", i + 1, linux_ordered_name_v1(editor, id), linux_ordered_mode_name_v1(mode), final ? " • selected final exit" : "");
        GtkWidget *label = gtk_label_new(text); gtk_label_set_xalign(GTK_LABEL(label), 0); gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
        gtk_container_add(GTK_CONTAINER(editor->list), label); g_free(text);
    }
    gtk_widget_show_all(editor->list);
    gtk_list_box_select_row(GTK_LIST_BOX(editor->list), gtk_list_box_get_row_at_index(GTK_LIST_BOX(editor->list), selected));
    gtk_widget_set_visible(editor->append_mode,editor->append_only);
    g_autofree char *original_next=g_strdup(gtk_combo_box_get_active_id(GTK_COMBO_BOX(editor->append_mode)));
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(editor->append_mode));
    const char *next_modes[]={"wg","awg2-fast","awg2-strong","shadowsocks","hysteria2"};
    for(guint i=0;i<G_N_ELEMENTS(next_modes);i++)gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(editor->append_mode),next_modes[i],linux_ordered_mode_name_v1(next_modes[i]));
    if(!linux_ordered_editor_proxy_entry_v1(editor))gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(editor->append_mode),"external-shadowsocks","Imported Shadowsocks");
    const char *remote_modes[]={"wg","awg2-fast","awg2-strong","shadowsocks","hysteria2"};
    for(guint i=0;i<G_N_ELEMENTS(remote_modes);i++) {
        const char *mode=remote_modes[i];
        g_autofree char *server=g_strconcat("server-",mode,NULL), *compare=g_strconcat("auto-",mode,NULL);
        if(linux_ordered_execution_append_v1(editor,mode) || !g_strcmp0(original_next,server) || !g_strcmp0(original_next,compare)) {
            g_autofree char *server_title=g_strconcat(linux_ordered_mode_name_v1(mode)," · Server",NULL);
            g_autofree char *compare_title=g_strconcat(linux_ordered_mode_name_v1(mode)," · Compare",NULL);
            gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(editor->append_mode),server,server_title);
            gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(editor->append_mode),compare,compare_title);
        }
    }
    if(!original_next || !gtk_combo_box_set_active_id(GTK_COMBO_BOX(editor->append_mode),original_next))gtk_combo_box_set_active(GTK_COMBO_BOX(editor->append_mode),-1);
    gtk_widget_set_visible(editor->complete_prefix,editor->append_only);
    gtk_widget_set_sensitive(editor->complete_prefix,linux_ordered_can_complete_v1(editor));
    gtk_button_set_label(GTK_BUTTON(editor->complete_prefix),editor->modes->len &&
        !g_strcmp0(g_ptr_array_index(editor->modes,editor->modes->len-1),"hysteria2") ?
        "Use last Hysteria2 node as final" : "Use last Shadowsocks node as final");
    gtk_widget_set_sensitive(editor->execution,!editor->append_only);
    gtk_button_set_label(GTK_BUTTON(editor->prefix_only),editor->append_only?"Use selected node as final":"Build prefix only");
    linux_ordered_selected_v1(NULL, NULL, editor);
}

static void linux_ordered_choose_external_exit_v1(GtkButton *button, gpointer data) {
    (void)button;
    LinuxOrderedEditorV1 *editor = data;
    JsonObject *catalog = json_node_get_object(editor->catalog);
    const char *id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(editor->candidate));
    const char *execution = gtk_combo_box_get_active_id(GTK_COMBO_BOX(editor->execution));
    if (editor->append_only || !linux_ordered_editable_v1(editor) || !id || !linux_ordered_external_final_profile_v1(external_source_profile_v24(catalog, id)) ||
        !linux_ordered_paired_layer_v1(external_source_profile_v24(catalog, editor->control), TRUE) ||
        (g_strcmp0(execution, "local") && g_strcmp0(execution, "server") && g_strcmp0(execution, "auto"))) {
        gtk_label_set_text(GTK_LABEL(editor->status), "Choose a linked literal Shadowsocks exit with the original paired WireGuard or AmneziaWG entry.");
        return;
    }
    for (guint i = editor->external_exit ? 1u : 0u; i < editor->ids->len; i++) {
        const char *node = g_ptr_array_index(editor->ids, i);
        if (!strcmp(node, id) || !linux_ordered_literal_import_off_v1(external_source_profile_v24(catalog, node))) {
            gtk_label_set_text(GTK_LABEL(editor->status), "Choose a different exit and keep only literal Shadowsocks imports after the paired entry.");
            return;
        }
    }
    if (!editor->external_exit) {
        if (editor->ids->len + 2 > ROUTERVPN_PHYSICAL_TRAVERSAL_DEPTH) return;
        g_ptr_array_insert(editor->ids, 0, g_strdup(editor->control));
        g_ptr_array_insert(editor->modes, 0, g_strdup("wg"));
    }
    g_free(editor->external_exit); editor->external_exit = g_strdup(id);
    g_free(editor->final_mode); editor->final_mode = g_strdup("shadowsocks");
    linux_ordered_render_v1(editor, (int)editor->ids->len);
}

static void linux_ordered_add_v1(GtkButton *button, gpointer data) {
    (void)button; LinuxOrderedEditorV1 *editor = data;
    const char *id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(editor->candidate));
    if (!linux_ordered_editable_v1(editor) || id == NULL || !linux_ordered_editor_can_extend_v1(editor) || (!editor->append_only && strcmp(id, editor->control) == 0)) return;
    JsonObject *profile = external_source_profile_v24(json_node_get_object(editor->catalog), id);
    if ((!linux_ordered_router_v1(profile) && !linux_ordered_imported_v1(profile)) || !external_source_token_v24(linux_ordered_string_v1(profile, "profile_token"))) return;
    if(editor->append_only){
        const char *mode=linux_ordered_router_v1(profile)?"wg":"shadowsocks";
        if(!linux_ordered_append_family_member_v1(profile,mode,editor->ids->len,linux_ordered_editor_proxy_entry_v1(editor)))return;
        for(guint i=0;i<editor->ids->len;i++)if(!strcmp(id,g_ptr_array_index(editor->ids,i)))return;
        g_ptr_array_add(editor->ids,g_strdup(id));g_ptr_array_add(editor->modes,g_strdup(mode));
        linux_ordered_render_v1(editor,(int)editor->ids->len-1);linux_ordered_queue_append_v1(editor);return;
    }
    if (linux_ordered_imported_v1(profile) && strcmp(linux_ordered_editor_final_mode_v1(editor), "shadowsocks") != 0) {
        gtk_label_set_text(GTK_LABEL(editor->status), "Choose a Shadowsocks 2022 exit before adding an imported middle."); return;
    }
    for (guint i = 0; i < editor->ids->len; i++) if (strcmp(g_ptr_array_index(editor->ids, i), id) == 0) return;
    const char *mode = linux_ordered_imported_v1(profile) ? linux_ordered_imported_mode_v1(profile) : "wg";
    if (editor->ids->len >= 7 && !strcmp(mode, "wg") && linux_ordered_editor_stream_v1(editor, editor->ids->len, id))
        mode = "shadowsocks";
    g_ptr_array_add(editor->ids, g_strdup(id)); g_ptr_array_add(editor->modes, g_strdup(mode));
    linux_ordered_render_v1(editor, (int)editor->ids->len - 1);
}

static void linux_ordered_remove_v1(GtkButton *button, gpointer data) {
    (void)button; LinuxOrderedEditorV1 *editor = data; int index = linux_ordered_index_v1(editor);
    if (!linux_ordered_editable_v1(editor) || index < 0 || (guint)index >= editor->ids->len) return;
    if (editor->external_exit && index == 0) return;
    if (editor->append_only) {
        JsonObject *catalog=json_node_get_object(editor->catalog);
        gboolean proxy_entry=editor->ids->len > 1 && linux_ordered_proxy_mode_v1(g_ptr_array_index(editor->modes,index == 0 ? 1 : 0));
        for(guint i=0,j=0;i<editor->ids->len;i++)if(i!=(guint)index) {
            if(!linux_ordered_append_family_member_v1(external_source_profile_v24(catalog,g_ptr_array_index(editor->ids,i)),g_ptr_array_index(editor->modes,i),j++,proxy_entry))return;
        }
    }
    g_ptr_array_remove_index(editor->ids, index); g_ptr_array_remove_index(editor->modes, index);
    linux_ordered_render_v1(editor, MIN(index, (int)editor->ids->len));
}

static void linux_ordered_move_v1(GtkButton *button, gpointer data) {
    LinuxOrderedEditorV1 *editor = data; int index = linux_ordered_index_v1(editor);
    int offset = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(button), "ordered-offset")), target = index + offset;
    if (!linux_ordered_editable_v1(editor) || (offset != -1 && offset != 1) || index < 0 || target < 0 || (guint)index >= editor->ids->len || (guint)target >= editor->ids->len) return;
    if (editor->external_exit && (index == 0 || target == 0)) return;
    if (editor->append_only) {
        JsonObject *catalog=json_node_get_object(editor->catalog);
        guint first=index == 0 ? (guint)target : target == 0 ? (guint)index : 0;
        gboolean proxy_entry=linux_ordered_proxy_mode_v1(g_ptr_array_index(editor->modes,first));
        for(guint i=0;i<editor->ids->len;i++) {
            guint at=i == (guint)index ? (guint)target : i == (guint)target ? (guint)index : i;
            if(!linux_ordered_append_family_member_v1(external_source_profile_v24(catalog,g_ptr_array_index(editor->ids,at)),g_ptr_array_index(editor->modes,at),i,proxy_entry))return;
        }
    }
    gpointer id = editor->ids->pdata[index], mode = editor->modes->pdata[index];
    editor->ids->pdata[index] = editor->ids->pdata[target]; editor->modes->pdata[index] = editor->modes->pdata[target];
    editor->ids->pdata[target] = id; editor->modes->pdata[target] = mode;
    linux_ordered_render_v1(editor, target);
}

static void linux_ordered_mode_v1(GtkComboBox *combo, gpointer data) {
    LinuxOrderedEditorV1 *editor = data; int index = linux_ordered_index_v1(editor);
    const char *mode = gtk_combo_box_get_active_id(combo);
    if (editor->syncing || !linux_ordered_editable_v1(editor)) return;
    if(editor->append_only){
        if(index<0 || (guint)index>=editor->ids->len){linux_ordered_selected_v1(NULL,NULL,editor);return;}
        gboolean proxy_entry=index == 0 ? linux_ordered_proxy_mode_v1(mode) : linux_ordered_editor_proxy_entry_v1(editor);
        for(guint i=0;i<editor->ids->len;i++) {
            const char *proposed=(guint)index == i ? mode : g_ptr_array_index(editor->modes,i);
            if(!linux_ordered_append_family_member_v1(external_source_profile_v24(json_node_get_object(editor->catalog),g_ptr_array_index(editor->ids,i)),proposed,i,proxy_entry)){
                linux_ordered_selected_v1(NULL,NULL,editor);return;
            }
        }
        char *copy=g_strdup(mode);g_free(editor->modes->pdata[index]);editor->modes->pdata[index]=copy;
        linux_ordered_render_v1(editor,index);return;
    }
    if (editor->external_exit && (index != 0 || !linux_ordered_prefix_v1(mode))) { linux_ordered_selected_v1(NULL, NULL, editor); return; }
    if (index >= 0 && (guint)index == editor->ids->len) {
        if (!linux_ordered_editor_final_allowed_v1(editor, mode)) {
            linux_ordered_selected_v1(NULL, NULL, editor);
            gtk_label_set_text(GTK_LABEL(editor->status), "WireGuard and AWG2 exits require two to eight paired Local packet nodes with Start Layer Off throughout. Hysteria2 retains its own Start Layer after paired packet prefixes."); return;
        }
        char *copy = g_strdup(mode); g_free(editor->final_mode); editor->final_mode = copy;
        linux_ordered_render_v1(editor, index); return;
    }
    gboolean imported = index >= 0 && (guint)index < editor->ids->len && linux_ordered_imported_v1(external_source_profile_v24(json_node_get_object(editor->catalog), g_ptr_array_index(editor->ids, index)));
    gboolean paired_hysteria = index >= 0 && (guint)index < editor->ids->len &&
        linux_ordered_editor_hysteria_v1(editor, index, g_ptr_array_index(editor->ids, index), mode, linux_ordered_editor_final_mode_v1(editor));
    gboolean selected_stream = !imported && !g_strcmp0(mode, "shadowsocks") && index >= 2 &&
        (guint)index < editor->ids->len && linux_ordered_editor_stream_v1(editor, (guint)index, g_ptr_array_index(editor->ids, index));
    if (index < 0 || (guint)index >= editor->ids->len || (imported ? g_strcmp0(mode, linux_ordered_imported_mode_v1(external_source_profile_v24(json_node_get_object(editor->catalog), g_ptr_array_index(editor->ids, index)))) != 0 : !linux_ordered_prefix_v1(mode) && !selected_stream && !paired_hysteria)) {
        linux_ordered_selected_v1(NULL, NULL, editor);
        gtk_label_set_text(GTK_LABEL(editor->status), "Paired prefixes use WireGuard, AWG2 Fast or AWG2 Strong. An imported middle keeps its saved transport. A WireGuard or AWG2 final requires Local execution and Start Layer Off throughout.");
        return;
    }
    char *copy = g_strdup(mode); g_free(editor->modes->pdata[index]); editor->modes->pdata[index] = copy;
    linux_ordered_render_v1(editor, index);
}

static LinuxOrderedSelectionV1 *linux_ordered_editor_selection_v1(LinuxOrderedEditorV1 *editor) {
    if(editor->append_only)return NULL;
    JsonArray *nodes = json_array_new(); JsonObject *tokens = json_object_new();
    for (guint i = 0; i <= editor->ids->len; i++) {
        const char *id = i == editor->ids->len ? linux_ordered_editor_exit_v1(editor) : g_ptr_array_index(editor->ids, i);
        const char *mode = i == editor->ids->len ? linux_ordered_editor_final_mode_v1(editor) : g_ptr_array_index(editor->modes, i);
        JsonObject *row = json_object_new(); json_object_set_string_member(row, "id", id); json_object_set_string_member(row, "mode", mode);
        json_array_add_object_element(nodes, row);
        json_object_set_string_member(tokens, id, linux_ordered_string_v1(external_source_profile_v24(json_node_get_object(editor->catalog), id), "profile_token"));
    }
    LinuxOrderedSelectionV1 *selection = linux_ordered_selection_v1(editor->control, nodes, tokens);
    const char *execution = editor->execution != NULL ? gtk_combo_box_get_active_id(GTK_COMBO_BOX(editor->execution)) : "local";
    if (!linux_ordered_execution_v1(selection, execution)) { linux_ordered_selection_free_v1(selection); selection = NULL; }
    json_array_unref(nodes); json_object_unref(tokens); return selection;
}


static gboolean linux_ordered_append_current_v1(LinuxOrderedEditorV1 *editor, JsonArray *nodes, JsonObject *tokens, JsonObject *current) {
    if(!nodes || !tokens || !current || strcmp(linux_ordered_string_v1(current,"selected_id"),editor->control) ||
       json_array_get_length(nodes)<1 || json_array_get_length(nodes)>96 || json_object_get_size(tokens)!=json_array_get_length(nodes))return FALSE;
    JsonObject *original=json_node_get_object(editor->catalog);
    const char *device=linux_ordered_string_v1(external_source_profile_v24(original,editor->control),"profile_token");
    JsonObject *current_device=external_source_profile_v24(current,editor->control);
    if(!external_source_token_v24(device) || strcmp(device,linux_ordered_string_v1(current_device,"profile_token")) ||
       !linux_ordered_paired_layer_v1(current_device,TRUE))return FALSE;
    JsonNode *first=json_array_get_element(nodes,0);
    gboolean proxy_entry=linux_ordered_proxy_mode_v1(linux_ordered_string_v1(first && JSON_NODE_HOLDS_OBJECT(first)?json_node_get_object(first):NULL,"mode"));
    g_autoptr(GHashTable) ids=g_hash_table_new(g_str_hash,g_str_equal);
    for(guint i=0;i<json_array_get_length(nodes);i++){
        JsonNode *raw=json_array_get_element(nodes,i);JsonObject *row=raw && JSON_NODE_HOLDS_OBJECT(raw)?json_node_get_object(raw):NULL;
        const char *id=linux_ordered_string_v1(row,"id"), *mode=linux_ordered_string_v1(row,"mode");
        JsonObject *old=external_source_profile_v24(original,id), *now=external_source_profile_v24(current,id);
        const char *token=linux_ordered_string_v1(old,"profile_token");
        if(!row || json_object_get_size(row)!=2 || !external_source_id_v24(id) || !g_hash_table_add(ids,(gpointer)id) ||
           !linux_ordered_append_family_member_v1(old,mode,i,proxy_entry) || !linux_ordered_append_family_member_v1(now,mode,i,proxy_entry) ||
           !external_source_token_v24(token) || strcmp(token,linux_ordered_string_v1(tokens,id)) ||
           strcmp(token,linux_ordered_string_v1(now,"profile_token")))return FALSE;
    }
    return TRUE;
}
static char *linux_ordered_append_body_v1(LinuxOrderedEditorV1 *editor) {
    if(!editor->append_only || editor->external_exit || editor->ids->len<1 || editor->ids->len>95 ||
       g_strcmp0(gtk_combo_box_get_active_id(GTK_COMBO_BOX(editor->execution)),"local"))return NULL;
    const char *choice=gtk_combo_box_get_active_id(GTK_COMBO_BOX(editor->append_mode));
    gboolean external=!g_strcmp0(choice,"external-shadowsocks");
    const char *requested=linux_ordered_append_requested_v1(choice);
    gboolean execution_append=strcmp(requested,"local")!=0;
    const char *next_mode=linux_ordered_append_mode_v1(choice);
    if((external && linux_ordered_editor_proxy_entry_v1(editor)) || (execution_append && !linux_ordered_execution_append_v1(editor,next_mode)))return NULL;
    if(!linux_ordered_prefix_v1(next_mode) && g_strcmp0(next_mode,"shadowsocks") && g_strcmp0(next_mode,"hysteria2"))return NULL;
    JsonObject *catalog=json_node_get_object(editor->catalog);
    g_autoptr(JsonArray) nodes=json_array_new();g_autoptr(JsonObject) tokens=json_object_new();
    for(guint i=0;i<editor->ids->len;i++){
        const char *id=g_ptr_array_index(editor->ids,i), *mode=g_ptr_array_index(editor->modes,i);
        JsonObject *row=json_object_new();json_object_set_string_member(row,"id",id);json_object_set_string_member(row,"mode",mode);
        json_array_add_object_element(nodes,row);json_object_set_string_member(tokens,id,linux_ordered_string_v1(external_source_profile_v24(catalog,id),"profile_token"));
    }
    if(!linux_ordered_append_current_v1(editor,nodes,tokens,catalog))return NULL;
    json_object_set_string_member(tokens,editor->control,linux_ordered_string_v1(external_source_profile_v24(catalog,editor->control),"profile_token"));
    g_autoptr(JsonObject) body=json_object_new();
    json_object_set_int_member(body,"schema",1);json_object_set_string_member(body,"purpose",execution_append?"draft-prefix-append-execution":"draft-prefix-append");json_object_set_string_member(body,"execution","local");
    if(execution_append)json_object_set_string_member(body,"requested_execution",requested);
    json_object_set_string_member(body,"draft_revision",editor->append_revision);json_object_set_int_member(body,"append_position",editor->ids->len);
    json_object_set_string_member(body,"next_mode",next_mode);
    if(external)json_object_set_string_member(body,"next_kind","external");
    json_object_set_array_member(body,"nodes",json_array_ref(nodes));json_object_set_string_member(body,"expected_selected_node_id",editor->control);
    json_object_set_object_member(body,"expected_profile_tokens",json_object_ref(tokens));return linux_ordered_json_v1(body);
}


static const char *linux_ordered_completion_purpose_v1(const char *mode) {
    if (!g_strcmp0(mode,"shadowsocks")) return "draft-last-ss-final";
    if (!g_strcmp0(mode,"hysteria2")) return "draft-last-hy2-final";
    return NULL;
}

static gboolean linux_ordered_can_complete_v1(LinuxOrderedEditorV1 *editor) {
    if (!editor->append_only || editor->external_exit || editor->ids->len < 2 || editor->ids->len > 96 ||
        editor->ids->len != editor->modes->len || g_strcmp0(gtk_combo_box_get_active_id(GTK_COMBO_BOX(editor->execution)),"local")) return FALSE;
    guint last=editor->ids->len-1;
    return linux_ordered_completion_purpose_v1(g_ptr_array_index(editor->modes,last)) != NULL &&
        linux_ordered_paired_off_v1(external_source_profile_v24(json_node_get_object(editor->catalog),g_ptr_array_index(editor->ids,last)));
}

static char *linux_ordered_completion_body_v1(LinuxOrderedEditorV1 *editor, JsonObject *current) {
    if (!linux_ordered_can_complete_v1(editor) || !linux_ordered_editable_v1(editor)) return NULL;
    JsonObject *catalog=json_node_get_object(editor->catalog);
    g_autoptr(JsonArray) nodes=json_array_new();g_autoptr(JsonObject) tokens=json_object_new();
    for (guint i=0;i<editor->ids->len;i++) {
        const char *id=g_ptr_array_index(editor->ids,i),*mode=g_ptr_array_index(editor->modes,i);
        JsonObject *row=json_object_new();json_object_set_string_member(row,"id",id);json_object_set_string_member(row,"mode",mode);
        json_array_add_object_element(nodes,row);json_object_set_string_member(tokens,id,linux_ordered_string_v1(external_source_profile_v24(catalog,id),"profile_token"));
    }
    if (!linux_ordered_append_current_v1(editor,nodes,tokens,current)) return NULL;
    const char *last=g_ptr_array_index(editor->ids,editor->ids->len-1);
    if (!linux_ordered_paired_off_v1(external_source_profile_v24(current,last))) return NULL;
    g_autoptr(JsonObject) body=json_object_new();
    const char *purpose=linux_ordered_completion_purpose_v1(g_ptr_array_index(editor->modes,editor->modes->len-1));
    json_object_set_int_member(body,"schema",1);json_object_set_string_member(body,"purpose",purpose);json_object_set_string_member(body,"execution","local");
    json_object_set_string_member(body,"draft_revision",editor->append_revision);json_object_set_string_member(body,"device_id",editor->control);
    json_object_set_string_member(body,"device_revision",linux_ordered_string_v1(external_source_profile_v24(catalog,editor->control),"profile_token"));
    json_object_set_string_member(body,"final_id",last);json_object_set_array_member(body,"nodes",json_array_ref(nodes));
    json_object_set_string_member(body,"expected_selected_node_id",editor->control);json_object_set_object_member(body,"expected_profile_tokens",json_object_ref(tokens));
    return linux_ordered_json_v1(body);
}

static gboolean linux_ordered_completion_current_v1(LinuxOrderedEditorV1 *editor, JsonObject *body) {
    if (!linux_ordered_editable_v1(editor) || !linux_ordered_can_complete_v1(editor) ||
        strcmp(linux_ordered_string_v1(body,"purpose"),linux_ordered_completion_purpose_v1(g_ptr_array_index(editor->modes,editor->modes->len-1))) ||
        strcmp(linux_ordered_string_v1(body,"draft_revision"),editor->append_revision) ||
        strcmp(linux_ordered_string_v1(body,"device_id"),editor->control)) return FALSE;
    JsonArray *nodes=linux_ordered_array_v1(body,"nodes");
    if (!nodes || json_array_get_length(nodes)!=editor->ids->len) return FALSE;
    for (guint i=0;i<editor->ids->len;i++) {
        JsonObject *row=json_array_get_object_element(nodes,i);
        if (!row || strcmp(linux_ordered_string_v1(row,"id"),g_ptr_array_index(editor->ids,i)) ||
            strcmp(linux_ordered_string_v1(row,"mode"),g_ptr_array_index(editor->modes,i))) return FALSE;
    }
    g_autoptr(JsonNode) current=linux_ordered_read_v1("/api/profiles");
    return current && linux_ordered_append_current_v1(editor,nodes,linux_ordered_object_v1(body,"expected_profile_tokens"),json_node_get_object(current)) &&
        !strcmp(linux_ordered_string_v1(body,"device_revision"),linux_ordered_string_v1(external_source_profile_v24(json_node_get_object(current),editor->control),"profile_token"));
}

static gboolean linux_ordered_completion_response_v1(JsonObject *body, JsonObject *value, gboolean saved) {
    const char *fields[]={"schema","purpose","compiled","draft_revision","device_id","device_revision","final_id","nodes",
        "source_sha256","device_source_sha256","device_mtu_revision","completion_sha256","active_path_changed","profile_id","profile_name"};
    guint count=saved?15:13;
    if (!body || !value || json_object_get_size(value)!=count) return FALSE;
    JsonArray *original=linux_ordered_array_v1(body,"nodes");
    if (!original || json_array_get_length(original)<2) return FALSE;
    JsonNode *last=json_array_get_element(original,json_array_get_length(original)-1);
    if (!last || !JSON_NODE_HOLDS_OBJECT(last)) return FALSE;
    const char *purpose=linux_ordered_completion_purpose_v1(linux_ordered_string_v1(json_node_get_object(last),"mode"));
    if (!purpose || strcmp(linux_ordered_string_v1(body,"purpose"),purpose)) return FALSE;
    for (guint i=0;i<count;i++) if (!json_object_has_member(value,fields[i])) return FALSE;
    JsonNode *schema=json_object_get_member(value,"schema"),*changed=json_object_get_member(value,"active_path_changed");
    if (!schema || !JSON_NODE_HOLDS_VALUE(schema) || json_node_get_value_type(schema)!=G_TYPE_INT64 || json_node_get_int(schema)!=1 ||
        strcmp(linux_ordered_string_v1(value,"purpose"),purpose) || !linux_ordered_flag_v1(value,"compiled") ||
        !changed || !JSON_NODE_HOLDS_VALUE(changed) || json_node_get_value_type(changed)!=G_TYPE_BOOLEAN || json_node_get_boolean(changed)) return FALSE;
    const char *identity[]={"draft_revision","device_id","device_revision","final_id"};
    for (guint i=0;i<G_N_ELEMENTS(identity);i++) if (!*linux_ordered_string_v1(body,identity[i]) ||
        strcmp(linux_ordered_string_v1(value,identity[i]),linux_ordered_string_v1(body,identity[i]))) return FALSE;
    const char *hashes[]={"source_sha256","device_source_sha256","device_mtu_revision","completion_sha256"};
    for (guint i=0;i<G_N_ELEMENTS(hashes);i++) if (!external_source_token_v24(linux_ordered_string_v1(value,hashes[i]))) return FALSE;
    JsonArray *nodes=linux_ordered_array_v1(value,"nodes");
    if (!nodes || json_array_get_length(original)!=json_array_get_length(nodes)) return FALSE;
    for (guint i=0;i<json_array_get_length(nodes);i++) {
        JsonNode *raw=json_array_get_element(nodes,i);JsonObject *row=raw && JSON_NODE_HOLDS_OBJECT(raw)?json_node_get_object(raw):NULL;
        JsonObject *old=json_array_get_object_element(original,i);
        if (!row || json_object_get_size(row)!=2 || !old || strcmp(linux_ordered_string_v1(row,"id"),linux_ordered_string_v1(old,"id")) ||
            strcmp(linux_ordered_string_v1(row,"mode"),linux_ordered_string_v1(old,"mode"))) return FALSE;
    }
    return !saved || (external_source_id_v24(linux_ordered_string_v1(value,"profile_id")) &&
        !strcmp(linux_ordered_string_v1(value,"profile_name"),linux_ordered_string_v1(body,"name")) &&
        !strcmp(linux_ordered_string_v1(value,"completion_sha256"),linux_ordered_string_v1(body,"expected_completion_sha256")));
}

static JsonNode *linux_ordered_completion_post_v1(const char *path, const char *body, char **error) {
    Buffer out={0};JsonNode *result=NULL;
    if (api_request(path,"POST",body,15000,&out,error) && out.data && strlen(out.data)<=(1u<<20)) result=parse_json(out.data);
    free(out.data);
    if (result && !JSON_NODE_HOLDS_OBJECT(result)) { json_node_free(result);result=NULL; }
    return result;
}

static void linux_ordered_complete_prefix_v1(GtkButton *button, gpointer data) {
    (void)button;LinuxOrderedEditorV1 *editor=data;
    if (!linux_ordered_editable_v1(editor) || !routervpn_require_mutation_idle(editor->owned->unified->app,"completing the original ordered prefix")) return;
    linux_ordered_cancel_next_v1(editor);
    g_autoptr(JsonNode) current=linux_ordered_read_v1("/api/profiles");
    g_autofree char *body=current?linux_ordered_completion_body_v1(editor,json_node_get_object(current)):NULL;
    g_autoptr(JsonNode) original=body?parse_json(body):NULL;
    if (!original) { gtk_label_set_text(GTK_LABEL(editor->status),"Keep the actual last paired Shadowsocks or Hysteria2 node and original Local prefix.");return; }
    g_autofree char *error=NULL;
    g_autoptr(JsonNode) preview=linux_ordered_completion_post_v1("/api/connection-profile/setup/complete-prefix",body,&error);
    if (!preview || !linux_ordered_completion_response_v1(json_node_get_object(original),json_node_get_object(preview),FALSE) ||
        !linux_ordered_completion_current_v1(editor,json_node_get_object(original))) {
        if (!editor->closed) {
            gtk_label_set_text(GTK_LABEL(editor->status),error?error:"The original complete path could not be compiled. Reopen its current sources.");
        }
        return;
    }
    const char *title=!strcmp(linux_ordered_string_v1(json_node_get_object(original),"purpose"),"draft-last-hy2-final") ?
        "Use last Hysteria2 node as final" : "Use last Shadowsocks node as final";
    GtkWidget *dialog=gtk_dialog_new_with_buttons(title,GTK_WINDOW(editor->dialog),GTK_DIALOG_MODAL|GTK_DIALOG_DESTROY_WITH_PARENT,
        "Back",GTK_RESPONSE_CANCEL,"Save profile",GTK_RESPONSE_ACCEPT,NULL);
    g_object_ref_sink(dialog);GtkWidget *box=gtk_dialog_get_content_area(GTK_DIALOG(dialog));gtk_container_set_border_width(GTK_CONTAINER(box),12);
    GtkWidget *note=gtk_label_new("The complete path compiled with every original node in order. Name this future profile, then Save explicitly. Load and Connect remain separate choices.");
    gtk_label_set_line_wrap(GTK_LABEL(note),TRUE);gtk_widget_set_size_request(note,360,-1);gtk_box_pack_start(GTK_BOX(box),note,FALSE,FALSE,6);
    GtkWidget *entry=gtk_entry_new();gtk_entry_set_placeholder_text(GTK_ENTRY(entry),"Profile name");gtk_box_pack_start(GTK_BOX(box),entry,FALSE,FALSE,6);
    gtk_widget_show_all(dialog);gint choice=gtk_dialog_run(GTK_DIALOG(dialog));
    g_autofree char *name=choice==GTK_RESPONSE_ACCEPT?g_strdup(gtk_entry_get_text(GTK_ENTRY(entry))):NULL;
    gtk_widget_destroy(dialog);g_object_unref(dialog);
    if (choice!=GTK_RESPONSE_ACCEPT || editor->closed) return;
    if (name) g_strstrip(name);
    if (!name || !*name || !linux_ordered_completion_current_v1(editor,json_node_get_object(original)) ||
        !routervpn_require_mutation_idle(editor->owned->unified->app,"saving the complete future profile")) {
        gtk_label_set_text(GTK_LABEL(editor->status),"The original completion or profile name changed. Review the complete path again.");return;
    }
    g_autoptr(JsonNode) save=parse_json(body);JsonObject *save_body=json_node_get_object(save);
    json_object_set_string_member(save_body,"name",name);json_object_set_string_member(save_body,"expected_completion_sha256",linux_ordered_string_v1(json_node_get_object(preview),"completion_sha256"));
    g_autofree char *save_raw=linux_ordered_json_v1(save_body);g_clear_pointer(&error,g_free);
    g_autoptr(JsonNode) result=linux_ordered_completion_post_v1("/api/connection-profile/setup/save-completed-prefix",save_raw,&error);
    gboolean valid=result && linux_ordered_completion_response_v1(save_body,json_node_get_object(result),TRUE);
    const char *hashes[]={"source_sha256","device_source_sha256","device_mtu_revision","completion_sha256"};
    for (guint i=0;valid && i<G_N_ELEMENTS(hashes);i++) valid=!strcmp(linux_ordered_string_v1(json_node_get_object(result),hashes[i]),linux_ordered_string_v1(json_node_get_object(preview),hashes[i]));
    valid=valid && linux_ordered_completion_current_v1(editor,json_node_get_object(original));
    if (editor->closed) return;
    if (!valid) { gtk_label_set_text(GTK_LABEL(editor->status),error?error:"The Save result no longer matches the original preview. Refresh saved profiles before reviewing again.");return; }
    g_autofree char *message=g_strdup_printf("Saved %s. Load this future profile separately, then Connect to verify its complete path.",name);
    gtk_label_set_text(GTK_LABEL(editor->status),message);
}

static gboolean linux_ordered_adopt_append_v1(LinuxOrderedEditorV1 *editor, const char *captured, int position, JsonObject *response) {
    g_autofree char *original=linux_ordered_append_body_v1(editor);
    const char *choice=gtk_combo_box_get_active_id(GTK_COMBO_BOX(editor->append_mode));
    const char *requested=linux_ordered_append_requested_v1(choice);
    gboolean execution_append=strcmp(requested,"local")!=0;
    const char *purpose=execution_append?"draft-prefix-append-execution":"draft-prefix-append";
    if(!original || strcmp(original,captured) || position!=(int)editor->ids->len-1 ||
       strcmp(linux_ordered_string_v1(response,"scope"),purpose) ||
       strcmp(linux_ordered_string_v1(response,"purpose"),purpose) ||
       strcmp(linux_ordered_string_v1(response,"origin"),"editor-draft") ||
       strcmp(linux_ordered_string_v1(response,"requested_execution"),requested) ||
       (execution_append && !external_source_token_v24(linux_ordered_string_v1(response,"execution_source_sha256"))) ||
       strcmp(linux_ordered_string_v1(response,"draft_action"),"append-measured-hop") ||
       strcmp(linux_ordered_string_v1(response,"draft_revision"),editor->append_revision) ||
       strcmp(linux_ordered_string_v1(response,"expected_selected_node_id"),editor->control) ||
       strcmp(linux_ordered_string_v1(response,"device_revision"),linux_ordered_string_v1(external_source_profile_v24(json_node_get_object(editor->catalog),editor->control),"profile_token")) ||
       !linux_ordered_flag_v1(response,"chosen") || !linux_ordered_flag_v1(response,"native_down"))return FALSE;
    gboolean external=!g_strcmp0(choice,"external-shadowsocks");
    const char *mode=linux_ordered_append_mode_v1(choice), *id=linux_ordered_string_v1(response,"candidate_id");
    if(strcmp(linux_ordered_string_v1(response,"measurement"),external?"routed-public-candidate-response":"routed-candidate-response") ||
       (external?strcmp(linux_ordered_string_v1(response,"candidate_kind"),"external"):json_object_has_member(response,"candidate_kind")))return FALSE;
    JsonArray *nodes=linux_ordered_array_v1(response,"proposed_path");JsonObject *tokens=linux_ordered_object_v1(response,"expected_profile_tokens");
    JsonNode *append=json_object_has_member(response,"append_position")?json_object_get_member(response,"append_position"):NULL;
    JsonNode *prefix=json_object_has_member(response,"prefix_position")?json_object_get_member(response,"prefix_position"):NULL;
    if(!nodes || json_array_get_length(nodes)!=editor->ids->len+1 || strcmp(linux_ordered_string_v1(response,"candidate_mode"),mode) ||
       !append || !prefix || json_node_get_value_type(append)!=G_TYPE_INT64 || json_node_get_int(append)!=(gint64)editor->ids->len ||
       json_node_get_value_type(prefix)!=G_TYPE_INT64 || json_node_get_int(prefix)!=position)return FALSE;
    for(guint i=0;i<editor->ids->len;i++){
        JsonObject *row=json_array_get_object_element(nodes,i);
        if(!strcmp(id,g_ptr_array_index(editor->ids,i)) || strcmp(linux_ordered_string_v1(row,"id"),g_ptr_array_index(editor->ids,i)) ||
           strcmp(linux_ordered_string_v1(row,"mode"),g_ptr_array_index(editor->modes,i)))return FALSE;
    }
    JsonObject *last=json_array_get_object_element(nodes,editor->ids->len);
    g_autoptr(JsonNode) current=linux_ordered_read_v1("/api/profiles");
    if(!last || strcmp(linux_ordered_string_v1(last,"id"),id) || strcmp(linux_ordered_string_v1(last,"mode"),mode) || !current ||
       !linux_ordered_append_current_v1(editor,nodes,tokens,json_node_get_object(current)) ||
       !(external?linux_ordered_append_import_off_v1(external_source_profile_v24(json_node_get_object(current),id)):
           linux_ordered_paired_off_v1(external_source_profile_v24(json_node_get_object(current),id))) ||
       (execution_append && !linux_ordered_paired_proxy_member_v1(external_source_profile_v24(json_node_get_object(current),id),mode)) || !linux_ordered_editable_v1(editor))return FALSE;
    g_ptr_array_add(editor->ids,g_strdup(id));g_ptr_array_add(editor->modes,g_strdup(mode));
    g_autofree char *uuid=g_uuid_string_random();guint n=0;for(char *c=uuid;*c;c++)if(*c!='-')editor->append_revision[n++]=*c;editor->append_revision[n]=0;
    linux_ordered_render_v1(editor,(int)editor->ids->len-1);
    gtk_label_set_text(GTK_LABEL(editor->status),
        "Appended the measured node after the temporary path stopped. Select a real final before using this path.");
    linux_ordered_queue_append_v1(editor);
    return TRUE;
}
static void linux_ordered_prefix_only_v1(GtkButton *button, gpointer data) {
    (void)button;LinuxOrderedEditorV1 *editor=data;
    if(!linux_ordered_editable_v1(editor))return;
    if(editor->append_only){
        editor->append_only=FALSE;LinuxOrderedSelectionV1 *selection=linux_ordered_editor_selection_v1(editor);
        g_autoptr(JsonNode) current=selection?linux_ordered_read_v1("/api/profiles"):NULL;
        gboolean valid=current && linux_ordered_current_v1(selection,json_node_get_object(current));
        linux_ordered_selection_free_v1(selection);
        if(!valid){editor->append_only=TRUE;gtk_label_set_text(GTK_LABEL(editor->status),"The selected node must be a different real final supported by this complete route.");return;}
    }else{
        if(editor->external_exit || g_strcmp0(gtk_combo_box_get_active_id(GTK_COMBO_BOX(editor->execution)),"local") || editor->ids->len>95)return;
        JsonObject *catalog=json_node_get_object(editor->catalog);
        for(guint i=0;i<editor->ids->len;i++)if(!linux_ordered_append_family_member_v1(
            external_source_profile_v24(catalog,g_ptr_array_index(editor->ids,i)),g_ptr_array_index(editor->modes,i),i,linux_ordered_editor_proxy_entry_v1(editor))){
            gtk_label_set_text(GTK_LABEL(editor->status),"Start with a paired transport. A Shadowsocks or Hysteria2 entry requires every prefix member paired with Start Layer Off.");return;
        }
        editor->append_only=TRUE;
        g_autofree char *uuid=g_uuid_string_random();guint n=0;for(char *c=uuid;*c;c++)if(*c!='-')editor->append_revision[n++]=*c;editor->append_revision[n]=0;
    }
    linux_ordered_render_v1(editor,MAX(0,(int)editor->ids->len-1));
    gtk_label_set_text(GTK_LABEL(editor->status),editor->append_only?"Only actual prefix nodes are captured. Select the next transport, then measure it.":"The selected node is now the real final. Review the complete path before using it.");
}

static void (*linux_ordered_present_measurement_v1)(App *, GtkWindow *, const char *, int);

/* Run after the choosing dialog has consumed native DOWN and closed. Re-read
 * the catalog for this exact insertion, including the retained suffix. */
static gboolean linux_ordered_continue_measured_v1(gpointer data) {
    LinuxOrderedEditorV1 *editor = data;
    editor->next_measurement = 0;
    g_autofree char *expected = g_steal_pointer(&editor->next_draft);
    int position = editor->next_position;
    App *app = editor->owned->unified->app;
    if (!expected || !app->window || !linux_ordered_present_measurement_v1 || !linux_ordered_editable_v1(editor) ||
        !gtk_widget_get_visible(editor->dialog) || linux_ordered_index_v1(editor) != position ||
        g_object_get_data(G_OBJECT(app->window), "linux-ordered-candidates")) return G_SOURCE_REMOVE;
    if (editor->append_only) {
        g_autofree char *actual=linux_ordered_append_body_v1(editor);
        if (!actual || strcmp(expected,actual) || position!=(int)editor->ids->len-1 ||
            !routervpn_require_mutation_idle(app,"measuring the next node through the original prefix")) return G_SOURCE_REMOVE;
        linux_ordered_measure_next_v1(NULL,editor);
        return G_SOURCE_REMOVE;
    }
    LinuxOrderedSelectionV1 *selection = linux_ordered_editor_selection_v1(editor);
    if (!selection) return G_SOURCE_REMOVE;
    g_autofree char *actual = linux_ordered_connect_body_v1(selection);
    g_autoptr(JsonNode) current = !strcmp(expected, actual) ? linux_ordered_read_v1("/api/profiles") : NULL;
    if (current && linux_ordered_measurement_prefix_v1(selection, json_node_get_object(current), position) &&
        linux_ordered_editable_v1(editor) && linux_ordered_index_v1(editor) == position)
        linux_ordered_present_measurement_v1(app, GTK_WINDOW(editor->dialog), expected, position);
    linux_ordered_selection_free_v1(selection);
    return G_SOURCE_REMOVE;
}

static gboolean linux_ordered_adopt_measured_v1(GtkWindow *parent, const char *captured, int position, JsonObject *response) {
    LinuxOrderedEditorV1 *editor = g_object_get_data(G_OBJECT(parent), "ordered-live-editor");
    if (!editor || !linux_ordered_editable_v1(editor) || position != linux_ordered_index_v1(editor) ||
        position < 0 || (guint)position >= editor->ids->len) return FALSE;
    if(editor->append_only)return linux_ordered_adopt_append_v1(editor,captured,position,response);
    LinuxOrderedSelectionV1 *before = linux_ordered_editor_selection_v1(editor);
    if (!before) return FALSE;
    char *original = linux_ordered_connect_body_v1(before);
    gboolean valid = !strcmp(captured, original) && !strcmp(editor->control, linux_ordered_string_v1(response, "expected_selected_node_id")) &&
        (!strcmp(before->execution, "local") || !strcmp(before->execution, linux_ordered_string_v1(response, "requested_execution")));
    g_free(original);
    JsonArray *rows = linux_ordered_array_v1(response, "proposed_path");
    JsonObject *tokens = linux_ordered_object_v1(response, "expected_profile_tokens");
    const guint added = (guint)position + 1;
    gboolean replacement=json_object_has_member(response,"candidate_mode");
    if (replacement) {
        const char *mode=linux_ordered_prepared_candidate_mode_v1(before,json_node_get_object(editor->catalog),position);
        valid=valid && linux_ordered_prefix_v1(mode) && added+1<json_array_get_length(before->nodes) &&
            !strcmp(linux_ordered_string_v1(response,"candidate_mode"),mode) &&
            !strcmp(linux_ordered_string_v1(response,"draft_action"),"replace-measured-hop");
    }
    LinuxOrderedSelectionV1 *next = valid ? linux_ordered_selection_v1(editor->control, rows, tokens) : NULL;
    valid = next && json_array_get_length(next->nodes) == json_array_get_length(before->nodes) + (replacement?0:1) &&
        linux_ordered_execution_v1(next, before->execution) && linux_ordered_current_v1(next, json_node_get_object(editor->catalog));
    for (guint i = 0; valid && i < json_array_get_length(before->nodes); i++) {
        JsonNode *original_row = json_array_get_element(before->nodes, i);
        JsonObject *original_object=json_node_get_object(original_row);
        if (replacement) {
            valid=strcmp(linux_ordered_string_v1(original_object,"id"),linux_ordered_string_v1(response,"candidate_id"))!=0;
            if (i==added) {
                valid=valid && !strcmp(linux_ordered_string_v1(original_object,"mode"),
                    linux_ordered_string_v1(json_array_get_object_element(next->nodes,i),"mode"));
                continue;
            }
        }
        valid = valid && json_node_equal(original_row, json_array_get_element(next->nodes, replacement || i < added ? i : i + 1));
    }
    JsonObject *row = valid ? json_array_get_object_element(next->nodes, added) : NULL;
    valid = valid && !strcmp(linux_ordered_string_v1(row, "id"), linux_ordered_string_v1(response, "candidate_id"));
    JsonNode *current = valid ? linux_ordered_read_v1("/api/profiles") : NULL;
    valid = current && linux_ordered_current_v1(next, json_node_get_object(current)) && linux_ordered_editable_v1(editor);
    if (valid) {
        if (replacement) {
            g_free(g_ptr_array_index(editor->ids,added));
            g_ptr_array_index(editor->ids,added)=g_strdup(linux_ordered_string_v1(row,"id"));
        } else {
            g_ptr_array_insert(editor->ids, added, g_strdup(linux_ordered_string_v1(row, "id")));
            g_ptr_array_insert(editor->modes, added, g_strdup(linux_ordered_string_v1(row, "mode")));
        }
        linux_ordered_render_v1(editor, added);
        gtk_label_set_text(GTK_LABEL(editor->status), replacement?"Replaced the measured hop in this draft.":"Added the measured hop to this draft.");
        if (linux_ordered_present_measurement_v1 &&
            (replacement || json_array_get_length(next->nodes) < ROUTERVPN_PHYSICAL_TRAVERSAL_DEPTH || linux_ordered_external_final_shape_v1(next->nodes,next->control)) &&
            linux_ordered_measurement_prefix_v1(next, json_node_get_object(current), added)) {
            editor->next_position = (int)added;
            editor->next_draft = linux_ordered_connect_body_v1(next);
            editor->next_measurement = g_idle_add(linux_ordered_continue_measured_v1, editor);
        }
    }
    if (current) json_node_free(current);
    linux_ordered_selection_free_v1(next);
    linux_ordered_selection_free_v1(before);
    return valid;
}

static void linux_ordered_measure_next_v1(GtkButton *button, gpointer data) {
    (void)button;
    LinuxOrderedEditorV1 *editor = data;
    if (!linux_ordered_editable_v1(editor)) return;
    if(editor->append_only){
        g_autofree char *body=linux_ordered_append_body_v1(editor);
        g_autoptr(JsonNode) parsed=body?json_from_string(body,NULL):NULL;
        g_autoptr(JsonNode) current=body?linux_ordered_read_v1("/api/profiles"):NULL;
        JsonObject *request=parsed?json_node_get_object(parsed):NULL;
        JsonObject *expected=linux_ordered_object_v1(request,"expected_profile_tokens");
        g_autoptr(JsonObject) prefix_tokens=json_object_new();
        JsonArray *nodes=linux_ordered_array_v1(request,"nodes");
        for(guint i=0;nodes && i<json_array_get_length(nodes);i++){
            const char *id=linux_ordered_string_v1(json_array_get_object_element(nodes,i),"id");
            json_object_set_string_member(prefix_tokens,id,linux_ordered_string_v1(expected,id));
        }
        if(!body || !current || !linux_ordered_append_current_v1(editor,nodes,prefix_tokens,json_node_get_object(current)) || !linux_ordered_present_measurement_v1){
            gtk_label_set_text(GTK_LABEL(editor->status),"Recapture the original Local packet prefix and device selection.");return;
        }
        int last=(int)editor->ids->len-1;gtk_list_box_select_row(GTK_LIST_BOX(editor->list),gtk_list_box_get_row_at_index(GTK_LIST_BOX(editor->list),last));
        linux_ordered_present_measurement_v1(editor->owned->unified->app,GTK_WINDOW(editor->dialog),body,last);return;
    }
    int position = linux_ordered_index_v1(editor);
    LinuxOrderedSelectionV1 *selection = linux_ordered_editor_selection_v1(editor);
    if (linux_ordered_present_measurement_v1 && linux_ordered_measurement_prefix_v1(selection, json_node_get_object(editor->catalog), position)) {
        char *body = linux_ordered_connect_body_v1(selection);
        linux_ordered_present_measurement_v1(editor->owned->unified->app, GTK_WINDOW(editor->dialog), body, position);
        g_free(body);
    } else gtk_label_set_text(GTK_LABEL(editor->status), "Choose a packet prefix with room for another hop, or a supported Shadowsocks prefix.");
    linux_ordered_selection_free_v1(selection);
}

static void linux_ordered_next_popup_v1(GtkComboBox *combo, gpointer data) {
    LinuxOrderedEditorV1 *editor = data;
    if (editor->append_only || !linux_ordered_present_measurement_v1 || !linux_ordered_editable_v1(editor) || !editor->ids->len) return;
    LinuxOrderedSelectionV1 *selection = linux_ordered_editor_selection_v1(editor);
    if (linux_ordered_measurement_prefix_v1(selection, json_node_get_object(editor->catalog), (int)editor->ids->len - 1)) {
        char *body = linux_ordered_connect_body_v1(selection);
        if (g_strcmp0(body, editor->offered_draft)) {
            g_signal_stop_emission_by_name(combo, "popup");
            g_free(editor->offered_draft); editor->offered_draft = g_strdup(body);
            const int index = (int)editor->ids->len - 1;
            gtk_list_box_select_row(GTK_LIST_BOX(editor->list), gtk_list_box_get_row_at_index(GTK_LIST_BOX(editor->list), index));
            linux_ordered_measure_next_v1(NULL, editor);
        }
        g_free(body);
    }
    linux_ordered_selection_free_v1(selection);
}

static gboolean linux_ordered_apply_v1(LinuxOrderedEditorV1 *editor) {
    if (editor->append_only || !linux_ordered_editable_v1(editor) || !routervpn_require_mutation_idle(editor->owned->unified->app, "applying the ordered path")) return FALSE;
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
    LinuxOrderedEditorV1 *editor = data;
    editor->closed = TRUE;
    linux_ordered_cancel_next_v1(editor);
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
        if (linux_ordered_external_final_shape_v1(owned->selection->nodes, control)) {
            JsonObject *last = json_array_get_object_element(owned->selection->nodes, json_array_get_length(owned->selection->nodes)-1);
            editor.external_exit = g_strdup(linux_ordered_string_v1(last, "id"));
        }
        g_free(editor.final_mode); editor.final_mode=g_strdup(linux_ordered_string_v1(json_array_get_object_element(owned->selection->nodes, json_array_get_length(owned->selection->nodes)-1), "mode"));
    }
    if (!fresh && owned->selection != NULL) for (guint i = 0; i + 1 < json_array_get_length(owned->selection->nodes); i++) {
        JsonObject *row = json_array_get_object_element(owned->selection->nodes, i);
        g_ptr_array_add(editor.ids, g_strdup(linux_ordered_string_v1(row, "id"))); g_ptr_array_add(editor.modes, g_strdup(linux_ordered_string_v1(row, "mode")));
    }
    editor.dialog = gtk_dialog_new_with_buttons("Ordered native path", GTK_WINDOW(unified->app->window), GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "Cancel", GTK_RESPONSE_CANCEL, "Apply path", GTK_RESPONSE_APPLY, NULL);
    g_object_ref(unified->app->window); g_object_ref_sink(editor.dialog);
    g_object_set_data(G_OBJECT(editor.dialog), "ordered-live-editor", &editor);
    gulong parent_closed = g_signal_connect(unified->app->window, "destroy", G_CALLBACK(linux_ordered_closed_v1), &editor);
    g_signal_connect(editor.dialog, "destroy", G_CALLBACK(linux_ordered_closed_v1), &editor);
    gtk_window_set_default_size(GTK_WINDOW(editor.dialog), 660, 480);
    GtkWidget *box = gtk_dialog_get_content_area(GTK_DIALOG(editor.dialog)); gtk_container_set_border_width(GTK_CONTAINER(box), 12);
    GtkWidget *note = gtk_label_new("Choose the nodes in order. Use Build prefix only to select and measure the next node. Choose a final node when the path is ready. Each node keeps its saved settings.");
    gtk_label_set_line_wrap(GTK_LABEL(note), TRUE); gtk_box_pack_start(GTK_BOX(box), note, FALSE, FALSE, 6);
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL); gtk_widget_set_size_request(scroll, -1, 190);
    editor.list = gtk_list_box_new(); gtk_container_add(GTK_CONTAINER(scroll), editor.list); gtk_box_pack_start(GTK_BOX(box), scroll, TRUE, TRUE, 6);
    editor.candidate = gtk_combo_box_text_new();
    gtk_widget_set_name(editor.candidate, "ordered-node-candidate");
    JsonArray *profiles = linux_ordered_array_v1(store, "profiles");
    for (guint i = 0; profiles != NULL && i < json_array_get_length(profiles); i++) {
        JsonNode *value = json_array_get_element(profiles, i); if (value == NULL || !JSON_NODE_HOLDS_OBJECT(value)) continue;
        JsonObject *candidate = json_node_get_object(value); const char *id = linux_ordered_string_v1(candidate, "id");
        if (external_source_profile_v24(store, id) == candidate && (linux_ordered_router_v1(candidate) || linux_ordered_imported_v1(candidate)) &&
            external_source_token_v24(linux_ordered_string_v1(candidate, "profile_token")))
            gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(editor.candidate), id, linux_ordered_name_v1(&editor, id));
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(editor.candidate), -1);
    g_signal_connect(editor.candidate, "popup", G_CALLBACK(linux_ordered_next_popup_v1), &editor);
    GtkWidget *add_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6); gtk_box_pack_start(GTK_BOX(add_row), editor.candidate, TRUE, TRUE, 0);
    editor.add = make_button("Add entry / hop", G_CALLBACK(linux_ordered_add_v1), &editor); gtk_box_pack_start(GTK_BOX(add_row), editor.add, FALSE, FALSE, 0);
    GtkWidget *external_exit = make_button("Use as external exit", G_CALLBACK(linux_ordered_choose_external_exit_v1), &editor);
    gtk_box_pack_start(GTK_BOX(add_row), external_exit, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), add_row, FALSE, FALSE, 6);
    GtkWidget *actions = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    editor.up = make_button("Move up", G_CALLBACK(linux_ordered_move_v1), &editor); g_object_set_data(G_OBJECT(editor.up), "ordered-offset", GINT_TO_POINTER(-1));
    editor.down = make_button("Move down", G_CALLBACK(linux_ordered_move_v1), &editor); g_object_set_data(G_OBJECT(editor.down), "ordered-offset", GINT_TO_POINTER(1));
    editor.remove = make_button("Remove", G_CALLBACK(linux_ordered_remove_v1), &editor);
    editor.transport = gtk_combo_box_text_new(); const char *modes[] = {"wg", "awg2-fast", "awg2-strong", "shadowsocks", "socks5", "hysteria2", "http-connect", "https-connect", "openvpn"};
    gtk_widget_set_name(editor.transport, "ordered-prefix-transport");
    for (guint i = 0; i < G_N_ELEMENTS(modes); i++) gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(editor.transport), modes[i], linux_ordered_mode_name_v1(modes[i]));
    GtkWidget *measure = make_button("Measure next hop…", G_CALLBACK(linux_ordered_measure_next_v1), &editor);
    GtkWidget *buttons[] = {editor.up, editor.down, editor.remove, editor.transport, measure};
    for (guint i = 0; i < G_N_ELEMENTS(buttons); i++) gtk_box_pack_start(GTK_BOX(actions), buttons[i], FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), actions, FALSE, FALSE, 6);
    GtkWidget *append_row=gtk_box_new(GTK_ORIENTATION_HORIZONTAL,6);
    editor.prefix_only=make_button("Build prefix only",G_CALLBACK(linux_ordered_prefix_only_v1),&editor);
    gtk_box_pack_start(GTK_BOX(append_row),editor.prefix_only,FALSE,FALSE,0);
    editor.append_mode=gtk_combo_box_text_new();
    const char *append_modes[]={"wg","awg2-fast","awg2-strong","shadowsocks","hysteria2"};
    for(guint i=0;i<G_N_ELEMENTS(append_modes);i++)gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(editor.append_mode),append_modes[i],linux_ordered_mode_name_v1(append_modes[i]));
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(editor.append_mode),"external-shadowsocks","Imported Shadowsocks");
    gtk_combo_box_set_active(GTK_COMBO_BOX(editor.append_mode),0);gtk_widget_set_no_show_all(editor.append_mode,TRUE);
    gtk_widget_set_tooltip_text(editor.append_mode,"Explicit next measured transport");
    gtk_box_pack_start(GTK_BOX(append_row),editor.append_mode,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(box),append_row,FALSE,FALSE,6);
    editor.complete_prefix=make_button("Use last Shadowsocks node as final",G_CALLBACK(linux_ordered_complete_prefix_v1),&editor);
    gtk_widget_set_no_show_all(editor.complete_prefix,TRUE);gtk_box_pack_start(GTK_BOX(box),editor.complete_prefix,FALSE,FALSE,6);
    editor.execution = gtk_combo_box_text_new(); gtk_widget_set_name(editor.execution, "ordered-execution");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(editor.execution), "local", "Local");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(editor.execution), "server", "Server");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(editor.execution), "auto", "Compare in the native child");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(editor.execution), !fresh && owned->selection != NULL ? owned->selection->execution : "local");
    gtk_box_pack_start(GTK_BOX(box), editor.execution, FALSE, FALSE, 6);
    editor.status = gtk_label_new("Final exit stays pinned. Server and Compare support paired paths, Shadowsocks or CONNECT prefixes, SOCKS5 prefixes, or independently paired OpenVPN prefixes. Hostname paths need at least four nodes and saved Custom TCP DNS."); gtk_label_set_line_wrap(GTK_LABEL(editor.status), TRUE); gtk_box_pack_start(GTK_BOX(box), editor.status, FALSE, FALSE, 6);
    g_signal_connect(editor.candidate, "changed", G_CALLBACK(linux_ordered_candidate_changed_v1), &editor);
    g_signal_connect(editor.list, "row-selected", G_CALLBACK(linux_ordered_selected_v1), &editor);
    g_signal_connect(editor.transport, "changed", G_CALLBACK(linux_ordered_mode_v1), &editor);
    linux_ordered_render_v1(&editor, 0); gtk_widget_show_all(editor.dialog);
    while (gtk_dialog_run(GTK_DIALOG(editor.dialog)) == GTK_RESPONSE_APPLY) if (linux_ordered_apply_v1(&editor)) break;
    linux_ordered_cancel_next_v1(&editor);
    editor.closed = TRUE; g_object_set_data(G_OBJECT(editor.dialog), "ordered-live-editor", NULL); gtk_widget_destroy(editor.dialog);
    if (g_signal_handler_is_connected(unified->app->window, parent_closed))
        g_signal_handler_disconnect(unified->app->window, parent_closed);
    g_object_unref(editor.dialog); g_object_unref(unified->app->window);
    g_ptr_array_unref(editor.ids); g_ptr_array_unref(editor.modes); g_free(editor.control); g_free(editor.final_mode); g_free(editor.external_exit); g_free(editor.offered_draft); json_node_free(editor.catalog);
}
