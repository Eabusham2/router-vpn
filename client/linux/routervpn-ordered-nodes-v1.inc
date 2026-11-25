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
    return g_strcmp0(mode, "shadowsocks") == 0 || g_strcmp0(mode, "hysteria2") == 0;
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
    if (linux_ordered_extended_shape_v1(nodes)) return TRUE;
    guint count = nodes == NULL ? 0 : json_array_get_length(nodes);
    if (count <= 8 || count > ROUTERVPN_PHYSICAL_TRAVERSAL_DEPTH) return FALSE;
    for (guint i = 0; i < count; i++) {
        JsonNode *row = json_array_get_element(nodes, i);
        if (row == NULL || !JSON_NODE_HOLDS_OBJECT(row) ||
            g_strcmp0(linux_ordered_string_v1(json_node_get_object(row), "mode"), i == 0 ? "awg2-fast" : "shadowsocks") != 0)
            return FALSE;
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

static gboolean linux_ordered_rows_v1(JsonArray *nodes, const char *control) {
    guint count = nodes != NULL ? json_array_get_length(nodes) : 0;
    if (count < 2 || (count > 8 && !linux_ordered_extended_shape_v1(nodes) && !linux_ordered_extended_paired_shape_v1(nodes) && !linux_ordered_extended_mixed_shape_v1(nodes)) || !external_source_id_v24(control)) return FALSE;
    gboolean imported_middle = FALSE;
    for (guint i = 0; i < count; i++) {
        JsonNode *value = json_array_get_element(nodes, i);
        if (value == NULL || !JSON_NODE_HOLDS_OBJECT(value)) return FALSE;
        JsonObject *row = json_node_get_object(value);
        const char *id = linux_ordered_string_v1(row, "id"), *mode = linux_ordered_string_v1(row, "mode");
        if (json_object_get_size(row) != 2 || !external_source_id_v24(id) ||
            (i + 1 == count ? !linux_ordered_final_v1(mode) || strcmp(id, control) != 0 : !linux_ordered_prefix_v1(mode) && !((linux_ordered_imported_position_v1(mode, i, count) || linux_ordered_local_ss_position_v1(mode, i, count) || (i == 0 && linux_ordered_custom_entry_shape_v1(nodes))) && (strcmp(mode, "shadowsocks") == 0 || strcmp(mode, "socks5") == 0 || strcmp(mode, "http-connect") == 0 || strcmp(mode, "https-connect") == 0 || strcmp(mode, "openvpn") == 0)))) return FALSE;
        if (i + 1 < count && (strcmp(mode, "shadowsocks") == 0 || strcmp(mode, "socks5") == 0 || strcmp(mode, "http-connect") == 0 || strcmp(mode, "https-connect") == 0 || strcmp(mode, "openvpn") == 0)) imported_middle = TRUE;
        for (guint j = 0; j < i; j++)
            if (strcmp(id, linux_ordered_string_v1(json_array_get_object_element(nodes, j), "id")) == 0) return FALSE;
    }
    return !imported_middle || strcmp(linux_ordered_string_v1(json_array_get_object_element(nodes, count - 1), "mode"), "shadowsocks") == 0;
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
    if (json_array_get_length(selection->nodes) > 8 && !linux_ordered_extended_selected_shape_v1(selection->nodes) &&
        ((!linux_ordered_extended_paired_shape_v1(selection->nodes) && !linux_ordered_extended_mixed_shape_v1(selection->nodes)) || strcmp(execution, "local") != 0)) return FALSE;
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

static gboolean linux_ordered_paired_off_v1(JsonObject *profile) {
    if (!linux_ordered_router_v1(profile)) return FALSE;
    if (!json_object_has_member(profile, "start_layer")) return TRUE;
    JsonNode *layer = json_object_get_member(profile, "start_layer");
    if (layer == NULL || !JSON_NODE_HOLDS_VALUE(layer) || json_node_get_value_type(layer) != G_TYPE_STRING) return FALSE;
    const char *value = json_node_get_string(layer);
    return value != NULL && (!value[0] || strcmp(value, "off") == 0);
}

static gboolean linux_ordered_extended_paired_path_v1(const LinuxOrderedSelectionV1 *selection, JsonObject *catalog) {
    if (selection == NULL || strcmp(selection->execution, "local") != 0 || !linux_ordered_extended_paired_shape_v1(selection->nodes)) return FALSE;
    for (guint i = 0; i < json_array_get_length(selection->nodes); i++) {
        const char *id = linux_ordered_string_v1(json_array_get_object_element(selection->nodes, i), "id");
        if (!linux_ordered_paired_off_v1(external_source_profile_v24(catalog, id))) return FALSE;
    }
    return TRUE;
}

static gboolean linux_ordered_final_profile_v1(JsonObject *profile, const char *mode) {
    if (!linux_ordered_router_v1(profile) || !linux_ordered_final_v1(mode)) return FALSE;
    if (strcmp(mode, "shadowsocks") == 0) return TRUE;
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
    gboolean paired_stream = FALSE, hostname = FALSE, all_off = TRUE;
    for (guint position = 0; position < count; position++) {
        JsonObject *row = json_array_get_object_element(selection->nodes, position);
        const char *mode = linux_ordered_string_v1(row, "mode");
        JsonObject *profile = external_source_profile_v24(catalog, linux_ordered_string_v1(row, "id"));
        if (profile == NULL) return FALSE;
        gboolean host_here = !selected && count >= 4 && packet_prefixes > 0 && position == packet_prefixes &&
            (position + 2 < count || count > 8) && linux_ordered_hostname_import_off_v1(profile);
        all_off = all_off && (host_here || linux_ordered_paired_off_v1(profile) || linux_ordered_literal_import_off_v1(profile));
        if (count > 8) {
            gboolean interior = position >= packet_prefixes && position + 1 < count;
            gboolean imported = strcmp(linux_ordered_string_v1(profile, "node_kind"), "external") == 0;
            JsonNode *raw_layer = json_object_has_member(profile, "start_layer") ? json_object_get_member(profile, "start_layer") : NULL;
            const char *layer = linux_ordered_string_v1(profile, "start_layer");
            if (!packet_prefixes || (!interior && imported) || (selected && interior != imported) || (raw_layer && (!JSON_NODE_HOLDS_VALUE(raw_layer) || json_node_get_value_type(raw_layer) != G_TYPE_STRING)) ||
                (layer[0] && strcmp(layer, "off") != 0)) return FALSE;
        }
        if (strcmp(linux_ordered_string_v1(profile, "node_kind"), "external") == 0) {
            if ((!linux_ordered_local_ss_position_v1(mode, position, count) && !(position == 0 && linux_ordered_custom_entry_shape_v1(selection->nodes))) || strcmp(linux_ordered_imported_mode_v1(profile), "shadowsocks") != 0 ||
                (!host_here && !linux_ordered_flag_v1(linux_ordered_object_v1(profile, "external"), hint))) return FALSE;
            JsonObject *external = linux_ordered_object_v1(profile,"external");
            JsonNode *source_host = json_object_get_member(external,"ordered_hostname_execution_middle_supported");
            if (source_host && (!JSON_NODE_HOLDS_VALUE(source_host) || json_node_get_value_type(source_host)!=G_TYPE_BOOLEAN || (json_node_get_boolean(source_host) && !host_here))) return FALSE;
            hostname |= host_here;
            imports++;
        } else {
            if (!linux_ordered_router_v1(profile)) return FALSE;
            if (position + 1 < count && !linux_ordered_prefix_v1(mode)) {
                if (selected || !packet_prefixes || position < packet_prefixes || strcmp(mode,"shadowsocks")) return FALSE;
                paired_stream = TRUE;
            }
        }
    }
    return imports > 0 && (!(paired_stream || hostname) || all_off);
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
    gboolean local_imported = linux_ordered_local_imported_path_v1(selection, catalog);
    gboolean paired_extended = linux_ordered_extended_paired_path_v1(selection, catalog);
    gboolean multiple_imported = strcmp(selection->execution, "local") != 0 && linux_ordered_multiple_imported_shape_v1(selection->nodes);
    if ((multiple_imported || json_array_get_length(selection->nodes) > 8) && !local_imported && !paired_extended) return FALSE;
    for (guint i = 0; i < json_array_get_length(selection->nodes); i++) {
        const char *id = linux_ordered_string_v1(json_array_get_object_element(selection->nodes, i), "id");
        JsonObject *profile = external_source_profile_v24(catalog, id);
        const char *mode = linux_ordered_string_v1(json_array_get_object_element(selection->nodes, i), "mode");
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
        gboolean admitted = imported ? (linux_ordered_imported_position_v1(mode, i, json_array_get_length(selection->nodes)) || (local_imported && (linux_ordered_local_ss_position_v1(mode, i, json_array_get_length(selection->nodes)) || (i == 0 && linux_ordered_custom_entry_shape_v1(selection->nodes))))) && strcmp(mode, linux_ordered_imported_mode_v1(profile)) == 0 : linux_ordered_router_v1(profile) && (i + 1 == json_array_get_length(selection->nodes) || linux_ordered_prefix_v1(mode) || (local_imported && !strcmp(selection->execution,"local") && !strcmp(mode,"shadowsocks")));
        if (!admitted || (i + 1 == json_array_get_length(selection->nodes) && !linux_ordered_final_profile_v1(profile, mode)) ||
            strcmp(linux_ordered_string_v1(profile, "profile_token"), linux_ordered_string_v1(selection->tokens, id)) != 0) return FALSE;
    }
    return TRUE;
}

static gboolean linux_ordered_measurement_prefix_v1(const LinuxOrderedSelectionV1 *selection, JsonObject *catalog, int position) {
    if (!selection || position < 0 || !linux_ordered_current_v1(selection, catalog)) return FALSE;
    guint count = json_array_get_length(selection->nodes);
    if ((guint)position + 1 >= count) return FALSE;
    const char *mode = linux_ordered_string_v1(json_array_get_object_element(selection->nodes, position), "mode");
    if (!strcmp(mode, "shadowsocks")) {
        JsonObject *first = json_array_get_object_element(selection->nodes, 0), *final = json_array_get_object_element(selection->nodes, count - 1);
        JsonObject *selected = external_source_profile_v24(catalog, linux_ordered_string_v1(json_array_get_object_element(selection->nodes, position), "id"));
        JsonObject *external = linux_ordered_object_v1(selected, "external");
        if (linux_ordered_flag_v1(external, "ordered_hostname_execution_middle_supported") &&
            (linux_ordered_flag_v1(external, "ordered_execution_middle_supported") || linux_ordered_flag_v1(external, "ordered_local_imported_nodes_supported"))) return FALSE;
        gboolean hostname = count >= 3 && count <= 8 && (guint)position + 2 == count &&
            linux_ordered_flag_v1(external, "ordered_hostname_execution_middle_supported") &&
            !linux_ordered_flag_v1(external, "ordered_execution_middle_supported") &&
            !linux_ordered_flag_v1(external, "ordered_local_imported_nodes_supported");
        if (position < 1 || (count > 8 && !linux_ordered_extended_shape_v1(selection->nodes) && !linux_ordered_extended_mixed_shape_v1(selection->nodes)) || strcmp(selection->execution, "local") || (!hostname && !linux_ordered_local_imported_path_v1(selection, catalog)) ||
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
                    !((guint)i == linux_ordered_imported_packet_prefixes_v1(selection->nodes) && linux_ordered_hostname_import_off_v1(source))) return FALSE;
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
            valid = valid && count >= 2 && (count <= 8 || linux_ordered_extended_shape_v1(nodes) || linux_ordered_extended_paired_shape_v1(nodes) || linux_ordered_extended_mixed_shape_v1(nodes));
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
        if (value != NULL && JSON_NODE_HOLDS_VALUE(value) && json_node_get_value_type(value) == G_TYPE_STRING &&
            g_strcmp0(json_node_get_string(value), selection->execution) == 0) admitted = TRUE;
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
    char *control, *final_mode;
    JsonNode *catalog;
    GPtrArray *ids, *modes;
    GtkWidget *dialog, *list, *candidate, *transport, *execution, *status, *add, *remove, *up, *down;
    gboolean syncing, closed;
    char *offered_draft;
} LinuxOrderedEditorV1;

static const char *linux_ordered_editor_final_mode_v1(LinuxOrderedEditorV1 *editor) {
    return editor->final_mode != NULL ? editor->final_mode : "shadowsocks";
}

static gboolean linux_ordered_editor_final_allowed_v1(LinuxOrderedEditorV1 *editor, const char *mode) {
    if (!linux_ordered_final_profile_v1(external_source_profile_v24(json_node_get_object(editor->catalog), editor->control), mode)) return FALSE;
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

static gboolean linux_ordered_editor_can_extend_v1(LinuxOrderedEditorV1 *editor) {
    if (editor->ids->len < 7) return TRUE;
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
    gtk_widget_set_sensitive(editor->transport, valid && index >= 0 && (guint)index <= editor->ids->len);
    gtk_widget_set_sensitive(editor->remove, valid && prefix);
    gtk_widget_set_sensitive(editor->up, valid && prefix && index > 0);
    gtk_widget_set_sensitive(editor->down, valid && prefix && (guint)(index + 1) < editor->ids->len);
    gtk_widget_set_sensitive(editor->add, valid && linux_ordered_editor_can_extend_v1(editor));
    gtk_widget_set_sensitive(gtk_dialog_get_widget_for_response(GTK_DIALOG(editor->dialog), GTK_RESPONSE_APPLY), valid && editor->ids->len > 0 && editor->ids->len < ROUTERVPN_PHYSICAL_TRAVERSAL_DEPTH);
}

static void linux_ordered_candidate_changed_v1(GtkComboBox *combo, gpointer data) {
    (void)combo;
    LinuxOrderedEditorV1 *editor = data;
    gtk_widget_set_sensitive(editor->add, linux_ordered_editable_v1(editor) && linux_ordered_editor_can_extend_v1(editor));
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
    if (!linux_ordered_editable_v1(editor) || id == NULL || !linux_ordered_editor_can_extend_v1(editor) || strcmp(id, editor->control) == 0) return;
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
            gtk_label_set_text(GTK_LABEL(editor->status), "Choose Shadowsocks 2022, or Hysteria2 with its own Start Layer and paired packet prefixes."); return;
        }
        char *copy = g_strdup(mode); g_free(editor->final_mode); editor->final_mode = copy;
        linux_ordered_render_v1(editor, index); return;
    }
    gboolean imported = index >= 0 && (guint)index < editor->ids->len && linux_ordered_imported_v1(external_source_profile_v24(json_node_get_object(editor->catalog), g_ptr_array_index(editor->ids, index)));
    if (index < 0 || (guint)index >= editor->ids->len || (imported ? g_strcmp0(mode, linux_ordered_imported_mode_v1(external_source_profile_v24(json_node_get_object(editor->catalog), g_ptr_array_index(editor->ids, index)))) != 0 : !linux_ordered_prefix_v1(mode))) {
        linux_ordered_selected_v1(NULL, NULL, editor);
        gtk_label_set_text(GTK_LABEL(editor->status), "Paired prefixes use WireGuard, AWG2 Fast or AWG2 Strong. An imported middle keeps its saved transport. The paired final uses Shadowsocks 2022 or Hysteria2 with its own Start Layer.");
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
    const char *execution = editor->execution != NULL ? gtk_combo_box_get_active_id(GTK_COMBO_BOX(editor->execution)) : "local";
    if (!linux_ordered_execution_v1(selection, execution)) { linux_ordered_selection_free_v1(selection); selection = NULL; }
    json_array_unref(nodes); json_object_unref(tokens); return selection;
}

static void (*linux_ordered_present_measurement_v1)(App *, GtkWindow *, const char *, int);

static gboolean linux_ordered_adopt_measured_v1(GtkWindow *parent, const char *captured, int position, JsonObject *response) {
    LinuxOrderedEditorV1 *editor = g_object_get_data(G_OBJECT(parent), "ordered-live-editor");
    if (!editor || !linux_ordered_editable_v1(editor) || position != linux_ordered_index_v1(editor) ||
        position < 0 || (guint)position >= editor->ids->len) return FALSE;
    LinuxOrderedSelectionV1 *before = linux_ordered_editor_selection_v1(editor);
    if (!before) return FALSE;
    char *original = linux_ordered_connect_body_v1(before);
    gboolean valid = !strcmp(captured, original) && !strcmp(editor->control, linux_ordered_string_v1(response, "expected_selected_node_id")) &&
        (!strcmp(before->execution, "local") || !strcmp(before->execution, linux_ordered_string_v1(response, "requested_execution")));
    g_free(original);
    JsonArray *rows = linux_ordered_array_v1(response, "proposed_path");
    JsonObject *tokens = linux_ordered_object_v1(response, "expected_profile_tokens");
    const guint added = (guint)position + 1;
    LinuxOrderedSelectionV1 *next = valid ? linux_ordered_selection_v1(editor->control, rows, tokens) : NULL;
    valid = next && json_array_get_length(next->nodes) == json_array_get_length(before->nodes) + 1 &&
        linux_ordered_execution_v1(next, before->execution) && linux_ordered_current_v1(next, json_node_get_object(editor->catalog));
    for (guint i = 0; valid && i < json_array_get_length(before->nodes); i++) {
        JsonNode *original_row = json_array_get_element(before->nodes, i);
        valid = json_node_equal(original_row, json_array_get_element(next->nodes, i < added ? i : i + 1));
    }
    JsonObject *row = valid ? json_array_get_object_element(next->nodes, added) : NULL;
    valid = valid && !strcmp(linux_ordered_string_v1(row, "id"), linux_ordered_string_v1(response, "candidate_id"));
    JsonNode *current = valid ? linux_ordered_read_v1("/api/profiles") : NULL;
    valid = current && linux_ordered_current_v1(next, json_node_get_object(current)) && linux_ordered_editable_v1(editor);
    if (valid) {
        g_ptr_array_insert(editor->ids, added, g_strdup(linux_ordered_string_v1(row, "id")));
        g_ptr_array_insert(editor->modes, added, g_strdup(linux_ordered_string_v1(row, "mode")));
        linux_ordered_render_v1(editor, added);
        gtk_label_set_text(GTK_LABEL(editor->status), "Added the measured hop to this draft.");
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
    int position = linux_ordered_index_v1(editor);
    LinuxOrderedSelectionV1 *selection = linux_ordered_editor_selection_v1(editor);
    if (linux_ordered_present_measurement_v1 && linux_ordered_measurement_prefix_v1(selection, json_node_get_object(editor->catalog), position)) {
        char *body = linux_ordered_connect_body_v1(selection);
        linux_ordered_present_measurement_v1(editor->owned->unified->app, GTK_WINDOW(editor->dialog), body, position);
        g_free(body);
    } else gtk_label_set_text(GTK_LABEL(editor->status), "Choose a packet prefix with room for another hop, or a supported Local Shadowsocks import.");
    linux_ordered_selection_free_v1(selection);
}

static void linux_ordered_next_popup_v1(GtkComboBox *combo, gpointer data) {
    LinuxOrderedEditorV1 *editor = data;
    if (!linux_ordered_present_measurement_v1 || !linux_ordered_editable_v1(editor) || !editor->ids->len) return;
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
    g_object_set_data(G_OBJECT(editor.dialog), "ordered-live-editor", &editor);
    gulong parent_closed = g_signal_connect(unified->app->window, "destroy", G_CALLBACK(linux_ordered_closed_v1), &editor);
    g_signal_connect(editor.dialog, "destroy", G_CALLBACK(linux_ordered_closed_v1), &editor);
    gtk_window_set_default_size(GTK_WINDOW(editor.dialog), 660, 480);
    GtkWidget *box = gtk_dialog_get_content_area(GTK_DIALOG(editor.dialog)); gtk_container_set_border_width(GTK_CONTAINER(box), 12);
    GtkWidget *note = gtk_label_new("Choose the entry and each hop in order. Paired entries can use supported Shadowsocks 2022 imports at any interior position. Server and Compare require support from every import and the native controller. A custom entry uses Local with two distinct Shadowsocks imports and a paired Shadowsocks exit. SOCKS5, CONNECT and OpenVPN keep their single position immediately before a Shadowsocks final. A paired Hysteria2 final retains its selected Start Layer after paired WireGuard or AWG2 prefixes. Apply saves the choices; Connect proves the complete path.");
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
    g_signal_connect(editor.candidate, "popup", G_CALLBACK(linux_ordered_next_popup_v1), &editor);
    GtkWidget *add_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6); gtk_box_pack_start(GTK_BOX(add_row), editor.candidate, TRUE, TRUE, 0);
    editor.add = make_button("Add entry / hop", G_CALLBACK(linux_ordered_add_v1), &editor); gtk_box_pack_start(GTK_BOX(add_row), editor.add, FALSE, FALSE, 0); gtk_box_pack_start(GTK_BOX(box), add_row, FALSE, FALSE, 6);
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
    editor.closed = TRUE; g_object_set_data(G_OBJECT(editor.dialog), "ordered-live-editor", NULL); gtk_widget_destroy(editor.dialog);
    if (g_signal_handler_is_connected(unified->app->window, parent_closed))
        g_signal_handler_disconnect(unified->app->window, parent_closed);
    g_object_unref(editor.dialog); g_object_unref(unified->app->window);
    g_ptr_array_unref(editor.ids); g_ptr_array_unref(editor.modes); g_free(editor.control); g_free(editor.final_mode); g_free(editor.offered_draft); json_node_free(editor.catalog);
}
