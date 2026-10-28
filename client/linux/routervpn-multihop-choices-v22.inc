/* Router-to-Router exit IDs match the native controller catalog. Credentials
 * stay in the captured private node stores; these controls select only IDs. */
static const struct { const char *id; const char *label; } linux_multihop_exits_v22[] = {
    {"shadowsocks", "Shadowsocks exit"},
    {"hysteria2", "Hysteria2 exit"},
    {"reality-vision", "REALITY / Vision exit"},
    {"reality-pq-vision", "PQ REALITY / Vision exit"},
    {"reality-xhttp", "REALITY / XHTTP exit"},
    {"naive-h2", "Naive H2 exit"},
    {"naive-h3", "Naive H3 exit"},
    {"wg", "WireGuard exit"},
    {"awg2-fast", "AWG Fast exit"},
    {"awg2-strong", "AWG Strong exit"},
    {"ss-v2ray", "SS/V2Ray exit"},
    {"split", "Split exit"},
    {"max", "MAX exit"},
    {"wg-pq", "WG + PQ exit"},
    {"awg2-pq", "AWG + PQ exit"},
    {"max-tls-wg", "Complete MAX TLS / WG exit"},
    {"max-tls-awg", "Complete MAX TLS / AWG exit"},
    {"max-quic-wg", "Complete MAX QUIC / WG exit"},
    {"max-quic-awg", "Complete MAX QUIC / AWG exit"},
};

static gboolean linux_multihop_exit_supported_v22(const char *mode) {
    for (guint i = 0; i < G_N_ELEMENTS(linux_multihop_exits_v22); i++) {
        if (g_strcmp0(mode, linux_multihop_exits_v22[i].id) == 0) return TRUE;
    }
    return FALSE;
}

static gboolean linux_multihop_execution_supported_v22(const char *execution) {
    return g_strcmp0(execution, "local") == 0 || g_strcmp0(execution, "server") == 0 || g_strcmp0(execution, "auto") == 0;
}

static long linux_multihop_initial_key_ms_v23(const char *mode) {
    const char *modes[] = {"wg-pq", "awg2-pq", "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"};
    for (guint i = 0; i < G_N_ELEMENTS(modes); i++) {
        if (g_strcmp0(mode, modes[i]) == 0) return 30000;
    }
    return 0;
}

static long linux_multihop_startup_timeout_v23(const char *entry, const char *exit, const char *execution) {
    if (g_strcmp0(execution, "auto") != 0) return 180000;
    /* A blank entry delegates to the saved control graph; allow its possible
     * initial-key phase until the controller resolves that exact raw mode. */
    long entry_phase = entry == NULL || !entry[0] ? 30000 : linux_multihop_initial_key_ms_v23(entry);
    long alternatives = g_strcmp0(exit, "auto") == 0 ? 2 : 1;
    long phases = 4 * (alternatives * entry_phase + linux_multihop_initial_key_ms_v23(exit));
    return phases == 0 ? 180000 : 210000 + phases;
}

static gboolean linux_multihop_exit_advertised_v22(JsonArray *catalog, const char *mode) {
    if (!linux_multihop_exit_supported_v22(mode)) return FALSE;
    guint matches = 0;
    for (guint i = 0; catalog != NULL && i < json_array_get_length(catalog); i++) {
        JsonNode *item = json_array_get_element(catalog, i);
        if (item != NULL && JSON_NODE_HOLDS_VALUE(item) && json_node_get_value_type(item) == G_TYPE_STRING &&
            g_strcmp0(json_node_get_string(item), mode) == 0) matches++;
    }
    return matches == 1;
}

static void linux_multihop_select_preserving_v22(GtkWidget *combo, const char *id) {
    const char *choice = id != NULL ? id : "";
    if (gtk_combo_box_set_active_id(GTK_COMBO_BOX(combo), choice)) return;
    char *label = g_strdup_printf("Unavailable saved choice: %s", choice[0] ? choice : "missing");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo), choice, label);
    g_free(label);
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(combo), choice);
}

static void linux_multihop_exit_choices_v22(GtkWidget *combo, const char *selected) {
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(combo));
    for (guint i = 0; i < G_N_ELEMENTS(linux_multihop_exits_v22); i++) {
        gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo), linux_multihop_exits_v22[i].id, linux_multihop_exits_v22[i].label);
    }
    linux_multihop_select_preserving_v22(combo, selected);
}

static void linux_multihop_execution_choices_v22(GtkWidget *combo, const char *selected) {
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo), "local", "Local");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo), "server", "Server");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo), "auto", "Compare both");
    linux_multihop_select_preserving_v22(combo, selected);
}

static const struct { const char *id; const char *label; } linux_multihop_entries_v23[] = {
    {"wg", "WireGuard"}, {"awg2-fast", "AWG Fast"}, {"awg2-strong", "AWG Strong"},
    {"wg-pq", "WG + PQ"}, {"awg2-pq", "AWG + PQ"},
    {"shadowsocks", "Shadowsocks"}, {"hysteria2", "Hysteria2"},
    {"reality-vision", "REALITY / Vision"}, {"reality-pq-vision", "PQ REALITY / Vision"},
    {"reality-xhttp", "REALITY / XHTTP"}, {"naive-h2", "Naive H2"}, {"naive-h3", "Naive H3"},
    {"ss-v2ray", "SS/V2Ray"}, {"split", "Split"}, {"max", "MAX"},
    {"max-tls-wg", "Complete MAX TLS / WG"}, {"max-tls-awg", "Complete MAX TLS / AWG"},
    {"max-quic-wg", "Complete MAX QUIC / WG"}, {"max-quic-awg", "Complete MAX QUIC / AWG"},
};

static gboolean linux_multihop_entry_supported_v23(const char *mode) {
    if (mode == NULL) return FALSE;
    if (!mode[0]) return TRUE; /* The controller resolves the saved mode/base. */
    for (guint i = 0; i < G_N_ELEMENTS(linux_multihop_entries_v23); i++) {
        if (strcmp(mode, linux_multihop_entries_v23[i].id) == 0) return TRUE;
    }
    return FALSE;
}

static gboolean linux_multihop_entry_advertised_v23(JsonArray *catalog, const char *mode) {
    if (!linux_multihop_entry_supported_v23(mode) || catalog == NULL || json_array_get_length(catalog) == 0) return FALSE;
    if (!mode[0]) {
        for (guint i = 0; i < G_N_ELEMENTS(linux_multihop_entries_v23); i++) {
            if (linux_multihop_entry_advertised_v23(catalog, linux_multihop_entries_v23[i].id)) return TRUE;
        }
        return FALSE;
    }
    guint matches = 0;
    for (guint i = 0; i < json_array_get_length(catalog); i++) {
        JsonNode *item = json_array_get_element(catalog, i);
        if (item != NULL && JSON_NODE_HOLDS_VALUE(item) && json_node_get_value_type(item) == G_TYPE_STRING &&
            g_strcmp0(json_node_get_string(item), mode) == 0) matches++;
    }
    return matches == 1;
}

static void linux_multihop_entry_choices_v23(GtkWidget *combo, JsonArray *catalog, const char *selected) {
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(combo));
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo), "", "Use saved graph mode / entry base");
    for (guint i = 0; i < G_N_ELEMENTS(linux_multihop_entries_v23); i++) {
        if (linux_multihop_entry_advertised_v23(catalog, linux_multihop_entries_v23[i].id))
            gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo), linux_multihop_entries_v23[i].id, linux_multihop_entries_v23[i].label);
    }
    linux_multihop_select_preserving_v22(combo, selected);
}
