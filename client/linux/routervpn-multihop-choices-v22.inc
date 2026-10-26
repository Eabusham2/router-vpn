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
