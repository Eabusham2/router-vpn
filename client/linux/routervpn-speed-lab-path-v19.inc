/* The dialog owns this public options snapshot. Private transport credentials
 * stay in the controller, which validates and captures the path again at Run. */
static void linux_speed_lab_refresh_controls_v12(GtkComboBox *, gpointer);

static JsonArray *linux_speed_lab_catalog_v19(LinuxSpeedLabV12 *s, const char *key) {
    if (s->options == NULL) return NULL;
    JsonObject *root = json_node_get_object(s->options);
    JsonNode *value = json_object_get_member(root, key);
    return value != NULL && JSON_NODE_HOLDS_ARRAY(value) ? json_node_get_array(value) : NULL;
}

static JsonObject *linux_speed_lab_find_v19(LinuxSpeedLabV12 *s, const char *key, const char *id) {
    JsonArray *values = linux_speed_lab_catalog_v19(s, key); JsonObject *found = NULL;
    if (id == NULL || id[0] == '\0') return NULL;
    for (guint i = 0; values != NULL && i < json_array_get_length(values); i++) {
        JsonObject *value = json_array_get_object_element(values, i);
        if (value != NULL && strcmp(obj_string(value, "id"), id) == 0) {
            if (found != NULL) return NULL;
            found = value;
        }
    }
    return found;
}

static gboolean linux_speed_lab_flag_v19(JsonObject *value, const char *key) {
    JsonNode *member = value != NULL ? json_object_get_member(value, key) : NULL;
    return member != NULL && JSON_NODE_HOLDS_VALUE(member) && json_node_get_value_type(member) == G_TYPE_BOOLEAN && json_node_get_boolean(member);
}

static const char *linux_speed_lab_kind_v19(JsonObject *value) {
    if (value == NULL) return "";
    const char *kind = obj_string(value, "node_kind");
    return kind[0] != '\0' ? kind : "router-vpn";
}

static void linux_speed_lab_select_v19(GtkWidget *combo, const char *id) {
    /* Keep an unavailable saved identity visible. Run rejects it until the user
     * deliberately chooses a current node/mode; it never becomes Direct/WG. */
    if (!gtk_combo_box_set_active_id(GTK_COMBO_BOX(combo), id)) {
        char *label = g_strdup_printf("Unavailable saved choice: %s", id);
        gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo), id, label); g_free(label);
        gtk_combo_box_set_active_id(GTK_COMBO_BOX(combo), id);
    }
}

static void linux_speed_lab_entry_default_v19(LinuxSpeedLabV12 *s) {
    const char *id = linux_speed_lab_active_id_v12(s->entry);
    JsonObject *entry = linux_speed_lab_find_v19(s, "nodes", id);
    JsonObject *node = linux_speed_lab_find_v19(s, "nodes", linux_speed_lab_active_id_v12(s->node));
    if (strcmp(linux_speed_lab_kind_v19(entry), "router-vpn") != 0) {
        gtk_combo_box_set_active(GTK_COMBO_BOX(s->entry_mode), -1); return;
    }
    const char *mode = "";
    if (node != NULL && strcmp(id, obj_string(node, "multihop_entry_id")) == 0) mode = obj_string(node, "multihop_entry_mode");
    if (mode[0] == '\0') {
        const char *base=obj_string(entry,"base_tunnel");
        if(strcmp(base,"wg")!=0&&strcmp(base,"awg")!=0&&node!=NULL)base=obj_string(node,"base_tunnel");
        mode=strcmp(base,"awg")==0?"awg2-fast":"wg";
    }
    linux_speed_lab_select_v19(s->entry_mode, mode);
}

static void linux_speed_lab_defaults_v19(LinuxSpeedLabV12 *s) {
    if (s->updating_choices || s->options == NULL) return;
    JsonObject *node = linux_speed_lab_find_v19(s, "nodes", linux_speed_lab_active_id_v12(s->node));
    if (node == NULL) return;
    s->updating_choices = TRUE;
    const char *base = obj_string(node, "base_tunnel");
    linux_speed_lab_select_v19(s->base, base[0] != '\0' ? base : "auto");
    const char *top = linux_speed_lab_active_id_v12(s->topology);
    gboolean saved = linux_speed_lab_flag_v19(node, "multihop_enabled");
    if (strcmp(top, "external") == 0) {
        linux_speed_lab_select_v19(s->entry, saved ? obj_string(node, "multihop_entry_id") : "");
        const char *execution = saved ? obj_string(node, "multihop_execution") : "local";
        linux_speed_lab_select_v19(s->execution, execution[0] != '\0' ? execution : "local");
        linux_speed_lab_entry_default_v19(s);
    } else if (strcmp(top, "multihop") == 0) {
        const char *entry = saved ? obj_string(node, "multihop_entry_id") : obj_string(node, "id");
        linux_speed_lab_select_v19(s->entry, entry[0] != '\0' ? entry : obj_string(node, "id"));
        const char *exit = obj_string(node, "multihop_exit_id");
        if (saved && exit[0] != '\0') linux_speed_lab_select_v19(s->exit, exit);
        const char *execution = saved ? obj_string(node, "multihop_execution") : "local";
        linux_speed_lab_select_v19(s->execution, execution[0] != '\0' ? execution : "local");
    }
    s->updating_choices = FALSE;
}

static void linux_speed_lab_path_changed_v19(GtkComboBox *changed, gpointer data) {
    LinuxSpeedLabV12 *s = data;
    if (s == NULL || s->closed || s->updating_choices || s->options == NULL) return;
    if (GTK_WIDGET(changed) == s->entry) {
        s->updating_choices = TRUE;
        linux_speed_lab_entry_default_v19(s);
        JsonObject *entry = linux_speed_lab_find_v19(s, "nodes", linux_speed_lab_active_id_v12(s->entry));
        if (strcmp(linux_speed_lab_kind_v19(entry), "router-vpn") != 0) linux_speed_lab_select_v19(s->execution, "local");
        s->updating_choices = FALSE;
    } else {
        if (GTK_WIDGET(changed) == s->topology) {
            const char *top = linux_speed_lab_active_id_v12(s->topology);
            const char *kind = strcmp(top, "external") == 0 ? "external" : "router-vpn";
            JsonObject *node = linux_speed_lab_find_v19(s, "nodes", linux_speed_lab_active_id_v12(s->node));
            if (strcmp(linux_speed_lab_kind_v19(node), kind) != 0) {
                JsonArray *nodes = linux_speed_lab_catalog_v19(s, "nodes");
                s->updating_choices = TRUE;
                gtk_combo_box_set_active(GTK_COMBO_BOX(s->node), -1);
                for (guint i=0; nodes != NULL && i<json_array_get_length(nodes); i++) {
                    JsonObject *candidate = json_array_get_object_element(nodes, i);
                    if (strcmp(linux_speed_lab_kind_v19(candidate), kind) == 0) { linux_speed_lab_select_v19(s->node, obj_string(candidate, "id")); break; }
                }
                s->updating_choices = FALSE;
            }
        }
        linux_speed_lab_defaults_v19(s);
    }
    linux_speed_lab_refresh_controls_v12(NULL, s);
}

static gboolean linux_speed_lab_server_ready_v19(JsonObject *node) {
    if (!linux_speed_lab_flag_v19(node, "has_response_probe")) return FALSE;
    const char *protocol = obj_string(node, "external_protocol");
    if (strcmp(protocol, "wireguard") == 0 || strcmp(protocol, "amneziawg") == 0) return linux_speed_lab_flag_v19(node, "has_server_peer");
    if (strcmp(protocol, "openvpn") == 0) return linux_speed_lab_flag_v19(node, "has_openvpn_pairing");
    return strcmp(protocol, "shadowsocks") == 0 || strcmp(protocol, "hysteria2") == 0 || strcmp(protocol, "socks5") == 0 || strcmp(protocol, "http-connect") == 0 || strcmp(protocol, "https-connect") == 0;
}

static const char *linux_speed_lab_path_error_v19(LinuxSpeedLabV12 *s) {
    if (strcmp(linux_speed_lab_active_id_v12(s->scope), "current") == 0) return NULL;
    const char *top = linux_speed_lab_active_id_v12(s->topology);
    if (strcmp(top, "system-direct") == 0) return NULL;
    JsonObject *node = linux_speed_lab_find_v19(s, "nodes", linux_speed_lab_active_id_v12(s->node));
    JsonObject *entry = linux_speed_lab_find_v19(s, "nodes", linux_speed_lab_active_id_v12(s->entry));
    const char *execution = linux_speed_lab_active_id_v12(s->execution);
    if (strcmp(top, "router") == 0) return strcmp(linux_speed_lab_kind_v19(node), "router-vpn") == 0 ? NULL : "Select a linked Router VPN node.";
    if (strcmp(top, "multihop") == 0) {
        JsonObject *exit = linux_speed_lab_find_v19(s, "nodes", linux_speed_lab_active_id_v12(s->exit));
        if (strcmp(linux_speed_lab_kind_v19(entry), "router-vpn") != 0 || strcmp(linux_speed_lab_kind_v19(exit), "router-vpn") != 0 || entry == exit) return "Select two different linked Router VPN nodes.";
    } else if (strcmp(top, "external") == 0) {
        if (strcmp(linux_speed_lab_kind_v19(node), "external") != 0) return "Select a linked external exit.";
        const char *entryID = linux_speed_lab_active_id_v12(s->entry);
        if (entryID[0] != '\0' && (entry == NULL || entry == node)) return "Select a different linked entry, or Direct.";
        if (strcmp(linux_speed_lab_kind_v19(entry), "router-vpn") == 0) {
            if (linux_speed_lab_find_v19(s, "router_vpn_entry_modes", linux_speed_lab_active_id_v12(s->entry_mode)) == NULL) return "Select a supported Router entry mode.";
            if (strcmp(execution, "local") != 0 && !linux_speed_lab_server_ready_v19(node)) return "Server/Compare requires this exit's response probe and independent server pairing where required.";
        } else if (strcmp(execution, "local") != 0) return "Direct and ordinary external entry paths use Local execution.";
    } else return "Select a supported test topology.";
    if (strcmp(execution, "local") != 0 && strcmp(execution, "server") != 0 && strcmp(execution, "auto") != 0) return "Select Local, Server, or Compare both.";
    if (linux_speed_lab_find_v19(s, "execution_choices", execution) == NULL) return "Execution capabilities changed; reload Speed Lab.";
    return NULL;
}
