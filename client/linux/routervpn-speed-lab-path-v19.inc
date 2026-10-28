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

static const char *linux_speed_lab_main_selection_v19(LinuxSpeedLabV12 *s) {
    if (s->app == NULL || s->app->router_combo == NULL || s->app->router_ids == NULL) return "";
    const char *id = active_router_id(s->app);
    return id != NULL ? id : "";
}

static void linux_speed_lab_capture_selection_v19(LinuxSpeedLabV12 *s) {
    g_clear_pointer(&s->staged_selected, g_free);
    g_clear_pointer(&s->staged_entry, g_free); g_clear_pointer(&s->staged_exit, g_free);
    g_clear_pointer(&s->staged_exit_mode, g_free); g_clear_pointer(&s->staged_execution, g_free);
    g_clear_pointer(&s->staged_entry_mode, g_free);
    g_clear_pointer(&s->captured_profile_tokens, json_object_unref);
    s->staged_selected = g_strdup(linux_speed_lab_main_selection_v19(s));
    linux_profile_selection_v11(&s->staged_multihop, &s->staged_entry, &s->staged_exit, &s->staged_exit_mode, &s->staged_entry_mode);
    s->staged_execution = linux_multihop_execution_choice_v1();
    s->selection_captured = TRUE;
}

static gboolean linux_speed_lab_valid_token_v19(const char *token) {
    if (token == NULL || strlen(token) != 64) return FALSE;
    for (const char *p = token; *p; p++) if (!(*p >= '0' && *p <= '9') && !(*p >= 'a' && *p <= 'f')) return FALSE;
    return TRUE;
}

static const char *linux_speed_lab_selection_error_v19(LinuxSpeedLabV12 *s) {
    const char *changed = "The connection profile changed while Speed Lab was open. Reopen Speed Lab for that selection.";
    if (s->closed || !s->selection_captured || g_strcmp0(s->staged_selected, linux_speed_lab_main_selection_v19(s)) != 0) return changed;
    gboolean enabled = FALSE;
    char *entry = NULL, *exit = NULL, *mode = NULL, *entry_mode = NULL;
    linux_profile_selection_v11(&enabled, &entry, &exit, &mode, &entry_mode);
    char *execution = linux_multihop_execution_choice_v1();
    gboolean same = enabled == s->staged_multihop && (!enabled ||
        (g_strcmp0(entry, s->staged_entry) == 0 && g_strcmp0(exit, s->staged_exit) == 0 &&
         g_strcmp0(mode, s->staged_exit_mode) == 0 && g_strcmp0(execution, s->staged_execution) == 0 &&
         g_strcmp0(entry_mode, s->staged_entry_mode) == 0));
    g_free(entry); g_free(exit); g_free(mode); g_free(execution); g_free(entry_mode);
    if (!same) return changed;
    JsonArray *nodes = linux_speed_lab_catalog_v19(s, "nodes");
    if (nodes == NULL) return "Speed Lab has no captured node catalog. Reopen Speed Lab.";
    guint selected = 0;
    for (guint i = 0; i < json_array_get_length(nodes); i++) {
        JsonObject *node = json_array_get_object_element(nodes, i);
        if (linux_speed_lab_flag_v19(node, "selected")) {
            selected++;
            if (g_strcmp0(obj_string(node, "id"), s->staged_selected) != 0) return changed;
        }
    }
    if (selected != (s->staged_selected[0] ? 1u : 0u) ||
        (s->staged_selected[0] && linux_speed_lab_find_v19(s, "nodes", s->staged_selected) == NULL)) return changed;
    return NULL;
}

static const char *linux_speed_lab_capture_catalog_v19(LinuxSpeedLabV12 *s) {
    const char *error = linux_speed_lab_selection_error_v19(s);
    if (error != NULL) return error;
    JsonArray *nodes = linux_speed_lab_catalog_v19(s, "nodes");
    JsonObject *tokens = json_object_new();
    for (guint i = 0; i < json_array_get_length(nodes); i++) {
        JsonObject *node = json_array_get_object_element(nodes, i);
        const char *id = obj_string(node, "id"), *token = obj_string(node, "profile_token");
        if (!id[0] || json_object_has_member(tokens, id) || !linux_speed_lab_valid_token_v19(token) ||
            (s->captured_profile_tokens != NULL && g_strcmp0(obj_string(s->captured_profile_tokens, id), token) != 0)) {
            json_object_unref(tokens);
            return "A Speed Lab node was removed, relinked, or has no unique source identity. Reopen Speed Lab.";
        }
        json_object_set_string_member(tokens, id, token);
    }
    if (s->captured_profile_tokens == NULL) s->captured_profile_tokens = tokens;
    else json_object_unref(tokens);
    return NULL;
}

static gboolean linux_speed_lab_add_profile_v19(LinuxSpeedLabV12 *s, JsonObject *tokens, const char *id) {
    if (id == NULL || id[0] == '\0') return TRUE;
    JsonObject *node = linux_speed_lab_find_v19(s, "nodes", id);
    const char *token = obj_string(node, "profile_token");
    if (node == NULL || !linux_speed_lab_valid_token_v19(token) ||
        g_strcmp0(obj_string(s->captured_profile_tokens, id), token) != 0) return FALSE;
    if (tokens != NULL) json_object_set_string_member(tokens, id, token);
    return TRUE;
}

static const char *linux_speed_lab_bind_profiles_v19(LinuxSpeedLabV12 *s, JsonObject *tokens) {
    const char *error = linux_speed_lab_selection_error_v19(s);
    if (error != NULL) return error;
    const char *missing = "A captured test node was removed or relinked. Reopen Speed Lab before running this path.";
    if (s->captured_profile_tokens == NULL || !linux_speed_lab_add_profile_v19(s, tokens, s->staged_selected)) return missing;
    JsonObject *selected = linux_speed_lab_find_v19(s, "nodes", s->staged_selected);
    if (s->staged_multihop && strcmp(linux_speed_lab_kind_v19(selected), "router-vpn") == 0 &&
        (!s->staged_entry[0] || !s->staged_exit[0] || !linux_speed_lab_add_profile_v19(s, tokens, s->staged_entry) || !linux_speed_lab_add_profile_v19(s, tokens, s->staged_exit))) return missing;
    if (strcmp(linux_speed_lab_active_id_v12(s->scope), "temporary") == 0) {
        const char *top = linux_speed_lab_active_id_v12(s->topology);
        if ((strcmp(top, "router") == 0 || strcmp(top, "external") == 0) && !linux_speed_lab_add_profile_v19(s, tokens, linux_speed_lab_active_id_v12(s->node))) return missing;
        if ((strcmp(top, "multihop") == 0 || strcmp(top, "external") == 0) && !linux_speed_lab_add_profile_v19(s, tokens, linux_speed_lab_active_id_v12(s->entry))) return missing;
        if (strcmp(top, "multihop") == 0 && !linux_speed_lab_add_profile_v19(s, tokens, linux_speed_lab_active_id_v12(s->exit))) return missing;
    } else {
        JsonNode *current_node = json_object_get_member(json_node_get_object(s->options), "current");
        JsonObject *current = current_node != NULL && JSON_NODE_HOLDS_OBJECT(current_node) ? json_node_get_object(current_node) : NULL;
        if (linux_speed_lab_flag_v19(current, "connected") &&
            (!obj_string(current, "router_id")[0] || !linux_speed_lab_add_profile_v19(s, tokens, obj_string(current, "router_id")) ||
             !linux_speed_lab_add_profile_v19(s, tokens, obj_string(current, "entry_id")) || !linux_speed_lab_add_profile_v19(s, tokens, obj_string(current, "exit_id")))) return missing;
    }
    return NULL;
}

static void linux_speed_lab_select_v19(GtkWidget *combo, const char *id) {
    /* Keep an unavailable saved identity visible. Run rejects it until the user
     * deliberately chooses a current node/mode; it never becomes Direct/WG. */
    if (id == NULL) id = "";
    if (!gtk_combo_box_set_active_id(GTK_COMBO_BOX(combo), id)) {
        char *label = g_strdup_printf("Unavailable saved choice: %s", id);
        gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo), id, label); g_free(label);
        gtk_combo_box_set_active_id(GTK_COMBO_BOX(combo), id);
    }
}

static void linux_speed_lab_fill_entry_modes_v23(LinuxSpeedLabV12 *s, const char *selected) {
    if (strcmp(linux_speed_lab_active_id_v12(s->topology), "multihop") == 0) {
        linux_multihop_entry_choices_v23(s->entry_mode, linux_speed_lab_catalog_v19(s, "supported_entry_modes"), selected);
        return;
    }
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(s->entry_mode));
    JsonArray *modes = linux_speed_lab_catalog_v19(s, "router_vpn_entry_modes");
    for (guint i = 0; modes != NULL && i < json_array_get_length(modes); i++) {
        JsonObject *mode = json_array_get_object_element(modes, i);
        const char *id = obj_string(mode, "id"), *name = obj_string(mode, "name");
        if (id[0]) gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(s->entry_mode), id, name[0] ? name : id);
    }
    linux_speed_lab_select_v19(s->entry_mode, selected);
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
    if (strcmp(linux_speed_lab_active_id_v12(s->topology), "multihop") == 0) {
        linux_speed_lab_fill_entry_modes_v23(s, mode);
        return;
    }
    if (mode[0] == '\0') {
        const char *base=obj_string(entry,"base_tunnel");
        if(strcmp(base,"wg")!=0&&strcmp(base,"awg")!=0&&node!=NULL)base=obj_string(node,"base_tunnel");
        mode=strcmp(base,"awg")==0?"awg2-fast":"wg";
    }
    linux_speed_lab_fill_entry_modes_v23(s, mode);
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
        linux_speed_lab_entry_default_v19(s);
        JsonNode *current_node = json_object_get_member(json_node_get_object(s->options), "current");
        JsonObject *current = current_node != NULL && JSON_NODE_HOLDS_OBJECT(current_node) ? json_node_get_object(current_node) : NULL;
        if (linux_speed_lab_flag_v19(current, "connected") && g_strcmp0(obj_string(current, "mode"), "multihop") == 0 &&
            g_strcmp0(obj_string(current, "entry_id"), linux_speed_lab_active_id_v12(s->entry)) == 0 &&
            g_strcmp0(obj_string(current, "exit_id"), linux_speed_lab_active_id_v12(s->exit)) == 0) {
            linux_speed_lab_select_v19(s->exit_mode, obj_string(current, "exit_mode"));
            if (obj_string(current, "entry_mode")[0]) linux_speed_lab_fill_entry_modes_v23(s, obj_string(current, "entry_mode"));
            if (obj_string(current, "execution")[0]) linux_speed_lab_select_v19(s->execution, obj_string(current, "execution"));
        }
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

static gboolean linux_speed_lab_server_ready_v19(JsonObject *node, const char *execution) {
    const char *protocol = obj_string(node, "external_protocol");
    if (strcmp(protocol, "tor") == 0 || strcmp(protocol, "tor-bridge") == 0) {
        if (strcmp(execution, "auto") == 0) return linux_speed_lab_flag_v19(node, "tor_compare_execution") && linux_speed_lab_flag_v19(node, "tor_compare_requires_paired_source");
        return strcmp(execution, "server") == 0 && linux_speed_lab_flag_v19(node, "tor_server_execution");
    }
    if (!linux_speed_lab_flag_v19(node, "has_response_probe")) return FALSE;
    if (strcmp(protocol, "wireguard") == 0 || strcmp(protocol, "amneziawg") == 0) return linux_speed_lab_flag_v19(node, "has_server_peer");
    if (strcmp(protocol, "openvpn") == 0) return linux_speed_lab_flag_v19(node, "has_openvpn_pairing");
    return strcmp(protocol, "shadowsocks") == 0 || strcmp(protocol, "hysteria2") == 0 || strcmp(protocol, "socks5") == 0 || strcmp(protocol, "http-connect") == 0 || strcmp(protocol, "https-connect") == 0;
}

static gboolean linux_speed_lab_tor_compare_request_v19(LinuxSpeedLabV12 *s, const char *body) {
    g_autoptr(JsonNode) raw = body != NULL ? parse_json(body) : NULL;
    if (raw == NULL || !JSON_NODE_HOLDS_OBJECT(raw)) return FALSE;
    JsonObject *request = json_node_get_object(raw);
    if (strcmp(obj_string(request, "scope"), "temporary") != 0 || strcmp(obj_string(request, "topology"), "external") != 0 || strcmp(obj_string(request, "execution"), "auto") != 0) return FALSE;
    JsonObject *node = linux_speed_lab_find_v19(s, "nodes", obj_string(request, "node_id"));
    const char *protocol = obj_string(node, "external_protocol");
    return strcmp(protocol, "tor") == 0 || strcmp(protocol, "tor-bridge") == 0;
}

static long linux_speed_lab_request_timeout_v19(LinuxSpeedLabV12 *s, const char *body) {
    if (linux_speed_lab_tor_compare_request_v19(s, body)) return 960000L;
    g_autoptr(JsonNode) raw = body != NULL ? parse_json(body) : NULL;
    JsonObject *request = raw != NULL && JSON_NODE_HOLDS_OBJECT(raw) ? json_node_get_object(raw) : NULL;
    if (strcmp(obj_string(request, "duration_mode"), "custom") == 0)
        return MAX(90000L, (long)(json_object_get_double_member(request, "max_seconds") * 2000.0 + 80000.0));
    return 110000L;
}

static const char *linux_speed_lab_path_error_v19(LinuxSpeedLabV12 *s) {
    const char *capture_error = linux_speed_lab_bind_profiles_v19(s, NULL);
    if (capture_error != NULL) return capture_error;
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
        if (!linux_multihop_exit_advertised_v22(linux_speed_lab_catalog_v19(s, "supported_exit_modes"), linux_speed_lab_active_id_v12(s->exit_mode))) return "Select an exit transport supported by this controller; an unavailable saved choice is never replaced automatically.";
        if (!linux_multihop_entry_advertised_v23(linux_speed_lab_catalog_v19(s, "supported_entry_modes"), gtk_combo_box_get_active_id(GTK_COMBO_BOX(s->entry_mode)))) return "Select an entry transport supported by this controller; an unavailable saved choice is never replaced automatically.";
    } else if (strcmp(top, "external") == 0) {
        if (strcmp(linux_speed_lab_kind_v19(node), "external") != 0) return "Select a linked external exit.";
        const char *entryID = linux_speed_lab_active_id_v12(s->entry);
        if (entryID[0] != '\0' && (entry == NULL || entry == node)) return "Select a different linked entry, or Direct.";
        if (strcmp(linux_speed_lab_kind_v19(entry), "router-vpn") == 0) {
            if (linux_speed_lab_find_v19(s, "router_vpn_entry_modes", linux_speed_lab_active_id_v12(s->entry_mode)) == NULL) return "Select a supported Router entry mode.";
            const char *protocol = obj_string(node, "external_protocol");
            if (strcmp(execution, "local") != 0 && (strcmp(protocol, "tor") == 0 || strcmp(protocol, "tor-bridge") == 0) &&
                (obj_string(entry, "external_protocol")[0] || json_object_has_member(entry, "external"))) return "Tor Server/Compare requires a private Router entry source.";
            if (strcmp(execution, "local") != 0 && !linux_speed_lab_server_ready_v19(node, execution)) return "Tor Server/Compare requires advertised native support and a paired private Router entry. Other exits require their response probe and separate server pairing.";
        } else if (strcmp(execution, "local") != 0) return "Direct and ordinary external entry paths use Local execution.";
    } else return "Select a supported test topology.";
    if (strcmp(execution, "local") != 0 && strcmp(execution, "server") != 0 && strcmp(execution, "auto") != 0) return "Select Local, Server, or Compare both.";
    if (linux_speed_lab_find_v19(s, "execution_choices", execution) == NULL) return "Execution capabilities changed; reload Speed Lab.";
    return NULL;
}
