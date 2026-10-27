/* Short, captured settings transactions. The controller validates the actual
 * native transport and repeats the idle/source checks under its persistence lock. */
typedef struct {
    App *app;
    GtkWidget *dialog, *message, *lan, *kill, *ipv6, *mtu, *manual, *jumbo, *startup, *automatic;
    GtkWidget *cover, *cover_rate;
    char *profile, *token, *initial_startup, *original_startup;
    gboolean supported, idle, initial_automatic;
    gboolean jumbo_known, jumbo_supported, initial_jumbo;
    gboolean cover_known, cover_supported, initial_cover;
    gint64 initial_cover_rate;
} LinuxDeviceSettingsV1;

static const char *linux_device_string_v1(JsonObject *o, const char *name) {
    JsonNode *n = o != NULL ? json_object_get_member(o, name) : NULL;
    return n != NULL && JSON_NODE_HOLDS_VALUE(n) && json_node_get_value_type(n) == G_TYPE_STRING
        ? json_node_get_string(n) : NULL;
}
static gboolean linux_device_bool_v1(JsonObject *o, const char *name, gboolean *out) {
    JsonNode *n = o != NULL ? json_object_get_member(o, name) : NULL;
    if (n == NULL || !JSON_NODE_HOLDS_VALUE(n) || json_node_get_value_type(n) != G_TYPE_BOOLEAN) return FALSE;
    *out = json_node_get_boolean(n); return TRUE;
}
static gboolean linux_device_integer_v1(JsonObject *o, const char *name, gint64 *out) {
    JsonNode *n = o != NULL ? json_object_get_member(o, name) : NULL;
    if (n == NULL || !JSON_NODE_HOLDS_VALUE(n) || json_node_get_value_type(n) != G_TYPE_INT64) return FALSE;
    *out = json_node_get_int(n); return TRUE;
}
static gboolean linux_device_choice_v1(const char *value, const char *const *ids, guint count) {
    for (guint i = 0; i < count; i++) if (g_strcmp0(value, ids[i]) == 0) return TRUE;
    return FALSE;
}
static gboolean linux_device_token_v1(const char *value) {
    if (value == NULL || strlen(value) != 64) return FALSE;
    for (guint i = 0; i < 64; i++) if (!g_ascii_isdigit(value[i]) && !(value[i] >= 'a' && value[i] <= 'f')) return FALSE;
    return TRUE;
}
static const char *const linux_device_kill_ids_v1[] = {"off", "on-connect", "always"};
static const char *const linux_device_ipv6_ids_v1[] = {"on", "off", "auto"};
static const char *const linux_device_mtu_ids_v1[] = {"auto", "manual", "default"};
static const char *const linux_device_startup_ids_v1[] = {"auto", "last", "manual"};

static void linux_device_message_v1(LinuxDeviceSettingsV1 *s, const char *message) {
    gtk_label_set_text(GTK_LABEL(s->message), message != NULL ? message : "Settings could not be saved.");
}
static GtkWidget *linux_device_combo_v1(const char *const *ids, const char *const *labels, guint count, const char *selected) {
    GtkWidget *combo = gtk_combo_box_text_new();
    for (guint i = 0; i < count; i++) gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo), ids[i], labels[i]);
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(combo), selected);
    return combo;
}
static void linux_device_row_v1(GtkWidget *grid, int row, const char *label, GtkWidget *control) {
    GtkWidget *text = gtk_label_new(label);
    gtk_label_set_xalign(GTK_LABEL(text), 0.0f);
    gtk_widget_set_hexpand(control, TRUE);
    gtk_grid_attach(GTK_GRID(grid), text, 0, row, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), control, 1, row, 1, 1);
}
static void linux_device_mtu_changed_v1(GtkComboBox *combo, gpointer data) {
    LinuxDeviceSettingsV1 *s = data;
    gtk_widget_set_sensitive(s->manual, s->supported && s->idle &&
        g_strcmp0(gtk_combo_box_get_active_id(combo), "manual") == 0);
}
static void linux_device_startup_changed_v1(GtkComboBox *combo, gpointer data) {
    LinuxDeviceSettingsV1 *s = data;
    gboolean manual = g_strcmp0(gtk_combo_box_get_active_id(combo), "manual") == 0;
    if (manual) gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(s->automatic), FALSE);
    gtk_widget_set_sensitive(s->automatic, s->supported && s->idle && !manual);
}
static gboolean linux_device_fixed_v1(const char *text, gint64 *value) {
    if (text == NULL || !text[0] || strlen(text) > 4) return FALSE;
    for (const char *p = text; *p; p++) if (!g_ascii_isdigit(*p)) return FALSE;
    *value = g_ascii_strtoll(text, NULL, 10);
    return *value >= 1280 && *value <= 9000;
}
static gboolean linux_device_cover_rate_v1(const char *text, gint64 *value) {
    if (text == NULL || !text[0] || strlen(text) > 3) return FALSE;
    for (const char *p = text; *p; p++) if (!g_ascii_isdigit(*p)) return FALSE;
    *value = g_ascii_strtoll(text, NULL, 10);
    return *value == 0 || (*value >= 32 && *value <= 192);
}
static gboolean linux_device_cover_capture_v1(JsonObject *o, gboolean *known, gboolean *enabled, gint64 *rate, gboolean *supported) {
    gboolean has_enabled = o != NULL && json_object_has_member(o, "daita_enabled");
    gboolean has_rate = o != NULL && json_object_has_member(o, "daita_rate_kbps");
    gboolean has_support = o != NULL && json_object_has_member(o, "tor_cover_supported");
    *known = has_enabled;
    if (!has_enabled && !has_rate && !has_support) return TRUE;
    if (!has_enabled || !has_rate || !has_support ||
        !linux_device_bool_v1(o, "daita_enabled", enabled) || !linux_device_integer_v1(o, "daita_rate_kbps", rate) ||
        !linux_device_bool_v1(o, "tor_cover_supported", supported) || (*rate != 0 && (*rate < 32 || *rate > 192))) return FALSE;
    const char *protocol = linux_device_string_v1(o, "protocol");
    gboolean device = FALSE;
    return !*supported || ((g_strcmp0(protocol, "tor") == 0 || g_strcmp0(protocol, "tor-bridge") == 0) &&
        linux_device_bool_v1(o, "device_policy_supported", &device) && device);
}
static char *linux_device_payload_v1(LinuxDeviceSettingsV1 *s) {
    const char *kill = gtk_combo_box_get_active_id(GTK_COMBO_BOX(s->kill));
    const char *ipv6 = gtk_combo_box_get_active_id(GTK_COMBO_BOX(s->ipv6));
    const char *mtu = gtk_combo_box_get_active_id(GTK_COMBO_BOX(s->mtu));
    const char *startup = gtk_combo_box_get_active_id(GTK_COMBO_BOX(s->startup));
    if (s->profile == NULL || !s->profile[0] || !linux_device_token_v1(s->token) ||
        !linux_device_choice_v1(kill, linux_device_kill_ids_v1, G_N_ELEMENTS(linux_device_kill_ids_v1)) ||
        !linux_device_choice_v1(ipv6, linux_device_ipv6_ids_v1, G_N_ELEMENTS(linux_device_ipv6_ids_v1)) ||
        !linux_device_choice_v1(mtu, linux_device_mtu_ids_v1, G_N_ELEMENTS(linux_device_mtu_ids_v1)) ||
        !linux_device_choice_v1(startup, linux_device_startup_ids_v1, G_N_ELEMENTS(linux_device_startup_ids_v1))) {
        linux_device_message_v1(s, "Reopen Settings to capture the selected node and its saved policy."); return NULL;
    }
    gint64 manual = 0;
    if (g_strcmp0(mtu, "manual") == 0 && !linux_device_fixed_v1(gtk_entry_get_text(GTK_ENTRY(s->manual)), &manual)) {
        linux_device_message_v1(s, "Fixed MTU must be a whole number from 1280 to 9000. The selected transport must also support it."); return NULL;
    }
    gboolean automatic = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(s->automatic));
    if (g_strcmp0(startup, "manual") == 0 && automatic) {
        linux_device_message_v1(s, "Manual startup must remain disconnected."); return NULL;
    }
    gboolean jumbo = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(s->jumbo));
    gboolean jumbo_changed = jumbo != s->initial_jumbo;
    if (jumbo_changed && (!s->jumbo_known || !s->jumbo_supported)) {
        linux_device_message_v1(s, "This captured native runtime cannot change Jumbo."); return NULL;
    }
    if (jumbo && g_strcmp0(mtu, "manual") == 0 && manual != 9000) {
        linux_device_message_v1(s, "Jumbo uses a 9000-byte virtual interface. Choose Fixed 9000 or disable Jumbo; no MTU choice was changed."); return NULL;
    }
    gboolean cover = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(s->cover));
    gint64 cover_rate = 0;
    if (!linux_device_cover_rate_v1(gtk_entry_get_text(GTK_ENTRY(s->cover_rate)), &cover_rate)) {
        linux_device_message_v1(s, "Outgoing Tor cover budget must be a whole number: 0 or 32–192 kbit/s."); return NULL;
    }
    gboolean cover_changed = cover != s->initial_cover || cover_rate != s->initial_cover_rate;
    if (cover_changed && (!s->cover_known || !s->cover_supported)) {
        linux_device_message_v1(s, "This captured path cannot change outgoing Tor cover traffic. Use a saved Server path through a private Router entry."); return NULL;
    }
    JsonObject *o = json_object_new();
    json_object_set_string_member(o, "profile_id", s->profile);
    json_object_set_string_member(o, "profile_token", s->token);
    json_object_set_boolean_member(o, "home_lan_access", gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(s->lan)));
    json_object_set_string_member(o, "kill_switch_policy", kill);
    json_object_set_string_member(o, "ipv6_mode", ipv6);
    json_object_set_string_member(o, "mtu_policy", mtu);
    json_object_set_int_member(o, "manual_mtu", manual);
    if (jumbo_changed) json_object_set_boolean_member(o, "jumbo_tun", jumbo);
    if (cover_changed) {
        json_object_set_boolean_member(o, "daita_enabled", cover);
        json_object_set_int_member(o, "daita_rate_kbps", cover_rate);
    }
    // An unchanged display alias (SMART AUTO -> Saved connection) cannot
    // rewrite the source's startup choice during a device-only edit.
    if (g_strcmp0(startup, s->initial_startup) != 0 || automatic != s->initial_automatic) {
        json_object_set_string_member(o, "startup_mode", g_strcmp0(startup, s->initial_startup) == 0 ? s->original_startup : startup);
        json_object_set_boolean_member(o, "auto_connect", automatic);
    }
    JsonNode *root = json_node_new(JSON_NODE_OBJECT); json_node_take_object(root, o);
    JsonGenerator *generator = json_generator_new(); json_generator_set_root(generator, root);
    char *body = json_generator_to_data(generator, NULL);
    g_object_unref(generator); json_node_free(root); return body;
}
static gboolean linux_device_confirm_v1(LinuxDeviceSettingsV1 *s, const char *body, const char *response) {
    JsonNode *sent = body != NULL ? parse_json(body) : NULL;
    JsonNode *received = response != NULL ? parse_json(response) : NULL;
    JsonObject *request = sent != NULL && JSON_NODE_HOLDS_OBJECT(sent) ? json_node_get_object(sent) : NULL;
    JsonObject *saved = received != NULL && JSON_NODE_HOLDS_OBJECT(received) ? json_node_get_object(received) : NULL;
    gboolean supported = FALSE, automatic = FALSE, jumbo = FALSE, jumbo_supported = FALSE;
    gboolean valid = request != NULL && saved != NULL &&
        g_strcmp0(linux_device_string_v1(saved, "profile_id"), s->profile) == 0 &&
        g_strcmp0(linux_device_string_v1(saved, "node_kind"), "external") == 0 &&
        linux_device_token_v1(linux_device_string_v1(saved, "profile_token")) &&
        linux_device_bool_v1(saved, "device_policy_supported", &supported) && supported;
    if (valid) {
        GList *members = json_object_get_members(request);
        for (GList *item = members; item != NULL; item = item->next) {
            const char *key = item->data;
            if (g_strcmp0(key, "profile_token") == 0) continue;
            JsonNode *wanted = json_object_get_member(request, key), *actual = json_object_get_member(saved, key);
            if (actual == NULL || !JSON_NODE_HOLDS_VALUE(actual) ||
                json_node_get_value_type(wanted) != json_node_get_value_type(actual) || !json_node_equal(wanted, actual)) valid = FALSE;
        }
        g_list_free(members);
        if (!json_object_has_member(request, "startup_mode") &&
            g_strcmp0(linux_device_string_v1(saved, "startup_mode"), s->original_startup) != 0) valid = FALSE;
        if (!json_object_has_member(request, "auto_connect") &&
            (!linux_device_bool_v1(saved, "auto_connect", &automatic) || automatic != s->initial_automatic)) valid = FALSE;
        gboolean has_jumbo = json_object_has_member(saved, "jumbo_tun"), has_support = json_object_has_member(saved, "jumbo_tun_supported");
        if (has_jumbo != has_support || (has_jumbo &&
            (!linux_device_bool_v1(saved, "jumbo_tun", &jumbo) || !linux_device_bool_v1(saved, "jumbo_tun_supported", &jumbo_supported)))) valid = FALSE;
        if (s->jumbo_known && (!has_jumbo || (!json_object_has_member(request, "jumbo_tun") && jumbo != s->initial_jumbo))) valid = FALSE;
        if (json_object_has_member(request, "jumbo_tun") && !jumbo_supported) valid = FALSE;
        gboolean cover_known = FALSE, cover = FALSE, cover_supported = FALSE;
        gint64 cover_rate = 0;
        if (!linux_device_cover_capture_v1(saved, &cover_known, &cover, &cover_rate, &cover_supported)) valid = FALSE;
        if (s->cover_known && (!cover_known || (!json_object_has_member(request, "daita_enabled") &&
            (cover != s->initial_cover || cover_rate != s->initial_cover_rate)))) valid = FALSE;
        if (json_object_has_member(request, "daita_enabled") && !cover_supported) valid = FALSE;
    }
    if (sent != NULL) json_node_free(sent);
    if (received != NULL) json_node_free(received);
    return valid;
}
static gboolean linux_device_save_v1(LinuxDeviceSettingsV1 *s) {
    if (!s->supported || !s->idle) {
        linux_device_message_v1(s, "These device settings cannot be changed in this connection state."); return FALSE;
    }
    if (g_strcmp0(active_router_id(s->app), s->profile) != 0) {
        linux_device_message_v1(s, "The selected node changed. Close and reopen Settings."); return FALSE;
    }
    if (!routervpn_require_mutation_idle(s->app, "saving imported-node device settings")) {
        linux_device_message_v1(s, "Disconnect and wait for pending work to finish before saving."); return FALSE;
    }
    char *body = linux_device_payload_v1(s);
    if (body == NULL) return FALSE;
    Buffer response = {0}; char *error = NULL;
    gboolean saved = api_request("/api/profile/device", "POST", body, 8000, &response, &error);
    if (saved && !linux_device_confirm_v1(s, body, response.data)) {
        saved = FALSE;
        g_free(error); error = g_strdup("The controller did not confirm the captured settings. Refresh Settings before retrying.");
    }
    if (saved) append_diag(s->app, "Device and startup settings saved for the captured imported node.");
    else linux_device_message_v1(s, error != NULL ? error : "Settings were not saved. Reopen them if the node changed.");
    free(response.data); g_free(error); g_free(body); return saved;
}
static gboolean linux_device_build_v1(LinuxDeviceSettingsV1 *s, App *app, JsonObject *captured, const char *expected) {
    gboolean lan, automatic, supported, jumbo = FALSE, jumbo_supported = FALSE;
    gboolean cover_known = FALSE, cover = FALSE, cover_supported = FALSE;
    gint64 cover_rate = 0;
    gint64 manual;
    const char *profile = linux_device_string_v1(captured, "profile_id");
    const char *token = linux_device_string_v1(captured, "profile_token");
    const char *kind = linux_device_string_v1(captured, "node_kind");
    const char *kill = linux_device_string_v1(captured, "kill_switch_policy");
    const char *ipv6 = linux_device_string_v1(captured, "ipv6_mode");
    const char *mtu = linux_device_string_v1(captured, "mtu_policy");
    const char *startup = linux_device_string_v1(captured, "startup_mode");
    const char *original_startup = startup;
    gboolean has_jumbo = captured != NULL && json_object_has_member(captured, "jumbo_tun");
    gboolean has_jumbo_support = captured != NULL && json_object_has_member(captured, "jumbo_tun_supported");
    if (g_strcmp0(startup, "smart-auto") == 0) startup = "auto";
    if (expected == NULL || !expected[0] || g_strcmp0(profile, expected) != 0 ||
        g_strcmp0(active_router_id(app), expected) != 0 || g_strcmp0(kind, "external") != 0 || !linux_device_token_v1(token) ||
        !linux_device_bool_v1(captured, "home_lan_access", &lan) ||
        !linux_device_bool_v1(captured, "auto_connect", &automatic) ||
        !linux_device_bool_v1(captured, "device_policy_supported", &supported) ||
        !linux_device_integer_v1(captured, "manual_mtu", &manual) ||
        !linux_device_choice_v1(kill, linux_device_kill_ids_v1, G_N_ELEMENTS(linux_device_kill_ids_v1)) ||
        !linux_device_choice_v1(ipv6, linux_device_ipv6_ids_v1, G_N_ELEMENTS(linux_device_ipv6_ids_v1)) ||
        !linux_device_choice_v1(mtu, linux_device_mtu_ids_v1, G_N_ELEMENTS(linux_device_mtu_ids_v1)) ||
        !linux_device_choice_v1(startup, linux_device_startup_ids_v1, G_N_ELEMENTS(linux_device_startup_ids_v1)) ||
        (g_strcmp0(mtu, "manual") == 0 ? manual < 1280 || manual > 9000 : manual != 0) ||
        has_jumbo != has_jumbo_support || (has_jumbo &&
        (!linux_device_bool_v1(captured, "jumbo_tun", &jumbo) || !linux_device_bool_v1(captured, "jumbo_tun_supported", &jumbo_supported))) ||
        !linux_device_cover_capture_v1(captured, &cover_known, &cover, &cover_rate, &cover_supported)) return FALSE;
    s->app = app; s->profile = g_strdup(profile); s->token = g_strdup(token);
    s->initial_startup = g_strdup(startup); s->initial_automatic = automatic;
    s->original_startup = g_strdup(original_startup);
    s->jumbo_known = has_jumbo; s->jumbo_supported = jumbo_supported; s->initial_jumbo = jumbo;
    s->cover_known = cover_known; s->cover_supported = cover_supported; s->initial_cover = cover; s->initial_cover_rate = cover_rate;
    s->supported = supported; s->idle = !routervpn_mutation_busy(app);
    s->dialog = gtk_dialog_new_with_buttons("Imported node settings", GTK_WINDOW(app->window),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT, "Cancel", GTK_RESPONSE_CANCEL,
        "Save for next connection", GTK_RESPONSE_OK, NULL);
    g_object_ref_sink(s->dialog);
    gtk_window_set_default_size(GTK_WINDOW(s->dialog), 620, 520);
    GtkWidget *box = gtk_dialog_get_content_area(GTK_DIALOG(s->dialog));
    gtk_container_set_border_width(GTK_CONTAINER(box), 18);
    gtk_box_set_spacing(GTK_BOX(box), 12);
    char *heading = g_strdup_printf("Node: %s", s->profile);
    GtkWidget *identity = gtk_label_new(heading); g_free(heading);
    gtk_label_set_xalign(GTK_LABEL(identity), 0.0f); gtk_label_set_line_wrap(GTK_LABEL(identity), TRUE);
    gtk_box_pack_start(GTK_BOX(box), identity, FALSE, FALSE, 0);
    GtkWidget *grid = gtk_grid_new(); gtk_grid_set_row_spacing(GTK_GRID(grid), 10); gtk_grid_set_column_spacing(GTK_GRID(grid), 18);
    gtk_box_pack_start(GTK_BOX(box), grid, FALSE, FALSE, 0);
    s->lan = gtk_check_button_new_with_label("Allow home LAN access");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(s->lan), lan);
    gtk_grid_attach(GTK_GRID(grid), s->lan, 0, 0, 2, 1);
    const char *kill_labels[] = {"Off", "On connect", "Always / strict"};
    const char *ipv6_labels[] = {"On", "Off", "Auto"};
    const char *mtu_labels[] = {"Auto", "Fixed", "Default"};
    const char *startup_labels[] = {"Saved connection", "Last proven connection", "Manual / stay disconnected"};
    s->kill = linux_device_combo_v1(linux_device_kill_ids_v1, kill_labels, G_N_ELEMENTS(kill_labels), kill);
    s->ipv6 = linux_device_combo_v1(linux_device_ipv6_ids_v1, ipv6_labels, G_N_ELEMENTS(ipv6_labels), ipv6);
    s->mtu = linux_device_combo_v1(linux_device_mtu_ids_v1, mtu_labels, G_N_ELEMENTS(mtu_labels), mtu);
    s->manual = gtk_entry_new(); gtk_entry_set_placeholder_text(GTK_ENTRY(s->manual), "1280–9000, subject to transport support");
    if (manual > 0) { char *value = g_strdup_printf("%" G_GINT64_FORMAT, manual); gtk_entry_set_text(GTK_ENTRY(s->manual), value); g_free(value); }
    s->startup = linux_device_combo_v1(linux_device_startup_ids_v1, startup_labels, G_N_ELEMENTS(startup_labels), startup);
    linux_device_row_v1(grid, 1, "Kill switch", s->kill); linux_device_row_v1(grid, 2, "IPv6", s->ipv6);
    linux_device_row_v1(grid, 3, "MTU", s->mtu); linux_device_row_v1(grid, 4, "Fixed MTU", s->manual);
    linux_device_row_v1(grid, 5, "Startup", s->startup);
    s->jumbo = gtk_check_button_new_with_label("Jumbo virtual interface (9000)");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(s->jumbo), jumbo);
    gtk_widget_set_sensitive(s->jumbo, supported && s->idle && jumbo_supported);
    gtk_box_pack_start(GTK_BOX(box), s->jumbo, FALSE, FALSE, 0);
    GtkWidget *cover_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_box_pack_start(GTK_BOX(box), cover_box, FALSE, FALSE, 0);
    s->cover = gtk_check_button_new_with_label("Outgoing Tor cover traffic");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(s->cover), cover);
    gtk_widget_set_sensitive(s->cover, supported && s->idle && cover_supported);
    gtk_box_pack_start(GTK_BOX(cover_box), s->cover, FALSE, FALSE, 0);
    GtkWidget *cover_label = gtk_label_new("Cover budget (kbit/s): 32–192; 0 keeps the default 192");
    gtk_label_set_xalign(GTK_LABEL(cover_label), 0.0f);
    gtk_box_pack_start(GTK_BOX(cover_box), cover_label, FALSE, FALSE, 0);
    s->cover_rate = gtk_entry_new();
    char *rate_text = g_strdup_printf("%" G_GINT64_FORMAT, cover_rate);
    gtk_entry_set_text(GTK_ENTRY(s->cover_rate), rate_text); g_free(rate_text);
    gtk_widget_set_sensitive(s->cover_rate, supported && s->idle && cover_supported);
    gtk_box_pack_start(GTK_BOX(cover_box), s->cover_rate, FALSE, FALSE, 0);
    const char *cover_note = linux_device_string_v1(captured, "tor_cover_note");
    GtkWidget *cover_detail = gtk_label_new(cover_note != NULL ? cover_note : "Outgoing cover is a saved preference. Connect must prove the selected server and its live cover receipt.");
    gtk_label_set_xalign(GTK_LABEL(cover_detail), 0.0f); gtk_label_set_line_wrap(GTK_LABEL(cover_detail), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(cover_detail), 65);
    gtk_box_pack_start(GTK_BOX(cover_box), cover_detail, FALSE, FALSE, 0);
    s->automatic = gtk_check_button_new_with_label("Auto-connect when Router VPN starts");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(s->automatic), automatic);
    gtk_box_pack_start(GTK_BOX(box), s->automatic, FALSE, FALSE, 0);
    gint64 effective = 0;
    const char *source = linux_device_string_v1(captured, "mtu_source");
    char *history = linux_device_integer_v1(captured, "effective_mtu", &effective) && effective > 0
        ? g_strdup_printf("Last recorded interface MTU: %" G_GINT64_FORMAT "%s%s. This is historical interface readback.", effective, source != NULL && source[0] ? " • " : "", source != NULL ? source : "")
        : g_strdup("No interface MTU has been recorded.");
    GtkWidget *readback = gtk_label_new(history); g_free(history);
    gtk_label_set_xalign(GTK_LABEL(readback), 0.0f); gtk_label_set_line_wrap(GTK_LABEL(readback), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(readback), 65); gtk_box_pack_start(GTK_BOX(box), readback, FALSE, FALSE, 0);
    s->message = gtk_label_new(NULL); gtk_label_set_xalign(GTK_LABEL(s->message), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(s->message), TRUE); gtk_label_set_max_width_chars(GTK_LABEL(s->message), 65);
    gtk_box_pack_start(GTK_BOX(box), s->message, FALSE, FALSE, 0);
    const char *note = linux_device_string_v1(captured, "note");
    linux_device_message_v1(s, !supported ? linux_device_string_v1(captured, "device_policy_reason") :
        !s->idle ? "Disconnect before editing these settings." : note != NULL && note[0] ? note :
        "Save applies these device and startup choices together. DNS and hop settings are retained.");
    GtkWidget *controls[] = {s->lan, s->kill, s->ipv6, s->mtu, s->startup, s->automatic};
    for (guint i = 0; i < G_N_ELEMENTS(controls); i++) gtk_widget_set_sensitive(controls[i], supported && s->idle);
    gtk_dialog_set_response_sensitive(GTK_DIALOG(s->dialog), GTK_RESPONSE_OK, supported && s->idle);
    g_signal_connect(s->mtu, "changed", G_CALLBACK(linux_device_mtu_changed_v1), s);
    g_signal_connect(s->startup, "changed", G_CALLBACK(linux_device_startup_changed_v1), s);
    linux_device_mtu_changed_v1(GTK_COMBO_BOX(s->mtu), s);
    linux_device_startup_changed_v1(GTK_COMBO_BOX(s->startup), s);
    g_object_set_data(G_OBJECT(s->dialog), "router-vpn-device-settings-v1", s);
    gtk_widget_show_all(s->dialog);
    const char *protocol = linux_device_string_v1(captured, "protocol");
    if (!cover_known || (g_strcmp0(protocol, "tor") != 0 && g_strcmp0(protocol, "tor-bridge") != 0)) gtk_widget_hide(cover_box);
    return TRUE;
}
static void linux_device_clear_v1(LinuxDeviceSettingsV1 *s) {
    if (s->dialog != NULL) { gtk_widget_destroy(s->dialog); g_object_unref(s->dialog); }
    g_free(s->profile); g_free(s->token); g_free(s->initial_startup); g_free(s->original_startup); memset(s, 0, sizeof(*s));
}
static gboolean linux_device_settings_open_v1(App *app) {
    char *expected = g_strdup(active_router_id(app));
    if (expected == NULL || !expected[0]) { g_free(expected); return FALSE; }
    Buffer out = {0}; char *error = NULL;
    gboolean received = api_request("/api/profile/device", "GET", NULL, 5000, &out, &error);
    gboolean changed = g_strcmp0(active_router_id(app), expected) != 0;
    JsonNode *root = received ? parse_json(out.data) : NULL;
    JsonObject *captured = root != NULL && JSON_NODE_HOLDS_OBJECT(root) ? json_node_get_object(root) : NULL;
    gboolean external = g_strcmp0(linux_device_string_v1(captured, "node_kind"), "external") == 0;
    if (changed || (received && !external)) append_diag(app, "The selected node changed or returned invalid settings. Reopen Settings.");
    else if (external) {
        LinuxDeviceSettingsV1 state = {0};
        if (!linux_device_build_v1(&state, app, captured, expected)) append_diag(app, "The captured device settings are invalid or stale. Reopen Settings.");
        else {
            while (gtk_dialog_run(GTK_DIALOG(state.dialog)) == GTK_RESPONSE_OK) if (linux_device_save_v1(&state)) break;
            linux_device_clear_v1(&state);
        }
    }
    if (root != NULL) json_node_free(root);
    free(out.data); g_free(error); g_free(expected);
    return changed || received;
}
