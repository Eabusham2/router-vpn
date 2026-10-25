/* Short, captured settings transactions. The controller validates the actual
 * native transport and repeats the idle/source checks under its persistence lock. */
typedef struct {
    App *app;
    GtkWidget *dialog, *message, *lan, *kill, *ipv6, *mtu, *manual, *startup, *automatic;
    char *profile, *token, *initial_startup;
    gboolean supported, idle, initial_automatic;
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
    JsonObject *o = json_object_new();
    json_object_set_string_member(o, "profile_id", s->profile);
    json_object_set_string_member(o, "profile_token", s->token);
    json_object_set_boolean_member(o, "home_lan_access", gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(s->lan)));
    json_object_set_string_member(o, "kill_switch_policy", kill);
    json_object_set_string_member(o, "ipv6_mode", ipv6);
    json_object_set_string_member(o, "mtu_policy", mtu);
    json_object_set_int_member(o, "manual_mtu", manual);
    // An unchanged display alias (SMART AUTO -> Saved connection) cannot
    // rewrite the source's startup choice during a device-only edit.
    if (g_strcmp0(startup, s->initial_startup) != 0 || automatic != s->initial_automatic) {
        json_object_set_string_member(o, "startup_mode", startup);
        json_object_set_boolean_member(o, "auto_connect", automatic);
    }
    JsonNode *root = json_node_new(JSON_NODE_OBJECT); json_node_take_object(root, o);
    JsonGenerator *generator = json_generator_new(); json_generator_set_root(generator, root);
    char *body = json_generator_to_data(generator, NULL);
    g_object_unref(generator); json_node_free(root); return body;
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
    if (saved) append_diag(s->app, "Device and startup settings saved for the captured imported node.");
    else linux_device_message_v1(s, error != NULL ? error : "Settings were not saved. Reopen them if the node changed.");
    free(response.data); g_free(error); g_free(body); return saved;
}
static gboolean linux_device_build_v1(LinuxDeviceSettingsV1 *s, App *app, JsonObject *captured, const char *expected) {
    gboolean lan, automatic, supported;
    gint64 manual;
    const char *profile = linux_device_string_v1(captured, "profile_id");
    const char *token = linux_device_string_v1(captured, "profile_token");
    const char *kind = linux_device_string_v1(captured, "node_kind");
    const char *kill = linux_device_string_v1(captured, "kill_switch_policy");
    const char *ipv6 = linux_device_string_v1(captured, "ipv6_mode");
    const char *mtu = linux_device_string_v1(captured, "mtu_policy");
    const char *startup = linux_device_string_v1(captured, "startup_mode");
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
        (g_strcmp0(mtu, "manual") == 0 ? manual < 1280 || manual > 9000 : manual != 0)) return FALSE;
    s->app = app; s->profile = g_strdup(profile); s->token = g_strdup(token);
    s->initial_startup = g_strdup(startup); s->initial_automatic = automatic;
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
    const char *mtu_labels[] = {"Auto measured", "Fixed", "Default"};
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
    s->automatic = gtk_check_button_new_with_label("Auto-connect when Router VPN starts");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(s->automatic), automatic);
    gtk_box_pack_start(GTK_BOX(box), s->automatic, FALSE, FALSE, 0);
    gint64 effective = 0;
    const char *source = linux_device_string_v1(captured, "mtu_source");
    char *history = linux_device_integer_v1(captured, "effective_mtu", &effective) && effective > 0
        ? g_strdup_printf("Last recorded interface MTU: %" G_GINT64_FORMAT "%s%s. Retest the active path for a fresh measurement.", effective, source != NULL && source[0] ? " • " : "", source != NULL ? source : "")
        : g_strdup("No interface MTU has been recorded. Retest is available on the active path.");
    GtkWidget *readback = gtk_label_new(history); g_free(history);
    gtk_label_set_xalign(GTK_LABEL(readback), 0.0f); gtk_label_set_line_wrap(GTK_LABEL(readback), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(readback), 65); gtk_box_pack_start(GTK_BOX(box), readback, FALSE, FALSE, 0);
    s->message = gtk_label_new(NULL); gtk_label_set_xalign(GTK_LABEL(s->message), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(s->message), TRUE); gtk_label_set_max_width_chars(GTK_LABEL(s->message), 65);
    gtk_box_pack_start(GTK_BOX(box), s->message, FALSE, FALSE, 0);
    linux_device_message_v1(s, !supported ? linux_device_string_v1(captured, "device_policy_reason") :
        !s->idle ? "Disconnect before editing these settings." : "Save applies these device and startup choices together. DNS and hop settings are retained.");
    GtkWidget *controls[] = {s->lan, s->kill, s->ipv6, s->mtu, s->startup, s->automatic};
    for (guint i = 0; i < G_N_ELEMENTS(controls); i++) gtk_widget_set_sensitive(controls[i], supported && s->idle);
    gtk_dialog_set_response_sensitive(GTK_DIALOG(s->dialog), GTK_RESPONSE_OK, supported && s->idle);
    g_signal_connect(s->mtu, "changed", G_CALLBACK(linux_device_mtu_changed_v1), s);
    g_signal_connect(s->startup, "changed", G_CALLBACK(linux_device_startup_changed_v1), s);
    linux_device_mtu_changed_v1(GTK_COMBO_BOX(s->mtu), s);
    linux_device_startup_changed_v1(GTK_COMBO_BOX(s->startup), s);
    g_object_set_data(G_OBJECT(s->dialog), "router-vpn-device-settings-v1", s);
    gtk_widget_show_all(s->dialog); return TRUE;
}
static void linux_device_clear_v1(LinuxDeviceSettingsV1 *s) {
    if (s->dialog != NULL) { gtk_widget_destroy(s->dialog); g_object_unref(s->dialog); }
    g_free(s->profile); g_free(s->token); g_free(s->initial_startup); memset(s, 0, sizeof(*s));
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
