static GtkWidget *profile_settings_combo_v7(const char *const labels[], const char *const ids[], guint count, const char *selected) {
    GtkWidget *combo = gtk_combo_box_text_new();
    for (guint i = 0; i < count; i++) {
        gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo), ids[i], labels[i]);
    }
    if (!gtk_combo_box_set_active_id(GTK_COMBO_BOX(combo), selected != NULL ? selected : "")) {
        gtk_combo_box_set_active(GTK_COMBO_BOX(combo), 0);
    }
    return combo;
}

static void profile_settings_grid_row_v7(GtkWidget *grid, int row, const char *label, GtkWidget *widget) {
    GtkWidget *l = gtk_label_new(label);
    gtk_label_set_xalign(GTK_LABEL(l), 1.0f);
    gtk_grid_attach(GTK_GRID(grid), l, 0, row, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), widget, 1, row, 1, 1);
}

static void on_profile_settings_v7(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    Buffer out = {0};
    char *err = NULL;
    if (!api_request("/api/profile/settings", "GET", NULL, 5000, &out, &err)) {
        append_diag(app, err != NULL ? err : "Profile settings unavailable");
        g_free(err);
        free(out.data);
        return;
    }

    JsonNode *root = parse_json(out.data);
    if (root == NULL || !JSON_NODE_HOLDS_OBJECT(root)) {
        append_diag(app, "Profile settings returned invalid JSON.");
        if (root != NULL) {
            json_node_free(root);
        }
        g_free(err);
        free(out.data);
        return;
    }
    JsonObject *settings = json_node_get_object(root);

    GtkWidget *dialog = gtk_dialog_new_with_buttons(
        "Router VPN profile settings", GTK_WINDOW(app->window),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "Cancel", GTK_RESPONSE_CANCEL,
        "Save for next connection", GTK_RESPONSE_OK,
        NULL);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 640, 620);
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_vexpand(scroll, TRUE);
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 9);
    gtk_container_set_border_width(GTK_CONTAINER(box), 16);
    GtkWidget *note = gtk_label_new("Disconnect before saving. These are persistent selected-node preferences; unsupported runtime features remain unavailable and saved values are not runtime proof.");
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(note), TRUE);
    gtk_box_pack_start(GTK_BOX(box), note, FALSE, FALSE, 0);
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 7);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
    gtk_box_pack_start(GTK_BOX(box), grid, FALSE, FALSE, 0);

    GtkWidget *lan = gtk_check_button_new_with_label("Allow home LAN access");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(lan), json_object_has_member(settings, "home_lan_access") && json_object_get_boolean_member(settings, "home_lan_access"));
    gtk_box_pack_start(GTK_BOX(box), lan, FALSE, FALSE, 0);

    static const char *const kill_labels[] = {"Off", "On connect", "Always / strict"};
    static const char *const kill_ids[] = {"off", "on-connect", "always"};
    static const char *const ipv6_labels[] = {"Auto", "On", "Off"};
    static const char *const ipv6_ids[] = {"auto", "on", "off"};
    static const char *const base_labels[] = {"Auto", "WireGuard", "AmneziaWG"};
    static const char *const base_ids[] = {"auto", "wg", "awg"};
    static const char *const mtu_labels[] = {"Default", "Auto measured", "Manual"};
    static const char *const mtu_ids[] = {"default", "auto", "manual"};
    static const char *const startup_labels[] = {"Manual", "AUTO", "SMART AUTO", "Last mode"};
    static const char *const startup_ids[] = {"manual", "auto", "smart-auto", "last"};

    GtkWidget *kill = profile_settings_combo_v7(kill_labels, kill_ids, G_N_ELEMENTS(kill_ids), obj_string(settings, "kill_switch_policy"));
    profile_settings_grid_row_v7(grid, 0, "Kill switch", kill);
    GtkWidget *ipv6 = profile_settings_combo_v7(ipv6_labels, ipv6_ids, G_N_ELEMENTS(ipv6_ids), obj_string(settings, "ipv6_mode"));
    profile_settings_grid_row_v7(grid, 1, "IPv6 policy", ipv6);
    GtkWidget *base = profile_settings_combo_v7(base_labels, base_ids, G_N_ELEMENTS(base_ids), obj_string(settings, "base_tunnel"));
    profile_settings_grid_row_v7(grid, 2, "WG/AWG base", base);

    GtkWidget *fallback = gtk_check_button_new_with_label("Allow WG/AWG base fallback");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(fallback), json_object_has_member(settings, "base_fallback") && json_object_get_boolean_member(settings, "base_fallback"));
    gtk_box_pack_start(GTK_BOX(box), fallback, FALSE, FALSE, 0);

    GtkWidget *mtu = profile_settings_combo_v7(mtu_labels, mtu_ids, G_N_ELEMENTS(mtu_ids), obj_string(settings, "mtu_policy"));
    profile_settings_grid_row_v7(grid, 3, "MTU policy", mtu);
    GtkWidget *manual = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(manual), "Manual MTU 576–9000");
    if (json_object_has_member(settings, "manual_mtu")) {
        int current_manual = (int)json_object_get_int_member(settings, "manual_mtu");
        if (current_manual > 0) {
            char tmp[16];
            g_snprintf(tmp, sizeof(tmp), "%d", current_manual);
            gtk_entry_set_text(GTK_ENTRY(manual), tmp);
        }
    }
    profile_settings_grid_row_v7(grid, 4, "Manual MTU", manual);

    GtkWidget *daita = gtk_check_button_new_with_label("DAITA-like bounded cover traffic (supported modes only)");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(daita), json_object_has_member(settings, "daita_enabled") && json_object_get_boolean_member(settings, "daita_enabled"));
    gtk_box_pack_start(GTK_BOX(box), daita, FALSE, FALSE, 0);
    GtkWidget *jumbo = gtk_check_button_new_with_label("Jumbo TUN (compatible TUN/proxy paths only)");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(jumbo), json_object_has_member(settings, "jumbo_tun") && json_object_get_boolean_member(settings, "jumbo_tun"));
    gtk_box_pack_start(GTK_BOX(box), jumbo, FALSE, FALSE, 0);
    GtkWidget *socks = gtk_check_button_new_with_label("Private in-tunnel SOCKS5 utility");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(socks), json_object_has_member(settings, "socks_enabled") && json_object_get_boolean_member(settings, "socks_enabled"));
    gtk_box_pack_start(GTK_BOX(box), socks, FALSE, FALSE, 0);

    GtkWidget *startup = profile_settings_combo_v7(startup_labels, startup_ids, G_N_ELEMENTS(startup_ids), obj_string(settings, "startup_mode"));
    profile_settings_grid_row_v7(grid, 5, "Startup behavior", startup);
    GtkWidget *autoconnect = gtk_check_button_new_with_label("Auto-connect when Router VPN starts");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(autoconnect), json_object_has_member(settings, "auto_connect") && json_object_get_boolean_member(settings, "auto_connect"));
    gtk_box_pack_start(GTK_BOX(box), autoconnect, FALSE, FALSE, 0);

    int effective_mtu = json_object_has_member(settings, "effective_mtu") ? (int)json_object_get_int_member(settings, "effective_mtu") : 0;
    char effective_text[160];
    g_snprintf(effective_text, sizeof(effective_text), "Current effective MTU: %s%d%s%s",
        effective_mtu > 0 ? "" : "default/not measured", effective_mtu > 0 ? effective_mtu : 0,
        effective_mtu > 0 && obj_string(settings, "effective_mtu_source")[0] ? " • " : "",
        effective_mtu > 0 ? obj_string(settings, "effective_mtu_source") : "");
    GtkWidget *effective = gtk_label_new(effective_text);
    gtk_label_set_xalign(GTK_LABEL(effective), 0.0f);
    gtk_box_pack_start(GTK_BOX(box), effective, FALSE, FALSE, 0);

    gtk_container_add(GTK_CONTAINER(scroll), box);
    gtk_box_pack_start(GTK_BOX(content), scroll, TRUE, TRUE, 0);
    gtk_widget_show_all(dialog);

    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_OK) {
        const char *mtu_policy = gtk_combo_box_get_active_id(GTK_COMBO_BOX(mtu));
        int manual_mtu = (int)g_ascii_strtoll(gtk_entry_get_text(GTK_ENTRY(manual)), NULL, 10);
        if (g_strcmp0(mtu_policy, "manual") == 0 && (manual_mtu < 576 || manual_mtu > 9000)) {
            append_diag(app, "Profile settings not saved: manual MTU must be 576–9000.");
        } else {
            if (g_strcmp0(mtu_policy, "manual") != 0) {
                manual_mtu = 0;
            }
            JsonBuilder *builder = json_builder_new();
            json_builder_begin_object(builder);
#define ADD_BOOL(name, value) do { json_builder_set_member_name(builder, name); json_builder_add_boolean_value(builder, value); } while (0)
#define ADD_STR(name, value) do { json_builder_set_member_name(builder, name); json_builder_add_string_value(builder, (value) != NULL ? (value) : ""); } while (0)
            ADD_BOOL("home_lan_access", gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(lan)));
            ADD_STR("kill_switch_policy", gtk_combo_box_get_active_id(GTK_COMBO_BOX(kill)));
            ADD_STR("ipv6_mode", gtk_combo_box_get_active_id(GTK_COMBO_BOX(ipv6)));
            ADD_STR("base_tunnel", gtk_combo_box_get_active_id(GTK_COMBO_BOX(base)));
            ADD_BOOL("base_fallback", gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(fallback)));
            ADD_STR("mtu_policy", mtu_policy);
            json_builder_set_member_name(builder, "manual_mtu");
            json_builder_add_int_value(builder, manual_mtu);
            ADD_BOOL("daita_enabled", gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(daita)));
            ADD_BOOL("jumbo_tun", gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(jumbo)));
            ADD_BOOL("socks_enabled", gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(socks)));
            ADD_STR("startup_mode", gtk_combo_box_get_active_id(GTK_COMBO_BOX(startup)));
            ADD_BOOL("auto_connect", gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(autoconnect)));
#undef ADD_BOOL
#undef ADD_STR
            json_builder_end_object(builder);

            JsonGenerator *gen = json_generator_new();
            JsonNode *payload_root = json_builder_get_root(builder);
            json_generator_set_root(gen, payload_root);
            char *payload = json_generator_to_data(gen, NULL);
            Buffer saved = {0};
            char *save_err = NULL;
            if (api_request("/api/profile/settings", "POST", payload, 8000, &saved, &save_err)) {
                append_diag(app, "Profile settings saved for the next supported connection; saved preferences are not runtime proof.");
            } else {
                append_diag(app, save_err != NULL ? save_err : "Profile settings save failed.");
            }
            free(saved.data);
            g_free(save_err);
            g_free(payload);
            json_node_free(payload_root);
            g_object_unref(gen);
            g_object_unref(builder);
        }
    }

    gtk_widget_destroy(dialog);
    json_node_free(root);
    g_free(err);
    free(out.data);
    refresh_home_summary_v6(app);
}

/* Safe settings contract: /api/profile/settings only; never redacted full-profile POST.
 * LAN Off / kill switch / IPv6 / WG-AWG base+fallback / default-auto-manual MTU /
 * DAITA-like / Jumbo TUN / SOCKS5 / startup/autoconnect.
 */
