typedef struct {
    char *id;
    char *name;
    double latitude;
    double longitude;
    double latency_ms;
    gboolean has_coordinates;
} LinuxMultihopNodeV7;

typedef struct {
    App *app;
    GtkWidget *dialog;
    GtkWidget *map;
    GtkWidget *entry;
    GtkWidget *exit;
    GtkWidget *mode;
    GtkWidget *summary;
    GPtrArray *nodes;
    int pick_role;
} LinuxMultihopDialogV7;

static void linux_multihop_node_free_v7(gpointer data) {
    LinuxMultihopNodeV7 *node = data;
    if (node == NULL) return;
    g_free(node->id);
    g_free(node->name);
    g_free(node);
}

static LinuxMultihopNodeV7 *linux_multihop_find_v7(LinuxMultihopDialogV7 *state, const char *id) {
    if (state == NULL || state->nodes == NULL || id == NULL || id[0] == '\0') return NULL;
    for (guint i = 0; i < state->nodes->len; i++) {
        LinuxMultihopNodeV7 *node = g_ptr_array_index(state->nodes, i);
        if (node != NULL && g_strcmp0(node->id, id) == 0) return node;
    }
    return NULL;
}

static void linux_multihop_map_point_v7(GtkAllocation *allocation, LinuxMultihopNodeV7 *node, double *x, double *y) {
    *x = (node->longitude + 180.0) / 360.0 * allocation->width;
    *y = (90.0 - node->latitude) / 180.0 * allocation->height;
}

static gboolean linux_multihop_draw_v7(GtkWidget *widget, cairo_t *cr, gpointer data) {
    LinuxMultihopDialogV7 *state = data;
    GtkAllocation allocation;
    gtk_widget_get_allocation(widget, &allocation);
    double width = allocation.width;
    double height = allocation.height;
    cairo_set_source_rgb(cr, 0.055, 0.075, 0.12);
    cairo_paint(cr);
    cairo_set_source_rgb(cr, 0.20, 0.25, 0.34);
    cairo_set_line_width(cr, 1.0);
    for (int lon = -120; lon <= 120; lon += 60) {
        double x = (lon + 180.0) / 360.0 * width;
        cairo_move_to(cr, x, 0); cairo_line_to(cr, x, height);
    }
    for (int lat = -60; lat <= 60; lat += 30) {
        double y = (90.0 - lat) / 180.0 * height;
        cairo_move_to(cr, 0, y); cairo_line_to(cr, width, y);
    }
    cairo_stroke(cr);

    const char *entry_id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->entry));
    const char *exit_id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->exit));
    LinuxMultihopNodeV7 *entry = linux_multihop_find_v7(state, entry_id);
    LinuxMultihopNodeV7 *exit = linux_multihop_find_v7(state, exit_id);
    if (entry != NULL && exit != NULL && entry->has_coordinates && exit->has_coordinates) {
        double ex, ey, xx, xy;
        linux_multihop_map_point_v7(&allocation, entry, &ex, &ey);
        linux_multihop_map_point_v7(&allocation, exit, &xx, &xy);
        cairo_set_source_rgb(cr, 0.98, 0.70, 0.20);
        cairo_set_line_width(cr, 4.0);
        cairo_move_to(cr, ex, ey); cairo_line_to(cr, xx, xy); cairo_stroke(cr);
    }

    guint plotted = 0;
    for (guint i = 0; i < state->nodes->len; i++) {
        LinuxMultihopNodeV7 *node = g_ptr_array_index(state->nodes, i);
        if (node == NULL || !node->has_coordinates) continue;
        plotted++;
        double x, y;
        linux_multihop_map_point_v7(&allocation, node, &x, &y);
        gboolean is_entry = entry_id != NULL && g_strcmp0(node->id, entry_id) == 0;
        gboolean is_exit = exit_id != NULL && g_strcmp0(node->id, exit_id) == 0;
        if (is_entry) cairo_set_source_rgb(cr, 0.25, 0.62, 1.00);
        else if (is_exit) cairo_set_source_rgb(cr, 1.00, 0.42, 0.48);
        else cairo_set_source_rgb(cr, 0.20, 0.78, 0.66);
        cairo_arc(cr, x, y, is_entry || is_exit ? 8.0 : 5.0, 0, 2 * G_PI);
        cairo_fill(cr);
        cairo_set_source_rgb(cr, 0.92, 0.95, 1.0);
        cairo_move_to(cr, x + 10, y - 7);
        cairo_show_text(cr, node->name != NULL && node->name[0] ? node->name : node->id);
    }
    if (plotted == 0) {
        cairo_set_source_rgb(cr, 0.75, 0.78, 0.84);
        cairo_move_to(cr, 24, height / 2.0);
        cairo_show_text(cr, "No real node coordinates - Router VPN never invents map locations.");
    }
    return FALSE;
}

static void linux_multihop_update_summary_v7(LinuxMultihopDialogV7 *state, const char *runtime_status) {
    const char *entry_id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->entry));
    const char *exit_id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->exit));
    LinuxMultihopNodeV7 *entry = linux_multihop_find_v7(state, entry_id);
    LinuxMultihopNodeV7 *exit = linux_multihop_find_v7(state, exit_id);
    GString *text = g_string_new(runtime_status != NULL ? runtime_status : "");
    if (text->len > 0) g_string_append(text, "\n");
    if (entry != NULL && exit != NULL) {
        g_string_append_printf(text, "Path: %s -> %s -> Internet", entry->name, exit->name);
        if (entry->latency_ms > 0 || exit->latency_ms > 0) {
            g_string_append_printf(text, "\nMeasured node medians: entry %.1f ms • exit %.1f ms", entry->latency_ms, exit->latency_ms);
            if (entry->latency_ms > 0 && exit->latency_ms > 0) {
                g_string_append_printf(text, " • independent-median sum %.1f ms (display estimate, not measured multihop RTT)", entry->latency_ms + exit->latency_ms);
            }
        }
        if (!entry->has_coordinates || !exit->has_coordinates) {
            g_string_append(text, "\nOne or both selected nodes have no stored coordinates; the path stays selectable but is not fabricated on the map.");
        }
    } else {
        g_string_append(text, "Choose two different nodes. Map markers can assign Entry or Exit when real coordinates exist.");
    }
    gtk_label_set_text(GTK_LABEL(state->summary), text->str);
    g_string_free(text, TRUE);
    gtk_widget_queue_draw(state->map);
}

static void linux_multihop_combo_changed_v7(GtkComboBox *combo, gpointer data) {
    (void)combo;
    linux_multihop_update_summary_v7((LinuxMultihopDialogV7 *)data, NULL);
}

static gboolean linux_multihop_map_click_v7(GtkWidget *widget, GdkEventButton *event, gpointer data) {
    LinuxMultihopDialogV7 *state = data;
    if (event->button != 1 || state->pick_role == 0) return FALSE;
    GtkAllocation allocation;
    gtk_widget_get_allocation(widget, &allocation);
    LinuxMultihopNodeV7 *best = NULL;
    double best_distance = 24.0 * 24.0;
    for (guint i = 0; i < state->nodes->len; i++) {
        LinuxMultihopNodeV7 *node = g_ptr_array_index(state->nodes, i);
        if (node == NULL || !node->has_coordinates) continue;
        double x, y;
        linux_multihop_map_point_v7(&allocation, node, &x, &y);
        double dx = event->x - x, dy = event->y - y;
        double distance = dx * dx + dy * dy;
        if (distance < best_distance) { best_distance = distance; best = node; }
    }
    if (best == NULL) return FALSE;
    GtkWidget *target = state->pick_role == 1 ? state->entry : state->exit;
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(target), best->id);
    state->pick_role = 0;
    linux_multihop_update_summary_v7(state, "Map selection applied.");
    return TRUE;
}

static void linux_multihop_pick_entry_v7(GtkButton *button, gpointer data) {
    (void)button;
    LinuxMultihopDialogV7 *state = data;
    state->pick_role = 1;
    gtk_label_set_text(GTK_LABEL(state->summary), "Click a real-coordinate marker to use it as the multihop Entry.");
}

static void linux_multihop_pick_exit_v7(GtkButton *button, gpointer data) {
    (void)button;
    LinuxMultihopDialogV7 *state = data;
    state->pick_role = 2;
    gtk_label_set_text(GTK_LABEL(state->summary), "Click a real-coordinate marker to use it as the multihop Exit.");
}

static void linux_multihop_refresh_v7(LinuxMultihopDialogV7 *state) {
    Buffer out = {0};
    char *err = NULL;
    if (!api_request("/api/multihop/status", "GET", NULL, 5000, &out, &err)) {
        gtk_label_set_text(GTK_LABEL(state->summary), err != NULL ? err : "Multihop status unavailable.");
        g_free(err); free(out.data); return;
    }
    JsonNode *root = parse_json(out.data);
    if (root == NULL || !JSON_NODE_HOLDS_OBJECT(root)) {
        gtk_label_set_text(GTK_LABEL(state->summary), "Multihop status returned invalid JSON.");
        if (root != NULL) json_node_free(root);
        g_free(err); free(out.data); return;
    }
    JsonObject *obj = json_node_get_object(root);
    char *old_entry = g_strdup(gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->entry)));
    char *old_exit = g_strdup(gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->exit)));
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(state->entry));
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(state->exit));
    g_ptr_array_set_size(state->nodes, 0);
    JsonArray *nodes = json_object_has_member(obj, "nodes") ? json_object_get_array_member(obj, "nodes") : NULL;
    if (nodes != NULL) {
        for (guint i = 0; i < json_array_get_length(nodes); i++) {
            JsonObject *profile = json_array_get_object_element(nodes, i);
            if (profile == NULL) continue;
            const char *id = obj_string(profile, "id");
            if (id[0] == '\0') continue;
            LinuxMultihopNodeV7 *node = g_new0(LinuxMultihopNodeV7, 1);
            node->id = g_strdup(id);
            node->name = g_strdup(obj_string(profile, "name")[0] ? obj_string(profile, "name") : id);
            gboolean has_lat = FALSE, has_lon = FALSE, has_latency = FALSE;
            node->latitude = obj_double(profile, "latitude", &has_lat);
            node->longitude = obj_double(profile, "longitude", &has_lon);
            node->latency_ms = obj_double(profile, "latency_median_ms", &has_latency);
            if (!has_latency) node->latency_ms = 0;
            node->has_coordinates = has_lat && has_lon && isfinite(node->latitude) && isfinite(node->longitude)
                && node->latitude >= -90 && node->latitude <= 90 && node->longitude >= -180 && node->longitude <= 180
                && !(node->latitude == 0 && node->longitude == 0);
            g_ptr_array_add(state->nodes, node);
            gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state->entry), node->id, node->name);
            gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state->exit), node->id, node->name);
        }
    }
    const char *status_entry = obj_string(obj, "entry_id");
    const char *status_exit = obj_string(obj, "exit_id");
    const char *want_entry = old_entry != NULL && old_entry[0] ? old_entry : status_entry;
    const char *want_exit = old_exit != NULL && old_exit[0] ? old_exit : status_exit;
    if (want_entry != NULL && want_entry[0]) gtk_combo_box_set_active_id(GTK_COMBO_BOX(state->entry), want_entry);
    else if (state->nodes->len > 0) gtk_combo_box_set_active(GTK_COMBO_BOX(state->entry), 0);
    if (want_exit != NULL && want_exit[0]) gtk_combo_box_set_active_id(GTK_COMBO_BOX(state->exit), want_exit);
    else if (state->nodes->len > 1) gtk_combo_box_set_active(GTK_COMBO_BOX(state->exit), 1);

    gboolean supported = json_object_has_member(obj, "platform_supported") && json_object_get_boolean_member(obj, "platform_supported");
    gboolean connected = json_object_has_member(obj, "connected") && json_object_get_boolean_member(obj, "connected");
    const char *actual_exit = obj_string(obj, "actual_exit_id");
    const char *runtime_mode = obj_string(obj, "runtime_exit_mode");
    char *runtime = g_strdup_printf("Platform supported: %s • connected: %s%s%s%s%s",
        supported ? "yes" : "no", connected ? "yes" : "no",
        actual_exit[0] ? " • actual exit: " : "", actual_exit,
        runtime_mode[0] ? " • runtime: " : "", runtime_mode);
    linux_multihop_update_summary_v7(state, runtime);
    g_free(runtime); g_free(old_entry); g_free(old_exit);
    json_node_free(root); g_free(err); free(out.data);
}

static void linux_multihop_refresh_button_v7(GtkButton *button, gpointer data) {
    (void)button;
    linux_multihop_refresh_v7((LinuxMultihopDialogV7 *)data);
}

static void linux_multihop_connect_v7(GtkButton *button, gpointer data) {
    (void)button;
    LinuxMultihopDialogV7 *state = data;
    const char *entry = gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->entry));
    const char *exit = gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->exit));
    const char *mode = gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->mode));
    if (entry == NULL || exit == NULL || entry[0] == '\0' || exit[0] == '\0') {
        linux_multihop_update_summary_v7(state, "Select both entry and exit nodes first."); return;
    }
    if (g_strcmp0(entry, exit) == 0) {
        linux_multihop_update_summary_v7(state, "Entry and exit must be different nodes."); return;
    }
    JsonBuilder *builder = json_builder_new();
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "entry_id"); json_builder_add_string_value(builder, entry);
    json_builder_set_member_name(builder, "exit_id"); json_builder_add_string_value(builder, exit);
    json_builder_set_member_name(builder, "exit_mode"); json_builder_add_string_value(builder, mode != NULL ? mode : "shadowsocks");
    json_builder_end_object(builder);
    JsonNode *payload_root = json_builder_get_root(builder);
    JsonGenerator *gen = json_generator_new();
    json_generator_set_root(gen, payload_root);
    char *payload = json_generator_to_data(gen, NULL);
    Buffer out = {0}; char *err = NULL;
    if (api_request("/api/multihop/connect", "POST", payload, 180000, &out, &err)) {
        append_diag(state->app, "Real Linux multihop connected only after exact exit-node path proof.");
        linux_multihop_update_summary_v7(state, "Multihop connect completed; refreshing exact runtime/exit status…");
        linux_multihop_refresh_v7(state);
    } else {
        append_diag(state->app, err != NULL ? err : "Multihop connect failed.");
        linux_multihop_update_summary_v7(state, err != NULL ? err : "Multihop connect failed closed.");
    }
    free(out.data); g_free(err); g_free(payload); json_node_free(payload_root); g_object_unref(gen); g_object_unref(builder);
}

static void on_linux_multihop_v7(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    LinuxMultihopDialogV7 state = {0};
    state.app = app;
    state.nodes = g_ptr_array_new_with_free_func(linux_multihop_node_free_v7);
    state.dialog = gtk_dialog_new_with_buttons(
        "Router VPN multihop / map", GTK_WINDOW(app->window),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "Close", GTK_RESPONSE_CLOSE, NULL);
    gtk_window_set_default_size(GTK_WINDOW(state.dialog), 760, 650);
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(state.dialog));
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(box), 14);
    GtkWidget *note = gtk_label_new("Real path: client TUN -> exit transport -> entry WireGuard -> exit node -> Internet. Choose two different nodes. Map click selection is available only for stored real coordinates; coordinate-less nodes remain selectable in the lists. Connected still requires exact exit-node proof.");
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f); gtk_label_set_line_wrap(GTK_LABEL(note), TRUE);
    gtk_box_pack_start(GTK_BOX(box), note, FALSE, FALSE, 0);

    GtkWidget *grid = gtk_grid_new(); gtk_grid_set_row_spacing(GTK_GRID(grid), 7); gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    state.entry = gtk_combo_box_text_new(); state.exit = gtk_combo_box_text_new(); state.mode = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.mode), "shadowsocks", "Shadowsocks exit");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state.mode), "hysteria2", "Hysteria2 exit");
    gtk_combo_box_set_active(GTK_COMBO_BOX(state.mode), 0);
    profile_settings_grid_row_v7(grid, 0, "Entry node", state.entry);
    profile_settings_grid_row_v7(grid, 1, "Exit node", state.exit);
    profile_settings_grid_row_v7(grid, 2, "Exit transport", state.mode);
    gtk_box_pack_start(GTK_BOX(box), grid, FALSE, FALSE, 0);

    GtkWidget *pick = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(pick), make_button("Pick Entry on map", G_CALLBACK(linux_multihop_pick_entry_v7), &state), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(pick), make_button("Pick Exit on map", G_CALLBACK(linux_multihop_pick_exit_v7), &state), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(pick), make_button("Refresh multihop", G_CALLBACK(linux_multihop_refresh_button_v7), &state), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(pick), make_button("Connect real multihop", G_CALLBACK(linux_multihop_connect_v7), &state), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), pick, FALSE, FALSE, 0);

    state.map = gtk_drawing_area_new(); gtk_widget_set_size_request(state.map, -1, 300);
    gtk_widget_add_events(state.map, GDK_BUTTON_PRESS_MASK);
    g_signal_connect(state.map, "draw", G_CALLBACK(linux_multihop_draw_v7), &state);
    g_signal_connect(state.map, "button-press-event", G_CALLBACK(linux_multihop_map_click_v7), &state);
    gtk_box_pack_start(GTK_BOX(box), state.map, TRUE, TRUE, 0);
    state.summary = gtk_label_new("Loading multihop status…");
    gtk_label_set_xalign(GTK_LABEL(state.summary), 0.0f); gtk_label_set_line_wrap(GTK_LABEL(state.summary), TRUE);
    gtk_box_pack_start(GTK_BOX(box), state.summary, FALSE, FALSE, 0);
    g_signal_connect(state.entry, "changed", G_CALLBACK(linux_multihop_combo_changed_v7), &state);
    g_signal_connect(state.exit, "changed", G_CALLBACK(linux_multihop_combo_changed_v7), &state);
    gtk_box_pack_start(GTK_BOX(content), box, TRUE, TRUE, 0);
    linux_multihop_refresh_v7(&state);
    gtk_widget_show_all(state.dialog);
    gtk_dialog_run(GTK_DIALOG(state.dialog));
    gtk_widget_destroy(state.dialog);
    g_ptr_array_unref(state.nodes);
}

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
    GtkWidget *multihop = gtk_button_new_with_label("Multihop / Map — choose Entry -> Exit");
    g_signal_connect(multihop, "clicked", G_CALLBACK(on_linux_multihop_v7), app);
    gtk_box_pack_start(GTK_BOX(box), multihop, FALSE, FALSE, 0);
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
 * Linux Advanced also exposes real /api/multihop/status + /api/multihop/connect with
 * stored-coordinate map selection/path drawing; absent coordinates are never invented.
 */