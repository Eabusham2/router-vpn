/* Applied after the existing shell, telemetry, Profiles and Speed Lab are
 * composed. Reparent the actual controls, retaining callbacks and guards; do
 * not maintain a second compact UI with different behavior or preference state. */
static void linux_combo_tooltip_v15(GtkComboBox *combo, gpointer data) {
    (void)data;
    char *text = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(combo));
    gtk_widget_set_tooltip_text(GTK_WIDGET(combo), text);
    g_free(text);
}

static void linux_compact_map_controls_v15(GtkWidget *widget) {
    if (GTK_IS_COMBO_BOX_TEXT(widget)) {
        GList *cells = gtk_cell_layout_get_cells(GTK_CELL_LAYOUT(widget));
        for (GList *item = cells; item != NULL; item = item->next) {
            if (GTK_IS_CELL_RENDERER_TEXT(item->data)) {
                g_object_set(item->data, "ellipsize", PANGO_ELLIPSIZE_END,
                             "width-chars", 8, "max-width-chars", 24, NULL);
            }
        }
        g_list_free(cells);
        /* The shell populates the model before this layer is composed. GTK's
         * cell context may already hold widths measured without ellipsizing;
         * reset those cached requests without replacing the model or selection. */
        GtkWidget *view = gtk_bin_get_child(GTK_BIN(widget));
        if (GTK_IS_CELL_VIEW(view)) {
            GtkCellAreaContext *context = NULL;
            g_object_get(view, "cell-area-context", &context, NULL);
            if (context != NULL) {
                gtk_cell_area_context_reset(context);
                g_object_unref(context);
            }
            gtk_widget_queue_resize(view);
        }
        gtk_widget_queue_resize(widget);
        gtk_combo_box_set_popup_fixed_width(GTK_COMBO_BOX(widget), FALSE);
        g_signal_connect(widget, "changed", G_CALLBACK(linux_combo_tooltip_v15), NULL);
        linux_combo_tooltip_v15(GTK_COMBO_BOX(widget), NULL);
    } else if (GTK_IS_CONTAINER(widget)) {
        GList *children = gtk_container_get_children(GTK_CONTAINER(widget));
        for (GList *item = children; item != NULL; item = item->next)
            linux_compact_map_controls_v15(GTK_WIDGET(item->data));
        g_list_free(children);
    }
}

/* The external-node composer groups two existing buttons in a plain box.
 * Move each action separately so GTK can wrap between them at large fonts. */
static void linux_move_controls_v15(GtkWidget *box, GtkWidget *flow) {
    GList *children = gtk_container_get_children(GTK_CONTAINER(box));
    for (GList *item = children; item != NULL; item = item->next) {
        GtkWidget *control = GTK_WIDGET(item->data);
        if (GTK_IS_BOX(control)) {
            linux_move_controls_v15(control, flow);
            gtk_container_remove(GTK_CONTAINER(box), control);
        } else {
            g_object_ref(control);
            gtk_container_remove(GTK_CONTAINER(box), control);
            gtk_container_add(GTK_CONTAINER(flow), control);
            if (gtk_widget_get_no_show_all(control)) {
                GtkWidget *child = gtk_widget_get_parent(control);
                gtk_widget_set_no_show_all(child, TRUE);
                g_object_bind_property(control, "visible", child, "visible", G_BINDING_SYNC_CREATE);
            }
            g_object_unref(control);
        }
    }
    g_list_free(children);
}

static GtkWidget *linux_action_flow_v15(GtkWidget *box, const char *name) {
    GtkWidget *flow = gtk_flow_box_new();
    gtk_widget_set_name(flow, name);
    gtk_flow_box_set_selection_mode(GTK_FLOW_BOX(flow), GTK_SELECTION_NONE);
    gtk_flow_box_set_min_children_per_line(GTK_FLOW_BOX(flow), 1);
    gtk_flow_box_set_max_children_per_line(GTK_FLOW_BOX(flow), 6);
    gtk_flow_box_set_row_spacing(GTK_FLOW_BOX(flow), 4);
    gtk_flow_box_set_column_spacing(GTK_FLOW_BOX(flow), 4);
    linux_move_controls_v15(box, flow);
    return flow;
}

static void linux_reflow_controls_v15(GtkWidget *box, const char *name) {
    GtkWidget *flow = linux_action_flow_v15(box, name);
    gtk_orientable_set_orientation(GTK_ORIENTABLE(box), GTK_ORIENTATION_VERTICAL);
    gtk_box_pack_start(GTK_BOX(box), flow, FALSE, FALSE, 0);
}

static GtkWidget *linux_scroll_page_v15(GtkStack *stack, const char *name, GtkPolicyType horizontal) {
    GtkWidget *page = gtk_stack_get_child_by_name(stack, name);
    if (page == NULL) g_error("Router VPN responsive page contract drifted: %s", name);
    g_object_ref(page);
    gtk_container_remove(GTK_CONTAINER(stack), page);
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), horizontal, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(scroll), page);
    g_object_unref(page);
    gtk_stack_add_named(stack, scroll, name);
    return scroll;
}

static void linux_install_responsive_v15(App *app) {
    LinuxUnifiedV8 *base = g_object_get_data(G_OBJECT(app->window), "linux-unified-v8");
    if (base == NULL || g_object_get_data(G_OBJECT(app->window), "linux-responsive-v15") != NULL) return;
    GtkWidget *main = gtk_stack_get_child_by_name(GTK_STACK(base->stack), "map");
    GtkWidget *settings = linux_telemetry_find_button_v9(main, "Open settings");
    if (main == NULL || !GTK_IS_BOX(main) || settings == NULL || !GTK_IS_BOX(gtk_widget_get_parent(settings)))
        g_error("Router VPN responsive settings composition drifted");

    /* Long runtime status belongs on its own line, not in the node selector's
     * minimum width. Keep every node-management button and the original label. */
    GtkWidget *top = gtk_widget_get_parent(base->status);
    g_object_ref(base->status);
    gtk_container_remove(GTK_CONTAINER(top), base->status);
    gtk_box_pack_start(GTK_BOX(main), base->status, FALSE, FALSE, 0);
    gtk_box_reorder_child(GTK_BOX(main), base->status, 1);
    g_object_unref(base->status);
    gtk_label_set_xalign(GTK_LABEL(base->status), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(base->status), PANGO_ELLIPSIZE_END);
    g_object_bind_property(base->status, "label", base->status, "tooltip-text", G_BINDING_SYNC_CREATE);

    linux_reflow_controls_v15(top, "router-vpn-node-actions");
    linux_reflow_controls_v15(gtk_widget_get_parent(base->connect), "router-vpn-connection-actions");
    GtkWidget *external = linux_telemetry_find_button_v9(main, "Direct / entry · Local / Server / Compare…");
    if (external == NULL) g_error("Router VPN responsive external-path action missing");
    gtk_orientable_set_orientation(GTK_ORIENTABLE(gtk_widget_get_parent(external)), GTK_ORIENTATION_VERTICAL);
    linux_reflow_controls_v15(gtk_widget_get_parent(base->mode), "router-vpn-mode-actions");
    /* Ask the flow for its height at the width left beside the Settings label.
     * The original button box made this row reserve one line per action. */
    GtkWidget *settings_buttons = gtk_widget_get_parent(settings);
    GtkWidget *settings_row = gtk_widget_get_parent(settings_buttons);
    GtkWidget *settings_flow = linux_action_flow_v15(settings_buttons, "router-vpn-settings-actions");
    gtk_container_remove(GTK_CONTAINER(settings_row), settings_buttons);
    gtk_box_pack_start(GTK_BOX(settings_row), settings_flow, TRUE, TRUE, 0);
    linux_compact_map_controls_v15(main);
    GList *hops = gtk_container_get_children(GTK_CONTAINER(gtk_widget_get_parent(base->multihop)));
    for (GList *item = hops; item != NULL; item = item->next) {
        if (GTK_IS_LABEL(item->data))
            gtk_label_set_ellipsize(GTK_LABEL(item->data), PANGO_ELLIPSIZE_END);
    }
    g_list_free(hops);

    /* A hidden legacy detail page must not impose its natural size on the map.
     * Short windows can scroll vertically; details retain both-axis scrolling.
     * Settings actions reflow and mode text ellipsizes instead of losing buttons. */
    gtk_stack_set_hhomogeneous(GTK_STACK(base->stack), FALSE);
    gtk_stack_set_vhomogeneous(GTK_STACK(base->stack), FALSE);
    GtkWidget *scroll = linux_scroll_page_v15(GTK_STACK(base->stack), "map", GTK_POLICY_NEVER);
    (void)linux_scroll_page_v15(GTK_STACK(base->stack), "details", GTK_POLICY_AUTOMATIC);
    gtk_stack_set_visible_child_name(GTK_STACK(base->stack), "map");
    gtk_widget_set_size_request(app->window, 640, 480);
    g_object_set_data(G_OBJECT(app->window), "linux-responsive-v15", scroll);
    gtk_widget_show_all(app->window);
}

/* Check the real allocation, then scroll that same control into the viewport.
 * A control merely existing below the page is not evidence that it is usable. */
static gboolean linux_control_reachable_v15(GtkWidget *widget, GtkWidget *page,
                                           GtkWidget *viewport, GtkWidget *scroll) {
    int x = 0, y = 0;
    if (widget == NULL || !gtk_widget_is_visible(widget) ||
        !gtk_widget_translate_coordinates(widget, page, 0, 0, &x, &y)) return FALSE;
    int width = gtk_widget_get_allocated_width(widget);
    int height = gtk_widget_get_allocated_height(widget);
    if (GTK_IS_BUTTON(widget) && GTK_IS_LABEL(gtk_bin_get_child(GTK_BIN(widget)))) {
        GtkWidget *label = gtk_bin_get_child(GTK_BIN(widget));
        PangoRectangle logical;
        pango_layout_get_pixel_extents(gtk_label_get_layout(GTK_LABEL(label)), NULL, &logical);
        if (logical.height > gtk_widget_get_allocated_height(label)) return FALSE;
    }
    if (width < 1 || height < 1 || x < 0 ||
        x + width > gtk_widget_get_allocated_width(viewport) || y < 0 ||
        y + height > gtk_widget_get_allocated_height(page)) return FALSE;
    GtkAdjustment *vertical = gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(scroll));
    if (!gtk_widget_translate_coordinates(widget, viewport, 0, 0, &x, &y)) return FALSE;
    double top = gtk_adjustment_get_value(vertical) + y;
    gtk_adjustment_clamp_page(vertical, top, top + height);
    /* A scroll or resize may be committed on the next frame clock tick. */
    gint64 deadline = g_get_monotonic_time() + 400 * G_TIME_SPAN_MILLISECOND;
    do {
        while (gtk_events_pending()) gtk_main_iteration_do(FALSE);
        if (!gtk_widget_translate_coordinates(widget, viewport, 0, 0, &x, &y)) return FALSE;
        if (x >= 0 && y >= 0 && x + width <= gtk_widget_get_allocated_width(viewport) &&
            y + height <= gtk_widget_get_allocated_height(viewport)) return TRUE;
        g_usleep(5000);
    } while (g_get_monotonic_time() < deadline);
    return FALSE;
}

static gboolean linux_save_layout_v15(GtkWidget *window, const char *directory, const char *scenario,
                                      int width, int height, const char *view) {
    gtk_test_widget_wait_for_draw(window);
    GdkWindow *surface = gtk_widget_get_window(window);
    GdkPixbuf *image = gdk_pixbuf_get_from_window(surface, 0, 0, gdk_window_get_width(surface), gdk_window_get_height(surface));
    char *name = g_strdup_printf("linux-%dx%d-%s-%s.png", width, height, scenario, view);
    g_strdelimit(name, " ", '-');
    char *path = g_build_filename(directory, name, NULL);
    GError *error = NULL;
    gboolean saved = image != NULL && gdk_pixbuf_save(image, path, "png", &error, NULL);
    if (!saved) g_printerr("Could not save %s: %s\n", path, error != NULL ? error->message : "no window pixels");
    g_clear_error(&error);
    g_clear_object(&image);
    g_free(path);
    g_free(name);
    return saved;
}

static int linux_responsive_check_sizes_v15(App *app, const char *scenario) {
    LinuxUnifiedV8 *base = g_object_get_data(G_OBJECT(app->window), "linux-unified-v8");
    GtkWidget *scroll = g_object_get_data(G_OBJECT(app->window), "linux-responsive-v15");
    LinuxTelemetryV9 *telemetry = g_object_get_data(G_OBJECT(app->window), "linux-telemetry-v9");
    if (base == NULL || scroll == NULL || telemetry == NULL) return 5;
    static const int sizes[][2] = {{640,480}, {800,600}, {960,680}, {1280,800}};
    static const char *const actions[] = {
        "Open settings", "AUTO requirements", "Retest MTU", "Performance", "Profiles", "Speed Lab",
        "Presets / CUSTOM", "Details", "DNS details", "Choose hops", "Add / manage nodes",
        "Add external node…", "Tor bridges…", "Direct / entry · Local / Server / Compare…", "Show my location"
    };
    GtkWidget *primary[] = {base->connect, base->kill_switch, base->node, base->mode, base->dns, telemetry->fastest, telemetry->forward, telemetry->live};
    for (guint n = 0; n < G_N_ELEMENTS(sizes); n++) {
        gtk_window_resize(GTK_WINDOW(app->window), sizes[n][0], sizes[n][1]);
        for (int frame = 0; frame < 8; frame++) {
            while (gtk_events_pending()) gtk_main_iteration_do(FALSE);
            g_usleep(20000);
        }
        GtkWidget *viewport = gtk_bin_get_child(GTK_BIN(scroll));
        GtkWidget *page = gtk_bin_get_child(GTK_BIN(viewport));
        const char *evidence = g_getenv("ROUTERVPN_UI_EVIDENCE_DIR");
        if (evidence != NULL && *evidence != '\0') {
            GtkAdjustment *vertical = gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(scroll));
            gtk_adjustment_set_value(vertical, gtk_adjustment_get_lower(vertical));
            if (!linux_save_layout_v15(app->window, evidence, scenario, sizes[n][0], sizes[n][1], "map")) return 10;
            int x = 0, y = 0;
            if (!gtk_widget_translate_coordinates(base->connect, page, 0, 0, &x, &y)) return 10;
            gtk_adjustment_set_value(vertical, y);
            if (!linux_save_layout_v15(app->window, evidence, scenario, sizes[n][0], sizes[n][1], "controls")) return 10;
        }
        int minimum_width = 0, minimum_height = 0;
        gtk_widget_get_preferred_width(app->window, &minimum_width, NULL);
        gtk_widget_get_preferred_height(app->window, &minimum_height, NULL);
        if (minimum_width > 640 || minimum_height > 480 || gtk_widget_get_allocated_width(viewport) < 1) {
            fprintf(stderr, "Responsive minimum grew to %dx%d (%s)\n", minimum_width, minimum_height, scenario);
            return 6;
        }
        for (guint i = 0; i < G_N_ELEMENTS(actions); i++) {
            GtkWidget *button = linux_telemetry_find_button_v9(page, actions[i]);
            if (!linux_control_reachable_v15(button, page, viewport, scroll)) {
                fprintf(stderr, "Clipped/unreachable action %s at %dx%d (%s)\n", actions[i], sizes[n][0], sizes[n][1], scenario);
                return 7;
            }
        }
        for (guint i = 0; i < G_N_ELEMENTS(primary); i++) {
            if (primary[i] == telemetry->fastest && !telemetry->comparable_nodes) {
                if (gtk_widget_get_visible(telemetry->fastest)) {
                    fprintf(stderr, "Fastest is visible with fewer than two eligible nodes\n");
                    return 7;
                }
                continue;
            }
            if (!linux_control_reachable_v15(primary[i], page, viewport, scroll)) {
                fprintf(stderr, "Clipped/unreachable primary control %u at %dx%d (%s)\n", i, sizes[n][0], sizes[n][1], scenario);
                return 7;
            }
        }
        printf("Router VPN rendered layout: %dx%d; all %u actions and %u primary controls reachable; minimum %dx%d (%s)\n", sizes[n][0], sizes[n][1], (unsigned)G_N_ELEMENTS(actions), (unsigned)G_N_ELEMENTS(primary) - (!telemetry->comparable_nodes ? 1 : 0), minimum_width, minimum_height, scenario);
    }
    return 0;
}

/* Real-widget acceptance check for the built app under Xvfb. It opens no
 * connections and changes no profiles. Long labels change only existing model
 * display text; their IDs, selection, callbacks and stored preferences survive. */
static int linux_responsive_check_labels_v15(App *app, const char *scenario, const char *long_scenario) {
    int result = linux_responsive_check_sizes_v15(app, scenario);
    if (result != 0) return result;
    LinuxUnifiedV8 *base = g_object_get_data(G_OBJECT(app->window), "linux-unified-v8");
    GtkTreeModel *model = gtk_combo_box_get_model(GTK_COMBO_BOX(base->mode));
    GtkTreeIter iter;
    if (!GTK_IS_LIST_STORE(model) || !gtk_tree_model_get_iter_first(model, &iter)) return 8;
    char *selected = g_strdup(gtk_combo_box_get_active_id(GTK_COMBO_BOX(base->mode)));
    int rows = gtk_tree_model_iter_n_children(model, NULL);
    char *original = NULL;
    gtk_tree_model_get(model, &iter, 0, &original, -1);
    char *long_label = g_strnfill(1024, 'M');
    gboolean was_syncing = base->syncing;
    base->syncing = TRUE;
    gtk_list_store_set(GTK_LIST_STORE(model), &iter, 0, long_label, -1);
    base->syncing = was_syncing;
    result = linux_responsive_check_sizes_v15(app, long_scenario);
    base->syncing = TRUE;
    gtk_list_store_set(GTK_LIST_STORE(model), &iter, 0, original, -1);
    base->syncing = was_syncing;
    if (gtk_combo_box_get_model(GTK_COMBO_BOX(base->mode)) != model ||
        gtk_tree_model_iter_n_children(model, NULL) != rows ||
        g_strcmp0(gtk_combo_box_get_active_id(GTK_COMBO_BOX(base->mode)), selected) != 0) {
        fprintf(stderr, "Responsive sizing changed mode model or selection\n");
        result = 9;
    }
    g_free(long_label);
    g_free(original);
    g_free(selected);
    return result;
}

static int linux_responsive_self_test_v15(App *app) {
    int result = linux_responsive_check_labels_v15(app, "normal", "long mode label");
    if (result != 0) return result;
    LinuxUnifiedV8 *base = g_object_get_data(G_OBJECT(app->window), "linux-unified-v8");
    GtkWidget *label = gtk_bin_get_child(GTK_BIN(base->connect));
    if (!GTK_IS_LABEL(label)) return 11;
    int original_height = 0;
    pango_layout_get_pixel_size(gtk_label_get_layout(GTK_LABEL(label)), NULL, &original_height);
    GtkSettings *settings = gtk_widget_get_settings(app->window);
    char *original = NULL;
    gboolean animations;
    g_object_get(settings, "gtk-font-name", &original, "gtk-enable-animations", &animations, NULL);
    if (original == NULL) return 11;
    PangoFontDescription *font = pango_font_description_from_string(original);
    int size = pango_font_description_get_size(font);
    if (size <= 0 || size > G_MAXINT / 2) {
        g_printerr("Cannot double the configured GTK font %s\n", original);
        pango_font_description_free(font);
        g_free(original);
        return 11;
    }
    if (pango_font_description_get_size_is_absolute(font))
        pango_font_description_set_absolute_size(font, (double)size * 2);
    else
        pango_font_description_set_size(font, size * 2);
    char *enlarged = pango_font_description_to_string(font);
    g_print("Checking GTK layout with configured font %s doubled to %s\n", original, enlarged);
    // Measure the fully applied font at the first window size as well as later sizes.
    g_object_set(settings, "gtk-enable-animations", FALSE, "gtk-font-name", enlarged, NULL);
    result = linux_responsive_check_labels_v15(app, "double font", "double font long mode label");
    int enlarged_height = 0;
    pango_layout_get_pixel_size(gtk_label_get_layout(GTK_LABEL(label)), NULL, &enlarged_height);
    if (result == 0 && enlarged_height <= original_height) {
        g_printerr("Connect label did not grow after changing the configured GTK font\n");
        result = 11;
    }
    g_object_set(settings, "gtk-font-name", original, NULL);
    gtk_test_widget_wait_for_draw(app->window);
    g_object_set(settings, "gtk-enable-animations", animations, NULL);
    g_free(enlarged);
    pango_font_description_free(font);
    g_free(original);
    return result;
}
