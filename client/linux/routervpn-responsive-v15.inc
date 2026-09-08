/* Applied after the existing shell, telemetry, Profiles and Speed Lab are
 * composed. Reparent the actual controls, retaining callbacks and guards; do
 * not maintain a second compact UI with different behavior or preference state. */
static void linux_combo_tooltip_v15(GtkComboBox *combo, gpointer data) {
    (void)data;
    char *text = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(combo));
    gtk_widget_set_tooltip_text(GTK_WIDGET(combo), text);
    g_free(text);
}

static void linux_compact_combos_v15(GtkWidget *widget) {
    if (GTK_IS_COMBO_BOX_TEXT(widget)) {
        GList *cells = gtk_cell_layout_get_cells(GTK_CELL_LAYOUT(widget));
        for (GList *item = cells; item != NULL; item = item->next) {
            if (GTK_IS_CELL_RENDERER_TEXT(item->data)) {
                g_object_set(item->data, "ellipsize", PANGO_ELLIPSIZE_END,
                             "width-chars", 8, "max-width-chars", 24, NULL);
            }
        }
        g_list_free(cells);
        gtk_combo_box_set_popup_fixed_width(GTK_COMBO_BOX(widget), FALSE);
        g_signal_connect(widget, "changed", G_CALLBACK(linux_combo_tooltip_v15), NULL);
        linux_combo_tooltip_v15(GTK_COMBO_BOX(widget), NULL);
    } else if (GTK_IS_CONTAINER(widget)) {
        GList *children = gtk_container_get_children(GTK_CONTAINER(widget));
        for (GList *item = children; item != NULL; item = item->next)
            linux_compact_combos_v15(GTK_WIDGET(item->data));
        g_list_free(children);
    }
}

static void linux_reflow_settings_v15(GtkWidget *box) {
    GtkWidget *flow = gtk_flow_box_new();
    gtk_widget_set_name(flow, "router-vpn-settings-actions");
    gtk_flow_box_set_selection_mode(GTK_FLOW_BOX(flow), GTK_SELECTION_NONE);
    gtk_flow_box_set_min_children_per_line(GTK_FLOW_BOX(flow), 1);
    gtk_flow_box_set_max_children_per_line(GTK_FLOW_BOX(flow), 6);
    gtk_flow_box_set_row_spacing(GTK_FLOW_BOX(flow), 4);
    gtk_flow_box_set_column_spacing(GTK_FLOW_BOX(flow), 4);
    GList *children = gtk_container_get_children(GTK_CONTAINER(box));
    for (GList *item = children; item != NULL; item = item->next) {
        GtkWidget *button = GTK_WIDGET(item->data);
        g_object_ref(button);
        gtk_container_remove(GTK_CONTAINER(box), button);
        gtk_container_add(GTK_CONTAINER(flow), button);
        g_object_unref(button);
    }
    g_list_free(children);
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

    linux_reflow_settings_v15(gtk_widget_get_parent(settings));
    linux_compact_combos_v15(main);
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

/* Real-widget acceptance check for the built app under Xvfb. It opens no
 * connections, changes no profiles, and exercises the same shipping widget
 * hierarchy rather than rendering a separate mock UI. */
static int linux_responsive_self_test_v15(App *app) {
    LinuxUnifiedV8 *base = g_object_get_data(G_OBJECT(app->window), "linux-unified-v8");
    GtkWidget *scroll = g_object_get_data(G_OBJECT(app->window), "linux-responsive-v15");
    if (base == NULL || scroll == NULL) return 5;
    static const int sizes[][2] = {{640,480}, {800,600}, {960,680}, {1280,800}};
    static const char *const actions[] = {"Open settings", "AUTO requirements", "Retest MTU", "Performance", "Profiles", "Speed Lab", "Presets / CUSTOM", "Details", "DNS details", "Choose hops"};
    for (guint n = 0; n < G_N_ELEMENTS(sizes); n++) {
        gtk_window_resize(GTK_WINDOW(app->window), sizes[n][0], sizes[n][1]);
        for (int frame = 0; frame < 8; frame++) {
            while (gtk_events_pending()) gtk_main_iteration_do(FALSE);
            g_usleep(20000);
        }
        GtkWidget *viewport = gtk_bin_get_child(GTK_BIN(scroll));
        GtkWidget *page = gtk_bin_get_child(GTK_BIN(viewport));
        int width = gtk_widget_get_allocated_width(viewport);
        int minimum_width = 0, minimum_height = 0;
        gtk_widget_get_preferred_width(app->window, &minimum_width, NULL);
        gtk_widget_get_preferred_height(app->window, &minimum_height, NULL);
        if (minimum_width > 640 || minimum_height > 480 || width < 1) {
            fprintf(stderr, "Responsive minimum grew to %dx%d\n", minimum_width, minimum_height);
            return 6;
        }
        for (guint i = 0; i < G_N_ELEMENTS(actions); i++) {
            GtkWidget *button = linux_telemetry_find_button_v9(page, actions[i]);
            int x = 0, y = 0;
            if (button == NULL || !gtk_widget_get_visible(button) ||
                !gtk_widget_translate_coordinates(button, page, 0, 0, &x, &y) ||
                x < 0 || x + gtk_widget_get_allocated_width(button) > width ||
                y < 0 || y + gtk_widget_get_allocated_height(button) > gtk_widget_get_allocated_height(page)) {
                fprintf(stderr, "Clipped/unreachable action %s at %dx%d\n", actions[i], sizes[n][0], sizes[n][1]);
                return 7;
            }
        }
        printf("Router VPN rendered layout: %dx%d; all %u actions reachable; minimum %dx%d\n", sizes[n][0], sizes[n][1], (unsigned)G_N_ELEMENTS(actions), minimum_width, minimum_height);
    }
    return 0;
}
