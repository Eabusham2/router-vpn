static void refresh_home_summary_v6(App *app) {
    if (app == NULL || app->detail == NULL) return;
    Buffer out = {0};
    char *err = NULL;
    if (!api_request("/api/home-summary", "GET", NULL, 5000, &out, &err)) {
        char *message = g_strdup_printf("Home state unavailable: %s", err != NULL ? err : "request failed");
        gtk_label_set_text(GTK_LABEL(app->detail), message);
        g_free(message);
        g_free(err);
        free(out.data);
        return;
    }
    JsonNode *root = parse_json(out.data);
    if (root == NULL || !JSON_NODE_HOLDS_OBJECT(root)) {
        gtk_label_set_text(GTK_LABEL(app->detail), "Home state unavailable: invalid controller response");
        if (root != NULL) json_node_free(root);
        g_free(err);
        free(out.data);
        return;
    }
    JsonObject *s = json_node_get_object(root);
    gboolean connected = json_object_has_member(s, "connected") && json_object_get_boolean_member(s, "connected");
    gboolean lan = json_object_has_member(s, "lan_access") && json_object_get_boolean_member(s, "lan_access");
    const char *exit_status = obj_string(s, "actual_exit_status");
    const char *actual_exit = obj_string(s, "actual_exit_ip");
    const char *exit_text = "Not connected";
    if (connected) exit_text = strcmp(exit_status, "proved") == 0 && actual_exit[0] != '\0' ? actual_exit : "Unproven — click Prove actual exit";

    double dns_latency = json_object_has_member(s, "dns_latency_ms") ? json_object_get_double_member(s, "dns_latency_ms") : 0.0;
    double node_latency = json_object_has_member(s, "node_latency_ms") ? json_object_get_double_member(s, "node_latency_ms") : 0.0;
    int node_samples = json_object_has_member(s, "node_latency_samples") ? (int)json_object_get_int_member(s, "node_latency_samples") : 0;
    int effective_mtu = json_object_has_member(s, "effective_mtu") ? (int)json_object_get_int_member(s, "effective_mtu") : 0;

    GString *text = g_string_new("");
    g_string_append_printf(text, "Node: %s • %s\nPublic endpoint: %s\nActual public VPN exit: %s\n",
        obj_string(s, "node_name"), obj_string(s, "location")[0] ? obj_string(s, "location") : "Location not labeled",
        obj_string(s, "public_endpoint"), exit_text);
    g_string_append_printf(text, "Connection: %s • path proof %s\nLogical/runtime/base: %s • %s • %s\nFallback: %s\n",
        obj_string(s, "connection_phase"), obj_string(s, "path_proof"), obj_string(s, "logical_mode"),
        obj_string(s, "actual_runtime"), obj_string(s, "actual_base"), obj_string(s, "fallback")[0] ? obj_string(s, "fallback") : "None");
    g_string_append_printf(text, "DNS: %s • %s • proof %s\n", obj_string(s, "dns_mode"), obj_string(s, "dns_host"), obj_string(s, "dns_status"));
    if (dns_latency > 0) g_string_append_printf(text, "DNS measured RTT: %.2f ms\n", dns_latency);
    else g_string_append(text, "DNS measured RTT: not measured / not proven\n");
    if (node_samples > 0) g_string_append_printf(text, "Node measured latency: %.2f ms / %d samples\n", node_latency, node_samples);
    else g_string_append(text, "Node measured latency: Not measured\n");
    g_string_append_printf(text, "LAN access: %s • Kill switch: %s\n", lan ? "On" : "Off", obj_string(s, "kill_switch"));
    if (effective_mtu > 0) {
        g_string_append_printf(text, "Effective MTU: %d", effective_mtu);
        if (obj_string(s, "effective_mtu_source")[0]) g_string_append_printf(text, " • %s", obj_string(s, "effective_mtu_source"));
    } else {
        g_string_append(text, "Effective MTU: Default / not measured");
    }
    g_string_append_printf(text, " • IPv6: %s • Auto-connect: %s\n", obj_string(s, "ipv6_mode"),
        json_object_has_member(s, "auto_connect") && json_object_get_boolean_member(s, "auto_connect") ? "On" : "Off");

    JsonArray *warnings = json_object_has_member(s, "warnings") ? json_object_get_array_member(s, "warnings") : NULL;
    g_string_append(text, "Warnings: ");
    if (warnings == NULL || json_array_get_length(warnings) == 0) g_string_append(text, "None");
    else for (guint i = 0; i < json_array_get_length(warnings); i++) {
        if (i > 0) g_string_append(text, " | ");
        g_string_append(text, json_array_get_string_element(warnings, i));
    }
    gtk_label_set_line_wrap(GTK_LABEL(app->detail), TRUE);
    gtk_label_set_selectable(GTK_LABEL(app->detail), TRUE);
    gtk_label_set_text(GTK_LABEL(app->detail), text->str);
    g_string_free(text, TRUE);
    json_node_free(root);
    g_free(err);
    free(out.data);
}

static void on_home_exit_v6(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    post_and_log(app, "/api/home-summary/prove-exit", "{}", 12000, "Actual public VPN exit proof");
    refresh_home_summary_v6(app);
}

static void on_strategy_auto_v7(GtkButton *button, gpointer data) {
    (void)button;
    post_and_log((App *)data, "/api/strategy/auto", "{}", 180000, "AUTO");
}

static void on_strategy_smart_v7(GtkButton *button, gpointer data) {
    (void)button;
    post_and_log((App *)data, "/api/strategy/smart-auto", "{}", 240000, "SMART AUTO");
}

static char *strategy_custom_body_v7(const char *raw) {
    if (raw == NULL) return NULL;
    JsonBuilder *builder = json_builder_new();
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "layers");
    json_builder_begin_array(builder);
    gchar **parts = g_strsplit(raw, ",", -1);
    guint added = 0;
    for (guint i = 0; parts != NULL && parts[i] != NULL; i++) {
        gchar *value = g_strdup(parts[i]);
        g_strstrip(value);
        if (value[0] != '\0') {
            gchar *lower = g_ascii_strdown(value, -1);
            json_builder_add_string_value(builder, lower);
            g_free(lower);
            added++;
        }
        g_free(value);
    }
    g_strfreev(parts);
    json_builder_end_array(builder);
    json_builder_end_object(builder);
    if (added == 0) {
        g_object_unref(builder);
        return NULL;
    }
    JsonGenerator *generator = json_generator_new();
    JsonNode *root = json_builder_get_root(builder);
    json_generator_set_root(generator, root);
    gchar *body = json_generator_to_data(generator, NULL);
    json_node_free(root);
    g_object_unref(generator);
    g_object_unref(builder);
    return body;
}

static void on_strategy_custom_v7(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    GtkWidget *dialog = gtk_dialog_new_with_buttons("CUSTOM mode", GTK_WINDOW(app->window),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "Cancel", GTK_RESPONSE_CANCEL, "Connect", GTK_RESPONSE_ACCEPT, NULL);
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *label = gtk_label_new("Exact required layers, comma-separated. Router VPN tries only validated compatible stacks and minimizes extra layers, base mismatch, overhead and latency.");
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry), "wireguard, rosenpass, reality");
    gtk_box_pack_start(GTK_BOX(content), label, FALSE, FALSE, 8);
    gtk_box_pack_start(GTK_BOX(content), entry, FALSE, FALSE, 8);
    gtk_widget_show_all(dialog);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *body = strategy_custom_body_v7(gtk_entry_get_text(GTK_ENTRY(entry)));
        if (body == NULL) append_diag(app, "CUSTOM requires at least one exact layer.");
        else {
            post_and_log(app, "/api/strategy/custom", body, 240000, "CUSTOM");
            g_free(body);
        }
    }
    gtk_widget_destroy(dialog);
}

static void hide_legacy_auto_v7(GtkWidget *widget) {
    if (GTK_IS_BUTTON(widget)) {
        const char *label = gtk_button_get_label(GTK_BUTTON(widget));
        if (label != NULL && strcmp(label, "AUTO Connect") == 0) {
            gtk_widget_set_no_show_all(widget, TRUE);
            gtk_widget_hide(widget);
            return;
        }
    }
    if (!GTK_IS_CONTAINER(widget)) return;
    GList *children = gtk_container_get_children(GTK_CONTAINER(widget));
    for (GList *it = children; it != NULL; it = it->next) hide_legacy_auto_v7(GTK_WIDGET(it->data));
    g_list_free(children);
}

static GtkWidget *build_home_page_strategy_v7(App *app) {
    GtkWidget *home = build_home_page(app);
    hide_legacy_auto_v7(home);
    GtkWidget *frame = gtk_frame_new("Connection strategy");
    GtkWidget *flow = gtk_flow_box_new();
    gtk_flow_box_set_selection_mode(GTK_FLOW_BOX(flow), GTK_SELECTION_NONE);
    gtk_flow_box_set_max_children_per_line(GTK_FLOW_BOX(flow), 3);
    gtk_flow_box_set_min_children_per_line(GTK_FLOW_BOX(flow), 1);
    gtk_flow_box_set_row_spacing(GTK_FLOW_BOX(flow), 6);
    gtk_flow_box_set_column_spacing(GTK_FLOW_BOX(flow), 6);
    GtkWidget *auto_button = make_button("AUTO", G_CALLBACK(on_strategy_auto_v7), app);
    GtkWidget *smart_button = make_button("SMART AUTO", G_CALLBACK(on_strategy_smart_v7), app);
    GtkWidget *custom_button = make_button("CUSTOM…", G_CALLBACK(on_strategy_custom_v7), app);
    gtk_container_add(GTK_CONTAINER(flow), auto_button);
    gtk_container_add(GTK_CONTAINER(flow), smart_button);
    gtk_container_add(GTK_CONTAINER(flow), custom_button);
    gtk_container_add(GTK_CONTAINER(frame), flow);
    gtk_box_pack_start(GTK_BOX(home), frame, FALSE, FALSE, 4);
    return home;
}

#define build_home_page build_home_page_strategy_v7

/* Shipping Home contract:
 * node location public endpoint actual public VPN exit connection phase logical mode
 * actual runtime actual base fallback DNS latency node latency LAN access kill switch
 * effective MTU warnings Connect Emergency Disconnect /api/home-summary
 * /api/home-summary/prove-exit current-session proof only
 * AUTO /api/strategy/auto SMART AUTO /api/strategy/smart-auto CUSTOM /api/strategy/custom
 * responsive GtkFlowBox strategy controls; CUSTOM requires explicit exact layers.
 */