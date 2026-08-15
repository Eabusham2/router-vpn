#include "routervpn-gtk-product-v4-embedded.c"

/* Product v5: persistent native onboarding + dedicated diagnostics + parity controls. */

static char *onboarding_marker_v5(void) {
    const char *config = g_get_user_config_dir();
    char *dir = g_build_filename(config, "router-vpn", NULL);
    (void)g_mkdir_with_parents(dir, 0700);
    char *path = g_build_filename(dir, "linux-onboarding-v5.done", NULL);
    g_free(dir);
    return path;
}

static void onboarding_finish_v5(GtkAssistant *assistant, gpointer data) {
    (void)data;
    const char *path = g_object_get_data(G_OBJECT(assistant), "router-vpn-onboarding-marker");
    if (path != NULL) (void)g_file_set_contents(path, "done\n", -1, NULL);
    gtk_widget_destroy(GTK_WIDGET(assistant));
}

static void onboarding_cancel_v5(GtkAssistant *assistant, gpointer data) {
    (void)data;
    gtk_widget_destroy(GTK_WIDGET(assistant));
}

static void show_onboarding_v5(App *app, gboolean force) {
    char *path = onboarding_marker_v5();
    if (!force && g_file_test(path, G_FILE_TEST_EXISTS)) {
        g_free(path);
        return;
    }
    static const char *const titles[] = {
        "Welcome to Router VPN",
        "Link a node — do not reinstall",
        "Choose only a real runnable path",
        "DNS, LAN and kill switch",
        "Multihop and external exits",
        "Connect and prove the selected path",
        "Recovery and Full Guide"
    };
    static const char *const bodies[] = {
        "This is the native Linux Router VPN app. Setup Center deploys/administers the home server; this app is the daily VPN client. The local controller at 127.0.0.1:8788 is implementation plumbing, not a browser product.",
        "Install the generic app once. Pair a Router VPN home node with a one-time Setup Center code or import validated Router VPN/external JSON. Adding another home or external node is data linking, not a reinstall.",
        "Start with AUTO or a mode the selected node reports as available. WireGuard/AmneziaWG are compatible bases, not duplicate logical modes. Unsupported graphs stay unavailable instead of being forced green.",
        "Choose Home, Fastest, Custom UDP/TCP, DoT, DoH, DoH3 or Rescue DNS. DNS selection is not proof by itself: runtime DNS proof, LAN policy and kill-switch state must match the active session.",
        "Desktop multihop must be a real entry → exit chain. External WireGuard, SOCKS5, Shadowsocks, Hysteria2 and supported OpenVPN paths must prove the expected public exit; incompatible graphs are rejected.",
        "Connected only becomes true after the selected node/path is proven. Use Diagnostics for session phase, selected-path proof, DNS proof, rollback state and typed events. Prove public VPN exit checks actual egress, not generic Internet reachability.",
        "Emergency stop is separate from strict kill-switch policy. Setup Center Full Guide remains the server/router/admin source of truth and stays independently accessible after this tutorial. Run Tutorial in Help can restart these steps any time."
    };
    GtkWidget *assistant = gtk_assistant_new();
    gtk_window_set_title(GTK_WINDOW(assistant), "Router VPN setup");
    gtk_window_set_transient_for(GTK_WINDOW(assistant), GTK_WINDOW(app->window));
    gtk_window_set_modal(GTK_WINDOW(assistant), TRUE);
    gtk_window_set_default_size(GTK_WINDOW(assistant), 700, 460);
    g_object_set_data_full(G_OBJECT(assistant), "router-vpn-onboarding-marker", path, g_free);
    for (guint i = 0; i < G_N_ELEMENTS(titles); i++) {
        GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);
        gtk_container_set_border_width(GTK_CONTAINER(box), 24);
        GtkWidget *heading = gtk_label_new(NULL);
        char *markup = g_markup_printf_escaped("<span size='xx-large' weight='bold'>%s</span>", titles[i]);
        gtk_label_set_markup(GTK_LABEL(heading), markup);
        g_free(markup);
        gtk_label_set_xalign(GTK_LABEL(heading), 0.0f);
        GtkWidget *body = gtk_label_new(bodies[i]);
        gtk_label_set_xalign(GTK_LABEL(body), 0.0f);
        gtk_label_set_line_wrap(GTK_LABEL(body), TRUE);
        gtk_box_pack_start(GTK_BOX(box), heading, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(box), body, FALSE, FALSE, 0);
        gtk_assistant_append_page(GTK_ASSISTANT(assistant), box);
        gtk_assistant_set_page_title(GTK_ASSISTANT(assistant), box, titles[i]);
        gtk_assistant_set_page_complete(GTK_ASSISTANT(assistant), box, TRUE);
        gtk_assistant_set_page_type(GTK_ASSISTANT(assistant), box,
            i == 0 ? GTK_ASSISTANT_PAGE_INTRO :
            (i == G_N_ELEMENTS(titles) - 1 ? GTK_ASSISTANT_PAGE_CONFIRM : GTK_ASSISTANT_PAGE_CONTENT));
    }
    g_signal_connect(assistant, "apply", G_CALLBACK(onboarding_finish_v5), app);
    g_signal_connect(assistant, "close", G_CALLBACK(onboarding_finish_v5), app);
    g_signal_connect(assistant, "cancel", G_CALLBACK(onboarding_cancel_v5), app);
    gtk_widget_show_all(assistant);
}

static void on_run_tutorial_v5(GtkButton *button, gpointer data) {
    (void)button;
    show_onboarding_v5((App *)data, TRUE);
}

static void on_mtu_retest_v5(GtkButton *button, gpointer data) {
    (void)button;
    post_and_log((App *)data, "/api/mtu/retest", "{}", 130000, "MTU Retest");
}

static GtkWidget *find_button_v5(GtkWidget *root, const char *label) {
    if (root == NULL) return NULL;
    if (GTK_IS_BUTTON(root)) {
        const char *current = gtk_button_get_label(GTK_BUTTON(root));
        if (g_strcmp0(current, label) == 0) return root;
    }
    if (!GTK_IS_CONTAINER(root)) return NULL;
    GList *children = gtk_container_get_children(GTK_CONTAINER(root));
    GtkWidget *match = NULL;
    for (GList *item = children; item != NULL && match == NULL; item = item->next) {
        match = find_button_v5(GTK_WIDGET(item->data), label);
    }
    g_list_free(children);
    return match;
}

static void remember_button_v5(App *app, GtkWidget *root, const char *key, const char *label) {
    GtkWidget *button = find_button_v5(root, label);
    if (button != NULL) g_object_set_data(G_OBJECT(app->window), key, button);
}

static void set_remembered_sensitive_v5(App *app, const char *key, gboolean sensitive) {
    GtkWidget *widget = g_object_get_data(G_OBJECT(app->window), key);
    if (widget != NULL) gtk_widget_set_sensitive(widget, sensitive);
}

static void apply_action_sensitivity_v5(App *app, gboolean connected) {
    gboolean has_node = app->router_ids != NULL && app->router_ids->len > 0;
    gboolean has_mode = has_node && app->mode_combo != NULL &&
                        gtk_combo_box_get_active(GTK_COMBO_BOX(app->mode_combo)) >= 0;

    if (app->router_combo != NULL) gtk_widget_set_sensitive(app->router_combo, has_node);
    if (app->mode_combo != NULL) gtk_widget_set_sensitive(app->mode_combo, has_node);
    if (app->base_combo != NULL) gtk_widget_set_sensitive(app->base_combo, has_node);

    set_remembered_sensitive_v5(app, "router-vpn-home-auto-v5", has_node);
    set_remembered_sensitive_v5(app, "router-vpn-home-disconnect-v5", connected);
    set_remembered_sensitive_v5(app, "router-vpn-home-public-v5", connected);
    set_remembered_sensitive_v5(app, "router-vpn-home-dns-v5", connected);
    set_remembered_sensitive_v5(app, "router-vpn-modes-connect-v5", has_mode);
    set_remembered_sensitive_v5(app, "router-vpn-advanced-mtu-v5", connected);
    set_remembered_sensitive_v5(app, "router-vpn-diag-public-v5", connected);
    set_remembered_sensitive_v5(app, "router-vpn-diag-dns-v5", connected);
    set_remembered_sensitive_v5(app, "router-vpn-diag-mtu-v5", connected);
    /* Emergency stop deliberately remains available even while disconnected so
       a stale helper/runtime can always be torn down. */
}

static gboolean refresh_diagnostics_page_v5(gpointer data) {
    App *app = data;
    GtkWidget *view = g_object_get_data(G_OBJECT(app->window), "router-vpn-diagnostics-v5");
    if (view == NULL) return G_SOURCE_CONTINUE;
    Buffer status = {0}, session = {0}, events = {0};
    char *err_status = NULL, *err_session = NULL, *err_events = NULL;
    gboolean ok_status = api_request("/api/status", "GET", NULL, 1800, &status, &err_status);
    gboolean ok_session = api_request("/api/session", "GET", NULL, 1800, &session, &err_session);
    gboolean ok_events = api_request("/api/session/events?after=0", "GET", NULL, 1800, &events, &err_events);
    gboolean connected = FALSE;
    if (ok_status && status.data != NULL) {
        JsonNode *root = parse_json(status.data);
        if (root != NULL && JSON_NODE_HOLDS_OBJECT(root)) {
            JsonObject *obj = json_node_get_object(root);
            connected = json_object_has_member(obj, "connected") &&
                        json_object_get_boolean_member(obj, "connected");
        }
        if (root != NULL) json_node_free(root);
    }
    apply_action_sensitivity_v5(app, connected);

    GString *text = g_string_new("Router VPN native diagnostics\n\n");
    g_string_append_printf(text, "Status:\n%s\n\n", ok_status && status.data != NULL ? status.data : (err_status != NULL ? err_status : "unavailable"));
    g_string_append_printf(text, "Session / selected-path proof:\n%s\n\n", ok_session && session.data != NULL ? session.data : (err_session != NULL ? err_session : "unavailable"));
    g_string_append_printf(text, "Typed events:\n%s\n", ok_events && events.data != NULL ? events.data : (err_events != NULL ? err_events : "unavailable"));
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(view)), text->str, -1);
    g_string_free(text, TRUE);
    free(status.data); free(session.data); free(events.data);
    g_free(err_status); g_free(err_session); g_free(err_events);
    return G_SOURCE_CONTINUE;
}

static double json_number_v5(JsonObject *obj, const char *key) {
    if (obj == NULL || !json_object_has_member(obj, key)) return 0.0;
    JsonNode *node = json_object_get_member(obj, key);
    return node != NULL && JSON_NODE_HOLDS_VALUE(node) ? json_node_get_double(node) : 0.0;
}

static char *mode_layers_v5(JsonObject *logical) {
    if (logical == NULL || !json_object_has_member(logical, "variants")) return g_strdup("—");
    JsonObject *variants = json_object_get_object_member(logical, "variants");
    if (variants == NULL) return g_strdup("—");
    GHashTable *seen = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    GList *members = json_object_get_members(variants);
    for (GList *it = members; it != NULL; it = it->next) {
        JsonObject *variant = json_object_get_object_member(variants, (const char *)it->data);
        if (variant == NULL || !json_object_has_member(variant, "mode")) continue;
        JsonObject *mode = json_object_get_object_member(variant, "mode");
        JsonArray *layers = mode != NULL && json_object_has_member(mode, "layers") ? json_object_get_array_member(mode, "layers") : NULL;
        if (layers == NULL) continue;
        for (guint i = 0; i < json_array_get_length(layers); i++) {
            const char *layer = json_array_get_string_element(layers, i);
            if (layer != NULL && layer[0] != '\0') g_hash_table_add(seen, g_strdup(layer));
        }
    }
    g_list_free(members);
    GList *keys = g_hash_table_get_keys(seen);
    keys = g_list_sort(keys, (GCompareFunc)g_strcmp0);
    GString *out = g_string_new("");
    for (GList *it = keys; it != NULL; it = it->next) {
        if (out->len > 0) g_string_append(out, " • ");
        g_string_append(out, (const char *)it->data);
    }
    g_list_free(keys);
    g_hash_table_unref(seen);
    return g_string_free(out, FALSE);
}

static void refresh_mode_details_v5(App *app) {
    GtkWidget *view = g_object_get_data(G_OBJECT(app->window), "router-vpn-mode-details-v5");
    if (view == NULL) return;
    Buffer out = {0}; char *err = NULL;
    if (!api_request("/api/logical-modes", "GET", NULL, 3000, &out, &err)) {
        gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(view)), err != NULL ? err : "Mode details unavailable", -1);
        g_free(err); free(out.data); return;
    }
    JsonNode *root = parse_json(out.data);
    GString *text = g_string_new("Logical modes — real runtime readiness plus engineering overhead estimates\n\n");
    if (root != NULL && JSON_NODE_HOLDS_ARRAY(root)) {
        JsonArray *modes = json_node_get_array(root);
        for (guint i = 0; i < json_array_get_length(modes); i++) {
            JsonObject *mode = json_array_get_object_element(modes, i);
            if (mode == NULL) continue;
            gboolean available = json_object_has_member(mode, "available") && json_object_get_boolean_member(mode, "available");
            char *layers = mode_layers_v5(mode);
            GString *bases = g_string_new("");
            JsonArray *ready = json_object_has_member(mode, "ready_bases") ? json_object_get_array_member(mode, "ready_bases") : NULL;
            if (ready != NULL) for (guint j = 0; j < json_array_get_length(ready); j++) {
                if (bases->len > 0) g_string_append(bases, ", ");
                g_string_append(bases, json_array_get_string_element(ready, j));
            }
            g_string_append_printf(text,
                "%s %s\n  %s\n  Layers: %s\n  Added latency %.1f–%.1f ms • traffic +%.1f–%.1f%% • speed loss %.1f–%.1f%%\n  Readiness: %s%s%s\n  Reason: %s\n\n",
                available ? "✓" : "—", obj_string(mode, "name"), obj_string(mode, "description"), layers,
                json_number_v5(mode, "ping_min_ms"), json_number_v5(mode, "ping_max_ms"),
                json_number_v5(mode, "traffic_min_pct"), json_number_v5(mode, "traffic_max_pct"),
                json_number_v5(mode, "speed_loss_min_pct"), json_number_v5(mode, "speed_loss_max_pct"),
                available ? "Ready" : "Unavailable", bases->len > 0 ? " • ready bases: " : "", bases->str,
                obj_string(mode, "reason")[0] ? obj_string(mode, "reason") : (available ? "selected variant is runnable; final Connected still requires path proof" : "no runnable variant"));
            g_free(layers); g_string_free(bases, TRUE);
        }
    } else {
        g_string_append(text, "Mode details response was not a JSON array.\n");
    }
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(view)), text->str, -1);
    g_string_free(text, TRUE);
    if (root != NULL) json_node_free(root);
    free(out.data); g_free(err);
}

static void on_refresh_mode_details_v5(GtkButton *button, gpointer data) {
    (void)button;
    refresh_mode_details_v5((App *)data);
}

static GtkWidget *build_modes_page_v5(App *app) {
    GtkWidget *box = build_modes_page(app);
    GtkWidget *heading = gtk_label_new("Mode details: layers, added latency, traffic overhead, speed loss, readiness and exact reason");
    gtk_label_set_xalign(GTK_LABEL(heading), 0.0f); gtk_label_set_line_wrap(GTK_LABEL(heading), TRUE);
    gtk_box_pack_start(GTK_BOX(box), heading, FALSE, FALSE, 6);
    GtkWidget *view = NULL; GtkWidget *scroll = scrolled_text(&view);
    gtk_widget_set_size_request(scroll, -1, 240);
    g_object_set_data(G_OBJECT(app->window), "router-vpn-mode-details-v5", view);
    gtk_box_pack_start(GTK_BOX(box), scroll, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(box), make_button("Refresh mode details", G_CALLBACK(on_refresh_mode_details_v5), app), FALSE, FALSE, 0);
    return box;
}

static const char *dns_mode_id_v5(GtkWidget *combo) {
    const char *id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(combo));
    return id != NULL ? id : "home";
}

static void dns_set_text_v5(GtkWidget *entry, const char *value) {
    if (entry != NULL) gtk_entry_set_text(GTK_ENTRY(entry), value != NULL ? value : "");
}

static void refresh_dns_page_v5(App *app) {
    GtkWidget *summary = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-summary-v5");
    GtkWidget *mode = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-mode-v5");
    GtkWidget *protocol = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-protocol-v5");
    GtkWidget *host = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-host-v5");
    GtkWidget *port = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-port-v5");
    GtkWidget *server = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-server-v5");
    GtkWidget *path = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-path-v5");
    if (summary == NULL || mode == NULL) return;
    Buffer out = {0}; char *err = NULL;
    if (!api_request("/api/dns/policy", "GET", NULL, 3000, &out, &err)) {
        gtk_label_set_text(GTK_LABEL(summary), err != NULL ? err : "DNS policy unavailable");
        g_free(err); free(out.data); return;
    }
    JsonNode *root = parse_json(out.data);
    if (root != NULL && JSON_NODE_HOLDS_OBJECT(root)) {
        JsonObject *obj = json_node_get_object(root);
        const char *mode_id = obj_string(obj, "mode");
        if (!gtk_combo_box_set_active_id(GTK_COMBO_BOX(mode), mode_id[0] ? mode_id : "home")) gtk_combo_box_set_active(GTK_COMBO_BOX(mode), 0);
        const char *proto = obj_string(obj, "protocol");
        if (!gtk_combo_box_set_active_id(GTK_COMBO_BOX(protocol), proto[0] ? proto : "udp")) gtk_combo_box_set_active(GTK_COMBO_BOX(protocol), 0);
        dns_set_text_v5(host, obj_string(obj, "host"));
        char port_text[16]; g_snprintf(port_text, sizeof(port_text), "%d", json_object_has_member(obj, "port") ? (int)json_object_get_int_member(obj, "port") : 53);
        dns_set_text_v5(port, port_text); dns_set_text_v5(server, obj_string(obj, "server_name")); dns_set_text_v5(path, obj_string(obj, "path"));
        GString *detail = g_string_new("");
        g_string_append_printf(detail, "Selected: %s %s %s:%s\n", mode_id[0] ? mode_id : "home", proto[0] ? proto : "udp", obj_string(obj, "host"), port_text);
        if (json_object_has_member(obj, "fastest_dns_host") && obj_string(obj, "fastest_dns_host")[0]) {
            g_string_append_printf(detail, "Fastest measured: %s • %.2f ms • %s\n", obj_string(obj, "fastest_dns_name"), json_number_v5(obj, "fastest_dns_latency_ms"), obj_string(obj, "fastest_dns_host"));
        }
        JsonArray *results = json_object_has_member(obj, "results") ? json_object_get_array_member(obj, "results") : NULL;
        if (results != NULL) for (guint i = 0; i < json_array_get_length(results); i++) {
            JsonObject *r = json_array_get_object_element(results, i); if (r == NULL) continue;
            gboolean working = json_object_has_member(r, "working") && json_object_get_boolean_member(r, "working");
            g_string_append_printf(detail, "%s • %s • %s\n", obj_string(r, "name"), obj_string(r, "address"), working ? g_strdup_printf("%.2f ms", json_number_v5(r, "latency_ms")) : "failed");
        }
        g_string_append(detail, "\nBenchmark RTT = real A/AAAA DNS query time measured from the selected home node, not ICMP. Saving policy is not active-runtime proof; reconnect and session proof still decide that.");
        gtk_label_set_text(GTK_LABEL(summary), detail->str); g_string_free(detail, TRUE);
    }
    if (root != NULL) json_node_free(root); free(out.data); g_free(err);
}

static void on_dns_preset_v5(GtkComboBox *combo, gpointer data) {
    App *app = data;
    GtkWidget *host = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-host-v5");
    GtkWidget *server = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-server-v5");
    const char *id = gtk_combo_box_get_active_id(combo);
    if (id == NULL || strcmp(id, "manual") == 0) return;
    struct Preset { const char *id, *host, *server; } presets[] = {
        {"cf4","1.1.1.1","cloudflare-dns.com"},{"cf6","2606:4700:4700::1111","cloudflare-dns.com"},
        {"g4","8.8.8.8","dns.google"},{"g6","2001:4860:4860::8888","dns.google"},
        {"q4","9.9.9.9","dns.quad9.net"},{"q6","2620:fe::fe","dns.quad9.net"}
    };
    for (guint i = 0; i < G_N_ELEMENTS(presets); i++) if (strcmp(id, presets[i].id) == 0) {
        dns_set_text_v5(host, presets[i].host); dns_set_text_v5(server, presets[i].server); return;
    }
}

static void on_save_dns_v5(GtkButton *button, gpointer data) {
    (void)button; App *app = data;
    GtkWidget *mode = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-mode-v5");
    GtkWidget *protocol = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-protocol-v5");
    GtkWidget *host = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-host-v5");
    GtkWidget *port = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-port-v5");
    GtkWidget *server = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-server-v5");
    GtkWidget *path = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-path-v5");
    JsonBuilder *builder = json_builder_new(); json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "mode"); json_builder_add_string_value(builder, dns_mode_id_v5(mode));
    json_builder_set_member_name(builder, "protocol"); json_builder_add_string_value(builder, dns_mode_id_v5(protocol));
    json_builder_set_member_name(builder, "host"); json_builder_add_string_value(builder, gtk_entry_get_text(GTK_ENTRY(host)));
    json_builder_set_member_name(builder, "port"); json_builder_add_int_value(builder, (gint64)g_ascii_strtoll(gtk_entry_get_text(GTK_ENTRY(port)), NULL, 10));
    json_builder_set_member_name(builder, "server_name"); json_builder_add_string_value(builder, gtk_entry_get_text(GTK_ENTRY(server)));
    json_builder_set_member_name(builder, "path"); json_builder_add_string_value(builder, gtk_entry_get_text(GTK_ENTRY(path)));
    json_builder_end_object(builder); JsonGenerator *gen = json_generator_new(); JsonNode *root = json_builder_get_root(builder); json_generator_set_root(gen, root); char *payload = json_generator_to_data(gen, NULL);
    Buffer out = {0}; char *err = NULL;
    if (api_request("/api/dns/policy", "POST", payload, 5000, &out, &err)) append_diag(app, "DNS policy saved for the next connection. Reconnect and use session DNS proof to verify active enforcement.");
    else append_diag(app, err != NULL ? err : "DNS policy save failed");
    free(out.data); g_free(err); g_free(payload); json_node_free(root); g_object_unref(gen); g_object_unref(builder);
    refresh_dns_page_v5(app);
}

static void on_dns_retest_v5(GtkButton *button, gpointer data) {
    (void)button; App *app = data;
    post_and_log(app, "/api/dns/retest", "{}", 90000, "DNS Retest");
    refresh_dns_page_v5(app);
}

static void on_refresh_dns_v5(GtkButton *button, gpointer data) { (void)button; refresh_dns_page_v5((App *)data); }

static GtkWidget *build_dns_page_v5(App *app) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8); gtk_container_set_border_width(GTK_CONTAINER(box), 16);
    GtkWidget *title = gtk_label_new(NULL); gtk_label_set_markup(GTK_LABEL(title), "<span size='x-large' weight='bold'>DNS</span>"); gtk_label_set_xalign(GTK_LABEL(title), 0.0f); gtk_box_pack_start(GTK_BOX(box), title, FALSE, FALSE, 0);
    GtkWidget *note = gtk_label_new("Choose Home, Fastest, Custom UDP/TCP, DoT, DoH, DoH3 or Rescue. Common IPv4/IPv6 resolvers are convenience presets. Disconnect before changing policy; the next connection applies it, and session proof remains authoritative."); gtk_label_set_xalign(GTK_LABEL(note),0.0f);gtk_label_set_line_wrap(GTK_LABEL(note),TRUE);gtk_box_pack_start(GTK_BOX(box),note,FALSE,FALSE,0);
    GtkWidget *grid = gtk_grid_new(); gtk_grid_set_row_spacing(GTK_GRID(grid),6); gtk_grid_set_column_spacing(GTK_GRID(grid),10);
    GtkWidget *mode = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(mode),"home","Home AdGuard");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(mode),"fastest","Fastest measured");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(mode),"custom","Custom UDP/TCP");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(mode),"dot","DNS-over-TLS");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(mode),"doh","DNS-over-HTTPS");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(mode),"doh3","DNS-over-HTTP/3");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(mode),"rescue","DNS Rescue");
    GtkWidget *protocol=gtk_combo_box_text_new();gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(protocol),"udp","UDP");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(protocol),"tcp","TCP");
    GtkWidget *preset=gtk_combo_box_text_new();gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(preset),"manual","Manual/current");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(preset),"cf4","Cloudflare IPv4 — 1.1.1.1");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(preset),"cf6","Cloudflare IPv6 — 2606:4700:4700::1111");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(preset),"g4","Google IPv4 — 8.8.8.8");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(preset),"g6","Google IPv6 — 2001:4860:4860::8888");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(preset),"q4","Quad9 IPv4 — 9.9.9.9");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(preset),"q6","Quad9 IPv6 — 2620:fe::fe");gtk_combo_box_set_active(GTK_COMBO_BOX(preset),0);
    GtkWidget *host=gtk_entry_new(),*port=gtk_entry_new(),*server=gtk_entry_new(),*path=gtk_entry_new();gtk_entry_set_placeholder_text(GTK_ENTRY(host),"resolver host / IPv4 / IPv6");gtk_entry_set_placeholder_text(GTK_ENTRY(port),"port");gtk_entry_set_placeholder_text(GTK_ENTRY(server),"TLS server name");gtk_entry_set_placeholder_text(GTK_ENTRY(path),"/dns-query");
    const char *labels[]={"Mode","Custom protocol","Common resolver","Host","Port","TLS server name","HTTPS path"};GtkWidget *widgets[]={mode,protocol,preset,host,port,server,path};for(guint i=0;i<G_N_ELEMENTS(widgets);i++){GtkWidget*l=gtk_label_new(labels[i]);gtk_label_set_xalign(GTK_LABEL(l),1.0f);gtk_grid_attach(GTK_GRID(grid),l,0,(gint)i,1,1);gtk_grid_attach(GTK_GRID(grid),widgets[i],1,(gint)i,1,1);}
    gtk_box_pack_start(GTK_BOX(box),grid,FALSE,FALSE,0);GtkWidget *row=gtk_box_new(GTK_ORIENTATION_HORIZONTAL,8);gtk_box_pack_start(GTK_BOX(row),make_button("Save DNS policy",G_CALLBACK(on_save_dns_v5),app),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(row),make_button("Retest DNS RTT",G_CALLBACK(on_dns_retest_v5),app),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(row),make_button("Refresh DNS",G_CALLBACK(on_refresh_dns_v5),app),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(box),row,FALSE,FALSE,0);
    GtkWidget *summary=gtk_label_new("DNS policy not loaded yet.");gtk_label_set_xalign(GTK_LABEL(summary),0.0f);gtk_label_set_yalign(GTK_LABEL(summary),0.0f);gtk_label_set_line_wrap(GTK_LABEL(summary),TRUE);GtkWidget *scroll=gtk_scrolled_window_new(NULL,NULL);gtk_container_add(GTK_CONTAINER(scroll),summary);gtk_box_pack_start(GTK_BOX(box),scroll,TRUE,TRUE,0);
    g_object_set_data(G_OBJECT(app->window),"router-vpn-dns-summary-v5",summary);g_object_set_data(G_OBJECT(app->window),"router-vpn-dns-mode-v5",mode);g_object_set_data(G_OBJECT(app->window),"router-vpn-dns-protocol-v5",protocol);g_object_set_data(G_OBJECT(app->window),"router-vpn-dns-host-v5",host);g_object_set_data(G_OBJECT(app->window),"router-vpn-dns-port-v5",port);g_object_set_data(G_OBJECT(app->window),"router-vpn-dns-server-v5",server);g_object_set_data(G_OBJECT(app->window),"router-vpn-dns-path-v5",path);g_signal_connect(preset,"changed",G_CALLBACK(on_dns_preset_v5),app);
    return box;
}

static GtkWidget *build_advanced_page_v5(App *app) {
    GtkWidget *box = make_info_page(
        "Advanced",
        "MTU/Jumbo, LAN access, kill switch, Router VPN multihop and external entry/exit compatibility remain controller-owned so native UI cannot claim settings the dataplane did not apply. MTU Retest is accepted only while one Router VPN node is connected with Auto MTU; it compares bounded private-node loss/RTT/throughput candidates, caches by network/path context, and does not claim MTU caused an earlier cellular regression.");
    gtk_box_pack_start(GTK_BOX(box), make_button("Retest MTU", G_CALLBACK(on_mtu_retest_v5), app), FALSE, FALSE, 0);
    return box;
}

static GtkWidget *build_diagnostics_page_v5(App *app) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(box), 16);
    GtkWidget *heading = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(heading), "<span size='x-large' weight='bold'>Diagnostics</span>");
    gtk_label_set_xalign(GTK_LABEL(heading), 0.0f);
    GtkWidget *note = gtk_label_new("Read-only current status, exact selected-path proof, DNS proof, rollback state and typed session events. Generic Internet reachability alone is never accepted as connection proof. MTU Retest logs the effective MTU/source and measured private-node throughput/RTT/success returned by the local controller.");
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(note), TRUE);
    gtk_box_pack_start(GTK_BOX(box), heading, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), note, FALSE, FALSE, 0);
    GtkWidget *view = NULL;
    GtkWidget *scroll = scrolled_text(&view);
    g_object_set_data(G_OBJECT(app->window), "router-vpn-diagnostics-v5", view);
    gtk_box_pack_start(GTK_BOX(box), scroll, TRUE, TRUE, 0);
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(row), make_button("Prove public VPN exit", G_CALLBACK(on_public_ip), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Retest DNS", G_CALLBACK(on_dns), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Retest MTU", G_CALLBACK(on_mtu_retest_v5), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Emergency stop", G_CALLBACK(on_emergency), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), row, FALSE, FALSE, 0);
    return box;
}

static GtkWidget *build_help_page_v5(App *app) {
    GtkWidget *box = make_info_page("Help", "Pair a Router VPN home node or import validated Router VPN/external JSON. External direct or entry → exit connect succeeds only after its exact expected public exit is proven. Setup Center Full Guide remains the server/router administration source of truth.");
    gtk_box_pack_start(GTK_BOX(box), make_button("Run Tutorial", G_CALLBACK(on_run_tutorial_v5), app), FALSE, FALSE, 0);
    return box;
}

static void build_ui_v5(App *app) {
    app->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(app->window), "Router VPN");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 960, 680);
    gtk_window_set_default_icon_name("router-vpn");
    GtkNotebook *tabs = GTK_NOTEBOOK(gtk_notebook_new());
    gtk_notebook_set_scrollable(tabs, TRUE);

    GtkWidget *home = build_home_page(app);
    add_tab(tabs, home, "Home / Connect");
    remember_button_v5(app, home, "router-vpn-home-auto-v5", "AUTO Connect");
    remember_button_v5(app, home, "router-vpn-home-disconnect-v5", "Disconnect");
    remember_button_v5(app, home, "router-vpn-home-public-v5", "Prove public VPN exit");
    remember_button_v5(app, home, "router-vpn-home-dns-v5", "Retest DNS");

    add_tab(tabs, build_nodes_page_v4(app), "Nodes & Map");

    GtkWidget *modes = build_modes_page_v5(app);
    add_tab(tabs, modes, "Modes");
    remember_button_v5(app, modes, "router-vpn-modes-connect-v5", "Connect Selected");

    add_tab(tabs, build_dns_page_v5(app), "DNS");
    GtkWidget *advanced = build_advanced_page_v5(app);
    add_tab(tabs, advanced, "Advanced");
    remember_button_v5(app, advanced, "router-vpn-advanced-mtu-v5", "Retest MTU");
    add_tab(tabs, make_info_page("Forwarding", "Incoming forwarding is available only when the active routable Router VPN dataplane can implement it. Proxy-only/external modes never pretend arbitrary DNAT is available."), "Forwarding");
    add_tab(tabs, make_info_page("Settings", "Router VPN Linux talks only to the fixed local controller at 127.0.0.1:8788. External protocol credentials remain in the private 0600 profile store and are redacted from public node/profile APIs."), "Settings");
    add_tab(tabs, build_help_page_v5(app), "Help");

    GtkWidget *diagnostics = build_diagnostics_page_v5(app);
    add_tab(tabs, diagnostics, "Diagnostics");
    remember_button_v5(app, diagnostics, "router-vpn-diag-public-v5", "Prove public VPN exit");
    remember_button_v5(app, diagnostics, "router-vpn-diag-dns-v5", "Retest DNS");
    remember_button_v5(app, diagnostics, "router-vpn-diag-mtu-v5", "Retest MTU");

    gtk_container_add(GTK_CONTAINER(app->window), GTK_WIDGET(tabs));
}

static int self_test_v5(void) {
    if (self_test_v4() != 0) return 2;
    static const char *const visual_contract[] = {
        "Diagnostics", "Run Tutorial", "linux-onboarding-v5.done",
        "/api/session/events?after=0", "truthful-empty-state-actions", "/api/mtu/retest",
        "/api/dns/policy", "Mode details", "Added latency", "DoH3", "gtk_notebook_set_scrollable"
    };
    if (G_N_ELEMENTS(visual_contract) != 11 || visual_contract[0][0] != 'D') return 3;
    puts("Router VPN native Linux v5 onboarding/diagnostics/mode-metrics/DNS product self-test: OK");
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--self-test") == 0) return self_test_v5();
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        fprintf(stderr, "Router VPN: libcurl global initialization failed\n");
        return 2;
    }
    if (!gtk_init_check(&argc, &argv)) {
        fprintf(stderr, "Router VPN: no usable graphical display is available\n");
        curl_global_cleanup();
        return 2;
    }
    App app = {0};
    app.nodes = g_ptr_array_new_with_free_func(free_map_node);
    app.router_ids = g_ptr_array_new_with_free_func(g_free);
    app.mode_ids = g_ptr_array_new_with_free_func(g_free);
    if (!resolve_package_root(&app, argv[0])) {
        fprintf(stderr, "Router VPN: cannot resolve package root\n");
        g_ptr_array_unref(app.nodes); g_ptr_array_unref(app.router_ids); g_ptr_array_unref(app.mode_ids);
        curl_global_cleanup();
        return 2;
    }
    char *error = NULL;
    if (!ensure_controller(&app, &error)) {
        GtkWidget *dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR,
                                                   GTK_BUTTONS_CLOSE, "Router VPN could not start: %s",
                                                   error != NULL ? error : "unknown error");
        (void)gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        g_free(error); g_free(app.package_root);
        g_ptr_array_unref(app.nodes); g_ptr_array_unref(app.router_ids); g_ptr_array_unref(app.mode_ids);
        curl_global_cleanup();
        return 3;
    }
    build_ui_v5(&app);
    g_signal_connect(app.window, "destroy", G_CALLBACK(on_destroy), &app);
    refresh_all(&app);
    refresh_mode_details_v5(&app);
    refresh_dns_page_v5(&app);
    (void)g_timeout_add_seconds(2, refresh_timer, &app);
    (void)g_timeout_add_seconds(2, refresh_diagnostics_page_v5, &app);
    refresh_diagnostics_page_v5(&app);
    gtk_widget_show_all(app.window);
    show_onboarding_v5(&app, FALSE);
    gtk_main();
    g_free(app.package_root);
    g_ptr_array_unref(app.nodes); g_ptr_array_unref(app.router_ids); g_ptr_array_unref(app.mode_ids);
    curl_global_cleanup();
    return 0;
}
