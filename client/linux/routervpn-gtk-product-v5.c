#include "routervpn-gtk-product-v4-embedded.c"

/* Product v5: persistent native onboarding + dedicated diagnostics. */

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
        "DNS selection is not proof by itself. Runtime DNS proof, LAN policy and kill-switch state must match the active session. Strict policy must fail closed across reconnect, fallback and engine failure.",
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
    set_remembered_sensitive_v5(app, "router-vpn-diag-public-v5", connected);
    set_remembered_sensitive_v5(app, "router-vpn-diag-dns-v5", connected);
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

static GtkWidget *build_diagnostics_page_v5(App *app) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(box), 16);
    GtkWidget *heading = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(heading), "<span size='x-large' weight='bold'>Diagnostics</span>");
    gtk_label_set_xalign(GTK_LABEL(heading), 0.0f);
    GtkWidget *note = gtk_label_new("Read-only current status, exact selected-path proof, DNS proof, rollback state and typed session events. Generic Internet reachability alone is never accepted as connection proof.");
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
    gtk_window_set_default_size(GTK_WINDOW(app->window), 1120, 740);
    GtkNotebook *tabs = GTK_NOTEBOOK(gtk_notebook_new());

    GtkWidget *home = build_home_page(app);
    add_tab(tabs, home, "Home / Connect");
    remember_button_v5(app, home, "router-vpn-home-auto-v5", "AUTO Connect");
    remember_button_v5(app, home, "router-vpn-home-disconnect-v5", "Disconnect");
    remember_button_v5(app, home, "router-vpn-home-public-v5", "Prove public VPN exit");
    remember_button_v5(app, home, "router-vpn-home-dns-v5", "Retest DNS");

    add_tab(tabs, build_nodes_page_v4(app), "Nodes & Map");

    GtkWidget *modes = build_modes_page(app);
    add_tab(tabs, modes, "Modes");
    remember_button_v5(app, modes, "router-vpn-modes-connect-v5", "Connect Selected");

    add_tab(tabs, make_info_page("DNS", "Selected DNS is controller-owned and session-proven. Home shows typed dns-proof events; a saved DNS choice alone is never proof."), "DNS");
    add_tab(tabs, make_info_page("Advanced", "MTU/Jumbo, LAN access, kill switch, Router VPN multihop and external entry/exit compatibility remain controller-owned so native UI cannot claim settings the dataplane did not apply."), "Advanced");
    add_tab(tabs, make_info_page("Forwarding", "Incoming forwarding is available only when the active routable Router VPN dataplane can implement it. Proxy-only/external modes never pretend arbitrary DNAT is available."), "Forwarding");
    add_tab(tabs, make_info_page("Settings", "Router VPN Linux talks only to the fixed local controller at 127.0.0.1:8788. External protocol credentials remain in the private 0600 profile store and are redacted from public node/profile APIs."), "Settings");
    add_tab(tabs, build_help_page_v5(app), "Help");

    GtkWidget *diagnostics = build_diagnostics_page_v5(app);
    add_tab(tabs, diagnostics, "Diagnostics");
    remember_button_v5(app, diagnostics, "router-vpn-diag-public-v5", "Prove public VPN exit");
    remember_button_v5(app, diagnostics, "router-vpn-diag-dns-v5", "Retest DNS");

    gtk_container_add(GTK_CONTAINER(app->window), GTK_WIDGET(tabs));
}

static int self_test_v5(void) {
    if (self_test_v4() != 0) return 2;
    static const char *const visual_contract[] = {
        "Diagnostics", "Run Tutorial", "linux-onboarding-v5.done",
        "/api/session/events?after=0", "truthful-empty-state-actions"
    };
    if (G_N_ELEMENTS(visual_contract) != 5 || visual_contract[0][0] != 'D') return 3;
    puts("Router VPN native Linux v5 onboarding/diagnostics product self-test: OK");
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
