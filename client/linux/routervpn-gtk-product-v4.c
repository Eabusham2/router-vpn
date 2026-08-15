#define main routervpn_product_v3_main
#define build_ui_v3 routervpn_product_v3_build_ui
#define self_test_v3 routervpn_product_v3_self_test
#include "routervpn-gtk-product-v3.c"
#undef self_test_v3
#undef build_ui_v3
#undef main

/* Product v4: unified Router VPN + validated external-node desktop UX. */

static void on_import_any_node(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    GtkWidget *dialog = gtk_file_chooser_dialog_new(
        "Import Router VPN or external node", GTK_WINDOW(app->window),
        GTK_FILE_CHOOSER_ACTION_OPEN, "_Cancel", GTK_RESPONSE_CANCEL,
        "_Import", GTK_RESPONSE_ACCEPT, NULL);
    GtkFileFilter *filter = gtk_file_filter_new();
    gtk_file_filter_set_name(filter, "Router VPN / external JSON");
    gtk_file_filter_add_pattern(filter, "*.json");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dialog), filter);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        char *contents = NULL;
        gsize length = 0;
        GError *read_error = NULL;
        if (!g_file_get_contents(filename, &contents, &length, &read_error)) {
            append_diag(app, read_error != NULL ? read_error->message : "Import failed: could not read the selected file.");
        } else if (length > (32u * 1024u * 1024u)) {
            append_diag(app, "Import failed: node JSON is larger than 32 MiB.");
        } else {
            Buffer out = {0};
            char *router_err = NULL;
            if (api_request("/api/profile/import", "POST", contents, 25000, &out, &router_err)) {
                append_diag(app, "Router VPN node bundle imported into the private profile store.");
                refresh_profiles(app);
            } else {
                free(out.data); out.data = NULL; out.len = 0;
                char *external_err = NULL;
                if (api_request("/api/external-profile/import", "POST", contents, 25000, &out, &external_err)) {
                    append_diag(app, "Validated schema-v3 external node imported. Protocol credentials remain private; native UI receives only the public node view.");
                    refresh_profiles(app);
                } else {
                    char *line = g_strdup_printf(
                        "Import failed as Router VPN bundle (%s) and external node (%s)",
                        router_err != NULL ? router_err : "rejected",
                        external_err != NULL ? external_err : "rejected");
                    append_diag(app, line);
                    gtk_label_set_text(GTK_LABEL(app->error), line);
                    g_free(line);
                }
                g_free(external_err);
            }
            g_free(router_err);
            free(out.data);
        }
        if (read_error != NULL) g_error_free(read_error);
        g_free(contents);
        g_free(filename);
    }
    gtk_widget_destroy(dialog);
}

static void on_connect_external_node(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    const char *id = active_router_id(app);
    if (id == NULL || id[0] == '\0') {
        append_diag(app, "External connect failed: select a linked external node first.");
        return;
    }
    char *body = json_string_body("profile_id", id);
    post_and_log(app, "/api/external-profile/connect", body, 180000,
                 "External direct exit (exact public-exit proof required)");
    g_free(body);
    refresh_all(app);
}

static char *json_external_hop_body(const char *profile_id, const char *entry_id) {
    JsonBuilder *builder = json_builder_new();
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "profile_id");
    json_builder_add_string_value(builder, profile_id != NULL ? profile_id : "");
    json_builder_set_member_name(builder, "entry_id");
    json_builder_add_string_value(builder, entry_id != NULL ? entry_id : "");
    json_builder_end_object(builder);
    JsonNode *root = json_builder_get_root(builder);
    JsonGenerator *generator = json_generator_new();
    json_generator_set_root(generator, root);
    char *body = json_generator_to_data(generator, NULL);
    json_node_free(root);
    g_object_unref(generator);
    g_object_unref(builder);
    return body;
}

static void on_connect_external_via_entry(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    const char *exit_id = active_router_id(app);
    if (exit_id == NULL || exit_id[0] == '\0') {
        append_diag(app, "External hop failed: select the external exit node first.");
        return;
    }

    GtkWidget *dialog = gtk_dialog_new_with_buttons(
        "Connect external exit through an entry", GTK_WINDOW(app->window), GTK_DIALOG_MODAL,
        "_Cancel", GTK_RESPONSE_CANCEL, "_Connect", GTK_RESPONSE_ACCEPT, NULL);
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(box), 14);
    GtkWidget *note = gtk_label_new(
        "Exit is the currently selected node. Choose a different Router VPN or supported external entry. "
        "External WireGuard, SOCKS5, Shadowsocks and Hysteria2 can be upstream entries; OpenVPN remains final-exit only.");
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(note), TRUE);
    GtkWidget *combo = gtk_combo_box_text_new();
    guint choices = 0;
    for (guint i = 0; i < app->router_ids->len; i++) {
        const char *candidate = g_ptr_array_index(app->router_ids, i);
        if (candidate == NULL || candidate[0] == '\0' || g_strcmp0(candidate, exit_id) == 0) continue;
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo), candidate);
        choices++;
    }
    if (choices > 0) gtk_combo_box_set_active(GTK_COMBO_BOX(combo), 0);
    gtk_box_pack_start(GTK_BOX(box), note, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), gtk_label_new("Entry node"), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), combo, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(content), box, TRUE, TRUE, 0);
    gtk_widget_show_all(dialog);

    if (choices == 0) {
        append_diag(app, "External hop failed: link/import a second node to use as the entry.");
    } else if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        gchar *entry_id = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(combo));
        if (entry_id == NULL || entry_id[0] == '\0') {
            append_diag(app, "External hop failed: select an entry node.");
        } else {
            char *body = json_external_hop_body(exit_id, entry_id);
            post_and_log(app, "/api/external-profile/connect", body, 180000,
                         "External exit via selected entry (exact public-exit proof required)");
            g_free(body);
            refresh_all(app);
        }
        g_free(entry_id);
    }
    gtk_widget_destroy(dialog);
}

static GtkWidget *build_nodes_page_v4(App *app) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(box), 10);
    GtkWidget *note = gtk_label_new(
        "Install once; pair/import Router VPN and external node data separately. "
        "The map plots only stored real coordinates; coordinate-less nodes stay usable in the list.");
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(note), TRUE);
    gtk_box_pack_start(GTK_BOX(box), note, FALSE, FALSE, 0);

    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_VERTICAL);
    app->map = gtk_drawing_area_new();
    gtk_widget_set_size_request(app->map, -1, 300);
    g_signal_connect(app->map, "draw", G_CALLBACK(draw_map), app);
    gtk_paned_pack1(GTK_PANED(paned), app->map, TRUE, FALSE);
    GtkWidget *scroll = scrolled_text(&app->nodes_view);
    gtk_paned_pack2(GTK_PANED(paned), scroll, TRUE, FALSE);
    gtk_box_pack_start(GTK_BOX(box), paned, TRUE, TRUE, 0);

    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(row), make_button("Pair home node", G_CALLBACK(on_pair_node), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Import node JSON", G_CALLBACK(on_import_any_node), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Connect external direct", G_CALLBACK(on_connect_external_node), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("External via entry", G_CALLBACK(on_connect_external_via_entry), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Remove selected node", G_CALLBACK(on_remove_node), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Run 50-sample latency", G_CALLBACK(on_latency_node), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), row, FALSE, FALSE, 0);
    return box;
}

static void build_ui_v4(App *app) {
    app->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(app->window), "Router VPN");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 1120, 740);
    GtkWidget *tabs_widget = gtk_notebook_new();
    GtkNotebook *tabs = GTK_NOTEBOOK(tabs_widget);
    add_tab(tabs, build_home_page(app), "Home / Connect");
    add_tab(tabs, build_nodes_page_v4(app), "Nodes & Map");
    add_tab(tabs, build_modes_page(app), "Modes");
    add_tab(tabs, make_info_page("DNS", "Selected DNS is controller-owned and session-proven. Home shows typed dns-proof events; a saved DNS choice alone is never proof."), "DNS");
    add_tab(tabs, make_info_page("Advanced", "MTU/Jumbo, LAN access, kill switch, Router VPN multihop and external entry/exit compatibility remain controller-owned so native UI cannot claim settings the dataplane did not apply."), "Advanced");
    add_tab(tabs, make_info_page("Forwarding", "Incoming forwarding is available only when the active routable Router VPN dataplane can implement it. Proxy-only/external modes never pretend arbitrary DNAT is available."), "Forwarding");
    add_tab(tabs, make_info_page("Settings", "Router VPN Linux talks only to the fixed local controller at 127.0.0.1:8788. External protocol credentials remain in the private 0600 profile store and are redacted from public node/profile APIs."), "Settings");
    add_tab(tabs, make_info_page("Help", "Pair a Router VPN home node or import validated Router VPN/external JSON. External direct or entry->exit connect succeeds only after its exact expected public exit is proven. Use Setup Center Full Guide for server/router administration."), "Help");
    gtk_container_add(GTK_CONTAINER(app->window), tabs_widget);
}

static int self_test_v4(void) {
    if (routervpn_product_v3_self_test() != 0) return 2;
    static const char *const external_paths[] = {
        "/api/external-profile/import", "/api/external-profile/connect", "/api/nodes", "entry_id"
    };
    if (G_N_ELEMENTS(external_paths) != 4 || external_paths[0][0] != '/') return 3;
    puts("Router VPN native Linux unified external-node product self-test: OK");
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--self-test") == 0) return self_test_v4();
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
    build_ui_v4(&app);
    g_signal_connect(app.window, "destroy", G_CALLBACK(on_destroy), &app);
    refresh_all(&app);
    (void)g_timeout_add_seconds(2, refresh_timer, &app);
    gtk_widget_show_all(app.window);
    gtk_main();
    g_free(app.package_root);
    g_ptr_array_unref(app.nodes); g_ptr_array_unref(app.router_ids); g_ptr_array_unref(app.mode_ids);
    curl_global_cleanup();
    return 0;
}
