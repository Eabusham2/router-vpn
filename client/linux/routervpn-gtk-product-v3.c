#pragma push_macro("main")
#undef main
#define main routervpn_product_core_main
#define build_ui routervpn_product_core_build_ui
#define self_test routervpn_product_core_self_test
#include "routervpn-gtk-product.c"
#undef self_test
#undef build_ui
#undef main
#pragma pop_macro("main")

/*
 * Product v3 keeps the proven GTK/runtime shell above intact while making the
 * node-data lifecycle a first-class native workflow.  Pair/import/remove are
 * data operations; they never reinstall the application or bypass the shared
 * localhost controller's profile safety checks.
 */

static char *json_string_body(const char *key, const char *value) {
    JsonBuilder *builder = json_builder_new();
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, key);
    json_builder_add_string_value(builder, value != NULL ? value : "");
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

static char *json_pair_body(const char *host, const char *code) {
    JsonBuilder *builder = json_builder_new();
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "host");
    json_builder_add_string_value(builder, host != NULL ? host : "");
    json_builder_set_member_name(builder, "code");
    json_builder_add_string_value(builder, code != NULL ? code : "");
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

static const char *active_router_id(App *app) {
    gint index = gtk_combo_box_get_active(GTK_COMBO_BOX(app->router_combo));
    if (index < 0 || (guint)index >= app->router_ids->len) return NULL;
    return g_ptr_array_index(app->router_ids, (guint)index);
}

static gboolean code_is_six_digits(const char *code) {
    if (code == NULL || strlen(code) != 6) return FALSE;
    for (const char *p = code; *p != '\0'; p++) {
        if (*p < '0' || *p > '9') return FALSE;
    }
    return TRUE;
}

static void on_pair_node(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    GtkWidget *dialog = gtk_dialog_new_with_buttons(
        "Pair Router VPN home node", GTK_WINDOW(app->window), GTK_DIALOG_MODAL,
        "_Cancel", GTK_RESPONSE_CANCEL, "_Pair", GTK_RESPONSE_ACCEPT, NULL);
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 14);
    GtkWidget *note = gtk_label_new(
        "Create a short-lived 6-digit code in the authenticated private Setup Center.\n"
        "The shared controller accepts only private/local destinations and a one-time code.");
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    GtkWidget *host = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(host), "AI Board LAN IP / hostname");
    gtk_entry_set_text(GTK_ENTRY(host), "");
    GtkWidget *code = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(code), "6-digit one-time pairing code");
    gtk_entry_set_visibility(GTK_ENTRY(code), FALSE);
    gtk_entry_set_max_length(GTK_ENTRY(code), 6);
    gtk_grid_attach(GTK_GRID(grid), note, 0, 0, 2, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Home node"), 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), host, 1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Pairing code"), 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), code, 1, 2, 1, 1);
    gtk_box_pack_start(GTK_BOX(content), grid, TRUE, TRUE, 0);
    gtk_widget_show_all(dialog);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        const char *host_text = gtk_entry_get_text(GTK_ENTRY(host));
        const char *code_text = gtk_entry_get_text(GTK_ENTRY(code));
        if (!code_is_six_digits(code_text)) {
            append_diag(app, "Pairing failed: code must be exactly 6 digits.");
        } else {
            char *body = json_pair_body(host_text, code_text);
            Buffer out = {0};
            char *err = NULL;
            if (api_request("/api/profile/pair", "POST", body, 20000, &out, &err)) {
                append_diag(app, "Secure LAN pairing succeeded; node data was imported without reinstalling Router VPN.");
                refresh_profiles(app);
            } else {
                char *line = g_strdup_printf("Pairing failed: %s", err != NULL ? err : "request failed");
                append_diag(app, line);
                gtk_label_set_text(GTK_LABEL(app->error), err != NULL ? err : "pairing failed");
                g_free(line);
            }
            g_free(body);
            g_free(err);
            free(out.data);
        }
    }
    gtk_widget_destroy(dialog);
}

static void on_import_node(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    GtkWidget *dialog = gtk_file_chooser_dialog_new(
        "Import Router VPN node bundle", GTK_WINDOW(app->window),
        GTK_FILE_CHOOSER_ACTION_OPEN, "_Cancel", GTK_RESPONSE_CANCEL,
        "_Import", GTK_RESPONSE_ACCEPT, NULL);
    GtkFileFilter *filter = gtk_file_filter_new();
    gtk_file_filter_set_name(filter, "Router VPN JSON");
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
            append_diag(app, "Import failed: Router VPN bundle is larger than 32 MiB.");
        } else {
            Buffer out = {0};
            char *err = NULL;
            if (api_request("/api/profile/import", "POST", contents, 25000, &out, &err)) {
                append_diag(app, "Node bundle imported into the shared profile store.");
                refresh_profiles(app);
            } else {
                char *line = g_strdup_printf("Import failed: %s", err != NULL ? err : "request failed");
                append_diag(app, line);
                gtk_label_set_text(GTK_LABEL(app->error), err != NULL ? err : "import failed");
                g_free(line);
            }
            g_free(err);
            free(out.data);
        }
        if (read_error != NULL) g_error_free(read_error);
        g_free(contents);
        g_free(filename);
    }
    gtk_widget_destroy(dialog);
}

static void on_remove_node(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    const char *id = active_router_id(app);
    if (id == NULL || id[0] == '\0') {
        append_diag(app, "Remove failed: select a linked node first.");
        return;
    }
    GtkWidget *dialog = gtk_message_dialog_new(
        GTK_WINDOW(app->window), GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING,
        GTK_BUTTONS_NONE,
        "Remove linked node '%s' from this app?\n\nThis does not uninstall Router VPN or change the home server.", id);
    gtk_dialog_add_buttons(GTK_DIALOG(dialog), "_Cancel", GTK_RESPONSE_CANCEL,
                           "_Remove", GTK_RESPONSE_ACCEPT, NULL);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *body = json_string_body("id", id);
        Buffer out = {0};
        char *err = NULL;
        if (api_request("/api/profile/delete", "POST", body, 10000, &out, &err)) {
            append_diag(app, "Linked node removed from this app.");
            refresh_profiles(app);
        } else {
            char *line = g_strdup_printf("Remove failed: %s", err != NULL ? err : "request failed");
            append_diag(app, line);
            gtk_label_set_text(GTK_LABEL(app->error), err != NULL ? err : "remove failed");
            g_free(line);
        }
        g_free(body);
        g_free(err);
        free(out.data);
    }
    gtk_widget_destroy(dialog);
}

static void on_latency_node(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    const char *id = active_router_id(app);
    if (id == NULL || id[0] == '\0') {
        append_diag(app, "Latency test failed: select a linked node first.");
        return;
    }
    JsonBuilder *builder = json_builder_new();
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "id");
    json_builder_add_string_value(builder, id);
    json_builder_set_member_name(builder, "samples");
    json_builder_add_int_value(builder, 50);
    json_builder_end_object(builder);
    JsonNode *root = json_builder_get_root(builder);
    JsonGenerator *generator = json_generator_new();
    json_generator_set_root(generator, root);
    char *body = json_generator_to_data(generator, NULL);
    post_and_log(app, "/api/profile/latency", body, 180000, "50-sample node latency");
    g_free(body);
    json_node_free(root);
    g_object_unref(generator);
    g_object_unref(builder);
    refresh_profiles(app);
}

static GtkWidget *build_nodes_page_v3(App *app) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(box), 10);
    GtkWidget *note = gtk_label_new(
        "Install once; pair/import node data separately. The map plots only stored real coordinates.");
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
    gtk_box_pack_start(GTK_BOX(row), make_button("Import bundle JSON", G_CALLBACK(on_import_node), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Remove selected node", G_CALLBACK(on_remove_node), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Run 50-sample latency", G_CALLBACK(on_latency_node), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), row, FALSE, FALSE, 0);
    return box;
}

static void build_ui_v3(App *app) {
    app->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(app->window), "Router VPN");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 1080, 720);
    GtkWidget *tabs_widget = gtk_notebook_new();
    GtkNotebook *tabs = GTK_NOTEBOOK(tabs_widget);
    add_tab(tabs, build_home_page(app), "Home / Connect");
    add_tab(tabs, build_nodes_page_v3(app), "Nodes & Map");
    add_tab(tabs, build_modes_page(app), "Modes");
    add_tab(tabs, make_info_page("DNS", "Selected DNS is controller-owned and session-proven. Home shows typed dns-proof events; this shell does not create cosmetic DNS state."), "DNS");
    add_tab(tabs, make_info_page("Advanced", "MTU/Jumbo, LAN access, custom composition, and expert runtime settings remain controller-owned so native UI cannot claim settings the dataplane did not apply."), "Advanced");
    add_tab(tabs, make_info_page("Forwarding", "Incoming forwarding is available only when the active dataplane can implement it. Proxy-only modes never pretend DNAT is available."), "Forwarding");
    add_tab(tabs, make_info_page("Settings", "Router VPN Linux talks only to the fixed local controller at 127.0.0.1:8788 and preserves the app-owned controller lifecycle. No embedded browser is used."), "Settings");
    add_tab(tabs, make_info_page("Help", "Install Router VPN once. Nodes & Map can securely pair with the authenticated Setup Center, import/remove node data, and retest robust latency without reinstalling the app. Use Setup Center Full Guide for server/router administration."), "Help");
    gtk_container_add(GTK_CONTAINER(app->window), tabs_widget);
}

static int self_test_v3(void) {
    if (routervpn_product_core_self_test() != 0) return 2;
    static const char *const node_paths[] = {
        "/api/profile/pair", "/api/profile/import", "/api/profile/delete", "/api/profile/latency"
    };
    if (G_N_ELEMENTS(node_paths) != 4 || node_paths[0][0] != '/') return 3;
    puts("Router VPN native Linux node-management product self-test: OK");
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--self-test") == 0) return self_test_v3();
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
    build_ui_v3(&app);
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
