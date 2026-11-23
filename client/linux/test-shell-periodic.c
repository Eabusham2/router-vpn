/* Appended to the canonical composed GTK source by the native shell gate. */
static unsigned shell_fixture_beats;
static gboolean shell_fixture_heartbeat(gpointer data) {
    (void)data;
    shell_fixture_beats++;
    return G_SOURCE_CONTINUE;
}
static void shell_fixture_step(void) {
    while (g_main_context_iteration(NULL, FALSE)) {}
    g_usleep(1000);
}
static void shell_fixture_expect(gboolean condition, const char *message) {
    if (!condition) { fprintf(stderr, "GTK periodic fixture failed: %s\n", message); exit(1); }
}
int main(int argc, char **argv) {
    shell_fixture_expect(argc == 4, "scenario, controller marker directory and authentication required");
    const char *scenario = argv[1], *secret = argv[3];
    g_autofree char *entered = g_build_filename(argv[2], "entered", NULL);
    g_autofree char *release = g_build_filename(argv[2], "release", NULL);
    shell_fixture_expect(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK && gtk_init_check(&argc, &argv), "GTK and HTTP startup");
    App app = {0};
    app.nodes = g_ptr_array_new_with_free_func(free_map_node);
    app.router_ids = g_ptr_array_new_with_free_func(g_free);
    app.mode_ids = g_ptr_array_new_with_free_func(g_free);
    app.package_root = g_strdup(argv[2]);
    atomic_store(&controller_exit_pending, TRUE);
    build_ui_v5(&app);
    LinuxUnifiedV8 *state = g_object_get_data(G_OBJECT(app.window), "linux-unified-v8");
    shell_fixture_expect(state && state->readings.timer && !state->readings.active, "installed periodic callback obeyed shutdown admission");
    app.suppress_router_change = TRUE;
    const char *ids[] = {"alpha", "bravo"};
    for (guint i = 0; i < G_N_ELEMENTS(ids); i++) {
        g_ptr_array_add(app.router_ids, g_strdup(ids[i]));
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app.router_combo), ids[i]);
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(app.router_combo), 0);
    shell_fixture_expect(!g_strcmp0(active_router_id(&app), "alpha"), "selected original");
    app.event_seq = 3;
    gtk_label_set_text(GTK_LABEL(app.detail), "before delayed response");
    gtk_label_set_text(GTK_LABEL(state->settings_summary), "before delayed response");
    shell_fixture_expect(rv_controller_auth_publish(getpid(), secret), "publish specific controller owner");
    atomic_store(&controller_exit_pending, FALSE);
    guint heartbeat = g_timeout_add(10, shell_fixture_heartbeat, NULL);
    gint64 started = g_get_monotonic_time();
    while ((!g_file_test(entered, G_FILE_TEST_EXISTS) || shell_fixture_beats < 10) &&
           g_get_monotonic_time() < started + 2 * G_TIME_SPAN_SECOND) shell_fixture_step();
    shell_fixture_expect(state->readings.active && g_file_test(entered, G_FILE_TEST_EXISTS) && shell_fixture_beats >= 10,
                         "main loop continued dispatching while real Home HTTP read was held");
    shell_fixture_expect(!strcmp(gtk_label_get_text(GTK_LABEL(app.detail)), "before delayed response"), "no partial round published");
    gboolean selection = !strcmp(scenario, "selection"), mutation = !strcmp(scenario, "generation");
    gboolean shutting_down = !strcmp(scenario, "shutdown"), closing = !strcmp(scenario, "destroy");
    gboolean wrong_owner = !strcmp(scenario, "foreign"), cursor = !strcmp(scenario, "cursor");
    if (selection) gtk_combo_box_set_active(GTK_COMBO_BOX(app.router_combo), 1);
    if (mutation) linux_async_state_v16(&app)->generation++;
    if (shutting_down) atomic_store(&controller_exit_pending, TRUE);
    if (cursor) app.event_seq = 11;
    if (closing) {
        g_object_ref(app.window);
        gint64 before_close = g_get_monotonic_time();
        gtk_widget_destroy(app.window);
        shell_fixture_expect(g_get_monotonic_time() - before_close < 900 * G_TIME_SPAN_MILLISECOND &&
                             state->readings.closed && !state->readings.timer && !state->readings.active, "cancel then join all pending workers on window destruction");
        for (guint i = 0; i < G_N_ELEMENTS(state->readings.jobs); i++)
            shell_fixture_expect(!state->readings.jobs[i], "retired worker retained after close");
        shell_fixture_expect(g_file_set_contents(release, "", 0, NULL), "release synthetic controller after join");
        g_object_unref(app.window);
    } else {
        shell_fixture_expect(g_file_set_contents(release, "", 0, NULL), "release synthetic controller");
        gint64 deadline = g_get_monotonic_time() + G_TIME_SPAN_SECOND;
        while (state->readings.active && g_get_monotonic_time() < deadline) shell_fixture_step();
        shell_fixture_expect(!state->readings.active, "all seven source workers retired");
        const char *home = gtk_label_get_text(GTK_LABEL(app.detail));
        const char *settings = gtk_label_get_text(GTK_LABEL(state->settings_summary));
        if (selection || mutation || shutting_down) {
            shell_fixture_expect(!strcmp(home, "before delayed response") && !strcmp(settings, "before delayed response") && app.event_seq == 3,
                                 "discarded source did not mutate any rendered view or event cursor");
        } else {
            shell_fixture_expect(!strcmp(gtk_button_get_label(GTK_BUTTON(state->connect)), "Retry Disconnect") &&
                                 !g_strcmp0(g_object_get_data(G_OBJECT(state->connect), "routervpn-stop-retry-token"), "0123456789abcdef0123456789abcdef"),
                                 "real status rendered retry with original receipt");
            shell_fixture_expect(app.event_seq == (cursor ? 11 : 8), "incremental events are tied to exact cursor");
            if (wrong_owner) {
                shell_fixture_expect(strstr(home, "Home state unavailable") && strstr(settings, "requirements unavailable") &&
                                     gtk_toggle_button_get_inconsistent(GTK_TOGGLE_BUTTON(state->kill_switch)),
                                     "foreign Home, settings and protection snapshots all refused");
            } else {
                shell_fixture_expect(strstr(home, "Source Alpha") && strstr(settings, "Encrypted + Obfuscation") &&
                                     !gtk_toggle_button_get_inconsistent(GTK_TOGGLE_BUTTON(state->kill_switch)),
                                     "original Home, settings and protection rendered from retained round");
            }
            GtkWidget *view = g_object_get_data(G_OBJECT(app.window), "router-vpn-diagnostics-v5");
            GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
            GtkTextIter first, last;
            gtk_text_buffer_get_bounds(buffer, &first, &last);
            g_autofree char *diagnostics = gtk_text_buffer_get_text(buffer, &first, &last, FALSE);
            shell_fixture_expect(strstr(diagnostics, "session proof from shell fixture") && strstr(diagnostics, "full event from shell fixture"),
                                 "real diagnostics rendered full session and event history");
        }
        gtk_widget_destroy(app.window);
    }
    g_source_remove(heartbeat);
    rv_controller_auth_clear(getpid(), secret);
    g_free(app.package_root);
    g_ptr_array_unref(app.nodes); g_ptr_array_unref(app.router_ids); g_ptr_array_unref(app.mode_ids);
    curl_global_cleanup();
    printf("GTK periodic shell %s: deferred HTTP, event loop and original ownership PASS\n", scenario);
    return 0;
}
