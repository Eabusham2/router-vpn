/* Real CUSTOM dialog actions and checked private-store publication. */
typedef struct {
    App *app;
    int scenario, ticks, phase, failure;
    guint source;
} LinuxCustomProbeV18;

static gboolean linux_custom_probe_v18(gpointer data) {
    LinuxCustomProbeV18 *p = data;
    GList *windows = gtk_window_list_toplevels(); GtkWidget *dialog = NULL;
    for (GList *w = windows; w; w = w->next)
        if (g_object_get_data(G_OBJECT(w->data), "custom-name-v18")) { dialog = w->data; break; }
    g_list_free(windows);
    if (dialog == NULL && ++p->ticks < 120) return G_SOURCE_CONTINUE;
    if (dialog == NULL) { p->failure = 1; p->source = 0; return G_SOURCE_REMOVE; }
    if (p->phase == 1) {
        /* Invalid name / failed publication must leave the editor open. */
        if (!gtk_widget_get_visible(dialog) || linux_async_state_v16(p->app)->primary != NULL) p->failure = 2;
        p->source = 0;
        gtk_button_clicked(GTK_BUTTON(gtk_dialog_get_widget_for_response(GTK_DIALOG(dialog), GTK_RESPONSE_CANCEL)));
        return G_SOURCE_REMOVE;
    }
    GtkWidget *name = g_object_get_data(G_OBJECT(dialog), "custom-name-v18");
    GPtrArray *checks = g_object_get_data(G_OBJECT(dialog), "custom-checks-v18");
    const char *names[] = {"fixture-custom", "fixture-renamed", "unused", "new", "cannot-write", "fixture-live", "must-not-save", "multihop-saved"};
    gtk_entry_set_text(GTK_ENTRY(name), names[p->scenario]);
    for (guint i = 0; i < checks->len; i++) gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(g_ptr_array_index(checks, i)), i == 0);
    int response = p->scenario == 2 ? GTK_RESPONSE_REJECT : p->scenario >= 3 ? GTK_RESPONSE_APPLY : GTK_RESPONSE_ACCEPT;
    if (p->scenario == 6) linux_async_state_v16(p->app)->auxiliary_jobs++;
    if (p->scenario == 3 || p->scenario == 4) p->phase = 1;
    else p->source = 0;
    GtkWidget *action = gtk_dialog_get_widget_for_response(GTK_DIALOG(dialog), response);
    if (action == NULL) { p->failure = 3; gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_CANCEL); p->source = 0; return G_SOURCE_REMOVE; }
    gtk_button_clicked(GTK_BUTTON(action));
    return p->source ? G_SOURCE_CONTINUE : G_SOURCE_REMOVE;
}

static int linux_custom_builder_self_test_v18(void) {
    App app = {0};
    app.nodes = g_ptr_array_new_with_free_func(free_map_node);
    app.router_ids = g_ptr_array_new_with_free_func(g_free);
    app.mode_ids = g_ptr_array_new_with_free_func(g_free);
    build_ui_v5(&app); gtk_widget_show_all(app.window); g_object_ref(app.window);
    LinuxUnifiedV8 *base = g_object_get_data(G_OBJECT(app.window), "linux-unified-v8");
    LinuxAsyncActionsV16 *owner = linux_async_state_v16(&app);
    char *path = linux_unified_preset_path_v8(), *backup = g_strconcat(path, ".fixture-backup", NULL);
    int failure = 0;
    for (int scenario = 0; scenario < 8 && !failure; scenario++) {
        char *before = NULL; g_file_get_contents(path, &before, NULL, NULL);
        if (scenario == 4 && (g_rename(path, backup) != 0 || g_mkdir(path, 0700) != 0)) { failure = 4; g_free(before); break; }
        base->syncing = TRUE;
        if (scenario != 1 && scenario != 2) gtk_combo_box_set_active_id(GTK_COMBO_BOX(base->mode), "smart-auto");
        base->syncing = FALSE;
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(base->multihop), scenario == 7);
        LinuxCustomProbeV18 probe = {.app = &app, .scenario = scenario};
        probe.source = g_timeout_add(50, linux_custom_probe_v18, &probe);
        linux_unified_custom_builder_v8(base);
        if (probe.source) { g_source_remove(probe.source); failure = 5; }
        if (probe.failure) failure = 10 + probe.failure;
        if (scenario == 6) owner->auxiliary_jobs--;
        if (scenario == 4 && (g_rmdir(path) != 0 || g_rename(backup, path) != 0)) failure = 6;
        if (scenario == 5) {
            if (owner->primary == NULL || !owner->primary->connecting) failure = 7;
            gint64 deadline = g_get_monotonic_time() + 3000000;
            while (linux_async_busy_v16(&app) && g_get_monotonic_time() < deadline) {
                while (gtk_events_pending()) gtk_main_iteration_do(FALSE);
                g_usleep(10000);
            }
            if (linux_async_busy_v16(&app) || !owner->last_ok) failure = 8;
        } else if (owner->primary != NULL || owner->stop != NULL) failure = 9;
        char *after = NULL; g_file_get_contents(path, &after, NULL, NULL);
        if ((scenario == 3 || scenario == 4 || scenario == 6) && g_strcmp0(before, after) != 0) failure = 14;
        GKeyFile *key = g_key_file_new();
        if (!g_key_file_load_from_file(key, path, G_KEY_FILE_NONE, NULL)) failure = 15;
        char *mode = g_key_file_get_string(key, "state", "selected_mode", NULL);
        const char *expected[] = {"custom:fixture-custom", "custom:fixture-renamed", "smart-auto", "smart-auto", "smart-auto", "custom:fixture-live", "custom:fixture-live", "custom:multihop-saved"};
        if (g_strcmp0(mode, expected[scenario]) != 0) failure = 16;
        if (scenario == 1 && g_key_file_has_group(key, "preset:fixture-custom")) failure = 17;
        if (scenario == 2 && g_key_file_has_group(key, "preset:fixture-renamed")) failure = 18;
        struct stat st;
        if (g_stat(path, &st) != 0 || (st.st_mode & 0777) != 0600) failure = 19;
        g_free(mode); g_key_file_unref(key); g_free(before); g_free(after);
        if (!failure) printf("Linux CUSTOM actual dialog scenario %d: PASS\n", scenario);
    }
    while (g_source_remove_by_user_data(base)) {}
    gtk_widget_destroy(app.window); g_object_unref(app.window);
    g_ptr_array_unref(app.nodes); g_ptr_array_unref(app.router_ids); g_ptr_array_unref(app.mode_ids);
    g_free(path); g_free(backup);
    if (failure) fprintf(stderr, "Linux CUSTOM checked Save / Save & Connect acceptance failed: %d\n", failure);
    return failure ? 100 + failure : 0;
}
