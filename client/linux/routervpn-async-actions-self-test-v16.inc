/* Actual shipping map, Connect, MTU and Emergency stop callbacks. The explicit
 * Speed Lab test CLI provides an isolated loopback fixture, never a real VPN. */
typedef struct {
    App *app;
    LinuxUnifiedV8 *base;
    int stage, ticks, beats, failure;
    guint source;
} LinuxAsyncProbeV16;

static gboolean linux_async_probe_v16(gpointer data) {
    LinuxAsyncProbeV16 *p = data;
    p->ticks++; p->beats++;
    if (p->ticks > 240) { p->failure = 1; goto finish; }
    LinuxAsyncActionsV16 *s = linux_async_state_v16(p->app);
    if (p->stage == 0) {
        gint64 start = g_get_monotonic_time();
        gtk_button_clicked(GTK_BUTTON(p->base->connect));
        if (g_get_monotonic_time()-start > 500000 || s->primary == NULL ||
            !routervpn_mutation_busy(p->app) || gtk_widget_get_sensitive(p->base->dns) ||
            strcmp(gtk_button_get_label(GTK_BUTTON(p->base->connect)), "Disconnect") != 0) {
            p->failure = 2; goto finish;
        }
        post_and_log(p->app, "/api/profile/select", "{\"id\":\"must-not-write\"}", 12000, "Blocked selection");
        p->stage = 1; p->beats = 0;
    } else if (p->stage == 1 && !linux_async_busy_v16(p->app)) {
        if (p->beats < 4) { p->failure = 3; goto finish; }
        printf("Linux actual map action: delayed SMART AUTO remained responsive; pending profile mutation refused: PASS\n");
        gtk_button_clicked(GTK_BUTTON(p->base->connect));
        p->stage = 2; p->beats = 0;
    } else if (p->stage == 2 && p->beats >= 6) {
        gtk_button_clicked(GTK_BUTTON(p->base->connect));
        if (s->primary != NULL || s->stop == NULL || !linux_async_stopping_v16(p->app)) {
            p->failure = 4; goto finish;
        }
        p->stage = 3; p->beats = 0;
    } else if (p->stage == 3 && p->beats >= 6) {
        GtkWidget *emergency = linux_telemetry_find_button_v9(p->base->stack, "Emergency stop");
        if (emergency == NULL) { p->failure = 5; goto finish; }
        gtk_button_clicked(GTK_BUTTON(emergency));
        if (s->stop == NULL || strstr(s->stop->url, "/api/emergency-stop") == NULL) {
            p->failure = 6; goto finish;
        }
        p->stage = 4; p->beats = 0;
    } else if (p->stage == 4 && !linux_async_busy_v16(p->app)) {
        printf("Linux actual map action: Disconnect preempted Connect; Emergency stop escalated pending Disconnect: PASS\n");
        GtkWidget *mtu = linux_telemetry_find_button_v9(p->base->stack, "Retest MTU");
        if (mtu == NULL) { p->failure = 7; goto finish; }
        gtk_button_clicked(GTK_BUTTON(mtu));
        if (s->primary == NULL || s->primary->connecting) { p->failure = 8; goto finish; }
        p->stage = 5; p->beats = 0;
    } else if (p->stage == 5 && p->beats >= 6) {
        printf("Linux actual map action: MTU request remained responsive before window close: PASS\n");
        goto finish;
    }
    return G_SOURCE_CONTINUE;
finish:
    p->source = 0;
    while (g_source_remove_by_user_data(p->base)) {}
    gint64 start = g_get_monotonic_time();
    gtk_widget_destroy(p->app->window);
    if (g_get_monotonic_time()-start > 800000) p->failure = 9;
    gtk_main_quit();
    return G_SOURCE_REMOVE;
}

static int linux_async_actions_self_test_v16(void) {
    App app = {0};
    app.nodes = g_ptr_array_new_with_free_func(free_map_node);
    app.router_ids = g_ptr_array_new_with_free_func(g_free);
    app.mode_ids = g_ptr_array_new_with_free_func(g_free);
    build_ui_v5(&app);
    g_object_ref(app.window); /* Retain only to inspect shutdown ownership. */
    gtk_widget_show_all(app.window);
    LinuxAsyncProbeV16 probe = {.app = &app, .base = g_object_get_data(G_OBJECT(app.window), "linux-unified-v8")};
    probe.source = g_timeout_add(25, linux_async_probe_v16, &probe);
    gtk_main();
    LinuxAsyncActionsV16 *s = linux_async_state_v16(&app);
    if (s == NULL || !s->closed || s->primary != NULL || s->stop != NULL || s->poll != 0) probe.failure = 10;
    for (int i = 0; i < 10; i++) {
        while (gtk_events_pending()) gtk_main_iteration_do(FALSE);
        g_usleep(20000);
    }
    g_object_unref(app.window);
    g_ptr_array_unref(app.nodes); g_ptr_array_unref(app.router_ids); g_ptr_array_unref(app.mode_ids);
    if (probe.failure) fprintf(stderr, "Linux real async action test failed: %d (stage %d)\n", probe.failure, probe.stage);
    else puts("Linux actual map action: window close reaped workers and completion source: PASS");
    return probe.failure ? 50 + probe.failure : 0;
}
