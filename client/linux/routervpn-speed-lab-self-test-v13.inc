#include "routervpn-async-actions-self-test-v16.inc"
#include "routervpn-extended-actions-self-test-v17.inc"
#include "routervpn-custom-builder-self-test-v18.inc"

/* Invoked only by the explicit --speed-lab-self-test CLI. The fixture server
 * is loopback-only and makes no VPN or Internet requests. Drive the actual
 * dialog, buttons, worker and destroy callback, not a second test UI. */
typedef struct {
    int scenario;
    int ticks;
    int running_ticks;
    int stage;
    int failure;
    guint source;
} LinuxSpeedLabProbeV13;

static LinuxSpeedLabV12 *linux_speed_lab_find_v13(void) {
    GList *windows = gtk_window_list_toplevels();
    LinuxSpeedLabV12 *result = NULL;
    for (GList *item = windows; item != NULL; item = item->next) {
        result = g_object_get_data(G_OBJECT(item->data), "linux-speed-lab-v12");
        if (result != NULL && !result->closed) break;
        result = NULL;
    }
    g_list_free(windows);
    return result;
}

static gboolean linux_speed_lab_probe_v13(gpointer data) {
    LinuxSpeedLabProbeV13 *probe = data;
    probe->ticks++;
    LinuxSpeedLabV12 *s = linux_speed_lab_find_v13();
    if (s == NULL) {
        if (probe->ticks < 200) return G_SOURCE_CONTINUE;
        probe->failure = 1;
        probe->source = 0;
        return G_SOURCE_REMOVE;
    }
    if (probe->ticks > 200) {
        probe->failure = 2;
        gtk_dialog_response(GTK_DIALOG(s->dialog), GTK_RESPONSE_CLOSE);
        probe->source = 0;
        return G_SOURCE_REMOVE;
    }
    /* Last scenario closes while options are still loading. */
    if (probe->scenario == 6 && probe->ticks >= 6) {
        if (s->worker == NULL || !s->loading_options) probe->failure = 3;
        gtk_dialog_response(GTK_DIALOG(s->dialog), GTK_RESPONSE_CLOSE);
        probe->source = 0;
        return G_SOURCE_REMOVE;
    }
    if (probe->stage == 0) {
        if (s->worker != NULL) return G_SOURCE_CONTINUE;
        if (!s->options_ready || !gtk_widget_get_sensitive(s->run) ||
            strcmp(linux_speed_lab_active_id_v12(s->scope), "current") != 0) {
            probe->failure = 4;
            gtk_dialog_response(GTK_DIALOG(s->dialog), GTK_RESPONSE_CLOSE);
            probe->source = 0;
            return G_SOURCE_REMOVE;
        }
        gtk_button_clicked(GTK_BUTTON(s->run));
        if (s->worker == NULL || gtk_widget_get_sensitive(s->scope) ||
            !gtk_widget_get_sensitive(s->run)) probe->failure = 5;
        probe->stage = 1;
        return G_SOURCE_CONTINUE;
    }
    probe->running_ticks++;
    if (probe->scenario == 4 && probe->stage == 1 && probe->running_ticks >= 6) {
        gtk_button_clicked(GTK_BUTTON(s->run));
        if (!g_atomic_int_get(&s->cancelled)) probe->failure = 6;
        probe->stage = 2;
    }
    if (probe->scenario == 5 && probe->running_ticks >= 6) {
        if (s->worker == NULL) probe->failure = 7;
        gtk_dialog_response(GTK_DIALOG(s->dialog), GTK_RESPONSE_CLOSE);
        probe->source = 0;
        return G_SOURCE_REMOVE;
    }
    if (s->worker != NULL) return G_SOURCE_CONTINUE;
    const char *status = gtk_label_get_text(GTK_LABEL(s->status));
    if (probe->running_ticks < 3) probe->failure = 8;
    if (probe->scenario == 0) {
        if (strstr(status, "Finished") == NULL ||
            strcmp(gtk_label_get_text(GTK_LABEL(s->download)), "123.0 Mbps") != 0 ||
            strcmp(gtk_label_get_text(GTK_LABEL(s->idle)), "12.0 ms") != 0)
            probe->failure = 9;
    } else {
        const char *expected = probe->scenario == 4 ? "Cancelled" :
                               probe->scenario == 3 ? "invalid" : "failed";
        if (strstr(status, expected) == NULL ||
            strcmp(gtk_label_get_text(GTK_LABEL(s->download)), "--") != 0)
            probe->failure = 10;
    }
    if (!gtk_widget_get_sensitive(s->run) || !gtk_widget_get_sensitive(s->scope) ||
        strcmp(linux_speed_lab_active_id_v12(s->scope), "current") != 0)
        probe->failure = 11;
    gtk_dialog_response(GTK_DIALOG(s->dialog), GTK_RESPONSE_CLOSE);
    probe->source = 0;
    return G_SOURCE_REMOVE;
}

static int linux_speed_lab_self_test_v13(void) {
    static const char *const scenarios[] = {
        "delayed success without UI freeze", "HTTP failure", "oversized response",
        "invalid result cannot become zero-speed success", "cancel test",
        "close during test", "close while loading options"
    };
    App app = {0};
    app.window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    for (guint i = 0; i < G_N_ELEMENTS(scenarios); i++) {
        LinuxSpeedLabProbeV13 probe = {.scenario = (int)i};
        gint64 started = g_get_monotonic_time();
        probe.source = g_timeout_add(50, linux_speed_lab_probe_v13, &probe);
        linux_speed_lab_open_v12(NULL, &app);
        if (probe.source != 0) { g_source_remove(probe.source); probe.failure = 12; }
        /* A destroyed dialog must not retain a completion callback into freed
         * state, including after a close while the network worker is running. */
        for (int frame = 0; frame < 10; frame++) {
            while (gtk_events_pending()) gtk_main_iteration_do(FALSE);
            g_usleep(20000);
        }
        if (g_get_monotonic_time() - started > 5 * G_TIME_SPAN_SECOND) probe.failure = 13;
        if (probe.failure != 0) {
            fprintf(stderr, "Speed Lab UI scenario %s failed (%d); heartbeat ticks=%d\n",
                    scenarios[i], probe.failure, probe.running_ticks);
            gtk_widget_destroy(app.window);
            return 20 + probe.failure;
        }
        printf("Speed Lab real-dialog test: %s PASS; heartbeat ticks=%d\n", scenarios[i], probe.ticks);
    }
    gtk_widget_destroy(app.window);
    int actions_result = linux_async_actions_self_test_v16();
    if (actions_result != 0) return actions_result;
    actions_result = linux_extended_actions_self_test_v17();
    return actions_result != 0 ? actions_result : linux_custom_builder_self_test_v18();
}
