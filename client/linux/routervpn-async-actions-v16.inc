/* Composed into the canonical core after its immutable-session transform. */
#include "routervpn-http-job-v16.h"
static void append_diag(App *app, const char *line);
static void refresh_all(App *app);

typedef struct {
    App *app;
    RVHttpJobV16 *primary, *stop;
    guint poll;
    gboolean closed;
    void (*changed)(App *app);
} LinuxAsyncActionsV16;

static LinuxAsyncActionsV16 *linux_async_state_v16(App *app) {
    return app != NULL && app->window != NULL ? g_object_get_data(G_OBJECT(app->window), "linux-async-actions-v16") : NULL;
}
static gboolean linux_async_busy_v16(App *app) {
    LinuxAsyncActionsV16 *s = linux_async_state_v16(app);
    return s != NULL && (s->closed || s->primary != NULL || s->stop != NULL);
}
static gboolean linux_async_connecting_v16(App *app) {
    LinuxAsyncActionsV16 *s = linux_async_state_v16(app);
    return s != NULL && !s->closed && s->primary != NULL && s->primary->connecting;
}
static gboolean linux_async_stopping_v16(App *app) {
    LinuxAsyncActionsV16 *s = linux_async_state_v16(app);
    return s != NULL && (s->closed || s->stop != NULL);
}
static void linux_async_close_v16(GtkWidget *widget, gpointer data) {
    (void)widget;
    LinuxAsyncActionsV16 *s = data;
    s->closed = TRUE;
    if (s->poll != 0) { g_source_remove(s->poll); s->poll = 0; }
    /* Signal BOTH first. Shutdown never waits on one uncancelled request. */
    rv_http_cancel_v16(s->primary); rv_http_cancel_v16(s->stop);
    rv_http_free_v16(s->primary); rv_http_free_v16(s->stop);
    s->primary = NULL; s->stop = NULL;
}
static void linux_async_report_v16(LinuxAsyncActionsV16 *s, RVHttpJobV16 *job) {
    if (atomic_load(&job->cancelled)) return; /* Superseded results cannot win. */
    gboolean ok = job->result == CURLE_OK && job->status >= 200 && job->status < 300;
    char *detail = job->length != 0 ? g_utf8_make_valid(job->response, MIN(job->length, (size_t)4096)) :
        g_strdup(job->result != CURLE_OK ? curl_easy_strerror(job->result) : ok ? "completed" : "controller rejected request");
    char *line = g_strdup_printf("%s%s: %s", job->label, ok ? "" : " failed", detail);
    append_diag(s->app, line);
    if (!ok) gtk_label_set_text(GTK_LABEL(s->app->error), line);
    g_free(line); g_free(detail);
}
static gboolean linux_async_poll_v16(gpointer data) {
    LinuxAsyncActionsV16 *s = data;
    gboolean changed = FALSE;
    if (rv_http_ready_v16(s->primary)) {
        linux_async_report_v16(s, s->primary);
        rv_http_free_v16(s->primary); s->primary = NULL; changed = TRUE;
    }
    if (rv_http_ready_v16(s->stop)) {
        linux_async_report_v16(s, s->stop);
        rv_http_free_v16(s->stop); s->stop = NULL; changed = TRUE;
    }
    gboolean pending = s->primary != NULL || s->stop != NULL;
    if (!pending) s->poll = 0;
    if (changed && s->changed != NULL) s->changed(s->app);
    if (changed && !pending) refresh_all(s->app);
    return pending ? G_SOURCE_CONTINUE : G_SOURCE_REMOVE;
}
static LinuxAsyncActionsV16 *linux_async_ensure_v16(App *app) {
    LinuxAsyncActionsV16 *s = linux_async_state_v16(app);
    if (s != NULL) return s;
    s = g_new0(LinuxAsyncActionsV16, 1); s->app = app;
    g_object_set_data_full(G_OBJECT(app->window), "linux-async-actions-v16", s, g_free);
    g_signal_connect(app->window, "destroy", G_CALLBACK(linux_async_close_v16), s);
    return s;
}
/* TRUE means handled or refused; FALSE preserves existing short, synchronous
 * profile-commit semantics. No nested GTK loop or queued persistent mutation. */
static gboolean linux_async_dispatch_v16(App *app, const char *path, const char *body, long timeout_ms, const char *label) {
    gboolean stop = strcmp(path, "/api/disconnect") == 0 || strcmp(path, "/api/emergency-stop") == 0;
    LinuxAsyncActionsV16 *s = linux_async_state_v16(app);
    if (s != NULL && s->closed) return TRUE;
    if (!stop && linux_async_busy_v16(app)) {
        append_diag(app, "An owned operation is pending; persistent changes remain locked. Disconnect or Emergency stop can interrupt it.");
        return TRUE;
    }
    if (!stop && timeout_ms < 30000) return FALSE;
    s = linux_async_ensure_v16(app);
    if (stop && s->stop != NULL) {
        /* Emergency Stop must be able to escalate a pending normal Disconnect. */
        if (strcmp(path, "/api/emergency-stop") != 0 || strstr(s->stop->url, "/api/emergency-stop") != NULL) return TRUE;
        rv_http_cancel_v16(s->stop); rv_http_free_v16(s->stop); s->stop = NULL;
    }
    if (stop) {
        /* Reap the cancelled sender before issuing Stop: it must not submit a
         * late Connect after the controller has already processed Stop. The
         * numeric-loopback worker polls cancellation at most every 50 ms. */
        rv_http_cancel_v16(s->primary); rv_http_free_v16(s->primary); s->primary = NULL;
    }
    RVHttpJobV16 *job = rv_http_start_v16(path, body != NULL ? body : "{}", timeout_ms, label);
    if (job == NULL) {
        append_diag(app, "Could not start request worker; no new request was issued.");
        return TRUE;
    }
    if (stop) s->stop = job; else s->primary = job;
    if (s->poll == 0) s->poll = g_timeout_add(50, linux_async_poll_v16, s);
    if (s->changed != NULL) s->changed(app);
    return TRUE;
}
