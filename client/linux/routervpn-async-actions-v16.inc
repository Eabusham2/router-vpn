/* Non-secret execution preference shared by the map and saved setups. */
static GKeyFile *linux_unified_load_keyfile_v8(void);
static void linux_unified_save_keyfile_v8(GKeyFile *key);
static char *linux_multihop_execution_choice_v1(void) {
    GKeyFile *key = linux_unified_load_keyfile_v8();
    char *choice = g_key_file_get_string(key, "state", "multihop_execution", NULL);
    g_key_file_unref(key);
    if (choice == NULL) return g_strdup("auto");
    return choice;
}
static void linux_multihop_store_execution_v1(const char *choice) {
    GKeyFile *key = linux_unified_load_keyfile_v8();
    g_key_file_set_string(key,"state","multihop_execution",choice != NULL ? choice : "");
    linux_unified_save_keyfile_v8(key); g_key_file_unref(key);
}

static char *linux_multihop_entry_choice_v23(void) {
    GKeyFile *key = linux_unified_load_keyfile_v8();
    char *choice = g_key_file_get_string(key, "connection-profile-selection", "entry_mode", NULL);
    g_key_file_unref(key);
    return choice != NULL ? choice : g_strdup("");
}

static void linux_multihop_store_entry_v23(const char *choice) {
    GKeyFile *key = linux_unified_load_keyfile_v8();
    g_key_file_set_string(key, "connection-profile-selection", "entry_mode", choice != NULL ? choice : "");
    linux_unified_save_keyfile_v8(key); g_key_file_unref(key);
}

/* Composed into the canonical core after its immutable-session transform. */
#include "routervpn-http-job-v16.h"
#include "routervpn-comparison-progress-v25.h"
static void append_diag(App *app, const char *line);
static void refresh_all(App *app);

typedef struct {
    App *app;
    RVHttpJobV16 *primary, *stop, *progress;
    guint64 progress_generation;
    gint64 next_progress, progress_deadline;
    char comparison_request_id[33];
    gboolean progress_complete;
    guint poll;
    gboolean closed;
    guint auxiliary_jobs;
    guint64 generation, finished_generation;
    char *last_result;
    gboolean last_ok;
    void (*changed)(App *app);
} LinuxAsyncActionsV16;

static LinuxAsyncActionsV16 *linux_async_state_v16(App *app) {
    return app != NULL && app->window != NULL ? g_object_get_data(G_OBJECT(app->window), "linux-async-actions-v16") : NULL;
}
static gboolean linux_async_busy_v16(App *app) {
    LinuxAsyncActionsV16 *s = linux_async_state_v16(app);
    return s != NULL && (s->closed || s->primary != NULL || s->stop != NULL || s->auxiliary_jobs != 0);
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
    s->progress_complete = TRUE;
    s->comparison_request_id[0] = '\0';
    if (s->poll != 0) { g_source_remove(s->poll); s->poll = 0; }
    /* Signal BOTH first. Shutdown never waits on one uncancelled request. */
    rv_http_cancel_v16(s->primary); rv_http_cancel_v16(s->stop); rv_http_cancel_v16(s->progress);
    rv_http_free_v16(s->primary); rv_http_free_v16(s->stop); rv_http_free_v16(s->progress);
    s->primary = NULL; s->stop = NULL; s->progress = NULL;
    g_clear_pointer(&s->last_result, g_free);
}
static void linux_async_report_v16(LinuxAsyncActionsV16 *s, RVHttpJobV16 *job) {
    s->finished_generation = s->generation;
    g_clear_pointer(&s->last_result, g_free);
    s->last_ok = !atomic_load(&job->cancelled) && job->result == CURLE_OK && job->status >= 200 && job->status < 300;
    if (atomic_load(&job->cancelled)) {
        s->last_result = g_strdup("Cancelled request. Controller cleanup may still be pending; no successful result is claimed.");
        return; /* Superseded results cannot win. */
    }
    s->last_result = job->length != 0 ? g_utf8_make_valid(job->response, MIN(job->length, (size_t)32768)) :
        g_strdup(job->result != CURLE_OK ? curl_easy_strerror(job->result) : s->last_ok ? "Request completed" : "Controller rejected request");
    gboolean ok = job->result == CURLE_OK && job->status >= 200 && job->status < 300;
    char *detail = job->length != 0 ? g_utf8_make_valid(job->response, MIN(job->length, (size_t)4096)) :
        g_strdup(job->result != CURLE_OK ? curl_easy_strerror(job->result) : ok ? "completed" : "controller rejected request");
    char *line = g_strdup_printf("%s%s: %s", job->label, ok ? "" : " failed", detail);
    append_diag(s->app, line);
    if (!ok) gtk_label_set_text(GTK_LABEL(s->app->error), line);
    g_free(line); g_free(detail);
}
static char *linux_multihop_progress_text_v1(const char *json);
static void linux_async_progress_v1(LinuxAsyncActionsV16 *s) {
    gboolean observing = !s->closed && !s->progress_complete && s->primary != NULL && s->stop == NULL &&
        (strcmp(s->primary->url, "http://127.0.0.1:8788/api/multihop/connect") == 0 || s->comparison_request_id[0]) &&
        !atomic_load(&s->primary->cancelled) && g_get_monotonic_time() < s->progress_deadline;
    if (!observing) {
        rv_http_cancel_v16(s->progress); rv_http_free_v16(s->progress); s->progress = NULL;
        return;
    }
    if (rv_http_ready_v16(s->progress)) {
        RVHttpJobV16 *job = s->progress;
        s->progress = NULL;
        guint64 generation = s->generation;
        gboolean complete = FALSE, failed = FALSE;
        char *summary = NULL;
        if (s->progress_generation == generation && !atomic_load(&job->cancelled) &&
            job->result == CURLE_OK && job->status == 200 && job->response != NULL && job->length <= 32768 &&
            (!s->comparison_request_id[0] || linux_comparison_progress_matches_v25(job->response, s->comparison_request_id, &complete, &failed)))
            summary = linux_multihop_progress_text_v1(job->response);
        (void)failed;
        rv_http_free_v16(job);
        s->next_progress = g_get_monotonic_time() + 500000;
        if (summary != NULL) {
            /* Retire this generation's read before a UI callback can reenter
             * and start a replacement action. No post-callback cleanup may
             * cancel that replacement's observer. */
            if (complete) s->progress_complete = TRUE;
            g_object_set_data_full(G_OBJECT(s->app->window), "linux-multihop-progress", summary, g_free);
            if (s->changed != NULL) s->changed(s->app);
        }
        return;
    }
    if (s->progress == NULL && g_get_monotonic_time() >= s->next_progress) {
        s->progress_generation = s->generation;
        s->progress = rv_http_start_comparison_progress_v25();
        if (s->progress == NULL) s->next_progress = g_get_monotonic_time() + 1000000;
    }
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
    linux_async_progress_v1(s);
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
static gboolean linux_async_submit_v17(App *app, const char *path, const char *body, long timeout_ms, const char *label, gboolean always, gboolean get) {
    gboolean stop = strcmp(path, "/api/disconnect") == 0 || strcmp(path, "/api/emergency-stop") == 0;
    LinuxAsyncActionsV16 *s = linux_async_state_v16(app);
    if (s != NULL && s->closed) return TRUE;
    if (!stop && linux_async_busy_v16(app)) {
        append_diag(app, "An owned operation is pending; persistent changes remain locked. Disconnect or Emergency stop can interrupt it.");
        return TRUE;
    }
    if (!always && !stop && timeout_ms < 30000) return FALSE;
    char comparison_request_id[33] = {0};
    if (!get && strcmp(path, "/api/external-profile/connect") == 0 &&
        !linux_comparison_connect_id_v25(body, comparison_request_id)) {
        append_diag(app, "The captured comparison request is invalid; no request was issued.");
        return TRUE;
    }
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
        rv_http_cancel_v16(s->primary); rv_http_cancel_v16(s->progress);
        rv_http_free_v16(s->primary); s->primary = NULL;
        rv_http_free_v16(s->progress); s->progress = NULL;
    }
    RVHttpJobV16 *job = comparison_request_id[0] ? rv_http_start_tor_comparison_v25(body, label) :
        get ? rv_http_start_method_v17(path, "", timeout_ms, label, 1) :
        rv_http_start_v16(path, body != NULL ? body : "{}", timeout_ms, label);
    if (job == NULL) {
        append_diag(app, "Could not start request worker; no new request was issued.");
        return TRUE;
    }
    rv_http_cancel_v16(s->progress); rv_http_free_v16(s->progress); s->progress = NULL;
    s->next_progress = 0;
    s->progress_deadline = g_get_monotonic_time() + (gint64)job->timeout_ms * 1000;
    s->progress_complete = FALSE;
    memcpy(s->comparison_request_id, comparison_request_id, sizeof(comparison_request_id));
    g_object_set_data_full(G_OBJECT(app->window), "linux-multihop-progress", NULL, g_free);
    s->generation++;
    if (stop) s->stop = job; else s->primary = job;
    if (s->poll == 0) s->poll = g_timeout_add(50, linux_async_poll_v16, s);
    if (s->changed != NULL) s->changed(app);
    return TRUE;
}

static gboolean linux_async_dispatch_v16(App *app, const char *path, const char *body, long timeout_ms, const char *label) {
    return linux_async_submit_v17(app, path, body, timeout_ms, label, FALSE, FALSE);
}

/* Generation tokens, not worker addresses or dialog pointers, associate a
 * result with its observer. Closing an old view cannot cancel a newer job. */
static guint64 linux_async_request_v17(App *app, const char *path, const char *body, long timeout_ms, const char *label, gboolean get) {
    LinuxAsyncActionsV16 *s = linux_async_ensure_v16(app);
    guint64 before = s->generation;
    (void)linux_async_submit_v17(app, path, body, timeout_ms, label, TRUE, get);
    return s->generation != before ? s->generation : 0;
}

static void linux_async_cancel_request_v17(App *app, guint64 generation) {
    LinuxAsyncActionsV16 *s = linux_async_state_v16(app);
    if (s != NULL && !s->closed && generation != 0 && s->generation == generation) {
        s->progress_complete = TRUE;
        rv_http_cancel_v16(s->primary); rv_http_cancel_v16(s->progress);
    }
}
