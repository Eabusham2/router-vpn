/* Modeless, captured ordered response measurements. Only a durable controller
 * receipt changes history; neither CURL completion nor Cancel proves native DOWN. */
#include <math.h>
enum { OL_INFO_V1, OL_START_V1, OL_POLL_V1, OL_CANCEL_V1, OL_JOBS_V1 };
typedef struct {
    App *app;
    GtkWidget *parent, *dialog, *message_label, *hops, *history_view, *retest, *cancel;
    gulong parent_destroy;
    guint timer;
    guint64 generation, job_generation[OL_JOBS_V1];
    RVHttpJobV16 *jobs[OL_JOBS_V1];
    JsonNode *capture, *nodes, *history;
    char *displayed, *request, *message;
    int position;
    gint64 next_poll, next_cancel, deadline;
    gboolean complete, drained, cancelled, invalid, closing, parent_closing, detaching;
} LinuxOrderedLatencyV1;

static gboolean linux_ol_tick_v1(gpointer data);
static void linux_ol_cancel_v1(LinuxOrderedLatencyV1 *s);
static const char *linux_ol_string_v1(JsonObject *o, const char *key) {
    JsonNode *n = o != NULL ? json_object_get_member(o, key) : NULL;
    return n != NULL && JSON_NODE_HOLDS_VALUE(n) && json_node_get_value_type(n) == G_TYPE_STRING ? json_node_get_string(n) : NULL;
}
static JsonObject *linux_ol_object_v1(JsonObject *o, const char *key) {
    JsonNode *n = o != NULL ? json_object_get_member(o, key) : NULL;
    return n != NULL && JSON_NODE_HOLDS_OBJECT(n) ? json_node_get_object(n) : NULL;
}
static JsonArray *linux_ol_array_v1(JsonObject *o, const char *key) {
    JsonNode *n = o != NULL ? json_object_get_member(o, key) : NULL;
    return n != NULL && JSON_NODE_HOLDS_ARRAY(n) ? json_node_get_array(n) : NULL;
}
static gboolean linux_ol_bool_v1(JsonObject *o, const char *key, gboolean *v) {
    JsonNode *n = o != NULL ? json_object_get_member(o, key) : NULL;
    if (n == NULL || !JSON_NODE_HOLDS_VALUE(n) || json_node_get_value_type(n) != G_TYPE_BOOLEAN) return FALSE;
    *v = json_node_get_boolean(n); return TRUE;
}
static gboolean linux_ol_number_v1(JsonObject *o, const char *key, double low, double high, gboolean integer) {
    JsonNode *n = o != NULL ? json_object_get_member(o, key) : NULL;
    if (n == NULL || !JSON_NODE_HOLDS_VALUE(n)) return FALSE;
    GType type = json_node_get_value_type(n);
    if (type != G_TYPE_INT64 && type != G_TYPE_DOUBLE) return FALSE;
    double v = json_node_get_double(n);
    return isfinite(v) && v >= low && v <= high && (!integer || floor(v) == v);
}
static gboolean linux_ol_text_v1(const char *v, size_t limit) {
    if (v == NULL || !*v || strlen(v) > limit || !g_utf8_validate(v, -1, NULL)) return FALSE;
    for (const char *p = v; *p; p++) if ((unsigned char)*p < 32 || *p == 127) return FALSE;
    return TRUE;
}
static gboolean linux_ol_hex_v1(const char *v, size_t length) {
    return v != NULL && strlen(v) == length && strspn(v, "0123456789abcdef") == length;
}
static gboolean linux_ol_capture_v1(JsonObject *c) {
    if (c == NULL || json_object_get_size(c) != 6) return FALSE;
    const char *session = linux_ol_string_v1(c, "session_id");
    if (!linux_ol_text_v1(linux_ol_string_v1(c, "profile_id"), 128) || !linux_ol_text_v1(session, 64) ||
        !g_regex_match_simple("^session-[0-9]+-[0-9]+$", session, 0, 0)) return FALSE;
    const char *keys[] = {"profile_token", "source_sha256", "config_sha256", "generation_sha256"};
    for (guint i = 0; i < G_N_ELEMENTS(keys); i++) if (!linux_ol_hex_v1(linux_ol_string_v1(c, keys[i]), 64)) return FALSE;
    return TRUE;
}
static gboolean linux_ol_same_capture_v1(JsonObject *a, JsonObject *b) {
    const char *keys[] = {"session_id", "profile_id", "profile_token", "source_sha256", "config_sha256", "generation_sha256"};
    if (!linux_ol_capture_v1(a) || !linux_ol_capture_v1(b)) return FALSE;
    for (guint i = 0; i < G_N_ELEMENTS(keys); i++)
        if (g_strcmp0(linux_ol_string_v1(a, keys[i]), linux_ol_string_v1(b, keys[i])) != 0) return FALSE;
    return TRUE;
}
static gboolean linux_ol_node_v1(JsonObject *n, int position) {
    const char *id = linux_ol_string_v1(n, "node_id"), *roles[] = {"entry", "intermediate", "exit"};
    return position >= 0 && position < 3 && linux_ol_text_v1(id, 64) && strspn(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") == strlen(id) &&
        linux_ol_text_v1(linux_ol_string_v1(n, "label"), 256) && linux_ol_number_v1(n, "position", position, position, TRUE) &&
        g_strcmp0(linux_ol_string_v1(n, "role"), roles[position]) == 0 &&
        g_strcmp0(linux_ol_string_v1(n, "kind"), position == 1 ? "public-path" : "private-node") == 0 &&
        g_strcmp0(linux_ol_string_v1(n, "measurement"), position == 1 ? "routed-https-response-after-tls" : "routed-private-response-including-connection") == 0;
}
static gboolean linux_ol_receipt_v1(JsonObject *r, JsonObject *capture, JsonObject *node, gboolean current) {
    int position = (int)json_object_get_int_member(node, "position");
    if (!linux_ol_number_v1(r, "schema", 1, 1, TRUE) || !linux_ol_number_v1(r, "position", position, position, TRUE) ||
        g_strcmp0(linux_ol_string_v1(r, "node_id"), linux_ol_string_v1(node, "node_id")) != 0 ||
        !linux_ol_hex_v1(linux_ol_string_v1(r, "request_id"), 32) || !linux_ol_hex_v1(linux_ol_string_v1(r, "generation_sha256"), 64) ||
        g_strcmp0(linux_ol_string_v1(r, "source_sha256"), linux_ol_string_v1(capture, "source_sha256")) != 0 ||
        g_strcmp0(linux_ol_string_v1(r, "config_sha256"), linux_ol_string_v1(capture, "config_sha256")) != 0 ||
        (current && g_strcmp0(linux_ol_string_v1(r, "generation_sha256"), linux_ol_string_v1(capture, "generation_sha256")) != 0) ||
        !linux_ol_number_v1(r, "measured_at", 1, (double)(g_get_real_time()/1000 + 1000), TRUE)) return FALSE;
    JsonObject *result = linux_ol_object_v1(r, "result"), *b = linux_ol_object_v1(result, "benchmark"), *d = linux_ol_object_v1(b, "distribution");
    gboolean ready = FALSE; const char *failure = linux_ol_string_v1(result, "failure");
    const char *keys[] = {"node_id", "kind", "role"};
    for (guint i = 0; i < G_N_ELEMENTS(keys); i++)
        if (g_strcmp0(linux_ol_string_v1(result, keys[i]), linux_ol_string_v1(node, keys[i])) != 0) return FALSE;
    const char *labels[] = {"Cumulative path through node 1 of 3", "Cumulative path through custom node 2 of 3 → Cloudflare edge", "Cumulative path through node 3 of 3"};
    if (g_strcmp0(linux_ol_string_v1(result, "label"), labels[position])) return FALSE;
    const char *unrelated[] = {"idle", "download", "upload", "response"};
    for (guint i = 0; i < G_N_ELEMENTS(unrelated); i++) {
        JsonNode *extra = json_object_get_member(result, unrelated[i]);
        if (extra != NULL && !JSON_NODE_HOLDS_NULL(extra)) return FALSE;
    }
    const char *endpoint = linux_ol_string_v1(b, "endpoint");
    if (!linux_ol_bool_v1(result, "ready", &ready) || !ready || (failure != NULL && *failure) ||
        (result != NULL && json_object_has_member(result, "failure") && failure == NULL) ||
        !linux_ol_number_v1(b, "schema", 1, 1, TRUE) || !linux_ol_number_v1(b, "attempts", 50, 50, TRUE) ||
        !linux_ol_number_v1(b, "failed", 0, 0, TRUE) || !linux_ol_number_v1(d, "samples", 50, 50, TRUE) ||
        g_strcmp0(linux_ol_string_v1(b, "measurement"), linux_ol_string_v1(node, "measurement")) != 0 ||
        (b != NULL && json_object_has_member(b, "endpoint") && endpoint == NULL) ||
        (position == 1 ? g_strcmp0(endpoint, "https://speed.cloudflare.com/__down?bytes=1") != 0 : endpoint != NULL && *endpoint)) return FALSE;
    double maximum = position == 1 ? 5000 : 2000;
    const char *times[] = {"min_ms", "median_ms", "average_ms", "p90_ms", "max_ms"};
    for (guint i = 0; i < G_N_ELEMENTS(times); i++) if ((!linux_ol_number_v1(d, times[i], 0, maximum, FALSE) || json_object_get_double_member(d, times[i]) <= 0)) return FALSE;
    double min = json_object_get_double_member(d, "min_ms"), max = json_object_get_double_member(d, "max_ms");
    double median = json_object_get_double_member(d, "median_ms"), p90 = json_object_get_double_member(d, "p90_ms");
    return min <= median && median <= p90 && p90 <= max && linux_ol_number_v1(d, "average_ms", min, max, FALSE) &&
        linux_ol_number_v1(b, "trimmed_mean_ms", min, max, FALSE) && linux_ol_number_v1(d, "jitter_ms", 0, max-min+1e-9, FALSE);
}
static void linux_ol_message_v1(LinuxOrderedLatencyV1 *s, const char *message) {
    g_free(s->message); s->message = g_strdup(message);
}
static gboolean linux_ol_settled_v1(LinuxOrderedLatencyV1 *s) {
    if (s->request != NULL && !(s->complete && s->drained)) return FALSE;
    for (int i = 0; i < OL_JOBS_V1; i++) if (s->jobs[i] != NULL) return FALSE;
    return TRUE;
}
static gboolean linux_ol_job_v1(LinuxOrderedLatencyV1 *s, int kind) {
    if (s->detaching || s->jobs[kind] != NULL) return FALSE;
    char *path = g_strdup("/api/speed-lab/ordered-latency"), *body = NULL;
    if (kind == OL_POLL_V1) { g_free(path); path = g_strdup_printf("/api/speed-lab/ordered-latency?request_id=%s", s->request); }
    if (kind == OL_START_V1 || kind == OL_CANCEL_V1) {
        JsonObject *o = json_object_new();
        json_object_set_member(o, "capture", json_node_copy(s->capture));
        JsonObject *node = json_array_get_object_element(json_node_get_array(s->nodes), (guint)s->position);
        json_object_set_string_member(o, "node_id", linux_ol_string_v1(node, "node_id"));
        json_object_set_int_member(o, "position", s->position); json_object_set_string_member(o, "request_id", s->request);
        JsonNode *n = json_node_new(JSON_NODE_OBJECT); json_node_take_object(n, o);
        JsonGenerator *g = json_generator_new(); json_generator_set_root(g, n); body = json_generator_to_data(g, NULL);
        g_object_unref(g); json_node_free(n);
        if (kind == OL_CANCEL_V1) { g_free(path); path = g_strdup("/api/speed-lab/ordered-latency/cancel"); }
    }
    s->jobs[kind] = rv_http_start_method_v17(path, body != NULL ? body : "", 6000, "Ordered hop responses", kind == OL_INFO_V1 || kind == OL_POLL_V1);
    s->job_generation[kind] = s->generation; g_free(path); g_free(body); return s->jobs[kind] != NULL;
}
static gboolean linux_ol_receive_v1(LinuxOrderedLatencyV1 *s, JsonObject *reply, gboolean initial) {
    JsonObject *capture = linux_ol_object_v1(reply, "capture"), *status = linux_ol_object_v1(reply, "status");
    const char *request = linux_ol_string_v1(reply, "request_id"), *stage = linux_ol_string_v1(status, "stage"), *failure = linux_ol_string_v1(status, "failure");
    gboolean complete = FALSE, drained = FALSE; JsonArray *results = linux_ol_array_v1(status, "results");
    if (request == NULL && initial && !json_object_has_member(reply, "request_id")) request = "";
    if (!linux_ol_number_v1(reply, "schema", 1, 1, TRUE) || !linux_ol_capture_v1(capture) ||
        !linux_ol_bool_v1(status, "complete", &complete) || !linux_ol_bool_v1(status, "drained", &drained) || (drained && !complete) ||
        !linux_ol_text_v1(stage, 128) || request == NULL || g_strcmp0(linux_ol_string_v1(status, "request_id"), request) != 0 ||
        (failure != NULL && strlen(failure) > 512) || (status != NULL && json_object_has_member(status, "failure") && failure == NULL) ||
        results == NULL || json_array_get_length(results) > 3) return FALSE;
    if (initial) {
        JsonArray *nodes = linux_ol_array_v1(reply, "nodes"), *history = linux_ol_array_v1(reply, "history");
        if (s->invalid || s->capture != NULL || g_strcmp0(linux_ol_string_v1(capture, "profile_id"), s->displayed) != 0 || *request ||
            strcmp(stage, "idle") || !complete || !drained || nodes == NULL || json_array_get_length(nodes) != 3 ||
            (history == NULL && json_object_has_member(reply, "history")) || (history != NULL && json_array_get_length(history) > 128)) return FALSE;
        for (guint i = 0; i < 3; i++) {
            JsonNode *n = json_array_get_element(nodes, i);
            if (!JSON_NODE_HOLDS_OBJECT(n) || !linux_ol_node_v1(json_node_get_object(n), (int)i)) return FALSE;
            for (guint j = 0; j < i; j++) if (!g_strcmp0(linux_ol_string_v1(json_node_get_object(n), "node_id"), linux_ol_string_v1(json_array_get_object_element(nodes, j), "node_id"))) return FALSE;
        }
        for (guint i = 0; history != NULL && i < json_array_get_length(history); i++) {
            JsonNode *n = json_array_get_element(history, i);
            if (!JSON_NODE_HOLDS_OBJECT(n) || !linux_ol_number_v1(json_node_get_object(n), "position", 0, 2, TRUE)) return FALSE;
            JsonObject *r = json_node_get_object(n); guint position = (guint)json_object_get_int_member(r, "position");
            if (!linux_ol_receipt_v1(r, capture, json_array_get_object_element(nodes, position), FALSE)) return FALSE;
        }
        s->capture = json_node_copy(json_object_get_member(reply, "capture")); s->nodes = json_node_copy(json_object_get_member(reply, "nodes"));
        if (history != NULL) s->history = json_node_copy(json_object_get_member(reply, "history"));
        else { s->history = json_node_new(JSON_NODE_ARRAY); json_node_take_array(s->history, json_array_new()); }
        for (guint i = 0; i < 3; i++) {
            JsonObject *n = json_array_get_object_element(nodes, i);
            char *label = g_strdup_printf("%u. %s — %s", i+1, linux_ol_string_v1(n, "label"), linux_ol_string_v1(n, "role"));
            gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(s->hops), label); g_free(label);
        }
        gtk_combo_box_set_active(GTK_COMBO_BOX(s->hops), 0);
        linux_ol_message_v1(s, "Choose a hop. Saved results show when that route was measured."); return TRUE;
    }
    if (!linux_ol_same_capture_v1(capture, s->capture != NULL ? json_node_get_object(s->capture) : NULL) ||
        s->request == NULL || strcmp(request, s->request) || !linux_ol_number_v1(reply, "position", s->position, s->position, TRUE)) return FALSE;
    JsonObject *node = json_array_get_object_element(json_node_get_array(s->nodes), (guint)s->position);
    if (g_strcmp0(linux_ol_string_v1(reply, "node_id"), linux_ol_string_v1(node, "node_id"))) return FALSE;
    if (s->complete && s->drained) return TRUE; /* An older admitted response cannot undo a tombstone. */
    JsonNode *record = json_object_get_member(reply, "receipt");
    if (record != NULL && !JSON_NODE_HOLDS_NULL(record)) {
        if (!JSON_NODE_HOLDS_OBJECT(record) || !complete || !drained || strcmp(stage, "complete") || (failure != NULL && *failure) ||
            g_strcmp0(linux_ol_string_v1(json_node_get_object(record), "request_id"), s->request) ||
            !linux_ol_receipt_v1(json_node_get_object(record), capture, node, TRUE)) return FALSE;
        if (s->invalid) {
            /* A locally invalidated view cannot adopt results, but this exact
             * original durable receipt still proves native cleanup. */
            s->complete = complete; s->drained = drained;
            linux_ol_message_v1(s, "Measurement context changed; original cleanup finished. Reopen to read saved history.");
            return TRUE;
        }
        JsonArray *next = json_array_new(), *old = json_node_get_array(s->history);
        for (guint i = 0; i < json_array_get_length(old); i++) {
            JsonObject *r = json_array_get_object_element(old, i);
            if (json_array_get_length(next) < 127 && g_strcmp0(linux_ol_string_v1(r, "node_id"), linux_ol_string_v1(node, "node_id"))) json_array_add_element(next, json_node_copy(json_array_get_element(old, i)));
        }
        json_array_add_element(next, json_node_copy(record)); json_node_free(s->history); s->history = json_node_new(JSON_NODE_ARRAY); json_node_take_array(s->history, next);
        linux_ol_message_v1(s, s->cancelled ? "The test finished before cancellation; its 50 responses were saved." : "Saved 50 responses for the selected hop.");
    } else if (complete && drained) {
        if (!strcmp(stage, "complete") && (failure == NULL || !*failure)) return FALSE;
        linux_ol_message_v1(s, "Test stopped; previous saved history is unchanged.");
    } else if (!s->cancelled && !s->closing) linux_ol_message_v1(s, "Measuring 50 responses through the selected hop…");
    s->complete = complete; s->drained = drained; return TRUE;
}
static void linux_ol_render_v1(LinuxOrderedLatencyV1 *s) {
    if (s->dialog == NULL) return;
    gtk_label_set_text(GTK_LABEL(s->message_label), s->message != NULL ? s->message : "");
    gboolean idle = linux_ol_settled_v1(s) && !s->invalid && !s->closing && s->capture != NULL;
    gtk_widget_set_sensitive(s->retest, idle); gtk_widget_set_sensitive(s->hops, idle);
    gtk_widget_set_sensitive(s->cancel, s->request != NULL && !(s->complete && s->drained));
    GString *text = g_string_new("Private entry and exit: HTTP response including connection setup.\nPublic middle: routed HTTPS response after TLS setup. Times are not interchangeable with direct-node rankings.\n\n");
    if (s->history != NULL) {
        JsonArray *history = json_node_get_array(s->history);
        for (guint i = 0; i < json_array_get_length(history); i++) {
            JsonObject *r = json_array_get_object_element(history, i), *b = linux_ol_object_v1(linux_ol_object_v1(r, "result"), "benchmark"), *d = linux_ol_object_v1(b, "distribution");
            guint position = (guint)json_object_get_int_member(r, "position"); JsonObject *n = json_array_get_object_element(json_node_get_array(s->nodes), position);
            GDateTime *date = g_date_time_new_from_unix_local(json_object_get_int_member(r, "measured_at")/1000); char *stamp = date != NULL ? g_date_time_format(date, "%Y-%m-%d %H:%M:%S %Z") : g_strdup("Date unavailable");
            g_string_append_printf(text, "%u. %s (%s) — saved %s\n50 responses: median %.2f ms · trimmed mean %.2f ms\nMin %.2f · average %.2f · p90 %.2f · max %.2f · jitter %.2f ms\n\n", position+1, linux_ol_string_v1(n, "label"), linux_ol_string_v1(n, "role"), stamp,
                json_object_get_double_member(d, "median_ms"), json_object_get_double_member(b, "trimmed_mean_ms"), json_object_get_double_member(d, "min_ms"), json_object_get_double_member(d, "average_ms"), json_object_get_double_member(d, "p90_ms"), json_object_get_double_member(d, "max_ms"), json_object_get_double_member(d, "jitter_ms"));
            g_free(stamp); if (date != NULL) g_date_time_unref(date);
        }
    }
    if (s->history == NULL || json_array_get_length(json_node_get_array(s->history)) == 0) g_string_append(text, "No saved 50-response measurements for this route.");
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(s->history_view)), text->str, -1); g_string_free(text, TRUE);
}
static void linux_ol_cancel_v1(LinuxOrderedLatencyV1 *s) {
    if (s->request == NULL || (s->complete && s->drained)) return;
    s->cancelled = TRUE;
    linux_ol_message_v1(s, "Cancelling the captured request; waiting for native cleanup and HTTP workers.");
    gint64 now = g_get_monotonic_time();
    if (s->jobs[OL_CANCEL_V1] == NULL && now >= s->next_cancel) {
        (void)linux_ol_job_v1(s, OL_CANCEL_V1); s->next_cancel = now + G_TIME_SPAN_SECOND/2;
    }
}
static gboolean linux_ol_start_v1(LinuxOrderedLatencyV1 *s) {
    if (s->invalid || s->closing || s->capture == NULL || !linux_ol_settled_v1(s) || g_strcmp0(active_router_id(s->app), s->displayed)) return FALSE;
    int position = gtk_combo_box_get_active(GTK_COMBO_BOX(s->hops)); if (position < 0 || position > 2) return FALSE;
    char *uuid = g_uuid_string_random(); GString *request = g_string_new(NULL);
    for (const char *p = uuid; *p; p++) if (*p != '-') g_string_append_c(request, *p);
    g_free(uuid); g_free(s->request); s->request = g_string_free(request, FALSE); s->position = position;
    s->generation++; s->complete = FALSE; s->drained = FALSE; s->cancelled = FALSE;
    s->next_poll = 0; s->next_cancel = 0; s->deadline = g_get_monotonic_time() + 100*G_TIME_SPAN_SECOND;
    if (!linux_ol_job_v1(s, OL_START_V1)) {
        g_clear_pointer(&s->request, g_free); s->complete = TRUE; s->drained = TRUE;
        linux_ol_message_v1(s, "No HTTP worker was created; no measurement was started."); return FALSE;
    }
    linux_ol_message_v1(s, "Measuring 50 responses through the selected hop…"); return TRUE;
}
static void linux_ol_free_v1(LinuxOrderedLatencyV1 *s) {
    if (s->parent != NULL && s->parent_destroy != 0) g_signal_handler_disconnect(s->parent, s->parent_destroy);
    g_clear_pointer(&s->capture, json_node_free); g_clear_pointer(&s->nodes, json_node_free); g_clear_pointer(&s->history, json_node_free);
    g_free(s->displayed); g_free(s->request); g_free(s->message); g_free(s);
}
static gboolean linux_ol_tick_v1(gpointer data) {
    LinuxOrderedLatencyV1 *s = data;
    if (!s->detaching && g_strcmp0(active_router_id(s->app), s->displayed)) { s->invalid = TRUE; linux_ol_cancel_v1(s); }
    for (int kind = 0; kind < OL_JOBS_V1; kind++) {
        RVHttpJobV16 *job = s->jobs[kind]; if (job == NULL || !rv_http_ready_v16(job)) continue;
        s->jobs[kind] = NULL;
        if (!s->detaching && s->job_generation[kind] == s->generation) {
            gboolean ok = !atomic_load(&job->cancelled) && job->result == CURLE_OK && job->length <= 1048576 && job->status >= 200 && job->status < 300;
            JsonNode *root = ok ? parse_json(job->response) : NULL; JsonObject *reply = root != NULL && JSON_NODE_HOLDS_OBJECT(root) ? json_node_get_object(root) : NULL;
            if (reply != NULL && linux_ol_receive_v1(s, reply, kind == OL_INFO_V1)) {
                /* Receipt validation above is the sole native-drain authority. */
            } else if (kind == OL_INFO_V1 || !(s->complete && s->drained)) {
                if (kind == OL_INFO_V1 || ok) s->invalid = TRUE;
                linux_ol_message_v1(s, "Measurement response unavailable or rejected; saved history is unchanged.");
                if (s->request != NULL) linux_ol_cancel_v1(s);
            }
            if (root != NULL) json_node_free(root);
        }
        rv_http_free_v16(job);
    }
    if (s->detaching) {
        for (int i = 0; i < OL_JOBS_V1; i++) if (s->jobs[i] != NULL) return G_SOURCE_CONTINUE;
        s->timer = 0; linux_ol_free_v1(s); return G_SOURCE_REMOVE;
    }
    gint64 now = g_get_monotonic_time();
    if (s->request != NULL && !(s->complete && s->drained)) {
        if (now >= s->deadline || s->cancelled || s->invalid || s->closing) linux_ol_cancel_v1(s);
        if (s->jobs[OL_POLL_V1] == NULL && now >= s->next_poll) { (void)linux_ol_job_v1(s, OL_POLL_V1); s->next_poll = now + G_TIME_SPAN_SECOND/2; }
    }
    linux_ol_render_v1(s);
    if (s->closing && linux_ol_settled_v1(s)) {
        GtkWidget *parent = s->parent_closing ? s->parent : NULL; if (parent != NULL) g_object_ref(parent);
        gtk_widget_destroy(s->dialog);
        if (parent != NULL) { gtk_window_close(GTK_WINDOW(parent)); g_object_unref(parent); }
        return G_SOURCE_REMOVE;
    }
    return G_SOURCE_CONTINUE;
}
static void linux_ol_destroy_v1(GtkWidget *widget, gpointer data) {
    (void)widget; LinuxOrderedLatencyV1 *s = data;
    if (s->timer != 0) { g_source_remove(s->timer); s->timer = 0; }
    if (s->parent != NULL && g_object_get_data(G_OBJECT(s->parent), "router-vpn-ordered-latency-v1") == s) g_object_set_data(G_OBJECT(s->parent), "router-vpn-ordered-latency-v1", NULL);
    s->dialog = NULL; s->app = NULL; s->detaching = TRUE; s->generation++;
    for (int i = 0; i < OL_JOBS_V1; i++) rv_http_cancel_v16(s->jobs[i]);
    s->timer = g_timeout_add(50, linux_ol_tick_v1, s);
}
static void linux_ol_parent_destroy_v1(GtkWidget *widget, gpointer data) {
    (void)widget; LinuxOrderedLatencyV1 *s = data; s->parent = NULL; s->parent_destroy = 0;
    /* The existing checked controller shutdown proves native cleanup before
     * parent destruction. Join our original HTTP workers before global CURL exit. */
    if (s->dialog != NULL) gtk_widget_destroy(s->dialog);
    if (s->timer != 0) { g_source_remove(s->timer); s->timer = 0; }
    for (int i = 0; i < OL_JOBS_V1; i++) rv_http_cancel_v16(s->jobs[i]);
    for (int i = 0; i < OL_JOBS_V1; i++) { rv_http_free_v16(s->jobs[i]); s->jobs[i] = NULL; }
    linux_ol_free_v1(s);
}
static gboolean linux_ol_close_v1(LinuxOrderedLatencyV1 *s) {
    s->closing = TRUE;
    if (!linux_ol_settled_v1(s)) { linux_ol_cancel_v1(s); linux_ol_render_v1(s); return FALSE; }
    gtk_widget_destroy(s->dialog); return TRUE;
}
static gboolean linux_ordered_latency_parent_delete_v1(GtkWidget *widget, GdkEvent *event, gpointer data) {
    (void)widget; (void)event; App *app = data;
    LinuxOrderedLatencyV1 *s = g_object_get_data(G_OBJECT(app->window), "router-vpn-ordered-latency-v1");
    if (s == NULL || linux_ol_settled_v1(s)) return FALSE;
    s->parent_closing = TRUE; s->closing = TRUE; linux_ol_cancel_v1(s); linux_ol_render_v1(s); return TRUE;
}
static gboolean linux_ol_delete_v1(GtkWidget *widget, GdkEvent *event, gpointer data) {
    (void)widget; (void)event; (void)linux_ol_close_v1(data); return TRUE;
}
static void linux_ol_response_v1(GtkDialog *dialog, int response, gpointer data) {
    (void)dialog; LinuxOrderedLatencyV1 *s = data;
    if (response == 1) (void)linux_ol_start_v1(s);
    else if (response == 2) linux_ol_cancel_v1(s);
    else if (response == GTK_RESPONSE_CLOSE || response == GTK_RESPONSE_DELETE_EVENT) { (void)linux_ol_close_v1(s); return; }
    linux_ol_render_v1(s);
}
static void linux_ordered_latency_open_v1(App *app) {
    if (app == NULL || app->window == NULL) return;
    LinuxOrderedLatencyV1 *old = g_object_get_data(G_OBJECT(app->window), "router-vpn-ordered-latency-v1");
    if (old != NULL && old->dialog != NULL) { gtk_window_present(GTK_WINDOW(old->dialog)); return; }
    const char *displayed = active_router_id(app); if (!linux_ol_text_v1(displayed, 128)) { append_diag(app, "Connect the selected ordered route first."); return; }
    LinuxOrderedLatencyV1 *s = g_new0(LinuxOrderedLatencyV1, 1); s->app = app; s->parent = app->window; s->displayed = g_strdup(displayed);
    s->generation = 1; s->complete = TRUE; s->drained = TRUE; linux_ol_message_v1(s, "Reading the connected ordered route…");
    s->dialog = gtk_dialog_new_with_buttons("50 responses through each hop", GTK_WINDOW(app->window), GTK_DIALOG_DESTROY_WITH_PARENT,
        "Retest 50 responses", 1, "Cancel test", 2, "Close", GTK_RESPONSE_CLOSE, NULL);
    gtk_window_set_default_size(GTK_WINDOW(s->dialog), 800, 520); gtk_widget_set_size_request(s->dialog, 600, 360);
    GtkWidget *area = gtk_dialog_get_content_area(GTK_DIALOG(s->dialog)); gtk_container_set_border_width(GTK_CONTAINER(area), 16);
    s->hops = gtk_combo_box_text_new(); gtk_box_pack_start(GTK_BOX(area), s->hops, FALSE, FALSE, 5);
    s->message_label = gtk_label_new(s->message); gtk_label_set_line_wrap(GTK_LABEL(s->message_label), TRUE); gtk_label_set_xalign(GTK_LABEL(s->message_label), 0);
    gtk_box_pack_start(GTK_BOX(area), s->message_label, FALSE, FALSE, 5);
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL); s->history_view = gtk_text_view_new(); gtk_text_view_set_editable(GTK_TEXT_VIEW(s->history_view), FALSE); gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(s->history_view), GTK_WRAP_WORD_CHAR);
    gtk_container_add(GTK_CONTAINER(scroll), s->history_view); gtk_box_pack_start(GTK_BOX(area), scroll, TRUE, TRUE, 5);
    s->retest = gtk_dialog_get_widget_for_response(GTK_DIALOG(s->dialog), 1); s->cancel = gtk_dialog_get_widget_for_response(GTK_DIALOG(s->dialog), 2);
    g_object_set_data(G_OBJECT(s->parent), "router-vpn-ordered-latency-v1", s); g_object_set_data(G_OBJECT(s->dialog), "ordered-latency-state", s);
    g_signal_connect(s->dialog, "response", G_CALLBACK(linux_ol_response_v1), s); g_signal_connect(s->dialog, "delete-event", G_CALLBACK(linux_ol_delete_v1), s); g_signal_connect(s->dialog, "destroy", G_CALLBACK(linux_ol_destroy_v1), s);
    s->parent_destroy = g_signal_connect(s->parent, "destroy", G_CALLBACK(linux_ol_parent_destroy_v1), s);
    if (!linux_ol_job_v1(s, OL_INFO_V1)) { s->invalid = TRUE; linux_ol_message_v1(s, "The connected route could not be requested."); }
    linux_ol_render_v1(s); gtk_widget_show_all(s->dialog); s->timer = g_timeout_add(50, linux_ol_tick_v1, s);
}
