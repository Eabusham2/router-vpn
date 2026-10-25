/* A modeless DNS panel owns one captured native path and one request at a time.
 * Only the controller measures DNS. Loopback workers never touch GTK widgets;
 * a transport error cannot attest that admitted native work has drained. */
#include <math.h>

enum { DNS_POLICY_V1, DNS_INFO_V1, DNS_START_V1, DNS_POLL_V1, DNS_CANCEL_V1,
       DNS_SELECT_V1, DNS_SAVE_V1, DNS_JOBS_V1 };
enum { DNS_ROW_ID_V1, DNS_ROW_NAME_V1, DNS_ROW_ADDRESS_V1, DNS_ROW_TRANSPORT_V1,
       DNS_ROW_TIME_V1, DNS_ROW_ROUTE_V1, DNS_ROW_STATE_V1, DNS_ROW_READY_V1,
       DNS_ROW_SORT_V1, DNS_COLUMNS_V1 };
typedef struct {
    App *app;
    GtkWidget *parent, *dialog, *message_label, *selected_label, *draft_label;
    GtkWidget *transport, *table, *retest, *cancel, *choose, *fastest, *save;
    GtkListStore *rows;
    gulong parent_destroy;
    guint timer;
    guint64 generation, job_generation[DNS_JOBS_V1];
    gint64 job_started[DNS_JOBS_V1], next_poll, next_cancel, expires_at;
    RVHttpJobV16 *jobs[DNS_JOBS_V1];
    char *profile, *token, *session, *request, *public_transport, *requested_result;
    char *message, *selected_text, *draft_text;
    JsonNode *results, *draft;
    gboolean owned, complete, drained, successful, cancelled, invalid, closing, detaching, parent_closing;
} LinuxDNSV1;

static gboolean linux_dns_tick_v1(gpointer data);
static void linux_dns_cancel_v1(LinuxDNSV1 *s);
static void refresh_dns_page_v5(App *app);

static const char *linux_dns_string_v1(JsonObject *o, const char *key) {
    JsonNode *n = o != NULL ? json_object_get_member(o, key) : NULL;
    return n != NULL && JSON_NODE_HOLDS_VALUE(n) && json_node_get_value_type(n) == G_TYPE_STRING
        ? json_node_get_string(n) : NULL;
}
static JsonObject *linux_dns_object_v1(JsonObject *o, const char *key) {
    JsonNode *n = o != NULL ? json_object_get_member(o, key) : NULL;
    return n != NULL && JSON_NODE_HOLDS_OBJECT(n) ? json_node_get_object(n) : NULL;
}
static gboolean linux_dns_bool_v1(JsonObject *o, const char *key, gboolean *value) {
    JsonNode *n = o != NULL ? json_object_get_member(o, key) : NULL;
    if (n == NULL || !JSON_NODE_HOLDS_VALUE(n) || json_node_get_value_type(n) != G_TYPE_BOOLEAN) return FALSE;
    *value = json_node_get_boolean(n); return TRUE;
}
static gboolean linux_dns_number_v1(JsonObject *o, const char *key, double *value) {
    JsonNode *n = o != NULL ? json_object_get_member(o, key) : NULL;
    if (n == NULL || !JSON_NODE_HOLDS_VALUE(n)) return FALSE;
    GType type = json_node_get_value_type(n);
    if (type != G_TYPE_INT64 && type != G_TYPE_DOUBLE) return FALSE;
    *value = json_node_get_double(n); return isfinite(*value);
}
static gboolean linux_dns_hex_v1(const char *value, size_t length) {
    if (value == NULL || strlen(value) != length) return FALSE;
    for (size_t i = 0; i < length; i++)
        if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) return FALSE;
    return TRUE;
}
static gboolean linux_dns_text_v1(const char *value, size_t limit) {
    if (value == NULL || !value[0] || strlen(value) > limit || !g_utf8_validate(value, -1, NULL)) return FALSE;
    for (const char *p = value; *p; p++) if ((unsigned char)*p < 32 || *p == 127) return FALSE;
    return TRUE;
}
static void linux_dns_message_v1(LinuxDNSV1 *s, const char *text) {
    g_free(s->message); s->message = g_utf8_make_valid(text != NULL ? text : "DNS status unavailable", -1);
}
static void linux_dns_clear_draft_v1(LinuxDNSV1 *s) {
    g_clear_pointer(&s->draft, json_node_free);
    g_clear_pointer(&s->draft_text, g_free);
}
static gboolean linux_dns_settled_v1(LinuxDNSV1 *s) {
    return (!s->owned || (s->complete && s->drained)) && s->jobs[DNS_START_V1] == NULL &&
        s->jobs[DNS_CANCEL_V1] == NULL && s->jobs[DNS_SELECT_V1] == NULL && s->jobs[DNS_SAVE_V1] == NULL;
}
static gboolean linux_dns_eligible_v1(LinuxDNSV1 *s) {
    return s->successful && s->complete && s->drained && !s->cancelled && !s->invalid &&
        !s->closing && g_get_monotonic_time() < s->expires_at && linux_dns_settled_v1(s);
}
static gboolean linux_dns_job_v1(LinuxDNSV1 *s, int kind, const char *path, const char *body, gboolean get) {
    if (s->detaching || s->jobs[kind] != NULL) return FALSE;
    s->jobs[kind] = rv_http_start_method_v17(path, body != NULL ? body : "", 6000, "Captured DNS", get);
    s->job_generation[kind] = s->generation;
    s->job_started[kind] = g_get_monotonic_time();
    return s->jobs[kind] != NULL;
}
static char *linux_dns_encode_v1(JsonNode *node) {
    JsonGenerator *generator = json_generator_new(); json_generator_set_root(generator, node);
    char *text = json_generator_to_data(generator, NULL); g_object_unref(generator); return text;
}
static char *linux_dns_body_v1(LinuxDNSV1 *s, const char *extra, const char *value) {
    JsonObject *o = json_object_new();
    json_object_set_string_member(o, "profile_id", s->profile);
    json_object_set_string_member(o, "profile_token", s->token);
    json_object_set_string_member(o, "session_id", s->session);
    json_object_set_string_member(o, "request_id", s->request);
    if (extra != NULL) json_object_set_string_member(o, extra, value);
    JsonNode *node = json_node_new(JSON_NODE_OBJECT); json_node_take_object(node, o);
    char *text = linux_dns_encode_v1(node); json_node_free(node); return text;
}
static void linux_dns_invalidate_v1(LinuxDNSV1 *s, const char *reason) {
    s->invalid = TRUE; s->successful = FALSE; linux_dns_clear_draft_v1(s);
    linux_dns_message_v1(s, reason);
    if (s->owned && !(s->complete && s->drained)) linux_dns_cancel_v1(s);
}
static gboolean linux_dns_deadline_v1(LinuxDNSV1 *s, JsonObject *reply, gint64 began) {
    double remaining = 0;
    if (!linux_dns_number_v1(reply, "expires_in_ms", &remaining) || remaining < 0 ||
        remaining > 120000 || floor(remaining) != remaining) return FALSE;
    gint64 deadline = began + (gint64)remaining * G_TIME_SPAN_MILLISECOND;
    if (s->expires_at == 0 || deadline < s->expires_at) s->expires_at = deadline;
    return TRUE;
}
static gboolean linux_dns_public_id_v1(const char *id) {
    const char *ids[] = {"cf4a", "cf4b", "cf6a", "cf6b", "g4a", "g4b", "g6a", "g6b", "q4a", "q4b", "q6a", "q6b"};
    for (guint i = 0; i < G_N_ELEMENTS(ids); i++) if (g_strcmp0(ids[i], id) == 0) return TRUE;
    return FALSE;
}
static gboolean linux_dns_row_ready_v1(JsonObject *row) {
    gboolean ready = FALSE; double median = 0, samples = 0, failed = 0;
    return g_strcmp0(linux_dns_string_v1(row, "kind"), "public") == 0 &&
        linux_dns_public_id_v1(linux_dns_string_v1(row, "id")) &&
        linux_dns_bool_v1(row, "ready", &ready) && ready &&
        linux_dns_number_v1(row, "samples", &samples) && samples == 3 &&
        linux_dns_number_v1(row, "failed", &failed) && failed == 0 &&
        linux_dns_number_v1(row, "median_ms", &median) && median > 0 &&
        (linux_dns_string_v1(row, "failure") == NULL || !linux_dns_string_v1(row, "failure")[0]);
}
static gboolean linux_dns_rows_v1(LinuxDNSV1 *s, JsonObject *status) {
    JsonNode *node = json_object_get_member(status, "results");
    if (node == NULL || !JSON_NODE_HOLDS_ARRAY(node)) return FALSE;
    JsonArray *rows = json_node_get_array(node); guint length = json_array_get_length(rows);
    if (length > 13) return FALSE;
    GHashTable *seen = g_hash_table_new(g_str_hash, g_str_equal); gboolean valid = TRUE;
    for (guint i = 0; i < length && valid; i++) {
        JsonNode *item = json_array_get_element(rows, i);
        if (!JSON_NODE_HOLDS_OBJECT(item)) { valid = FALSE; break; }
        JsonObject *row = json_node_get_object(item);
        const char *id = linux_dns_string_v1(row, "id"), *kind = linux_dns_string_v1(row, "kind");
        gboolean selected = g_strcmp0(kind, "selected") == 0, ready = FALSE;
        double port = 0, samples = 0, failed = 0;
        valid = (selected ? g_strcmp0(id, "selected") == 0 : g_strcmp0(kind, "public") == 0 && linux_dns_public_id_v1(id)) &&
            !g_hash_table_contains(seen, id) && linux_dns_text_v1(linux_dns_string_v1(row, "name"), 160) &&
            linux_dns_text_v1(linux_dns_string_v1(row, "address"), 253) &&
            linux_dns_text_v1(linux_dns_string_v1(row, "route_label"), 160) &&
            linux_dns_text_v1(linux_dns_string_v1(row, "route"), 128) &&
            linux_dns_text_v1(linux_dns_string_v1(row, "transport"), 16) &&
            (selected || g_strcmp0(linux_dns_string_v1(row, "transport"), s->public_transport) == 0) &&
            linux_dns_number_v1(row, "port", &port) && port >= 1 && port <= 65535 && floor(port) == port &&
            linux_dns_number_v1(row, "samples", &samples) && samples >= 0 && samples <= 3 && floor(samples) == samples &&
            linux_dns_number_v1(row, "failed", &failed) && failed >= 0 && failed <= 3 && floor(failed) == failed &&
            linux_dns_bool_v1(row, "ready", &ready);
        if (valid) g_hash_table_add(seen, (gpointer)id);
    }
    g_hash_table_unref(seen); if (!valid) return FALSE;
    g_clear_pointer(&s->results, json_node_free); s->results = json_node_copy(node);
    gtk_list_store_clear(s->rows); g_clear_pointer(&s->selected_text, g_free);
    for (guint i = 0; i < length; i++) {
        JsonObject *row = json_array_get_object_element(rows, i);
        double median = 0, samples = 0, failed = 0; gboolean ready = FALSE;
        (void)linux_dns_number_v1(row, "samples", &samples); (void)linux_dns_number_v1(row, "failed", &failed);
        (void)linux_dns_bool_v1(row, "ready", &ready);
        gboolean timed = ready && samples == 3 && failed == 0 && linux_dns_number_v1(row, "median_ms", &median) && median > 0;
        char *time = timed ? g_strdup_printf("%.2f ms", median) : g_strdup("—");
        const char *failure = linux_dns_string_v1(row, "failure");
        char *state = failure != NULL && failure[0] ? g_strndup(failure, 256) :
            g_strdup_printf("%.0f/3 successful%s", samples, failed > 0 ? " • failed sample" : "");
        if (g_strcmp0(linux_dns_string_v1(row, "kind"), "selected") == 0) {
            s->selected_text = g_strdup_printf("Selected DNS: %s • %s:%d • %s\n%s • median query time %s • %s",
                linux_dns_string_v1(row, "name"), linux_dns_string_v1(row, "address"),
                (int)json_object_get_int_member(row, "port"), linux_dns_string_v1(row, "transport"),
                linux_dns_string_v1(row, "route_label"), time, state);
        } else {
            GtkTreeIter iter; gtk_list_store_append(s->rows, &iter);
            gtk_list_store_set(s->rows, &iter, DNS_ROW_ID_V1, linux_dns_string_v1(row, "id"),
                DNS_ROW_NAME_V1, linux_dns_string_v1(row, "name"), DNS_ROW_ADDRESS_V1, linux_dns_string_v1(row, "address"),
                DNS_ROW_TRANSPORT_V1, linux_dns_string_v1(row, "transport"), DNS_ROW_TIME_V1, time,
                DNS_ROW_ROUTE_V1, linux_dns_string_v1(row, "route_label"), DNS_ROW_STATE_V1, state,
                DNS_ROW_READY_V1, linux_dns_row_ready_v1(row), DNS_ROW_SORT_V1, timed ? median : G_MAXDOUBLE, -1);
        }
        g_free(state); g_free(time);
    }
    return TRUE;
}
static gboolean linux_dns_receive_v1(LinuxDNSV1 *s, JsonObject *reply, gint64 began, gboolean initial) {
    JsonObject *status = linux_dns_object_v1(reply, "status");
    const char *profile = linux_dns_string_v1(reply, "profile_id"), *token = linux_dns_string_v1(reply, "profile_token");
    const char *session = linux_dns_string_v1(reply, "session_id"), *request = linux_dns_string_v1(reply, "request_id");
    const char *stage = linux_dns_string_v1(status, "stage"); gboolean complete = FALSE, drained = FALSE; double schema = 0;
    if (g_strcmp0(profile, s->profile) != 0 || !linux_dns_hex_v1(token, 64) || !linux_dns_hex_v1(session, 32) ||
        (s->token != NULL && g_strcmp0(token, s->token) != 0) || (s->session != NULL && g_strcmp0(session, s->session) != 0) ||
        g_strcmp0(linux_dns_string_v1(status, "node_id"), profile) != 0 ||
        g_strcmp0(linux_dns_string_v1(status, "session_id"), session) != 0 ||
        g_strcmp0(linux_dns_string_v1(status, "request_id"), request) != 0 ||
        !linux_dns_number_v1(status, "schema", &schema) || schema != 1 ||
        !linux_dns_bool_v1(status, "complete", &complete) || !linux_dns_bool_v1(status, "drained", &drained) ||
        (drained && !complete) || !linux_dns_text_v1(stage, 24)) return FALSE;
    if (initial) {
        if (request == NULL || request[0] || g_strcmp0(stage, "idle") != 0 || !complete || !drained ||
            g_strcmp0(active_router_id(s->app), s->profile) != 0) return FALSE;
        s->token = g_strdup(token); s->session = g_strdup(session); s->complete = TRUE; s->drained = TRUE;
        linux_dns_message_v1(s, "Ready to measure DNS queries through this connected path."); return TRUE;
    }
    if (g_strcmp0(request, s->request) != 0 || !linux_dns_hex_v1(request, 32)) return FALSE;
    const char *stages[] = {"preparing", "starting", "measuring", "verifying", "complete", "failed", "cancelled", "invalidated", "draining"};
    gboolean known = FALSE; for (guint i = 0; i < G_N_ELEMENTS(stages); i++) if (strcmp(stage, stages[i]) == 0) known = TRUE;
    if (!known || (!s->cancelled && g_strcmp0(linux_dns_string_v1(status, "public_transport"), s->public_transport) != 0)) return FALSE;
    /* A retained final drain receipt cannot regress when an older Start or Poll
     * reply arrives. It never grants adoption to a cancelled operation. */
    if (s->complete && s->drained) return TRUE;
    if (!s->cancelled && !s->invalid && !linux_dns_rows_v1(s, status)) return FALSE;
    s->complete = complete; s->drained = drained;
    if (complete && drained) {
        const char *failure = linux_dns_string_v1(status, "failure");
        s->successful = !s->cancelled && !s->invalid && strcmp(stage, "complete") == 0 && (failure == NULL || !failure[0]);
        if (s->successful && !linux_dns_deadline_v1(s, reply, began)) return FALSE;
        linux_dns_message_v1(s, s->successful ? "Measured through the captured path. Choose a public resolver, then Disconnect before saving." :
            s->cancelled ? "DNS test cancelled. All workers for this request have stopped." : "DNS test ended without an adoptable result.");
        if (!s->successful) linux_dns_clear_draft_v1(s);
    } else linux_dns_message_v1(s, s->cancelled ? "Cancelling DNS test; waiting for its workers to stop…" :
        complete ? "DNS queries finished; waiting for cleanup…" : "Measuring DNS query time through the captured path…");
    return TRUE;
}
static gboolean linux_dns_start_v1(LinuxDNSV1 *s) {
    if (s->detaching || s->invalid || s->closing || s->session == NULL || !linux_dns_settled_v1(s) ||
        s->app == NULL || linux_async_busy_v16(s->app) || g_strcmp0(active_router_id(s->app), s->profile) != 0) return FALSE;
    const char *transport = gtk_combo_box_get_active_id(GTK_COMBO_BOX(s->transport));
    if (g_strcmp0(transport, "tcp") != 0 && g_strcmp0(transport, "tls") != 0 && g_strcmp0(transport, "https") != 0) return FALSE;
    rv_http_cancel_v16(s->jobs[DNS_POLL_V1]); s->generation++;
    char *uuid = g_uuid_string_random(); GString *nonce = g_string_new(NULL);
    for (char *p = uuid; *p; p++) if (*p != '-') g_string_append_c(nonce, *p);
    g_free(uuid); g_free(s->request); s->request = g_string_free(nonce, FALSE);
    g_free(s->public_transport); s->public_transport = g_strdup(transport);
    linux_dns_clear_draft_v1(s); g_clear_pointer(&s->results, json_node_free);
    gtk_list_store_clear(s->rows); g_clear_pointer(&s->selected_text, g_free);
    s->cancelled = FALSE; s->successful = FALSE; s->expires_at = 0; s->next_poll = 0;
    char *body = linux_dns_body_v1(s, "public_transport", transport);
    gboolean started = linux_dns_job_v1(s, DNS_START_V1, "/api/dns/measurement", body, FALSE); g_free(body);
    if (!started) { linux_dns_message_v1(s, "The DNS request could not be created. Retest can be retried."); return FALSE; }
    s->owned = TRUE; s->complete = FALSE; s->drained = FALSE;
    linux_dns_message_v1(s, "Starting DNS Retest on this captured path…"); return TRUE;
}
static void linux_dns_cancel_v1(LinuxDNSV1 *s) {
    if (s->detaching || !s->owned || (s->complete && s->drained) || s->jobs[DNS_CANCEL_V1] != NULL ||
        g_get_monotonic_time() < s->next_cancel) return;
    s->cancelled = TRUE; s->successful = FALSE; linux_dns_clear_draft_v1(s);
    char *body = linux_dns_body_v1(s, NULL, NULL);
    (void)linux_dns_job_v1(s, DNS_CANCEL_V1, "/api/dns/measurement/cancel", body, FALSE); g_free(body);
    s->next_cancel = g_get_monotonic_time() + G_TIME_SPAN_SECOND;
    linux_dns_message_v1(s, "Cancelling DNS test; waiting for the captured cleanup receipt…");
}
static JsonObject *linux_dns_result_v1(LinuxDNSV1 *s, const char *id) {
    if (s->results == NULL || !JSON_NODE_HOLDS_ARRAY(s->results)) return NULL;
    JsonArray *rows = json_node_get_array(s->results);
    for (guint i = 0; i < json_array_get_length(rows); i++) {
        JsonObject *row = json_array_get_object_element(rows, i);
        if (g_strcmp0(linux_dns_string_v1(row, "id"), id) == 0 && linux_dns_row_ready_v1(row)) return row;
    }
    return NULL;
}
static gboolean linux_dns_choose_v1(LinuxDNSV1 *s, const char *id) {
    if (!linux_dns_eligible_v1(s) || (g_strcmp0(id, "fastest") != 0 && linux_dns_result_v1(s, id) == NULL)) return FALSE;
    if (s->app == NULL || g_strcmp0(active_router_id(s->app), s->profile) != 0) return FALSE;
    linux_dns_clear_draft_v1(s); g_free(s->requested_result); s->requested_result = g_strdup(id);
    char *body = linux_dns_body_v1(s, "result_id", id);
    gboolean ok = linux_dns_job_v1(s, DNS_SELECT_V1, "/api/dns/measurement/select", body, FALSE); g_free(body);
    if (ok) linux_dns_message_v1(s, "Checking the selected measurement before preparing its DNS draft…");
    return ok;
}
static gboolean linux_dns_draft_v1(LinuxDNSV1 *s, JsonObject *reply, gint64 began) {
    JsonObject *draft = linux_dns_object_v1(reply, "draft");
    const char *id = linux_dns_string_v1(draft, "result_id"); JsonObject *row = linux_dns_result_v1(s, id);
    if (s->cancelled || s->invalid || !s->successful || !s->complete || !s->drained || row == NULL ||
        (g_strcmp0(s->requested_result, "fastest") != 0 && g_strcmp0(s->requested_result, id) != 0) ||
        g_strcmp0(linux_dns_string_v1(reply, "session_id"), s->session) != 0 ||
        g_strcmp0(linux_dns_string_v1(reply, "request_id"), s->request) != 0 ||
        g_strcmp0(linux_dns_string_v1(draft, "profile_id"), s->profile) != 0 ||
        g_strcmp0(linux_dns_string_v1(draft, "profile_token"), s->token) != 0 ||
        g_strcmp0(linux_dns_string_v1(draft, "measurement_id"), s->request) != 0 ||
        g_strcmp0(linux_dns_string_v1(draft, "protocol"), linux_dns_string_v1(row, "transport")) != 0 ||
        g_strcmp0(linux_dns_string_v1(draft, "host"), linux_dns_string_v1(row, "address")) != 0 ||
        !linux_dns_deadline_v1(s, reply, began) || g_get_monotonic_time() >= s->expires_at) return FALSE;
    double port = 0, row_port = 0;
    if (!linux_dns_number_v1(draft, "port", &port) || !linux_dns_number_v1(row, "port", &row_port) || port != row_port) return FALSE;
    const char *transport = linux_dns_string_v1(row, "transport");
    const char *mode = strcmp(transport, "tls") == 0 ? "dot" : strcmp(transport, "https") == 0 ? "doh" : "custom";
    if (g_strcmp0(linux_dns_string_v1(draft, "mode"), mode) != 0) return FALSE;
    const char *fields[] = {"server_name", "path"};
    for (guint i = 0; i < G_N_ELEMENTS(fields); i++) {
        const char *a = linux_dns_string_v1(draft, fields[i]), *b = linux_dns_string_v1(row, fields[i]);
        if (g_strcmp0(a != NULL ? a : "", b != NULL ? b : "") != 0) return FALSE;
    }
    linux_dns_clear_draft_v1(s); s->draft = json_node_copy(json_object_get_member(reply, "draft"));
    s->draft_text = g_strdup_printf("Draft: %s • %s:%d • %s. Disconnect on the main window, then choose Save measured DNS.",
        linux_dns_string_v1(row, "name"), linux_dns_string_v1(row, "address"), (int)port, transport);
    linux_dns_message_v1(s, "Measured DNS draft prepared. Your active DNS has not changed."); return TRUE;
}
static gboolean linux_dns_save_v1(LinuxDNSV1 *s) {
    if (!linux_dns_eligible_v1(s) || s->draft == NULL || s->app == NULL ||
        g_strcmp0(active_router_id(s->app), s->profile) != 0) return FALSE;
    if (!routervpn_require_mutation_idle(s->app, "saving measured DNS")) {
        linux_dns_message_v1(s, "Disconnect on the main window and wait for cleanup before saving this DNS draft."); return FALSE;
    }
    char *body = linux_dns_encode_v1(s->draft);
    gboolean ok = linux_dns_job_v1(s, DNS_SAVE_V1, "/api/dns/policy", body, FALSE); g_free(body);
    if (ok) linux_dns_message_v1(s, "Saving this exact measured DNS draft for the next connection…");
    return ok;
}
static gboolean linux_dns_saved_v1(LinuxDNSV1 *s, JsonObject *reply) {
    if (s->draft == NULL || g_strcmp0(linux_dns_string_v1(reply, "profile_id"), s->profile) != 0) return FALSE;
    JsonObject *draft = json_node_get_object(s->draft);
    const char *fields[] = {"mode", "protocol", "host", "server_name", "path"};
    for (guint i = 0; i < G_N_ELEMENTS(fields); i++) {
        const char *a = linux_dns_string_v1(draft, fields[i]), *b = linux_dns_string_v1(reply, fields[i]);
        if (g_strcmp0(a != NULL ? a : "", b != NULL ? b : "") != 0) return FALSE;
    }
    double a = 0, b = 0; return linux_dns_number_v1(draft, "port", &a) && linux_dns_number_v1(reply, "port", &b) && a == b;
}
static void linux_dns_render_v1(LinuxDNSV1 *s) {
    if (s->dialog == NULL) return;
    gtk_label_set_text(GTK_LABEL(s->message_label), s->message != NULL ? s->message : "");
    gtk_label_set_text(GTK_LABEL(s->selected_label), s->selected_text != NULL ? s->selected_text : "Selected DNS is measured separately along its actual route.");
    char *draft = s->draft_text != NULL ? g_strdup_printf("%s\nExpires in %.0f seconds.", s->draft_text,
        MAX(0.0, (double)(s->expires_at - g_get_monotonic_time()) / G_TIME_SPAN_SECOND)) : g_strdup("No measured resolver is selected for saving.");
    gtk_label_set_text(GTK_LABEL(s->draft_label), draft); g_free(draft);
    gboolean ready = !s->invalid && !s->closing && s->session != NULL && linux_dns_settled_v1(s);
    gtk_widget_set_sensitive(s->retest, ready); gtk_widget_set_sensitive(s->transport, ready);
    gtk_widget_set_sensitive(s->cancel, s->owned && !(s->complete && s->drained) && s->jobs[DNS_CANCEL_V1] == NULL);
    gboolean eligible = linux_dns_eligible_v1(s);
    gtk_widget_set_sensitive(s->choose, eligible); gtk_widget_set_sensitive(s->fastest, eligible);
    gtk_widget_set_sensitive(s->save, eligible && s->draft != NULL);
}
static void linux_dns_free_v1(LinuxDNSV1 *s) {
    if (s->parent != NULL && s->parent_destroy != 0) g_signal_handler_disconnect(s->parent, s->parent_destroy);
    g_free(s->profile); g_free(s->token); g_free(s->session); g_free(s->request); g_free(s->public_transport);
    g_free(s->requested_result); g_free(s->message); g_free(s->selected_text); linux_dns_clear_draft_v1(s);
    g_clear_pointer(&s->results, json_node_free); g_object_unref(s->rows); g_free(s);
}
static gboolean linux_dns_tick_v1(gpointer data) {
    LinuxDNSV1 *s = data;
    for (int kind = 0; kind < DNS_JOBS_V1; kind++) {
        RVHttpJobV16 *job = s->jobs[kind]; if (job == NULL || !rv_http_ready_v16(job)) continue;
        s->jobs[kind] = NULL;
        if (!s->detaching && s->job_generation[kind] == s->generation) {
            JsonNode *root = job->response != NULL && job->length <= 131072 ? parse_json(job->response) : NULL;
            JsonObject *reply = root != NULL && JSON_NODE_HOLDS_OBJECT(root) ? json_node_get_object(root) : NULL;
            gboolean ok = job->result == CURLE_OK && job->status >= 200 && job->status < 300 && !atomic_load(&job->cancelled);
            if (kind == DNS_POLICY_V1) {
                const char *kind_name = linux_dns_string_v1(reply, "node_kind");
                if (!ok || g_strcmp0(linux_dns_string_v1(reply, "profile_id"), s->profile) != 0 ||
                    g_strcmp0(active_router_id(s->app), s->profile) != 0) linux_dns_invalidate_v1(s, "The displayed node changed or its DNS settings could not be read. Reopen DNS Retest.");
                else if (g_strcmp0(kind_name, "external") == 0) {
                    if (!linux_dns_job_v1(s, DNS_INFO_V1, "/api/dns/measurement", "", TRUE)) linux_dns_invalidate_v1(s, "The active DNS path could not be requested.");
                } else if (g_strcmp0(kind_name, "router-vpn") == 0) {
                    post_and_log(s->app, "/api/dns/retest", "{}", 90000, "DNS Retest");
                    s->closing = TRUE;
                } else linux_dns_invalidate_v1(s, "The selected node has no recognized DNS path. Refresh its settings.");
            } else if (kind == DNS_INFO_V1) {
                if (!ok || !linux_dns_receive_v1(s, reply, s->job_started[kind], TRUE))
                    linux_dns_invalidate_v1(s, "DNS Retest needs this node's currently proved native connection. Connect it, then reopen Retest.");
            } else if (kind == DNS_SELECT_V1) {
                if (!ok || !linux_dns_draft_v1(s, reply, s->job_started[kind])) linux_dns_invalidate_v1(s, "This DNS result expired or no longer belongs to the captured path. No draft was adopted.");
            } else if (kind == DNS_SAVE_V1) {
                gboolean saved = ok && linux_dns_saved_v1(s, reply);
                linux_dns_clear_draft_v1(s); s->invalid = TRUE; s->successful = FALSE;
                linux_dns_message_v1(s, saved ? "Measured DNS saved for the next connection. Reconnect to prove its active path." : "DNS save was not confirmed. Refresh DNS settings before making another change.");
                if (saved) { append_diag(s->app, s->message); refresh_dns_page_v5(s->app); }
            } else if (ok && linux_dns_receive_v1(s, reply, s->job_started[kind], FALSE)) {
                /* Only a matching native receipt or no-work tombstone sets drained. */
            } else {
                if (kind == DNS_START_V1 || (ok && reply != NULL))
                    linux_dns_invalidate_v1(s, "DNS response was rejected. Cancelling only the captured request and waiting for cleanup.");
                else linux_dns_message_v1(s, "DNS progress is unavailable. Retrying this captured request; cleanup is not yet confirmed.");
                if (s->cancelled) s->next_cancel = g_get_monotonic_time();
            }
            if (root != NULL) json_node_free(root);
        }
        rv_http_free_v16(job);
    }
    if (s->detaching) {
        for (int i = 0; i < DNS_JOBS_V1; i++) if (s->jobs[i] != NULL) return G_SOURCE_CONTINUE;
        s->timer = 0; linux_dns_free_v1(s); return G_SOURCE_REMOVE;
    }
    gint64 now = g_get_monotonic_time();
    if (s->draft != NULL && now >= s->expires_at) {
        linux_dns_clear_draft_v1(s); linux_dns_message_v1(s, "The measured DNS draft expired. Retest the current connection before selecting another result.");
    }
    if (s->owned && !(s->complete && s->drained)) {
        if (s->cancelled || s->invalid || s->closing) linux_dns_cancel_v1(s);
        if (s->jobs[DNS_POLL_V1] == NULL && now >= s->next_poll) {
            char *path = g_strdup_printf("/api/dns/measurement?request_id=%s", s->request);
            (void)linux_dns_job_v1(s, DNS_POLL_V1, path, "", TRUE); g_free(path);
            s->next_poll = now + G_TIME_SPAN_SECOND / 2;
        }
    }
    linux_dns_render_v1(s);
    if (s->closing && linux_dns_settled_v1(s)) {
        GtkWidget *parent = s->parent_closing ? s->parent : NULL;
        if (parent != NULL) g_object_ref(parent);
        gtk_widget_destroy(s->dialog);
        if (parent != NULL) { gtk_window_close(GTK_WINDOW(parent)); g_object_unref(parent); }
        return G_SOURCE_REMOVE;
    }
    return G_SOURCE_CONTINUE;
}
static void linux_dns_destroy_v1(GtkWidget *widget, gpointer data) {
    (void)widget; LinuxDNSV1 *s = data;
    if (s->timer != 0) { g_source_remove(s->timer); s->timer = 0; }
    if (s->app != NULL && s->app->window != NULL && g_object_get_data(G_OBJECT(s->app->window), "router-vpn-dns-measurement-v1") == s)
        g_object_set_data(G_OBJECT(s->app->window), "router-vpn-dns-measurement-v1", NULL);
    s->dialog = NULL; s->app = NULL; s->detaching = TRUE; s->generation++;
    for (int i = 0; i < DNS_JOBS_V1; i++) rv_http_cancel_v16(s->jobs[i]);
    s->timer = g_timeout_add(50, linux_dns_tick_v1, s);
}
static void linux_dns_parent_destroy_v1(GtkWidget *widget, gpointer data) {
    (void)widget; LinuxDNSV1 *s = data; s->parent = NULL; s->parent_destroy = 0;
    /* Parent destruction follows the app's checked controller cleanup, which
     * drains native DNS. Join only our loopback workers before global CURL exit. */
    if (s->dialog != NULL) gtk_widget_destroy(s->dialog);
    if (s->timer != 0) { g_source_remove(s->timer); s->timer = 0; }
    for (int i = 0; i < DNS_JOBS_V1; i++) rv_http_cancel_v16(s->jobs[i]);
    for (int i = 0; i < DNS_JOBS_V1; i++) { rv_http_free_v16(s->jobs[i]); s->jobs[i] = NULL; }
    linux_dns_free_v1(s);
}
static gboolean linux_dns_close_v1(LinuxDNSV1 *s) {
    s->closing = TRUE;
    if (!linux_dns_settled_v1(s)) { linux_dns_cancel_v1(s); linux_dns_render_v1(s); return FALSE; }
    gtk_widget_destroy(s->dialog); return TRUE;
}
static gboolean linux_dns_parent_delete_v1(GtkWidget *widget, GdkEvent *event, gpointer data) {
    (void)widget; (void)event; App *app = data;
    LinuxDNSV1 *s = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-measurement-v1");
    if (s == NULL || linux_dns_settled_v1(s)) return FALSE;
    s->parent_closing = TRUE; s->closing = TRUE; linux_dns_cancel_v1(s); linux_dns_render_v1(s);
    return TRUE;
}
static gboolean linux_dns_delete_v1(GtkWidget *widget, GdkEvent *event, gpointer data) {
    (void)widget; (void)event; (void)linux_dns_close_v1(data); return TRUE;
}
static void linux_dns_response_v1(GtkDialog *dialog, int response, gpointer data) {
    (void)dialog; LinuxDNSV1 *s = data;
    if (response == 1) (void)linux_dns_start_v1(s);
    else if (response == 2) linux_dns_cancel_v1(s);
    else if (response == 3) {
        GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(s->table)); GtkTreeIter iter; GtkTreeModel *model;
        if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
            char *id = NULL; gtk_tree_model_get(model, &iter, DNS_ROW_ID_V1, &id, -1);
            (void)linux_dns_choose_v1(s, id); g_free(id);
        } else linux_dns_message_v1(s, "Select a public resolver row with three successful samples.");
    } else if (response == 4) (void)linux_dns_choose_v1(s, "fastest");
    else if (response == 5) (void)linux_dns_save_v1(s);
    else if (response == GTK_RESPONSE_CLOSE || response == GTK_RESPONSE_DELETE_EVENT) { (void)linux_dns_close_v1(s); return; }
    linux_dns_render_v1(s);
}
static GtkWidget *linux_dns_label_v1(GtkWidget *area, const char *text) {
    GtkWidget *label = gtk_label_new(text); gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_label_set_xalign(GTK_LABEL(label), 0); gtk_label_set_selectable(GTK_LABEL(label), TRUE);
    gtk_box_pack_start(GTK_BOX(area), label, FALSE, FALSE, 6); return label;
}
static void linux_dns_retest_v1(App *app) {
    if (app == NULL || app->window == NULL) return;
    LinuxDNSV1 *existing = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-measurement-v1");
    if (existing != NULL && existing->dialog != NULL) { gtk_window_present(GTK_WINDOW(existing->dialog)); return; }
    const char *displayed = active_router_id(app);
    if (!linux_dns_text_v1(displayed, 128)) { append_diag(app, "Select a node before DNS Retest."); return; }
    LinuxDNSV1 *s = g_new0(LinuxDNSV1, 1); s->app = app; s->parent = app->window;
    s->profile = g_strdup(displayed); s->generation = 1; s->complete = TRUE; s->drained = TRUE;
    linux_dns_message_v1(s, "Reading the displayed node and its active DNS path…");
    s->dialog = gtk_dialog_new_with_buttons("DNS query measurements", GTK_WINDOW(app->window), GTK_DIALOG_DESTROY_WITH_PARENT,
        "Retest", 1, "Cancel test", 2, "Use selected", 3, "Use fastest", 4, "Save measured DNS", 5, "Close", GTK_RESPONSE_CLOSE, NULL);
    gtk_window_set_default_size(GTK_WINDOW(s->dialog), 920, 560); gtk_widget_set_size_request(s->dialog, 700, 420);
    GtkWidget *area = gtk_dialog_get_content_area(GTK_DIALOG(s->dialog)); gtk_container_set_border_width(GTK_CONTAINER(area), 16);
    (void)linux_dns_label_v1(area, "Compare median DNS query time from three successful samples through this connection. Public resolvers use the exit route; selected DNS keeps its own route. A failed result cannot win Fastest.");
    s->transport = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(s->transport), "tcp", "Public comparison: DNS over TCP");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(s->transport), "tls", "Public comparison: DNS over TLS");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(s->transport), "https", "Public comparison: DNS over HTTPS");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(s->transport), "tls"); gtk_box_pack_start(GTK_BOX(area), s->transport, FALSE, FALSE, 4);
    s->message_label = linux_dns_label_v1(area, s->message); s->selected_label = linux_dns_label_v1(area, "");
    s->rows = gtk_list_store_new(DNS_COLUMNS_V1, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
        G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_BOOLEAN, G_TYPE_DOUBLE);
    s->table = gtk_tree_view_new_with_model(GTK_TREE_MODEL(s->rows));
    const char *titles[] = {"Resolver", "Address", "Transport", "Query median", "Route", "Samples / status"};
    int columns[] = {DNS_ROW_NAME_V1, DNS_ROW_ADDRESS_V1, DNS_ROW_TRANSPORT_V1, DNS_ROW_TIME_V1, DNS_ROW_ROUTE_V1, DNS_ROW_STATE_V1};
    for (guint i = 0; i < G_N_ELEMENTS(columns); i++) {
        GtkCellRenderer *renderer = gtk_cell_renderer_text_new();
        GtkTreeViewColumn *column = gtk_tree_view_column_new_with_attributes(titles[i], renderer, "text", columns[i], NULL);
        gtk_tree_view_column_set_resizable(column, TRUE); gtk_tree_view_column_set_sort_column_id(column, i == 3 ? DNS_ROW_SORT_V1 : columns[i]);
        gtk_tree_view_append_column(GTK_TREE_VIEW(s->table), column);
    }
    gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(s->rows), DNS_ROW_SORT_V1, GTK_SORT_ASCENDING);
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL); gtk_container_add(GTK_CONTAINER(scroll), s->table);
    gtk_box_pack_start(GTK_BOX(area), scroll, TRUE, TRUE, 4); s->draft_label = linux_dns_label_v1(area, "");
    s->retest = gtk_dialog_get_widget_for_response(GTK_DIALOG(s->dialog), 1); s->cancel = gtk_dialog_get_widget_for_response(GTK_DIALOG(s->dialog), 2);
    s->choose = gtk_dialog_get_widget_for_response(GTK_DIALOG(s->dialog), 3); s->fastest = gtk_dialog_get_widget_for_response(GTK_DIALOG(s->dialog), 4);
    s->save = gtk_dialog_get_widget_for_response(GTK_DIALOG(s->dialog), 5);
    g_object_set_data(G_OBJECT(app->window), "router-vpn-dns-measurement-v1", s);
    g_signal_connect(s->dialog, "response", G_CALLBACK(linux_dns_response_v1), s);
    g_signal_connect(s->dialog, "delete-event", G_CALLBACK(linux_dns_delete_v1), s);
    g_signal_connect(s->dialog, "destroy", G_CALLBACK(linux_dns_destroy_v1), s);
    s->parent_destroy = g_signal_connect(s->parent, "destroy", G_CALLBACK(linux_dns_parent_destroy_v1), s);
    if (!linux_dns_job_v1(s, DNS_POLICY_V1, "/api/dns/policy", "", TRUE)) linux_dns_invalidate_v1(s, "The selected DNS policy could not be requested.");
    linux_dns_render_v1(s); gtk_widget_show_all(s->dialog); s->timer = g_timeout_add(50, linux_dns_tick_v1, s);
}
