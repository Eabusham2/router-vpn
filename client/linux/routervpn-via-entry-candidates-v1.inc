/* Candidate response receipts are dialog-local. They never replace direct RTT
 * cache values or start a VPN. Only the controller can validate their source,
 * network generation and exact saved entry settings before exit selection. */
#include "routervpn-http-job-v16.h"

typedef struct {
    LinuxMultihopDialogV7 *parent;
    GtkWidget *dialog, *heading, *status, *list, *select, *fastest, *retest, *cancel;
    GtkListStore *rows;
    GPtrArray *ids;
    GHashTable *names, *eligible;
    char *entry_id, *entry_name, *entry_base, *entry_mode, *request_id, *fastest_id, *pending_exit, *last_error;
    RVHttpJobV16 *job, *cancel_job;
    guint poll;
    gint64 expires_at;
    gboolean receipt, cancelled, cancel_ack, allow_close, close_main, close_parent;
    int operation, after_cancel;
} LinuxCandidatesV1;

enum { LINUX_CANDIDATES_MEASURE_V1 = 1, LINUX_CANDIDATES_VALIDATE_V1 = 2 };
enum { LINUX_CANDIDATES_CANCEL_V1 = 0, LINUX_CANDIDATES_RETEST_V1 = 1, LINUX_CANDIDATES_CLOSE_V1 = 2 };
enum { LINUX_CANDIDATE_ID_V1, LINUX_CANDIDATE_NAME_V1, LINUX_CANDIDATE_TEXT_V1, LINUX_CANDIDATE_ELIGIBLE_V1, LINUX_CANDIDATE_MEDIAN_V1, LINUX_CANDIDATE_COLUMNS_V1 };

static const char *linux_candidates_string_v1(JsonObject *o, const char *key) {
    JsonNode *n = o != NULL ? json_object_get_member(o, key) : NULL;
    return n != NULL && JSON_NODE_HOLDS_VALUE(n) && json_node_get_value_type(n) == G_TYPE_STRING ? json_node_get_string(n) : "";
}
static gboolean linux_candidates_true_v1(JsonObject *o, const char *key) {
    JsonNode *n = o != NULL ? json_object_get_member(o, key) : NULL;
    return n != NULL && JSON_NODE_HOLDS_VALUE(n) && json_node_get_value_type(n) == G_TYPE_BOOLEAN && json_node_get_boolean(n);
}
static double linux_candidates_number_v1(JsonObject *o, const char *key) {
    JsonNode *n = o != NULL ? json_object_get_member(o, key) : NULL;
    if (n == NULL || !JSON_NODE_HOLDS_VALUE(n)) return NAN;
    GType type = json_node_get_value_type(n);
    return type == G_TYPE_DOUBLE || type == G_TYPE_INT64 ? json_node_get_double(n) : NAN;
}
static gboolean linux_candidates_current_v1(LinuxCandidatesV1 *s) {
    return !s->allow_close && g_object_get_data(G_OBJECT(s->parent->dialog), "linux-via-entry-candidates-v1") == s &&
        g_strcmp0(gtk_combo_box_get_active_id(GTK_COMBO_BOX(s->parent->entry)), s->entry_id) == 0;
}
static gboolean linux_candidates_fresh_v1(LinuxCandidatesV1 *s) {
    return linux_candidates_current_v1(s) && !s->cancelled && s->receipt && s->expires_at > g_get_real_time();
}
static void linux_candidates_buttons_v1(LinuxCandidatesV1 *s) {
    gboolean idle = s->job == NULL && s->cancel_job == NULL && !s->cancelled;
    gboolean fresh = idle && linux_candidates_fresh_v1(s), eligible = FALSE;
    GtkTreeModel *model = NULL; GtkTreeIter iter;
    if (gtk_tree_selection_get_selected(gtk_tree_view_get_selection(GTK_TREE_VIEW(s->list)), &model, &iter))
        gtk_tree_model_get(model, &iter, LINUX_CANDIDATE_ELIGIBLE_V1, &eligible, -1);
    gtk_widget_set_sensitive(s->select, fresh && eligible);
    gtk_widget_set_sensitive(s->fastest, fresh && s->fastest_id != NULL && s->fastest_id[0]);
    gtk_widget_set_sensitive(s->retest, idle);
    gtk_widget_set_sensitive(s->cancel, s->request_id != NULL && s->cancel_job == NULL);
    if (s->receipt && idle && !fresh)
        gtk_label_set_text(GTK_LABEL(s->status), "Measurements expired or the entry changed. Retest before selecting an exit.");
}
static gboolean linux_candidates_reject_v1(char **error, const char *reason) {
    if (error != NULL) *error = g_strdup(reason);
    return FALSE;
}
static gboolean linux_candidates_receipt_v1(LinuxCandidatesV1 *s, const char *json, char **error) {
    s->receipt = FALSE; s->expires_at = 0;
    JsonNode *root = parse_json(json);
    if (root == NULL || !JSON_NODE_HOLDS_OBJECT(root)) {
        if (root != NULL) json_node_free(root);
        return linux_candidates_reject_v1(error, "Invalid routed measurement response.");
    }
    JsonObject *top = json_node_get_object(root);
    const char *base = linux_candidates_string_v1(top, "entry_base"), *mode = linux_candidates_string_v1(top, "entry_mode");
    gboolean base_matches = (strcmp(base, "wg") == 0 && strcmp(mode, "wg") == 0) ||
        (strcmp(base, "awg") == 0 && (strcmp(mode, "awg2-fast") == 0 || strcmp(mode, "awg2-strong") == 0));
    gboolean valid = linux_candidates_number_v1(top, "schema") == 1 &&
        g_strcmp0(linux_candidates_string_v1(top, "request_id"), s->request_id) == 0 &&
        g_strcmp0(linux_candidates_string_v1(top, "entry_id"), s->entry_id) == 0 &&
        base_matches && linux_candidates_true_v1(top, "drained");
    GDateTime *expiry = g_date_time_new_from_iso8601(linux_candidates_string_v1(top, "expires_at"), NULL);
    GDateTime *measured = g_date_time_new_from_iso8601(linux_candidates_string_v1(top, "measured_at"), NULL);
    gint64 expires = expiry != NULL ? g_date_time_to_unix(expiry) * G_USEC_PER_SEC + g_date_time_get_microsecond(expiry) : 0;
    valid = valid && expiry != NULL && measured != NULL && expires > g_get_real_time() && g_date_time_compare(expiry, measured) > 0;
    if (expiry != NULL) g_date_time_unref(expiry);
    if (measured != NULL) g_date_time_unref(measured);
    if (!valid) {
        json_node_free(root);
        return linux_candidates_reject_v1(error, "The routed receipt is stale, belongs to another request or entry, or native cleanup is incomplete. Retest.");
    }
    GHashTable *results = g_hash_table_new(g_str_hash, g_str_equal), *errors = g_hash_table_new(g_str_hash, g_str_equal);
    const char *fields[] = {"results", "errors"}; GHashTable *tables[] = {results, errors};
    for (guint field = 0; field < G_N_ELEMENTS(fields) && valid; field++) {
        JsonNode *node = json_object_get_member(top, fields[field]);
        if (node == NULL || JSON_NODE_HOLDS_NULL(node)) continue;
        if (!JSON_NODE_HOLDS_ARRAY(node)) { valid = FALSE; break; }
        JsonArray *items = json_node_get_array(node);
        if (json_array_get_length(items) > 64) { valid = FALSE; break; }
        for (guint i = 0; i < json_array_get_length(items); i++) {
            JsonNode *item = json_array_get_element(items, i);
            if (item == NULL || !JSON_NODE_HOLDS_OBJECT(item)) { valid = FALSE; break; }
            JsonObject *o = json_node_get_object(item); const char *id = linux_candidates_string_v1(o, "id");
            if (!g_hash_table_contains(s->names, id) || g_hash_table_contains(tables[field], id)) { valid = FALSE; break; }
            g_hash_table_insert(tables[field], (gpointer)id, o);
        }
    }
    gtk_list_store_clear(s->rows); g_hash_table_remove_all(s->eligible);
    for (guint i = 0; i < s->ids->len && valid; i++) {
        const char *id = g_ptr_array_index(s->ids, i);
        if (!g_hash_table_contains(results, id) && !g_hash_table_contains(errors, id)) valid = FALSE;
    }
    if (valid) {
        const char *base_name = strcmp(mode, "awg2-strong") == 0 ? "AmneziaWG Strong" : strcmp(mode, "awg2-fast") == 0 ? "AmneziaWG Fast" : "WireGuard";
        for (guint i = 0; i < s->ids->len; i++) {
            const char *id = g_ptr_array_index(s->ids, i), *name = g_hash_table_lookup(s->names, id);
            JsonObject *result = g_hash_table_lookup(results, id), *failure = g_hash_table_lookup(errors, id);
            double samples = linux_candidates_number_v1(result, "samples"), failed = linux_candidates_number_v1(result, "failed"), median = linux_candidates_number_v1(result, "median_ms");
            gboolean eligible = result != NULL && failure == NULL && isfinite(samples) && samples >= 3 && floor(samples) == samples && failed == 0 && isfinite(median) && median > 0;
            char *line;
            if (eligible) {
                line = g_strdup_printf("via %s · TCP response %.1f ms · %s · %.0f samples", s->entry_name, median, base_name, samples);
                g_hash_table_add(s->eligible, g_strdup(id));
            } else if (failure != NULL) {
                line = g_strdup_printf("via %s · unavailable — %s", s->entry_name, linux_candidates_string_v1(failure, "error"));
            } else if (result != NULL && isfinite(samples) && isfinite(failed)) {
                line = g_strdup_printf("via %s · unavailable — %.0f successful samples, %.0f failed; at least 3 and no failures are required", s->entry_name, samples, failed);
            } else line = g_strdup_printf("via %s · unavailable — no routed response", s->entry_name);
            GtkTreeIter row; gtk_list_store_append(s->rows, &row);
            gtk_list_store_set(s->rows, &row, LINUX_CANDIDATE_ID_V1, id, LINUX_CANDIDATE_NAME_V1, name,
                LINUX_CANDIDATE_TEXT_V1, line, LINUX_CANDIDATE_ELIGIBLE_V1, eligible, LINUX_CANDIDATE_MEDIAN_V1, eligible ? median : 0, -1);
            g_free(line);
        }
        const char *fastest = linux_candidates_string_v1(top, "fastest_id");
        if (fastest[0] && !g_hash_table_contains(s->eligible, fastest)) valid = FALSE;
        if (valid) {
            g_free(s->fastest_id); s->fastest_id = g_strdup(fastest); s->expires_at = expires; s->receipt = TRUE;
            g_free(s->entry_base); g_free(s->entry_mode); s->entry_base = g_strdup(base); s->entry_mode = g_strdup(mode);
            char *title = g_strdup_printf("Candidate exits via %s · %s entry", s->entry_name, base_name);
            gtk_label_set_text(GTK_LABEL(s->heading), title); g_free(title);
        }
    }
    g_hash_table_unref(results); g_hash_table_unref(errors); json_node_free(root);
    if (!valid) {
        gtk_list_store_clear(s->rows); g_hash_table_remove_all(s->eligible);
        return linux_candidates_reject_v1(error, "The routed response contains unknown or duplicate candidates, or an ineligible fastest result.");
    }
    return TRUE;
}
static gboolean linux_candidates_validated_v1(LinuxCandidatesV1 *s, const char *json) {
    if (!linux_candidates_fresh_v1(s) || s->pending_exit == NULL || !g_hash_table_contains(s->eligible, s->pending_exit)) return FALSE;
    JsonNode *root = parse_json(json);
    if (root == NULL || !JSON_NODE_HOLDS_OBJECT(root)) { if (root != NULL) json_node_free(root); return FALSE; }
    JsonObject *o = json_node_get_object(root);
    gboolean ok = linux_candidates_true_v1(o, "ok") && linux_candidates_true_v1(o, "measured") &&
        g_strcmp0(linux_candidates_string_v1(o, "request_id"), s->request_id) == 0 &&
        g_strcmp0(linux_candidates_string_v1(o, "entry_id"), s->entry_id) == 0 &&
        g_strcmp0(linux_candidates_string_v1(o, "exit_id"), s->pending_exit) == 0 &&
        g_strcmp0(linux_candidates_string_v1(o, "entry_base"), s->entry_base) == 0 &&
        g_strcmp0(linux_candidates_string_v1(o, "entry_mode"), s->entry_mode) == 0;
    json_node_free(root); return ok;
}
static char *linux_candidates_payload_v1(LinuxCandidatesV1 *s, gboolean cancel, gboolean validate) {
    JsonBuilder *b = json_builder_new(); json_builder_begin_object(b);
    json_builder_set_member_name(b, "request_id"); json_builder_add_string_value(b, s->request_id);
    if (!cancel) {
        json_builder_set_member_name(b, "entry_id"); json_builder_add_string_value(b, s->entry_id);
        if (validate) { json_builder_set_member_name(b, "exit_id"); json_builder_add_string_value(b, s->pending_exit); }
        else {
            /* Match Linux Connect's saved base resolver; the receipt captures
             * its actual WG/AWG graph and validation binds that same decision. */
            json_builder_set_member_name(b, "base"); json_builder_add_string_value(b, "auto");
            json_builder_set_member_name(b, "candidate_ids"); json_builder_begin_array(b);
            for (guint i = 0; i < s->ids->len; i++) json_builder_add_string_value(b, g_ptr_array_index(s->ids, i));
            json_builder_end_array(b); json_builder_set_member_name(b, "samples"); json_builder_add_int_value(b, 5);
        }
    }
    json_builder_end_object(b); JsonNode *root = json_builder_get_root(b); JsonGenerator *g = json_generator_new();
    json_generator_set_root(g, root); char *out = json_generator_to_data(g, NULL);
    g_object_unref(g); json_node_free(root); g_object_unref(b); return out;
}
static void linux_candidates_start_v1(LinuxCandidatesV1 *s);
static void linux_candidates_cancel_v1(LinuxCandidatesV1 *s, int after);
static void linux_candidates_finish_cancel_v1(LinuxCandidatesV1 *s) {
    if (!s->cancel_ack || s->job != NULL || s->cancel_job != NULL) return;
    int after = s->after_cancel; g_clear_pointer(&s->request_id, g_free); s->cancelled = FALSE; s->cancel_ack = FALSE;
    if (after == LINUX_CANDIDATES_CLOSE_V1) {
        s->allow_close = TRUE; gtk_dialog_response(GTK_DIALOG(s->dialog), GTK_RESPONSE_CLOSE); return;
    }
    if (after == LINUX_CANDIDATES_RETEST_V1) { linux_candidates_start_v1(s); return; }
    char *message = g_strdup_printf("%sNative cleanup is confirmed. Retest to measure again.", s->last_error != NULL ? s->last_error : "Cancelled. ");
    gtk_label_set_text(GTK_LABEL(s->status), message); g_free(message); linux_candidates_buttons_v1(s);
}
static void linux_candidates_cancel_v1(LinuxCandidatesV1 *s, int after) {
    if (s->allow_close) return;
    if (s->after_cancel != LINUX_CANDIDATES_CLOSE_V1) s->after_cancel = after;
    s->cancelled = TRUE; s->receipt = FALSE; g_hash_table_remove_all(s->eligible); g_clear_pointer(&s->fastest_id, g_free);
    if (s->request_id == NULL) { s->cancel_ack = TRUE; linux_candidates_finish_cancel_v1(s); return; }
    rv_http_cancel_v16(s->job);
    if (s->cancel_job == NULL && !s->cancel_ack) {
        gtk_label_set_text(GTK_LABEL(s->status), "Cancelling and waiting for native cleanup…");
        char *body = linux_candidates_payload_v1(s, TRUE, FALSE);
        s->cancel_job = rv_http_start_v16("/api/multihop/candidates/cancel", body, 180000, "Cancel routed candidate measurement"); g_free(body);
        if (s->cancel_job == NULL) gtk_label_set_text(GTK_LABEL(s->status), "Could not start cleanup request. Retry Cancel; Retest and selection remain unavailable.");
    }
    linux_candidates_buttons_v1(s);
}
static void linux_candidates_start_v1(LinuxCandidatesV1 *s) {
    if (!linux_candidates_current_v1(s) || s->job != NULL || s->cancel_job != NULL || s->request_id != NULL) return;
    char *uuid = g_uuid_string_random(); char **parts = g_strsplit(uuid, "-", 0);
    s->request_id = g_strjoinv("", parts); g_strfreev(parts); g_free(uuid);
    /* Allocate the client nonce before the HTTP worker can submit anything. */
    s->cancelled = FALSE; s->cancel_ack = FALSE; s->receipt = FALSE; s->after_cancel = LINUX_CANDIDATES_CANCEL_V1;
    g_clear_pointer(&s->fastest_id, g_free); g_clear_pointer(&s->pending_exit, g_free); g_clear_pointer(&s->last_error, g_free);
    g_clear_pointer(&s->entry_base, g_free); g_clear_pointer(&s->entry_mode, g_free);
    g_hash_table_remove_all(s->eligible); gtk_list_store_clear(s->rows); s->operation = LINUX_CANDIDATES_MEASURE_V1;
    gtk_label_set_text(GTK_LABEL(s->status), "Measuring TCP responses through the saved entry tunnel with its Start Layer and DNS. Selection and Connect remain separate.");
    char *body = linux_candidates_payload_v1(s, FALSE, FALSE);
    s->job = rv_http_start_v16("/api/multihop/candidates", body, 180000, "Routed candidate responses"); g_free(body);
    if (s->job == NULL) { s->last_error = g_strdup("Could not start measurement request. "); linux_candidates_cancel_v1(s, LINUX_CANDIDATES_CANCEL_V1); }
    linux_candidates_buttons_v1(s);
}
static char *linux_candidates_failure_v1(RVHttpJobV16 *job) {
    char *detail = job->response != NULL ? g_utf8_make_valid(job->response, MIN(job->length, (size_t)512)) : g_strdup(curl_easy_strerror(job->result));
    char *out = g_strdup_printf("Routed candidate request failed (HTTP %ld): %s. ", job->status, detail); g_free(detail); return out;
}
static gboolean linux_candidates_poll_v1(gpointer data) {
    LinuxCandidatesV1 *s = data;
    if (!linux_candidates_current_v1(s) && !s->cancelled) {
        g_free(s->last_error); s->last_error = g_strdup("The entry changed; the old measurement was discarded. ");
        linux_candidates_cancel_v1(s, LINUX_CANDIDATES_CLOSE_V1);
    }
    if (rv_http_ready_v16(s->job)) {
        RVHttpJobV16 *job = s->job; s->job = NULL;
        if (!s->cancelled && linux_candidates_current_v1(s)) {
            char *error = NULL;
            if (atomic_load(&job->cancelled) || job->result != CURLE_OK || job->status != 200) error = linux_candidates_failure_v1(job);
            else if (s->operation == LINUX_CANDIDATES_MEASURE_V1) {
                if (linux_candidates_receipt_v1(s, job->response, &error))
                    gtk_label_set_text(GTK_LABEL(s->status), "Routed TCP response medians. Unavailable candidates keep their failure reason. Select an exit, then use Connect in the multihop dialog.");
            } else if (!linux_candidates_validated_v1(s, job->response)) error = g_strdup("The selection receipt is stale or does not match this candidate. Retest. ");
            else if (!gtk_combo_box_set_active_id(GTK_COMBO_BOX(s->parent->exit), s->pending_exit)) error = g_strdup("The measured exit is no longer in the current node list. Retest. ");
            else {
                char *selected = g_strdup_printf("Selected %s from a current routed measurement via %s. Use Connect to start the VPN.", (char *)g_hash_table_lookup(s->names, s->pending_exit), s->entry_name);
                linux_multihop_update_summary_v7(s->parent, selected); append_diag(s->parent->app, selected); g_free(selected);
                linux_candidates_cancel_v1(s, LINUX_CANDIDATES_CLOSE_V1);
            }
            if (error != NULL) { g_free(s->last_error); s->last_error = error; linux_candidates_cancel_v1(s, LINUX_CANDIDATES_CANCEL_V1); }
        }
        rv_http_free_v16(job);
    }
    if (rv_http_ready_v16(s->cancel_job)) {
        RVHttpJobV16 *job = s->cancel_job; s->cancel_job = NULL;
        JsonNode *root = job->result == CURLE_OK && job->status == 200 ? parse_json(job->response) : NULL;
        if (root != NULL && JSON_NODE_HOLDS_OBJECT(root)) {
            JsonObject *o = json_node_get_object(root);
            s->cancel_ack = linux_candidates_true_v1(o, "ok") && linux_candidates_true_v1(o, "drained") &&
                g_strcmp0(linux_candidates_string_v1(o, "request_id"), s->request_id) == 0;
        }
        if (!s->cancel_ack) gtk_label_set_text(GTK_LABEL(s->status), "Native cleanup could not be confirmed. Retry Cancel; Retest and selection remain unavailable.");
        if (root != NULL) json_node_free(root);
        rv_http_free_v16(job);
    }
    if (s->cancelled) linux_candidates_finish_cancel_v1(s);
    if (s->allow_close) { s->poll = 0; return G_SOURCE_REMOVE; }
    linux_candidates_buttons_v1(s); return G_SOURCE_CONTINUE;
}
static void linux_candidates_select_id_v1(LinuxCandidatesV1 *s, const char *id) {
    if (s->job != NULL || s->cancel_job != NULL || !linux_candidates_fresh_v1(s) || id == NULL || !g_hash_table_contains(s->eligible, id)) { linux_candidates_buttons_v1(s); return; }
    g_free(s->pending_exit); s->pending_exit = g_strdup(id); s->operation = LINUX_CANDIDATES_VALIDATE_V1;
    gtk_label_set_text(GTK_LABEL(s->status), "Checking the measurement against the current entry, network and saved settings…");
    char *body = linux_candidates_payload_v1(s, FALSE, TRUE);
    s->job = rv_http_start_v16("/api/multihop/candidates/validate", body, 15000, "Validate routed candidate selection"); g_free(body);
    if (s->job == NULL) { g_free(s->last_error); s->last_error = g_strdup("Could not validate the measured selection. "); linux_candidates_cancel_v1(s, LINUX_CANDIDATES_CANCEL_V1); }
    linux_candidates_buttons_v1(s);
}
static void linux_candidates_select_v1(GtkButton *button, gpointer data) {
    (void)button; LinuxCandidatesV1 *s = data; GtkTreeModel *model = NULL; GtkTreeIter iter; char *id = NULL;
    if (gtk_tree_selection_get_selected(gtk_tree_view_get_selection(GTK_TREE_VIEW(s->list)), &model, &iter)) {
        gtk_tree_model_get(model, &iter, LINUX_CANDIDATE_ID_V1, &id, -1); linux_candidates_select_id_v1(s, id); g_free(id);
    }
}
static void linux_candidates_fastest_v1(GtkButton *button, gpointer data) { (void)button; LinuxCandidatesV1 *s = data; linux_candidates_select_id_v1(s, s->fastest_id); }
static void linux_candidates_retest_v1(GtkButton *button, gpointer data) { (void)button; LinuxCandidatesV1 *s = data; if (s->request_id != NULL) linux_candidates_cancel_v1(s, LINUX_CANDIDATES_RETEST_V1); else linux_candidates_start_v1(s); }
static void linux_candidates_stop_v1(GtkButton *button, gpointer data) { (void)button; linux_candidates_cancel_v1(data, LINUX_CANDIDATES_CANCEL_V1); }
static void linux_candidates_close_v1(GtkButton *button, gpointer data) { (void)button; linux_candidates_cancel_v1(data, LINUX_CANDIDATES_CLOSE_V1); }
static void linux_candidates_changed_v1(GtkTreeSelection *selection, gpointer data) { (void)selection; linux_candidates_buttons_v1(data); }
static gboolean linux_candidates_delete_v1(GtkWidget *widget, GdkEvent *event, gpointer data) {
    (void)event; LinuxCandidatesV1 *s = data;
    if (s->allow_close) return FALSE;
    if (widget == s->parent->app->window) s->close_main = TRUE;
    else if (widget == s->parent->dialog) s->close_parent = TRUE;
    linux_candidates_cancel_v1(s, LINUX_CANDIDATES_CLOSE_V1); return TRUE;
}
static void linux_candidates_response_v1(GtkDialog *dialog, gint response, gpointer data) {
    (void)response; LinuxCandidatesV1 *s = data;
    if (!s->allow_close) { g_signal_stop_emission_by_name(dialog, "response"); linux_candidates_cancel_v1(s, LINUX_CANDIDATES_CLOSE_V1); }
}
static gboolean linux_candidates_close_main_v1(gpointer data) {
    GtkWidget *window = data;
    gtk_window_close(GTK_WINDOW(window)); g_object_unref(window); return G_SOURCE_REMOVE;
}
static void on_linux_candidates_v1(GtkButton *button, gpointer data) {
    (void)button; LinuxMultihopDialogV7 *parent = data;
    if (!routervpn_require_mutation_idle(parent->app, "measuring exits through the selected entry")) return;
    const char *entry_id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(parent->entry));
    LinuxMultihopNodeV7 *entry = linux_multihop_find_v7(parent, entry_id);
    if (entry == NULL || parent->nodes->len < 2) { linux_multihop_update_summary_v7(parent, "Choose a Router entry and add a different Router exit before measuring candidates."); return; }
    if (parent->nodes->len > 65) { linux_multihop_update_summary_v7(parent, "A routed comparison supports at most 64 candidate exits. Reduce the Router node list before measuring."); return; }
    LinuxCandidatesV1 s = {0}; s.parent = parent; s.entry_id = g_strdup(entry_id); s.entry_name = g_strdup(entry->name);
    s.ids = g_ptr_array_new_with_free_func(g_free); s.names = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free); s.eligible = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    for (guint i = 0; i < parent->nodes->len; i++) {
        LinuxMultihopNodeV7 *node = g_ptr_array_index(parent->nodes, i);
        if (strcmp(node->id, s.entry_id) != 0 && !g_hash_table_contains(s.names, node->id)) { g_ptr_array_add(s.ids, g_strdup(node->id)); g_hash_table_insert(s.names, g_strdup(node->id), g_strdup(node->name)); }
    }
    s.dialog = gtk_dialog_new_with_buttons("Exits via selected entry", GTK_WINDOW(parent->dialog), GTK_DIALOG_MODAL, NULL, NULL);
    gtk_window_set_default_size(GTK_WINDOW(s.dialog), 820, 480);
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(s.dialog)), *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(box), 16); gtk_box_pack_start(GTK_BOX(content), box, TRUE, TRUE, 0);
    char *title = g_strdup_printf("Candidate exits via %s · saved entry tunnel", s.entry_name); s.heading = gtk_label_new(title); g_free(title);
    gtk_label_set_xalign(GTK_LABEL(s.heading), 0); gtk_label_set_line_wrap(GTK_LABEL(s.heading), TRUE); gtk_box_pack_start(GTK_BOX(box), s.heading, FALSE, FALSE, 0);
    s.rows = gtk_list_store_new(LINUX_CANDIDATE_COLUMNS_V1, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_BOOLEAN, G_TYPE_DOUBLE);
    s.list = gtk_tree_view_new_with_model(GTK_TREE_MODEL(s.rows));
    GtkCellRenderer *name_renderer = gtk_cell_renderer_text_new(), *result_renderer = gtk_cell_renderer_text_new();
    g_object_set(result_renderer, "wrap-mode", PANGO_WRAP_WORD_CHAR, "wrap-width", 540, NULL);
    gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(s.list), -1, "Exit", name_renderer, "text", LINUX_CANDIDATE_NAME_V1, NULL);
    gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(s.list), -1, "Routed measurement", result_renderer, "text", LINUX_CANDIDATE_TEXT_V1, NULL);
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL); gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(scroll), s.list); gtk_box_pack_start(GTK_BOX(box), scroll, TRUE, TRUE, 0);
    s.status = gtk_label_new(""); gtk_label_set_xalign(GTK_LABEL(s.status), 0); gtk_label_set_line_wrap(GTK_LABEL(s.status), TRUE); gtk_box_pack_start(GTK_BOX(box), s.status, FALSE, FALSE, 0);
    GtkWidget *actions = gtk_button_box_new(GTK_ORIENTATION_HORIZONTAL); gtk_button_box_set_layout(GTK_BUTTON_BOX(actions), GTK_BUTTONBOX_END);
    s.retest = make_button("Retest", G_CALLBACK(linux_candidates_retest_v1), &s); s.cancel = make_button("Cancel measurement", G_CALLBACK(linux_candidates_stop_v1), &s);
    s.select = make_button("Select exit", G_CALLBACK(linux_candidates_select_v1), &s); s.fastest = make_button("Select fastest", G_CALLBACK(linux_candidates_fastest_v1), &s);
    GtkWidget *close = make_button("Close", G_CALLBACK(linux_candidates_close_v1), &s);
    GtkWidget *buttons[] = {s.retest, s.cancel, s.select, s.fastest, close};
    for (guint i = 0; i < G_N_ELEMENTS(buttons); i++) gtk_container_add(GTK_CONTAINER(actions), buttons[i]);
    gtk_box_pack_start(GTK_BOX(box), actions, FALSE, FALSE, 0);
    g_signal_connect(gtk_tree_view_get_selection(GTK_TREE_VIEW(s.list)), "changed", G_CALLBACK(linux_candidates_changed_v1), &s);
    g_signal_connect(s.dialog, "delete-event", G_CALLBACK(linux_candidates_delete_v1), &s);
    g_signal_connect(s.dialog, "response", G_CALLBACK(linux_candidates_response_v1), &s);
    g_signal_connect(parent->dialog, "delete-event", G_CALLBACK(linux_candidates_delete_v1), &s);
    g_signal_connect(parent->app->window, "delete-event", G_CALLBACK(linux_candidates_delete_v1), &s);
    g_object_set_data(G_OBJECT(parent->dialog), "linux-via-entry-candidates-v1", &s);
    LinuxAsyncActionsV16 *owner = linux_async_ensure_v16(parent->app); owner->auxiliary_jobs++;
    if (owner->changed != NULL) owner->changed(parent->app);
    gtk_widget_show_all(s.dialog); s.poll = g_timeout_add(50, linux_candidates_poll_v1, &s); linux_candidates_start_v1(&s);
    gtk_dialog_run(GTK_DIALOG(s.dialog));
    if (s.poll != 0) g_source_remove(s.poll);
    g_signal_handlers_disconnect_by_data(parent->dialog, &s); g_signal_handlers_disconnect_by_data(parent->app->window, &s);
    g_object_set_data(G_OBJECT(parent->dialog), "linux-via-entry-candidates-v1", NULL);
    rv_http_free_v16(s.job); rv_http_free_v16(s.cancel_job);
    gtk_widget_destroy(s.dialog); g_object_unref(s.rows);
    g_ptr_array_unref(s.ids); g_hash_table_unref(s.names); g_hash_table_unref(s.eligible);
    g_free(s.entry_id); g_free(s.entry_name); g_free(s.entry_base); g_free(s.entry_mode); g_free(s.request_id); g_free(s.fastest_id); g_free(s.pending_exit); g_free(s.last_error);
    owner->auxiliary_jobs--; if (owner->changed != NULL) owner->changed(parent->app);
    if (s.close_main) {
        /* Release the parent's modal grab before asking the main window to
         * close. A close event sent while that grab is held is ignored by GTK. */
        gtk_dialog_response(GTK_DIALOG(parent->dialog), GTK_RESPONSE_CLOSE);
        g_idle_add(linux_candidates_close_main_v1, g_object_ref(parent->app->window));
    }
    else if (s.close_parent) gtk_dialog_response(GTK_DIALOG(parent->dialog), GTK_RESPONSE_CLOSE);
}

/* Automatic measurement follows an explicit entry-picker commit only. A status
 * refresh, initial default, programmatic selection or an unchanged popup never
 * opens a native lane. Keyboard navigation uses the same captured transition. */
static void linux_candidates_capture_entry_v1(GtkComboBox *combo) {
    g_object_set_data_full(G_OBJECT(combo), "linux-candidate-entry-before-v1", g_strdup(gtk_combo_box_get_active_id(combo)), g_free);
}
static void linux_candidates_commit_entry_v1(GtkComboBox *combo, LinuxMultihopDialogV7 *parent) {
    const char *before = g_object_get_data(G_OBJECT(combo), "linux-candidate-entry-before-v1");
    const char *after = gtk_combo_box_get_active_id(combo);
    gboolean changed = before != NULL && after != NULL && g_strcmp0(before, after) != 0;
    g_object_set_data_full(G_OBJECT(combo), "linux-candidate-entry-before-v1", NULL, g_free);
    if (changed) on_linux_candidates_v1(NULL, parent);
}
static void linux_candidates_popup_v1(GObject *object, GParamSpec *property, gpointer data) {
    (void)property; gboolean shown = FALSE; g_object_get(object, "popup-shown", &shown, NULL);
    if (shown) linux_candidates_capture_entry_v1(GTK_COMBO_BOX(object));
    else linux_candidates_commit_entry_v1(GTK_COMBO_BOX(object), data);
}
static gboolean linux_candidates_entry_key_v1(GtkWidget *widget, GdkEventKey *event, gpointer data) {
    gboolean shown = FALSE; g_object_get(widget, "popup-shown", &shown, NULL);
    if (shown) return FALSE;
    switch (event->keyval) {
        case GDK_KEY_Up: case GDK_KEY_Down: case GDK_KEY_Home: case GDK_KEY_End: case GDK_KEY_Page_Up: case GDK_KEY_Page_Down:
            if (event->type == GDK_KEY_PRESS) linux_candidates_capture_entry_v1(GTK_COMBO_BOX(widget));
            else if (event->type == GDK_KEY_RELEASE) linux_candidates_commit_entry_v1(GTK_COMBO_BOX(widget), data);
            break;
        default: break;
    }
    return FALSE;
}
static void linux_candidates_bind_entry_v1(LinuxMultihopDialogV7 *parent) {
    g_signal_connect(parent->entry, "notify::popup-shown", G_CALLBACK(linux_candidates_popup_v1), parent);
    g_signal_connect(parent->entry, "key-press-event", G_CALLBACK(linux_candidates_entry_key_v1), parent);
    g_signal_connect(parent->entry, "key-release-event", G_CALLBACK(linux_candidates_entry_key_v1), parent);
}
