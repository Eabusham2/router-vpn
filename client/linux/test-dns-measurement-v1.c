/* The real GTK panel and callbacks run against controllable HTTP completions.
 * --live builds retain the actual pthread/libcurl loopback transport. */
#include <gtk/gtk.h>
#include <json-glib/json-glib.h>
#include <string.h>
#include "routervpn-http-job-v16.h"
typedef struct { GtkWidget *window; const char *selected; } App;
static gboolean idle = FALSE, other_busy = FALSE;
static guint legacy_calls = 0, saved_refreshes = 0;
static const char *active_router_id(App *app) { return app->selected; }
static gboolean linux_async_busy_v16(App *app) { (void)app; return other_busy; }
static gboolean routervpn_require_mutation_idle(App *app, const char *reason) { (void)app; (void)reason; return idle; }
static void append_diag(App *app, const char *text) { (void)app; (void)text; }
static void refresh_dns_page_v5(App *app) { (void)app; saved_refreshes++; }
static void post_and_log(App *app, const char *path, const char *body, long timeout, const char *label) {
    (void)app; (void)body; (void)timeout; (void)label;
    if (strcmp(path, "/api/dns/retest") != 0) g_error("Foreign legacy path");
    legacy_calls++;
}
static JsonNode *parse_json(const char *text) {
    JsonParser *parser = json_parser_new(); JsonNode *node = NULL;
    if (text != NULL && json_parser_load_from_data(parser, text, -1, NULL)) node = json_node_copy(json_parser_get_root(parser));
    g_object_unref(parser); return node;
}
static int checks = 0;
static void check(gboolean ok, const char *reason) { if (!ok) g_error("DNS panel check failed: %s", reason); checks++; }

#ifndef ROUTERVPN_DNS_LIVE
typedef struct { RVHttpJobV16 *job; char *path, *body; gboolean get, cancelled, freed; } Record;
static GPtrArray *records;
static gboolean parent_join = FALSE;
static Record *record(RVHttpJobV16 *job) {
    for (guint i = 0; i < records->len; i++) { Record *r = g_ptr_array_index(records, i); if (r->job == job) return r; }
    g_error("Unowned job"); return NULL;
}
static RVHttpJobV16 *fake_start(const char *path, const char *body, long timeout, const char *label, int get) {
    (void)label; check(timeout > 0 && timeout <= 6000, "bounded loopback timeout");
    RVHttpJobV16 *job = g_new0(RVHttpJobV16, 1); atomic_init(&job->ready, 0); atomic_init(&job->cancelled, 0); job->result = CURLE_OK;
    Record *r = g_new0(Record, 1); r->job = job; r->path = g_strdup(path); r->body = g_strdup(body); r->get = get;
    g_ptr_array_add(records, r); return job;
}
static void fake_cancel(RVHttpJobV16 *job) { if (job != NULL) { record(job)->cancelled = TRUE; atomic_store(&job->cancelled, 1); } }
static void fake_free(RVHttpJobV16 *job) {
    if (job == NULL) return;
    check(atomic_load(&job->ready) || (parent_join && atomic_load(&job->cancelled)), "join only a ready or explicitly cancelled worker");
    Record *r = record(job); r->job = NULL; r->freed = TRUE; free(job->response); g_free(job);
}
#define rv_http_start_method_v17 fake_start
#define rv_http_cancel_v16 fake_cancel
#define rv_http_free_v16 fake_free
#endif
#ifndef ROUTERVPN_DNS_SOURCE
#define ROUTERVPN_DNS_SOURCE "routervpn-dns-measurement-v1.inc"
#endif
#include ROUTERVPN_DNS_SOURCE

static const char *session_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char *profile_token = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static LinuxDNSV1 *open_panel(App *app) {
    linux_dns_retest_v1(app); LinuxDNSV1 *s = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-measurement-v1");
    check(s != NULL && s->dialog != NULL, "actual panel created");
    check(!gtk_window_get_modal(GTK_WINDOW(s->dialog)) && gtk_widget_is_sensitive(app->window), "main Disconnect remains reachable");
    return s;
}
#ifndef ROUTERVPN_DNS_LIVE
static void freeze(LinuxDNSV1 *s) { if (s->timer != 0) { g_source_remove(s->timer); s->timer = 0; } }
static void reply(RVHttpJobV16 *job, long code, JsonNode *node) {
    check(job != NULL && !record(job)->freed, "reply has an owned worker"); job->status = code;
    JsonGenerator *g = json_generator_new(); json_generator_set_root(g, node); job->response = json_generator_to_data(g, &job->length);
    g_object_unref(g); json_node_free(node); atomic_store(&job->ready, 1);
}
static void fail_reply(RVHttpJobV16 *job, long code) { reply(job, code, parse_json("{\"error\":\"fixture\"}")); }
static JsonNode *status(LinuxDNSV1 *s, const char *stage, gboolean complete, gboolean drained, gboolean rows) {
    JsonObject *root = json_object_new(), *state = json_object_new();
    json_object_set_string_member(root, "profile_id", "exit-a"); json_object_set_string_member(root, "profile_token", profile_token);
    json_object_set_string_member(root, "session_id", session_id); json_object_set_string_member(root, "request_id", s->request != NULL ? s->request : "");
    json_object_set_int_member(root, "expires_in_ms", rows ? 120000 : 0);
    json_object_set_int_member(state, "schema", 1); json_object_set_string_member(state, "node_id", "exit-a");
    json_object_set_string_member(state, "session_id", session_id); json_object_set_string_member(state, "request_id", s->request != NULL ? s->request : "");
    json_object_set_string_member(state, "public_transport", s->public_transport != NULL ? s->public_transport : "");
    json_object_set_string_member(state, "stage", stage); json_object_set_boolean_member(state, "complete", complete); json_object_set_boolean_member(state, "drained", drained);
    JsonArray *results = json_array_new();
    if (rows) {
        const char *ids[] = {"selected", "cf4a", "cf4b", "g4a"};
        const char *addresses[] = {"192.168.50.133", "1.1.1.1", "1.0.0.1", "8.8.8.8"};
        for (int i = 0; i < 4; i++) {
            JsonObject *row = json_object_new(); const char *transport = i == 0 ? "https" : s->public_transport;
            json_object_set_string_member(row, "id", ids[i]); json_object_set_string_member(row, "name", i == 0 ? "Home AdGuard" : ids[i]);
            json_object_set_string_member(row, "kind", i == 0 ? "selected" : "public"); json_object_set_string_member(row, "address", addresses[i]);
            json_object_set_string_member(row, "transport", transport);
            json_object_set_int_member(row, "port", strcmp(transport, "tcp") == 0 ? 53 : strcmp(transport, "tls") == 0 ? 853 : 443);
            if (strcmp(transport, "tcp") != 0) json_object_set_string_member(row, "server_name", i == 0 ? "home.example" : i == 3 ? "dns.google" : "cloudflare-dns.com");
            if (strcmp(transport, "https") == 0) json_object_set_string_member(row, "path", i == 0 ? "/home-dns" : "/dns-query");
            json_object_set_string_member(row, "route", i == 0 ? "entry" : "exit");
            json_object_set_string_member(row, "route_label", i == 0 ? "Authenticated Router entry" : "Captured external exit");
            json_object_set_int_member(row, "samples", i == 3 ? 0 : 3); json_object_set_int_member(row, "failed", i == 3 ? 3 : 0);
            json_object_set_boolean_member(row, "ready", i != 3);
            if (i != 3) json_object_set_double_member(row, "median_ms", i == 0 ? 0.5 : i == 1 ? 9.0 : 2.0);
            else json_object_set_string_member(row, "failure", "DNS query timed out");
            json_array_add_object_element(results, row);
        }
    }
    json_object_set_array_member(state, "results", results); json_object_set_object_member(root, "status", state);
    JsonNode *node = json_node_new(JSON_NODE_OBJECT); json_node_take_object(node, root); return node;
}
static LinuxDNSV1 *ready_panel(App *app) {
    app->selected = "exit-a"; idle = FALSE; LinuxDNSV1 *s = open_panel(app); freeze(s);
    check(strcmp(record(s->jobs[DNS_POLICY_V1])->path, "/api/dns/policy") == 0, "read policy after capturing displayed node");
    reply(s->jobs[DNS_POLICY_V1], 200, parse_json("{\"profile_id\":\"exit-a\",\"node_kind\":\"external\"}"));
    (void)linux_dns_tick_v1(s); check(s->jobs[DNS_INFO_V1] != NULL, "external policy opens native capture");
    reply(s->jobs[DNS_INFO_V1], 200, status(s, "idle", TRUE, TRUE, FALSE)); (void)linux_dns_tick_v1(s);
    check(!s->invalid && strcmp(s->token, profile_token) == 0 && strcmp(s->session, session_id) == 0, "exact native capture retained"); return s;
}
static void dispose(LinuxDNSV1 *s) {
    if (s->dialog != NULL) gtk_widget_destroy(s->dialog);
    freeze(s);
    for (guint i = 0; i < records->len; i++) {
        Record *r = g_ptr_array_index(records, i); if (r->job != NULL) { check(r->cancelled, "detached HTTP work cancelled"); atomic_store(&r->job->ready, 1); }
    }
    check(linux_dns_tick_v1(s) == G_SOURCE_REMOVE, "detached owner releases after local workers drain");
}
static void start(LinuxDNSV1 *s, const char *transport) {
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(s->transport), transport); gtk_button_clicked(GTK_BUTTON(s->retest));
    check(s->owned && s->jobs[DNS_START_V1] != NULL && !s->complete && !s->drained, "Retest is asynchronous and owns pending Start");
    JsonNode *body = parse_json(record(s->jobs[DNS_START_V1])->body); JsonObject *b = json_node_get_object(body);
    check(json_object_get_size(b) == 5 && g_strcmp0(linux_dns_string_v1(b, "profile_id"), s->profile) == 0 &&
        g_strcmp0(linux_dns_string_v1(b, "profile_token"), profile_token) == 0 && g_strcmp0(linux_dns_string_v1(b, "session_id"), session_id) == 0 &&
        g_strcmp0(linux_dns_string_v1(b, "request_id"), s->request) == 0 && g_strcmp0(linux_dns_string_v1(b, "public_transport"), transport) == 0 &&
        linux_dns_hex_v1(s->request, 32), "Start serializes only exact captured identity and chosen transport"); json_node_free(body);
}
static void complete(LinuxDNSV1 *s) {
    reply(s->jobs[DNS_START_V1], 202, status(s, "preparing", FALSE, FALSE, FALSE)); (void)linux_dns_tick_v1(s);
    reply(s->jobs[DNS_POLL_V1], 200, status(s, "starting", FALSE, FALSE, FALSE)); (void)linux_dns_tick_v1(s);
    check(!s->invalid && !s->complete, "native starting status remains pending");
    s->next_poll = 0; (void)linux_dns_tick_v1(s);
    reply(s->jobs[DNS_POLL_V1], 200, status(s, "verifying", FALSE, FALSE, FALSE)); (void)linux_dns_tick_v1(s);
    check(!s->invalid && !s->complete, "final native verification remains pending");
    s->next_poll = 0; (void)linux_dns_tick_v1(s);
    reply(s->jobs[DNS_POLL_V1], 200, status(s, "complete", TRUE, FALSE, TRUE)); (void)linux_dns_tick_v1(s);
    check(!linux_dns_eligible_v1(s) && !linux_dns_choose_v1(s, "fastest"), "Complete without Drained cannot win or stage a draft");
    s->next_poll = 0; (void)linux_dns_tick_v1(s); reply(s->jobs[DNS_POLL_V1], 200, status(s, "complete", TRUE, TRUE, TRUE)); (void)linux_dns_tick_v1(s);
    check(linux_dns_eligible_v1(s), "matching final drained receipt enables measured selection");
}
static JsonNode *draft(LinuxDNSV1 *s) {
    JsonObject *root = json_object_new(), *d = json_object_new(); JsonObject *row = linux_dns_result_v1(s, "cf4b");
    json_object_set_string_member(root, "session_id", s->session); json_object_set_string_member(root, "request_id", s->request);
    json_object_set_int_member(root, "expires_in_ms", 115000);
    json_object_set_string_member(d, "profile_id", s->profile); json_object_set_string_member(d, "profile_token", s->token);
    json_object_set_string_member(d, "measurement_id", s->request); json_object_set_string_member(d, "result_id", "cf4b");
    json_object_set_string_member(d, "mode", strcmp(s->public_transport, "tls") == 0 ? "dot" : strcmp(s->public_transport, "https") == 0 ? "doh" : "custom");
    json_object_set_string_member(d, "protocol", s->public_transport); json_object_set_string_member(d, "host", "1.0.0.1");
    json_object_set_int_member(d, "port", json_object_get_int_member(row, "port"));
    const char *fields[] = {"server_name", "path"};
    for (guint i = 0; i < G_N_ELEMENTS(fields); i++) if (json_object_has_member(row, fields[i])) json_object_set_string_member(d, fields[i], linux_dns_string_v1(row, fields[i]));
    json_object_set_object_member(root, "draft", d); JsonNode *n = json_node_new(JSON_NODE_OBJECT); json_node_take_object(n, root); return n;
}
static void state_tests(App *app) {
    records = g_ptr_array_new();
    const char *transports[] = {"tcp", "tls", "https"};
    for (guint i = 0; i < G_N_ELEMENTS(transports); i++) {
        LinuxDNSV1 *s = ready_panel(app); start(s, transports[i]); complete(s);
        check(gtk_tree_model_iter_n_children(GTK_TREE_MODEL(s->rows), NULL) == 3 && strstr(s->selected_text, "Authenticated Router entry") != NULL,
            "selected DNS stays separate; all public success and failure rows remain visible");
        GtkTreeIter iter; check(gtk_tree_model_get_iter_first(GTK_TREE_MODEL(s->rows), &iter), "public table has rows");
        char *first = NULL; gtk_tree_model_get(GTK_TREE_MODEL(s->rows), &iter, DNS_ROW_ID_V1, &first, -1);
        check(strcmp(first, "cf4b") == 0, "public rows sort by real query median"); g_free(first);
        check(!linux_dns_choose_v1(s, "selected") && !linux_dns_choose_v1(s, "g4a"), "selected private route and failed public DNS cannot win Fastest");
        check(linux_dns_choose_v1(s, "fastest"), "valid public result can be selected");
        reply(s->jobs[DNS_SELECT_V1], 200, draft(s)); (void)linux_dns_tick_v1(s);
        check(s->draft != NULL && !s->invalid, "server-issued typed draft retained");
        guint before = records->len; check(!linux_dns_save_v1(s) && records->len == before, "connected save emits no mutation");
        app->selected = "replacement"; idle = TRUE; check(!linux_dns_save_v1(s), "replacement displayed node cannot receive draft"); app->selected = "exit-a";
        check(linux_dns_save_v1(s), "explicit disconnected Save emits typed draft");
        JsonNode *payload = parse_json(record(s->jobs[DNS_SAVE_V1])->body);
        check(json_node_equal(payload, s->draft), "Save preserves exact measured fields and proof references"); json_node_free(payload);
        JsonNode *receipt = json_node_copy(s->draft); reply(s->jobs[DNS_SAVE_V1], 200, receipt); (void)linux_dns_tick_v1(s);
        check(s->draft == NULL && s->invalid && strstr(s->message, "saved for the next") != NULL, "matching saved readback acknowledged without connecting"); dispose(s);
    }
    check(saved_refreshes == 3, "only confirmed saves refresh persistent policy");

    LinuxDNSV1 *s = ready_panel(app); start(s, "tls"); RVHttpJobV16 *pending = s->jobs[DNS_START_V1];
    check(!linux_dns_close_v1(s) && s->closing && s->jobs[DNS_CANCEL_V1] != NULL, "Close while Start pending creates captured cancellation");
    fail_reply(s->jobs[DNS_CANCEL_V1], 404); (void)linux_dns_tick_v1(s);
    check(!s->complete && !s->drained && s->dialog != NULL, "404 cannot infer that native work never started");
    if (s->jobs[DNS_CANCEL_V1] == NULL) { s->next_cancel = 0; (void)linux_dns_tick_v1(s); }
    reply(s->jobs[DNS_CANCEL_V1], 200, status(s, "cancelled", TRUE, TRUE, FALSE)); (void)linux_dns_tick_v1(s);
    check(s->complete && s->drained && !linux_dns_settled_v1(s) && s->dialog != NULL, "no-work tombstone still retains pending Start worker");
    fail_reply(pending, 409); (void)linux_dns_tick_v1(s);
    check(s->detaching && s->dialog == NULL, "Close occurs after tombstone and local Start drain"); dispose(s);

    s = ready_panel(app); start(s, "tls"); reply(s->jobs[DNS_START_V1], 202, status(s, "measuring", FALSE, FALSE, FALSE)); (void)linux_dns_tick_v1(s);
    gtk_button_clicked(GTK_BUTTON(s->cancel)); reply(s->jobs[DNS_CANCEL_V1], 202, status(s, "invalidated", TRUE, FALSE, FALSE)); (void)linux_dns_tick_v1(s);
    check(!linux_dns_settled_v1(s), "cancel acknowledgement without drain is not completion");
    reply(s->jobs[DNS_POLL_V1], 200, status(s, "cancelled", TRUE, TRUE, FALSE)); (void)linux_dns_tick_v1(s);
    check(s->complete && s->drained && !s->successful && !linux_dns_choose_v1(s, "fastest"), "cancelled result never becomes a draft"); dispose(s);

    const char *identities[] = {"profile_id", "profile_token", "session_id", "request_id"};
    for (guint i = 0; i < G_N_ELEMENTS(identities); i++) {
        s = ready_panel(app); start(s, "tls"); reply(s->jobs[DNS_START_V1], 202, status(s, "measuring", FALSE, FALSE, FALSE)); (void)linux_dns_tick_v1(s);
        JsonNode *bad = status(s, "complete", TRUE, TRUE, TRUE); json_object_set_string_member(json_node_get_object(bad), identities[i], "replacement");
        if (i == 0) json_object_set_string_member(linux_dns_object_v1(json_node_get_object(bad), "status"), "node_id", "replacement");
        reply(s->jobs[DNS_POLL_V1], 200, bad); (void)linux_dns_tick_v1(s);
        check(s->invalid && !s->drained && s->jobs[DNS_CANCEL_V1] != NULL, "foreign identity cannot attest results or drain");
        JsonNode *body = parse_json(record(s->jobs[DNS_CANCEL_V1])->body); JsonObject *b = json_node_get_object(body);
        check(g_strcmp0(linux_dns_string_v1(b, "session_id"), session_id) == 0 && g_strcmp0(linux_dns_string_v1(b, "profile_id"), "exit-a") == 0,
            "rejected response cannot redirect cancellation"); json_node_free(body); dispose(s);
    }
    s = ready_panel(app); start(s, "tls"); reply(s->jobs[DNS_START_V1], 202, status(s, "preparing", FALSE, FALSE, FALSE)); (void)linux_dns_tick_v1(s);
    JsonNode *bad = status(s, "complete", TRUE, TRUE, TRUE); json_object_set_string_member(linux_dns_object_v1(json_node_get_object(bad), "status"), "drained", "true");
    reply(s->jobs[DNS_POLL_V1], 200, bad); (void)linux_dns_tick_v1(s); check(s->invalid && !s->drained, "string true is not a drain receipt"); dispose(s);

    s = ready_panel(app); start(s, "tls"); complete(s); gint64 deadline = s->expires_at;
    check(linux_dns_choose_v1(s, "fastest"), "draft expiry fixture selected"); JsonNode *longer = draft(s);
    json_object_set_int_member(json_node_get_object(longer), "expires_in_ms", 120000);
    s->job_started[DNS_SELECT_V1] += 30 * G_TIME_SPAN_SECOND;
    reply(s->jobs[DNS_SELECT_V1], 200, longer); (void)linux_dns_tick_v1(s);
    check(s->expires_at <= deadline && s->draft != NULL, "new responses cannot extend original measurement deadline");
    s->expires_at = g_get_monotonic_time() - 1; idle = TRUE; guint before = records->len;
    check(!linux_dns_save_v1(s) && !linux_dns_choose_v1(s, "fastest") && records->len == before, "expired draft cannot be selected or saved");
    (void)linux_dns_tick_v1(s); check(s->draft == NULL, "expired local draft is removed"); dispose(s);

    s = ready_panel(app); start(s, "tls"); complete(s);
    JsonObject *partial = linux_dns_result_v1(s, "cf4a"); json_object_set_int_member(partial, "samples", 2);
    check(!linux_dns_choose_v1(s, "cf4a"), "partial sample row cannot become a typed resolver");
    check(linux_dns_choose_v1(s, "fastest"), "malformed draft fixture selected"); bad = draft(s);
    json_object_set_string_member(linux_dns_object_v1(json_node_get_object(bad), "draft"), "host", "8.8.8.8");
    reply(s->jobs[DNS_SELECT_V1], 200, bad); (void)linux_dns_tick_v1(s);
    check(s->invalid && s->draft == NULL, "typed draft must match measured host and transport"); dispose(s);

    s = ready_panel(app); start(s, "tls"); complete(s); char *old_id = g_strdup(s->request);
    start(s, "https"); check(strcmp(s->request, old_id) != 0, "new Retest creates a fresh request nonce"); g_free(old_id); dispose(s);
    s = ready_panel(app); start(s, "tls"); check(linux_dns_parent_delete_v1(app->window, NULL, app) && s->parent_closing,
        "whole app close first retains DNS cancel/drain even with an attached controller"); dispose(s);

    app->selected = "exit-a"; s = open_panel(app); freeze(s); app->selected = "replacement";
    reply(s->jobs[DNS_POLICY_V1], 200, parse_json("{\"profile_id\":\"exit-a\",\"node_kind\":\"external\"}")); (void)linux_dns_tick_v1(s);
    check(s->invalid && s->jobs[DNS_INFO_V1] == NULL, "late policy read cannot bind a replacement displayed node"); dispose(s);
    app->selected = "exit-a"; s = open_panel(app); freeze(s);
    reply(s->jobs[DNS_POLICY_V1], 200, parse_json("{\"profile_id\":\"exit-a\",\"node_kind\":\"router-vpn\"}")); (void)linux_dns_tick_v1(s);
    check(legacy_calls == 1 && s->detaching, "Router Retest stays on existing asynchronous route"); dispose(s);

    s = ready_panel(app); start(s, "tls"); RVHttpJobV16 *worker = s->jobs[DNS_START_V1]; Record *held = record(worker);
    parent_join = TRUE; gtk_widget_destroy(app->window); app->window = NULL;
    check(held->cancelled && held->freed, "parent destruction joins loopback worker before global CURL cleanup");
    for (guint i = 0; i < records->len; i++) {
        Record *r = g_ptr_array_index(records, i); check(r->freed && r->job == NULL, "every local HTTP owner freed exactly once");
        g_free(r->path); g_free(r->body); g_free(r);
    }
    g_ptr_array_free(records, TRUE);
}
#else
static void pump(void) { while (g_main_context_iteration(NULL, FALSE)) {} g_usleep(5000); }
static void live_test(App *app, const char *scenario) {
    LinuxDNSV1 *s = open_panel(app); gint64 deadline = g_get_monotonic_time() + 12 * G_TIME_SPAN_SECOND;
    while (s->session == NULL && !s->invalid && g_get_monotonic_time() < deadline) pump();
    check(s->session != NULL && !s->invalid, "real loopback captured native session");
    gtk_button_clicked(GTK_BUTTON(s->retest)); check(s->owned && s->jobs[DNS_START_V1] != NULL, "real Start leaves GTK responsive");
    if (strcmp(scenario, "early") != 0) {
        while (s->jobs[DNS_START_V1] != NULL && !s->invalid && g_get_monotonic_time() < deadline) pump();
    }
    gtk_button_clicked(GTK_BUTTON(s->cancel)); guint pulses = 0;
    while ((!s->complete || !s->drained || !linux_dns_settled_v1(s)) && g_get_monotonic_time() < deadline) { pump(); pulses++; }
    check(pulses > 0 && gtk_widget_is_sensitive(app->window), "main UI remains responsive during real cancellation");
    check(s->complete && s->drained && !s->successful, "real Cancel waits for exact native drain or no-work tombstone");
    check(linux_dns_close_v1(s), "drained real panel can close");
    for (int i = 0; i < 20; i++) pump();
}
#endif
int main(int argc, char **argv) {
    gtk_init(&argc, &argv); curl_global_init(CURL_GLOBAL_DEFAULT);
    App app = {gtk_window_new(GTK_WINDOW_TOPLEVEL), "exit-a"}; gtk_widget_show(app.window);
#ifdef ROUTERVPN_DNS_LIVE
    (void)session_id; (void)profile_token; live_test(&app, argc > 1 ? argv[1] : "accepted");
#else
    state_tests(&app);
#endif
    if (app.window != NULL) gtk_widget_destroy(app.window);
    while (g_main_context_iteration(NULL, FALSE)) {}
    curl_global_cleanup(); g_print("PASS: %d actual GTK DNS capture, results and lifecycle checks\n", checks); return 0;
}
