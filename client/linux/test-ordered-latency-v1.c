/* Actual GTK callbacks; controlled completions isolate ownership faults. LIVE
 * builds retain the original RVHttpJobV16 pthread/libcurl loopback transport. */
#include <gtk/gtk.h>
#include <json-glib/json-glib.h>
#include <string.h>
#include "routervpn-http-job-v16.h"
typedef struct { GtkWidget *window; const char *selected; } App;
static const char *active_router_id(App *app) { return app->selected; }
static void append_diag(App *app, const char *text) { (void)app; (void)text; }
static JsonNode *parse_json(const char *text) {
    JsonParser *p = json_parser_new(); JsonNode *n = NULL;
    if (text != NULL && json_parser_load_from_data(p, text, -1, NULL)) n = json_node_copy(json_parser_get_root(p));
    g_object_unref(p); return n;
}
static int checks;
static void check(gboolean ok, const char *why) { if (!ok) g_error("Ordered latency check failed: %s", why); checks++; }
#ifndef ROUTERVPN_ORDERED_LIVE
typedef struct { RVHttpJobV16 *job; char *path, *body; gboolean freed, cancelled; } Record;
static GPtrArray *records;
static gboolean checked_parent_shutdown;
static Record *record(RVHttpJobV16 *job) {
    for (guint i = 0; i < records->len; i++) { Record *r = g_ptr_array_index(records, i); if (r->job == job) return r; }
    g_error("Unknown original worker"); return NULL;
}
static RVHttpJobV16 *fake_start(const char *path, const char *body, long timeout, const char *label, int get) {
    (void)label; (void)get; check(timeout == 6000, "bounded original HTTP worker");
    RVHttpJobV16 *j = g_new0(RVHttpJobV16, 1); atomic_init(&j->ready, 0); atomic_init(&j->cancelled, 0); j->result = CURLE_OK;
    Record *r = g_new0(Record, 1); r->job = j; r->path = g_strdup(path); r->body = g_strdup(body); g_ptr_array_add(records, r); return j;
}
static void fake_cancel(RVHttpJobV16 *j) { if (j != NULL) { record(j)->cancelled = TRUE; atomic_store(&j->cancelled, 1); } }
static void fake_free(RVHttpJobV16 *j) {
    if (j == NULL) return;
    check(atomic_load(&j->ready) || (checked_parent_shutdown && atomic_load(&j->cancelled)), "HTTP completion joined before free");
    Record *r = record(j); r->job = NULL; r->freed = TRUE; free(j->response); g_free(j);
}
#define rv_http_start_method_v17 fake_start
#define rv_http_cancel_v16 fake_cancel
#define rv_http_free_v16 fake_free
#endif
#ifndef ROUTERVPN_ORDERED_SOURCE
#define ROUTERVPN_ORDERED_SOURCE "routervpn-ordered-latency-v1.inc"
#endif
#include ROUTERVPN_ORDERED_SOURCE
static void pump(void) { while (gtk_events_pending()) gtk_main_iteration(); }
static LinuxOrderedLatencyV1 *panel(App *app) {
    linux_ordered_latency_open_v1(app); LinuxOrderedLatencyV1 *s = g_object_get_data(G_OBJECT(app->window), "router-vpn-ordered-latency-v1");
    check(s != NULL && s->dialog != NULL, "shipping panel created");
    check(!gtk_window_get_modal(GTK_WINDOW(s->dialog)) && gtk_widget_is_sensitive(app->window), "modeless panel keeps main actions reachable"); return s;
}
#ifndef ROUTERVPN_ORDERED_LIVE
static JsonNode *fixture;
static JsonNode *field_copy(const char *key) { return json_node_copy(json_object_get_member(json_node_get_object(fixture), key)); }
static void reply(RVHttpJobV16 *job, long code, JsonNode *node) {
    check(job != NULL && !record(job)->freed, "response retains its HTTP worker");
    JsonGenerator *g = json_generator_new(); json_generator_set_root(g, node); job->response = json_generator_to_data(g, &job->length);
    job->status = code; atomic_store(&job->ready, 1); g_object_unref(g); json_node_free(node);
}
static void freeze(LinuxOrderedLatencyV1 *s) { if (s->timer != 0) { g_source_remove(s->timer); s->timer = 0; } }
static LinuxOrderedLatencyV1 *ready(App *app) {
    LinuxOrderedLatencyV1 *s = panel(app); freeze(s); reply(s->jobs[OL_INFO_V1], 200, field_copy("info")); linux_ol_tick_v1(s);
    check(s->capture != NULL && !s->invalid && linux_ol_settled_v1(s), "exact connected three-hop catalog admitted");
    check(json_array_get_length(json_node_get_array(s->history)) == 1, "historical same-source old-generation result retained"); return s;
}
static JsonNode *status(LinuxOrderedLatencyV1 *s, const char *stage, gboolean complete, gboolean drained, gboolean receipt) {
    JsonNode *n = field_copy("info"); JsonObject *r = json_node_get_object(n), *st = linux_ol_object_v1(r, "status");
    JsonObject *node = json_array_get_object_element(json_node_get_array(s->nodes), (guint)s->position);
    json_object_set_string_member(r, "request_id", s->request); json_object_set_string_member(r, "node_id", linux_ol_string_v1(node, "node_id")); json_object_set_int_member(r, "position", s->position);
    json_object_set_string_member(st, "request_id", s->request); json_object_set_string_member(st, "stage", stage); json_object_set_boolean_member(st, "complete", complete); json_object_set_boolean_member(st, "drained", drained);
    if (receipt) {
        char key[32]; g_snprintf(key, sizeof key, "receipt%d", s->position); JsonNode *saved = field_copy(key); json_object_set_string_member(json_node_get_object(saved), "request_id", s->request); json_object_set_member(r, "receipt", saved);
    }
    return n;
}
static void start(LinuxOrderedLatencyV1 *s, int position) {
    gtk_combo_box_set_active(GTK_COMBO_BOX(s->hops), position); check(linux_ol_start_v1(s), "selected hop starts once");
    check(!linux_ol_start_v1(s), "overlapping Retest cannot replace original request");
    JsonNode *n = parse_json(record(s->jobs[OL_START_V1])->body); JsonObject *o = json_node_get_object(n);
    check(json_object_get_size(o) == 4 && linux_ol_same_capture_v1(linux_ol_object_v1(o, "capture"), json_node_get_object(s->capture)) &&
        json_object_get_int_member(o, "position") == position && !g_strcmp0(linux_ol_string_v1(o, "request_id"), s->request), "POST sends only exact capture, node, position and request"); json_node_free(n);
}
static void finish_jobs(LinuxOrderedLatencyV1 *s) {
    s->next_poll = s->next_cancel = G_MAXINT64;
    for (int i = 0; i < OL_JOBS_V1; i++) if (s->jobs[i] != NULL) reply(s->jobs[i], 200, status(s, "cancelled", TRUE, TRUE, FALSE));
    linux_ol_tick_v1(s);
}
static void dispose(LinuxOrderedLatencyV1 *s) {
    if (s->request != NULL && !(s->complete && s->drained)) { JsonNode *n = status(s, "cancelled", TRUE, TRUE, FALSE); check(linux_ol_receive_v1(s, json_node_get_object(n), FALSE), "original cancelled receipt admitted"); json_node_free(n); }
    finish_jobs(s); check(linux_ol_close_v1(s), "settled panel closes"); pump();
}
static void validation(App *app) {
    LinuxOrderedLatencyV1 *empty = panel(app); freeze(empty); JsonNode *catalog = field_copy("info"); json_object_remove_member(json_node_get_object(catalog), "history");
    reply(empty->jobs[OL_INFO_V1], 200, catalog); linux_ol_tick_v1(empty);
    check(empty->capture != NULL && !empty->invalid && json_array_get_length(json_node_get_array(empty->history)) == 0, "first-run omitted empty history is accepted"); dispose(empty);
    LinuxOrderedLatencyV1 *stale = panel(app); freeze(stale); app->selected = "replacement"; reply(stale->jobs[OL_INFO_V1], 200, field_copy("info")); linux_ol_tick_v1(stale);
    check(stale->invalid && stale->capture == NULL && stale->history == NULL, "replacement before catalog completion cannot adopt original history"); app->selected = "exit-a"; dispose(stale);
    LinuxOrderedLatencyV1 *s = ready(app); JsonObject *capture = json_node_get_object(s->capture);
    for (int position = 0; position < 3; position++) {
        char key[24]; g_snprintf(key, sizeof key, "receipt%d", position); JsonNode *n = field_copy(key); JsonObject *r = json_node_get_object(n), *node = json_array_get_object_element(json_node_get_array(s->nodes), (guint)position);
        check(linux_ol_receipt_v1(r, capture, node, TRUE), "fifty actual responses accepted for each timing method");
        const char *fields[] = {"source_sha256", "config_sha256", "generation_sha256", "request_id", "node_id"};
        for (guint i = 0; i < G_N_ELEMENTS(fields); i++) { JsonNode *bad = json_node_copy(n); json_object_set_string_member(json_node_get_object(bad), fields[i], "foreign"); check(!linux_ol_receipt_v1(json_node_get_object(bad), capture, node, TRUE), "foreign receipt owner refused"); json_node_free(bad); }
        const char *faults[] = {"samples", "attempts", "failed", "endpoint", "measurement", "median_ms", "jitter_ms", "trimmed_mean_ms", "date", "position", "ready", "probe-budget", "jitter-range", "unrelated", "label"};
        for (guint i = 0; i < G_N_ELEMENTS(faults); i++) {
            JsonNode *bad = json_node_copy(n); JsonObject *o = json_node_get_object(bad), *result = linux_ol_object_v1(o, "result"), *b = linux_ol_object_v1(result, "benchmark"), *d = linux_ol_object_v1(b, "distribution");
            switch(i) { case 0:json_object_set_int_member(d,"samples",49);break;case 1:json_object_set_int_member(b,"attempts",49);break;case 2:json_object_set_int_member(b,"failed",1);break;case 3:json_object_set_string_member(b,"endpoint","https://foreign.invalid/");break;case 4:json_object_set_string_member(b,"measurement","direct");break;case 5:json_object_set_double_member(d,"median_ms",0);break;case 6:json_object_set_double_member(d,"jitter_ms",-1);break;case 7:json_object_set_double_member(b,"trimmed_mean_ms",99999);break;case 8:json_object_set_int_member(o,"measured_at",g_get_real_time()/1000+60000);break;case 9:json_object_set_int_member(o,"position",(position+1)%3);break;case 10:json_object_set_boolean_member(result,"ready",FALSE);break;case 11:json_object_set_double_member(d,"max_ms",5001);break;case 12:json_object_set_double_member(d,"jitter_ms",5);break;case 13:json_object_set_object_member(result,"download",json_object_new());break;case 14:json_object_set_string_member(result,"label","foreign label");break; }
            check(!linux_ol_receipt_v1(o, capture, node, TRUE), faults[i]); json_node_free(bad);
        }
        json_node_free(n);
    }
    start(s, 1); guint old_count = json_array_get_length(json_node_get_array(s->history));
    JsonNode *n = status(s, "complete", TRUE, FALSE, TRUE);
    check(!linux_ol_receive_v1(s, json_node_get_object(n), FALSE) && json_array_get_length(json_node_get_array(s->history)) == old_count, "undrained receipt cannot replace saved history"); json_node_free(n);
    n = status(s, "complete", TRUE, TRUE, FALSE); check(!linux_ol_receive_v1(s, json_node_get_object(n), FALSE), "complete success requires durable receipt"); json_node_free(n);
    const char *owners[] = {"session_id", "profile_id", "profile_token", "source_sha256", "config_sha256", "generation_sha256"};
    const char *foreign[] = {"session-999-999", "foreign-profile", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000"};
    for (guint i = 0; i < G_N_ELEMENTS(owners); i++) { n = status(s,"cancelled",TRUE,TRUE,FALSE); json_object_set_string_member(linux_ol_object_v1(json_node_get_object(n),"capture"),owners[i],foreign[i]); check(linux_ol_capture_v1(linux_ol_object_v1(json_node_get_object(n),"capture")),"foreign capture remains structurally valid"); check(!linux_ol_receive_v1(s,json_node_get_object(n),FALSE),"stale status cannot attest drain");json_node_free(n); }
    linux_ol_cancel_v1(s); n = status(s,"complete",TRUE,TRUE,TRUE); check(linux_ol_receive_v1(s,json_node_get_object(n),FALSE),"commit before Cancel honestly remains saved");json_node_free(n);
    check(strstr(s->message,"finished before cancellation") != NULL && json_array_get_length(json_node_get_array(s->history)) == 2,"saved commit is visible with date/history");
    check(!linux_ol_settled_v1(s), "native drain still waits original HTTP jobs"); finish_jobs(s); dispose(s);
}
static void cancellation(App *app) {
    LinuxOrderedLatencyV1 *s = ready(app); start(s, 0); RVHttpJobV16 *original = s->jobs[OL_START_V1]; char *request = g_strdup(s->request);
    check(linux_ordered_latency_parent_delete_v1(app->window,NULL,app), "parent close waits captured native and HTTP cleanup"); s->parent_closing = FALSE;
    reply(s->jobs[OL_CANCEL_V1],200,status(s,"cancelled",TRUE,TRUE,FALSE)); linux_ol_tick_v1(s);
    check(s->dialog != NULL && s->jobs[OL_START_V1] == original && !linux_ol_settled_v1(s), "queued Start still joins after cancellation tombstone");
    check(!g_strcmp0(request,s->request),"cancellation never borrows a newer owner");
    reply(original,409,parse_json("{\"error\":\"queued Start tombstoned\"}")); linux_ol_tick_v1(s); g_free(request); pump();
    check(g_object_get_data(G_OBJECT(app->window),"router-vpn-ordered-latency-v1")==NULL,"close waits queued original HTTP worker then removes dialog");
    s = ready(app); start(s,2); reply(s->jobs[OL_START_V1],503,parse_json("{}")); linux_ol_tick_v1(s);
    check(!(s->complete&&s->drained)&&s->cancelled,"transport failure cannot prove native drain");
    s->deadline = 0; linux_ol_tick_v1(s); check(!(s->complete&&s->drained),"timeout only cancels original request");
    app->selected="replacement"; linux_ol_tick_v1(s); check(s->invalid&&!linux_ol_settled_v1(s),"selection replacement retains old owner until drain"); app->selected="exit-a";
    JsonNode *committed = status(s,"complete",TRUE,TRUE,TRUE);
    check(linux_ol_receive_v1(s,json_node_get_object(committed),FALSE),"invalidated view accepts only exact original committed drain"); json_node_free(committed);
    check(s->invalid && json_array_get_length(json_node_get_array(s->history))==1 && !linux_ol_start_v1(s),"invalidated view never adopts history or retests");
    check(!linux_ol_settled_v1(s),"invalidated terminal still waits every original HTTP worker");
    dispose(s);
}
#else
static void live(App *app, const char *scenario) {
    LinuxOrderedLatencyV1 *s = panel(app); gint64 until = g_get_monotonic_time()+20*G_TIME_SPAN_SECOND;
    while (s->capture == NULL && !s->invalid && g_get_monotonic_time()<until) { pump(); g_usleep(10000); }
    check(s->capture != NULL && !s->invalid,"real loopback catalog captured");
    gtk_combo_box_set_active(GTK_COMBO_BOX(s->hops),1); gtk_dialog_response(GTK_DIALOG(s->dialog),1);
    check(s->request != NULL,"real GTK Retest created original request");
    gboolean early = !strcmp(scenario,"early"), saved = !strcmp(scenario,"saved") || !strcmp(scenario,"commit-race");
    if (!early) { gint64 admitted=g_get_monotonic_time()+500000;while(g_get_monotonic_time()<admitted){pump();g_usleep(10000);} }
    if (!strcmp(scenario,"replacement-commit")) { app->selected="replacement"; }
    if (strcmp(scenario,"saved")) gtk_dialog_response(GTK_DIALOG(s->dialog),2);
    while (!linux_ol_settled_v1(s) && g_get_monotonic_time()<until) { pump();g_usleep(10000); }
    check(linux_ol_settled_v1(s),"real original native receipt and all HTTP workers joined");
    check(json_array_get_length(json_node_get_array(s->history))==(saved?2u:1u),"only durable exact receipt changes historical results");
    if (saved) check(strstr(s->message,"saved")!=NULL,"saved result rendered honestly");
    if (early) check(s->cancelled,"prestart cancellation retained original tombstone");
    if (!strcmp(scenario,"replacement-commit")) check(s->invalid && !linux_ol_start_v1(s),"replaced display drains original commit without adopting or retesting");
    app->selected="exit-a";gtk_dialog_response(GTK_DIALOG(s->dialog),GTK_RESPONSE_CLOSE);pump();
}
#endif
int main(int argc,char **argv) {
    gtk_init(&argc,&argv);curl_global_init(CURL_GLOBAL_DEFAULT);App app={gtk_window_new(GTK_WINDOW_TOPLEVEL),"exit-a"};gtk_widget_show_all(app.window);
#ifndef ROUTERVPN_ORDERED_LIVE
    check(argc==2,"fixture JSON supplied");char *text=NULL;check(g_file_get_contents(argv[1],&text,NULL,NULL),"read fixture");fixture=parse_json(text);g_free(text);check(fixture!=NULL,"fixture JSON valid");records=g_ptr_array_new();
    validation(&app);cancellation(&app);checked_parent_shutdown=TRUE;gtk_widget_destroy(app.window);pump();
    for(guint i=0;i<records->len;i++){Record*r=g_ptr_array_index(records,i);check(r->freed,"every original HTTP worker released");g_free(r->path);g_free(r->body);g_free(r);}g_ptr_array_free(records,TRUE);json_node_free(fixture);
#else
    check(argc==2,"live scenario supplied");live(&app,argv[1]);gtk_widget_destroy(app.window);pump();
#endif
    gint64 until=g_get_monotonic_time()+100000;while(g_get_monotonic_time()<until){pump();g_usleep(1000);}curl_global_cleanup();g_print("GTK ordered latency checks: %d PASS\n",checks);return 0;
}
