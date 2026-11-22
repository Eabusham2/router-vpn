#include <gtk/gtk.h>
#include <json-glib/json-glib.h>
#include <math.h>
#include <string.h>

typedef struct { int unused; } App;
typedef struct {
    gboolean closed, last_ok;
    guint64 generation, finished_generation;
    gpointer primary;
    char *last_result;
} LinuxAsyncActionsV16;

static LinuxAsyncActionsV16 worker;
static JsonObject *scenario;
static guint requests;
static void check(gboolean ok, const char *why) { if (!ok) g_error("Extended throughput: %s", why); }
static JsonNode *parse_json(const char *raw) { return json_from_string(raw, NULL); }
static LinuxAsyncActionsV16 *linux_async_state_v16(App *app) { (void)app; return &worker; }
static void linux_async_cancel_request_v17(App *app, guint64 generation) { (void)app; (void)generation; }
static guint64 linux_async_request_v17(App *app, const char *path, const char *body, long timeout, const char *name, gboolean get) {
    (void)app; (void)name;
    requests++;
    JsonObject *original = json_object_get_object_member(scenario, "preflight");
    if (get) {
        check(requests == 1 && timeout == 5000 && !strcmp(path, "/api/multihop/status"), "original status request changed");
    } else {
        check(requests == 2 && timeout == 100000 && !strcmp(path, "/api/multihop/speed-test"), "original throughput owner or deadline changed");
        JsonNode *payload = parse_json(body);
        JsonObject *obj = json_node_get_object(payload);
        check(json_object_get_size(obj) == 4 && json_object_get_int_member(obj, "bytes") == 8388608, "changed POST byte budget or private fields");
        const char *keys[] = {"entry_id", "exit_id", "ordered_capture"};
        for (guint i = 0; i < G_N_ELEMENTS(keys); i++)
            check(!g_strcmp0(json_object_get_string_member(obj, keys[i]), json_object_get_string_member(original, keys[i])), "POST borrowed another source");
        json_node_free(payload);
    }
    g_free(worker.last_result);
    worker.last_result = json_to_string(json_object_get_member(scenario, get ? "preflight" : "result"), FALSE);
    worker.last_ok = TRUE;
    worker.finished_generation = ++worker.generation;
    return worker.generation;
}

#include ROUTERVPN_PERFORMANCE_SOURCE

int main(int argc, char **argv) {
    gtk_init(&argc, &argv);
    char *raw = NULL;
    check(argc == 2 && g_file_get_contents(argv[1], &raw, NULL, NULL), "missing test catalog");
    JsonNode *data = parse_json(raw); JsonArray *cases = json_node_get_array(data); g_free(raw);
    for (guint j = 0; j < json_array_get_length(cases); j++) {
        scenario = json_array_get_object_element(cases, j); requests = 0;
        App app = {0}; LinuxPerformanceV17 panel = {.app = &app, .preflight = TRUE};
        panel.dialog = gtk_dialog_new(); panel.result = gtk_label_new(""); panel.detail = gtk_text_view_new();
        GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(panel.dialog));
        gtk_container_add(GTK_CONTAINER(content), panel.result); gtk_container_add(GTK_CONTAINER(content), panel.detail);
        for (guint i = 0; i < G_N_ELEMENTS(panel.actions); i++)
            panel.actions[i] = gtk_dialog_add_button(GTK_DIALOG(panel.dialog), "Test", (int)i);
        linux_performance_begin_v17(&panel, "/api/multihop/status", NULL, 5000, TRUE);
        gint64 until = g_get_monotonic_time() + 3000000;
        while (panel.generation && g_get_monotonic_time() < until) {
            g_main_context_iteration(NULL, FALSE); g_usleep(1000);
        }
        check(!panel.generation && !panel.poll && !panel.local_source && !panel.ordered_token, "owner did not drain");
        check(requests == (guint)json_object_get_int_member(scenario, "requests"), "wrong source reached the measurement endpoint");
        GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(panel.detail)); GtkTextIter start, end;
        gtk_text_buffer_get_bounds(buffer, &start, &end);
        char *displayed = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);
        if (json_object_get_boolean_member(scenario, "adopt")) {
            check(!strcmp(displayed, worker.last_result), "complete original response was not displayed");
        } else { check(strstr(displayed, "to the public benchmark") == NULL, "unbound rows were displayed"); }
        g_free(displayed); gtk_widget_destroy(panel.dialog);
    }
    g_print("GTK extended throughput: %u shipping preflight and result callbacks PASS\n", json_array_get_length(cases));
    json_node_free(data); g_free(worker.last_result); return 0;
}
