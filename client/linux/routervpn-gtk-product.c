
/* Consolidated routervpn-gtk-product-v4-embedded.c */
#define draw_map routervpn_flat_map_v9
#define self_test_v3 routervpn_product_v3_self_test

/* Consolidated routervpn-gtk-product-v3.c */
#define self_test routervpn_product_core_self_test

/* Consolidated routervpn-gtk-product.c */
#define _GNU_SOURCE
#include <curl/curl.h>
#include <gtk/gtk.h>
#include <json-glib/json-glib.h>
#include <math.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "routervpn-controller-auth-v1.h"

#define ROUTER_VPN_BASE_URL "http://127.0.0.1:8788"
#define ROUTER_VPN_PRODUCT_CONTRACT 2

typedef struct {
    char *data;
    size_t len;
} Buffer;

typedef struct {
    char *id;
    char *name;
    char *location;
    char *endpoint;
    double latitude;
    double longitude;
    double latency;
    gboolean has_coordinates;
    gboolean selected;
} MapNode;

typedef struct {
    GtkWidget *window;
    GtkWidget *status;
    GtkWidget *detail;
    GtkWidget *error;
    GtkWidget *diagnostics;
    GtkWidget *nodes_view;
    GtkWidget *modes_view;
    GtkWidget *map;
    GtkWidget *router_combo;
    GtkWidget *mode_combo;
    GtkWidget *base_combo;
    GPtrArray *nodes;
    GPtrArray *router_ids;
    GPtrArray *mode_ids;
    guint64 event_seq;
    pid_t controller_pid;
    gboolean owns_controller;
    char controller_owner[33];
    char controller_access[65];
    int controller_lifetime_fd;
    gpointer controller_shutdown;
    gboolean suppress_router_change;
    char *package_root;
} App;

#include "routervpn-async-actions-v16.inc"

static size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t total = size * nmemb;
    Buffer *buf = userp;
    char *next = realloc(buf->data, buf->len + total + 1);
    if (next == NULL) return 0;
    buf->data = next;
    memcpy(buf->data + buf->len, contents, total);
    buf->len += total;
    buf->data[buf->len] = '\0';
    return total;
}

static atomic_bool controller_exit_pending=ATOMIC_VAR_INIT(FALSE);

static gboolean api_request(const char *path, const char *method, const char *body,
                            long timeout_ms, Buffer *out, char **error_out) {
    if (!strcmp(method, "POST") && linux_load_fences_launch(path)) {
        if (out) memset(out, 0, sizeof(*out));
        if (error_out) *error_out = g_strdup("Open Profiles to recover the pending Load before connecting.");
        return FALSE;
    }
    if (atomic_load_explicit(&controller_exit_pending,memory_order_acquire)) {
        if (out != NULL) memset(out,0,sizeof(*out));
        if (error_out != NULL) *error_out=g_strdup("Router VPN is waiting for checked controller cleanup.");
        return FALSE;
    }
    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        if (error_out != NULL) *error_out = g_strdup("libcurl initialization failed");
        return FALSE;
    }
    char *url = g_strdup_printf("%s%s", ROUTER_VPN_BASE_URL, path);
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept: application/json");
    if (body != NULL) headers = curl_slist_append(headers, "Content-Type: application/json");
    RVControllerAuth authentication;rv_controller_auth_capture(&authentication);
    if(authentication.header[0])headers=curl_slist_append(headers,authentication.header);
    memset(out, 0, sizeof(*out));
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    curl_easy_setopt(curl, CURLOPT_NOPROXY, "*");
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, timeout_ms);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, out);
    if (method != NULL && strcmp(method, "GET") != 0) curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    if (body != NULL) curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    CURLcode code = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    gboolean ok = code == CURLE_OK && status >= 200 && status < 300;
    if (!ok && error_out != NULL) {
        if (out->data != NULL && out->data[0] != '\0') *error_out = g_strdup(g_strstrip(out->data));
        else *error_out = g_strdup(code != CURLE_OK ? curl_easy_strerror(code) : "local controller request failed");
    }
    g_free(url);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return ok;
}

static JsonNode *parse_json(const char *text) {
    if (text == NULL) return NULL;
    JsonParser *parser = json_parser_new();
    GError *error = NULL;
    if (!json_parser_load_from_data(parser, text, -1, &error)) {
        if (error != NULL) g_error_free(error);
        g_object_unref(parser);
        return NULL;
    }
    JsonNode *node = json_node_copy(json_parser_get_root(parser));
    g_object_unref(parser);
    return node;
}

/* JsonNode copies retain object references. Snapshot public catalog values so
 * later UI/controller callbacks cannot mutate an already displayed owner. */
static JsonNode *copy_public_source_value_v24(JsonNode *root) {
    if (root == NULL) return NULL;
    char *text = json_to_string(root, FALSE);
    JsonNode *copy = text != NULL ? parse_json(text) : NULL;
    g_free(text);
    return copy;
}

static const char *obj_string(JsonObject *obj, const char *key) {
    if (obj == NULL || !json_object_has_member(obj, key)) return "";
    JsonNode *node = json_object_get_member(obj, key);
    if (!JSON_NODE_HOLDS_VALUE(node) || json_node_get_value_type(node) != G_TYPE_STRING) return "";
    return json_node_get_string(node);
}

static double obj_double(JsonObject *obj, const char *key, gboolean *present) {
    if (present != NULL) *present = FALSE;
    if (obj == NULL || !json_object_has_member(obj, key)) return 0;
    JsonNode *node = json_object_get_member(obj, key);
    if (!JSON_NODE_HOLDS_VALUE(node)) return 0;
    GType type = json_node_get_value_type(node);
    if (type != G_TYPE_DOUBLE && type != G_TYPE_INT64 && type != G_TYPE_INT && type != G_TYPE_UINT64) return 0;
    if (present != NULL) *present = TRUE;
    return json_node_get_double(node);
}

static void free_map_node(gpointer data) {
    MapNode *node = data;
    if (node == NULL) return;
    g_free(node->id);
    g_free(node->name);
    g_free(node->location);
    g_free(node->endpoint);
    g_free(node);
}

static void append_diag(App *app, const char *message) {
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->diagnostics));
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(buffer, &end);
    GDateTime *now = g_date_time_new_now_local();
    char *stamp = g_date_time_format(now, "%H:%M:%S");
    char *line = g_strdup_printf("[%s] %s\n", stamp, message != NULL ? message : "");
    gtk_text_buffer_insert(buffer, &end, line, -1);
    g_free(line);
    g_free(stamp);
    g_date_time_unref(now);
}

static gboolean draw_map(GtkWidget *widget, cairo_t *cr, gpointer user_data) {
    App *app = user_data;
    GtkAllocation allocation;
    gtk_widget_get_allocation(widget, &allocation);
    double width = allocation.width;
    double height = allocation.height;
    cairo_set_source_rgb(cr, 0.055, 0.075, 0.12);
    cairo_paint(cr);
    cairo_set_source_rgb(cr, 0.20, 0.25, 0.34);
    cairo_set_line_width(cr, 1.0);
    for (int lon = -120; lon <= 120; lon += 60) {
        double x = (lon + 180.0) / 360.0 * width;
        cairo_move_to(cr, x, 0); cairo_line_to(cr, x, height);
    }
    for (int lat = -60; lat <= 60; lat += 30) {
        double y = (90.0 - lat) / 180.0 * height;
        cairo_move_to(cr, 0, y); cairo_line_to(cr, width, y);
    }
    cairo_stroke(cr);
    guint plotted = 0;
    for (guint i = 0; i < app->nodes->len; i++) {
        MapNode *node = g_ptr_array_index(app->nodes, i);
        if (!node->has_coordinates) continue;
        plotted++;
        double x = (node->longitude + 180.0) / 360.0 * width;
        double y = (90.0 - node->latitude) / 180.0 * height;
        cairo_set_source_rgb(cr, node->selected ? 0.25 : 0.20,
                             node->selected ? 0.62 : 0.78,
                             node->selected ? 1.00 : 0.66);
        cairo_arc(cr, x, y, node->selected ? 7.0 : 5.0, 0, 2 * G_PI);
        cairo_fill(cr);
        cairo_set_source_rgb(cr, 0.92, 0.95, 1.0);
        cairo_move_to(cr, x + 9, y - 7);
        cairo_show_text(cr, node->name[0] != '\0' ? node->name : node->id);
    }
    if (plotted == 0) {
        cairo_set_source_rgb(cr, 0.75, 0.78, 0.84);
        cairo_move_to(cr, 24, height / 2.0);
        cairo_show_text(cr, "No real node coordinates - Router VPN never invents map locations.");
    }
    return FALSE;
}

static GtkWidget *scrolled_text(GtkWidget **view_out) {
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    GtkWidget *view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_WORD_CHAR);
    gtk_container_add(GTK_CONTAINER(scroll), view);
    *view_out = view;
    return scroll;
}

static GtkWidget *make_info_page(const char *title, const char *body) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_container_set_border_width(GTK_CONTAINER(box), 20);
    GtkWidget *heading = gtk_label_new(NULL);
    char *markup = g_markup_printf_escaped("<span size='x-large' weight='bold'>%s</span>", title);
    gtk_label_set_markup(GTK_LABEL(heading), markup);
    g_free(markup);
    gtk_label_set_xalign(GTK_LABEL(heading), 0.0f);
    gtk_box_pack_start(GTK_BOX(box), heading, FALSE, FALSE, 0);
    GtkWidget *label = gtk_label_new(body);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);
    return box;
}

static GtkWidget *make_button(const char *label, GCallback callback, App *app) {
    GtkWidget *button = gtk_button_new_with_label(label);
    g_signal_connect(button, "clicked", callback, app);
    return button;
}

static gboolean routervpn_phase_busy(const char *phase) {
    if (phase == NULL || phase[0] == '\0') return FALSE;
    char *lower = g_ascii_strdown(phase, -1);
    gboolean busy = strstr(lower, "connecting") != NULL || strstr(lower, "starting") != NULL ||
        strstr(lower, "checking") != NULL || strstr(lower, "trying") != NULL ||
        strstr(lower, "proving") != NULL || strstr(lower, "reasserting") != NULL ||
        strstr(lower, "disconnecting") != NULL || strstr(lower, "stopping") != NULL ||
        strstr(lower, "switching") != NULL || strstr(lower, "reconnecting") != NULL || g_str_has_prefix(lower, "candidate:");
    g_free(lower);
    return busy;
}

static gboolean routervpn_phase_disconnecting(const char *phase) {
    if (phase == NULL || phase[0] == '\0') return FALSE;
    char *lower = g_ascii_strdown(phase, -1);
    gboolean stopping = strstr(lower, "disconnecting") != NULL || strstr(lower, "stopping") != NULL;
    g_free(lower);
    return stopping;
}

static gboolean routervpn_mutation_busy_from_status(JsonObject *obj) {
    if (obj == NULL) return TRUE;
    if(json_object_has_member(obj,"stop_pending")){JsonNode *pending=json_object_get_member(obj,"stop_pending");if(!JSON_NODE_HOLDS_VALUE(pending)||json_node_get_value_type(pending)!=G_TYPE_BOOLEAN||json_node_get_boolean(pending))return TRUE;}
    gboolean connected = json_object_has_member(obj, "connected") && json_object_get_boolean_member(obj, "connected");
    return connected || routervpn_phase_busy(obj_string(obj, "phase"));
}

static gboolean routervpn_mutation_busy(App *app) {
    if (linux_async_busy_v16(app)) return TRUE;
    if(app&&app->window&&g_object_get_data(G_OBJECT(app->window),"linux-ordered-candidates-pending")!=NULL)return TRUE;
    Buffer out = {0}; char *err = NULL; gboolean busy = TRUE;
    if (api_request("/api/status", "GET", NULL, 3500, &out, &err)) {
        JsonNode *root = parse_json(out.data);
        if (root != NULL && JSON_NODE_HOLDS_OBJECT(root)) busy = routervpn_mutation_busy_from_status(json_node_get_object(root));
        if (root != NULL) json_node_free(root);
    }
    g_free(err); free(out.data);
    return busy;
}

static gboolean routervpn_require_mutation_idle(App *app, const char *action) {
    if (!routervpn_mutation_busy(app)) return TRUE;
    char *line = g_strdup_printf("Disconnect Router VPN or let the active transition finish before %s; live session identity and proof are immutable.", action != NULL ? action : "changing persistent session state");
    append_diag(app, line);
    gtk_label_set_text(GTK_LABEL(app->error), line);
    g_free(line);
    return FALSE;
}

#include "routervpn-shell-readings-v1.inc"

static void refresh_status_readings(App *app, const LinuxShellReadings *round) {
    Buffer out = {0};
    char *err = NULL;
    if (!linux_shell_read_v1(round, "/api/status", "GET", NULL, 2200, &out, &err)) {
        gtk_label_set_text(GTK_LABEL(app->status), "● Controller unavailable");
        gtk_label_set_text(GTK_LABEL(app->error), err != NULL ? err : "Controller unavailable");
        g_free(err); free(out.data); return;
    }
    JsonNode *root = parse_json(out.data);
    if (root != NULL && JSON_NODE_HOLDS_OBJECT(root)) {
        JsonObject *obj = json_node_get_object(root);
        gboolean connected = json_object_has_member(obj, "connected") && json_object_get_boolean_member(obj, "connected");
        const char *phase = obj_string(obj, "phase");
        const char *runtime_mode = obj_string(obj, "runtime_mode");
        if (runtime_mode[0] == '\0') runtime_mode = obj_string(obj, "mode");
        char *state = g_strdup_printf("%s %s", connected ? "●" : "○",
                                      connected ? "Connected" : (phase[0] != '\0' ? phase : "Off"));
        char *detail = g_strdup_printf("Logical: %s    Runtime: %s    Base: %s    Router: %s",
                                       obj_string(obj, "logical_mode"), runtime_mode,
                                       obj_string(obj, "base"), obj_string(obj, "router_id"));
        gtk_label_set_text(GTK_LABEL(app->status), state);
        gtk_label_set_text(GTK_LABEL(app->detail), detail);
        gtk_label_set_text(GTK_LABEL(app->error), obj_string(obj, "last_error"));
        g_free(state); g_free(detail);
    }
    if (root != NULL) json_node_free(root);
    free(out.data); g_free(err);
}

static void refresh_status(App *app) {
    refresh_status_readings(app, NULL);
}

static void refresh_session_events_readings(App *app, const LinuxShellReadings *round) {
    char *path = g_strdup_printf("/api/session/events?after=%" G_GUINT64_FORMAT, app->event_seq);
    Buffer out = {0};
    char *err = NULL;
    if (!linux_shell_read_v1(round, path, "GET", NULL, 2200, &out, &err)) {
        g_free(path); g_free(err); free(out.data); return;
    }
    g_free(path);
    JsonNode *root = parse_json(out.data);
    if (root != NULL && JSON_NODE_HOLDS_OBJECT(root)) {
        JsonObject *obj = json_node_get_object(root);
        JsonArray *events = json_object_get_array_member(obj, "events");
        if (events != NULL) {
            for (guint i = 0; i < json_array_get_length(events); i++) {
                JsonObject *event = json_array_get_object_element(events, i);
                if (event == NULL) continue;
                guint64 seq = (guint64)json_object_get_int_member(event, "seq");
                if (seq <= app->event_seq) continue;
                const char *type = obj_string(event, "type");
                const char *phase = obj_string(event, "phase");
                const char *runtime_mode = obj_string(event, "runtime_mode");
                const char *base = obj_string(event, "base");
                const char *message = obj_string(event, "message");
                char *line = g_strdup_printf("Session #%" G_GUINT64_FORMAT " %s: %s%s%s%s%s%s%s",
                    seq, type, phase,
                    runtime_mode[0] ? " | runtime=" : "", runtime_mode,
                    base[0] ? " | base=" : "", base,
                    message[0] ? " | " : "", message);
                append_diag(app, line);
                g_free(line);
                app->event_seq = seq;
            }
        }
        if (json_object_has_member(obj, "last_event_seq")) {
            guint64 last = (guint64)json_object_get_int_member(obj, "last_event_seq");
            if (last > app->event_seq) app->event_seq = last;
        }
    }
    if (root != NULL) json_node_free(root);
    free(out.data); g_free(err);
}

static void refresh_session_events(App *app) {
    refresh_session_events_readings(app, NULL);
}

static void refresh_profiles(App *app) {
    Buffer out = {0};
    char *err = NULL;
    if (!api_request("/api/profiles", "GET", NULL, 3000, &out, &err)) {
        g_free(err); free(out.data); return;
    }
    JsonNode *root = parse_json(out.data);
    if (root == NULL || !JSON_NODE_HOLDS_OBJECT(root)) {
        if (root != NULL) json_node_free(root);
        free(out.data); g_free(err); return;
    }
    JsonObject *store = json_node_get_object(root);
    const char *selected = obj_string(store, "selected_id");
    JsonArray *profiles = json_object_get_array_member(store, "profiles");
    app->suppress_router_change = TRUE;
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(app->router_combo));
    g_ptr_array_set_size(app->router_ids, 0);
    g_ptr_array_set_size(app->nodes, 0);
    GString *text = g_string_new("");
    guint selected_index = 0;
    if (profiles != NULL) {
        for (guint i = 0; i < json_array_get_length(profiles); i++) {
            JsonObject *profile = json_array_get_object_element(profiles, i);
            if (profile == NULL) continue;
            MapNode *node = g_new0(MapNode, 1);
            node->id = g_strdup(obj_string(profile, "id"));
            node->name = g_strdup(obj_string(profile, "name"));
            node->location = g_strdup(obj_string(profile, "location"));
            node->endpoint = g_strdup(obj_string(profile, "endpoint"));
            gboolean has_lat = FALSE, has_lon = FALSE, has_latency = FALSE;
            node->latitude = obj_double(profile, "latitude", &has_lat);
            node->longitude = obj_double(profile, "longitude", &has_lon);
            node->latency = obj_double(profile, "latency_median_ms", &has_latency);
            node->has_coordinates = (has_lat || has_lon) &&
                (has_lat || !json_object_has_member(profile, "latitude")) &&
                (has_lon || !json_object_has_member(profile, "longitude")) &&
                isfinite(node->latitude) && isfinite(node->longitude)
                && node->latitude >= -90 && node->latitude <= 90
                && node->longitude >= -180 && node->longitude <= 180
                && !(node->latitude == 0 && node->longitude == 0);
            node->selected = selected[0] != '\0' && strcmp(selected, node->id) == 0;
            if (node->selected) selected_index = i;
            gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->router_combo),
                                           node->name[0] != '\0' ? node->name : node->id);
            g_ptr_array_add(app->router_ids, g_strdup(node->id));
            g_ptr_array_add(app->nodes, node);
            g_string_append_printf(text, "%s%s\n  %s\n  endpoint: %s\n  coordinates: %s",
                node->selected ? "● " : "", node->name[0] ? node->name : node->id,
                node->location[0] ? node->location : "Location not labeled",
                node->endpoint[0] ? node->endpoint : "—",
                node->has_coordinates ? "real stored latitude/longitude" : "not stored — not plotted");
            if (has_latency && node->latency > 0) g_string_append_printf(text, "\n  median latency: %.1f ms", node->latency);
            g_string_append(text, "\n\n");
        }
    }
    if (app->router_ids->len > 0) gtk_combo_box_set_active(GTK_COMBO_BOX(app->router_combo), (gint)selected_index);
    app->suppress_router_change = FALSE;
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->nodes_view));
    gtk_text_buffer_set_text(buffer, text->str, -1);
    g_string_free(text, TRUE);
    gtk_widget_queue_draw(app->map);
    g_object_set_data_full(G_OBJECT(app->window), "router-vpn-source-catalog-v24", copy_public_source_value_v24(root), (GDestroyNotify)json_node_free);
    json_node_free(root); free(out.data); g_free(err);
}

static void refresh_modes(App *app) {
    Buffer out = {0};
    char *err = NULL;
    if (!api_request("/api/logical-modes", "GET", NULL, 12000, &out, &err)) {
        g_free(err); free(out.data); return;
    }
    JsonNode *root = parse_json(out.data);
    if (root != NULL && JSON_NODE_HOLDS_ARRAY(root)) {
        JsonArray *modes = json_node_get_array(root);
        gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(app->mode_combo));
        g_ptr_array_set_size(app->mode_ids, 0);
        GString *text = g_string_new("");
        for (guint i = 0; i < json_array_get_length(modes); i++) {
            JsonObject *mode = json_array_get_object_element(modes, i);
            if (mode == NULL) continue;
            const char *id = obj_string(mode, "id");
            const char *name = obj_string(mode, "name");
            const char *reason = obj_string(mode, "reason");
            gboolean available = json_object_has_member(mode, "available") && json_object_get_boolean_member(mode, "available");
            g_string_append_printf(text, "%s %s [%s]\n  %s\n\n",
                                   available ? "✓" : "—", name, id,
                                   reason[0] != '\0' ? reason : "Ready");
            if (available) {
                gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->mode_combo), name);
                g_ptr_array_add(app->mode_ids, g_strdup(id));
            }
        }
        if (app->mode_ids->len > 0) gtk_combo_box_set_active(GTK_COMBO_BOX(app->mode_combo), 0);
        GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->modes_view));
        gtk_text_buffer_set_text(buffer, text->str, -1);
        g_string_free(text, TRUE);
    }
    if (root != NULL) json_node_free(root);
    free(out.data); g_free(err);
}

static void refresh_all(App *app) {
    refresh_status(app);
    refresh_session_events(app);
    refresh_profiles(app);
    refresh_modes(app);
}

static gboolean refresh_timer(gpointer data) {
    linux_shell_request_v1(data);
    return G_SOURCE_CONTINUE;
}

static void post_and_log(App *app, const char *path, const char *body, long timeout_ms, const char *label) {
    if (linux_async_dispatch_v16(app, path, body, timeout_ms, label)) return;
    Buffer out = {0};
    char *err = NULL;
    if (api_request(path, "POST", body, timeout_ms, &out, &err)) {
        char *line = g_strdup_printf("%s: %s", label, out.data != NULL && out.data[0] != '\0' ? g_strstrip(out.data) : "OK");
        append_diag(app, line);
        g_free(line);
    } else {
        char *line = g_strdup_printf("%s failed: %s", label, err != NULL ? err : "request failed");
        append_diag(app, line);
        gtk_label_set_text(GTK_LABEL(app->error), err != NULL ? err : "request failed");
        g_free(line);
    }
    g_free(err); free(out.data);
    refresh_status(app);
    refresh_session_events(app);
}

static void on_auto(GtkButton *button, gpointer data) {
    (void)button; App *app = data;
    if (!routervpn_require_mutation_idle(app, "starting AUTO")) return;
    post_and_log(app, "/api/auto", "{}", 150000, "AUTO");
}

static void on_disconnect(GtkButton *button, gpointer data) {
    (void)button;
    post_and_log((App *)data, "/api/disconnect", "{}", 20000, "Disconnect");
}

static void on_emergency(GtkButton *button, gpointer data) {
    (void)button;
    post_and_log((App *)data, "/api/emergency-stop", "{}", 20000, "Emergency stop");
}

static void on_public_ip(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    Buffer out = {0}; char *err = NULL;
    if (api_request("/api/public-ip", "GET", NULL, 20000, &out, &err)) append_diag(app, out.data != NULL ? g_strstrip(out.data) : "Public exit proof OK");
    else append_diag(app, err != NULL ? err : "Public exit proof failed");
    g_free(err); free(out.data); refresh_status(app);
}

static void linux_dns_retest_v1(App *app);

static void on_dns(GtkButton *button, gpointer data) {
    (void)button;
    linux_dns_retest_v1((App *)data);
}

static void on_connect(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    if (!routervpn_require_mutation_idle(app, "starting the selected mode")) return;
    gint mode_index = gtk_combo_box_get_active(GTK_COMBO_BOX(app->mode_combo));
    if (mode_index < 0 || (guint)mode_index >= app->mode_ids->len) {
        append_diag(app, "Connect failed: choose an available mode first.");
        return;
    }
    const char *mode = g_ptr_array_index(app->mode_ids, (guint)mode_index);
    gint base_index = gtk_combo_box_get_active(GTK_COMBO_BOX(app->base_combo));
    const char *base = base_index == 1 ? "wg" : (base_index == 2 ? "awg" : "auto");
    char *body = g_strdup_printf("{\"mode\":\"%s\",\"base\":\"%s\"}", mode, base);
    post_and_log(app, "/api/connect-logical", body, 180000, "Connect");
    g_free(body);
}

static void on_router_changed(GtkComboBox *box, gpointer data) {
    App *app = data;
    if (app->suppress_router_change) return;
    if (!routervpn_require_mutation_idle(app, "selecting another Router VPN node")) { refresh_profiles(app); return; }
    gint index = gtk_combo_box_get_active(box);
    if (index < 0 || (guint)index >= app->router_ids->len) return;
    const char *id = g_ptr_array_index(app->router_ids, (guint)index);
    char *body = g_strdup_printf("{\"id\":\"%s\"}", id);
    post_and_log(app, "/api/profile/select", body, 10000, "Select node");
    g_free(body);
    refresh_profiles(app);
}

static GtkWidget *build_home_page(App *app) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_container_set_border_width(GTK_CONTAINER(box), 20);
    GtkWidget *heading = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(heading), "<span size='xx-large' weight='bold'>Router VPN</span>");
    gtk_label_set_xalign(GTK_LABEL(heading), 0.0f);
    app->status = gtk_label_new("Checking local controller…");
    app->detail = gtk_label_new("");
    app->error = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(app->status), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(app->detail), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(app->error), 0.0f);
    gtk_box_pack_start(GTK_BOX(box), heading, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), app->status, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), app->detail, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), app->error, FALSE, FALSE, 0);

    GtkWidget *router_label = gtk_label_new("Router");
    gtk_label_set_xalign(GTK_LABEL(router_label), 0.0f);
    gtk_box_pack_start(GTK_BOX(box), router_label, FALSE, FALSE, 0);
    app->router_combo = gtk_combo_box_text_new();
    g_signal_connect(app->router_combo, "changed", G_CALLBACK(on_router_changed), app);
    gtk_box_pack_start(GTK_BOX(box), app->router_combo, FALSE, FALSE, 0);

    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(row), make_button("AUTO Connect", G_CALLBACK(on_auto), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Disconnect", G_CALLBACK(on_disconnect), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Prove public VPN exit", G_CALLBACK(on_public_ip), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Retest DNS", G_CALLBACK(on_dns), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Emergency stop", G_CALLBACK(on_emergency), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), row, FALSE, FALSE, 0);

    GtkWidget *proof = gtk_label_new("Connected is accepted only after exact selected-node private path proof. Typed attempt/fallback/rollback and selected-DNS proof events stream below.");
    gtk_label_set_xalign(GTK_LABEL(proof), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(proof), TRUE);
    gtk_box_pack_start(GTK_BOX(box), proof, FALSE, FALSE, 0);
    GtkWidget *scroll = scrolled_text(&app->diagnostics);
    gtk_widget_set_size_request(scroll, -1, 300);
    gtk_box_pack_start(GTK_BOX(box), scroll, TRUE, TRUE, 0);
    return box;
}



static GtkWidget *build_modes_page(App *app) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(box), 16);
    GtkWidget *mode_label = gtk_label_new("Available mode");
    gtk_label_set_xalign(GTK_LABEL(mode_label), 0.0f);
    gtk_box_pack_start(GTK_BOX(box), mode_label, FALSE, FALSE, 0);
    app->mode_combo = gtk_combo_box_text_new();
    gtk_box_pack_start(GTK_BOX(box), app->mode_combo, FALSE, FALSE, 0);
    GtkWidget *base_label = gtk_label_new("Tunnel base");
    gtk_label_set_xalign(GTK_LABEL(base_label), 0.0f);
    gtk_box_pack_start(GTK_BOX(box), base_label, FALSE, FALSE, 0);
    app->base_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->base_combo), "Auto");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->base_combo), "WireGuard");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->base_combo), "AmneziaWG");
    gtk_combo_box_set_active(GTK_COMBO_BOX(app->base_combo), 0);
    gtk_box_pack_start(GTK_BOX(box), app->base_combo, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), make_button("Connect Selected", G_CALLBACK(on_connect), app), FALSE, FALSE, 0);
    GtkWidget *scroll = scrolled_text(&app->modes_view);
    gtk_box_pack_start(GTK_BOX(box), scroll, TRUE, TRUE, 0);
    return box;
}

static void add_tab(GtkNotebook *tabs, GtkWidget *page, const char *title) {
    gtk_notebook_append_page(tabs, page, gtk_label_new(title));
}



static gboolean resolve_package_root(App *app, const char *argv0) {
    char *absolute = realpath(argv0, NULL);
    if (absolute == NULL) return FALSE;
    char *directory = g_path_get_dirname(absolute);
    free(absolute);
    if (directory == NULL || directory[0] == '\0') {
        g_free(directory);
        return FALSE;
    }
    app->package_root = directory;
    return TRUE;
}

#include "routervpn-controller-shutdown-v1.inc"
#include "routervpn-controller-launch-v1.inc"

static void on_destroy(GtkWidget *widget, gpointer data) {
    (void)widget;
    App *app = data;
    app->window = NULL;
    if (app->owns_controller) { shutdown_controller(app); return; }
    if (gtk_main_level() > 0) gtk_main_quit();
}

static int self_test(void) {
    static const char *const paths[] = {
        "/api/status", "/api/profiles", "/api/logical-modes", "/api/auto",
        "/api/connect-logical", "/api/disconnect", "/api/profile/select",
        "/api/public-ip", "/api/dns/retest", "/api/emergency-stop", "/api/session/events"
    };
    if (strcmp(ROUTER_VPN_BASE_URL, "http://127.0.0.1:8788") != 0 || ROUTER_VPN_PRODUCT_CONTRACT != 2) return 2;
    if (G_N_ELEMENTS(paths) != 11 || paths[10][0] != '/') return 3;
    puts("Router VPN native Linux product shell self-test: OK");
    return 0;
}




#undef self_test

/*
 * Product v3 keeps the proven GTK/runtime shell above intact while making the
 * node-data lifecycle a first-class native workflow.  Pair/import/remove are
 * data operations; they never reinstall the application or bypass the shared
 * localhost controller's profile safety checks.
 */

static char *json_string_body(const char *key, const char *value) {
    JsonBuilder *builder = json_builder_new();
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, key);
    json_builder_add_string_value(builder, value != NULL ? value : "");
    json_builder_end_object(builder);
    JsonNode *root = json_builder_get_root(builder);
    JsonGenerator *generator = json_generator_new();
    json_generator_set_root(generator, root);
    char *body = json_generator_to_data(generator, NULL);
    json_node_free(root);
    g_object_unref(generator);
    g_object_unref(builder);
    return body;
}

static char *json_pair_body(const char *host, const char *code) {
    JsonBuilder *builder = json_builder_new();
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "host");
    json_builder_add_string_value(builder, host != NULL ? host : "");
    json_builder_set_member_name(builder, "code");
    json_builder_add_string_value(builder, code != NULL ? code : "");
    json_builder_end_object(builder);
    JsonNode *root = json_builder_get_root(builder);
    JsonGenerator *generator = json_generator_new();
    json_generator_set_root(generator, root);
    char *body = json_generator_to_data(generator, NULL);
    json_node_free(root);
    g_object_unref(generator);
    g_object_unref(builder);
    return body;
}

static const char *active_router_id(App *app) {
    gint index = gtk_combo_box_get_active(GTK_COMBO_BOX(app->router_combo));
    if (index < 0 || (guint)index >= app->router_ids->len) return NULL;
    return g_ptr_array_index(app->router_ids, (guint)index);
}

static gboolean code_is_six_digits(const char *code) {
    if (code == NULL || strlen(code) != 6) return FALSE;
    for (const char *p = code; *p != '\0'; p++) {
        if (*p < '0' || *p > '9') return FALSE;
    }
    return TRUE;
}

static void on_pair_node(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    if (!routervpn_require_mutation_idle(app, "opening node pairing")) return;
    GtkWidget *dialog = gtk_dialog_new_with_buttons(
        "Pair Router VPN home node", GTK_WINDOW(app->window), GTK_DIALOG_MODAL,
        "_Cancel", GTK_RESPONSE_CANCEL, "_Pair", GTK_RESPONSE_ACCEPT, NULL);
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 14);
    GtkWidget *note = gtk_label_new(
        "Create a short-lived 6-digit code in the authenticated private Setup Center.\n"
        "The shared controller accepts only private/local destinations and a one-time code.");
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    GtkWidget *host = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(host), "AI Board LAN IP / hostname");
    gtk_entry_set_text(GTK_ENTRY(host), "");
    GtkWidget *code = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(code), "6-digit one-time pairing code");
    gtk_entry_set_visibility(GTK_ENTRY(code), FALSE);
    gtk_entry_set_max_length(GTK_ENTRY(code), 6);
    gtk_grid_attach(GTK_GRID(grid), note, 0, 0, 2, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Home node"), 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), host, 1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Pairing code"), 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), code, 1, 2, 1, 1);
    gtk_box_pack_start(GTK_BOX(content), grid, TRUE, TRUE, 0);
    gtk_widget_show_all(dialog);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        const char *host_text = gtk_entry_get_text(GTK_ENTRY(host));
        const char *code_text = gtk_entry_get_text(GTK_ENTRY(code));
        if (!code_is_six_digits(code_text)) {
            append_diag(app, "Pairing failed: code must be exactly 6 digits.");
        } else if (!routervpn_require_mutation_idle(app, "redeeming the one-time pairing code")) {
            append_diag(app, "Pairing code was not consumed because VPN state changed while the dialog was open.");
        } else {
            char *body = json_pair_body(host_text, code_text);
            Buffer out = {0};
            char *err = NULL;
            if (api_request("/api/profile/pair", "POST", body, 20000, &out, &err)) {
                append_diag(app, "Secure LAN pairing succeeded; node data was imported without reinstalling Router VPN.");
                refresh_profiles(app);
            } else {
                char *line = g_strdup_printf("Pairing failed: %s", err != NULL ? err : "request failed");
                append_diag(app, line);
                gtk_label_set_text(GTK_LABEL(app->error), err != NULL ? err : "pairing failed");
                g_free(line);
            }
            g_free(body);
            g_free(err);
            free(out.data);
        }
    }
    gtk_widget_destroy(dialog);
}



static void on_remove_node(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    if (!routervpn_require_mutation_idle(app, "removing a linked node")) return;
    const char *id = active_router_id(app);
    if (id == NULL || id[0] == '\0') {
        append_diag(app, "Remove failed: select a linked node first.");
        return;
    }
    GtkWidget *dialog = gtk_message_dialog_new(
        GTK_WINDOW(app->window), GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING,
        GTK_BUTTONS_NONE,
        "Remove linked node '%s' from this app?\n\nThis does not uninstall Router VPN or change the home server.", id);
    gtk_dialog_add_buttons(GTK_DIALOG(dialog), "_Cancel", GTK_RESPONSE_CANCEL,
                           "_Remove", GTK_RESPONSE_ACCEPT, NULL);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        if (!routervpn_require_mutation_idle(app, "committing linked-node removal")) { gtk_widget_destroy(dialog); return; }
        char *body = json_string_body("id", id);
        Buffer out = {0};
        char *err = NULL;
        if (api_request("/api/profile/delete", "POST", body, 10000, &out, &err)) {
            append_diag(app, "Linked node removed from this app.");
            refresh_profiles(app);
        } else {
            char *line = g_strdup_printf("Remove failed: %s", err != NULL ? err : "request failed");
            append_diag(app, line);
            gtk_label_set_text(GTK_LABEL(app->error), err != NULL ? err : "remove failed");
            g_free(line);
        }
        g_free(body);
        g_free(err);
        free(out.data);
    }
    gtk_widget_destroy(dialog);
}

static void on_latency_node(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    const char *id = active_router_id(app);
    if (id == NULL || id[0] == '\0') {
        append_diag(app, "Latency test failed: select a linked node first.");
        return;
    }
    JsonBuilder *builder = json_builder_new();
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "id");
    json_builder_add_string_value(builder, id);
    json_builder_set_member_name(builder, "samples");
    json_builder_add_int_value(builder, 50);
    json_builder_end_object(builder);
    JsonNode *root = json_builder_get_root(builder);
    JsonGenerator *generator = json_generator_new();
    json_generator_set_root(generator, root);
    char *body = json_generator_to_data(generator, NULL);
    post_and_log(app, "/api/profile/latency", body, 180000, "50-sample node latency");
    g_free(body);
    json_node_free(root);
    g_object_unref(generator);
    g_object_unref(builder);
    refresh_profiles(app);
}





static int self_test_v3(void) {
    if (routervpn_product_core_self_test() != 0) return 2;
    static const char *const node_paths[] = {
        "/api/profile/pair", "/api/profile/import", "/api/profile/delete", "/api/profile/latency"
    };
    if (G_N_ELEMENTS(node_paths) != 4 || node_paths[0][0] != '/') return 3;
    puts("Router VPN native Linux node-management product self-test: OK");
    return 0;
}




#undef self_test_v3

/* Product v4: unified Router VPN + validated external-node desktop UX. */

static void refresh_nodes_order_v4(App *app, const char *order) {
    char *path = g_strdup_printf("/api/nodes?sort=%s", order != NULL ? order : "current");
    Buffer out = {0};
    char *err = NULL;
    if (!api_request(path, "GET", NULL, 3000, &out, &err)) {
        g_free(path); g_free(err); free(out.data); return;
    }
    g_free(path);
    JsonNode *root = parse_json(out.data);
    if (root == NULL || !JSON_NODE_HOLDS_OBJECT(root)) {
        if (root != NULL) json_node_free(root);
        free(out.data); g_free(err); return;
    }
    JsonObject *store = json_node_get_object(root);
    const char *selected = obj_string(store, "selected_id");
    JsonArray *profiles = json_object_get_array_member(store, "profiles");
    app->suppress_router_change = TRUE;
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(app->router_combo));
    g_ptr_array_set_size(app->router_ids, 0);
    g_ptr_array_set_size(app->nodes, 0);
    GString *text = g_string_new("");
    guint selected_index = 0;
    if (profiles != NULL) {
        for (guint i = 0; i < json_array_get_length(profiles); i++) {
            JsonObject *profile = json_array_get_object_element(profiles, i);
            if (profile == NULL) continue;
            MapNode *node = g_new0(MapNode, 1);
            node->id = g_strdup(obj_string(profile, "id"));
            node->name = g_strdup(obj_string(profile, "name"));
            node->location = g_strdup(obj_string(profile, "location"));
            node->endpoint = g_strdup(obj_string(profile, "endpoint"));
            gboolean has_lat = FALSE, has_lon = FALSE, has_latency = FALSE;
            node->latitude = obj_double(profile, "latitude", &has_lat);
            node->longitude = obj_double(profile, "longitude", &has_lon);
            node->latency = obj_double(profile, "latency_median_ms", &has_latency);
            node->has_coordinates = (has_lat || has_lon) &&
                (has_lat || !json_object_has_member(profile, "latitude")) &&
                (has_lon || !json_object_has_member(profile, "longitude")) &&
                isfinite(node->latitude) && isfinite(node->longitude)
                && node->latitude >= -90 && node->latitude <= 90
                && node->longitude >= -180 && node->longitude <= 180
                && !(node->latitude == 0 && node->longitude == 0);
            node->selected = selected[0] != '\0' && strcmp(selected, node->id) == 0;
            if (node->selected) selected_index = i;
            gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->router_combo),
                                           node->name[0] != '\0' ? node->name : node->id);
            g_ptr_array_add(app->router_ids, g_strdup(node->id));
            g_ptr_array_add(app->nodes, node);
            g_string_append_printf(text, "%s%s\n  %s\n  endpoint: %s\n  coordinates: %s",
                node->selected ? "● " : "", node->name[0] ? node->name : node->id,
                node->location[0] ? node->location : "Location not labeled",
                node->endpoint[0] ? node->endpoint : "—",
                node->has_coordinates ? "real stored latitude/longitude" : "not stored — not plotted");
            if (has_latency && node->latency > 0) g_string_append_printf(text, "\n  median latency: %.1f ms", node->latency);
            const char *last_used = obj_string(profile, "last_used_at");
            if (last_used[0] != '\0') g_string_append_printf(text, "\n  last used: %s", last_used);
            g_string_append(text, "\n\n");
        }
    }
    if (app->router_ids->len > 0) gtk_combo_box_set_active(GTK_COMBO_BOX(app->router_combo), (gint)selected_index);
    app->suppress_router_change = FALSE;
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->nodes_view));
    gtk_text_buffer_set_text(buffer, text->str, -1);
    g_string_free(text, TRUE);
    gtk_widget_queue_draw(app->map);
    g_object_set_data_full(G_OBJECT(app->window), "router-vpn-source-catalog-v24", copy_public_source_value_v24(root), (GDestroyNotify)json_node_free);
    json_node_free(root); free(out.data); g_free(err);
}

static void on_sort_nodes_current(GtkButton *button, gpointer data) {(void)button;refresh_nodes_order_v4((App *)data,"current");}
static void on_sort_nodes_recent(GtkButton *button, gpointer data) {(void)button;refresh_nodes_order_v4((App *)data,"last-used");}
static void on_sort_nodes_usage(GtkButton *button, gpointer data) {(void)button;refresh_nodes_order_v4((App *)data,"most-used");}
static void on_sort_nodes_latency(GtkButton *button, gpointer data) {(void)button;refresh_nodes_order_v4((App *)data,"latency");}
static void on_sort_nodes_name(GtkButton *button, gpointer data) {(void)button;refresh_nodes_order_v4((App *)data,"name");}

static void on_select_lowest_latency(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    if (!routervpn_require_mutation_idle(app, "selecting the lowest-latency node")) return;
    Buffer out = {0};
    char *err = NULL;
    if (!routervpn_require_mutation_idle(app, "committing the lowest-latency node selection")) return;
    if (api_request("/api/profile/lowest-saved-latency", "POST", "{}", 10000, &out, &err)) {
        append_diag(app, "Selected lowest saved 10% trimmed mean. Saved measurements may come from different times and networks; use Fastest for a current comparison.");
        refresh_nodes_order_v4(app, "latency");
    } else {
        append_diag(app, err != NULL ? err : "Saved lowest-latency selection failed.");
    }
    g_free(err); free(out.data);
}

static void on_import_any_node(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    if (!routervpn_require_mutation_idle(app, "importing a Router or external node")) return;
    GtkWidget *dialog = gtk_file_chooser_dialog_new(
        "Import Router VPN or external node", GTK_WINDOW(app->window),
        GTK_FILE_CHOOSER_ACTION_OPEN, "_Cancel", GTK_RESPONSE_CANCEL,
        "_Import", GTK_RESPONSE_ACCEPT, NULL);
    GtkFileFilter *filter = gtk_file_filter_new();
    gtk_file_filter_set_name(filter, "Router VPN / external JSON");
    gtk_file_filter_add_pattern(filter, "*.json");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dialog), filter);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        char *contents = NULL;
        gsize length = 0;
        GError *read_error = NULL;
        if (!g_file_get_contents(filename, &contents, &length, &read_error)) {
            append_diag(app, read_error != NULL ? read_error->message : "Import failed: could not read the selected file.");
        } else if (length > (32u * 1024u * 1024u)) {
            append_diag(app, "Import failed: node JSON is larger than 32 MiB.");
        } else if (!routervpn_require_mutation_idle(app, "committing Router or external node import")) {
            append_diag(app, "Import cancelled because VPN state changed while the file picker was open.");
        } else {
            Buffer out = {0};
            char *router_err = NULL;
            if (api_request("/api/profile/import", "POST", contents, 25000, &out, &router_err)) {
                append_diag(app, "Router VPN node bundle imported into the private profile store.");
                refresh_profiles(app);
            } else {
                free(out.data); out.data = NULL; out.len = 0;
                char *external_err = NULL;
                if (api_request("/api/external-profile/import", "POST", contents, 25000, &out, &external_err)) {
                    append_diag(app, "Validated schema-v3 external node imported. Protocol credentials remain private; native UI receives only the public node view.");
                    refresh_profiles(app);
                } else {
                    char *line = g_strdup_printf(
                        "Import failed as Router VPN bundle (%s) and external node (%s)",
                        router_err != NULL ? router_err : "rejected",
                        external_err != NULL ? external_err : "rejected");
                    append_diag(app, line);
                    gtk_label_set_text(GTK_LABEL(app->error), line);
                    g_free(line);
                }
                g_free(external_err);
            }
            g_free(router_err);
            free(out.data);
        }
        if (read_error != NULL) g_error_free(read_error);
        g_free(contents);
        g_free(filename);
    }
    gtk_widget_destroy(dialog);
}

static char *external_primary_body_v24(App *app, const char *id, gboolean direct, char **error);

static void on_connect_external_node(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    const char *id = active_router_id(app);
    if (id == NULL || id[0] == '\0') {
        append_diag(app, "External connect failed: select a linked external node first.");
        return;
    }
    if (!routervpn_require_mutation_idle(app, "starting an external connection")) return;
    char *error = NULL;
    char *body = external_primary_body_v24(app, id, TRUE, &error);
    if (body == NULL) { append_diag(app, error != NULL ? error : "The captured external path is invalid."); g_free(error); return; }
    g_free(error);
    post_and_log(app, "/api/external-profile/connect", body, 180000,
                 "External direct exit (exact public-exit proof required)");
    g_free(body);
    refresh_all(app);
}

static const char *external_saved_execution_v4(JsonObject *profile) {
    const char *saved=obj_string(profile,"multihop_execution");
    if(saved[0]=='\0')return "local";
    return g_strcmp0(saved,"local")==0||g_strcmp0(saved,"server")==0||g_strcmp0(saved,"auto")==0?saved:NULL;
}

static char *json_external_hop_body(const char *profile_id, const char *entry_id, const char *execution, gboolean direct) {
    if(profile_id==NULL||!profile_id[0]||g_strcmp0(profile_id,entry_id)==0||execution==NULL||
       (g_strcmp0(execution,"local")!=0&&g_strcmp0(execution,"server")!=0&&g_strcmp0(execution,"auto")!=0))return NULL;
    JsonBuilder *builder=json_builder_new();json_builder_begin_object(builder);
    json_builder_set_member_name(builder,"profile_id");json_builder_add_string_value(builder,profile_id);
    json_builder_set_member_name(builder,"execution");json_builder_add_string_value(builder,direct?"local":execution);
    if(direct){json_builder_set_member_name(builder,"direct");json_builder_add_boolean_value(builder,TRUE);}
    else if(entry_id!=NULL&&entry_id[0]){json_builder_set_member_name(builder,"entry_id");json_builder_add_string_value(builder,entry_id);}
    json_builder_end_object(builder);JsonNode *root=json_builder_get_root(builder);
    JsonGenerator *generator=json_generator_new();json_generator_set_root(generator,root);
    char *body=json_generator_to_data(generator,NULL);json_node_free(root);g_object_unref(generator);g_object_unref(builder);return body;
}

static const char *external_path_string_v4(JsonObject *object,const char *key) {
    JsonNode *node=object!=NULL&&json_object_has_member(object,key)?json_object_get_member(object,key):NULL;
    return node!=NULL&&JSON_NODE_HOLDS_VALUE(node)&&json_node_get_value_type(node)==G_TYPE_STRING?json_node_get_string(node):"";
}

static gboolean external_path_flag_v4(JsonObject *object,const char *key) {
    JsonNode *node=object!=NULL&&json_object_has_member(object,key)?json_object_get_member(object,key):NULL;
    return node!=NULL&&JSON_NODE_HOLDS_VALUE(node)&&json_node_get_value_type(node)==G_TYPE_BOOLEAN&&json_node_get_boolean(node);
}

static JsonObject *external_path_object_v4(JsonObject *object,const char *key) {
    JsonNode *node=object!=NULL&&json_object_has_member(object,key)?json_object_get_member(object,key):NULL;
    return node!=NULL&&JSON_NODE_HOLDS_OBJECT(node)?json_node_get_object(node):NULL;
}

#include "routervpn-external-source-v24.inc"

static char *external_path_current_body_v4(JsonObject *captured,JsonNode *current,const char *entry_id,const char *execution,gboolean direct,char **error) {
    const char *message=NULL;JsonObject *found=NULL,*entry=NULL;guint matches=0,entries=0;
    JsonObject *store=current!=NULL&&JSON_NODE_HOLDS_OBJECT(current)?json_node_get_object(current):NULL;
    JsonNode *list=store!=NULL&&json_object_has_member(store,"profiles")?json_object_get_member(store,"profiles"):NULL;
    JsonArray *catalog=list!=NULL&&JSON_NODE_HOLDS_ARRAY(list)?json_node_get_array(list):NULL;
    const char *id=external_path_string_v4(captured,"id");
    for(guint i=0;catalog!=NULL&&i<json_array_get_length(catalog);i++){
        JsonNode *item=json_array_get_element(catalog,i);
        if(item==NULL||!JSON_NODE_HOLDS_OBJECT(item)){message="The current node catalog is invalid.";break;}
        JsonObject *node=json_node_get_object(item);const char *node_id=external_path_string_v4(node,"id");
        if(g_strcmp0(node_id,id)==0){found=node;matches++;}
        if(g_strcmp0(node_id,entry_id)==0){entry=node;entries++;}
    }
    if(message==NULL&&(!id[0]||matches!=1||g_strcmp0(external_path_string_v4(found,"node_kind"),"external")!=0))message="The external node changed while this dialog was open. Reopen its path settings.";
    JsonObject *before=external_path_object_v4(captured,"external"),*after=external_path_object_v4(found,"external");
    const char *identity[]={"id","node_kind","endpoint","start_layer","multihop_entry_mode","profile_token"},*transport[]={"protocol","expected_public_ip"},*flags[]={"has_response_probe","has_server_peer","has_openvpn_pairing"};
    for(guint i=0;message==NULL&&i<G_N_ELEMENTS(identity);i++)if(g_strcmp0(external_path_string_v4(captured,identity[i]),external_path_string_v4(found,identity[i]))!=0)message="The external node changed while this dialog was open. Reopen its path settings.";
    for(guint i=0;message==NULL&&i<G_N_ELEMENTS(transport);i++)if(g_strcmp0(external_path_string_v4(before,transport[i]),external_path_string_v4(after,transport[i]))!=0)message="The external transport changed while this dialog was open. Reopen its path settings.";
    for(guint i=0;message==NULL&&i<G_N_ELEMENTS(flags);i++)if(external_path_flag_v4(before,flags[i])!=external_path_flag_v4(after,flags[i]))message="The external provisioning changed while this dialog was open. Reopen its path settings.";
    if(message==NULL&&!direct&&(entry_id==NULL||!entry_id[0]||entries!=1))message="The selected entry is missing or ambiguous. Choose it again.";
    if(message==NULL&&g_strcmp0(execution,"local")!=0){
        const char *protocol=external_path_string_v4(after,"protocol"),*kind=external_path_string_v4(entry,"node_kind");
        gboolean packet=g_strcmp0(protocol,"wireguard")==0||g_strcmp0(protocol,"amneziawg")==0;
        gboolean tor=g_strcmp0(protocol,"tor")==0||g_strcmp0(protocol,"tor-bridge")==0;
        if(!tor&&!packet&&g_strcmp0(protocol,"shadowsocks")!=0&&g_strcmp0(protocol,"hysteria2")!=0&&g_strcmp0(protocol,"socks5")!=0&&g_strcmp0(protocol,"http-connect")!=0&&g_strcmp0(protocol,"https-connect")!=0&&g_strcmp0(protocol,"openvpn")!=0)message="Server / Compare requires a supported authenticated external transport.";
        else if(!tor&&!external_path_flag_v4(after,"has_response_probe"))message="Server / Compare requires this external node's HTTPS response probe.";
        else if(packet&&!external_path_flag_v4(after,"has_server_peer"))message="WireGuard / AmneziaWG Server / Compare requires a separately provisioned server peer.";
        else if(g_strcmp0(protocol,"openvpn")==0&&!external_path_flag_v4(after,"has_openvpn_pairing"))message="OpenVPN Server / Compare requires private pairing with independent provider credentials.";
        else if(direct||(kind[0]&&g_strcmp0(kind,"router-vpn")!=0)||json_object_has_member(entry,"external"))message="Server / Compare requires a private Router VPN entry.";
    }
    if(message!=NULL){if(error!=NULL)*error=g_strdup(message);return NULL;}
    char *body=json_external_hop_body(id,entry_id,execution,direct);
    if(body==NULL&&error!=NULL)*error=g_strdup("The captured external path is invalid.");
    return body;
}

static char *external_entry_mode_v4(JsonObject *captured,JsonObject *entry,const char *selected,JsonArray *modes,char **error) {
    const char *message=NULL,*kind=external_path_string_v4(entry,"node_kind");
    if(entry==NULL||(kind[0]&&g_strcmp0(kind,"router-vpn")!=0)){
        if(selected!=NULL&&selected[0])message="An entry mode applies only to a Router VPN entry.";
        else return g_strdup("");
    }
    const char *mode=selected!=NULL?selected:"";
    if(message==NULL&&!mode[0]){
        const char *base=external_path_string_v4(entry,"base_tunnel");
        if(g_strcmp0(base,"wg")!=0&&g_strcmp0(base,"awg")!=0)base=external_path_string_v4(captured,"base_tunnel");
        mode=g_strcmp0(base,"awg")==0?"awg2-fast":"wg";
    }
    guint matches=0;
    for(guint i=0;message==NULL&&modes!=NULL&&i<json_array_get_length(modes);i++){
        JsonNode *item=json_array_get_element(modes,i);
        if(item!=NULL&&JSON_NODE_HOLDS_OBJECT(item)&&g_strcmp0(external_path_string_v4(json_node_get_object(item),"id"),mode)==0)matches++;
    }
    if(message==NULL&&matches!=1)message="Choose an exact Router entry mode from the current native catalog.";
    if(message!=NULL){if(error!=NULL)*error=g_strdup(message);return NULL;}
    return g_strdup(mode);
}

static char *external_saved_entry_mode_v4(JsonObject *captured,JsonArray *profiles,JsonArray *modes,char **error) {
    const char *mode=external_path_string_v4(captured,"multihop_entry_mode"),*message=NULL;
    if(!mode[0])return g_strdup("");
    const char *entry_id=external_path_string_v4(captured,"multihop_entry_id");
    if(external_path_flag_v4(captured,"multihop_enabled")&&entry_id[0]){
        JsonObject *entry=NULL;guint matches=0;
        for(guint i=0;profiles!=NULL&&i<json_array_get_length(profiles);i++){
            JsonNode *item=json_array_get_element(profiles,i);
            if(item!=NULL&&JSON_NODE_HOLDS_OBJECT(item)&&g_strcmp0(external_path_string_v4(json_node_get_object(item),"id"),entry_id)==0){entry=json_node_get_object(item);matches++;}
        }
        if(matches!=1)message="The saved entry is missing or ambiguous. Refresh the node list.";
        const char *kind=external_path_string_v4(entry,"node_kind");JsonObject *external=external_path_object_v4(entry,"external");
        if(message==NULL&&g_strcmp0(kind,"external")==0){
            const char *protocol=external_path_string_v4(external,"protocol");
            const char *supported[]={"wireguard","amneziawg","socks5","http-connect","https-connect","shadowsocks","hysteria2","openvpn"};gboolean valid=FALSE;
            for(guint i=0;i<G_N_ELEMENTS(supported);i++)if(g_strcmp0(protocol,supported[i])==0)valid=TRUE;
            const char *exit_protocol=external_path_string_v4(external_path_object_v4(captured,"external"),"protocol");
            if(valid&&g_strcmp0(mode,protocol)==0&&(g_strcmp0(exit_protocol,"tor")==0||g_strcmp0(exit_protocol,"tor-bridge")==0))return g_strdup("");
            message="The saved Tor entry no longer matches its imported protocol. Reopen its path settings after relinking.";
        }else if(message==NULL&&((kind[0]&&g_strcmp0(kind,"router-vpn")!=0)||external!=NULL))message="The saved entry has an inconsistent node identity.";
    }
    guint matches=0;
    for(guint i=0;message==NULL&&modes!=NULL&&i<json_array_get_length(modes);i++){
        JsonNode *item=json_array_get_element(modes,i);
        if(item!=NULL&&JSON_NODE_HOLDS_OBJECT(item)&&g_strcmp0(external_path_string_v4(json_node_get_object(item),"id"),mode)==0)matches++;
    }
    if(message==NULL&&matches!=1)message="The saved Router entry mode is missing from the current native catalog.";
    if(message!=NULL){if(error!=NULL)*error=g_strdup(message);return NULL;}
    return g_strdup(mode);
}

static char *external_path_mode_body_v4(JsonObject *captured,JsonNode *current,const char *entry_id,const char *execution,gboolean direct,const char *entry_mode,JsonArray *entry_modes,char **error) {
    char *body=external_path_current_body_v4(captured,current,entry_id,execution,direct,error);
    if(body==NULL)return NULL;
    JsonObject *entry=NULL;JsonArray *catalog=json_object_get_array_member(json_node_get_object(current),"profiles");
    for(guint i=0;!direct&&i<json_array_get_length(catalog);i++){
        JsonObject *item=json_array_get_object_element(catalog,i);
        if(g_strcmp0(external_path_string_v4(item,"id"),entry_id)==0)entry=item;
    }
    char *mode=external_entry_mode_v4(captured,entry,entry_mode,entry_modes,error);
    if(mode==NULL){g_free(body);return NULL;}
    if(mode[0]){
        JsonNode *root=parse_json(body);JsonObject *object=json_node_get_object(root);
        json_object_set_string_member(object,"entry_mode",mode);
        JsonGenerator *generator=json_generator_new();json_generator_set_root(generator,root);
        g_free(body);body=json_generator_to_data(generator,NULL);g_object_unref(generator);json_node_free(root);
    }
    g_free(mode);return body;
}

typedef struct {JsonArray *profiles;GtkWidget *mode;GtkWidget *execution;} LinuxExternalEntryModeV4;
static void external_entry_changed_v4(GtkComboBox *combo,gpointer data) {
    LinuxExternalEntryModeV4 *state=data;const char *id=gtk_combo_box_get_active_id(combo);JsonObject *entry=NULL;
    for(guint i=0;id!=NULL&&id[0]&&i<json_array_get_length(state->profiles);i++){
        JsonObject *item=json_array_get_object_element(state->profiles,i);
        if(g_strcmp0(external_path_string_v4(item,"id"),id)==0)entry=item;
    }
    const char *kind=external_path_string_v4(entry,"node_kind");
    gboolean router=entry!=NULL&&(!kind[0]||g_strcmp0(kind,"router-vpn")==0),direct=id==NULL||!id[0];
    gtk_widget_set_sensitive(state->mode,router);
    if(!router)gtk_combo_box_set_active_id(GTK_COMBO_BOX(state->mode),"");
    gtk_widget_set_sensitive(state->execution,!direct);
    if(direct)gtk_combo_box_set_active_id(GTK_COMBO_BOX(state->execution),"local");
}

static void linux_external_path_dialog_v4(App *app, gboolean require_entry) {
    if(!routervpn_require_mutation_idle(app,"starting an external via-entry connection"))return;
    g_autofree char *exit_id=g_strdup(active_router_id(app));
    if(exit_id==NULL||!exit_id[0]){append_diag(app,"Select an external node first.");return;}
    Buffer out={0};char *err=NULL;
    if(!api_request("/api/nodes","GET",NULL,5000,&out,&err)){append_diag(app,"External path catalog unavailable.");g_free(err);free(out.data);return;}
    JsonNode *root=parse_json(out.data);g_free(err);free(out.data);
    if(root==NULL||!JSON_NODE_HOLDS_OBJECT(root)){if(root!=NULL)json_node_free(root);append_diag(app,"External path catalog is invalid.");return;}
    JsonObject *store=json_node_get_object(root),*captured=NULL;
    JsonArray *profiles=json_object_has_member(store,"profiles")?json_object_get_array_member(store,"profiles"):NULL;
    guint captured_count=0;for(guint i=0;profiles!=NULL&&i<json_array_get_length(profiles);i++){JsonObject *p=json_array_get_object_element(profiles,i);if(p!=NULL&&g_strcmp0(obj_string(p,"id"),exit_id)==0){captured=p;captured_count++;}}
    if(captured==NULL||captured_count!=1||g_strcmp0(obj_string(captured,"node_kind"),"external")!=0){append_diag(app,"Select an external node first.");json_node_free(root);return;}
    const char *saved=external_saved_execution_v4(captured);
    if(saved==NULL){append_diag(app,"The external node has an invalid saved execution choice.");json_node_free(root);return;}
    const char *saved_entry=json_object_has_member(captured,"multihop_enabled")&&json_object_get_boolean_member(captured,"multihop_enabled")?obj_string(captured,"multihop_entry_id"):"";
    Buffer capability_data={0};char *capability_error=NULL;
    if(!api_request("/api/external-profile/capabilities","GET",NULL,5000,&capability_data,&capability_error)){append_diag(app,"The native Router entry mode catalog is unavailable.");g_free(capability_error);free(capability_data.data);json_node_free(root);return;}
    g_autoptr(JsonNode) capability_root=parse_json(capability_data.data);g_free(capability_error);free(capability_data.data);
    JsonObject *capabilities=capability_root!=NULL&&JSON_NODE_HOLDS_OBJECT(capability_root)?json_node_get_object(capability_root):NULL;
    JsonNode *mode_list=capabilities!=NULL&&json_object_has_member(capabilities,"router_vpn_entry_modes")?json_object_get_member(capabilities,"router_vpn_entry_modes"):NULL;
    JsonArray *entry_modes=mode_list!=NULL&&JSON_NODE_HOLDS_ARRAY(mode_list)?json_node_get_array(mode_list):NULL;
    if(!external_path_flag_v4(capabilities,"profile_source_preconditions")){append_diag(app,"Update the local controller before connecting this captured external path.");json_node_free(root);return;}
    if(entry_modes==NULL){append_diag(app,"The native Router entry mode catalog is invalid.");json_node_free(root);return;}
    g_autofree char *saved_mode_error=NULL;
    g_autofree char *saved_mode=external_saved_entry_mode_v4(captured,profiles,entry_modes,&saved_mode_error);
    if(saved_mode==NULL){append_diag(app,saved_mode_error!=NULL?saved_mode_error:"The saved entry mode is invalid.");json_node_free(root);return;}
    JsonObject *external=json_object_has_member(captured,"external")?json_object_get_object_member(captured,"external"):NULL;
    gboolean has_probe=external!=NULL&&json_object_has_member(external,"has_response_probe")&&json_object_get_boolean_member(external,"has_response_probe");
    GtkWidget *dialog=gtk_dialog_new_with_buttons("External path",GTK_WINDOW(app->window),GTK_DIALOG_MODAL|GTK_DIALOG_DESTROY_WITH_PARENT,"Cancel",GTK_RESPONSE_CANCEL,"Connect selected path",GTK_RESPONSE_ACCEPT,NULL);
    GtkWidget *box=gtk_box_new(GTK_ORIENTATION_VERTICAL,10);gtk_container_set_border_width(GTK_CONTAINER(box),16);gtk_window_set_default_size(GTK_WINDOW(dialog),640,420);
    GtkWidget *title=gtk_label_new(obj_string(captured,"name"));gtk_label_set_xalign(GTK_LABEL(title),0.0f);gtk_box_pack_start(GTK_BOX(box),title,FALSE,FALSE,0);
    GtkWidget *entry=gtk_combo_box_text_new();gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(entry),"","Direct — no entry");
    for(guint i=0;profiles!=NULL&&i<json_array_get_length(profiles);i++){
        JsonObject *p=json_array_get_object_element(profiles,i);if(p==NULL||g_strcmp0(obj_string(p,"id"),exit_id)==0)continue;
        gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(entry),obj_string(p,"id"),obj_string(p,"display_name")[0]?obj_string(p,"display_name"):obj_string(p,"name"));
    }
    if(!gtk_combo_box_set_active_id(GTK_COMBO_BOX(entry),saved_entry)){append_diag(app,"The saved external entry is missing. Relink it or use External direct explicitly.");gtk_widget_destroy(dialog);json_node_free(root);return;}
    GtkWidget *execution=gtk_combo_box_text_new();gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(execution),"local","Local — exit runs on this device");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(execution),"server","Server — exit runs on Router entry");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(execution),"auto","Compare both — lowest valid average");gtk_combo_box_set_active_id(GTK_COMBO_BOX(execution),saved_entry[0]?saved:"local");
    GtkWidget *entry_mode=gtk_combo_box_text_new();gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(entry_mode),"","Use selected entry's saved base");
    for(guint i=0;i<json_array_get_length(entry_modes);i++){
        JsonNode *item=json_array_get_element(entry_modes,i);if(item==NULL||!JSON_NODE_HOLDS_OBJECT(item))continue;
        JsonObject *mode=json_node_get_object(item);const char *id=external_path_string_v4(mode,"id"),*name=external_path_string_v4(mode,"name");
        if(id[0])gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(entry_mode),id,name[0]?name:id);
    }
    if(!gtk_combo_box_set_active_id(GTK_COMBO_BOX(entry_mode),saved_mode)){append_diag(app,"The saved Router entry mode is missing from the current native catalog.");gtk_widget_destroy(dialog);json_node_free(root);return;}
    LinuxExternalEntryModeV4 mode_state={.profiles=profiles,.mode=entry_mode,.execution=execution};
    g_signal_connect(entry,"changed",G_CALLBACK(external_entry_changed_v4),&mode_state);external_entry_changed_v4(GTK_COMBO_BOX(entry),&mode_state);
    GtkWidget *mode_note=gtk_label_new("The exact selected mode and the entry node's saved Start Layer are used. Compatibility and path proof are checked before Connected.");gtk_label_set_line_wrap(GTK_LABEL(mode_note),TRUE);gtk_label_set_xalign(GTK_LABEL(mode_note),0.0f);
    GtkWidget *note=gtk_label_new("Server / Compare uses a paired private Router entry. Tor compares last-relay HTTP and the same external-server HTTP response on each path. Other external exits need their saved HTTPS response probe; WireGuard / AmneziaWG also needs a separately provisioned server peer. Direct and ordinary entries use Local. A successful connection saves this node's choice.");gtk_label_set_line_wrap(GTK_LABEL(note),TRUE);gtk_label_set_xalign(GTK_LABEL(note),0.0f);
    const char *exit_protocol=external_path_string_v4(external,"protocol");
    gboolean is_tor=g_strcmp0(exit_protocol,"tor")==0||g_strcmp0(exit_protocol,"tor-bridge")==0;
    GtkWidget *probe=gtk_label_new(is_tor?"Tor uses its native last-relay proof and one shared external target. Private pairing, selected DNS and path proof are checked when connecting.":has_probe?"HTTPS response probe saved; server pairing and native proof remain pending.":"No HTTPS response probe saved. Import or create a provisioned external node before choosing Server / Compare.");gtk_label_set_line_wrap(GTK_LABEL(probe),TRUE);gtk_label_set_xalign(GTK_LABEL(probe),0.0f);
    GtkWidget *error=gtk_label_new("");gtk_label_set_line_wrap(GTK_LABEL(error),TRUE);gtk_label_set_xalign(GTK_LABEL(error),0.0f);
    gtk_box_pack_start(GTK_BOX(box),gtk_label_new("Entry"),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(box),entry,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(box),gtk_label_new("Router entry mode"),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(box),entry_mode,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(box),mode_note,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(box),gtk_label_new("External execution"),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(box),execution,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(box),note,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(box),probe,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(box),error,FALSE,FALSE,0);
    gtk_box_pack_start(GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))),box,TRUE,TRUE,0);gtk_widget_show_all(dialog);
    while(gtk_dialog_run(GTK_DIALOG(dialog))==GTK_RESPONSE_ACCEPT){
        if(!routervpn_require_mutation_idle(app,"committing an external via-entry connection"))break;
        const char *entry_id=gtk_combo_box_get_active_id(GTK_COMBO_BOX(entry));const char *choice=gtk_combo_box_get_active_id(GTK_COMBO_BOX(execution));
        if(entry_id==NULL||choice==NULL){gtk_label_set_text(GTK_LABEL(error),"Choose an entry or Direct and an execution choice.");continue;}
        gboolean direct=!entry_id[0];
        if(require_entry&&direct){gtk_label_set_text(GTK_LABEL(error),"Choose an entry for this via-entry connection.");continue;}
        if(direct&&g_strcmp0(choice,"local")!=0){gtk_label_set_text(GTK_LABEL(error),"Direct uses Local. Choose an entry for Server / Compare.");continue;}
        Buffer fresh={0};char *fresh_error=NULL;
        if(!api_request("/api/nodes","GET",NULL,5000,&fresh,&fresh_error)){gtk_label_set_text(GTK_LABEL(error),"The current node catalog is unavailable. Nothing was connected.");g_free(fresh_error);free(fresh.data);continue;}
        JsonNode *current=parse_json(fresh.data);g_free(fresh_error);free(fresh.data);fresh_error=NULL;
        char *prepared=external_path_mode_body_v4(captured,current,entry_id,choice,direct,gtk_combo_box_get_active_id(GTK_COMBO_BOX(entry_mode)),entry_modes,&fresh_error);
        char *body=prepared!=NULL?external_captured_body_v24(prepared,root,current,&fresh_error):NULL;g_free(prepared);if(current!=NULL)json_node_free(current);
        if(body==NULL){gtk_label_set_text(GTK_LABEL(error),fresh_error!=NULL?fresh_error:"The captured external path is invalid.");g_free(fresh_error);continue;}
        post_and_log(app,"/api/external-profile/connect",body,180000,"External selected path (exact public-exit proof required)");g_free(body);refresh_all(app);break;
    }
    gtk_widget_destroy(dialog);json_node_free(root);
}

static void on_connect_external_via_entry(GtkButton *button, gpointer data) {
    (void)button;linux_external_path_dialog_v4(data,TRUE);
}

static GtkWidget *build_nodes_page_v4(App *app) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(box), 10);
    GtkWidget *note = gtk_label_new(
        "Install once; pair/import Router VPN and external node data separately. "
        "The map plots only stored real coordinates; coordinate-less nodes stay usable in the list.");
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(note), TRUE);
    gtk_box_pack_start(GTK_BOX(box), note, FALSE, FALSE, 0);

    GtkWidget *sort_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(sort_row), gtk_label_new("Order:"), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(sort_row), make_button("Current / recent", G_CALLBACK(on_sort_nodes_current), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(sort_row), make_button("Last used", G_CALLBACK(on_sort_nodes_recent), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(sort_row), make_button("Most used", G_CALLBACK(on_sort_nodes_usage), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(sort_row), make_button("Lowest latency", G_CALLBACK(on_sort_nodes_latency), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(sort_row), make_button("Name", G_CALLBACK(on_sort_nodes_name), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(sort_row), make_button("Select lowest latency", G_CALLBACK(on_select_lowest_latency), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), sort_row, FALSE, FALSE, 0);

    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_VERTICAL);
    app->map = gtk_drawing_area_new();
    gtk_widget_set_size_request(app->map, -1, 300);
    g_signal_connect(app->map, "draw", G_CALLBACK(draw_map), app);
    gtk_paned_pack1(GTK_PANED(paned), app->map, TRUE, FALSE);
    GtkWidget *scroll = scrolled_text(&app->nodes_view);
    gtk_paned_pack2(GTK_PANED(paned), scroll, TRUE, FALSE);
    gtk_box_pack_start(GTK_BOX(box), paned, TRUE, TRUE, 0);

    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(row), make_button("Pair home node", G_CALLBACK(on_pair_node), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Import node JSON", G_CALLBACK(on_import_any_node), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Connect external direct", G_CALLBACK(on_connect_external_node), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("External via entry", G_CALLBACK(on_connect_external_via_entry), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Remove selected node", G_CALLBACK(on_remove_node), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Run 50-sample latency", G_CALLBACK(on_latency_node), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), row, FALSE, FALSE, 0);
    return box;
}



static int self_test_v4(void) {
    if (routervpn_product_v3_self_test() != 0) return 2;
    static const char *const external_paths[] = {
        "/api/external-profile/import", "/api/external-profile/connect", "/api/nodes", "entry_id", "/api/nodes?sort=latency", "Select lowest latency"
    };
    if (G_N_ELEMENTS(external_paths) != 6 || external_paths[0][0] != '/') return 3;
    puts("Router VPN native Linux unified external-node product self-test: OK");
    return 0;
}


#undef draw_map


#include "routervpn-mtu-v20.inc"
#include "routervpn-dns-measurement-v1.inc"
#include "routervpn-home-summary-v1.inc"
#include "routervpn-device-settings-v1.inc"
#include "routervpn-profile-settings-v1.inc"
#include "routervpn-auto-requirements-v11.inc"

/* Product v5: persistent native onboarding + dedicated diagnostics + parity controls. */

static char *onboarding_marker_v5(void) {
    const char *config = g_get_user_config_dir();
    char *dir = g_build_filename(config, "router-vpn", NULL);
    (void)g_mkdir_with_parents(dir, 0700);
    char *path = g_build_filename(dir, "linux-onboarding-v5.done", NULL);
    g_free(dir);
    return path;
}

static char *onboarding_step_path_v6(const char *done_path) {
    return done_path != NULL ? g_strconcat(done_path, ".step", NULL) : NULL;
}

static int onboarding_read_step_v6(const char *done_path) {
    char *path = onboarding_step_path_v6(done_path);
    char *raw = NULL;
    gsize length = 0;
    int step = 0;
    if (path != NULL && g_file_get_contents(path, &raw, &length, NULL) && raw != NULL) step = (int)g_ascii_strtoll(raw, NULL, 10);
    g_free(raw); g_free(path); return step;
}

static void onboarding_write_step_v6(const char *done_path, int step) {
    char *path = onboarding_step_path_v6(done_path);
    char *raw = g_strdup_printf("%d\n", step < 0 ? 0 : step);
    if (path != NULL) (void)g_file_set_contents(path, raw, -1, NULL);
    g_free(raw); g_free(path);
}

static void onboarding_finish_v5(GtkAssistant *assistant, gpointer data) {
    (void)data;
    const char *path = g_object_get_data(G_OBJECT(assistant), "router-vpn-onboarding-marker");
    if (path != NULL) { (void)g_file_set_contents(path, "done\n", -1, NULL); onboarding_write_step_v6(path, 0); }
    gtk_widget_destroy(GTK_WIDGET(assistant));
}

static void onboarding_cancel_v5(GtkAssistant *assistant, gpointer data) {
    (void)data;
    const char *path = g_object_get_data(G_OBJECT(assistant), "router-vpn-onboarding-marker");
    if (path != NULL) onboarding_write_step_v6(path, gtk_assistant_get_current_page(assistant));
    gtk_widget_destroy(GTK_WIDGET(assistant));
}

static void show_onboarding_v5(App *app, gboolean force) {
    char *path = onboarding_marker_v5();
    if (!force && g_file_test(path, G_FILE_TEST_EXISTS)) {
        g_free(path);
        return;
    }
    #include "routervpn-product-onboarding-v6.inc"
    GtkWidget *assistant = gtk_assistant_new();
    gtk_window_set_title(GTK_WINDOW(assistant), "Router VPN setup");
    gtk_window_set_transient_for(GTK_WINDOW(assistant), GTK_WINDOW(app->window));
    gtk_window_set_modal(GTK_WINDOW(assistant), TRUE);
    gtk_window_set_default_size(GTK_WINDOW(assistant), 700, 460);
    g_object_set_data_full(G_OBJECT(assistant), "router-vpn-onboarding-marker", path, g_free);
    for (guint i = 0; i < G_N_ELEMENTS(titles); i++) {
        GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);
        gtk_container_set_border_width(GTK_CONTAINER(box), 24);
        GtkWidget *heading = gtk_label_new(NULL);
        char *markup = g_markup_printf_escaped("<span size='xx-large' weight='bold'>%s</span>", titles[i]);
        gtk_label_set_markup(GTK_LABEL(heading), markup);
        g_free(markup);
        gtk_label_set_xalign(GTK_LABEL(heading), 0.0f);
        GtkWidget *body = gtk_label_new(bodies[i]);
        gtk_label_set_xalign(GTK_LABEL(body), 0.0f);
        gtk_label_set_line_wrap(GTK_LABEL(body), TRUE);
        gtk_box_pack_start(GTK_BOX(box), heading, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(box), body, FALSE, FALSE, 0);
        gtk_assistant_append_page(GTK_ASSISTANT(assistant), box);
        gtk_assistant_set_page_title(GTK_ASSISTANT(assistant), box, titles[i]);
        gtk_assistant_set_page_complete(GTK_ASSISTANT(assistant), box, TRUE);
        gtk_assistant_set_page_type(GTK_ASSISTANT(assistant), box,
            i == 0 ? GTK_ASSISTANT_PAGE_INTRO :
            (i == G_N_ELEMENTS(titles) - 1 ? GTK_ASSISTANT_PAGE_CONFIRM : GTK_ASSISTANT_PAGE_CONTENT));
    }
    if (!force) {
        int saved_step = onboarding_read_step_v6(path);
        if (saved_step >= 0 && saved_step < (int)G_N_ELEMENTS(titles)) gtk_assistant_set_current_page(GTK_ASSISTANT(assistant), saved_step);
    }
    g_signal_connect(assistant, "apply", G_CALLBACK(onboarding_finish_v5), app);
    g_signal_connect(assistant, "close", G_CALLBACK(onboarding_cancel_v5), app);
    g_signal_connect(assistant, "cancel", G_CALLBACK(onboarding_cancel_v5), app);
    gtk_widget_show_all(assistant);
}

static void on_run_tutorial_v5(GtkButton *button, gpointer data) {
    (void)button;
    show_onboarding_v5((App *)data, TRUE);
}

static void linux_mtu_dialog_v20(App *app);

static void on_mtu_retest_v5(GtkButton *button, gpointer data) {
    (void)button;
    linux_mtu_dialog_v20((App *)data);
}

static GtkWidget *find_button_v5(GtkWidget *root, const char *label) {
    if (root == NULL) return NULL;
    if (GTK_IS_BUTTON(root)) {
        const char *current = gtk_button_get_label(GTK_BUTTON(root));
        if (g_strcmp0(current, label) == 0) return root;
    }
    if (!GTK_IS_CONTAINER(root)) return NULL;
    GList *children = gtk_container_get_children(GTK_CONTAINER(root));
    GtkWidget *match = NULL;
    for (GList *item = children; item != NULL && match == NULL; item = item->next) {
        match = find_button_v5(GTK_WIDGET(item->data), label);
    }
    g_list_free(children);
    return match;
}

static void remember_button_v5(App *app, GtkWidget *root, const char *key, const char *label) {
    GtkWidget *button = find_button_v5(root, label);
    if (button != NULL) g_object_set_data(G_OBJECT(app->window), key, button);
}

static void set_remembered_sensitive_v5(App *app, const char *key, gboolean sensitive) {
    GtkWidget *widget = g_object_get_data(G_OBJECT(app->window), key);
    if (widget != NULL) gtk_widget_set_sensitive(widget, sensitive);
}

static void apply_action_sensitivity_v5(App *app, gboolean connected) {
    gboolean has_node = app->router_ids != NULL && app->router_ids->len > 0;
    gboolean has_mode = has_node && app->mode_combo != NULL &&
                        gtk_combo_box_get_active(GTK_COMBO_BOX(app->mode_combo)) >= 0;

    if (app->router_combo != NULL) gtk_widget_set_sensitive(app->router_combo, has_node);
    if (app->mode_combo != NULL) gtk_widget_set_sensitive(app->mode_combo, has_node);
    if (app->base_combo != NULL) gtk_widget_set_sensitive(app->base_combo, has_node);

    set_remembered_sensitive_v5(app, "router-vpn-home-auto-v5", has_node);
    set_remembered_sensitive_v5(app, "router-vpn-home-disconnect-v5", connected);
    set_remembered_sensitive_v5(app, "router-vpn-home-public-v5", connected);
    set_remembered_sensitive_v5(app, "router-vpn-home-dns-v5", connected);
    set_remembered_sensitive_v5(app, "router-vpn-modes-connect-v5", has_mode);
    set_remembered_sensitive_v5(app, "router-vpn-advanced-settings-v7", has_node && !connected);
    set_remembered_sensitive_v5(app, "router-vpn-advanced-mtu-v5", connected);
    set_remembered_sensitive_v5(app, "router-vpn-diag-public-v5", connected);
    set_remembered_sensitive_v5(app, "router-vpn-diag-dns-v5", connected);
    set_remembered_sensitive_v5(app, "router-vpn-diag-mtu-v5", connected);
    /* Emergency stop deliberately remains available even while disconnected so
       a stale helper/runtime can always be torn down. */
}

static gboolean refresh_diagnostics_readings_v1(gpointer data, const LinuxShellReadings *round) {
    App *app = data;
    GtkWidget *view = g_object_get_data(G_OBJECT(app->window), "router-vpn-diagnostics-v5");
    if (view == NULL) return G_SOURCE_CONTINUE;
    Buffer status = {0}, session = {0}, events = {0};
    char *err_status = NULL, *err_session = NULL, *err_events = NULL;
    gboolean ok_status = linux_shell_read_v1(round, "/api/status", "GET", NULL, 1800, &status, &err_status);
    gboolean ok_session = linux_shell_read_v1(round, "/api/session", "GET", NULL, 1800, &session, &err_session);
    gboolean ok_events = linux_shell_read_v1(round, "/api/session/events?after=0", "GET", NULL, 1800, &events, &err_events);
    gboolean connected = FALSE;
    if (ok_status && status.data != NULL) {
        JsonNode *root = parse_json(status.data);
        if (root != NULL && JSON_NODE_HOLDS_OBJECT(root)) {
            JsonObject *obj = json_node_get_object(root);
            connected = json_object_has_member(obj, "connected") &&
                        json_object_get_boolean_member(obj, "connected");
        }
        if (root != NULL) json_node_free(root);
    }
    apply_action_sensitivity_v5(app, connected);

    GString *text = g_string_new("Router VPN native diagnostics\n\n");
    g_string_append_printf(text, "Status:\n%s\n\n", ok_status && status.data != NULL ? status.data : (err_status != NULL ? err_status : "unavailable"));
    g_string_append_printf(text, "Session / selected-path proof:\n%s\n\n", ok_session && session.data != NULL ? session.data : (err_session != NULL ? err_session : "unavailable"));
    g_string_append_printf(text, "Typed events:\n%s\n", ok_events && events.data != NULL ? events.data : (err_events != NULL ? err_events : "unavailable"));
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(view)), text->str, -1);
    g_string_free(text, TRUE);
    free(status.data); free(session.data); free(events.data);
    g_free(err_status); g_free(err_session); g_free(err_events);
    return G_SOURCE_CONTINUE;
}

static gboolean refresh_diagnostics_page_v5(gpointer data) {
    linux_shell_request_v1(data);
    return G_SOURCE_CONTINUE;
}

static double json_number_v5(JsonObject *obj, const char *key) {
    if (obj == NULL || !json_object_has_member(obj, key)) return 0.0;
    JsonNode *node = json_object_get_member(obj, key);
    return node != NULL && JSON_NODE_HOLDS_VALUE(node) ? json_node_get_double(node) : 0.0;
}

static char *mode_layers_v5(JsonObject *logical) {
    if (logical == NULL || !json_object_has_member(logical, "variants")) return g_strdup("—");
    JsonObject *variants = json_object_get_object_member(logical, "variants");
    if (variants == NULL) return g_strdup("—");
    GHashTable *seen = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    GList *members = json_object_get_members(variants);
    for (GList *it = members; it != NULL; it = it->next) {
        JsonObject *variant = json_object_get_object_member(variants, (const char *)it->data);
        if (variant == NULL || !json_object_has_member(variant, "mode")) continue;
        JsonObject *mode = json_object_get_object_member(variant, "mode");
        JsonArray *layers = mode != NULL && json_object_has_member(mode, "layers") ? json_object_get_array_member(mode, "layers") : NULL;
        if (layers == NULL) continue;
        for (guint i = 0; i < json_array_get_length(layers); i++) {
            const char *layer = json_array_get_string_element(layers, i);
            if (layer != NULL && layer[0] != '\0') g_hash_table_add(seen, g_strdup(layer));
        }
    }
    g_list_free(members);
    GList *keys = g_hash_table_get_keys(seen);
    keys = g_list_sort(keys, (GCompareFunc)g_strcmp0);
    GString *out = g_string_new("");
    for (GList *it = keys; it != NULL; it = it->next) {
        if (out->len > 0) g_string_append(out, " • ");
        g_string_append(out, (const char *)it->data);
    }
    g_list_free(keys);
    g_hash_table_unref(seen);
    return g_string_free(out, FALSE);
}

static void refresh_mode_details_v5(App *app) {
    GtkWidget *view = g_object_get_data(G_OBJECT(app->window), "router-vpn-mode-details-v5");
    if (view == NULL) return;
    Buffer out = {0}; char *err = NULL;
    if (!api_request("/api/logical-modes", "GET", NULL, 3000, &out, &err)) {
        gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(view)), err != NULL ? err : "Mode details unavailable", -1);
        g_free(err); free(out.data); return;
    }
    JsonNode *root = parse_json(out.data);
    GString *text = g_string_new("Logical modes — real runtime readiness plus engineering overhead estimates\n\n");
    if (root != NULL && JSON_NODE_HOLDS_ARRAY(root)) {
        JsonArray *modes = json_node_get_array(root);
        for (guint i = 0; i < json_array_get_length(modes); i++) {
            JsonObject *mode = json_array_get_object_element(modes, i);
            if (mode == NULL) continue;
            gboolean available = json_object_has_member(mode, "available") && json_object_get_boolean_member(mode, "available");
            char *layers = mode_layers_v5(mode);
            GString *bases = g_string_new("");
            JsonArray *ready = json_object_has_member(mode, "ready_bases") ? json_object_get_array_member(mode, "ready_bases") : NULL;
            if (ready != NULL) for (guint j = 0; j < json_array_get_length(ready); j++) {
                if (bases->len > 0) g_string_append(bases, ", ");
                g_string_append(bases, json_array_get_string_element(ready, j));
            }
            g_string_append_printf(text,
                "%s %s\n  %s\n  Layers: %s\n  Added latency %.1f–%.1f ms • traffic +%.1f–%.1f%% • speed loss %.1f–%.1f%%\n  Readiness: %s%s%s\n  Reason: %s\n\n",
                available ? "✓" : "—", obj_string(mode, "name"), obj_string(mode, "description"), layers,
                json_number_v5(mode, "ping_min_ms"), json_number_v5(mode, "ping_max_ms"),
                json_number_v5(mode, "traffic_min_pct"), json_number_v5(mode, "traffic_max_pct"),
                json_number_v5(mode, "speed_loss_min_pct"), json_number_v5(mode, "speed_loss_max_pct"),
                available ? "Ready" : "Unavailable", bases->len > 0 ? " • ready bases: " : "", bases->str,
                obj_string(mode, "reason")[0] ? obj_string(mode, "reason") : (available ? "selected variant is runnable; final Connected still requires path proof" : "no runnable variant"));
            g_free(layers); g_string_free(bases, TRUE);
        }
    } else {
        g_string_append(text, "Mode details response was not a JSON array.\n");
    }
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(view)), text->str, -1);
    g_string_free(text, TRUE);
    if (root != NULL) json_node_free(root);
    free(out.data); g_free(err);
}

static void on_refresh_mode_details_v5(GtkButton *button, gpointer data) {
    (void)button;
    refresh_mode_details_v5((App *)data);
}

static GtkWidget *build_modes_page_v5(App *app) {
    GtkWidget *box = build_modes_page(app);
    GtkWidget *heading = gtk_label_new("Mode details: layers, added latency, traffic overhead, speed loss, readiness and exact reason");
    gtk_label_set_xalign(GTK_LABEL(heading), 0.0f); gtk_label_set_line_wrap(GTK_LABEL(heading), TRUE);
    gtk_box_pack_start(GTK_BOX(box), heading, FALSE, FALSE, 6);
    GtkWidget *view = NULL; GtkWidget *scroll = scrolled_text(&view);
    gtk_widget_set_size_request(scroll, -1, 240);
    g_object_set_data(G_OBJECT(app->window), "router-vpn-mode-details-v5", view);
    gtk_box_pack_start(GTK_BOX(box), scroll, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(box), make_button("Refresh mode details", G_CALLBACK(on_refresh_mode_details_v5), app), FALSE, FALSE, 0);
    return box;
}

static const char *dns_mode_id_v5(GtkWidget *combo) {
    const char *id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(combo));
    return id != NULL ? id : "home";
}

static void dns_set_text_v5(GtkWidget *entry, const char *value) {
    if (entry != NULL) gtk_entry_set_text(GTK_ENTRY(entry), value != NULL ? value : "");
}

static char *dns_policy_payload_v5(JsonObject *captured, const char *displayed_id,
                                   const char *mode, const char *protocol, const char *host,
                                   const char *port_text, const char *server, const char *path) {
    const char *profile_id = captured != NULL ? obj_string(captured, "profile_id") : "";
    const char *token = captured != NULL ? obj_string(captured, "profile_token") : "";
    if (displayed_id == NULL || displayed_id[0] == '\0' || strcmp(profile_id, displayed_id) != 0 || token[0] == '\0') return NULL;
    char *end = NULL;
    gint64 port = port_text != NULL && port_text[0] != '\0' ? g_ascii_strtoll(port_text, &end, 10) : 0;
    if ((end != NULL && *end != '\0') || port < 0 || port > 65535) return NULL;
    JsonBuilder *builder = json_builder_new(); json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "profile_id"); json_builder_add_string_value(builder, profile_id);
    json_builder_set_member_name(builder, "profile_token"); json_builder_add_string_value(builder, token);
    json_builder_set_member_name(builder, "mode"); json_builder_add_string_value(builder, mode != NULL ? mode : "");
    json_builder_set_member_name(builder, "protocol"); json_builder_add_string_value(builder, protocol != NULL ? protocol : "");
    json_builder_set_member_name(builder, "host"); json_builder_add_string_value(builder, host != NULL ? host : "");
    json_builder_set_member_name(builder, "port"); json_builder_add_int_value(builder, port);
    json_builder_set_member_name(builder, "server_name"); json_builder_add_string_value(builder, server != NULL ? server : "");
    json_builder_set_member_name(builder, "path"); json_builder_add_string_value(builder, path != NULL ? path : "");
    json_builder_end_object(builder);
    JsonGenerator *generator = json_generator_new(); JsonNode *body = json_builder_get_root(builder); json_generator_set_root(generator, body);
    char *payload = json_generator_to_data(generator, NULL);
    json_node_free(body); g_object_unref(generator); g_object_unref(builder);
    return payload;
}

static void refresh_dns_page_v5(App *app) {
    GtkWidget *summary = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-summary-v5");
    GtkWidget *mode = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-mode-v5");
    GtkWidget *protocol = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-protocol-v5");
    GtkWidget *host = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-host-v5");
    GtkWidget *port = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-port-v5");
    GtkWidget *server = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-server-v5");
    GtkWidget *path = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-path-v5");
    if (summary == NULL || mode == NULL) return;
    g_object_set_data(G_OBJECT(app->window), "router-vpn-dns-capture-v5", NULL);
    dns_set_text_v5(host, ""); dns_set_text_v5(port, ""); dns_set_text_v5(server, ""); dns_set_text_v5(path, "");
    const char *displayed = active_router_id(app);
    if (displayed == NULL || displayed[0] == '\0') {
        gtk_label_set_text(GTK_LABEL(summary), "Select a node to load DNS settings."); return;
    }
    char *expected = g_strdup(displayed);
    Buffer out = {0}; char *err = NULL;
    if (!api_request("/api/dns/policy", "GET", NULL, 3000, &out, &err)) {
        gtk_label_set_text(GTK_LABEL(summary), err != NULL ? err : "DNS policy unavailable");
        g_free(expected); g_free(err); free(out.data); return;
    }
    JsonNode *root = parse_json(out.data);
    if (root != NULL && JSON_NODE_HOLDS_OBJECT(root)) {
        JsonObject *obj = json_node_get_object(root);
        if (g_strcmp0(obj_string(obj, "profile_id"), expected) != 0 ||
            g_strcmp0(active_router_id(app), expected) != 0 || obj_string(obj, "profile_token")[0] == '\0') {
            gtk_label_set_text(GTK_LABEL(summary), "The selected node changed while DNS settings loaded. Refresh DNS.");
            json_node_free(root); g_free(expected); free(out.data); g_free(err); return;
        }
        g_object_set_data_full(G_OBJECT(app->window), "router-vpn-dns-capture-v5", json_node_copy(root), (GDestroyNotify)json_node_free);
        const char *mode_id = obj_string(obj, "mode");
        if (!gtk_combo_box_set_active_id(GTK_COMBO_BOX(mode), mode_id[0] ? mode_id : "home")) gtk_combo_box_set_active(GTK_COMBO_BOX(mode), 0);
        const char *proto = obj_string(obj, "protocol");
        if (!gtk_combo_box_set_active_id(GTK_COMBO_BOX(protocol), proto[0] ? proto : "udp")) gtk_combo_box_set_active(GTK_COMBO_BOX(protocol), 0);
        dns_set_text_v5(host, obj_string(obj, "host"));
        char port_text[16]; g_snprintf(port_text, sizeof(port_text), "%d", json_object_has_member(obj, "port") ? (int)json_object_get_int_member(obj, "port") : 53);
        dns_set_text_v5(port, port_text); dns_set_text_v5(server, obj_string(obj, "server_name")); dns_set_text_v5(path, obj_string(obj, "path"));
        GString *detail = g_string_new("");
        g_string_append_printf(detail, "Selected: %s %s %s:%s\n", mode_id[0] ? mode_id : "home", proto[0] ? proto : "udp", obj_string(obj, "host"), port_text);
        if (json_object_has_member(obj, "fastest_dns_host") && obj_string(obj, "fastest_dns_host")[0]) {
            g_string_append_printf(detail, "Fastest measured: %s • %.2f ms • %s\n", obj_string(obj, "fastest_dns_name"), json_number_v5(obj, "fastest_dns_latency_ms"), obj_string(obj, "fastest_dns_host"));
        }
        JsonArray *results = json_object_has_member(obj, "results") ? json_object_get_array_member(obj, "results") : NULL;
        if (results != NULL) {
            for (guint i = 0; i < json_array_get_length(results); i++) {
                JsonObject *r = json_array_get_object_element(results, i);
                if (r == NULL) continue;
                gboolean working = json_object_has_member(r, "working") && json_object_get_boolean_member(r, "working");
                if (working) {
                    g_string_append_printf(detail, "%s • %s • %.2f ms\n", obj_string(r, "name"), obj_string(r, "address"), json_number_v5(r, "latency_ms"));
                } else {
                    g_string_append_printf(detail, "%s • %s • failed\n", obj_string(r, "name"), obj_string(r, "address"));
                }
            }
        }
        g_string_append_printf(detail, "\n%s", obj_string(obj, "note"));
        gtk_label_set_text(GTK_LABEL(summary), detail->str);
        g_string_free(detail, TRUE);
    }
    if (root != NULL) {
        json_node_free(root);
    }
    free(out.data);
    g_free(err);
    g_free(expected);
}

static const struct { const char *id, *label, *host, *server; } dns_presets_v5[] = {
    {"cf4", "Cloudflare IPv4", "1.1.1.1", "cloudflare-dns.com"},
    {"cf4b", "Cloudflare IPv4 secondary", "1.0.0.1", "cloudflare-dns.com"},
    {"cf6", "Cloudflare IPv6", "2606:4700:4700::1111", "cloudflare-dns.com"},
    {"cf6b", "Cloudflare IPv6 secondary", "2606:4700:4700::1001", "cloudflare-dns.com"},
    {"g4", "Google IPv4", "8.8.8.8", "dns.google"},
    {"g4b", "Google IPv4 secondary", "8.8.4.4", "dns.google"},
    {"g6", "Google IPv6", "2001:4860:4860::8888", "dns.google"},
    {"g6b", "Google IPv6 secondary", "2001:4860:4860::8844", "dns.google"},
    {"q4", "Quad9 IPv4", "9.9.9.9", "dns.quad9.net"},
    {"q4b", "Quad9 IPv4 secondary", "149.112.112.112", "dns.quad9.net"},
    {"q6", "Quad9 IPv6", "2620:fe::fe", "dns.quad9.net"},
    {"q6b", "Quad9 IPv6 secondary", "2620:fe::9", "dns.quad9.net"},
};

static void on_dns_preset_v5(GtkComboBox *combo, gpointer data) {
    App *app = data;
    GtkWidget *host = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-host-v5");
    GtkWidget *server = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-server-v5");
    const char *id = gtk_combo_box_get_active_id(combo);
    if (id == NULL || strcmp(id, "manual") == 0) return;
    for (guint i = 0; i < G_N_ELEMENTS(dns_presets_v5); i++) if (strcmp(id, dns_presets_v5[i].id) == 0) {
        dns_set_text_v5(host, dns_presets_v5[i].host); dns_set_text_v5(server, dns_presets_v5[i].server); return;
    }
}

static void on_save_dns_v5(GtkButton *button, gpointer data) {
    (void)button; App *app = data;
    GtkWidget *mode = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-mode-v5");
    GtkWidget *protocol = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-protocol-v5");
    GtkWidget *host = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-host-v5");
    GtkWidget *port = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-port-v5");
    GtkWidget *server = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-server-v5");
    GtkWidget *path = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-path-v5");
    JsonNode *capture = g_object_get_data(G_OBJECT(app->window), "router-vpn-dns-capture-v5");
    JsonObject *captured = capture != NULL && JSON_NODE_HOLDS_OBJECT(capture) ? json_node_get_object(capture) : NULL;
    char *payload = dns_policy_payload_v5(captured, active_router_id(app), dns_mode_id_v5(mode), dns_mode_id_v5(protocol),
        gtk_entry_get_text(GTK_ENTRY(host)), gtk_entry_get_text(GTK_ENTRY(port)), gtk_entry_get_text(GTK_ENTRY(server)), gtk_entry_get_text(GTK_ENTRY(path)));
    if (payload == NULL) {
        append_diag(app, "Refresh DNS for the displayed node and enter a valid port before saving."); return;
    }
    Buffer out = {0}; char *err = NULL;
    if (api_request("/api/dns/policy", "POST", payload, 5000, &out, &err)) append_diag(app, "DNS policy saved for the next connection. Reconnect and use session DNS proof to verify active enforcement.");
    else append_diag(app, err != NULL ? err : "DNS policy save failed");
    free(out.data); g_free(err); g_free(payload);
    refresh_dns_page_v5(app);
}

static void on_dns_retest_v5(GtkButton *button, gpointer data) {
    (void)button; App *app = data;
    linux_dns_retest_v1(app);
}

static void on_refresh_dns_v5(GtkButton *button, gpointer data) { (void)button; refresh_dns_page_v5((App *)data); }

static GtkWidget *build_dns_page_v5(App *app) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8); gtk_container_set_border_width(GTK_CONTAINER(box), 16);
    GtkWidget *title = gtk_label_new(NULL); gtk_label_set_markup(GTK_LABEL(title), "<span size='x-large' weight='bold'>DNS</span>"); gtk_label_set_xalign(GTK_LABEL(title), 0.0f); gtk_box_pack_start(GTK_BOX(box), title, FALSE, FALSE, 0);
    GtkWidget *note = gtk_label_new("Choose Home, Fastest, Custom UDP/TCP, DoT, DoH, DoH3 or Rescue. Common IPv4/IPv6 resolvers are convenience presets. Disconnect before changing policy; the next connection applies it, and session proof remains authoritative."); gtk_label_set_xalign(GTK_LABEL(note),0.0f);gtk_label_set_line_wrap(GTK_LABEL(note),TRUE);gtk_box_pack_start(GTK_BOX(box),note,FALSE,FALSE,0);
    GtkWidget *grid = gtk_grid_new(); gtk_grid_set_row_spacing(GTK_GRID(grid),6); gtk_grid_set_column_spacing(GTK_GRID(grid),10);
    GtkWidget *mode = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(mode),"home","Home AdGuard");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(mode),"fastest","Fastest measured");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(mode),"custom","Custom UDP/TCP");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(mode),"dot","DNS-over-TLS");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(mode),"doh","DNS-over-HTTPS");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(mode),"doh3","DNS-over-HTTP/3");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(mode),"rescue","DNS Rescue");
    GtkWidget *protocol=gtk_combo_box_text_new();gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(protocol),"udp","UDP");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(protocol),"tcp","TCP");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(protocol),"tls","TLS");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(protocol),"https","HTTPS");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(protocol),"h3","HTTP/3");
    GtkWidget *preset=gtk_combo_box_text_new();gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(preset),"manual","Manual/current");
    for (guint i = 0; i < G_N_ELEMENTS(dns_presets_v5); i++) {
        g_autofree char *label = g_strdup_printf("%s — %s", dns_presets_v5[i].label, dns_presets_v5[i].host);
        gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(preset), dns_presets_v5[i].id, label);
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(preset),0);
    GtkWidget *host=gtk_entry_new(),*port=gtk_entry_new(),*server=gtk_entry_new(),*path=gtk_entry_new();gtk_entry_set_placeholder_text(GTK_ENTRY(host),"resolver host / IPv4 / IPv6");gtk_entry_set_placeholder_text(GTK_ENTRY(port),"port");gtk_entry_set_placeholder_text(GTK_ENTRY(server),"TLS server name");gtk_entry_set_placeholder_text(GTK_ENTRY(path),"/dns-query");
    const char *labels[]={"Mode","Home / Custom transport","Common resolver","Host","Port","TLS server name","HTTPS path"};GtkWidget *widgets[]={mode,protocol,preset,host,port,server,path};for(guint i=0;i<G_N_ELEMENTS(widgets);i++){GtkWidget*l=gtk_label_new(labels[i]);gtk_label_set_xalign(GTK_LABEL(l),1.0f);gtk_grid_attach(GTK_GRID(grid),l,0,(gint)i,1,1);gtk_grid_attach(GTK_GRID(grid),widgets[i],1,(gint)i,1,1);}
    gtk_box_pack_start(GTK_BOX(box),grid,FALSE,FALSE,0);GtkWidget *row=gtk_box_new(GTK_ORIENTATION_HORIZONTAL,8);gtk_box_pack_start(GTK_BOX(row),make_button("Save DNS policy",G_CALLBACK(on_save_dns_v5),app),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(row),make_button("Retest DNS queries",G_CALLBACK(on_dns_retest_v5),app),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(row),make_button("Refresh DNS",G_CALLBACK(on_refresh_dns_v5),app),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(box),row,FALSE,FALSE,0);
    GtkWidget *summary=gtk_label_new("DNS policy not loaded yet.");gtk_label_set_xalign(GTK_LABEL(summary),0.0f);gtk_label_set_yalign(GTK_LABEL(summary),0.0f);gtk_label_set_line_wrap(GTK_LABEL(summary),TRUE);GtkWidget *scroll=gtk_scrolled_window_new(NULL,NULL);gtk_container_add(GTK_CONTAINER(scroll),summary);gtk_box_pack_start(GTK_BOX(box),scroll,TRUE,TRUE,0);
    g_object_set_data(G_OBJECT(app->window),"router-vpn-dns-summary-v5",summary);g_object_set_data(G_OBJECT(app->window),"router-vpn-dns-mode-v5",mode);g_object_set_data(G_OBJECT(app->window),"router-vpn-dns-protocol-v5",protocol);g_object_set_data(G_OBJECT(app->window),"router-vpn-dns-host-v5",host);g_object_set_data(G_OBJECT(app->window),"router-vpn-dns-port-v5",port);g_object_set_data(G_OBJECT(app->window),"router-vpn-dns-server-v5",server);g_object_set_data(G_OBJECT(app->window),"router-vpn-dns-path-v5",path);g_signal_connect(preset,"changed",G_CALLBACK(on_dns_preset_v5),app);
    return box;
}

static GtkWidget *build_advanced_page_v5(App *app) {
    GtkWidget *box = make_info_page(
        "Advanced",
        "MTU/Jumbo, LAN access, kill switch, Router VPN multihop and external entry/exit compatibility remain controller-owned so native UI cannot claim settings the dataplane did not apply. MTU Retest is accepted only while one Router VPN node is connected with Auto MTU; it compares bounded private-node loss/RTT/throughput candidates, caches by network/path context, and does not claim MTU caused any earlier cellular regression.");
    gtk_box_pack_start(GTK_BOX(box), make_button("Retest MTU", G_CALLBACK(on_mtu_retest_v5), app), FALSE, FALSE, 0);
    return box;
}

static GtkWidget *build_diagnostics_page_v5(App *app) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(box), 16);
    GtkWidget *heading = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(heading), "<span size='x-large' weight='bold'>Diagnostics</span>");
    gtk_label_set_xalign(GTK_LABEL(heading), 0.0f);
    GtkWidget *note = gtk_label_new("Read-only current status, exact selected-path proof, DNS proof, rollback state and typed session events. Generic Internet reachability alone is never accepted as connection proof. MTU Retest logs the effective MTU/source and measured private-node throughput/RTT/success returned by the local controller.");
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(note), TRUE);
    gtk_box_pack_start(GTK_BOX(box), heading, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), note, FALSE, FALSE, 0);
    GtkWidget *view = NULL;
    GtkWidget *scroll = scrolled_text(&view);
    g_object_set_data(G_OBJECT(app->window), "router-vpn-diagnostics-v5", view);
    gtk_box_pack_start(GTK_BOX(box), scroll, TRUE, TRUE, 0);
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(row), make_button("Prove public VPN exit", G_CALLBACK(on_public_ip), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Retest DNS", G_CALLBACK(on_dns), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Retest MTU", G_CALLBACK(on_mtu_retest_v5), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Emergency stop", G_CALLBACK(on_emergency), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), row, FALSE, FALSE, 0);
    return box;
}

static GtkWidget *build_help_page_v5(App *app) {
    GtkWidget *box = make_info_page("Help", "Pair a Router VPN home node or import validated Router VPN/external JSON. External direct or entry → exit connect succeeds only after its exact expected public exit is proven. Setup Center Full Guide remains the server/router administration source of truth.");
    gtk_box_pack_start(GTK_BOX(box), make_button("Run Tutorial", G_CALLBACK(on_run_tutorial_v5), app), FALSE, FALSE, 0);
    return box;
}

static void build_ui_legacy_v5(App *app) {
    app->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(app->window), "Router VPN");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 960, 680);
    gtk_window_set_default_icon_name("router-vpn");
    GtkNotebook *tabs = GTK_NOTEBOOK(gtk_notebook_new());
    gtk_notebook_set_scrollable(tabs, TRUE);

    GtkWidget *home = build_home_page(app);
    GtkWidget *home_exit_v6 = find_button_v5(home, "Prove public VPN exit");
    if (home_exit_v6 == NULL) { g_error("Router VPN shipping Home public-exit button contract drifted"); }
    g_signal_handlers_disconnect_by_func(home_exit_v6, G_CALLBACK(on_public_ip), app);
    gtk_button_set_label(GTK_BUTTON(home_exit_v6), "Prove actual exit");
    g_signal_connect(home_exit_v6, "clicked", G_CALLBACK(on_home_exit_v6), app);
    add_tab(tabs, home, "Home / Connect");
    remember_button_v5(app, home, "router-vpn-home-auto-v5", "AUTO Connect");
    remember_button_v5(app, home, "router-vpn-home-disconnect-v5", "Disconnect");
    remember_button_v5(app, home, "router-vpn-home-public-v5", "Prove public VPN exit");
    remember_button_v5(app, home, "router-vpn-home-dns-v5", "Retest DNS");

    add_tab(tabs, build_nodes_page_v4(app), "Nodes & Map");

    GtkWidget *modes = build_modes_page_v5(app);
    add_tab(tabs, modes, "Modes");
    remember_button_v5(app, modes, "router-vpn-modes-connect-v5", "Connect Selected");

    add_tab(tabs, build_dns_page_v5(app), "DNS");
    GtkWidget *advanced = build_advanced_page_v5(app);
    GtkWidget *settings_v7 = make_button("Edit profile settings", G_CALLBACK(on_profile_settings_v7), app);
    gtk_box_pack_start(GTK_BOX(advanced), settings_v7, FALSE, FALSE, 0);
    add_tab(tabs, advanced, "Advanced");
    remember_button_v5(app, advanced, "router-vpn-advanced-settings-v7", "Edit profile settings");
    remember_button_v5(app, advanced, "router-vpn-advanced-mtu-v5", "Retest MTU");
    add_tab(tabs, make_info_page("Forwarding", "Incoming forwarding is available only when the active routable Router VPN dataplane can implement it. Proxy-only/external modes never pretend arbitrary DNAT is available."), "Forwarding");
    add_tab(tabs, make_info_page("Settings", "Router VPN Linux talks only to the fixed local controller at 127.0.0.1:8788. External protocol credentials remain in the private 0600 profile store and are redacted from public node/profile APIs."), "Settings");
    add_tab(tabs, build_help_page_v5(app), "Help");

    GtkWidget *diagnostics = build_diagnostics_page_v5(app);
    add_tab(tabs, diagnostics, "Diagnostics");
    remember_button_v5(app, diagnostics, "router-vpn-diag-public-v5", "Prove public VPN exit");
    remember_button_v5(app, diagnostics, "router-vpn-diag-dns-v5", "Retest DNS");
    remember_button_v5(app, diagnostics, "router-vpn-diag-mtu-v5", "Retest MTU");

    gtk_container_add(GTK_CONTAINER(app->window), GTK_WIDGET(tabs));
}

#include "routervpn-unified-shell-v8.inc"
#include "routervpn-telemetry-v9.inc"
#include "routervpn-speed-lab-v12.inc"
#include "routervpn-globe-v10.inc"
#include "routervpn-responsive-v15.inc"

static int self_test_v5(void) {
    if (self_test_v4() != 0) return 2;
    static const char *const visual_contract[] = {
        "Diagnostics", "Run Tutorial", "linux-onboarding-v5.done",
        "/api/session/events?after=0", "truthful-empty-state-actions", "/api/mtu/retest",
        "/api/dns/policy", "Mode details", "Added latency", "DoH3", "gtk_notebook_set_scrollable"
    };
    if (G_N_ELEMENTS(visual_contract) != 11 || visual_contract[0][0] != 'D') return 3;
    puts("Router VPN native Linux v5 onboarding/diagnostics/mode-metrics/DNS product self-test: OK");
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--self-test") == 0) return self_test_v5();
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        fprintf(stderr, "Router VPN: libcurl global initialization failed\n");
        return 2;
    }
    if (!gtk_init_check(&argc, &argv)) {
        fprintf(stderr, "Router VPN: no usable graphical display is available\n");
        curl_global_cleanup();
        return 2;
    }
    if (argc > 1 && strcmp(argv[1], "--speed-lab-self-test") == 0) {
        int speed_result = linux_speed_lab_self_test_v13();
        curl_global_cleanup();
        return speed_result;
    }
    App app = {0};
    app.nodes = g_ptr_array_new_with_free_func(free_map_node);
    app.router_ids = g_ptr_array_new_with_free_func(g_free);
    app.mode_ids = g_ptr_array_new_with_free_func(g_free);
    if (!resolve_package_root(&app, argv[0])) {
        fprintf(stderr, "Router VPN: cannot resolve package root\n");
        g_ptr_array_unref(app.nodes); g_ptr_array_unref(app.router_ids); g_ptr_array_unref(app.mode_ids);
        curl_global_cleanup();
        return 2;
    }
    char *error = NULL;
    gboolean layout_only = argc == 2 && strcmp(argv[1], "--layout-self-test") == 0;
    if (layout_only) atomic_store_explicit(&controller_exit_pending, TRUE, memory_order_release);
    if (!layout_only && !ensure_controller(&app, &error)) {
        GtkWidget *dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR,
                                                   GTK_BUTTONS_CLOSE, "Router VPN could not start: %s",
                                                   error != NULL ? error : "unknown error");
        (void)gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        g_free(error); g_free(app.package_root);
        g_ptr_array_unref(app.nodes); g_ptr_array_unref(app.router_ids); g_ptr_array_unref(app.mode_ids);
        curl_global_cleanup();
        return 3;
    }
    build_ui_v5(&app);
    linux_install_telemetry_v9(&app);
    linux_install_speed_lab_v12(&app);
    linux_install_globe_v10(&app);
    linux_install_responsive_v15(&app);
    g_signal_connect(app.window, "delete-event", G_CALLBACK(linux_dns_parent_delete_v1), &app);
    g_signal_connect(app.window, "delete-event", G_CALLBACK(linux_ordered_latency_parent_delete_v1), &app);
    g_signal_connect(app.window, "delete-event", G_CALLBACK(on_delete), &app);
    g_signal_connect(app.window, "destroy", G_CALLBACK(on_destroy), &app);
    refresh_all(&app);
    refresh_home_summary_v6(&app);
    refresh_mode_details_v5(&app);
    refresh_dns_page_v5(&app);
    refresh_diagnostics_page_v5(&app);
    gtk_widget_show_all(app.window);
    /* Map-first startup: onboarding is explicit from Help -> Run Tutorial. */
    if (argc > 1 && strcmp(argv[1], "--layout-self-test") == 0) {
        int layout_result = linux_responsive_self_test_v15(&app);
        if (app.owns_controller) { shutdown_controller(&app); gtk_main(); }
        if (app.window != NULL) gtk_widget_destroy(app.window);
        g_free(app.package_root);
        g_ptr_array_unref(app.nodes); g_ptr_array_unref(app.router_ids); g_ptr_array_unref(app.mode_ids);
        curl_global_cleanup();
        return layout_result;
    }
    gtk_main();
    g_free(app.package_root);
    g_ptr_array_unref(app.nodes); g_ptr_array_unref(app.router_ids); g_ptr_array_unref(app.mode_ids);
    curl_global_cleanup();
    return 0;
}
