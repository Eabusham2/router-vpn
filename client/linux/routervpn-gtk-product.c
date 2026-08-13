#define _GNU_SOURCE
#include <curl/curl.h>
#include <gtk/gtk.h>
#include <json-glib/json-glib.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

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
    gboolean suppress_router_change;
    char *package_root;
} App;

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

static gboolean api_request(const char *path, const char *method, const char *body,
                            long timeout_ms, Buffer *out, char **error_out) {
    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        if (error_out != NULL) *error_out = g_strdup("libcurl initialization failed");
        return FALSE;
    }
    char *url = g_strdup_printf("%s%s", ROUTER_VPN_BASE_URL, path);
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept: application/json");
    if (body != NULL) headers = curl_slist_append(headers, "Content-Type: application/json");
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

static gboolean api_ready(void) {
    Buffer out = {0};
    gboolean ok = api_request("/api/status", "GET", NULL, 900, &out, NULL);
    free(out.data);
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

static void refresh_status(App *app) {
    Buffer out = {0};
    char *err = NULL;
    if (!api_request("/api/status", "GET", NULL, 2200, &out, &err)) {
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

static void refresh_session_events(App *app) {
    char *path = g_strdup_printf("/api/session/events?after=%" G_GUINT64_FORMAT, app->event_seq);
    Buffer out = {0};
    char *err = NULL;
    if (!api_request(path, "GET", NULL, 2200, &out, &err)) {
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
            node->has_coordinates = has_lat && has_lon && isfinite(node->latitude) && isfinite(node->longitude)
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
    App *app = data;
    refresh_status(app);
    refresh_session_events(app);
    return G_SOURCE_CONTINUE;
}

static void post_and_log(App *app, const char *path, const char *body, long timeout_ms, const char *label) {
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
    (void)button;
    post_and_log((App *)data, "/api/auto", "{}", 150000, "AUTO");
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

static void on_dns(GtkButton *button, gpointer data) {
    (void)button;
    post_and_log((App *)data, "/api/dns/retest", "{}", 90000, "DNS retest");
}

static void on_connect(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
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

static GtkWidget *build_nodes_page(App *app) {
    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_VERTICAL);
    app->map = gtk_drawing_area_new();
    gtk_widget_set_size_request(app->map, -1, 300);
    g_signal_connect(app->map, "draw", G_CALLBACK(draw_map), app);
    gtk_paned_pack1(GTK_PANED(paned), app->map, TRUE, FALSE);
    GtkWidget *scroll = scrolled_text(&app->nodes_view);
    gtk_paned_pack2(GTK_PANED(paned), scroll, TRUE, FALSE);
    return paned;
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

static void build_ui(App *app) {
    app->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(app->window), "Router VPN");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 1080, 720);
    GtkWidget *tabs_widget = gtk_notebook_new();
    GtkNotebook *tabs = GTK_NOTEBOOK(tabs_widget);
    add_tab(tabs, build_home_page(app), "Home / Connect");
    add_tab(tabs, build_nodes_page(app), "Nodes & Map");
    add_tab(tabs, build_modes_page(app), "Modes");
    add_tab(tabs, make_info_page("DNS", "Selected DNS is controller-owned and session-proven. Home shows typed dns-proof events; this shell does not create cosmetic DNS state."), "DNS");
    add_tab(tabs, make_info_page("Advanced", "MTU/Jumbo, LAN access, custom composition, and expert runtime settings remain controller-owned so native UI cannot claim settings the dataplane did not apply."), "Advanced");
    add_tab(tabs, make_info_page("Forwarding", "Incoming forwarding is available only when the active dataplane can implement it. Proxy-only modes never pretend DNAT is available."), "Forwarding");
    add_tab(tabs, make_info_page("Settings", "Router VPN Linux talks only to the fixed local controller at 127.0.0.1:8788 and preserves the app-owned controller lifecycle. No embedded browser is used."), "Settings");
    add_tab(tabs, make_info_page("Help", "Use Setup Center Full Guide for server/pairing setup. Home diagnostics show typed connection attempts, fallback, rollback, path proof, and DNS proof."), "Help");
    gtk_container_add(GTK_CONTAINER(app->window), tabs_widget);
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

static gboolean ensure_controller(App *app, char **error_out) {
    if (api_ready()) return TRUE;
    char *controller = g_build_filename(app->package_root, "router-vpn-client", NULL);
    char *config = g_build_filename(app->package_root, "client.json", NULL);
    if (access(controller, X_OK) != 0 || access(config, R_OK) != 0) {
        if (error_out != NULL) *error_out = g_strdup("Router VPN GTK must stay beside router-vpn-client and client.json in its package.");
        g_free(controller); g_free(config); return FALSE;
    }
    pid_t pid = fork();
    if (pid < 0) {
        if (error_out != NULL) *error_out = g_strdup("Could not fork local controller");
        g_free(controller); g_free(config); return FALSE;
    }
    if (pid == 0) {
        if (setenv("HOMEVPN_ROOT", app->package_root, 1) != 0 ||
            setenv("HOMEVPN_CLIENT_CONFIG", config, 1) != 0 ||
            setenv("HOMEVPN_NATIVE_APP", "linux-gtk-product", 1) != 0 ||
            chdir(app->package_root) != 0) _exit(126);
        execl(controller, controller, (char *)NULL);
        _exit(127);
    }
    app->controller_pid = pid;
    app->owns_controller = TRUE;
    g_free(controller); g_free(config);
    for (int i = 0; i < 60; i++) {
        if (api_ready()) return TRUE;
        int status = 0;
        if (waitpid(pid, &status, WNOHANG) == pid) break;
        g_usleep(200000);
    }
    (void)kill(pid, SIGTERM);
    if (error_out != NULL) *error_out = g_strdup("Local Router VPN controller did not become ready on 127.0.0.1:8788.");
    return FALSE;
}

static void shutdown_controller(App *app) {
    if (!app->owns_controller || app->controller_pid <= 0) return;
    Buffer out = {0};
    (void)api_request("/api/emergency-stop", "POST", "{}", 1800, &out, NULL);
    free(out.data);
    (void)kill(app->controller_pid, SIGTERM);
    for (int i = 0; i < 20; i++) {
        int status = 0;
        if (waitpid(app->controller_pid, &status, WNOHANG) == app->controller_pid) return;
        g_usleep(100000);
    }
    (void)kill(app->controller_pid, SIGKILL);
    (void)waitpid(app->controller_pid, NULL, 0);
}

static void on_destroy(GtkWidget *widget, gpointer data) {
    (void)widget;
    App *app = data;
    shutdown_controller(app);
    gtk_main_quit();
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

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--self-test") == 0) return self_test();
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        fprintf(stderr, "Router VPN: libcurl global initialization failed\n");
        return 2;
    }
    if (!gtk_init_check(&argc, &argv)) {
        fprintf(stderr, "Router VPN: no usable graphical display is available\n");
        curl_global_cleanup();
        return 2;
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
    if (!ensure_controller(&app, &error)) {
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
    build_ui(&app);
    g_signal_connect(app.window, "destroy", G_CALLBACK(on_destroy), &app);
    refresh_all(&app);
    (void)g_timeout_add_seconds(2, refresh_timer, &app);
    gtk_widget_show_all(app.window);
    gtk_main();
    g_free(app.package_root);
    g_ptr_array_unref(app.nodes); g_ptr_array_unref(app.router_ids); g_ptr_array_unref(app.mode_ids);
    curl_global_cleanup();
    return 0;
}
