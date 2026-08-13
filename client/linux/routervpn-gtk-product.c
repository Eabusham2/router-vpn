#define _GNU_SOURCE
#include <curl/curl.h>
#include <gtk/gtk.h>
#include <json-glib/json-glib.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    GtkWidget *diagnostics;
    GtkWidget *nodes_box;
    GtkWidget *modes_box;
    GtkWidget *map;
    GPtrArray *nodes;
    guint64 event_seq;
} App;

static size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t total = size * nmemb;
    Buffer *buf = userp;
    char *next = realloc(buf->data, buf->len + total + 1);
    if (!next) return 0;
    buf->data = next;
    memcpy(buf->data + buf->len, contents, total);
    buf->len += total;
    buf->data[buf->len] = '\0';
    return total;
}

static gboolean api_request(const char *path, const char *method, const char *body,
                            long timeout_ms, Buffer *out, char **error_out) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        if (error_out) *error_out = g_strdup("libcurl initialization failed");
        return FALSE;
    }
    char *url = g_strdup_printf("%s%s", ROUTER_VPN_BASE_URL, path);
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept: application/json");
    if (body) headers = curl_slist_append(headers, "Content-Type: application/json");
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
    if (method && strcmp(method, "GET") != 0) curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    if (body) curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    CURLcode code = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    gboolean ok = code == CURLE_OK && status >= 200 && status < 300;
    if (!ok && error_out) {
        if (out->data && out->data[0]) *error_out = g_strdup(g_strstrip(out->data));
        else *error_out = g_strdup(code != CURLE_OK ? curl_easy_strerror(code) : "local controller request failed");
    }
    g_free(url);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return ok;
}

static JsonNode *parse_json(const char *text) {
    if (!text) return NULL;
    JsonParser *parser = json_parser_new();
    GError *error = NULL;
    if (!json_parser_load_from_data(parser, text, -1, &error)) {
        if (error) g_error_free(error);
        g_object_unref(parser);
        return NULL;
    }
    JsonNode *node = json_node_copy(json_parser_get_root(parser));
    g_object_unref(parser);
    return node;
}

static const char *obj_string(JsonObject *obj, const char *key) {
    if (!obj || !json_object_has_member(obj, key)) return "";
    JsonNode *node = json_object_get_member(obj, key);
    if (!JSON_NODE_HOLDS_VALUE(node) || json_node_get_value_type(node) != G_TYPE_STRING) return "";
    return json_node_get_string(node);
}

static double obj_double(JsonObject *obj, const char *key, gboolean *present) {
    if (present) *present = FALSE;
    if (!obj || !json_object_has_member(obj, key)) return 0;
    JsonNode *node = json_object_get_member(obj, key);
    if (!JSON_NODE_HOLDS_VALUE(node)) return 0;
    GType type = json_node_get_value_type(node);
    if (type != G_TYPE_DOUBLE && type != G_TYPE_INT64 && type != G_TYPE_INT && type != G_TYPE_UINT64) return 0;
    if (present) *present = TRUE;
    return json_node_get_double(node);
}

static void free_map_node(gpointer data) {
    MapNode *node = data;
    if (!node) return;
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
    char *line = g_strdup_printf("[%s] %s\n", stamp, message ? message : "");
    gtk_text_buffer_insert(buffer, &end, line, -1);
    g_free(line);
    g_free(stamp);
    g_date_time_unref(now);
}

static gboolean draw_map(GtkWidget *widget, cairo_t *cr, gpointer user_data) {
    App *app = user_data;
    GtkAllocation a;
    gtk_widget_get_allocation(widget, &a);
    double w = a.width, h = a.height;

    cairo_set_source_rgb(cr, 0.055, 0.075, 0.12);
    cairo_paint(cr);
    cairo_set_source_rgb(cr, 0.20, 0.25, 0.34);
    cairo_set_line_width(cr, 1.0);
    for (int lon = -120; lon <= 120; lon += 60) {
        double x = (lon + 180.0) / 360.0 * w;
        cairo_move_to(cr, x, 0); cairo_line_to(cr, x, h);
    }
    for (int lat = -60; lat <= 60; lat += 30) {
        double y = (90.0 - lat) / 180.0 * h;
        cairo_move_to(cr, 0, y); cairo_line_to(cr, w, y);
    }
    cairo_stroke(cr);

    guint plotted = 0;
    for (guint i = 0; i < app->nodes->len; i++) {
        MapNode *node = g_ptr_array_index(app->nodes, i);
        if (!node->has_coordinates) continue;
        plotted++;
        double x = (node->longitude + 180.0) / 360.0 * w;
        double y = (90.0 - node->latitude) / 180.0 * h;
        cairo_set_source_rgb(cr, node->selected ? 0.25 : 0.20, node->selected ? 0.62 : 0.78, node->selected ? 1.0 : 0.66);
        cairo_arc(cr, x, y, node->selected ? 7 : 5, 0, 2 * G_PI);
        cairo_fill(cr);
        cairo_set_source_rgb(cr, 0.92, 0.95, 1.0);
        cairo_move_to(cr, x + 9, y - 7);
        cairo_show_text(cr, node->name);
    }
    if (plotted == 0) {
        cairo_set_source_rgb(cr, 0.75, 0.78, 0.84);
        cairo_move_to(cr, 24, h / 2.0);
        cairo_show_text(cr, "No real node coordinates - Router VPN never invents map locations.");
    }
    return FALSE;
}

static GtkWidget *make_scrolled_text(GtkWidget **view_out) {
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    GtkWidget *view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_WORD_CHAR);
    gtk_container_add(GTK_CONTAINER(scroll), view);
    if (view_out) *view_out = view;
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

static void refresh_status(App *app) {
    Buffer out = {0}; char *err = NULL;
    if (!api_request("/api/status", "GET", NULL, 2200, &out, &err)) {
        gtk_label_set_text(GTK_LABEL(app->status), "Controller unavailable");
        gtk_label_set_text(GTK_LABEL(app->detail), err ? err : "Local controller unavailable");
        g_free(err); free(out.data); return;
    }
    JsonNode *root = parse_json(out.data);
    if (root && JSON_NODE_HOLDS_OBJECT(root)) {
        JsonObject *obj = json_node_get_object(root);
        gboolean connected = json_object_has_member(obj, "connected") && json_object_get_boolean_member(obj, "connected");
        const char *phase = obj_string(obj, "phase");
        const char *runtime = obj_string(obj, "runtime_mode");
        if (!runtime[0]) runtime = obj_string(obj, "mode");
        char *state = g_strdup_printf("%s %s", connected ? "●" : "○", connected ? "Connected" : (phase[0] ? phase : "Off"));
        char *detail = g_strdup_printf("Logical: %s    Runtime: %s    Base: %s    Router: %s",
            obj_string(obj, "logical_mode"), runtime, obj_string(obj, "base"), obj_string(obj, "router_id"));
        gtk_label_set_text(GTK_LABEL(app->status), state);
        gtk_label_set_text(GTK_LABEL(app->detail), detail);
        g_free(state); g_free(detail);
    }
    if (root) json_node_free(root);
    free(out.data); g_free(err);
}

static void refresh_session_events(App *app) {
    char *path = g_strdup_printf("/api/session/events?after=%" G_GUINT64_FORMAT, app->event_seq);
    Buffer out = {0}; char *err = NULL;
    if (!api_request(path, "GET", NULL, 2200, &out, &err)) {
        g_free(path); g_free(err); free(out.data); return;
    }
    g_free(path);
    JsonNode *root = parse_json(out.data);
    if (root && JSON_NODE_HOLDS_OBJECT(root)) {
        JsonObject *obj = json_node_get_object(root);
        JsonArray *events = json_object_get_array_member(obj, "events");
        if (events) {
            for (guint i = 0; i < json_array_get_length(events); i++) {
                JsonObject *event = json_array_get_object_element(events, i);
                if (!event) continue;
                guint64 seq = (guint64)json_object_get_int_member(event, "seq");
                if (seq <= app->event_seq) continue;
                const char *type = obj_string(event, "type");
                const char *phase = obj_string(event, "phase");
                const char *runtime = obj_string(event, "runtime_mode");
                const char *base = obj_string(event, "base");
                const char *message = obj_string(event, "message");
                char *line = g_strdup_printf("Session #%" G_GUINT64_FORMAT " %s: %s%s%s%s%s%s%s",
                    seq, type, phase,
                    runtime[0] ? " | runtime=" : "", runtime,
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
    if (root) json_node_free(root);
    free(out.data); g_free(err);
}

static void refresh_profiles(App *app) {
    Buffer out = {0}; char *err = NULL;
    if (!api_request("/api/profiles", "GET", NULL, 3000, &out, &err)) {
        g_free(err); free(out.data); return;
    }
    JsonNode *root = parse_json(out.data);
    if (!root || !JSON_NODE_HOLDS_OBJECT(root)) {
        if (root) json_node_free(root); free(out.data); return;
    }
    JsonObject *store = json_node_get_object(root);
    const char *selected = obj_string(store, "selected_id");
    JsonArray *profiles = json_object_get_array_member(store, "profiles");
    g_ptr_array_set_size(app->nodes, 0);
    GString *text = g_string_new("");
    if (profiles) {
        for (guint i = 0; i < json_array_get_length(profiles); i++) {
            JsonObject *p = json_array_get_object_element(profiles, i);
            if (!p) continue;
            MapNode *node = g_new0(MapNode, 1);
            node->id = g_strdup(obj_string(p, "id"));
            node->name = g_strdup(obj_string(p, "name"));
            node->location = g_strdup(obj_string(p, "location"));
            node->endpoint = g_strdup(obj_string(p, "endpoint"));
            gboolean has_lat = FALSE, has_lon = FALSE, has_latency = FALSE;
            node->latitude = obj_double(p, "latitude", &has_lat);
            node->longitude = obj_double(p, "longitude", &has_lon);
            node->latency = obj_double(p, "latency_median_ms", &has_latency);
            node->has_coordinates = has_lat && has_lon && isfinite(node->latitude) && isfinite(node->longitude)
                && node->latitude >= -90 && node->latitude <= 90 && node->longitude >= -180 && node->longitude <= 180
                && !(node->latitude == 0 && node->longitude == 0);
            node->selected = selected[0] && strcmp(selected, node->id) == 0;
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
    GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->nodes_box));
    gtk_text_buffer_set_text(buf, text->str, -1);
    g_string_free(text, TRUE);
    gtk_widget_queue_draw(app->map);
    json_node_free(root); free(out.data); g_free(err);
}

static void refresh_modes(App *app) {
    Buffer out = {0}; char *err = NULL;
    if (!api_request("/api/logical-modes", "GET", NULL, 12000, &out, &err)) {
        g_free(err); free(out.data); return;
    }
    JsonNode *root = parse_json(out.data);
    if (root && JSON_NODE_HOLDS_ARRAY(root)) {
        JsonArray *modes = json_node_get_array(root);
        GString *text = g_string_new("");
        for (guint i = 0; i < json_array_get_length(modes); i++) {
            JsonObject *mode = json_array_get_object_element(modes, i);
            if (!mode) continue;
            gboolean available = json_object_has_member(mode, "available") && json_object_get_boolean_member(mode, "available");
            g_string_append_printf(text, "%s %s\n  %s\n\n", available ? "✓" : "—", obj_string(mode, "name"), obj_string(mode, "reason"));
        }
        GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->modes_box));
        gtk_text_buffer_set_text(buf, text->str, -1);
        g_string_free(text, TRUE);
    }
    if (root) json_node_free(root);
    free(out.data); g_free(err);
}

static gboolean refresh_timer(gpointer data) {
    App *app = data;
    refresh_status(app);
    refresh_session_events(app);
    return G_SOURCE_CONTINUE;
}

static GtkWidget *build_nodes_page(App *app) {
    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_VERTICAL);
    app->map = gtk_drawing_area_new();
    gtk_widget_set_size_request(app->map, -1, 300);
    g_signal_connect(app->map, "draw", G_CALLBACK(draw_map), app);
    gtk_paned_pack1(GTK_PANED(paned), app->map, TRUE, FALSE);
    GtkWidget *scroll = make_scrolled_text(&app->nodes_box);
    gtk_paned_pack2(GTK_PANED(paned), scroll, TRUE, FALSE);
    return paned;
}

static GtkWidget *build_home_page(App *app) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_container_set_border_width(GTK_CONTAINER(box), 20);
    GtkWidget *heading = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(heading), "<span size='xx-large' weight='bold'>Router VPN</span>");
    gtk_label_set_xalign(GTK_LABEL(heading), 0.0f);
    app->status = gtk_label_new("Checking local controller…");
    app->detail = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(app->status), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(app->detail), 0.0f);
    gtk_box_pack_start(GTK_BOX(box), heading, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), app->status, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), app->detail, FALSE, FALSE, 0);
    GtkWidget *scroll = make_scrolled_text(&app->diagnostics);
    gtk_widget_set_size_request(scroll, -1, 320);
    gtk_box_pack_start(GTK_BOX(box), scroll, TRUE, TRUE, 0);
    return box;
}

static void add_tab(GtkNotebook *tabs, GtkWidget *page, const char *title) {
    gtk_notebook_append_page(tabs, page, gtk_label_new(title));
}

static void activate(GtkApplication *application, gpointer user_data) {
    (void)user_data;
    App *app = g_new0(App, 1);
    app->nodes = g_ptr_array_new_with_free_func(free_map_node);
    app->window = gtk_application_window_new(application);
    gtk_window_set_title(GTK_WINDOW(app->window), "Router VPN");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 1080, 720);

    GtkWidget *tabs_widget = gtk_notebook_new();
    GtkNotebook *tabs = GTK_NOTEBOOK(tabs_widget);
    add_tab(tabs, build_home_page(app), "Home / Connect");
    add_tab(tabs, build_nodes_page(app), "Nodes & Map");
    GtkWidget *modes_scroll = make_scrolled_text(&app->modes_box);
    add_tab(tabs, modes_scroll, "Modes");
    add_tab(tabs, make_info_page("DNS", "Selected DNS is enforced and proven by the local Router VPN controller. Use Home diagnostics to watch typed dns-proof events."), "DNS");
    add_tab(tabs, make_info_page("Advanced", "MTU/Jumbo, LAN access, custom mode composition, and expert runtime settings remain controller-owned so the native shell cannot create cosmetic state."), "Advanced");
    add_tab(tabs, make_info_page("Forwarding", "Incoming forwarding is managed only where the active dataplane supports real forwarding. Proxy-only modes never pretend DNAT is available."), "Forwarding");
    add_tab(tabs, make_info_page("Settings", "Router VPN Linux talks only to the fixed local controller at 127.0.0.1:8788. No embedded browser or remote control endpoint is used."), "Settings");
    add_tab(tabs, make_info_page("Help", "Use Setup Center Full Guide for pairing/server setup. Typed connection attempt, fallback, rollback, selected-path, and DNS proof events appear on Home."), "Help");
    gtk_container_add(GTK_CONTAINER(app->window), tabs_widget);
    gtk_widget_show_all(app->window);

    refresh_status(app);
    refresh_session_events(app);
    refresh_profiles(app);
    refresh_modes(app);
    g_timeout_add_seconds(2, refresh_timer, app);
}

static int self_test(void) {
    if (strcmp(ROUTER_VPN_BASE_URL, "http://127.0.0.1:8788") != 0) return 2;
    if (ROUTER_VPN_PRODUCT_CONTRACT != 2) return 3;
    puts("Router VPN native Linux product shell self-test: OK");
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--self-test") == 0) return self_test();
    curl_global_init(CURL_GLOBAL_DEFAULT);
    GtkApplication *application = gtk_application_new("com.eabusham.routervpn.linux", G_APPLICATION_FLAGS_NONE);
    g_signal_connect(application, "activate", G_CALLBACK(activate), NULL);
    int status = g_application_run(G_APPLICATION(application), argc, argv);
    g_object_unref(application);
    curl_global_cleanup();
    return status;
}
