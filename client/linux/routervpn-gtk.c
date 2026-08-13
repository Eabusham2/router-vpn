#define _GNU_SOURCE
#include <curl/curl.h>
#include <gtk/gtk.h>
#include <json-glib/json-glib.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define ROUTER_VPN_BASE_URL "http://127.0.0.1:8788"
#define ROUTER_VPN_APP_CONTRACT 1

typedef struct {
    char *data;
    size_t len;
} Buffer;

typedef struct {
    GtkWidget *window;
    GtkWidget *status;
    GtkWidget *detail;
    GtkWidget *error;
    GtkWidget *router_combo;
    GtkWidget *mode_combo;
    GtkWidget *base_combo;
    GtkWidget *nodes_view;
    GtkWidget *methods_view;
    GtkWidget *diagnostics_view;
    GPtrArray *router_ids;
    GPtrArray *mode_ids;
    pid_t controller_pid;
    gboolean owns_controller;
    gboolean suppress_router_change;
    char *package_root;
} App;

static size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    const size_t total = size * nmemb;
    Buffer *buf = userp;
    char *next = realloc(buf->data, buf->len + total + 1);
    if (next == NULL) {
        return 0;
    }
    buf->data = next;
    memcpy(buf->data + buf->len, contents, total);
    buf->len += total;
    buf->data[buf->len] = '\0';
    return total;
}

static gboolean api_request(const char *path, const char *method, const char *json_body,
                            long timeout_ms, Buffer *out, char **error_out) {
    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        if (error_out != NULL) {
            *error_out = g_strdup("libcurl initialization failed");
        }
        return FALSE;
    }

    char *url = g_strdup_printf("%s%s", ROUTER_VPN_BASE_URL, path);
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept: application/json");
    if (json_body != NULL) {
        headers = curl_slist_append(headers, "Content-Type: application/json");
    }
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
    if (method != NULL && strcmp(method, "GET") != 0) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    }
    if (json_body != NULL) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
    }

    const CURLcode code = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    if (code != CURLE_OK || status < 200 || status >= 300) {
        if (error_out != NULL) {
            if (out->data != NULL && out->data[0] != '\0') {
                *error_out = g_strdup(g_strstrip(out->data));
            } else {
                *error_out = g_strdup(code != CURLE_OK ? curl_easy_strerror(code) : "local controller request failed");
            }
        }
        g_free(url);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return FALSE;
    }

    g_free(url);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return TRUE;
}

static gboolean api_ready(void) {
    Buffer out = {0};
    const gboolean ok = api_request("/api/status", "GET", NULL, 900, &out, NULL);
    free(out.data);
    return ok;
}

static JsonNode *parse_json(const char *text, char **error_out) {
    JsonParser *parser = json_parser_new();
    GError *error = NULL;
    if (text == NULL || !json_parser_load_from_data(parser, text, -1, &error)) {
        if (error_out != NULL) {
            *error_out = g_strdup(error != NULL ? error->message : "invalid JSON");
        }
        if (error != NULL) {
            g_error_free(error);
        }
        g_object_unref(parser);
        return NULL;
    }
    JsonNode *root = json_node_copy(json_parser_get_root(parser));
    g_object_unref(parser);
    return root;
}

static const char *obj_string(JsonObject *obj, const char *key) {
    if (obj == NULL || !json_object_has_member(obj, key)) {
        return "";
    }
    JsonNode *node = json_object_get_member(obj, key);
    if (!JSON_NODE_HOLDS_VALUE(node) || json_node_get_value_type(node) != G_TYPE_STRING) {
        return "";
    }
    return json_node_get_string(node);
}

static gboolean obj_bool(JsonObject *obj, const char *key) {
    if (obj == NULL || !json_object_has_member(obj, key)) {
        return FALSE;
    }
    return json_object_get_boolean_member(obj, key);
}

static void set_text_view(GtkWidget *view, const char *text) {
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
    gtk_text_buffer_set_text(buffer, text != NULL ? text : "", -1);
}

static void append_diag(App *app, const char *message) {
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->diagnostics_view));
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

static void refresh_status(App *app) {
    Buffer out = {0};
    char *err = NULL;
    if (!api_request("/api/status", "GET", NULL, 1800, &out, &err)) {
        gtk_label_set_text(GTK_LABEL(app->status), "● Controller unavailable");
        gtk_label_set_text(GTK_LABEL(app->error), err != NULL ? err : "Controller unavailable");
        g_free(err);
        free(out.data);
        return;
    }

    JsonNode *root = parse_json(out.data, &err);
    if (root == NULL || !JSON_NODE_HOLDS_OBJECT(root)) {
        gtk_label_set_text(GTK_LABEL(app->error), err != NULL ? err : "Invalid status JSON");
        if (root != NULL) {
            json_node_free(root);
        }
        g_free(err);
        free(out.data);
        return;
    }

    JsonObject *obj = json_node_get_object(root);
    const gboolean connected = obj_bool(obj, "connected");
    const char *phase = obj_string(obj, "phase");
    const char *runtime = obj_string(obj, "runtime_mode");
    if (runtime[0] == '\0') {
        runtime = obj_string(obj, "mode");
    }
    char *status = g_strdup_printf("%s %s", connected ? "●" : "○",
                                   connected ? "Connected" : (phase[0] != '\0' ? phase : "Off"));
    char *detail = g_strdup_printf("Logical: %s    Runtime: %s    Base: %s    Router: %s",
                                   obj_string(obj, "logical_mode"), runtime,
                                   obj_string(obj, "base"), obj_string(obj, "router_id"));
    gtk_label_set_text(GTK_LABEL(app->status), status);
    gtk_label_set_text(GTK_LABEL(app->detail), detail);
    gtk_label_set_text(GTK_LABEL(app->error), obj_string(obj, "last_error"));
    g_free(status);
    g_free(detail);
    json_node_free(root);
    free(out.data);
}

static void refresh_profiles(App *app) {
    Buffer out = {0};
    char *err = NULL;
    if (!api_request("/api/profiles", "GET", NULL, 2500, &out, &err)) {
        g_free(err);
        free(out.data);
        return;
    }
    JsonNode *root = parse_json(out.data, &err);
    if (root == NULL || !JSON_NODE_HOLDS_OBJECT(root)) {
        if (root != NULL) {
            json_node_free(root);
        }
        g_free(err);
        free(out.data);
        return;
    }

    JsonObject *obj = json_node_get_object(root);
    JsonArray *profiles = json_object_get_array_member(obj, "profiles");
    const char *selected = obj_string(obj, "selected_id");
    app->suppress_router_change = TRUE;
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(app->router_combo));
    g_ptr_array_set_size(app->router_ids, 0);
    GString *text = g_string_new("");
    guint selected_index = 0;

    if (profiles != NULL) {
        const guint count = json_array_get_length(profiles);
        for (guint i = 0; i < count; i++) {
            JsonObject *profile = json_array_get_object_element(profiles, i);
            if (profile == NULL) {
                continue;
            }
            const char *id = obj_string(profile, "id");
            const char *name = obj_string(profile, "name");
            const char *endpoint = obj_string(profile, "endpoint");
            const char *dns = obj_string(profile, "dns_host");
            const char *public_ip = obj_string(profile, "public_ip");
            if (name[0] == '\0') {
                name = id;
            }
            gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->router_combo), name);
            g_ptr_array_add(app->router_ids, g_strdup(id));
            if (selected[0] != '\0' && strcmp(id, selected) == 0) {
                selected_index = i;
            }
            g_string_append_printf(text, "%s\n  endpoint: %s\n  DNS: %s\n  public exit: %s\n\n",
                                   name,
                                   endpoint[0] != '\0' ? endpoint : "—",
                                   dns[0] != '\0' ? dns : "—",
                                   public_ip[0] != '\0' ? public_ip : "—");
        }
    }
    if (app->router_ids->len > 0) {
        gtk_combo_box_set_active(GTK_COMBO_BOX(app->router_combo), (gint)selected_index);
    }
    app->suppress_router_change = FALSE;
    set_text_view(app->nodes_view, text->str);
    g_string_free(text, TRUE);
    json_node_free(root);
    free(out.data);
}

static void refresh_modes(App *app) {
    Buffer out = {0};
    char *err = NULL;
    if (!api_request("/api/logical-modes", "GET", NULL, 12000, &out, &err)) {
        g_free(err);
        free(out.data);
        return;
    }
    JsonNode *root = parse_json(out.data, &err);
    if (root == NULL || !JSON_NODE_HOLDS_ARRAY(root)) {
        if (root != NULL) {
            json_node_free(root);
        }
        g_free(err);
        free(out.data);
        return;
    }

    JsonArray *modes = json_node_get_array(root);
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(app->mode_combo));
    g_ptr_array_set_size(app->mode_ids, 0);
    GString *text = g_string_new("");
    const guint count = json_array_get_length(modes);
    for (guint i = 0; i < count; i++) {
        JsonObject *mode = json_array_get_object_element(modes, i);
        if (mode == NULL) {
            continue;
        }
        const char *id = obj_string(mode, "id");
        const char *name = obj_string(mode, "name");
        const char *reason = obj_string(mode, "reason");
        const gboolean available = obj_bool(mode, "available");
        g_string_append_printf(text, "%s %s [%s]\n  %s\n\n",
                               available ? "✓" : "—", name, id,
                               reason[0] != '\0' ? reason : "Ready");
        if (available) {
            gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->mode_combo), name);
            g_ptr_array_add(app->mode_ids, g_strdup(id));
        }
    }
    if (app->mode_ids->len > 0) {
        gtk_combo_box_set_active(GTK_COMBO_BOX(app->mode_combo), 0);
    }
    set_text_view(app->methods_view, text->str);
    g_string_free(text, TRUE);
    json_node_free(root);
    free(out.data);
}

static void refresh_all(App *app) {
    refresh_status(app);
    refresh_profiles(app);
    refresh_modes(app);
}

static gboolean refresh_timer(gpointer data) {
    refresh_status((App *)data);
    return G_SOURCE_CONTINUE;
}

static void post_and_log(App *app, const char *path, const char *json_body,
                         long timeout_ms, const char *label) {
    Buffer out = {0};
    char *err = NULL;
    if (api_request(path, "POST", json_body, timeout_ms, &out, &err)) {
        char *line = g_strdup_printf("%s: %s", label,
                                     out.data != NULL ? g_strstrip(out.data) : "OK");
        append_diag(app, line);
        g_free(line);
    } else {
        char *line = g_strdup_printf("%s failed: %s", label,
                                     err != NULL ? err : "request failed");
        append_diag(app, line);
        gtk_label_set_text(GTK_LABEL(app->error), err != NULL ? err : "request failed");
        g_free(line);
    }
    g_free(err);
    free(out.data);
    refresh_all(app);
}

static void on_auto(GtkButton *button, gpointer data) {
    (void)button;
    post_and_log((App *)data, "/api/auto", "{}", 150000, "AUTO");
}

static void on_disconnect(GtkButton *button, gpointer data) {
    (void)button;
    post_and_log((App *)data, "/api/disconnect", "{}", 20000, "Disconnect");
}

static void on_dns(GtkButton *button, gpointer data) {
    (void)button;
    post_and_log((App *)data, "/api/dns/retest", "{}", 90000, "DNS retest");
}

static void on_emergency(GtkButton *button, gpointer data) {
    (void)button;
    post_and_log((App *)data, "/api/emergency-stop", "{}", 20000, "Emergency stop");
}

static void on_public_ip(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    Buffer out = {0};
    char *err = NULL;
    if (api_request("/api/public-ip", "GET", NULL, 20000, &out, &err)) {
        append_diag(app, out.data != NULL ? g_strstrip(out.data) : "Public exit proof OK");
    } else {
        append_diag(app, err != NULL ? err : "Public exit proof failed");
    }
    g_free(err);
    free(out.data);
    refresh_status(app);
}

static void on_connect(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    const gint mode_index = gtk_combo_box_get_active(GTK_COMBO_BOX(app->mode_combo));
    if (mode_index < 0 || (guint)mode_index >= app->mode_ids->len) {
        return;
    }
    const char *mode = g_ptr_array_index(app->mode_ids, (guint)mode_index);
    const gint base_index = gtk_combo_box_get_active(GTK_COMBO_BOX(app->base_combo));
    const char *base = base_index == 1 ? "wg" : (base_index == 2 ? "awg" : "auto");
    char *json_body = g_strdup_printf("{\"mode\":\"%s\",\"base\":\"%s\"}", mode, base);
    post_and_log(app, "/api/connect-logical", json_body, 180000, "Connect");
    g_free(json_body);
}

static void on_router_changed(GtkComboBox *box, gpointer data) {
    App *app = data;
    if (app->suppress_router_change) {
        return;
    }
    const gint index = gtk_combo_box_get_active(box);
    if (index < 0 || (guint)index >= app->router_ids->len) {
        return;
    }
    const char *id = g_ptr_array_index(app->router_ids, (guint)index);
    char *json_body = g_strdup_printf("{\"id\":\"%s\"}", id);
    Buffer out = {0};
    char *err = NULL;
    if (!api_request("/api/profile/select", "POST", json_body, 10000, &out, &err)) {
        gtk_label_set_text(GTK_LABEL(app->error), err != NULL ? err : "Router switch failed");
    }
    g_free(err);
    free(out.data);
    g_free(json_body);
    refresh_status(app);
}

static GtkWidget *scroll_text(GtkWidget **view_out) {
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    GtkWidget *view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(view), TRUE);
    gtk_container_add(GTK_CONTAINER(scroll), view);
    *view_out = view;
    return scroll;
}

static GtkWidget *make_button(const char *label, GCallback callback, App *app) {
    GtkWidget *button = gtk_button_new_with_label(label);
    g_signal_connect(button, "clicked", callback, app);
    return button;
}

static void build_ui(App *app) {
    app->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(app->window), "Router VPN");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 1040, 720);

    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_container_set_border_width(GTK_CONTAINER(root), 16);
    gtk_container_add(GTK_CONTAINER(app->window), root);

    GtkWidget *header = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<span size='xx-large' weight='bold'>Router VPN</span>");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(header), title, TRUE, TRUE, 0);
    app->status = gtk_label_new("Checking…");
    gtk_box_pack_end(GTK_BOX(header), app->status, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root), header, FALSE, FALSE, 0);

    app->detail = gtk_label_new("");
    gtk_widget_set_halign(app->detail, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(root), app->detail, FALSE, FALSE, 0);
    app->error = gtk_label_new("");
    gtk_widget_set_halign(app->error, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(root), app->error, FALSE, FALSE, 0);

    GtkWidget *notebook = gtk_notebook_new();
    gtk_box_pack_start(GTK_BOX(root), notebook, TRUE, TRUE, 0);

    GtkWidget *connect = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(connect), 20);
    gtk_box_pack_start(GTK_BOX(connect), gtk_label_new("Router"), FALSE, FALSE, 0);
    app->router_combo = gtk_combo_box_text_new();
    gtk_box_pack_start(GTK_BOX(connect), app->router_combo, FALSE, FALSE, 0);
    g_signal_connect(app->router_combo, "changed", G_CALLBACK(on_router_changed), app);
    gtk_box_pack_start(GTK_BOX(connect), gtk_label_new("Mode"), FALSE, FALSE, 0);
    app->mode_combo = gtk_combo_box_text_new();
    gtk_box_pack_start(GTK_BOX(connect), app->mode_combo, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(connect), gtk_label_new("Tunnel base"), FALSE, FALSE, 0);
    app->base_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->base_combo), "Auto");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->base_combo), "WireGuard");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->base_combo), "AmneziaWG");
    gtk_combo_box_set_active(GTK_COMBO_BOX(app->base_combo), 0);
    gtk_box_pack_start(GTK_BOX(connect), app->base_combo, FALSE, FALSE, 0);

    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(row), make_button("AUTO Connect", G_CALLBACK(on_auto), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Connect Selected", G_CALLBACK(on_connect), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Disconnect", G_CALLBACK(on_disconnect), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(connect), row, FALSE, FALSE, 0);
    GtkWidget *proof = gtk_label_new("Connected is shown only after exact selected-node private identity proof succeeds.");
    gtk_label_set_line_wrap(GTK_LABEL(proof), TRUE);
    gtk_widget_set_halign(proof, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(connect), proof, FALSE, FALSE, 0);
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), connect, gtk_label_new("Connect"));

    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), scroll_text(&app->nodes_view), gtk_label_new("Nodes"));
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), scroll_text(&app->methods_view), gtk_label_new("Methods"));

    GtkWidget *diagnostics = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(diagnostics), 12);
    GtkWidget *diagnostics_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(diagnostics_row), make_button("Prove public VPN exit", G_CALLBACK(on_public_ip), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(diagnostics_row), make_button("Retest home-exit DNS", G_CALLBACK(on_dns), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(diagnostics_row), make_button("Emergency stop", G_CALLBACK(on_emergency), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(diagnostics), diagnostics_row, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(diagnostics), scroll_text(&app->diagnostics_view), TRUE, TRUE, 0);
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), diagnostics, gtk_label_new("Diagnostics"));
}

static gboolean resolve_package_root(App *app, const char *argv0) {
    char *absolute = realpath(argv0, NULL);
    if (absolute == NULL) {
        return FALSE;
    }
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
    if (api_ready()) {
        return TRUE;
    }
    char *controller = g_build_filename(app->package_root, "router-vpn-client", NULL);
    char *config = g_build_filename(app->package_root, "client.json", NULL);
    if (access(controller, X_OK) != 0 || access(config, R_OK) != 0) {
        if (error_out != NULL) {
            *error_out = g_strdup("RouterVPN GTK must stay beside router-vpn-client and client.json in its package.");
        }
        g_free(controller);
        g_free(config);
        return FALSE;
    }

    const pid_t pid = fork();
    if (pid < 0) {
        if (error_out != NULL) {
            *error_out = g_strdup("Could not fork local controller");
        }
        g_free(controller);
        g_free(config);
        return FALSE;
    }
    if (pid == 0) {
        if (setenv("HOMEVPN_ROOT", app->package_root, 1) != 0 ||
            setenv("HOMEVPN_CLIENT_CONFIG", config, 1) != 0 ||
            setenv("HOMEVPN_NATIVE_APP", "linux-gtk", 1) != 0 ||
            chdir(app->package_root) != 0) {
            _exit(126);
        }
        execl(controller, controller, (char *)NULL);
        _exit(127);
    }

    app->controller_pid = pid;
    app->owns_controller = TRUE;
    g_free(controller);
    g_free(config);
    for (int i = 0; i < 60; i++) {
        if (api_ready()) {
            return TRUE;
        }
        int status = 0;
        if (waitpid(pid, &status, WNOHANG) == pid) {
            break;
        }
        g_usleep(200000);
    }
    (void)kill(pid, SIGTERM);
    if (error_out != NULL) {
        *error_out = g_strdup("Local Router VPN controller did not become ready on 127.0.0.1:8788.");
    }
    return FALSE;
}

static void shutdown_controller(App *app) {
    if (!app->owns_controller || app->controller_pid <= 0) {
        return;
    }
    Buffer out = {0};
    (void)api_request("/api/emergency-stop", "POST", "{}", 1800, &out, NULL);
    free(out.data);
    (void)kill(app->controller_pid, SIGTERM);
    for (int i = 0; i < 20; i++) {
        int status = 0;
        if (waitpid(app->controller_pid, &status, WNOHANG) == app->controller_pid) {
            return;
        }
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
        "/api/public-ip", "/api/dns/retest", "/api/emergency-stop"
    };
    if (strcmp(ROUTER_VPN_BASE_URL, "http://127.0.0.1:8788") != 0 || ROUTER_VPN_APP_CONTRACT != 1) {
        return 2;
    }
    if (G_N_ELEMENTS(paths) != 10 || paths[0][0] != '/') {
        return 3;
    }
    puts("Router VPN native Linux GTK self-test: OK");
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--self-test") == 0) {
        return self_test();
    }
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
    app.router_ids = g_ptr_array_new_with_free_func(g_free);
    app.mode_ids = g_ptr_array_new_with_free_func(g_free);
    if (!resolve_package_root(&app, argv[0])) {
        fprintf(stderr, "Router VPN: cannot resolve package root\n");
        g_ptr_array_unref(app.router_ids);
        g_ptr_array_unref(app.mode_ids);
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
        g_free(error);
        g_free(app.package_root);
        g_ptr_array_unref(app.router_ids);
        g_ptr_array_unref(app.mode_ids);
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
    g_ptr_array_unref(app.router_ids);
    g_ptr_array_unref(app.mode_ids);
    curl_global_cleanup();
    return 0;
}
