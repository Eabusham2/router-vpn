/* The original Compare graph owns its computed startup budget. This helper
 * validates that exact request without rewriting any captured node or mode. */
#ifndef ROUTERVPN_MULTIHOP_HTTP_V26_H
#define ROUTERVPN_MULTIHOP_HTTP_V26_H
#include <json-glib/json-glib.h>
#include "routervpn-http-job-v16.h"

/* Defined by the shipping multihop catalog included later in the GTK unit. */
static gboolean linux_multihop_entry_supported_v23(const char *mode);
static gboolean linux_multihop_exit_supported_v22(const char *mode);
static long linux_multihop_startup_timeout_v23(const char *entry, const char *exit, const char *execution);

static inline void linux_multihop_http_member_v26(JsonParser *parser, JsonObject *object, const gchar *member, gpointer data) {
    (void)parser; (void)object; (void)member;
    (*(guint *)data)++;
}

static inline const char *linux_multihop_http_string_v26(JsonObject *object, const char *key) {
    JsonNode *node = json_object_has_member(object, key) ? json_object_get_member(object, key) : NULL;
    return node != NULL && JSON_NODE_HOLDS_VALUE(node) && json_node_get_value_type(node) == G_TYPE_STRING ? json_node_get_string(node) : NULL;
}

/* json-glib accepts a sequence of top-level values. The captured controller
 * request owns exactly one object, so reject trailing data before parsing. */
static inline gboolean linux_multihop_http_one_object_v26(const char *body) {
    const char *p = body;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != '{') return FALSE;
    guint depth = 0;
    gboolean quoted = FALSE, escaped = FALSE;
    for (; *p; p++) {
        if (quoted) {
            if (escaped) escaped = FALSE;
            else if (*p == '\\') escaped = TRUE;
            else if (*p == '"') quoted = FALSE;
        } else if (*p == '"') quoted = TRUE;
        else if (*p == '{') depth++;
        else if (*p == '}' && --depth == 0) {
            p++;
            while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
            return *p == '\0';
        }
    }
    return FALSE;
}

static inline RVHttpJobV16 *rv_http_start_multihop_comparison_v26(const char *path, const char *body, long timeout_ms, const char *label, int get) {
    if (get || path == NULL || strcmp(path, "/api/multihop/connect") != 0 || body == NULL ||
        strlen(body) > RV_HTTP_LIMIT_V16 || !linux_multihop_http_one_object_v26(body) || timeout_ms <= 300000L || timeout_ms > 450000L) return NULL;
    g_autoptr(JsonParser) parser = json_parser_new();
    guint members = 0;
    g_signal_connect(parser, "object-member", G_CALLBACK(linux_multihop_http_member_v26), &members);
    if (!json_parser_load_from_data(parser, body, -1, NULL)) return NULL;
    JsonNode *root = json_parser_get_root(parser);
    if (root == NULL || !JSON_NODE_HOLDS_OBJECT(root)) return NULL;
    JsonObject *request = json_node_get_object(root);
    /* Counting parser events also refuses duplicate keys that a map would
     * otherwise collapse. The native builders capture exactly these fields. */
    if (members != 5 || json_object_get_size(request) != 5) return NULL;
    const char *entry_id = linux_multihop_http_string_v26(request, "entry_id");
    const char *exit_id = linux_multihop_http_string_v26(request, "exit_id");
    const char *entry = linux_multihop_http_string_v26(request, "entry_mode");
    const char *exit = linux_multihop_http_string_v26(request, "exit_mode");
    const char *execution = linux_multihop_http_string_v26(request, "execution");
    if (entry_id == NULL || !entry_id[0] || exit_id == NULL || !exit_id[0] || strcmp(entry_id, exit_id) == 0 ||
        g_strcmp0(execution, "auto") != 0 ||
        !linux_multihop_entry_supported_v23(entry) || !linux_multihop_exit_supported_v22(exit) ||
        timeout_ms != linux_multihop_startup_timeout_v23(entry, exit, execution)) return NULL;
    return rv_http_start_bounded_v25("/api/multihop/connect", body, timeout_ms, 450000L, RV_HTTP_LIMIT_V16, label, 0);
}
#endif
