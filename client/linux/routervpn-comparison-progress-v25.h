/* Captured public request ownership shared by the native GTK surfaces.
 * These public nonces correlate read-only progress; the controller separately
 * validates the captured private path and owns all tunnel measurements. */
#ifndef ROUTERVPN_COMPARISON_PROGRESS_V25_H
#define ROUTERVPN_COMPARISON_PROGRESS_V25_H
#include <glib.h>
#include <json-glib/json-glib.h>
#include <string.h>

static inline const char *linux_comparison_string_v25(JsonObject *object, const char *key) {
    JsonNode *node = object != NULL && json_object_has_member(object, key) ? json_object_get_member(object, key) : NULL;
    return node != NULL && JSON_NODE_HOLDS_VALUE(node) && json_node_get_value_type(node) == G_TYPE_STRING ? json_node_get_string(node) : NULL;
}

static inline gboolean linux_comparison_id_v25(const char *id) {
    if (id == NULL || strlen(id) != 32) return FALSE;
    for (const char *p = id; *p; p++) if (!(*p >= '0' && *p <= '9') && !(*p >= 'a' && *p <= 'f')) return FALSE;
    return TRUE;
}

static inline char *linux_comparison_new_id_v25(void) {
    char *id = g_uuid_string_random();
    char *write = id;
    for (const char *read = id; *read; read++) if (*read != '-') *write++ = *read;
    *write = '\0';
    return id;
}

static inline JsonNode *linux_comparison_parse_v25(const char *json) {
    if (json == NULL) return NULL;
    JsonParser *parser = json_parser_new();
    JsonNode *root = json_parser_load_from_data(parser, json, -1, NULL) ? json_node_copy(json_parser_get_root(parser)) : NULL;
    g_object_unref(parser);
    return root;
}

/* Only the already source-captured Tor-auto request builder supplies this
 * marker. Reject malformed markers rather than losing ownership and using an
 * ordinary timeout. Source/entry/credential admission remains in the builder
 * and the controller, not in an opaque progress nonce. */
static inline gboolean linux_comparison_connect_id_v25(const char *body, char id[33]) {
    id[0] = '\0';
    g_autoptr(JsonNode) root = linux_comparison_parse_v25(body);
    if (root == NULL || !JSON_NODE_HOLDS_OBJECT(root)) return FALSE;
    JsonObject *request = json_node_get_object(root);
    if (!json_object_has_member(request, "comparison_request_id")) return TRUE;
    const char *nonce = linux_comparison_string_v25(request, "comparison_request_id");
    JsonNode *direct = json_object_get_member(request, "direct");
    JsonNode *tokens = json_object_get_member(request, "expected_profile_tokens");
    const char *profile = linux_comparison_string_v25(request, "profile_id");
    if (!linux_comparison_id_v25(nonce) || g_strcmp0(linux_comparison_string_v25(request, "execution"), "auto") != 0 ||
        (direct != NULL && (!JSON_NODE_HOLDS_VALUE(direct) || json_node_get_value_type(direct) != G_TYPE_BOOLEAN || json_node_get_boolean(direct))) ||
        profile == NULL || !profile[0] || linux_comparison_string_v25(request, "expected_selected_node_id") == NULL ||
        tokens == NULL || !JSON_NODE_HOLDS_OBJECT(tokens) || !json_object_has_member(json_node_get_object(tokens), profile)) return FALSE;
    memcpy(id, nonce, 33);
    return TRUE;
}

static inline gboolean linux_comparison_progress_matches_v25(const char *json, const char *expected, gboolean *complete, gboolean *failed) {
    if (complete != NULL) *complete = FALSE;
    if (failed != NULL) *failed = FALSE;
    if (!linux_comparison_id_v25(expected)) return FALSE;
    g_autoptr(JsonNode) root = linux_comparison_parse_v25(json);
    if (root == NULL || !JSON_NODE_HOLDS_OBJECT(root)) return FALSE;
    JsonNode *value = json_object_get_member(json_node_get_object(root), "comparison");
    if (value == NULL || !JSON_NODE_HOLDS_OBJECT(value)) return FALSE;
    JsonObject *progress = json_node_get_object(value);
    JsonNode *terminal = json_object_get_member(progress, "complete");
    if (g_strcmp0(linux_comparison_string_v25(progress, "request_id"), expected) != 0 ||
        g_strcmp0(linux_comparison_string_v25(progress, "last_node_measurement"), "tor-last-relay-http") != 0 ||
        g_strcmp0(linux_comparison_string_v25(progress, "external_measurement"), "same-captured-endpoint-http") != 0 ||
        terminal == NULL || !JSON_NODE_HOLDS_VALUE(terminal) || json_node_get_value_type(terminal) != G_TYPE_BOOLEAN) return FALSE;
    if (complete != NULL) *complete = json_node_get_boolean(terminal);
    const char *failure = linux_comparison_string_v25(progress, "failure");
    if (failed != NULL) *failed = failure != NULL && failure[0];
    return TRUE;
}
#endif
