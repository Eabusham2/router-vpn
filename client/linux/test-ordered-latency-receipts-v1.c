/* Executes the unchanged shipping C JSON/receipt validators with real json-glib.
 * This isolated fixture does not create GTK widgets or a native tunnel. */
#include <json-glib/json-glib.h>
#include <math.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef ROUTERVPN_ORDERED_VALIDATORS
#error Exact shipping validator slice is required
#endif
#include ROUTERVPN_ORDERED_VALIDATORS
static int checks;
static void check(gboolean value, const char *why) {
    checks++;
    if (!value) { fprintf(stderr, "Ordered latency check failed: %s\n", why); exit(1); }
}
/* Mutable fixture faults must not share nested objects with the positive source. */
static JsonNode *fixture_copy(JsonNode *node) {
    char *text = json_to_string(node, FALSE);
    GError *error = NULL;
    JsonNode *copy = json_from_string(text, &error);
    g_free(text);
    if (copy == NULL) g_error("Cannot clone exact JSON fixture: %s", error != NULL ? error->message : "unknown error");
    g_clear_error(&error);
    return copy;
}
int main(int argc, char **argv) {
    check(argc == 2, "fixture path");
    JsonParser *parser = json_parser_new();
    check(json_parser_load_from_file(parser, argv[1], NULL), "actual json-glib parses fixtures");
    JsonObject *root = json_node_get_object(json_parser_get_root(parser));
    JsonArray *cases = json_object_get_array_member(root, "ordinary");
    check(json_array_get_length(cases) == 7, "all bounded private counts");
    for (guint c = 0; c < json_array_get_length(cases); c++) {
        JsonObject *fixture = json_array_get_object_element(cases, c), *info = json_object_get_object_member(fixture, "info");
        JsonArray *nodes = json_object_get_array_member(info, "nodes"), *receipts = json_object_get_array_member(fixture, "receipts");
        JsonObject *capture = json_object_get_object_member(info, "capture");
        int count = (int)json_array_get_length(nodes);
        check(count == (int)c+2 && (int)json_array_get_length(receipts) == count, "complete private fixture inventory");
        for (int position = 0; position < count; position++) {
            JsonObject *node = json_array_get_object_element(nodes, position), *receipt = json_array_get_object_element(receipts, position);
            check(linux_ol_node_v1(node, position, count), "private prefix keeps its captured kind and role");
            check(linux_ol_receipt_v1(receipt, capture, node, count, TRUE), "complete private receipt");
            JsonNode *copy = fixture_copy(json_array_get_element(receipts, position));
            JsonObject *bad = json_node_get_object(copy), *result = linux_ol_object_v1(bad, "result"), *benchmark = linux_ol_object_v1(result, "benchmark"), *distribution = linux_ol_object_v1(benchmark, "distribution");
            double original = json_object_get_double_member(distribution, "max_ms");
            json_object_set_double_member(distribution, "max_ms", 2001);
            check(!linux_ol_receipt_v1(bad, capture, node, count, TRUE), "private middle cannot borrow public timeout");
            json_object_set_double_member(distribution, "max_ms", original);
            char foreign[128]; g_snprintf(foreign, sizeof(foreign), "Cumulative path through node %d of %d", position+1, count == 8 ? 7 : 8);
            json_object_set_string_member(result, "label", foreign);
            check(!linux_ol_receipt_v1(bad, capture, node, count, TRUE), "another path length cannot relabel this result");
            json_node_free(copy);
        }
        JsonObject *first = json_array_get_object_element(nodes, 0);
        check(!linux_ol_node_v1(first, 0, 1) && !linux_ol_node_v1(first, 0, 9), "bounded path inventory");
    }
    JsonObject *info = json_object_get_object_member(root, "info"), *capture = json_object_get_object_member(info, "capture");
    JsonArray *nodes = json_object_get_array_member(info, "nodes");
    for (int position = 0; position < 3; position++) {
        char key[32];g_snprintf(key, sizeof(key), "receipt%d", position);
        check(linux_ol_receipt_v1(json_object_get_object_member(root, key), capture, json_array_get_object_element(nodes, position), 3, TRUE), "original imported-middle receipt retained");
    }

    JsonArray *selected = json_object_get_array_member(root, "selected");
    check(json_array_get_length(selected) == 16, "both selected paths keep all private counts and imported middle");
    for (guint c = 0; c < json_array_get_length(selected); c++) {
        JsonObject *item = json_array_get_object_element(selected, c), *selected_info = json_object_get_object_member(item, "info");
        JsonObject *owner = json_object_get_object_member(selected_info, "capture");
        JsonArray *rows = json_object_get_array_member(selected_info, "nodes"), *receipts = json_object_get_array_member(item, "receipts");
        int count = (int)json_array_get_length(rows);
        for (int position = 0; position < count; position++) {
            JsonObject *node = json_array_get_object_element(rows, position), *saved = json_array_get_object_element(receipts, position);
            check(linux_ol_node_v1(node, position, count), "canonical selected node retained");
            check(linux_ol_receipt_v1(saved, owner, node, count, TRUE) && linux_ol_receipt_v1(saved, owner, node, count, FALSE), "selected current and history receipt retained");
            const char *prefixes[] = {"Cumulative path", "Cumulative local path", "Cumulative server path"};
            const char *label = linux_ol_string_v1(node, "label"), *suffix = strstr(label, " path");
            check(suffix != NULL, "selected fixture has canonical path label");
            for (guint kind = 0; kind < G_N_ELEMENTS(prefixes); kind++) {
                char *other = g_strconcat(prefixes[kind], suffix+5, NULL);
                if (strcmp(other, label)) {
                    JsonNode *copy = fixture_copy(json_array_get_element(receipts, position));
                    JsonObject *bad = json_node_get_object(copy);
                    json_object_set_string_member(linux_ol_object_v1(bad, "result"), "label", other);
                    check(!linux_ol_receipt_v1(bad, owner, node, count, TRUE), "current receipt cannot borrow another selected label");
                    check(!linux_ol_receipt_v1(bad, owner, node, count, FALSE), "history cannot borrow another selected label");
                    json_node_free(copy);
                }
                g_free(other);
            }
            JsonNode *copy = fixture_copy(json_array_get_element(rows, position));
            char *unknown = g_strconcat("Cumulative auto path", suffix+5, NULL);
            json_object_set_string_member(json_node_get_object(copy), "label", unknown);
            check(!linux_ol_node_v1(json_node_get_object(copy), position, count), "unknown selected label refused");
            g_free(unknown);json_node_free(copy);
        }
    }

    g_object_unref(parser);
    printf("Shipping C receipt validators: %d PASS (no GTK widgets/native tunnel)\n", checks);
    return 0;
}
