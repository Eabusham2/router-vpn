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
            JsonNode *copy = json_node_copy(json_array_get_element(receipts, position));
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
    g_object_unref(parser);
    printf("Shipping C receipt validators: %d PASS (no GTK widgets/native tunnel)\n", checks);
    return 0;
}
