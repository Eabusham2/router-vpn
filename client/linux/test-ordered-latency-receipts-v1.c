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
static gboolean fixture_unbound_node(JsonObject *node, int position, int count) {
    return linux_ol_bound_node_v1(node, position, count, NULL, NULL, NULL);
}

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
            check(fixture_unbound_node(node, position, count), "private prefix keeps its captured kind and role");
            check(linux_ol_receipt_v1(receipt, capture, node, count, TRUE, NULL), "complete private receipt");
            JsonNode *copy = fixture_copy(json_array_get_element(receipts, position));
            JsonObject *bad = json_node_get_object(copy), *result = linux_ol_object_v1(bad, "result"), *benchmark = linux_ol_object_v1(result, "benchmark"), *distribution = linux_ol_object_v1(benchmark, "distribution");
            double original = json_object_get_double_member(distribution, "max_ms");
            json_object_set_double_member(distribution, "max_ms", 2001);
            check(!linux_ol_receipt_v1(bad, capture, node, count, TRUE, NULL), "private middle cannot borrow public timeout");
            json_object_set_double_member(distribution, "max_ms", original);
            char foreign[128]; g_snprintf(foreign, sizeof(foreign), "Cumulative path through node %d of %d", position+1, count == 8 ? 7 : 8);
            json_object_set_string_member(result, "label", foreign);
            check(!linux_ol_receipt_v1(bad, capture, node, count, TRUE, NULL), "another path length cannot relabel this result");
            json_node_free(copy);
        }
        JsonObject *first = json_array_get_object_element(nodes, 0);
        check(!fixture_unbound_node(first, 0, 1) && !fixture_unbound_node(first, 0, 9), "bounded path inventory");
    }
    JsonArray *connect = json_object_get_array_member(root, "connect");
    check(json_array_get_length(connect) == 6, "all six CONNECT path counts");
    for (guint c=0;c<6;c++) {
        int count=c+3, position=count-2;
        JsonObject *fixture=json_array_get_object_element(connect,c), *view=json_object_get_object_member(fixture,"info");
        JsonObject *node=json_array_get_object_element(json_object_get_array_member(view,"nodes"),position);
        JsonObject *saved=json_array_get_object_element(json_object_get_array_member(fixture,"receipts"),position);
        JsonObject *owner=json_object_get_object_member(view,"capture");
        check(fixture_unbound_node(node,position,count),"CONNECT bounded penultimate row");
        check(linux_ol_receipt_v1(saved,owner,node,count,TRUE, NULL) && linux_ol_receipt_v1(saved,owner,node,count,FALSE, NULL),"CONNECT current and saved fifty receipt");
        for(int other=0;other<count;other++)if(other!=position){
            JsonNode *copy=fixture_copy(json_array_get_element(json_object_get_array_member(view,"nodes"),position));
            JsonObject *bad=json_node_get_object(copy);char label[160];g_snprintf(label,sizeof(label),"Cumulative path through custom node %d of %d → Cloudflare edge",other+1,count);
            json_object_set_int_member(bad,"position",other);json_object_set_string_member(bad,"role",other==0?"entry":other==count-1?"exit":"intermediate");json_object_set_string_member(bad,"label",label);
            if(other==0||other==count-1)check(!fixture_unbound_node(bad,other,count),"public row cannot become an endpoint");
            else check(!linux_ol_receipt_v1(saved,owner,bad,count,TRUE, NULL),"original CONNECT receipt cannot move to another interior");
            json_node_free(copy);
        }
    }
    JsonArray *independent = json_object_get_array_member(root,"independent");
    check(json_array_get_length(independent)==8,"complete independent imported receipt inventory");
    for(guint c=0;c<json_array_get_length(independent);c++){
        JsonObject *item=json_array_get_object_element(independent,c), *view=json_object_get_object_member(item,"info");
        JsonArray *rows=json_object_get_array_member(view,"nodes"), *receipts=json_object_get_array_member(item,"receipts");
        JsonObject *owner=json_object_get_object_member(view,"capture");
        int count=(int)json_array_get_length(receipts);
        check((int)json_array_get_length(rows)==count&&(int)json_array_get_length(receipts)==count,"independent public path lost a member");
        for(int position=1;position<count-1;position++){
            JsonObject *node=json_array_get_object_element(rows,position), *saved=json_array_get_object_element(receipts,position);
            check(linux_ol_bound_node_v1(node,position,count,owner, NULL,rows)&&linux_ol_receipt_v1(saved,owner,node,count,TRUE, rows)&&linux_ol_receipt_v1(saved,owner,node,count,FALSE, rows),"independent imported interior receipt was refused");
            JsonNode *copy=fixture_copy(json_array_get_element(receipts,position));JsonObject *bad=json_node_get_object(copy);
            JsonObject *distribution=linux_ol_object_v1(linux_ol_object_v1(linux_ol_object_v1(bad,"result"),"benchmark"),"distribution");
            json_object_set_int_member(distribution,"samples",49);check(!linux_ol_receipt_v1(bad,owner,node,count,TRUE, rows),"independent public history accepted incomplete fifty");json_object_set_int_member(distribution,"samples",50);
            json_object_set_string_member(bad,"source_sha256","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");check(!linux_ol_receipt_v1(bad,owner,node,count,TRUE, rows)&&!linux_ol_receipt_v1(bad,owner,node,count,FALSE, rows),"independent public history borrowed another source");json_node_free(copy);
            if(position!=count-2){
                for(guint selected=0;selected<2;selected++){
                    JsonNode *changed=fixture_copy(json_array_get_element(rows,position));JsonObject *selected_node=json_node_get_object(changed);char label[180];
                    g_snprintf(label,sizeof(label),"Cumulative %s path through custom node %d of %d → Cloudflare edge",selected?"server":"local",position+1,count);
                    json_object_set_string_member(selected_node,"label",label);check(!fixture_unbound_node(selected_node,position,count),"independent Local history borrowed selected execution authority");json_node_free(changed);
                }
            }
        }
    }
    JsonArray *paired = json_object_get_array_member(root, "paired_extended");
    check(json_array_get_length(paired) == 3, "complete extended paired receipt inventory");
    for (guint c = 0; c < json_array_get_length(paired); c++) {
        JsonObject *item = json_array_get_object_element(paired, c), *view = json_object_get_object_member(item, "info");
        JsonArray *rows = json_object_get_array_member(view, "nodes"), *receipts = json_object_get_array_member(item, "receipts");
        JsonObject *owner = json_object_get_object_member(view, "capture");
        int count = (int)json_array_get_length(rows);
        check(linux_ol_capture_v1(owner) && linux_ol_extended_family_v1(owner, rows, count) == 1, "paired history lost its original Local inventory");
        for (int position = 0; position < count; position++) {
            JsonObject *node = json_array_get_object_element(rows, position), *saved = json_array_get_object_element(receipts, position);
            check(linux_ol_bound_node_v1(node, position, count, owner, NULL, rows) &&
                  linux_ol_receipt_v1(saved, owner, node, count, TRUE, rows) && linux_ol_receipt_v1(saved, owner, node, count, FALSE, rows), "extended private fifty-sample receipt was hidden");
            check(!linux_ol_receipt_v1(saved, owner, node, count, TRUE, NULL), "extended private receipt borrowed an absent original inventory");
            JsonNode *copy = fixture_copy(json_array_get_element(rows, position));
            check(!linux_ol_bound_node_v1(json_node_get_object(copy), position, count, owner, NULL, rows), "extended private receipt borrowed another indexed source object");json_node_free(copy);
            copy = fixture_copy(json_array_get_element(receipts, position));JsonObject *bad = json_node_get_object(copy);
            JsonObject *distribution = linux_ol_object_v1(linux_ol_object_v1(linux_ol_object_v1(bad, "result"), "benchmark"), "distribution");
            json_object_set_double_member(distribution, "max_ms", 2001);
            check(!linux_ol_receipt_v1(bad, owner, node, count, TRUE, rows), "extended private receipt borrowed a public latency budget");json_node_free(copy);
        }
        JsonObject *late = json_array_get_object_element(rows, count - 2), *entry = json_array_get_object_element(rows, 0);
        json_object_set_string_member(late, "kind", "public-path");
        check(linux_ol_extended_family_v1(owner, rows, count) < 0 && !linux_ol_bound_node_v1(entry, 0, count, owner, NULL, rows), "extended receipt accepted a mixed private/public family");
        json_object_set_string_member(late, "kind", "private-node");
        json_object_set_int_member(owner, "extended_local_nodes", count - 1);
        check(!linux_ol_bound_node_v1(entry, 0, count, owner, NULL, rows), "extended private receipt truncated the captured node count");
        json_object_set_int_member(owner, "extended_local_nodes", count);
    }
    JsonArray *mixed = json_object_get_array_member(root, "mixed_extended");
    check(json_array_get_length(mixed) == 9, "complete extended mixed receipt inventory");
    for (guint c = 0; c < json_array_get_length(mixed); c++) {
        JsonObject *item = json_array_get_object_element(mixed, c), *view = json_object_get_object_member(item, "info");
        JsonArray *rows = json_object_get_array_member(view, "nodes"), *receipts = json_object_get_array_member(item, "receipts");
        JsonObject *owner = json_object_get_object_member(view, "capture");
        int count = (int)json_array_get_length(rows), prefixes = (int)json_object_get_int_member(owner, "paired_prefix_nodes");
        check(linux_ol_capture_v1(owner) && linux_ol_extended_family_v1(owner, rows, count) == 2, "mixed history lost its original Local prefix boundary");
        for (int position = 0; position < count; position++) {
            JsonObject *node = json_array_get_object_element(rows, position), *saved = json_array_get_object_element(receipts, position);
            check(linux_ol_bound_node_v1(node, position, count, owner, NULL, rows) &&
                  linux_ol_receipt_v1(saved, owner, node, count, TRUE, rows) && linux_ol_receipt_v1(saved, owner, node, count, FALSE, rows), "mixed receipt lost a private packet or imported public result");
            check(!linux_ol_receipt_v1(saved, owner, node, count, TRUE, NULL), "mixed receipt borrowed an absent complete inventory");
            JsonNode *copy = fixture_copy(json_array_get_element(rows, position));
            check(!linux_ol_bound_node_v1(json_node_get_object(copy), position, count, owner, NULL, rows), "mixed receipt borrowed a copied indexed row");json_node_free(copy);
        }
        JsonNode *copy = fixture_copy(json_object_get_member(view, "capture"));JsonObject *bad = json_node_get_object(copy);
        json_object_set_int_member(bad, "paired_prefix_nodes", prefixes + 1);
        check(!linux_ol_same_capture_v1(owner, bad) && linux_ol_extended_family_v1(bad, rows, count) < 0, "mixed history accepted a changed private prefix boundary");
        json_object_remove_member(bad, "paired_prefix_nodes");
        check(!linux_ol_same_capture_v1(owner, bad), "mixed capture silently discarded its original prefix boundary");
        if (prefixes > 1) check(linux_ol_extended_family_v1(bad, rows, count) < 0, "mixed receipt borrowed the old all-import family");
        json_object_set_boolean_member(bad, "paired_prefix_nodes", TRUE);check(!linux_ol_capture_v1(bad), "mixed capture accepted a boolean prefix count");
        json_object_set_string_member(bad, "paired_prefix_nodes", "2");check(!linux_ol_capture_v1(bad), "mixed capture accepted a string prefix count");
        json_object_set_double_member(bad, "paired_prefix_nodes", 2.0);check(!linux_ol_capture_v1(bad), "mixed capture accepted a non-integer JSON prefix count");
        json_object_set_int_member(bad, "paired_prefix_nodes", 0);check(!linux_ol_capture_v1(bad), "mixed capture accepted a missing packet prefix");
        json_object_set_int_member(bad, "paired_prefix_nodes", count - 1);check(!linux_ol_capture_v1(bad), "mixed capture accepted a route with no imported interior");
        json_object_set_int_member(bad, "paired_prefix_nodes", prefixes);json_object_set_string_member(bad, "selected_capture", "{}");
        check(!linux_ol_capture_v1(bad), "mixed capture borrowed selected-execution authority");json_node_free(copy);
        JsonObject *first_import = json_array_get_object_element(rows, prefixes);
        json_object_set_string_member(first_import, "kind", "private-node");
        check(linux_ol_extended_family_v1(owner, rows, count) < 0, "mixed capture accepted a private member inside its imported suffix");
        json_object_set_string_member(first_import, "kind", "public-path");
    }
    JsonObject *info = json_object_get_object_member(root, "info"), *capture = json_object_get_object_member(info, "capture");
    JsonArray *nodes = json_object_get_array_member(info, "nodes");
    for (int position = 0; position < 3; position++) {
        char key[32];g_snprintf(key, sizeof(key), "receipt%d", position);
        check(linux_ol_receipt_v1(json_object_get_object_member(root, key), capture, json_array_get_object_element(nodes, position), 3, TRUE, NULL), "original imported-middle receipt retained");
    }

    JsonArray *selected = json_object_get_array_member(root, "selected");
    check(json_array_get_length(selected) == 26, "both selected paths keep every private and imported layout");
    for (guint c = 0; c < json_array_get_length(selected); c++) {
        JsonObject *item = json_array_get_object_element(selected, c), *selected_info = json_object_get_object_member(item, "info");
        JsonObject *owner = json_object_get_object_member(selected_info, "capture");
        JsonArray *rows = json_object_get_array_member(selected_info, "nodes"), *receipts = json_object_get_array_member(item, "receipts");
        int count = (int)json_array_get_length(rows);
        if (c >= 16) {
            JsonNode *native=linux_ol_selected_v1(owner);
            check(native!=NULL,"multiple-import selected inventory refused");
            JsonObject *metadata=linux_ol_object_v1(json_node_get_object(native),"multiple_imported");
            JsonArray *public=linux_ol_array_v1(metadata,"public");
            JsonNode *wrong=fixture_copy(json_object_get_member(selected_info,"capture"));
            JsonObject *copy=json_node_get_object(wrong);
            json_object_set_int_member(json_array_get_object_element(public,0),"position",0);
            char *text=json_to_string(native,FALSE);json_object_set_string_member(copy,"selected_capture",text);g_free(text);
            check(!linux_ol_capture_v1(copy),"selected inventory admitted an imported seal at the wrong position");
            json_object_remove_member(json_node_get_object(native),"multiple_imported");
            text=json_to_string(native,FALSE);json_object_set_string_member(copy,"selected_capture",text);g_free(text);
            check(!linux_ol_capture_v1(copy),"legacy selected inventory borrowed independently imported positions");
            json_node_free(wrong);json_node_free(native);
        }
        for (int position = 0; position < count; position++) {
            JsonObject *node = json_array_get_object_element(rows, position), *saved = json_array_get_object_element(receipts, position);
            check(linux_ol_bound_node_v1(node, position, count, owner, NULL, rows), "canonical selected node retained");
            check(linux_ol_receipt_v1(saved, owner, node, count, TRUE, NULL) && linux_ol_receipt_v1(saved, owner, node, count, FALSE, NULL), "selected current and history receipt retained");
            JsonNode *without = fixture_copy(json_object_get_member(selected_info, "capture"));
            JsonObject *uncaptured = json_node_get_object(without);
            json_object_remove_member(uncaptured, "selected_capture");
            check(!linux_ol_receipt_v1(saved, uncaptured, node, count, TRUE, NULL) && !linux_ol_receipt_v1(saved, uncaptured, node, count, FALSE, NULL), "selected receipt requires original facade");
            json_node_free(without);
            const char *digests[] = {"source_sha256", "config_sha256", "generation_sha256"};
            for (guint d=0; d<G_N_ELEMENTS(digests); d++) {
                JsonNode *changed = fixture_copy(json_object_get_member(selected_info, "capture"));
                JsonObject *bad_owner = json_node_get_object(changed);
                json_object_set_string_member(bad_owner, digests[d], "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
                check(!linux_ol_capture_v1(bad_owner), "selected facade binds each original digest");
                json_node_free(changed);
            }
            const char *prefixes[] = {"Cumulative path", "Cumulative local path", "Cumulative server path"};
            const char *label = linux_ol_string_v1(node, "label"), *suffix = strstr(label, " path");
            check(suffix != NULL, "selected fixture has canonical path label");
            for (guint kind = 0; kind < G_N_ELEMENTS(prefixes); kind++) {
                char *other = g_strconcat(prefixes[kind], suffix+5, NULL);
                if (strcmp(other, label)) {
                    JsonNode *copy = fixture_copy(json_array_get_element(receipts, position));
                    JsonObject *bad = json_node_get_object(copy);
                    json_object_set_string_member(linux_ol_object_v1(bad, "result"), "label", other);
                    check(!linux_ol_receipt_v1(bad, owner, node, count, TRUE, NULL), "current receipt cannot borrow another selected label");
                    check(!linux_ol_receipt_v1(bad, owner, node, count, FALSE, NULL), "history cannot borrow another selected label");
                    json_node_free(copy);
                }
                g_free(other);
            }
            JsonNode *copy = fixture_copy(json_array_get_element(rows, position));
            char *unknown = g_strconcat("Cumulative auto path", suffix+5, NULL);
            json_object_set_string_member(json_node_get_object(copy), "label", unknown);
            check(!fixture_unbound_node(json_node_get_object(copy), position, count), "unknown selected label refused");
            g_free(unknown);json_node_free(copy);
        }
    }

    g_object_unref(parser);
    printf("Shipping C receipt validators: %d PASS (no GTK widgets/native tunnel)\n", checks);
    return 0;
}
