static void refresh_home_summary_v6(App *app) {
    if (app == NULL || app->detail == NULL) return;
    Buffer out = {0};
    char *err = NULL;
    if (!api_request("/api/home-summary", "GET", NULL, 5000, &out, &err)) {
        char *message = g_strdup_printf("Home state unavailable: %s", err != NULL ? err : "request failed");
        gtk_label_set_text(GTK_LABEL(app->detail), message);
        g_free(message);
        g_free(err);
        free(out.data);
        return;
    }
    JsonNode *root = parse_json(out.data);
    if (root == NULL || !JSON_NODE_HOLDS_OBJECT(root)) {
        gtk_label_set_text(GTK_LABEL(app->detail), "Home state unavailable: invalid controller response");
        if (root != NULL) json_node_free(root);
        g_free(err);
        free(out.data);
        return;
    }
    JsonObject *s = json_node_get_object(root);
    gboolean connected = json_object_has_member(s, "connected") && json_object_get_boolean_member(s, "connected");
    gboolean lan = json_object_has_member(s, "lan_access") && json_object_get_boolean_member(s, "lan_access");
    const char *exit_status = obj_string(s, "actual_exit_status");
    const char *actual_exit = obj_string(s, "actual_exit_ip");
    const char *exit_text = "Not connected";
    if (connected) exit_text = strcmp(exit_status, "proved") == 0 && actual_exit[0] != '\0' ? actual_exit : "Unproven — click Prove public VPN exit";

    double dns_latency = json_object_has_member(s, "dns_latency_ms") ? json_object_get_double_member(s, "dns_latency_ms") : 0.0;
    double node_latency = json_object_has_member(s, "node_latency_ms") ? json_object_get_double_member(s, "node_latency_ms") : 0.0;
    int node_samples = json_object_has_member(s, "node_latency_samples") ? (int)json_object_get_int_member(s, "node_latency_samples") : 0;
    int effective_mtu = json_object_has_member(s, "effective_mtu") ? (int)json_object_get_int_member(s, "effective_mtu") : 0;

    GString *text = g_string_new("");
    g_string_append_printf(text, "Node: %s • %s\nPublic endpoint: %s\nActual public VPN exit: %s\n",
        obj_string(s, "node_name"), obj_string(s, "location")[0] ? obj_string(s, "location") : "Location not labeled",
        obj_string(s, "public_endpoint"), exit_text);
    g_string_append_printf(text, "Connection: %s • path proof %s\nLogical/runtime/base: %s • %s • %s\nFallback: %s\n",
        obj_string(s, "connection_phase"), obj_string(s, "path_proof"), obj_string(s, "logical_mode"),
        obj_string(s, "actual_runtime"), obj_string(s, "actual_base"), obj_string(s, "fallback")[0] ? obj_string(s, "fallback") : "None");
    g_string_append_printf(text, "DNS: %s • %s • proof %s\n", obj_string(s, "dns_mode"), obj_string(s, "dns_host"), obj_string(s, "dns_status"));
    if (dns_latency > 0) g_string_append_printf(text, "DNS measured RTT: %.2f ms\n", dns_latency);
    else g_string_append(text, "DNS measured RTT: not measured / not proven\n");
    if (node_samples > 0) g_string_append_printf(text, "Node measured latency: %.2f ms / %d samples\n", node_latency, node_samples);
    else g_string_append(text, "Node measured latency: Not measured\n");
    g_string_append_printf(text, "LAN access: %s • Kill switch: %s\n", lan ? "On" : "Off", obj_string(s, "kill_switch"));
    if (effective_mtu > 0) {
        g_string_append_printf(text, "Effective MTU: %d", effective_mtu);
        if (obj_string(s, "effective_mtu_source")[0]) g_string_append_printf(text, " • %s", obj_string(s, "effective_mtu_source"));
    } else {
        g_string_append(text, "Effective MTU: Default / not measured");
    }
    g_string_append_printf(text, " • IPv6: %s • Auto-connect: %s\n", obj_string(s, "ipv6_mode"),
        json_object_has_member(s, "auto_connect") && json_object_get_boolean_member(s, "auto_connect") ? "On" : "Off");

    JsonArray *warnings = json_object_has_member(s, "warnings") ? json_object_get_array_member(s, "warnings") : NULL;
    g_string_append(text, "Warnings: ");
    if (warnings == NULL || json_array_get_length(warnings) == 0) g_string_append(text, "None");
    else for (guint i = 0; i < json_array_get_length(warnings); i++) {
        if (i > 0) g_string_append(text, " | ");
        g_string_append(text, json_array_get_string_element(warnings, i));
    }
    gtk_label_set_line_wrap(GTK_LABEL(app->detail), TRUE);
    gtk_label_set_selectable(GTK_LABEL(app->detail), TRUE);
    gtk_label_set_text(GTK_LABEL(app->detail), text->str);
    g_string_free(text, TRUE);
    json_node_free(root);
    g_free(err);
    free(out.data);
}

/* Shipping Home contract:
 * node location public endpoint actual public VPN exit connection phase logical mode
 * actual runtime actual base fallback DNS latency node latency LAN access kill switch
 * effective MTU warnings Connect Emergency Disconnect /api/home-summary
 */
