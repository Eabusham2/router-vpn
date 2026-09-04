/* Shipping Linux AUTO/SMART requirement controls.
 * Kept separate from the mature profile-settings include so the product can
 * add schema-v4 candidate filters without duplicating or rewriting node secrets.
 */
static void on_linux_auto_requirements_v11(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    Buffer out = {0};
    char *err = NULL;
    if (!api_request("/api/profile/settings", "GET", NULL, 5000, &out, &err)) {
        append_diag(app, err != NULL ? err : "AUTO / SMART requirements unavailable.");
        g_free(err); free(out.data); return;
    }
    JsonNode *root = parse_json(out.data);
    if (root == NULL || !JSON_NODE_HOLDS_OBJECT(root)) {
        append_diag(app, "AUTO / SMART requirements returned invalid JSON.");
        if (root != NULL) json_node_free(root);
        g_free(err); free(out.data); return;
    }
    JsonObject *settings = json_node_get_object(root);
    gboolean require_encrypted = json_object_has_member(settings, "auto_require_encrypted")
        && json_object_get_boolean_member(settings, "auto_require_encrypted");
    gboolean require_obfuscation = json_object_has_member(settings, "auto_require_obfuscation")
        && json_object_get_boolean_member(settings, "auto_require_obfuscation");

    GtkWidget *dialog = gtk_dialog_new_with_buttons(
        "AUTO / SMART requirements", GTK_WINDOW(app->window),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "Cancel", GTK_RESPONSE_CANCEL,
        "Save requirements", GTK_RESPONSE_OK,
        NULL);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 560, 300);
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 9);
    gtk_container_set_border_width(GTK_CONTAINER(box), 16);
    GtkWidget *note = gtk_label_new(
        "These schema-v4 filters apply before AUTO/SMART connection attempts. "
        "SMART simplification cannot drop below an enabled requirement. Both are Off by default. "
        "Disconnect before saving; the controller rejects connected/transition mutations.");
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(note), TRUE);
    gtk_box_pack_start(GTK_BOX(box), note, FALSE, FALSE, 0);
    GtkWidget *encrypted = gtk_check_button_new_with_label("Require encrypted AUTO candidates");
    GtkWidget *obfuscated = gtk_check_button_new_with_label("Require obfuscation for AUTO candidates");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(encrypted), require_encrypted);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(obfuscated), require_obfuscation);
    gtk_box_pack_start(GTK_BOX(box), encrypted, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), obfuscated, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(content), box, TRUE, TRUE, 0);
    gtk_widget_show_all(dialog);

    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_OK) {
        JsonBuilder *builder = json_builder_new();
        json_builder_begin_object(builder);
        json_builder_set_member_name(builder, "auto_require_encrypted");
        json_builder_add_boolean_value(builder, gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(encrypted)));
        json_builder_set_member_name(builder, "auto_require_obfuscation");
        json_builder_add_boolean_value(builder, gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(obfuscated)));
        json_builder_end_object(builder);
        JsonNode *payload_root = json_builder_get_root(builder);
        JsonGenerator *gen = json_generator_new();
        json_generator_set_root(gen, payload_root);
        char *payload = json_generator_to_data(gen, NULL);
        Buffer saved = {0}; char *save_err = NULL;
        if (api_request("/api/profile/settings", "POST", payload, 8000, &saved, &save_err)) {
            append_diag(app, "AUTO / SMART requirements saved for the selected Router VPN node; saved policy is not runtime proof.");
        } else {
            append_diag(app, save_err != NULL ? save_err : "AUTO / SMART requirement save failed.");
        }
        free(saved.data); g_free(save_err); g_free(payload);
        json_node_free(payload_root); g_object_unref(gen); g_object_unref(builder);
    }
    gtk_widget_destroy(dialog);
    json_node_free(root); g_free(err); free(out.data);
    refresh_home_summary_v6(app);
}

/* The canonical builder composes this include before routervpn-unified-shell-v8.inc.
 * Keep typed external-node creation on that real shipping path without forking
 * the mature unified shell source. */
#include "routervpn-external-node-wire-v14.inc"
