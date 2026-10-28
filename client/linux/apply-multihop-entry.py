#!/usr/bin/env python3
"""Compose exact Router entry selection after the frozen lifecycle/UI guards."""


def apply(text: str) -> str:
    changes = [
        ('    GtkWidget *execution;\n', '    GtkWidget *execution;\n    GtkWidget *entry_mode;\n'),
        ('    JsonArray *exit_modes;\n', '    JsonArray *exit_modes;\n    JsonArray *entry_modes;\n'),
        ('        linux_multihop_execution_supported_v22(gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->execution)));',
         '        linux_multihop_execution_supported_v22(gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->execution))) &&\n'
         '        linux_multihop_entry_advertised_v23(state->entry_modes, gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->entry_mode)));'),
        ('static void linux_multihop_execution_changed_v1(GtkComboBox *combo, gpointer data) {', '''static void linux_multihop_entry_changed_v23(GtkComboBox *combo, gpointer data) {
    LinuxMultihopDialogV7 *state = data;
    if (!routervpn_require_mutation_idle(state->app, "changing multihop entry transport")) {
        char *previous = linux_multihop_entry_choice_v23();
        g_signal_handlers_block_by_func(combo, G_CALLBACK(linux_multihop_entry_changed_v23), data);
        linux_multihop_select_preserving_v22(GTK_WIDGET(combo), previous);
        g_signal_handlers_unblock_by_func(combo, G_CALLBACK(linux_multihop_entry_changed_v23), data);
        g_free(previous); return;
    }
    linux_multihop_store_entry_v23(gtk_combo_box_get_active_id(combo));
    linux_multihop_update_summary_v7(state, NULL);
}

static void linux_multihop_execution_changed_v1(GtkComboBox *combo, gpointer data) {'''),
        ('    gtk_widget_set_sensitive(state->execution, !busy);\n',
         '    gtk_widget_set_sensitive(state->execution, !busy);\n    gtk_widget_set_sensitive(state->entry_mode, !busy);\n'),
        ('    g_clear_pointer(&state->exit_modes, json_array_unref);\n', '''    g_clear_pointer(&state->entry_modes, json_array_unref);
    JsonNode *entry_modes = json_object_get_member(obj, "supported_entry_modes");
    if (entry_modes != NULL && JSON_NODE_HOLDS_ARRAY(entry_modes)) state->entry_modes = json_array_ref(json_node_get_array(entry_modes));
    char *selected_entry_mode = g_strdup(gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->entry_mode)));
    g_signal_handlers_block_by_func(state->entry_mode, G_CALLBACK(linux_multihop_entry_changed_v23), state);
    linux_multihop_entry_choices_v23(state->entry_mode, state->entry_modes, selected_entry_mode);
    g_signal_handlers_unblock_by_func(state->entry_mode, G_CALLBACK(linux_multihop_entry_changed_v23), state);
    g_free(selected_entry_mode);
    g_clear_pointer(&state->exit_modes, json_array_unref);
'''),
        ('    json_builder_set_member_name(builder, "exit_mode"); json_builder_add_string_value(builder, mode);\n',
         '    json_builder_set_member_name(builder, "exit_mode"); json_builder_add_string_value(builder, mode);\n'
         '    const char *entry_mode = gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->entry_mode));\n'
         '    json_builder_set_member_name(builder, "entry_mode"); json_builder_add_string_value(builder, entry_mode);\n'),
        ('    state.execution = gtk_combo_box_text_new();\n', '''    state.entry_mode = gtk_combo_box_text_new();
    char *saved_entry_mode = linux_multihop_entry_choice_v23();
    linux_multihop_entry_choices_v23(state.entry_mode, NULL, saved_entry_mode); g_free(saved_entry_mode);
    g_signal_connect(state.entry_mode, "changed", G_CALLBACK(linux_multihop_entry_changed_v23), &state);
    state.execution = gtk_combo_box_text_new();
'''),
        ('    profile_settings_grid_row_v7(grid, 3, "Execution", state.execution);\n',
         '    profile_settings_grid_row_v7(grid, 3, "Execution", state.execution);\n'
         '    profile_settings_grid_row_v7(grid, 4, "Entry transport", state.entry_mode);\n'),
        ('    g_clear_pointer(&state.exit_modes, json_array_unref);\n',
         '    g_clear_pointer(&state.exit_modes, json_array_unref);\n    g_clear_pointer(&state.entry_modes, json_array_unref);\n'),
        ('Select a supported exit transport and two currently linked nodes; refresh if capabilities changed.',
         'Select supported entry and exit transports and two currently linked nodes; refresh if capabilities changed.'),
    ]
    for before, after in changes:
        if text.count(before) != 1:
            raise RuntimeError('Router entry UI composition seam changed: '+before[:100])
        text = text.replace(before, after, 1)
    return text
