#!/usr/bin/env python3
"""Attach routed candidate UI after the immutable session and execution guards."""

def apply(text: str) -> str:
    replacements = [
        ('    linux_multihop_refresh_v7(&state);\n',
         '    linux_multihop_refresh_v7(&state);\n    linux_candidates_bind_entry_v1(&state);\n'),
        ('static void on_linux_multihop_v7(GtkButton *button, gpointer data) {',
         '#include "routervpn-via-entry-candidates-v1.inc"\n\nstatic void on_linux_multihop_v7(GtkButton *button, gpointer data) {'),
        ('    gtk_box_pack_start(GTK_BOX(box), pick, FALSE, FALSE, 0);\n',
         '    gtk_box_pack_start(GTK_BOX(box), pick, FALSE, FALSE, 0);\n'
         '    gtk_box_pack_start(GTK_BOX(box), make_button("Measure exits via entry…", G_CALLBACK(on_linux_candidates_v1), &state), FALSE, FALSE, 0);\n'),
    ]
    for old, new in replacements:
        if text.count(old) != 1:
            raise RuntimeError("Routed candidate UI seam changed: " + old[:100])
        text = text.replace(old, new, 1)
    return text
