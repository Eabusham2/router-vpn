#!/usr/bin/env python3
"""Inject the native Linux Start Layer controls into the hardened Settings include.

This is deliberately an exact-anchor shipping transform: source drift fails the
native build instead of silently dropping the user-visible Start Layer policy.
"""
from __future__ import annotations

import sys
from pathlib import Path

if len(sys.argv) != 3:
    raise SystemExit("usage: apply-start-layer-settings.py INPUT OUTPUT")

source_path = Path(sys.argv[1])
out_path = Path(sys.argv[2])
text = source_path.read_text(encoding="utf-8")


def replace_once(old: str, new: str, label: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"Linux Start Layer settings {label} drifted: expected one anchor, got {count}")
    text = text.replace(old, new, 1)


replace_once(
    '    static const char *const base_labels[] = {"Auto", "WireGuard", "AmneziaWG"};\n'
    '    static const char *const base_ids[] = {"auto", "wg", "awg"};\n'
    '    static const char *const mtu_labels[] = {"Default", "Auto measured", "Manual"};',
    '    static const char *const base_labels[] = {"Auto", "WireGuard", "AmneziaWG"};\n'
    '    static const char *const base_ids[] = {"auto", "wg", "awg"};\n'
    '    static const char *const start_layer_labels[] = {"Off — default", "AES-256-GCM — authenticated", "AES-256-GCM + XOR whitening"};\n'
    '    static const char *const start_layer_ids[] = {"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"};\n'
    '    static const char *const mtu_labels[] = {"Default", "Auto measured", "Manual"};',
    "mode catalog",
)

replace_once(
    '    GtkWidget *fallback = gtk_check_button_new_with_label("Allow WG/AWG base fallback");\n'
    '    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(fallback), json_object_has_member(settings, "base_fallback") && json_object_get_boolean_member(settings, "base_fallback"));\n'
    '    gtk_box_pack_start(GTK_BOX(box), fallback, FALSE, FALSE, 0);\n\n'
    '    GtkWidget *mtu = profile_settings_combo_v7(mtu_labels, mtu_ids, G_N_ELEMENTS(mtu_ids), obj_string(settings, "mtu_policy"));\n'
    '    profile_settings_grid_row_v7(grid, 3, "MTU policy", mtu);',
    '    GtkWidget *fallback = gtk_check_button_new_with_label("Allow WG/AWG base fallback");\n'
    '    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(fallback), json_object_has_member(settings, "base_fallback") && json_object_get_boolean_member(settings, "base_fallback"));\n'
    '    gtk_box_pack_start(GTK_BOX(box), fallback, FALSE, FALSE, 0);\n\n'
    '    GtkWidget *start_layer = profile_settings_combo_v7(start_layer_labels, start_layer_ids, G_N_ELEMENTS(start_layer_ids), obj_string(settings, "start_layer"));\n'
    '    profile_settings_grid_row_v7(grid, 3, "Start Layer", start_layer);\n'
    '    GtkWidget *start_layer_note = gtk_label_new("AES uses vetted Shadowsocks 2022 BLAKE3 AES-256-GCM. AES+XOR keeps AES as the authenticated security boundary and only whitens the already-encrypted stream; XOR is never counted as encryption. Unsupported direct/multihop graphs fail closed rather than dropping the saved layer.");\n'
    '    gtk_label_set_xalign(GTK_LABEL(start_layer_note), 0.0f);\n'
    '    gtk_label_set_line_wrap(GTK_LABEL(start_layer_note), TRUE);\n'
    '    gtk_box_pack_start(GTK_BOX(box), start_layer_note, FALSE, FALSE, 0);\n\n'
    '    GtkWidget *mtu = profile_settings_combo_v7(mtu_labels, mtu_ids, G_N_ELEMENTS(mtu_ids), obj_string(settings, "mtu_policy"));\n'
    '    profile_settings_grid_row_v7(grid, 4, "MTU policy", mtu);',
    "picker insertion",
)

replace_once(
    '    profile_settings_grid_row_v7(grid, 4, "Manual MTU", manual);',
    '    profile_settings_grid_row_v7(grid, 5, "Manual MTU", manual);',
    "manual MTU row",
)
replace_once(
    '    profile_settings_grid_row_v7(grid, 5, "Startup behavior", startup);',
    '    profile_settings_grid_row_v7(grid, 6, "Startup behavior", startup);',
    "startup row",
)

replace_once(
    '            ADD_STR("base_tunnel", gtk_combo_box_get_active_id(GTK_COMBO_BOX(base)));\n'
    '            ADD_BOOL("base_fallback", gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(fallback)));\n'
    '            ADD_STR("mtu_policy", mtu_policy);',
    '            ADD_STR("base_tunnel", gtk_combo_box_get_active_id(GTK_COMBO_BOX(base)));\n'
    '            ADD_BOOL("base_fallback", gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(fallback)));\n'
    '            ADD_STR("start_layer", gtk_combo_box_get_active_id(GTK_COMBO_BOX(start_layer)));\n'
    '            ADD_STR("mtu_policy", mtu_policy);',
    "save payload",
)

replace_once(
    ' * LAN Off / kill switch / IPv6 / WG-AWG base+fallback / default-auto-manual MTU /\n'
    ' * DAITA-like / Jumbo TUN / SOCKS5 / startup/autoconnect.\n',
    ' * LAN Off / kill switch / IPv6 / WG-AWG base+fallback / authenticated AES/XOR-whitening Start Layer /\n'
    ' * default-auto-manual MTU / DAITA-like / Jumbo TUN / SOCKS5 / startup/autoconnect.\n',
    "shipping contract comment",
)

for marker in (
    '"/api/profile/settings"',
    '"Start Layer"',
    '"start_layer"',
    '"aes-256-gcm"',
    '"aes-256-gcm+xor-whitening"',
    'XOR is never counted as encryption',
    'Unsupported direct/multihop graphs fail closed',
):
    if marker not in text:
        raise SystemExit(f"Linux Start Layer settings missing post-transform marker: {marker}")

out_path.write_text(text, encoding="utf-8")
