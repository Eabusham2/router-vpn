#!/usr/bin/env python3
"""Current Linux session-mutation transform layered over the frozen v1 table.

Two reviewed shipping-composition changes added three lines before every
routervpn-unified-shell-v8 session-mutation anchor: Tor added one include and one
handler; typed external nodes added one include. The exact-source SHA in v1 was
already updated to the resulting shell, so only those absolute anchor indices
move. All expected/replacement text remains unchanged and is still verified.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
V1 = HERE / "apply-session-mutation-v1.py"
spec = importlib.util.spec_from_file_location("routervpn_linux_session_mutation_v1", V1)
if spec is None or spec.loader is None:
    raise SystemExit("cannot load frozen Linux session mutation baseline")
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

name = "routervpn-unified-shell-v8.inc"
expected, changes = base.SPECS[name]
base.SPECS[name] = (
    expected,
    [(i1 + 3, i2 + 3, old, new) for i1, i2, old, new in changes],
)

# The explicit Direct action now emits a typed JSON boolean while the primary
# Connect action follows the saved path. Its 13 additional builder lines come
# after the Direct action's own guard and before the two via-entry guards.
# Keep the frozen guards and exact-source rejection; only their reviewed source
# identity and downstream insertion positions change.
name = "routervpn-gtk-product-v4.c"
_, changes = base.SPECS[name]
base.SPECS[name] = (
    "5421266644b6475980fa4c6d37ce4c14511b0d741c26242cef70539ea8e4f31a",
    [(i1 + (13 if i1 > 186 else 0), i2 + (13 if i2 > 186 else 0), old, new)
     for i1, i2, old, new in changes],
)

# Current external execution dialog and explicit primary choice.
# All earlier guards remain in the hardened target; exact source hashes and
# insertion text continue to reject unreviewed drift.
base.SPECS['routervpn-gtk-product-v4.c'] = ('cb77ac47292c390ecd2760c6887106c178da4f9d08ca66cdfca4fbaf768ece7d', [(83, 83, [], ['    if (!routervpn_require_mutation_idle(app, "selecting the lowest-latency node")) return;\n']), (109, 109, [], ['    } else if (!routervpn_require_mutation_idle(app, "committing the lowest-latency node selection")) {\n', '        append_diag(app, "Lowest-latency result discarded because VPN state changed during measurement.");\n']), (128, 128, [], ['    if (!routervpn_require_mutation_idle(app, "importing a Router or external node")) return;\n']), (145, 145, [], ['        } else if (!routervpn_require_mutation_idle(app, "committing Router or external node import")) {\n', '            append_diag(app, "Import cancelled because VPN state changed while the file picker was open.");\n']), (186, 186, [], ['    if (!routervpn_require_mutation_idle(app, "starting an external connection")) return;\n'])])
base.SPECS['routervpn-unified-shell-v8.inc'] = ('5be7ef822ff87ec8cd7082e4fc75e85691b1d31a9fa64f263831abd29e384610', [(183, 183, [], ['    if (!routervpn_require_mutation_idle(state->app, "editing CUSTOM presets")) { linux_unified_refresh_mode_combo_v8(state); return; }\n']), (199, 199, [], ['        if (!routervpn_require_mutation_idle(state->app, "deleting a CUSTOM preset")) { gtk_widget_destroy(dialog); g_ptr_array_unref(checks); g_hash_table_unref(old); g_free(editing); g_free(old_layers); linux_unified_refresh_mode_combo_v8(state); return; }\n']), (201, 201, [], ['        if (!routervpn_require_mutation_idle(state->app, "saving a CUSTOM preset")) { gtk_widget_destroy(dialog); g_ptr_array_unref(checks); g_hash_table_unref(old); g_free(editing); g_free(old_layers); linux_unified_refresh_mode_combo_v8(state); return; }\n']), (211, 211, [], ['    if (!routervpn_require_mutation_idle(state->app, "changing the selected mode")) { linux_unified_refresh_mode_combo_v8(state); return; }\n']), (240, 242, ['    (void)button; LinuxUnifiedV8 *state=data; Buffer out={0};char *err=NULL;gboolean active=FALSE;\n', '    if(api_request("/api/status","GET",NULL,4000,&out,&err)){JsonNode *root=parse_json(out.data);if(root!=NULL&&JSON_NODE_HOLDS_OBJECT(root)){JsonObject *obj=json_node_get_object(root);gboolean connected=json_object_has_member(obj,"connected")&&json_object_get_boolean_member(obj,"connected");const char *phase=obj_string(obj,"phase");active=connected||g_str_has_prefix(phase,"starting")||g_str_has_prefix(phase,"checking")||strstr(phase,"trying")!=NULL||strstr(phase,"proving")!=NULL;json_node_free(root);}}g_free(err);free(out.data);\n'], ['    (void)button; LinuxUnifiedV8 *state=data; Buffer out={0}; char *err=NULL; gboolean status_ok=FALSE, active=FALSE, disconnecting=FALSE;\n', '    if(api_request("/api/status","GET",NULL,4000,&out,&err)){JsonNode *root=parse_json(out.data);if(root!=NULL&&JSON_NODE_HOLDS_OBJECT(root)){JsonObject *obj=json_node_get_object(root);const char *phase=obj_string(obj,"phase");status_ok=TRUE;active=routervpn_mutation_busy_from_status(obj);disconnecting=routervpn_phase_disconnecting(phase);json_node_free(root);}}g_free(err);free(out.data);\n', '    if(!status_ok){append_diag(state->app,"Status unavailable; refusing to change the live session.");return;}\n', '    if(disconnecting){append_diag(state->app,"Disconnect already in progress.");return;}\n']), (243, 244, ['    char *external_id=NULL,*external_execution=NULL;int selected_kind=linux_unified_selected_external_v8(&external_id,&external_execution);if(selected_kind<0){append_diag(state->app,"The selected node is unavailable. Refresh the node list before connecting.");return;}if(selected_kind==1){char *body=json_external_hop_body(external_id,"",external_execution,FALSE);if(body!=NULL){post_and_log(state->app,"/api/external-profile/connect",body,180000,"Custom/external exit");g_free(body);}else append_diag(state->app,"The external node has an invalid saved execution choice.");g_free(external_execution);g_free(external_id);return;}g_free(external_execution);g_free(external_id);\n'], ['    if(!routervpn_require_mutation_idle(state->app,"starting a new connection"))return;\n', '    char *external_id=NULL,*external_execution=NULL;int selected_kind=linux_unified_selected_external_v8(&external_id,&external_execution);if(selected_kind<0){append_diag(state->app,"The selected node is unavailable. Refresh the node list before connecting.");return;}if(selected_kind==1){if(!routervpn_require_mutation_idle(state->app,"starting a Custom/external exit")){g_free(external_execution);g_free(external_id);return;}char *body=json_external_hop_body(external_id,"",external_execution,FALSE);if(body!=NULL){post_and_log(state->app,"/api/external-profile/connect",body,180000,"Custom/external exit");g_free(body);}else append_diag(state->app,"The external node has an invalid saved execution choice.");g_free(external_execution);g_free(external_id);return;}g_free(external_execution);g_free(external_id);\n']), (246, 246, [], ['    if(!routervpn_require_mutation_idle(state->app,"starting the selected mode"))return;\n']), (286, 287, ['    LinuxUnifiedV8 *state=data;if(state==NULL||state->syncing)return;const char *id=gtk_combo_box_get_active_id(combo);if(id==NULL||id[0]==\'\\0\')return;char *body=json_string_body("id",id);post_and_log(state->app,"/api/profile/select",body,12000,"Node selection");g_free(body);refresh_all(state->app);\n'], ['    LinuxUnifiedV8 *state=data;if(state==NULL||state->syncing)return;if(!routervpn_require_mutation_idle(state->app,"selecting another Router VPN node")){linux_unified_refresh_v8(state);return;}const char *id=gtk_combo_box_get_active_id(combo);if(id==NULL||id[0]==\'\\0\')return;char *body=json_string_body("id",id);post_and_log(state->app,"/api/profile/select",body,12000,"Node selection");g_free(body);refresh_all(state->app);\n']), (290, 291, ['    Buffer out={0};char *err=NULL;if(api_request("/api/status","GET",NULL,3500,&out,&err)){JsonNode *root=parse_json(out.data);if(root!=NULL&&JSON_NODE_HOLDS_OBJECT(root)){JsonObject *obj=json_node_get_object(root);gboolean connected=json_object_has_member(obj,"connected")&&json_object_get_boolean_member(obj,"connected");const char *phase=obj_string(obj,"phase");gboolean transition=g_str_has_prefix(phase,"starting")||g_str_has_prefix(phase,"checking")||strstr(phase,"trying")!=NULL||strstr(phase,"proving")!=NULL;gtk_button_set_label(GTK_BUTTON(state->connect),(connected||transition)?"Disconnect":"Connect");char *text=g_strdup_printf("%s • logical %s • runtime %s • base %s",phase[0]?phase:"disconnected",obj_string(obj,"logical_mode"),obj_string(obj,"runtime_mode"),obj_string(obj,"base"));gtk_label_set_text(GTK_LABEL(state->status),text);g_free(text);json_node_free(root);}}g_free(err);free(out.data);\n'], ['    gboolean status_ok=FALSE,busy=TRUE,disconnecting=FALSE;Buffer out={0};char *err=NULL;if(api_request("/api/status","GET",NULL,3500,&out,&err)){JsonNode *root=parse_json(out.data);if(root!=NULL&&JSON_NODE_HOLDS_OBJECT(root)){JsonObject *obj=json_node_get_object(root);const char *phase=obj_string(obj,"phase");status_ok=TRUE;busy=routervpn_mutation_busy_from_status(obj);disconnecting=routervpn_phase_disconnecting(phase);gtk_button_set_label(GTK_BUTTON(state->connect),disconnecting?"Disconnecting…":busy?"Disconnect":"Connect");char *text=g_strdup_printf("%s • logical %s • runtime %s • base %s",phase[0]?phase:"disconnected",obj_string(obj,"logical_mode"),obj_string(obj,"runtime_mode"),obj_string(obj,"base"));gtk_label_set_text(GTK_LABEL(state->status),text);g_free(text);json_node_free(root);}}g_free(err);free(out.data);if(!status_ok){gtk_button_set_label(GTK_BUTTON(state->connect),"Checking…");gtk_label_set_text(GTK_LABEL(state->status),"Controller/status unavailable • session mutation locked");busy=TRUE;}gtk_widget_set_sensitive(state->connect,status_ok&&!disconnecting);gtk_widget_set_sensitive(state->node,!busy);gtk_widget_set_sensitive(state->kill_switch,!busy);gtk_widget_set_sensitive(state->multihop,!busy);gtk_widget_set_sensitive(state->mode,!busy);gtk_widget_set_sensitive(state->dns,!busy);\n'])])

# Owned controller shutdown stores its immutable launch nonce and
# pending owner in App. All frozen mutation guards precede the new shutdown
# include; the two member lines and eight terminal-request guard lines move
# their exact source ranges by ten reviewed lines.
name = "routervpn-gtk-product.c"
_, changes = base.SPECS[name]
base.SPECS[name] = (
    "ac1a1c2a7660dbb49a68b85aaf2216c9e1a7920798a6d719e38b7126b687d806",
    [(i1 + 10, i2 + 10, old, new) for i1, i2, old, new in changes],
)

# The wrapper is both the shipping CLI and the importable compatibility API used
# by the authoritative session-mutation audit. Keep one mutation implementation:
# the frozen v1 apply() operates on the adjusted SPECS table above.
async_spec = importlib.util.spec_from_file_location("routervpn_linux_async_actions", HERE / "apply-async-actions.py")
if async_spec is None or async_spec.loader is None:
    raise SystemExit("cannot load Linux async action composition")
async_actions = importlib.util.module_from_spec(async_spec)
async_spec.loader.exec_module(async_actions)
frozen_apply = base.apply


def apply(src, dst):
    frozen_apply(src, dst)
    async_actions.apply(Path(dst))


base.apply = apply

if __name__ == "__main__":
    base.main()
