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
# Saved ordinary Tor entries reopen through the reviewed protocol-aware helper.
# Tor Compare admission and its explanatory labels also follow these insertions.
# Those additions follow every insertion below; their guard positions are intact.
# Most used adds one callback before all five guards and its button after them.
# Saved lowest selection now uses one atomic endpoint. Keep preflight and
# immediate-before-POST idle checks; move subsequent guards past the removed
# client-side GET/filter/select sequence. Exact source hashing still applies.
base.SPECS['routervpn-gtk-product-v4.c'] = ('ac9c86c07064d41fe0b46e5f3225416485d86bc481e1d1ad51dde79c395c4886',
 [(85,
   85,
   [],
   ['    if (!routervpn_require_mutation_idle(app, "selecting the lowest-latency node")) return;\n']),
  (87,
   87,
   [],
   ['    if (!routervpn_require_mutation_idle(app, "committing the lowest-latency node selection")) return;\n']),
  (99,
   99,
   [],
   ['    if (!routervpn_require_mutation_idle(app, "importing a Router or external node")) return;\n']),
  (116,
   116,
   [],
   ['        } else if (!routervpn_require_mutation_idle(app, "committing Router or external node import")) '
    '{\n',
    '            append_diag(app, "Import cancelled because VPN state changed while the file picker was '
    'open.");\n']),
  (159,
   159,
   [],
   ['    if (!routervpn_require_mutation_idle(app, "starting an external connection")) return;\n'])])
base.SPECS['routervpn-unified-shell-v8.inc'] = ('93acb4605c44dc779265cb719f73b5bdefa7a828bd9880045e5b8702c124fa17',
 [(183,
   183,
   [],
   ['    if (!routervpn_require_mutation_idle(state->app, "editing CUSTOM presets")) { '
    'linux_unified_refresh_mode_combo_v8(state); return; }\n']),
  (199,
   199,
   [],
   ['        if (!routervpn_require_mutation_idle(state->app, "deleting a CUSTOM preset")) { '
    'gtk_widget_destroy(dialog); g_ptr_array_unref(checks); g_hash_table_unref(old); g_free(editing); '
    'g_free(old_layers); linux_unified_refresh_mode_combo_v8(state); return; }\n']),
  (201,
   201,
   [],
   ['        if (!routervpn_require_mutation_idle(state->app, "saving a CUSTOM preset")) { '
    'gtk_widget_destroy(dialog); g_ptr_array_unref(checks); g_hash_table_unref(old); g_free(editing); '
    'g_free(old_layers); linux_unified_refresh_mode_combo_v8(state); return; }\n']),
  (211,
   211,
   [],
   ['    if (!routervpn_require_mutation_idle(state->app, "changing the selected mode")) { '
    'linux_unified_refresh_mode_combo_v8(state); return; }\n']),
  (233,
   235,
   ['    (void)button; LinuxUnifiedV8 *state=data; Buffer out={0};char *err=NULL;gboolean active=FALSE;\n',
    '    if(api_request("/api/status","GET",NULL,4000,&out,&err)){JsonNode '
    '*root=parse_json(out.data);if(root!=NULL&&JSON_NODE_HOLDS_OBJECT(root)){JsonObject '
    '*obj=json_node_get_object(root);gboolean '
    'connected=json_object_has_member(obj,"connected")&&json_object_get_boolean_member(obj,"connected");const '
    'char '
    '*phase=obj_string(obj,"phase");active=connected||g_str_has_prefix(phase,"starting")||g_str_has_prefix(phase,"checking")||strstr(phase,"trying")!=NULL||strstr(phase,"proving")!=NULL;json_node_free(root);}}g_free(err);free(out.data);\n'],
   ['    (void)button; LinuxUnifiedV8 *state=data; Buffer out={0}; char *err=NULL; gboolean status_ok=FALSE, '
    'active=FALSE, disconnecting=FALSE;\n',
    '    if(api_request("/api/status","GET",NULL,4000,&out,&err)){JsonNode '
    '*root=parse_json(out.data);if(root!=NULL&&JSON_NODE_HOLDS_OBJECT(root)){JsonObject '
    '*obj=json_node_get_object(root);const char '
    '*phase=obj_string(obj,"phase");status_ok=TRUE;active=routervpn_mutation_busy_from_status(obj);disconnecting=routervpn_phase_disconnecting(phase);json_node_free(root);}}g_free(err);free(out.data);\n',
    '    if(!status_ok){append_diag(state->app,"Status unavailable; refusing to change the live '
    'session.");return;}\n',
    '    if(disconnecting){append_diag(state->app,"Disconnect already in progress.");return;}\n']),
  (236,
   237,
   ['    char *external_body=NULL;int '
    'selected_kind=linux_unified_selected_external_v8(state->app,gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->node)),&external_body);if(selected_kind<0){append_diag(state->app,"The '
    'selected node or captured revision is unavailable. Refresh the node list and local '
    'controller.");return;}if(selected_kind==1){post_and_log(state->app,"/api/external-profile/connect",external_body,180000,"Custom/external '
    'exit");g_free(external_body);return;}g_free(external_body);\n'],
   ['    if(!routervpn_require_mutation_idle(state->app,"starting a new connection"))return;\n',
    '    char *external_body=NULL;int '
    'selected_kind=linux_unified_selected_external_v8(state->app,gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->node)),&external_body);if(selected_kind<0){append_diag(state->app,"The '
    'selected node or captured revision is unavailable. Refresh the node list and local '
    'controller.");return;}if(selected_kind==1){if(!routervpn_require_mutation_idle(state->app,"starting a '
    'Custom/external '
    'exit")){g_free(external_body);return;}post_and_log(state->app,"/api/external-profile/connect",external_body,180000,"Custom/external '
    'exit");g_free(external_body);return;}g_free(external_body);\n']),
  (239,
   239,
   [],
   ['    if(!routervpn_require_mutation_idle(state->app,"starting the selected mode"))return;\n']),
  (279,
   280,
   ['    LinuxUnifiedV8 *state=data;if(state==NULL||state->syncing)return;const char '
    "*id=gtk_combo_box_get_active_id(combo);if(id==NULL||id[0]=='\\0')return;char "
    '*body=json_string_body("id",id);post_and_log(state->app,"/api/profile/select",body,12000,"Node '
    'selection");g_free(body);refresh_all(state->app);\n'],
   ['    LinuxUnifiedV8 '
    '*state=data;if(state==NULL||state->syncing)return;if(!routervpn_require_mutation_idle(state->app,"selecting '
    'another Router VPN node")){linux_unified_refresh_v8(state);return;}const char '
    "*id=gtk_combo_box_get_active_id(combo);if(id==NULL||id[0]=='\\0')return;char "
    '*body=json_string_body("id",id);post_and_log(state->app,"/api/profile/select",body,12000,"Node '
    'selection");g_free(body);refresh_all(state->app);\n']),
  (283,
   284,
   ['    Buffer out={0};char *err=NULL;if(api_request("/api/status","GET",NULL,3500,&out,&err)){JsonNode '
    '*root=parse_json(out.data);if(root!=NULL&&JSON_NODE_HOLDS_OBJECT(root)){JsonObject '
    '*obj=json_node_get_object(root);gboolean '
    'connected=json_object_has_member(obj,"connected")&&json_object_get_boolean_member(obj,"connected");const '
    'char *phase=obj_string(obj,"phase");gboolean '
    'transition=g_str_has_prefix(phase,"starting")||g_str_has_prefix(phase,"checking")||strstr(phase,"trying")!=NULL||strstr(phase,"proving")!=NULL;gtk_button_set_label(GTK_BUTTON(state->connect),(connected||transition)?"Disconnect":"Connect");char '
    '*text=g_strdup_printf("%s • logical %s • runtime %s • base '
    '%s",phase[0]?phase:"disconnected",obj_string(obj,"logical_mode"),obj_string(obj,"runtime_mode"),obj_string(obj,"base"));gtk_label_set_text(GTK_LABEL(state->status),text);g_free(text);json_node_free(root);}}g_free(err);free(out.data);\n'],
   ['    gboolean status_ok=FALSE,busy=TRUE,disconnecting=FALSE;Buffer out={0};char '
    '*err=NULL;if(api_request("/api/status","GET",NULL,3500,&out,&err)){JsonNode '
    '*root=parse_json(out.data);if(root!=NULL&&JSON_NODE_HOLDS_OBJECT(root)){JsonObject '
    '*obj=json_node_get_object(root);const char '
    '*phase=obj_string(obj,"phase");status_ok=TRUE;busy=routervpn_mutation_busy_from_status(obj);disconnecting=routervpn_phase_disconnecting(phase);gtk_button_set_label(GTK_BUTTON(state->connect),disconnecting?"Disconnecting…":busy?"Disconnect":"Connect");char '
    '*text=g_strdup_printf("%s • logical %s • runtime %s • base '
    '%s",g_str_has_prefix(phase,"candidate:")?"Testing saved path":phase[0]?phase:"disconnected",obj_string(obj,"logical_mode"),obj_string(obj,"runtime_mode"),obj_string(obj,"base"));gtk_label_set_text(GTK_LABEL(state->status),text);g_free(text);json_node_free(root);}}g_free(err);free(out.data);if(!status_ok){gtk_button_set_label(GTK_BUTTON(state->connect),"Checking…");gtk_label_set_text(GTK_LABEL(state->status),"Controller/status '
    'unavailable • session mutation '
    'locked");busy=TRUE;}gtk_widget_set_sensitive(state->connect,status_ok&&!disconnecting);gtk_widget_set_sensitive(state->node,!busy);gtk_widget_set_sensitive(state->kill_switch,!busy);gtk_widget_set_sensitive(state->multihop,!busy);gtk_widget_set_sensitive(state->mode,!busy);gtk_widget_set_sensitive(state->dns,!busy);\n'])])

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

# Bind the Settings form to the displayed router before constructing its controls.
# The captured revision and selection check precede the three dialog guards.
base.SPECS['routervpn-profile-settings-v1.inc'] = ('41f78b1a9d6ccfda47c931e982c65e9f3ffdf0d2ce880cbffdc1c75ac02ec893', [(264, 264, [], ['    if (!routervpn_require_mutation_idle(state->app, "starting multihop")) { linux_multihop_update_summary_v7(state, "Disconnect Router VPN or let the active transition finish before changing the live route graph."); return; }\n']), (476, 476, [], ['    gboolean mutation_busy = routervpn_mutation_busy(app);\n']), (567, 567, [], ['    GtkWidget *save_button = gtk_dialog_get_widget_for_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);\n', '    GtkWidget *mutable_widgets[] = {multihop, lan, kill, ipv6, base, fallback, mtu, manual, daita, jumbo, socks, startup, autoconnect};\n', '    for (guint i = 0; i < G_N_ELEMENTS(mutable_widgets); i++) gtk_widget_set_sensitive(mutable_widgets[i], !mutation_busy);\n', '    if (save_button != NULL) gtk_widget_set_sensitive(save_button, !mutation_busy);\n', '    if (mutation_busy) gtk_label_set_text(GTK_LABEL(note), "Connected/transitioning: settings are read-only. Disconnect Router VPN or let the active transition finish before saving persistent node policy.");\n', '\n']), (572, 572, [], ['        if (!routervpn_require_mutation_idle(app, "saving persistent node settings")) { gtk_widget_destroy(dialog); json_node_free(root); g_free(err); free(out.data); refresh_home_summary_v6(app); return; }\n'])])

# Captured public source catalog is retained by the actual node renderer.
base.SPECS['routervpn-gtk-product.c'] = ('a1f087cb2260183b8f75320d177336f2578ee07801f697c32fa9e4852a1220de',
 [(262,
   262,
   [],
   ['static gboolean routervpn_phase_busy(const char *phase) {\n',
    "    if (phase == NULL || phase[0] == '\\0') return FALSE;\n",
    '    char *lower = g_ascii_strdown(phase, -1);\n',
    '    gboolean busy = strstr(lower, "connecting") != NULL || strstr(lower, "starting") != NULL ||\n',
    '        strstr(lower, "checking") != NULL || strstr(lower, "trying") != NULL ||\n',
    '        strstr(lower, "proving") != NULL || strstr(lower, "reasserting") != NULL ||\n',
    '        strstr(lower, "disconnecting") != NULL || strstr(lower, "stopping") != NULL ||\n',
    '        strstr(lower, "switching") != NULL || strstr(lower, "reconnecting") != NULL || g_str_has_prefix(lower, "candidate:");\n',
    '    g_free(lower);\n',
    '    return busy;\n',
    '}\n',
    '\n',
    'static gboolean routervpn_phase_disconnecting(const char *phase) {\n',
    "    if (phase == NULL || phase[0] == '\\0') return FALSE;\n",
    '    char *lower = g_ascii_strdown(phase, -1);\n',
    '    gboolean stopping = strstr(lower, "disconnecting") != NULL || strstr(lower, "stopping") != NULL;\n',
    '    g_free(lower);\n',
    '    return stopping;\n',
    '}\n',
    '\n',
    'static gboolean routervpn_mutation_busy_from_status(JsonObject *obj) {\n',
    '    if (obj == NULL) return TRUE;\n',
    '    gboolean connected = json_object_has_member(obj, "connected") && '
    'json_object_get_boolean_member(obj, "connected");\n',
    '    return connected || routervpn_phase_busy(obj_string(obj, "phase"));\n',
    '}\n',
    '\n',
    'static gboolean routervpn_mutation_busy(App *app) {\n',
    '    if(app&&app->window&&g_object_get_data(G_OBJECT(app->window),"linux-ordered-candidates-pending")!=NULL)return TRUE;\n',
    '    Buffer out = {0}; char *err = NULL; gboolean busy = TRUE;\n',
    '    if (api_request("/api/status", "GET", NULL, 3500, &out, &err)) {\n',
    '        JsonNode *root = parse_json(out.data);\n',
    '        if (root != NULL && JSON_NODE_HOLDS_OBJECT(root)) busy = '
    'routervpn_mutation_busy_from_status(json_node_get_object(root));\n',
    '        if (root != NULL) json_node_free(root);\n',
    '    }\n',
    '    g_free(err); free(out.data);\n',
    '    return busy;\n',
    '}\n',
    '\n',
    'static gboolean routervpn_require_mutation_idle(App *app, const char *action) {\n',
    '    if (!routervpn_mutation_busy(app)) return TRUE;\n',
    '    char *line = g_strdup_printf("Disconnect Router VPN or let the active transition finish before %s; '
    'live session identity and proof are immutable.", action != NULL ? action : "changing persistent session '
    'state");\n',
    '    append_diag(app, line);\n',
    '    gtk_label_set_text(GTK_LABEL(app->error), line);\n',
    '    g_free(line);\n',
    '    return FALSE;\n',
    '}\n',
    '\n']),
  (464,
   466,
   ['    (void)button;\n', '    post_and_log((App *)data, "/api/auto", "{}", 150000, "AUTO");\n'],
   ['    (void)button; App *app = data;\n',
    '    if (!routervpn_require_mutation_idle(app, "starting AUTO")) return;\n',
    '    post_and_log(app, "/api/auto", "{}", 150000, "AUTO");\n']),
  (495, 495, [], ['    if (!routervpn_require_mutation_idle(app, "starting the selected mode")) return;\n']),
  (511,
   511,
   [],
   ['    if (!routervpn_require_mutation_idle(app, "selecting another Router VPN node")) { '
    'refresh_profiles(app); return; }\n'])])

# The wrapper is both the shipping CLI and the importable compatibility API used
# by the authoritative session-mutation audit. Keep one mutation implementation:
# the frozen v1 apply() operates on the adjusted SPECS table above.
async_spec = importlib.util.spec_from_file_location("routervpn_linux_async_actions", HERE / "apply-async-actions.py")
if async_spec is None or async_spec.loader is None:
    raise SystemExit("cannot load Linux async action composition")
async_actions = importlib.util.module_from_spec(async_spec)
async_spec.loader.exec_module(async_actions)
poll_spec = importlib.util.spec_from_file_location("routervpn_linux_shell_refresh", HERE / "apply-periodic-refresh.py")
periodic = importlib.util.module_from_spec(poll_spec)
poll_spec.loader.exec_module(periodic)
# The owned retry helpers precede the original primary action. Retain every
# frozen mutation anchor and reject any other source change.
name = "routervpn-unified-shell-v8.inc"
_, changes = base.SPECS[name]
base.SPECS[name] = ("71f0e699aead35b7a390a35bc89303867b252d95897c0c3693e8ef719d532b28",
    [(i1 + (36 if i1 >= 233 else 0), i2 + (36 if i2 >= 233 else 0), old, new) for i1, i2, old, new in changes])
frozen_apply = base.apply



def _owned_stop_retry(path):
    text = path.read_text()
    def replace(old, new):
        nonlocal text
        if text.count(old) != 1:
            raise RuntimeError("Linux owned Stop retry composition drifted: " + old[:100])
        text = text.replace(old, new, 1)
    replace('    if (linux_async_stopping_v16(state->app)) return;', '    const char *captured_retry=g_object_get_data(G_OBJECT(state->connect),"routervpn-stop-retry-token");\n    if(captured_retry!=NULL){g_autofree char *token=g_strdup(captured_retry);linux_unified_retry_stop_v26(state,token);return;}\n    if (linux_async_stopping_v16(state->app)) return;')
    replace('gboolean status_ok=FALSE, active=FALSE, disconnecting=FALSE;', 'gboolean status_ok=FALSE, active=FALSE, disconnecting=FALSE; g_autofree char *retry_token=NULL;')
    replace('status_ok=TRUE;active=routervpn_mutation_busy_from_status(obj);', 'const char *retry=linux_stop_retry_token_v26(obj,&status_ok);retry_token=g_strdup(retry);active=routervpn_mutation_busy_from_status(obj)||g_object_get_data(G_OBJECT(state->app->window),"linux-ordered-candidates-pending")!=NULL;')
    replace('    if(active){post_and_log(state->app,"/api/disconnect","{}",30000,"Disconnect");return;}', '    if(retry_token!=NULL){linux_unified_retry_stop_v26(state,retry_token);return;}\n    if(active){post_and_log(state->app,"/api/disconnect","{}",30000,"Disconnect");return;}')
    replace('status_ok=TRUE;busy=routervpn_mutation_busy_from_status(obj);', 'const char *retry=linux_stop_retry_token_v26(obj,&status_ok);g_object_set_data_full(G_OBJECT(state->connect),"routervpn-stop-retry-token",g_strdup(retry),g_free);busy=routervpn_mutation_busy_from_status(obj)||retry!=NULL||!status_ok||g_object_get_data(G_OBJECT(state->app->window),"linux-ordered-candidates-pending")!=NULL;')
    replace('disconnecting?"Disconnecting…":busy?"Disconnect":"Connect"', 'disconnecting?"Disconnecting…":retry!=NULL?"Retry Disconnect":busy?"Disconnect":"Connect"')
    replace('if(!status_ok){gtk_button_set_label', 'if(!status_ok){g_object_set_data(G_OBJECT(state->connect),"routervpn-stop-retry-token",NULL);gtk_button_set_label')
    path.write_text(text)

def apply(src, dst):
    frozen_apply(src, dst)
    async_actions.apply(Path(dst))
    if Path(dst).name == "routervpn-gtk-product.c":
        text = Path(dst).read_text()
        old = 'static gboolean routervpn_mutation_busy_from_status(JsonObject *obj) {\n    if (obj == NULL) return TRUE;'
        new = old + '\n    if(json_object_has_member(obj,"stop_pending")){JsonNode *pending=json_object_get_member(obj,"stop_pending");if(!JSON_NODE_HOLDS_VALUE(pending)||json_node_get_value_type(pending)!=G_TYPE_BOOLEAN||json_node_get_boolean(pending))return TRUE;}'
        if text.count(old) != 1: raise RuntimeError("Linux pending Stop mutation guard drifted")
        Path(dst).write_text(periodic.core(text.replace(old,new,1)))
    if Path(dst).name == "routervpn-unified-shell-v8.inc":
        _owned_stop_retry(Path(dst))
        Path(dst).write_text(periodic.unified(Path(dst).read_text()))


base.apply = apply

# The authenticated native launch adds captured credentials before these
# existing session guards. Their exact text and rejection behavior are retained.
name = "routervpn-gtk-product.c"
_, changes = base.SPECS[name]
base.SPECS[name] = (
    '64c2473b72558d039e36fb7928ef7ed5971ede3df4a500ed0cde19f1c91210bf',
    [(i1 -2, i2 -2, old, new) for i1, i2, old, new in changes],
)

# Valid equator/prime-meridian coordinates may omit their zero-valued JSON
# component. The reviewed validity check adds three lines in each node reader;
# preserve every mutation guard and move only anchors after those expressions.
for name, expected, threshold in (
    ("routervpn-gtk-product.c", "968969d740722a0887d5b154629e9fefd3e4d667d8616c2a02ff5b767e418c67", 365),
    ("routervpn-gtk-product-v4.c", "b3f0b1115adee24be8e220034a98d9b0e204f0d6b2d77171b9475db49164f374", 46),
):
    _, changes = base.SPECS[name]
    base.SPECS[name] = (
        expected,
        [(i1 + (3 if i1 >= threshold else 0), i2 + (3 if i2 >= threshold else 0), old, new)
         for i1, i2, old, new in changes],
    )

if __name__ == "__main__":
    base.main()
