#include <sys/stat.h>

typedef struct {
    App *app;
    GtkWidget *stack;
    GtkWidget *legacy_notebook;
    GtkWidget *connect;
    GtkWidget *kill_switch;
    GtkWidget *multihop;
    GtkWidget *mode;
    GtkWidget *dns;
    GtkWidget *node;
    GtkWidget *status;
    GtkWidget *settings_summary;
    gboolean syncing;
} LinuxUnifiedV8;

// Forward declaration: callbacks above the refresh implementation may request an
// immediate UI refresh. Keep this explicit so -Werror never relies on an implicit
// function declaration on either amd64 or arm64 GTK builds.
static gboolean linux_unified_refresh_v8(gpointer data);

static const char *const linux_unified_mode_ids_v8[] = {
    "smart-auto","auto","base-raw","base-pq","awg-strong","shadowsocks","reality-vision","hysteria2",
    "reality-pq-vision","ss-v2ray","naive-h2","naive-h3","split","reality-xhttp","max","max-quic","max-tls","all",NULL
};
static const char *const linux_unified_mode_names_v8[] = {
    "SMART AUTO — recommended","AUTO — first proven path","Raw tunnel","Base tunnel + Rosenpass PQ","AmneziaWG Strong","Shadowsocks 2022","VLESS + REALITY + Vision","Hysteria2 + QUIC + Salamander",
    "PQ VLESS + REALITY + Vision","Shadowsocks + V2Ray TLS","Naive HTTPS HTTP/2","Naive HTTPS HTTP/3 + QUIC","Dual Transport","PQ REALITY + XHTTP + FinalMask","PQ Dual Transport","MAX QUIC","MAX TLS","ALL",NULL
};
static const char *const linux_custom_layers_v8[] = {
    "wireguard","amneziawg2","rosenpass-pq","light-obfuscation","strong-obfuscation","shadowsocks2022","vless","vless-pq","reality","xtls-vision","utls-chrome","hysteria2","quic","salamander","v2ray-plugin","websocket","tls","https","http2","http3","naive","xhttp","finalmask","protocol-split",NULL
};

static char *linux_unified_preset_path_v8(void) {
    char *dir = g_build_filename(g_get_user_config_dir(), "router-vpn", NULL);
    g_mkdir_with_parents(dir, 0700);
    char *path = g_build_filename(dir, "linux-custom-presets-v1.ini", NULL);
    g_free(dir);
    return path;
}
static GKeyFile *linux_unified_load_keyfile_v8(void) {
    GKeyFile *key = g_key_file_new();
    char *path = linux_unified_preset_path_v8();
    GError *error = NULL;
    if (!g_key_file_load_from_file(key, path, G_KEY_FILE_KEEP_COMMENTS, &error) && error != NULL) g_error_free(error);
    g_free(path);
    return key;
}
static void linux_unified_save_keyfile_v8(GKeyFile *key) {
    char *path = linux_unified_preset_path_v8();
    gsize length = 0; GError *error = NULL;
    char *data = g_key_file_to_data(key, &length, NULL);
    if (data != NULL && !g_file_set_contents(path, data, (gssize)length, &error) && error != NULL) g_error_free(error);
    if (data != NULL) { chmod(path, 0600); g_free(data); }
    g_free(path);
}
static char *linux_unified_selected_mode_v8(void) {
    GKeyFile *key = linux_unified_load_keyfile_v8();
    char *value = g_key_file_get_string(key, "state", "selected_mode", NULL);
    g_key_file_unref(key);
    if (value == NULL || value[0] == '\0') { g_free(value); return g_strdup("smart-auto"); }
    return value;
}
static void linux_unified_store_mode_v8(const char *mode) {
    GKeyFile *key = linux_unified_load_keyfile_v8();
    g_key_file_set_string(key, "state", "selected_mode", mode != NULL && mode[0] ? mode : "smart-auto");
    linux_unified_save_keyfile_v8(key); g_key_file_unref(key);
}

static void linux_unified_show_detail_v8(LinuxUnifiedV8 *state, int page) {
    if (state == NULL) return;
    gtk_notebook_set_current_page(GTK_NOTEBOOK(state->legacy_notebook), page);
    gtk_stack_set_visible_child_name(GTK_STACK(state->stack), "details");
}
static void linux_unified_back_v8(GtkButton *button, gpointer data) {
    (void)button; LinuxUnifiedV8 *state = data;
    gtk_stack_set_visible_child_name(GTK_STACK(state->stack), "map");
}
static void linux_unified_nodes_v8(GtkButton *button, gpointer data) { (void)button; linux_unified_show_detail_v8(data, 1); }
static void linux_unified_modes_v8(GtkButton *button, gpointer data) { (void)button; linux_unified_show_detail_v8(data, 2); }
static void linux_unified_dns_detail_v8(GtkButton *button, gpointer data) { (void)button; linux_unified_show_detail_v8(data, 3); }
static void linux_unified_settings_v8(GtkButton *button, gpointer data) { on_profile_settings_v7(button, ((LinuxUnifiedV8 *)data)->app); }
static void linux_unified_auto_requirements_v8(GtkButton *button, gpointer data) { LinuxUnifiedV8 *state=data; if(state!=NULL)on_linux_auto_requirements_v11(button,state->app); }
static void linux_unified_multihop_v8(GtkButton *button, gpointer data) { on_linux_multihop_v7(button, ((LinuxUnifiedV8 *)data)->app); }
static void linux_unified_mtu_v8(GtkButton *button, gpointer data) { (void)button; post_and_log(((LinuxUnifiedV8 *)data)->app, "/api/mtu/retest", "{}", 130000, "MTU Retest for current config/path"); }

static char *linux_unified_custom_layers_for_mode_v8(const char *mode) {
    if (mode == NULL || !g_str_has_prefix(mode, "custom:")) return NULL;
    const char *name = mode + strlen("custom:");
    GKeyFile *key = linux_unified_load_keyfile_v8();
    char *group = g_strdup_printf("preset:%s", name);
    char *layers = g_key_file_get_string(key, group, "layers", NULL);
    g_free(group); g_key_file_unref(key); return layers;
}
static void linux_unified_refresh_mode_combo_v8(LinuxUnifiedV8 *state) {
    if (state == NULL) return;
    char *wanted = linux_unified_selected_mode_v8();
    state->syncing = TRUE;
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(state->mode));
    Buffer out = {0}; char *err = NULL; JsonNode *root = NULL;
    if (api_request("/api/logical-modes", "GET", NULL, 8000, &out, &err)) root = parse_json(out.data);
    for (int i = 0; linux_unified_mode_ids_v8[i] != NULL; i++) {
        const char *id = linux_unified_mode_ids_v8[i]; const char *name = linux_unified_mode_names_v8[i];
        gboolean available = TRUE; const char *reason = "";
        if (strcmp(id, "smart-auto") != 0 && strcmp(id, "auto") != 0 && root != NULL && JSON_NODE_HOLDS_ARRAY(root)) {
            JsonArray *array = json_node_get_array(root); gboolean found = FALSE;
            for (guint j = 0; j < json_array_get_length(array); j++) {
                JsonObject *item = json_array_get_object_element(array, j); if (item == NULL || g_strcmp0(obj_string(item, "id"), id) != 0) continue;
                found = TRUE; available = !json_object_has_member(item, "available") || json_object_get_boolean_member(item, "available"); reason = obj_string(item, "reason"); break;
            }
            if (!found) available = FALSE;
        }
        char *label = available ? g_strdup(name) : g_strdup_printf("%s — unavailable%s%s", name, reason[0] ? ": " : "", reason);
        gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state->mode), id, label); g_free(label);
    }
    GKeyFile *key = linux_unified_load_keyfile_v8(); gsize groups_len = 0; char **groups = g_key_file_get_groups(key, &groups_len);
    for (gsize i = 0; groups != NULL && i < groups_len; i++) if (g_str_has_prefix(groups[i], "preset:")) {
        const char *name = groups[i] + strlen("preset:"); char *id = g_strdup_printf("custom:%s", name); char *label = g_strdup_printf("CUSTOM • %s", name);
        gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state->mode), id, label); g_free(id); g_free(label);
    }
    g_strfreev(groups); g_key_file_unref(key);
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state->mode), "custom:new", "New CUSTOM preset…");
    if (!gtk_combo_box_set_active_id(GTK_COMBO_BOX(state->mode), wanted)) gtk_combo_box_set_active_id(GTK_COMBO_BOX(state->mode), "smart-auto");
    state->syncing = FALSE;
    if (root != NULL) {
        json_node_free(root);
    }
    g_free(err);
    free(out.data);
    g_free(wanted);
}

static void linux_unified_custom_builder_v8(LinuxUnifiedV8 *state) {
    if (state == NULL) return;
    const char *selected = gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->mode));
    char *editing = selected != NULL && g_str_has_prefix(selected, "custom:") && strcmp(selected, "custom:new") != 0 ? g_strdup(selected + 7) : NULL;
    char *old_layers = editing != NULL ? linux_unified_custom_layers_for_mode_v8(selected) : NULL;
    GHashTable *old = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    if (old_layers != NULL) { gchar **parts = g_strsplit(old_layers, ",", -1); for (guint i=0; parts != NULL && parts[i] != NULL; i++) { g_strstrip(parts[i]); if (parts[i][0]) g_hash_table_add(old, g_strdup(parts[i])); } g_strfreev(parts); }
    GtkWidget *dialog = gtk_dialog_new_with_buttons("CUSTOM preset builder", GTK_WINDOW(state->app->window), GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT, "Cancel", GTK_RESPONSE_CANCEL, editing != NULL ? "Delete" : "", GTK_RESPONSE_REJECT, "Save", GTK_RESPONSE_ACCEPT, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 620, 620);
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog)); GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8); gtk_container_set_border_width(GTK_CONTAINER(box), 14);
    GtkWidget *note = gtk_label_new("Choose exact required layers. Router VPN only tries validated compatible Linux stacks containing every selected layer, prefers fewer unnecessary layers/overhead, and fails closed if none passes selected-node proof."); gtk_label_set_line_wrap(GTK_LABEL(note), TRUE); gtk_label_set_xalign(GTK_LABEL(note), 0.0f); gtk_box_pack_start(GTK_BOX(box), note, FALSE, FALSE, 0);
    GtkWidget *name = gtk_entry_new(); gtk_entry_set_placeholder_text(GTK_ENTRY(name), "Preset name"); if (editing != NULL) gtk_entry_set_text(GTK_ENTRY(name), editing); gtk_box_pack_start(GTK_BOX(box), name, FALSE, FALSE, 0);
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL); gtk_widget_set_size_request(scroll, -1, 390); GtkWidget *flow = gtk_flow_box_new(); gtk_flow_box_set_selection_mode(GTK_FLOW_BOX(flow), GTK_SELECTION_NONE); gtk_flow_box_set_max_children_per_line(GTK_FLOW_BOX(flow), 3); gtk_container_add(GTK_CONTAINER(scroll), flow);
    GPtrArray *checks = g_ptr_array_new();
    for (int i=0; linux_custom_layers_v8[i] != NULL; i++) { GtkWidget *check = gtk_check_button_new_with_label(linux_custom_layers_v8[i]); if (g_hash_table_contains(old, linux_custom_layers_v8[i])) gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(check), TRUE); g_object_set_data(G_OBJECT(check), "layer", (gpointer)linux_custom_layers_v8[i]); g_ptr_array_add(checks, check); gtk_container_add(GTK_CONTAINER(flow), check); }
    gtk_box_pack_start(GTK_BOX(box), scroll, TRUE, TRUE, 0); gtk_box_pack_start(GTK_BOX(content), box, TRUE, TRUE, 0); gtk_widget_show_all(dialog);
    int response = gtk_dialog_run(GTK_DIALOG(dialog));
    if (response == GTK_RESPONSE_REJECT && editing != NULL) {
        GKeyFile *key = linux_unified_load_keyfile_v8(); char *group = g_strdup_printf("preset:%s", editing); g_key_file_remove_group(key, group, NULL); g_free(group); g_key_file_set_string(key, "state", "selected_mode", "smart-auto"); linux_unified_save_keyfile_v8(key); g_key_file_unref(key);
    } else if (response == GTK_RESPONSE_ACCEPT) {
        const char *raw_name = gtk_entry_get_text(GTK_ENTRY(name)); char *clean = g_strdup(raw_name); g_strstrip(clean);
        GString *layers = g_string_new(""); for (guint i=0;i<checks->len;i++){GtkWidget *check=g_ptr_array_index(checks,i);if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(check))){if(layers->len)g_string_append_c(layers,',');g_string_append(layers,(const char*)g_object_get_data(G_OBJECT(check),"layer"));}}
        if (clean[0] == '\0' || strlen(clean) > 64 || layers->len == 0 || strchr(clean, ':') != NULL || strchr(clean, '\n') != NULL) append_diag(state->app, "CUSTOM preset requires a safe 1–64 character name and at least one exact layer.");
        else { GKeyFile *key=linux_unified_load_keyfile_v8(); if(editing!=NULL&&g_strcmp0(editing,clean)!=0){char *old_group=g_strdup_printf("preset:%s",editing);g_key_file_remove_group(key,old_group,NULL);g_free(old_group);}char *group=g_strdup_printf("preset:%s",clean);g_key_file_set_string(key,group,"layers",layers->str);char *mode=g_strdup_printf("custom:%s",clean);g_key_file_set_string(key,"state","selected_mode",mode);linux_unified_save_keyfile_v8(key);g_free(mode);g_free(group);g_key_file_unref(key);append_diag(state->app,"CUSTOM preset saved; it contains choices only, never private node credentials."); }
        g_string_free(layers, TRUE); g_free(clean);
    }
    gtk_widget_destroy(dialog); g_ptr_array_unref(checks); g_hash_table_unref(old); g_free(editing); g_free(old_layers); linux_unified_refresh_mode_combo_v8(state);
}
static void linux_unified_mode_changed_v8(GtkComboBox *combo, gpointer data) {
    LinuxUnifiedV8 *state = data; if (state == NULL || state->syncing) return; const char *id = gtk_combo_box_get_active_id(combo); if (id == NULL) return;
    if (strcmp(id, "custom:new") == 0) { linux_unified_custom_builder_v8(state); return; }
    linux_unified_store_mode_v8(id);
}
static void linux_unified_custom_button_v8(GtkButton *button, gpointer data) { (void)button; linux_unified_custom_builder_v8(data); }

static gboolean linux_unified_selected_external_v8(char **profile_id) {
    Buffer out={0};char *err=NULL;gboolean external=FALSE;*profile_id=NULL;
    if (api_request("/api/profiles","GET",NULL,5000,&out,&err)) { JsonNode *root=parse_json(out.data); if(root!=NULL&&JSON_NODE_HOLDS_OBJECT(root)){JsonObject *obj=json_node_get_object(root);const char *selected=obj_string(obj,"selected_id");JsonArray *profiles=json_object_has_member(obj,"profiles")?json_object_get_array_member(obj,"profiles"):NULL;for(guint i=0;profiles!=NULL&&i<json_array_get_length(profiles);i++){JsonObject *p=json_array_get_object_element(profiles,i);if(p!=NULL&&g_strcmp0(obj_string(p,"id"),selected)==0){external=g_ascii_strcasecmp(obj_string(p,"node_kind"),"external")==0;if(external)*profile_id=g_strdup(selected);break;}}json_node_free(root);}}
    g_free(err);free(out.data);return external;
}
static void linux_unified_connect_v8(GtkButton *button, gpointer data) {
    (void)button; LinuxUnifiedV8 *state=data; Buffer out={0};char *err=NULL;gboolean active=FALSE;
    if(api_request("/api/status","GET",NULL,4000,&out,&err)){JsonNode *root=parse_json(out.data);if(root!=NULL&&JSON_NODE_HOLDS_OBJECT(root)){JsonObject *obj=json_node_get_object(root);gboolean connected=json_object_has_member(obj,"connected")&&json_object_get_boolean_member(obj,"connected");const char *phase=obj_string(obj,"phase");active=connected||g_str_has_prefix(phase,"starting")||g_str_has_prefix(phase,"checking")||strstr(phase,"trying")!=NULL||strstr(phase,"proving")!=NULL;json_node_free(root);}}g_free(err);free(out.data);
    if(active){post_and_log(state->app,"/api/disconnect","{}",30000,"Disconnect");return;}
    if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(state->multihop))){on_linux_multihop_v7(NULL,state->app);return;}
    char *external_id=NULL;if(linux_unified_selected_external_v8(&external_id)){char *body=json_string_body("profile_id",external_id);post_and_log(state->app,"/api/external-profile/connect",body,180000,"Custom/external exit");g_free(body);g_free(external_id);return;}g_free(external_id);
    const char *mode=gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->mode));if(mode==NULL||mode[0]=='\0')mode="smart-auto";
    if(strcmp(mode,"smart-auto")==0)post_and_log(state->app,"/api/strategy/smart-auto","{}",240000,"SMART AUTO");
    else if(strcmp(mode,"auto")==0)post_and_log(state->app,"/api/strategy/auto","{}",200000,"AUTO");
    else if(g_str_has_prefix(mode,"custom:")){char *layers=linux_unified_custom_layers_for_mode_v8(mode);char *body=strategy_custom_body_v7(layers);if(body==NULL)append_diag(state->app,"CUSTOM preset has no exact layers; edit it first.");else{post_and_log(state->app,"/api/strategy/custom",body,240000,"CUSTOM preset");g_free(body);}g_free(layers);}
    else{JsonBuilder *builder=json_builder_new();json_builder_begin_object(builder);json_builder_set_member_name(builder,"mode");json_builder_add_string_value(builder,mode);json_builder_set_member_name(builder,"base");json_builder_add_string_value(builder,"auto");json_builder_end_object(builder);JsonNode *payload=json_builder_get_root(builder);JsonGenerator *gen=json_generator_new();json_generator_set_root(gen,payload);char *body=json_generator_to_data(gen,NULL);post_and_log(state->app,"/api/connect-logical",body,180000,"Logical mode");g_free(body);json_node_free(payload);g_object_unref(gen);g_object_unref(builder);}
}
static void linux_unified_kill_changed_v8(GtkToggleButton *toggle, gpointer data) {
    LinuxUnifiedV8 *state=data;if(state==NULL||state->syncing)return;const char *policy=gtk_toggle_button_get_active(toggle)?"on-connect":"off";char *body=g_strdup_printf("{\"kill_switch_policy\":\"%s\"}",policy);post_and_log(state->app,"/api/profile/settings",body,12000,"Kill switch");g_free(body);
}
static void linux_unified_dns_changed_v8(GtkComboBox *combo, gpointer data) {
    LinuxUnifiedV8 *state=data;if(state==NULL||state->syncing)return;const char *mode=gtk_combo_box_get_active_id(combo);if(mode==NULL)return;if(strcmp(mode,"custom")==0||strcmp(mode,"dot")==0||strcmp(mode,"doh")==0||strcmp(mode,"doh3")==0){linux_unified_show_detail_v8(state,3);return;}char *body=g_strdup_printf("{\"mode\":\"%s\"}",mode);post_and_log(state->app,"/api/dns/policy",body,12000,"DNS policy");g_free(body);
}
static void linux_unified_node_changed_v8(GtkComboBox *combo, gpointer data) {
    LinuxUnifiedV8 *state=data;if(state==NULL||state->syncing)return;const char *id=gtk_combo_box_get_active_id(combo);if(id==NULL||id[0]=='\0')return;char *body=json_string_body("id",id);post_and_log(state->app,"/api/profile/select",body,12000,"Node selection");g_free(body);refresh_all(state->app);
}
static gboolean linux_unified_refresh_v8(gpointer data) {
    LinuxUnifiedV8 *state=data;if(state==NULL)return G_SOURCE_REMOVE;state->syncing=TRUE;
    Buffer out={0};char *err=NULL;if(api_request("/api/status","GET",NULL,3500,&out,&err)){JsonNode *root=parse_json(out.data);if(root!=NULL&&JSON_NODE_HOLDS_OBJECT(root)){JsonObject *obj=json_node_get_object(root);gboolean connected=json_object_has_member(obj,"connected")&&json_object_get_boolean_member(obj,"connected");const char *phase=obj_string(obj,"phase");gboolean transition=g_str_has_prefix(phase,"starting")||g_str_has_prefix(phase,"checking")||strstr(phase,"trying")!=NULL||strstr(phase,"proving")!=NULL;gtk_button_set_label(GTK_BUTTON(state->connect),(connected||transition)?"Disconnect":"Connect");char *text=g_strdup_printf("%s • logical %s • runtime %s • base %s",phase[0]?phase:"disconnected",obj_string(obj,"logical_mode"),obj_string(obj,"runtime_mode"),obj_string(obj,"base"));gtk_label_set_text(GTK_LABEL(state->status),text);g_free(text);json_node_free(root);}}g_free(err);free(out.data);
    out=(Buffer){0};err=NULL;if(api_request("/api/profile/settings","GET",NULL,3500,&out,&err)){JsonNode *root=parse_json(out.data);if(root!=NULL&&JSON_NODE_HOLDS_OBJECT(root)){JsonObject *obj=json_node_get_object(root);const char *kill=obj_string(obj,"kill_switch_policy");gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(state->kill_switch),kill[0]&&strcmp(kill,"off")!=0);gboolean encrypted=json_object_has_member(obj,"auto_require_encrypted")&&json_object_get_boolean_member(obj,"auto_require_encrypted");gboolean obfuscated=json_object_has_member(obj,"auto_require_obfuscation")&&json_object_get_boolean_member(obj,"auto_require_obfuscation");const char *requirements=encrypted&&obfuscated?"Encrypted + Obfuscation":encrypted?"Encrypted":obfuscated?"Obfuscation":"Off";char *summary=g_strdup_printf("AUTO requirements: %s • Off by default • SMART never simplifies below enabled requirements",requirements);if(state->settings_summary!=NULL)gtk_label_set_text(GTK_LABEL(state->settings_summary),summary);g_free(summary);json_node_free(root);}}g_free(err);free(out.data);
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(state->node));for(guint i=0;i<state->app->router_ids->len;i++){const char *id=g_ptr_array_index(state->app->router_ids,i);gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state->node),id,id);}const char *active=active_router_id(state->app);if(active!=NULL)gtk_combo_box_set_active_id(GTK_COMBO_BOX(state->node),active);
    state->syncing=FALSE;refresh_home_summary_v6(state->app);if(state->app->map!=NULL)gtk_widget_queue_draw(state->app->map);return G_SOURCE_CONTINUE;
}

static GtkWidget *linux_unified_row_v8(const char *label, GtkWidget *control) {
    GtkWidget *row=gtk_box_new(GTK_ORIENTATION_HORIZONTAL,8);GtkWidget *title=gtk_label_new(label);gtk_widget_set_size_request(title,72,-1);gtk_label_set_xalign(GTK_LABEL(title),1.0f);gtk_box_pack_start(GTK_BOX(row),title,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(row),control,TRUE,TRUE,0);return row;
}
static void build_ui_v5(App *app) {
    build_ui_legacy_v5(app);
    GList *children=gtk_container_get_children(GTK_CONTAINER(app->window));if(children==NULL)return;GtkWidget *notebook=GTK_WIDGET(children->data);g_object_ref(notebook);g_list_free(children);gtk_container_remove(GTK_CONTAINER(app->window),notebook);
    if(app->map!=NULL&&gtk_widget_get_parent(app->map)!=NULL){g_object_ref(app->map);GtkWidget *parent=gtk_widget_get_parent(app->map);gtk_container_remove(GTK_CONTAINER(parent),app->map);}
    LinuxUnifiedV8 *state=g_new0(LinuxUnifiedV8,1);state->app=app;state->legacy_notebook=notebook;state->stack=gtk_stack_new();gtk_stack_set_transition_type(GTK_STACK(state->stack),GTK_STACK_TRANSITION_TYPE_SLIDE_LEFT_RIGHT);
    GtkWidget *main=gtk_box_new(GTK_ORIENTATION_VERTICAL,8);gtk_container_set_border_width(GTK_CONTAINER(main),10);
    GtkWidget *top=gtk_box_new(GTK_ORIENTATION_HORIZONTAL,8);state->node=gtk_combo_box_text_new();gtk_widget_set_hexpand(state->node,TRUE);gtk_box_pack_start(GTK_BOX(top),state->node,TRUE,TRUE,0);gtk_box_pack_start(GTK_BOX(top),make_button("Nodes",G_CALLBACK(linux_unified_nodes_v8),state),FALSE,FALSE,0);state->status=gtk_label_new("Disconnected • selected-path proof pending");gtk_label_set_xalign(GTK_LABEL(state->status),1.0f);gtk_box_pack_end(GTK_BOX(top),state->status,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(main),top,FALSE,FALSE,0);
    GtkWidget *map_frame=gtk_frame_new(NULL);if(app->map!=NULL){gtk_widget_set_size_request(app->map,-1,280);gtk_container_add(GTK_CONTAINER(map_frame),app->map);g_object_unref(app->map);}else gtk_container_add(GTK_CONTAINER(map_frame),gtk_label_new("No map widget available."));gtk_box_pack_start(GTK_BOX(main),map_frame,TRUE,TRUE,0);
    GtkWidget *dock=gtk_frame_new(NULL);GtkWidget *dock_box=gtk_box_new(GTK_ORIENTATION_VERTICAL,7);gtk_container_set_border_width(GTK_CONTAINER(dock_box),12);gtk_container_add(GTK_CONTAINER(dock),dock_box);
    GtkWidget *connect_row=gtk_box_new(GTK_ORIENTATION_HORIZONTAL,8);state->connect=make_button("Connect",G_CALLBACK(linux_unified_connect_v8),state);gtk_widget_set_hexpand(state->connect,TRUE);gtk_box_pack_start(GTK_BOX(connect_row),state->connect,TRUE,TRUE,0);state->kill_switch=gtk_check_button_new_with_label("Kill switch");g_signal_connect(state->kill_switch,"toggled",G_CALLBACK(linux_unified_kill_changed_v8),state);gtk_box_pack_start(GTK_BOX(connect_row),state->kill_switch,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(dock_box),connect_row,FALSE,FALSE,0);
    GtkWidget *multi_box=gtk_box_new(GTK_ORIENTATION_HORIZONTAL,8);state->multihop=gtk_check_button_new_with_label("Multihop");gtk_box_pack_start(GTK_BOX(multi_box),state->multihop,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(multi_box),gtk_label_new("Entry → Exit → Internet • color-coded real-coordinate map in hop editor"),TRUE,TRUE,0);gtk_box_pack_end(GTK_BOX(multi_box),make_button("Choose hops",G_CALLBACK(linux_unified_multihop_v8),state),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(dock_box),multi_box,FALSE,FALSE,0);
    GtkWidget *settings_buttons=gtk_box_new(GTK_ORIENTATION_HORIZONTAL,6);gtk_box_pack_start(GTK_BOX(settings_buttons),make_button("Open settings",G_CALLBACK(linux_unified_settings_v8),state),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(settings_buttons),make_button("AUTO requirements",G_CALLBACK(linux_unified_auto_requirements_v8),state),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(settings_buttons),make_button("Retest MTU",G_CALLBACK(linux_unified_mtu_v8),state),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(dock_box),linux_unified_row_v8("Settings",settings_buttons),FALSE,FALSE,0);state->settings_summary=gtk_label_new("AUTO requirements: Off • Off by default • SMART never simplifies below enabled requirements");gtk_label_set_xalign(GTK_LABEL(state->settings_summary),0.0f);gtk_label_set_ellipsize(GTK_LABEL(state->settings_summary),PANGO_ELLIPSIZE_END);gtk_widget_set_tooltip_text(state->settings_summary,"Enabled AUTO requirements filter candidates before attempts and bound SMART simplification.");gtk_box_pack_start(GTK_BOX(dock_box),state->settings_summary,FALSE,FALSE,0);
    GtkWidget *mode_row=gtk_box_new(GTK_ORIENTATION_HORIZONTAL,6);state->mode=gtk_combo_box_text_new();gtk_widget_set_hexpand(state->mode,TRUE);gtk_box_pack_start(GTK_BOX(mode_row),state->mode,TRUE,TRUE,0);gtk_box_pack_start(GTK_BOX(mode_row),make_button("Presets / CUSTOM",G_CALLBACK(linux_unified_custom_button_v8),state),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(mode_row),make_button("Details",G_CALLBACK(linux_unified_modes_v8),state),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(dock_box),linux_unified_row_v8("Mode",mode_row),FALSE,FALSE,0);
    state->dns=gtk_combo_box_text_new();gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state->dns),"home","Home AdGuard");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state->dns),"fastest","Fastest measured");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state->dns),"custom","Custom…");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state->dns),"dot","DoT…");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state->dns),"doh","DoH…");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state->dns),"doh3","DoH3…");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(state->dns),"rescue","Rescue");gtk_combo_box_set_active_id(GTK_COMBO_BOX(state->dns),"home");GtkWidget *dns_row=gtk_box_new(GTK_ORIENTATION_HORIZONTAL,6);gtk_box_pack_start(GTK_BOX(dns_row),state->dns,TRUE,TRUE,0);gtk_box_pack_start(GTK_BOX(dns_row),make_button("DNS details",G_CALLBACK(linux_unified_dns_detail_v8),state),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(dock_box),linux_unified_row_v8("DNS",dns_row),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(main),dock,FALSE,FALSE,0);
    GtkWidget *details=gtk_box_new(GTK_ORIENTATION_VERTICAL,6);gtk_box_pack_start(GTK_BOX(details),make_button("← Back to map",G_CALLBACK(linux_unified_back_v8),state),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(details),notebook,TRUE,TRUE,0);g_object_unref(notebook);
    gtk_stack_add_named(GTK_STACK(state->stack),main,"map");gtk_stack_add_named(GTK_STACK(state->stack),details,"details");gtk_stack_set_visible_child_name(GTK_STACK(state->stack),"map");gtk_container_add(GTK_CONTAINER(app->window),state->stack);
    linux_unified_refresh_mode_combo_v8(state);g_signal_connect(state->mode,"changed",G_CALLBACK(linux_unified_mode_changed_v8),state);g_signal_connect(state->dns,"changed",G_CALLBACK(linux_unified_dns_changed_v8),state);g_signal_connect(state->node,"changed",G_CALLBACK(linux_unified_node_changed_v8),state);g_object_set_data_full(G_OBJECT(app->window),"linux-unified-v8",state,g_free);g_timeout_add(1500,linux_unified_refresh_v8,state);linux_unified_refresh_v8(state);
}

/* Unified Linux shipping contract:
 * map-first actual GTK drawing area; real stored coordinates only; bottom control dock;
 * Connect/Disconnect + quick kill switch; real multihop editor/path proof; Settings -> Mode -> DNS;
 * SMART AUTO default; AUTO first-class; all logical presets stay discoverable with readiness text;
 * saved GUI CUSTOM presets with exact required layers and delete/edit-by-name behavior;
 * IPv6 On / Auto MTU / DAITA-like / Jumbo live in profile settings; AUTO requirements are directly reachable from the map-first Settings row;
 * hidden mature notebook remains drill-in detail only, never the daily top navigation.
 */
