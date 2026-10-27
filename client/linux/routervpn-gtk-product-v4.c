#define main routervpn_product_v3_main
#define build_ui_v3 routervpn_product_v3_build_ui
#define self_test_v3 routervpn_product_v3_self_test
#include "routervpn-gtk-product-v3.c"
#undef self_test_v3
#undef build_ui_v3
#undef main

/* Product v4: unified Router VPN + validated external-node desktop UX. */

static void refresh_nodes_order_v4(App *app, const char *order) {
    char *path = g_strdup_printf("/api/nodes?sort=%s", order != NULL ? order : "current");
    Buffer out = {0};
    char *err = NULL;
    if (!api_request(path, "GET", NULL, 3000, &out, &err)) {
        g_free(path); g_free(err); free(out.data); return;
    }
    g_free(path);
    JsonNode *root = parse_json(out.data);
    if (root == NULL || !JSON_NODE_HOLDS_OBJECT(root)) {
        if (root != NULL) json_node_free(root);
        free(out.data); g_free(err); return;
    }
    JsonObject *store = json_node_get_object(root);
    const char *selected = obj_string(store, "selected_id");
    JsonArray *profiles = json_object_get_array_member(store, "profiles");
    app->suppress_router_change = TRUE;
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(app->router_combo));
    g_ptr_array_set_size(app->router_ids, 0);
    g_ptr_array_set_size(app->nodes, 0);
    GString *text = g_string_new("");
    guint selected_index = 0;
    if (profiles != NULL) {
        for (guint i = 0; i < json_array_get_length(profiles); i++) {
            JsonObject *profile = json_array_get_object_element(profiles, i);
            if (profile == NULL) continue;
            MapNode *node = g_new0(MapNode, 1);
            node->id = g_strdup(obj_string(profile, "id"));
            node->name = g_strdup(obj_string(profile, "name"));
            node->location = g_strdup(obj_string(profile, "location"));
            node->endpoint = g_strdup(obj_string(profile, "endpoint"));
            gboolean has_lat = FALSE, has_lon = FALSE, has_latency = FALSE;
            node->latitude = obj_double(profile, "latitude", &has_lat);
            node->longitude = obj_double(profile, "longitude", &has_lon);
            node->latency = obj_double(profile, "latency_median_ms", &has_latency);
            node->has_coordinates = has_lat && has_lon && isfinite(node->latitude) && isfinite(node->longitude)
                && node->latitude >= -90 && node->latitude <= 90
                && node->longitude >= -180 && node->longitude <= 180
                && !(node->latitude == 0 && node->longitude == 0);
            node->selected = selected[0] != '\0' && strcmp(selected, node->id) == 0;
            if (node->selected) selected_index = i;
            gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->router_combo),
                                           node->name[0] != '\0' ? node->name : node->id);
            g_ptr_array_add(app->router_ids, g_strdup(node->id));
            g_ptr_array_add(app->nodes, node);
            g_string_append_printf(text, "%s%s\n  %s\n  endpoint: %s\n  coordinates: %s",
                node->selected ? "● " : "", node->name[0] ? node->name : node->id,
                node->location[0] ? node->location : "Location not labeled",
                node->endpoint[0] ? node->endpoint : "—",
                node->has_coordinates ? "real stored latitude/longitude" : "not stored — not plotted");
            if (has_latency && node->latency > 0) g_string_append_printf(text, "\n  median latency: %.1f ms", node->latency);
            const char *last_used = obj_string(profile, "last_used_at");
            if (last_used[0] != '\0') g_string_append_printf(text, "\n  last used: %s", last_used);
            g_string_append(text, "\n\n");
        }
    }
    if (app->router_ids->len > 0) gtk_combo_box_set_active(GTK_COMBO_BOX(app->router_combo), (gint)selected_index);
    app->suppress_router_change = FALSE;
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->nodes_view));
    gtk_text_buffer_set_text(buffer, text->str, -1);
    g_string_free(text, TRUE);
    gtk_widget_queue_draw(app->map);
    g_object_set_data_full(G_OBJECT(app->window), "router-vpn-source-catalog-v24", copy_public_source_value_v24(root), (GDestroyNotify)json_node_free);
    json_node_free(root); free(out.data); g_free(err);
}

static void on_sort_nodes_current(GtkButton *button, gpointer data) {(void)button;refresh_nodes_order_v4((App *)data,"current");}
static void on_sort_nodes_recent(GtkButton *button, gpointer data) {(void)button;refresh_nodes_order_v4((App *)data,"last-used");}
static void on_sort_nodes_latency(GtkButton *button, gpointer data) {(void)button;refresh_nodes_order_v4((App *)data,"latency");}
static void on_sort_nodes_name(GtkButton *button, gpointer data) {(void)button;refresh_nodes_order_v4((App *)data,"name");}

static void on_select_lowest_latency(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    Buffer out = {0};
    char *err = NULL;
    if (!api_request("/api/nodes?sort=latency", "GET", NULL, 3000, &out, &err)) {
        append_diag(app, err != NULL ? err : "Lowest-latency selection failed.");
        g_free(err); free(out.data); return;
    }
    JsonNode *root = parse_json(out.data);
    const char *best_id = NULL;
    guint measured = 0;
    if (root != NULL && JSON_NODE_HOLDS_OBJECT(root)) {
        JsonArray *profiles = json_object_get_array_member(json_node_get_object(root), "profiles");
        if (profiles != NULL) {
            for (guint i = 0; i < json_array_get_length(profiles); i++) {
                JsonObject *profile = json_array_get_object_element(profiles, i);
                if (profile == NULL) continue;
                gboolean has_latency = FALSE;
                double median = obj_double(profile, "latency_median_ms", &has_latency);
                gint64 samples = json_object_has_member(profile, "latency_samples") ? json_object_get_int_member(profile, "latency_samples") : 0;
                if (!has_latency || median <= 0 || samples <= 0) continue;
                if (best_id == NULL) best_id = obj_string(profile, "id");
                measured++;
            }
        }
    }
    if (measured < 2 || best_id == NULL || best_id[0] == '\0') {
        append_diag(app, "Lowest-latency selection requires real 50-sample measurements on at least two usable nodes; current selection was kept.");
    } else {
        char *body = json_string_body("id", best_id);
        Buffer selected_out = {0};
        char *select_err = NULL;
        if (api_request("/api/profile/select", "POST", body, 10000, &selected_out, &select_err)) {
            append_diag(app, "Selected the lowest measured median-latency node.");
            refresh_nodes_order_v4(app, "latency");
        } else {
            append_diag(app, select_err != NULL ? select_err : "Lowest-latency node selection failed.");
        }
        g_free(body); g_free(select_err); free(selected_out.data);
    }
    if (root != NULL) json_node_free(root);
    g_free(err); free(out.data);
}

static void on_import_any_node(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    GtkWidget *dialog = gtk_file_chooser_dialog_new(
        "Import Router VPN or external node", GTK_WINDOW(app->window),
        GTK_FILE_CHOOSER_ACTION_OPEN, "_Cancel", GTK_RESPONSE_CANCEL,
        "_Import", GTK_RESPONSE_ACCEPT, NULL);
    GtkFileFilter *filter = gtk_file_filter_new();
    gtk_file_filter_set_name(filter, "Router VPN / external JSON");
    gtk_file_filter_add_pattern(filter, "*.json");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dialog), filter);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        char *contents = NULL;
        gsize length = 0;
        GError *read_error = NULL;
        if (!g_file_get_contents(filename, &contents, &length, &read_error)) {
            append_diag(app, read_error != NULL ? read_error->message : "Import failed: could not read the selected file.");
        } else if (length > (32u * 1024u * 1024u)) {
            append_diag(app, "Import failed: node JSON is larger than 32 MiB.");
        } else {
            Buffer out = {0};
            char *router_err = NULL;
            if (api_request("/api/profile/import", "POST", contents, 25000, &out, &router_err)) {
                append_diag(app, "Router VPN node bundle imported into the private profile store.");
                refresh_profiles(app);
            } else {
                free(out.data); out.data = NULL; out.len = 0;
                char *external_err = NULL;
                if (api_request("/api/external-profile/import", "POST", contents, 25000, &out, &external_err)) {
                    append_diag(app, "Validated schema-v3 external node imported. Protocol credentials remain private; native UI receives only the public node view.");
                    refresh_profiles(app);
                } else {
                    char *line = g_strdup_printf(
                        "Import failed as Router VPN bundle (%s) and external node (%s)",
                        router_err != NULL ? router_err : "rejected",
                        external_err != NULL ? external_err : "rejected");
                    append_diag(app, line);
                    gtk_label_set_text(GTK_LABEL(app->error), line);
                    g_free(line);
                }
                g_free(external_err);
            }
            g_free(router_err);
            free(out.data);
        }
        if (read_error != NULL) g_error_free(read_error);
        g_free(contents);
        g_free(filename);
    }
    gtk_widget_destroy(dialog);
}

static char *external_primary_body_v24(App *app, const char *id, gboolean direct, char **error);

static void on_connect_external_node(GtkButton *button, gpointer data) {
    (void)button;
    App *app = data;
    const char *id = active_router_id(app);
    if (id == NULL || id[0] == '\0') {
        append_diag(app, "External connect failed: select a linked external node first.");
        return;
    }
    char *error = NULL;
    char *body = external_primary_body_v24(app, id, TRUE, &error);
    if (body == NULL) { append_diag(app, error != NULL ? error : "The captured external path is invalid."); g_free(error); return; }
    g_free(error);
    post_and_log(app, "/api/external-profile/connect", body, 180000,
                 "External direct exit (exact public-exit proof required)");
    g_free(body);
    refresh_all(app);
}

static const char *external_saved_execution_v4(JsonObject *profile) {
    const char *saved=obj_string(profile,"multihop_execution");
    if(saved[0]=='\0')return "local";
    return g_strcmp0(saved,"local")==0||g_strcmp0(saved,"server")==0||g_strcmp0(saved,"auto")==0?saved:NULL;
}

static char *json_external_hop_body(const char *profile_id, const char *entry_id, const char *execution, gboolean direct) {
    if(profile_id==NULL||!profile_id[0]||g_strcmp0(profile_id,entry_id)==0||execution==NULL||
       (g_strcmp0(execution,"local")!=0&&g_strcmp0(execution,"server")!=0&&g_strcmp0(execution,"auto")!=0))return NULL;
    JsonBuilder *builder=json_builder_new();json_builder_begin_object(builder);
    json_builder_set_member_name(builder,"profile_id");json_builder_add_string_value(builder,profile_id);
    json_builder_set_member_name(builder,"execution");json_builder_add_string_value(builder,direct?"local":execution);
    if(direct){json_builder_set_member_name(builder,"direct");json_builder_add_boolean_value(builder,TRUE);}
    else if(entry_id!=NULL&&entry_id[0]){json_builder_set_member_name(builder,"entry_id");json_builder_add_string_value(builder,entry_id);}
    json_builder_end_object(builder);JsonNode *root=json_builder_get_root(builder);
    JsonGenerator *generator=json_generator_new();json_generator_set_root(generator,root);
    char *body=json_generator_to_data(generator,NULL);json_node_free(root);g_object_unref(generator);g_object_unref(builder);return body;
}

static const char *external_path_string_v4(JsonObject *object,const char *key) {
    JsonNode *node=object!=NULL&&json_object_has_member(object,key)?json_object_get_member(object,key):NULL;
    return node!=NULL&&JSON_NODE_HOLDS_VALUE(node)&&json_node_get_value_type(node)==G_TYPE_STRING?json_node_get_string(node):"";
}

static gboolean external_path_flag_v4(JsonObject *object,const char *key) {
    JsonNode *node=object!=NULL&&json_object_has_member(object,key)?json_object_get_member(object,key):NULL;
    return node!=NULL&&JSON_NODE_HOLDS_VALUE(node)&&json_node_get_value_type(node)==G_TYPE_BOOLEAN&&json_node_get_boolean(node);
}

static JsonObject *external_path_object_v4(JsonObject *object,const char *key) {
    JsonNode *node=object!=NULL&&json_object_has_member(object,key)?json_object_get_member(object,key):NULL;
    return node!=NULL&&JSON_NODE_HOLDS_OBJECT(node)?json_node_get_object(node):NULL;
}

#include "routervpn-external-source-v24.inc"

static char *external_path_current_body_v4(JsonObject *captured,JsonNode *current,const char *entry_id,const char *execution,gboolean direct,char **error) {
    const char *message=NULL;JsonObject *found=NULL,*entry=NULL;guint matches=0,entries=0;
    JsonObject *store=current!=NULL&&JSON_NODE_HOLDS_OBJECT(current)?json_node_get_object(current):NULL;
    JsonNode *list=store!=NULL&&json_object_has_member(store,"profiles")?json_object_get_member(store,"profiles"):NULL;
    JsonArray *catalog=list!=NULL&&JSON_NODE_HOLDS_ARRAY(list)?json_node_get_array(list):NULL;
    const char *id=external_path_string_v4(captured,"id");
    for(guint i=0;catalog!=NULL&&i<json_array_get_length(catalog);i++){
        JsonNode *item=json_array_get_element(catalog,i);
        if(item==NULL||!JSON_NODE_HOLDS_OBJECT(item)){message="The current node catalog is invalid.";break;}
        JsonObject *node=json_node_get_object(item);const char *node_id=external_path_string_v4(node,"id");
        if(g_strcmp0(node_id,id)==0){found=node;matches++;}
        if(g_strcmp0(node_id,entry_id)==0){entry=node;entries++;}
    }
    if(message==NULL&&(!id[0]||matches!=1||g_strcmp0(external_path_string_v4(found,"node_kind"),"external")!=0))message="The external node changed while this dialog was open. Reopen its path settings.";
    JsonObject *before=external_path_object_v4(captured,"external"),*after=external_path_object_v4(found,"external");
    const char *identity[]={"id","node_kind","endpoint","start_layer","multihop_entry_mode","profile_token"},*transport[]={"protocol","expected_public_ip"},*flags[]={"has_response_probe","has_server_peer","has_openvpn_pairing"};
    for(guint i=0;message==NULL&&i<G_N_ELEMENTS(identity);i++)if(g_strcmp0(external_path_string_v4(captured,identity[i]),external_path_string_v4(found,identity[i]))!=0)message="The external node changed while this dialog was open. Reopen its path settings.";
    for(guint i=0;message==NULL&&i<G_N_ELEMENTS(transport);i++)if(g_strcmp0(external_path_string_v4(before,transport[i]),external_path_string_v4(after,transport[i]))!=0)message="The external transport changed while this dialog was open. Reopen its path settings.";
    for(guint i=0;message==NULL&&i<G_N_ELEMENTS(flags);i++)if(external_path_flag_v4(before,flags[i])!=external_path_flag_v4(after,flags[i]))message="The external provisioning changed while this dialog was open. Reopen its path settings.";
    if(message==NULL&&!direct&&(entry_id==NULL||!entry_id[0]||entries!=1))message="The selected entry is missing or ambiguous. Choose it again.";
    if(message==NULL&&g_strcmp0(execution,"local")!=0){
        const char *protocol=external_path_string_v4(after,"protocol"),*kind=external_path_string_v4(entry,"node_kind");
        gboolean packet=g_strcmp0(protocol,"wireguard")==0||g_strcmp0(protocol,"amneziawg")==0;
        if(!packet&&g_strcmp0(protocol,"shadowsocks")!=0&&g_strcmp0(protocol,"hysteria2")!=0&&g_strcmp0(protocol,"socks5")!=0&&g_strcmp0(protocol,"http-connect")!=0&&g_strcmp0(protocol,"https-connect")!=0&&g_strcmp0(protocol,"openvpn")!=0)message="Server / Compare requires a supported authenticated external transport.";
        else if(!external_path_flag_v4(after,"has_response_probe"))message="Server / Compare requires this external node's HTTPS response probe.";
        else if(packet&&!external_path_flag_v4(after,"has_server_peer"))message="WireGuard / AmneziaWG Server / Compare requires a separately provisioned server peer.";
        else if(g_strcmp0(protocol,"openvpn")==0&&!external_path_flag_v4(after,"has_openvpn_pairing"))message="OpenVPN Server / Compare requires private pairing with independent provider credentials.";
        else if(direct||(kind[0]&&g_strcmp0(kind,"router-vpn")!=0))message="Server / Compare requires a Router VPN entry.";
    }
    if(message!=NULL){if(error!=NULL)*error=g_strdup(message);return NULL;}
    char *body=json_external_hop_body(id,entry_id,execution,direct);
    if(body==NULL&&error!=NULL)*error=g_strdup("The captured external path is invalid.");
    return body;
}

static char *external_entry_mode_v4(JsonObject *captured,JsonObject *entry,const char *selected,JsonArray *modes,char **error) {
    const char *message=NULL,*kind=external_path_string_v4(entry,"node_kind");
    if(entry==NULL||(kind[0]&&g_strcmp0(kind,"router-vpn")!=0)){
        if(selected!=NULL&&selected[0])message="An entry mode applies only to a Router VPN entry.";
        else return g_strdup("");
    }
    const char *mode=selected!=NULL?selected:"";
    if(message==NULL&&!mode[0]){
        const char *base=external_path_string_v4(entry,"base_tunnel");
        if(g_strcmp0(base,"wg")!=0&&g_strcmp0(base,"awg")!=0)base=external_path_string_v4(captured,"base_tunnel");
        mode=g_strcmp0(base,"awg")==0?"awg2-fast":"wg";
    }
    guint matches=0;
    for(guint i=0;message==NULL&&modes!=NULL&&i<json_array_get_length(modes);i++){
        JsonNode *item=json_array_get_element(modes,i);
        if(item!=NULL&&JSON_NODE_HOLDS_OBJECT(item)&&g_strcmp0(external_path_string_v4(json_node_get_object(item),"id"),mode)==0)matches++;
    }
    if(message==NULL&&matches!=1)message="Choose an exact Router entry mode from the current native catalog.";
    if(message!=NULL){if(error!=NULL)*error=g_strdup(message);return NULL;}
    return g_strdup(mode);
}

static char *external_saved_entry_mode_v4(JsonObject *captured,JsonArray *profiles,JsonArray *modes,char **error) {
    const char *mode=external_path_string_v4(captured,"multihop_entry_mode"),*message=NULL;
    if(!mode[0])return g_strdup("");
    const char *entry_id=external_path_string_v4(captured,"multihop_entry_id");
    if(external_path_flag_v4(captured,"multihop_enabled")&&entry_id[0]){
        JsonObject *entry=NULL;guint matches=0;
        for(guint i=0;profiles!=NULL&&i<json_array_get_length(profiles);i++){
            JsonNode *item=json_array_get_element(profiles,i);
            if(item!=NULL&&JSON_NODE_HOLDS_OBJECT(item)&&g_strcmp0(external_path_string_v4(json_node_get_object(item),"id"),entry_id)==0){entry=json_node_get_object(item);matches++;}
        }
        if(matches!=1)message="The saved entry is missing or ambiguous. Refresh the node list.";
        const char *kind=external_path_string_v4(entry,"node_kind");JsonObject *external=external_path_object_v4(entry,"external");
        if(message==NULL&&g_strcmp0(kind,"external")==0){
            const char *protocol=external_path_string_v4(external,"protocol");
            const char *supported[]={"wireguard","amneziawg","socks5","http-connect","https-connect","shadowsocks","hysteria2","openvpn"};gboolean valid=FALSE;
            for(guint i=0;i<G_N_ELEMENTS(supported);i++)if(g_strcmp0(protocol,supported[i])==0)valid=TRUE;
            const char *exit_protocol=external_path_string_v4(external_path_object_v4(captured,"external"),"protocol");
            if(valid&&g_strcmp0(mode,protocol)==0&&(g_strcmp0(exit_protocol,"tor")==0||g_strcmp0(exit_protocol,"tor-bridge")==0))return g_strdup("");
            message="The saved Tor entry no longer matches its imported protocol. Reopen its path settings after relinking.";
        }else if(message==NULL&&((kind[0]&&g_strcmp0(kind,"router-vpn")!=0)||external!=NULL))message="The saved entry has an inconsistent node identity.";
    }
    guint matches=0;
    for(guint i=0;message==NULL&&modes!=NULL&&i<json_array_get_length(modes);i++){
        JsonNode *item=json_array_get_element(modes,i);
        if(item!=NULL&&JSON_NODE_HOLDS_OBJECT(item)&&g_strcmp0(external_path_string_v4(json_node_get_object(item),"id"),mode)==0)matches++;
    }
    if(message==NULL&&matches!=1)message="The saved Router entry mode is missing from the current native catalog.";
    if(message!=NULL){if(error!=NULL)*error=g_strdup(message);return NULL;}
    return g_strdup(mode);
}

static char *external_path_mode_body_v4(JsonObject *captured,JsonNode *current,const char *entry_id,const char *execution,gboolean direct,const char *entry_mode,JsonArray *entry_modes,char **error) {
    char *body=external_path_current_body_v4(captured,current,entry_id,execution,direct,error);
    if(body==NULL)return NULL;
    JsonObject *entry=NULL;JsonArray *catalog=json_object_get_array_member(json_node_get_object(current),"profiles");
    for(guint i=0;!direct&&i<json_array_get_length(catalog);i++){
        JsonObject *item=json_array_get_object_element(catalog,i);
        if(g_strcmp0(external_path_string_v4(item,"id"),entry_id)==0)entry=item;
    }
    char *mode=external_entry_mode_v4(captured,entry,entry_mode,entry_modes,error);
    if(mode==NULL){g_free(body);return NULL;}
    if(mode[0]){
        JsonNode *root=parse_json(body);JsonObject *object=json_node_get_object(root);
        json_object_set_string_member(object,"entry_mode",mode);
        JsonGenerator *generator=json_generator_new();json_generator_set_root(generator,root);
        g_free(body);body=json_generator_to_data(generator,NULL);g_object_unref(generator);json_node_free(root);
    }
    g_free(mode);return body;
}

typedef struct {JsonArray *profiles;GtkWidget *mode;GtkWidget *execution;} LinuxExternalEntryModeV4;
static void external_entry_changed_v4(GtkComboBox *combo,gpointer data) {
    LinuxExternalEntryModeV4 *state=data;const char *id=gtk_combo_box_get_active_id(combo);JsonObject *entry=NULL;
    for(guint i=0;id!=NULL&&id[0]&&i<json_array_get_length(state->profiles);i++){
        JsonObject *item=json_array_get_object_element(state->profiles,i);
        if(g_strcmp0(external_path_string_v4(item,"id"),id)==0)entry=item;
    }
    const char *kind=external_path_string_v4(entry,"node_kind");
    gboolean router=entry!=NULL&&(!kind[0]||g_strcmp0(kind,"router-vpn")==0),direct=id==NULL||!id[0];
    gtk_widget_set_sensitive(state->mode,router);
    if(!router)gtk_combo_box_set_active_id(GTK_COMBO_BOX(state->mode),"");
    gtk_widget_set_sensitive(state->execution,!direct);
    if(direct)gtk_combo_box_set_active_id(GTK_COMBO_BOX(state->execution),"local");
}

static void linux_external_path_dialog_v4(App *app, gboolean require_entry) {
    if(!routervpn_require_mutation_idle(app,"starting an external via-entry connection"))return;
    g_autofree char *exit_id=g_strdup(active_router_id(app));
    if(exit_id==NULL||!exit_id[0]){append_diag(app,"Select an external node first.");return;}
    Buffer out={0};char *err=NULL;
    if(!api_request("/api/nodes","GET",NULL,5000,&out,&err)){append_diag(app,"External path catalog unavailable.");g_free(err);free(out.data);return;}
    JsonNode *root=parse_json(out.data);g_free(err);free(out.data);
    if(root==NULL||!JSON_NODE_HOLDS_OBJECT(root)){if(root!=NULL)json_node_free(root);append_diag(app,"External path catalog is invalid.");return;}
    JsonObject *store=json_node_get_object(root),*captured=NULL;
    JsonArray *profiles=json_object_has_member(store,"profiles")?json_object_get_array_member(store,"profiles"):NULL;
    guint captured_count=0;for(guint i=0;profiles!=NULL&&i<json_array_get_length(profiles);i++){JsonObject *p=json_array_get_object_element(profiles,i);if(p!=NULL&&g_strcmp0(obj_string(p,"id"),exit_id)==0){captured=p;captured_count++;}}
    if(captured==NULL||captured_count!=1||g_strcmp0(obj_string(captured,"node_kind"),"external")!=0){append_diag(app,"Select an external node first.");json_node_free(root);return;}
    const char *saved=external_saved_execution_v4(captured);
    if(saved==NULL){append_diag(app,"The external node has an invalid saved execution choice.");json_node_free(root);return;}
    const char *saved_entry=json_object_has_member(captured,"multihop_enabled")&&json_object_get_boolean_member(captured,"multihop_enabled")?obj_string(captured,"multihop_entry_id"):"";
    Buffer capability_data={0};char *capability_error=NULL;
    if(!api_request("/api/external-profile/capabilities","GET",NULL,5000,&capability_data,&capability_error)){append_diag(app,"The native Router entry mode catalog is unavailable.");g_free(capability_error);free(capability_data.data);json_node_free(root);return;}
    g_autoptr(JsonNode) capability_root=parse_json(capability_data.data);g_free(capability_error);free(capability_data.data);
    JsonObject *capabilities=capability_root!=NULL&&JSON_NODE_HOLDS_OBJECT(capability_root)?json_node_get_object(capability_root):NULL;
    JsonNode *mode_list=capabilities!=NULL&&json_object_has_member(capabilities,"router_vpn_entry_modes")?json_object_get_member(capabilities,"router_vpn_entry_modes"):NULL;
    JsonArray *entry_modes=mode_list!=NULL&&JSON_NODE_HOLDS_ARRAY(mode_list)?json_node_get_array(mode_list):NULL;
    if(!external_path_flag_v4(capabilities,"profile_source_preconditions")){append_diag(app,"Update the local controller before connecting this captured external path.");json_node_free(root);return;}
    if(entry_modes==NULL){append_diag(app,"The native Router entry mode catalog is invalid.");json_node_free(root);return;}
    g_autofree char *saved_mode_error=NULL;
    g_autofree char *saved_mode=external_saved_entry_mode_v4(captured,profiles,entry_modes,&saved_mode_error);
    if(saved_mode==NULL){append_diag(app,saved_mode_error!=NULL?saved_mode_error:"The saved entry mode is invalid.");json_node_free(root);return;}
    JsonObject *external=json_object_has_member(captured,"external")?json_object_get_object_member(captured,"external"):NULL;
    gboolean has_probe=external!=NULL&&json_object_has_member(external,"has_response_probe")&&json_object_get_boolean_member(external,"has_response_probe");
    GtkWidget *dialog=gtk_dialog_new_with_buttons("External path",GTK_WINDOW(app->window),GTK_DIALOG_MODAL|GTK_DIALOG_DESTROY_WITH_PARENT,"Cancel",GTK_RESPONSE_CANCEL,"Connect selected path",GTK_RESPONSE_ACCEPT,NULL);
    GtkWidget *box=gtk_box_new(GTK_ORIENTATION_VERTICAL,10);gtk_container_set_border_width(GTK_CONTAINER(box),16);gtk_window_set_default_size(GTK_WINDOW(dialog),640,420);
    GtkWidget *title=gtk_label_new(obj_string(captured,"name"));gtk_label_set_xalign(GTK_LABEL(title),0.0f);gtk_box_pack_start(GTK_BOX(box),title,FALSE,FALSE,0);
    GtkWidget *entry=gtk_combo_box_text_new();gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(entry),"","Direct — no entry");
    for(guint i=0;profiles!=NULL&&i<json_array_get_length(profiles);i++){
        JsonObject *p=json_array_get_object_element(profiles,i);if(p==NULL||g_strcmp0(obj_string(p,"id"),exit_id)==0)continue;
        gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(entry),obj_string(p,"id"),obj_string(p,"display_name")[0]?obj_string(p,"display_name"):obj_string(p,"name"));
    }
    if(!gtk_combo_box_set_active_id(GTK_COMBO_BOX(entry),saved_entry)){append_diag(app,"The saved external entry is missing. Relink it or use External direct explicitly.");gtk_widget_destroy(dialog);json_node_free(root);return;}
    GtkWidget *execution=gtk_combo_box_text_new();gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(execution),"local","Local — exit runs on this device");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(execution),"server","Server — exit runs on Router entry");gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(execution),"auto","Compare both — lowest valid average");gtk_combo_box_set_active_id(GTK_COMBO_BOX(execution),saved_entry[0]?saved:"local");
    GtkWidget *entry_mode=gtk_combo_box_text_new();gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(entry_mode),"","Use selected entry's saved base");
    for(guint i=0;i<json_array_get_length(entry_modes);i++){
        JsonNode *item=json_array_get_element(entry_modes,i);if(item==NULL||!JSON_NODE_HOLDS_OBJECT(item))continue;
        JsonObject *mode=json_node_get_object(item);const char *id=external_path_string_v4(mode,"id"),*name=external_path_string_v4(mode,"name");
        if(id[0])gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(entry_mode),id,name[0]?name:id);
    }
    if(!gtk_combo_box_set_active_id(GTK_COMBO_BOX(entry_mode),saved_mode)){append_diag(app,"The saved Router entry mode is missing from the current native catalog.");gtk_widget_destroy(dialog);json_node_free(root);return;}
    LinuxExternalEntryModeV4 mode_state={.profiles=profiles,.mode=entry_mode,.execution=execution};
    g_signal_connect(entry,"changed",G_CALLBACK(external_entry_changed_v4),&mode_state);external_entry_changed_v4(GTK_COMBO_BOX(entry),&mode_state);
    GtkWidget *mode_note=gtk_label_new("The exact selected mode and the entry node's saved Start Layer are used. Compatibility and path proof are checked before Connected.");gtk_label_set_line_wrap(GTK_LABEL(mode_note),TRUE);gtk_label_set_xalign(GTK_LABEL(mode_note),0.0f);
    GtkWidget *note=gtk_label_new("Server / Compare requires a Router entry, an authenticated external exit, and its saved HTTPS response probe. WireGuard / AmneziaWG also needs a separately provisioned server peer. Pairing and actual path proof are checked when connecting. Direct uses Local. A successful connection saves this node's choice.");gtk_label_set_line_wrap(GTK_LABEL(note),TRUE);gtk_label_set_xalign(GTK_LABEL(note),0.0f);
    GtkWidget *probe=gtk_label_new(has_probe?"HTTPS response probe saved; server pairing and native proof remain pending.":"No HTTPS response probe saved. Import or create a provisioned external node before choosing Server / Compare.");gtk_label_set_line_wrap(GTK_LABEL(probe),TRUE);gtk_label_set_xalign(GTK_LABEL(probe),0.0f);
    GtkWidget *error=gtk_label_new("");gtk_label_set_line_wrap(GTK_LABEL(error),TRUE);gtk_label_set_xalign(GTK_LABEL(error),0.0f);
    gtk_box_pack_start(GTK_BOX(box),gtk_label_new("Entry"),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(box),entry,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(box),gtk_label_new("Router entry mode"),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(box),entry_mode,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(box),mode_note,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(box),gtk_label_new("External execution"),FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(box),execution,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(box),note,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(box),probe,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(box),error,FALSE,FALSE,0);
    gtk_box_pack_start(GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))),box,TRUE,TRUE,0);gtk_widget_show_all(dialog);
    while(gtk_dialog_run(GTK_DIALOG(dialog))==GTK_RESPONSE_ACCEPT){
        if(!routervpn_require_mutation_idle(app,"committing an external via-entry connection"))break;
        const char *entry_id=gtk_combo_box_get_active_id(GTK_COMBO_BOX(entry));const char *choice=gtk_combo_box_get_active_id(GTK_COMBO_BOX(execution));
        if(entry_id==NULL||choice==NULL){gtk_label_set_text(GTK_LABEL(error),"Choose an entry or Direct and an execution choice.");continue;}
        gboolean direct=!entry_id[0];
        if(require_entry&&direct){gtk_label_set_text(GTK_LABEL(error),"Choose an entry for this via-entry connection.");continue;}
        if(direct&&g_strcmp0(choice,"local")!=0){gtk_label_set_text(GTK_LABEL(error),"Direct uses Local. Choose an entry for Server / Compare.");continue;}
        Buffer fresh={0};char *fresh_error=NULL;
        if(!api_request("/api/nodes","GET",NULL,5000,&fresh,&fresh_error)){gtk_label_set_text(GTK_LABEL(error),"The current node catalog is unavailable. Nothing was connected.");g_free(fresh_error);free(fresh.data);continue;}
        JsonNode *current=parse_json(fresh.data);g_free(fresh_error);free(fresh.data);fresh_error=NULL;
        char *prepared=external_path_mode_body_v4(captured,current,entry_id,choice,direct,gtk_combo_box_get_active_id(GTK_COMBO_BOX(entry_mode)),entry_modes,&fresh_error);
        char *body=prepared!=NULL?external_captured_body_v24(prepared,root,current,&fresh_error):NULL;g_free(prepared);if(current!=NULL)json_node_free(current);
        if(body==NULL){gtk_label_set_text(GTK_LABEL(error),fresh_error!=NULL?fresh_error:"The captured external path is invalid.");g_free(fresh_error);continue;}
        post_and_log(app,"/api/external-profile/connect",body,180000,"External selected path (exact public-exit proof required)");g_free(body);refresh_all(app);break;
    }
    gtk_widget_destroy(dialog);json_node_free(root);
}

static void on_connect_external_via_entry(GtkButton *button, gpointer data) {
    (void)button;linux_external_path_dialog_v4(data,TRUE);
}

static GtkWidget *build_nodes_page_v4(App *app) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(box), 10);
    GtkWidget *note = gtk_label_new(
        "Install once; pair/import Router VPN and external node data separately. "
        "The map plots only stored real coordinates; coordinate-less nodes stay usable in the list.");
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(note), TRUE);
    gtk_box_pack_start(GTK_BOX(box), note, FALSE, FALSE, 0);

    GtkWidget *sort_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(sort_row), gtk_label_new("Order:"), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(sort_row), make_button("Current / recent", G_CALLBACK(on_sort_nodes_current), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(sort_row), make_button("Last used", G_CALLBACK(on_sort_nodes_recent), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(sort_row), make_button("Lowest latency", G_CALLBACK(on_sort_nodes_latency), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(sort_row), make_button("Name", G_CALLBACK(on_sort_nodes_name), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(sort_row), make_button("Select lowest latency", G_CALLBACK(on_select_lowest_latency), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), sort_row, FALSE, FALSE, 0);

    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_VERTICAL);
    app->map = gtk_drawing_area_new();
    gtk_widget_set_size_request(app->map, -1, 300);
    g_signal_connect(app->map, "draw", G_CALLBACK(draw_map), app);
    gtk_paned_pack1(GTK_PANED(paned), app->map, TRUE, FALSE);
    GtkWidget *scroll = scrolled_text(&app->nodes_view);
    gtk_paned_pack2(GTK_PANED(paned), scroll, TRUE, FALSE);
    gtk_box_pack_start(GTK_BOX(box), paned, TRUE, TRUE, 0);

    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(row), make_button("Pair home node", G_CALLBACK(on_pair_node), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Import node JSON", G_CALLBACK(on_import_any_node), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Connect external direct", G_CALLBACK(on_connect_external_node), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("External via entry", G_CALLBACK(on_connect_external_via_entry), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Remove selected node", G_CALLBACK(on_remove_node), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), make_button("Run 50-sample latency", G_CALLBACK(on_latency_node), app), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), row, FALSE, FALSE, 0);
    return box;
}

static void build_ui_v4(App *app) {
    app->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(app->window), "Router VPN");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 1120, 740);
    GtkWidget *tabs_widget = gtk_notebook_new();
    GtkNotebook *tabs = GTK_NOTEBOOK(tabs_widget);
    add_tab(tabs, build_home_page(app), "Home / Connect");
    add_tab(tabs, build_nodes_page_v4(app), "Nodes & Map");
    add_tab(tabs, build_modes_page(app), "Modes");
    add_tab(tabs, make_info_page("DNS", "Selected DNS is controller-owned and session-proven. Home shows typed dns-proof events; a saved DNS choice alone is never proof."), "DNS");
    add_tab(tabs, make_info_page("Advanced", "MTU/Jumbo, LAN access, kill switch, Router VPN multihop and external entry/exit compatibility remain controller-owned so native UI cannot claim settings the dataplane did not apply."), "Advanced");
    add_tab(tabs, make_info_page("Forwarding", "Incoming forwarding is available only when the active routable Router VPN dataplane can implement it. Proxy-only/external modes never pretend arbitrary DNAT is available."), "Forwarding");
    add_tab(tabs, make_info_page("Settings", "Router VPN Linux talks only to the fixed local controller at 127.0.0.1:8788. External protocol credentials remain in the private 0600 profile store and are redacted from public node/profile APIs."), "Settings");
    add_tab(tabs, make_info_page("Help", "Pair a Router VPN home node or import validated Router VPN/external JSON. External direct or entry->exit connect succeeds only after its exact expected public exit is proven. Use Setup Center Full Guide for server/router administration."), "Help");
    gtk_container_add(GTK_CONTAINER(app->window), tabs_widget);
}

static int self_test_v4(void) {
    if (routervpn_product_v3_self_test() != 0) return 2;
    static const char *const external_paths[] = {
        "/api/external-profile/import", "/api/external-profile/connect", "/api/nodes", "entry_id", "/api/nodes?sort=latency", "Select lowest latency"
    };
    if (G_N_ELEMENTS(external_paths) != 6 || external_paths[0][0] != '/') return 3;
    puts("Router VPN native Linux unified external-node product self-test: OK");
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--self-test") == 0) return self_test_v4();
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        fprintf(stderr, "Router VPN: libcurl global initialization failed\n");
        return 2;
    }
    if (!gtk_init_check(&argc, &argv)) {
        fprintf(stderr, "Router VPN: no usable graphical display is available\n");
        curl_global_cleanup();
        return 2;
    }
    App app = {0};
    app.nodes = g_ptr_array_new_with_free_func(free_map_node);
    app.router_ids = g_ptr_array_new_with_free_func(g_free);
    app.mode_ids = g_ptr_array_new_with_free_func(g_free);
    if (!resolve_package_root(&app, argv[0])) {
        fprintf(stderr, "Router VPN: cannot resolve package root\n");
        g_ptr_array_unref(app.nodes); g_ptr_array_unref(app.router_ids); g_ptr_array_unref(app.mode_ids);
        curl_global_cleanup();
        return 2;
    }
    char *error = NULL;
    if (!ensure_controller(&app, &error)) {
        GtkWidget *dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR,
                                                   GTK_BUTTONS_CLOSE, "Router VPN could not start: %s",
                                                   error != NULL ? error : "unknown error");
        (void)gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        g_free(error); g_free(app.package_root);
        g_ptr_array_unref(app.nodes); g_ptr_array_unref(app.router_ids); g_ptr_array_unref(app.mode_ids);
        curl_global_cleanup();
        return 3;
    }
    build_ui_v4(&app);
    g_signal_connect(app.window, "destroy", G_CALLBACK(on_destroy), &app);
    refresh_all(&app);
    (void)g_timeout_add_seconds(2, refresh_timer, &app);
    gtk_widget_show_all(app.window);
    gtk_main();
    g_free(app.package_root);
    g_ptr_array_unref(app.nodes); g_ptr_array_unref(app.router_ids); g_ptr_array_unref(app.mode_ids);
    curl_global_cleanup();
    return 0;
}
