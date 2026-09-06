typedef struct {
    App *app;
    LinuxUnifiedV8 *base;
    GtkWidget *fastest;
    GtkWidget *live;
    GtkWidget *hop;
    GtkWidget *forward;
    gboolean syncing;
} LinuxTelemetryV9;

#include "routervpn-connection-profiles-v11.inc"

static void linux_telemetry_profiles_v9(GtkButton *button, gpointer data) {
    (void)button;
    LinuxTelemetryV9 *telemetry = (LinuxTelemetryV9 *)data;
    if (telemetry == NULL || telemetry->base == NULL) return;
    linux_profile_manager_v11(NULL, telemetry->base);
}

static GtkWidget *linux_telemetry_button_v9(const char *label,GCallback callback,gpointer data){GtkWidget *button=gtk_button_new_with_label(label);g_signal_connect(button,"clicked",callback,data);return button;}

static GtkWidget *linux_telemetry_find_button_v9(GtkWidget *root, const char *label) {
    if (root == NULL) return NULL;
    if (GTK_IS_BUTTON(root)) {
        const char *value = gtk_button_get_label(GTK_BUTTON(root));
        if (value != NULL && g_strcmp0(value, label) == 0) return root;
    }
    if (!GTK_IS_CONTAINER(root)) return NULL;
    GList *children = gtk_container_get_children(GTK_CONTAINER(root));
    for (GList *it = children; it != NULL; it = it->next) {
        GtkWidget *found = linux_telemetry_find_button_v9(GTK_WIDGET(it->data), label);
        if (found != NULL) { g_list_free(children); return found; }
    }
    g_list_free(children); return NULL;
}

static void linux_telemetry_refresh_fastest_v9(LinuxTelemetryV9 *t) {
    if (t == NULL || t->fastest == NULL) return;
    Buffer out={0}; char *err=NULL;
    if (!api_request("/api/profiles","GET",NULL,4000,&out,&err)) { g_free(err); free(out.data); return; }
    JsonNode *root=parse_json(out.data);
    const char *active_id="fastest";
    t->syncing=TRUE; gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(t->fastest));
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(t->fastest),"fastest","⚡ Fastest");
    if (root!=NULL && JSON_NODE_HOLDS_OBJECT(root)) {
        JsonObject *obj=json_node_get_object(root);
        const char *selected=json_object_has_member(obj,"selected_id")?json_object_get_string_member(obj,"selected_id"):"";
        JsonArray *profiles=json_object_has_member(obj,"profiles")?json_object_get_array_member(obj,"profiles"):NULL;
        for (guint i=0; profiles!=NULL && i<json_array_get_length(profiles); i++) {
            JsonObject *p=json_array_get_object_element(profiles,i); if(p==NULL)continue;
            const char *kind=obj_string(p,"node_kind"); if(kind[0]&&g_ascii_strcasecmp(kind,"external")==0)continue;
            const char *id=obj_string(p,"id"); if(id[0]=='\0')continue; const char *name=obj_string(p,"name"); if(name[0]=='\0')name=id;
            double ms=0.0; if(json_object_has_member(p,"latency_trimmed_mean_ms"))ms=json_object_get_double_member(p,"latency_trimmed_mean_ms");
            char *label=ms>0.0?g_strdup_printf("%s  %.1f ms",name,ms):g_strdup(name); gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(t->fastest),id,label); g_free(label);
            if(selected[0]&&strcmp(id,selected)==0)active_id=id;
        }
    }
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(t->fastest),active_id); t->syncing=FALSE;
    if(root!=NULL){
        json_node_free(root);
    }
    g_free(err);
    free(out.data);
}

static void linux_telemetry_fastest_changed_v9(GtkComboBox *combo, gpointer data) {
    LinuxTelemetryV9 *t=data; if(t==NULL||t->syncing)return; const char *id=gtk_combo_box_get_active_id(combo); if(id==NULL||id[0]=='\0')return;
    if(!routervpn_require_mutation_idle(t->app,"selecting a Router VPN node")){linux_telemetry_refresh_fastest_v9(t);return;}
    gtk_widget_set_sensitive(GTK_WIDGET(combo),FALSE);
    char *body=NULL; Buffer out={0}; char *err=NULL; gboolean ok=FALSE;
    if(strcmp(id,"fastest")==0){body=g_strdup("{\"samples\":5,\"select\":true}");ok=api_request("/api/profile/fastest","POST",body,40000,&out,&err);}else{body=json_string_body("id",id);ok=api_request("/api/profile/select","POST",body,12000,&out,&err);}g_free(body);free(out.data);
    if(!ok){if(err!=NULL)append_diag(t->app,err);g_free(err);linux_telemetry_refresh_fastest_v9(t);gtk_widget_set_sensitive(GTK_WIDGET(combo),!routervpn_mutation_busy(t->app));return;}g_free(err);
    append_diag(t->app,strcmp(id,"fastest")==0?"Selected the fastest measured Router VPN node. Press Connect when ready.":"Selected Router VPN node. Press Connect when ready.");
    refresh_all(t->app); linux_unified_refresh_v8(t->base); linux_telemetry_refresh_fastest_v9(t); gtk_widget_set_sensitive(GTK_WIDGET(combo),!routervpn_mutation_busy(t->app));
}

static void linux_telemetry_set_forward_label_v9(LinuxTelemetryV9 *t,gboolean known,gboolean enabled){
    if(t==NULL||t->forward==NULL)return;
    gtk_button_set_label(GTK_BUTTON(t->forward),known?(enabled?"Forward ON":"Forward OFF"):"Forward ?");
    gtk_widget_set_tooltip_text(t->forward,known?"Real server forwarding master on the active Router VPN home node.":"Connect a Router VPN home-node path to verify the real forwarding master.");
}

static gboolean linux_telemetry_read_forward_v9(LinuxTelemetryV9*t,gboolean*enabled){
    if(t==NULL||enabled==NULL){
        return FALSE;
    }
    Buffer out={0};char*err=NULL;gboolean ok=api_request("/api/forwarding/master","GET",NULL,5000,&out,&err);if(!ok){g_free(err);free(out.data);return FALSE;}
    JsonNode*root=parse_json(out.data);free(out.data);g_free(err);if(root==NULL||!JSON_NODE_HOLDS_OBJECT(root)){if(root!=NULL)json_node_free(root);return FALSE;}JsonObject*obj=json_node_get_object(root);if(!json_object_has_member(obj,"enabled")){json_node_free(root);return FALSE;}*enabled=json_object_get_boolean_member(obj,"enabled");json_node_free(root);return TRUE;
}

static void linux_telemetry_forward_v9(GtkButton *button, gpointer data){
    LinuxTelemetryV9*t=data;if(t==NULL)return;gtk_widget_set_sensitive(GTK_WIDGET(button),FALSE);gtk_button_set_label(button,"Forward …");gboolean current=FALSE;if(!linux_telemetry_read_forward_v9(t,&current)){append_diag(t->app,"Forwarding master unavailable: connect a Router VPN home-node path first.");linux_telemetry_set_forward_label_v9(t,FALSE,FALSE);gtk_widget_set_sensitive(GTK_WIDGET(button),TRUE);return;}
    gboolean wanted=!current;char*body=g_strdup_printf("{\"enabled\":%s}",wanted?"true":"false");Buffer out={0};char*err=NULL;gboolean ok=api_request("/api/forwarding/master","PUT",body,10000,&out,&err);g_free(body);if(!ok){if(err!=NULL)append_diag(t->app,err);g_free(err);free(out.data);linux_telemetry_set_forward_label_v9(t,FALSE,FALSE);gtk_widget_set_sensitive(GTK_WIDGET(button),TRUE);return;}
    JsonNode*root=parse_json(out.data);free(out.data);g_free(err);gboolean verified=FALSE,actual=FALSE;if(root!=NULL&&JSON_NODE_HOLDS_OBJECT(root)){JsonObject*obj=json_node_get_object(root);if(json_object_has_member(obj,"enabled")){actual=json_object_get_boolean_member(obj,"enabled");verified=(actual==wanted);}}if(root!=NULL)json_node_free(root);if(!verified){append_diag(t->app,"Forwarding master response did not verify the requested state.");linux_telemetry_set_forward_label_v9(t,FALSE,FALSE);}else{char*msg=g_strdup_printf("Forwarding master %s on the active Router VPN home node.",actual?"ON":"OFF");append_diag(t->app,msg);g_free(msg);linux_telemetry_set_forward_label_v9(t,TRUE,actual);}gtk_widget_set_sensitive(GTK_WIDGET(button),TRUE);
}

static char *linux_telemetry_json_text_v9(const char *path,const char *method,const char *body,int timeout){Buffer out={0};char*err=NULL;if(api_request(path,method,body,timeout,&out,&err)){char*value=g_strdup(out.data?out.data:"{}");free(out.data);g_free(err);return value;}char*value=g_strdup(err?err:"request failed");g_free(err);free(out.data);return value;}

static char *linux_telemetry_multihop_speed_v9(void){
    Buffer out={0};char*err=NULL;
    if(!api_request("/api/multihop/status","GET",NULL,5000,&out,&err)){char*value=g_strdup(err?err:"multihop status failed");g_free(err);free(out.data);return value;}
    JsonNode*root=parse_json(out.data);free(out.data);g_free(err);
    if(root==NULL||!JSON_NODE_HOLDS_OBJECT(root)){if(root!=NULL)json_node_free(root);return g_strdup("Multihop status is not valid JSON.");}
    JsonObject*obj=json_node_get_object(root);const char*entry=obj_string(obj,"entry_id");const char*exit=obj_string(obj,"exit_id");gboolean connected=json_object_has_member(obj,"connected")&&json_object_get_boolean_member(obj,"connected");
    if(!connected||entry[0]=='\0'||exit[0]=='\0'||strcmp(entry,exit)==0){json_node_free(root);return g_strdup("Connect the actual multihop graph with different entry and exit nodes before testing routed hop speed.");}
    char*body=g_strdup_printf("{\"entry_id\":\"%s\",\"exit_id\":\"%s\",\"bytes\":4194304}",entry,exit);json_node_free(root);
    char*value=linux_telemetry_json_text_v9("/api/multihop/speed-test","POST",body,70000);g_free(body);return value;
}

static void linux_telemetry_performance_v9(GtkButton *button,gpointer data){
    (void)button;LinuxTelemetryV9*t=data;if(t==NULL)return;GtkWidget*d=gtk_dialog_new_with_buttons("Router VPN Performance",GTK_WINDOW(t->app->window),GTK_DIALOG_MODAL|GTK_DIALOG_DESTROY_WITH_PARENT,"Live path RTT",1,"50-sample selected node",2,"Real path speed",3,"Routed hop speeds",4,"Throughput + Auto MTU",5,"Close",GTK_RESPONSE_CLOSE,NULL);gtk_window_set_default_size(GTK_WINDOW(d),760,470);
    GtkWidget*area=gtk_dialog_get_content_area(GTK_DIALOG(d));GtkWidget*box=gtk_box_new(GTK_ORIENTATION_VERTICAL,8);gtk_container_set_border_width(GTK_CONTAINER(box),14);GtkWidget*note=gtk_label_new("Live RTT measures the current private tunnel. The 50-sample test is the durable node benchmark. Real path speed transfers authenticated bounded data to the active exit. Routed hop speed independently transfers to the entry and exit private agents through the active multihop graph; an unreachable hop keeps its real error. Throughput + Auto MTU is a separate path optimizer.");gtk_label_set_line_wrap(GTK_LABEL(note),TRUE);gtk_label_set_xalign(GTK_LABEL(note),0.0f);GtkWidget*result=gtk_label_new("Choose a real measurement.");gtk_label_set_selectable(GTK_LABEL(result),TRUE);gtk_label_set_line_wrap(GTK_LABEL(result),TRUE);gtk_label_set_xalign(GTK_LABEL(result),0.0f);gtk_box_pack_start(GTK_BOX(box),note,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(box),result,TRUE,TRUE,0);gtk_box_pack_start(GTK_BOX(area),box,TRUE,TRUE,0);gtk_widget_show_all(d);
    for(;;){int response=gtk_dialog_run(GTK_DIALOG(d));if(response==GTK_RESPONSE_CLOSE||response==GTK_RESPONSE_DELETE_EVENT)break;char*text=NULL;if(response==1)text=linux_telemetry_json_text_v9("/api/connection/live-latency","POST","{\"samples\":5}",12000);else if(response==2){const char*id=active_router_id(t->app);char*body=id?g_strdup_printf("{\"id\":\"%s\",\"samples\":50}",id):g_strdup("{}");text=linux_telemetry_json_text_v9("/api/profile/latency","POST",body,180000);g_free(body);refresh_all(t->app);}else if(response==3){text=linux_telemetry_json_text_v9("/api/connection/speed-test","POST","{\"bytes\":8388608}",45000);}else if(response==4){text=linux_telemetry_multihop_speed_v9();}else if(response==5){text=linux_telemetry_json_text_v9("/api/mtu/retest","POST","{}",130000);refresh_all(t->app);}if(text!=NULL){gtk_label_set_text(GTK_LABEL(result),text);g_free(text);}}
    gtk_widget_destroy(d);
}

static gboolean linux_telemetry_refresh_v9(gpointer data){
    LinuxTelemetryV9*t=data;if(t==NULL)return G_SOURCE_REMOVE;linux_telemetry_refresh_fastest_v9(t);
    if(t->fastest!=NULL)gtk_widget_set_sensitive(t->fastest,!routervpn_mutation_busy(t->app));
    Buffer out={0};char*err=NULL;if(api_request("/api/connection/live-latency","GET",NULL,3500,&out,&err)){JsonNode*root=parse_json(out.data);if(root!=NULL&&JSON_NODE_HOLDS_OBJECT(root)){JsonObject*obj=json_node_get_object(root);double ms=json_object_has_member(obj,"median_ms")?json_object_get_double_member(obj,"median_ms"):0.0;char*label=ms>0?g_strdup_printf("%.1f ms",ms):g_strdup("-- ms");gtk_label_set_text(GTK_LABEL(t->live),label);g_free(label);json_node_free(root);}}else gtk_label_set_text(GTK_LABEL(t->live),"-- ms");g_free(err);free(out.data);
    gboolean forward_enabled=FALSE;if(linux_telemetry_read_forward_v9(t,&forward_enabled))linux_telemetry_set_forward_label_v9(t,TRUE,forward_enabled);else linux_telemetry_set_forward_label_v9(t,FALSE,FALSE);
    out=(Buffer){0};err=NULL;if(api_request("/api/multihop/status","GET",NULL,3500,&out,&err)){JsonNode*root=parse_json(out.data);if(root!=NULL&&JSON_NODE_HOLDS_OBJECT(root)){JsonObject*obj=json_node_get_object(root);const char*entry=obj_string(obj,"entry_id");const char*exit=obj_string(obj,"exit_id");if(entry[0]&&exit[0]&&strcmp(entry,exit)!=0){char*body=g_strdup_printf("{\"entry_id\":\"%s\",\"exit_id\":\"%s\",\"samples\":2}",entry,exit);Buffer hop={0};char*hop_err=NULL;if(api_request("/api/multihop/live-latency","POST",body,8000,&hop,&hop_err)){JsonNode*h=parse_json(hop.data);if(h!=NULL&&JSON_NODE_HOLDS_OBJECT(h)){JsonObject*ho=json_node_get_object(h);GString*s=g_string_new("");if(json_object_has_member(ho,"entry")){JsonObject*e=json_object_get_object_member(ho,"entry");g_string_append_printf(s,"IN %.1f",json_object_get_double_member(e,"median_ms"));}if(json_object_has_member(ho,"exit")){JsonObject*x=json_object_get_object_member(ho,"exit");if(s->len)g_string_append(s," • ");g_string_append_printf(s,"OUT %.1f",json_object_get_double_member(x,"median_ms"));}if(json_object_has_member(ho,"current_path")){JsonObject*p=json_object_get_object_member(ho,"current_path");if(s->len)g_string_append(s," • ");g_string_append_printf(s,"PATH %.1f ms",json_object_get_double_member(p,"median_ms"));}gtk_label_set_text(GTK_LABEL(t->hop),s->str);g_string_free(s,TRUE);json_node_free(h);}}g_free(hop_err);free(hop.data);g_free(body);}else gtk_label_set_text(GTK_LABEL(t->hop),"");json_node_free(root);}}g_free(err);free(out.data);return G_SOURCE_CONTINUE;
}

static void linux_install_telemetry_v9(App *app){
    if(app==NULL||app->window==NULL){
        return;
    }
    LinuxUnifiedV8*base=g_object_get_data(G_OBJECT(app->window),"linux-unified-v8");if(base==NULL)return;LinuxTelemetryV9*t=g_new0(LinuxTelemetryV9,1);t->app=app;t->base=base;
    GtkWidget*connect_row=gtk_widget_get_parent(base->connect);if(GTK_IS_BOX(connect_row)){t->fastest=gtk_combo_box_text_new();gtk_widget_set_size_request(t->fastest,155,-1);gtk_widget_set_tooltip_text(t->fastest,"Select the fastest measured Router VPN node or a specific node. Use Connect separately.");gtk_box_pack_start(GTK_BOX(connect_row),t->fastest,FALSE,FALSE,0);gtk_box_reorder_child(GTK_BOX(connect_row),t->fastest,1);t->live=gtk_label_new("-- ms");gtk_box_pack_start(GTK_BOX(connect_row),t->live,FALSE,FALSE,0);gtk_box_reorder_child(GTK_BOX(connect_row),t->live,2);t->forward=linux_telemetry_button_v9("Forward ?",G_CALLBACK(linux_telemetry_forward_v9),t);gtk_widget_set_tooltip_text(t->forward,"Real server forwarding master on the active Router VPN home node.");gtk_box_pack_end(GTK_BOX(connect_row),t->forward,FALSE,FALSE,0);g_signal_connect(t->fastest,"changed",G_CALLBACK(linux_telemetry_fastest_changed_v9),t);}
    GtkWidget*multi_row=gtk_widget_get_parent(base->multihop);t->hop=gtk_label_new("");if(GTK_IS_BOX(multi_row)){gtk_box_pack_start(GTK_BOX(multi_row),t->hop,FALSE,FALSE,0);}
    GtkWidget*settings=linux_telemetry_find_button_v9(base->stack,"Open settings");if(settings!=NULL&&GTK_IS_BOX(gtk_widget_get_parent(settings))){GtkWidget*profiles=linux_telemetry_button_v9("Profiles",G_CALLBACK(linux_telemetry_profiles_v9),t);GtkWidget*performance=linux_telemetry_button_v9("Performance",G_CALLBACK(linux_telemetry_performance_v9),t);gtk_box_pack_start(GTK_BOX(gtk_widget_get_parent(settings)),profiles,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(gtk_widget_get_parent(settings)),performance,FALSE,FALSE,0);}
    g_object_set_data_full(G_OBJECT(app->window),"linux-telemetry-v9",t,g_free);linux_telemetry_refresh_fastest_v9(t);linux_telemetry_refresh_v9(t);g_timeout_add(3000,linux_telemetry_refresh_v9,t);gtk_widget_show_all(app->window);
}

/* Linux telemetry v9: fastest/specific node selector kept separate from Connect, live current-path RTT, live multihop
 * IN/OUT/PATH RTT, real authenticated path Mbps, real routed entry/exit Mbps when reachable,
 * separate MTU optimizer, Settings-row Profiles manager, Performance panel, real /api/forwarding/master ON/OFF control and map latency refresh. */
