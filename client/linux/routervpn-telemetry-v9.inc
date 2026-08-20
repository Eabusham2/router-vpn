typedef struct {
    App *app;
    LinuxUnifiedV8 *base;
    GtkWidget *fastest;
    GtkWidget *live;
    GtkWidget *hop;
    gboolean syncing;
} LinuxTelemetryV9;

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
    t->syncing=TRUE; gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(t->fastest));
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(t->fastest),"fastest","⚡ Fastest");
    if (root!=NULL && JSON_NODE_HOLDS_OBJECT(root)) {
        JsonObject *obj=json_node_get_object(root);
        JsonArray *profiles=json_object_has_member(obj,"profiles")?json_object_get_array_member(obj,"profiles"):NULL;
        for (guint i=0; profiles!=NULL && i<json_array_get_length(profiles); i++) {
            JsonObject *p=json_array_get_object_element(profiles,i); if(p==NULL)continue;
            const char *kind=obj_string(p,"node_kind"); if(kind[0]&&g_ascii_strcasecmp(kind,"external")==0)continue;
            const char *id=obj_string(p,"id"); if(id[0]=='\0')continue; const char *name=obj_string(p,"name"); if(name[0]=='\0')name=id;
            double ms=0.0; if(json_object_has_member(p,"latency_trimmed_mean_ms"))ms=json_object_get_double_member(p,"latency_trimmed_mean_ms");
            char *label=ms>0.0?g_strdup_printf("%s  %.1f ms",name,ms):g_strdup(name); gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(t->fastest),id,label); g_free(label);
        }
    }
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(t->fastest),"fastest"); t->syncing=FALSE;
    if(root!=NULL)json_node_free(root); g_free(err); free(out.data);
}

static void linux_telemetry_fastest_changed_v9(GtkComboBox *combo, gpointer data) {
    LinuxTelemetryV9 *t=data; if(t==NULL||t->syncing)return; const char *id=gtk_combo_box_get_active_id(combo); if(id==NULL||id[0]=='\0')return;
    char *body=NULL; Buffer out={0}; char *err=NULL; gboolean ok=FALSE;
    if(strcmp(id,"fastest")==0){body=g_strdup("{\"samples\":5,\"select\":true}");ok=api_request("/api/profile/fastest","POST",body,40000,&out,&err);}else{body=json_string_body("id",id);ok=api_request("/api/profile/select","POST",body,12000,&out,&err);}g_free(body);free(out.data);
    if(!ok){if(err!=NULL)append_diag(t->app,err);g_free(err);t->syncing=TRUE;gtk_combo_box_set_active_id(GTK_COMBO_BOX(t->fastest),"fastest");t->syncing=FALSE;return;}g_free(err);
    refresh_all(t->app); linux_unified_refresh_v8(t->base); linux_telemetry_refresh_fastest_v9(t); linux_unified_connect_v8(NULL,t->base);
}

static void linux_telemetry_forward_v9(GtkButton *button, gpointer data){(void)button;LinuxTelemetryV9*t=data;if(t!=NULL)linux_unified_show_detail_v8(t->base,5);}

static char *linux_telemetry_json_text_v9(const char *path,const char *method,const char *body,int timeout){Buffer out={0};char*err=NULL;if(api_request(path,method,body,timeout,&out,&err)){char*value=g_strdup(out.data?out.data:"{}");free(out.data);g_free(err);return value;}char*value=g_strdup(err?err:"request failed");g_free(err);free(out.data);return value;}

static void linux_telemetry_performance_v9(GtkButton *button,gpointer data){
    (void)button;LinuxTelemetryV9*t=data;if(t==NULL)return;GtkWidget*d=gtk_dialog_new_with_buttons("Router VPN Performance",GTK_WINDOW(t->app->window),GTK_DIALOG_MODAL|GTK_DIALOG_DESTROY_WITH_PARENT,"Live path RTT",1,"50-sample selected node",2,"Throughput + Auto MTU",3,"Close",GTK_RESPONSE_CLOSE,NULL);gtk_window_set_default_size(GTK_WINDOW(d),650,430);
    GtkWidget*area=gtk_dialog_get_content_area(GTK_DIALOG(d));GtkWidget*box=gtk_box_new(GTK_ORIENTATION_VERTICAL,8);gtk_container_set_border_width(GTK_CONTAINER(box),14);GtkWidget*note=gtk_label_new("Live RTT measures the current private tunnel. The 50-sample test is the durable node benchmark. Throughput + Auto MTU runs the bounded private-node loss/RTT/throughput comparison and may update Auto MTU; it is not a passive speed-test label.");gtk_label_set_line_wrap(GTK_LABEL(note),TRUE);gtk_label_set_xalign(GTK_LABEL(note),0.0f);GtkWidget*result=gtk_label_new("Choose a test.");gtk_label_set_selectable(GTK_LABEL(result),TRUE);gtk_label_set_line_wrap(GTK_LABEL(result),TRUE);gtk_label_set_xalign(GTK_LABEL(result),0.0f);gtk_box_pack_start(GTK_BOX(box),note,FALSE,FALSE,0);gtk_box_pack_start(GTK_BOX(box),result,TRUE,TRUE,0);gtk_box_pack_start(GTK_BOX(area),box,TRUE,TRUE,0);gtk_widget_show_all(d);
    for(;;){int response=gtk_dialog_run(GTK_DIALOG(d));if(response==GTK_RESPONSE_CLOSE||response==GTK_RESPONSE_DELETE_EVENT)break;char*text=NULL;if(response==1)text=linux_telemetry_json_text_v9("/api/connection/live-latency","POST","{\"samples\":5}",12000);else if(response==2){const char*id=active_router_id(t->app);char*body=id?g_strdup_printf("{\"id\":\"%s\",\"samples\":50}",id):g_strdup("{}");text=linux_telemetry_json_text_v9("/api/profile/latency","POST",body,180000);g_free(body);refresh_all(t->app);}else if(response==3){text=linux_telemetry_json_text_v9("/api/mtu/retest","POST","{}",130000);refresh_all(t->app);}if(text!=NULL){gtk_label_set_text(GTK_LABEL(result),text);g_free(text);}}
    gtk_widget_destroy(d);
}

static gboolean linux_telemetry_refresh_v9(gpointer data){
    LinuxTelemetryV9*t=data;if(t==NULL)return G_SOURCE_REMOVE;linux_telemetry_refresh_fastest_v9(t);
    Buffer out={0};char*err=NULL;if(api_request("/api/connection/live-latency","GET",NULL,3500,&out,&err)){JsonNode*root=parse_json(out.data);if(root!=NULL&&JSON_NODE_HOLDS_OBJECT(root)){JsonObject*obj=json_node_get_object(root);double ms=json_object_has_member(obj,"median_ms")?json_object_get_double_member(obj,"median_ms"):0.0;char*label=ms>0?g_strdup_printf("%.1f ms",ms):g_strdup("-- ms");gtk_label_set_text(GTK_LABEL(t->live),label);g_free(label);json_node_free(root);}}else gtk_label_set_text(GTK_LABEL(t->live),"-- ms");g_free(err);free(out.data);
    out=(Buffer){0};err=NULL;if(api_request("/api/multihop/status","GET",NULL,3500,&out,&err)){JsonNode*root=parse_json(out.data);if(root!=NULL&&JSON_NODE_HOLDS_OBJECT(root)){JsonObject*obj=json_node_get_object(root);const char*entry=obj_string(obj,"entry_id");const char*exit=obj_string(obj,"exit_id");if(entry[0]&&exit[0]&&strcmp(entry,exit)!=0){char*body=g_strdup_printf("{\"entry_id\":\"%s\",\"exit_id\":\"%s\",\"samples\":2}",entry,exit);Buffer hop={0};char*hop_err=NULL;if(api_request("/api/multihop/live-latency","POST",body,8000,&hop,&hop_err)){JsonNode*h=parse_json(hop.data);if(h!=NULL&&JSON_NODE_HOLDS_OBJECT(h)){JsonObject*ho=json_node_get_object(h);GString*s=g_string_new("");if(json_object_has_member(ho,"entry")){JsonObject*e=json_object_get_object_member(ho,"entry");g_string_append_printf(s,"IN %.1f",json_object_get_double_member(e,"median_ms"));}if(json_object_has_member(ho,"exit")){JsonObject*x=json_object_get_object_member(ho,"exit");if(s->len)g_string_append(s," • ");g_string_append_printf(s,"OUT %.1f",json_object_get_double_member(x,"median_ms"));}if(json_object_has_member(ho,"current_path")){JsonObject*p=json_object_get_object_member(ho,"current_path");if(s->len)g_string_append(s," • ");g_string_append_printf(s,"PATH %.1f ms",json_object_get_double_member(p,"median_ms"));}gtk_label_set_text(GTK_LABEL(t->hop),s->str);g_string_free(s,TRUE);json_node_free(h);}}g_free(hop_err);free(hop.data);g_free(body);}else gtk_label_set_text(GTK_LABEL(t->hop),"");json_node_free(root);}}g_free(err);free(out.data);return G_SOURCE_CONTINUE;
}

static void linux_install_telemetry_v9(App *app){
    if(app==NULL||app->window==NULL)return;LinuxUnifiedV8*base=g_object_get_data(G_OBJECT(app->window),"linux-unified-v8");if(base==NULL)return;LinuxTelemetryV9*t=g_new0(LinuxTelemetryV9,1);t->app=app;t->base=base;
    GtkWidget*connect_row=gtk_widget_get_parent(base->connect);if(GTK_IS_BOX(connect_row)){t->fastest=gtk_combo_box_text_new();gtk_widget_set_size_request(t->fastest,155,-1);gtk_box_pack_start(GTK_BOX(connect_row),t->fastest,FALSE,FALSE,0);gtk_box_reorder_child(GTK_BOX(connect_row),t->fastest,1);t->live=gtk_label_new("-- ms");gtk_box_pack_start(GTK_BOX(connect_row),t->live,FALSE,FALSE,0);gtk_box_reorder_child(GTK_BOX(connect_row),t->live,2);GtkWidget*forward=make_button("Forward",G_CALLBACK(linux_telemetry_forward_v9),t);gtk_box_pack_end(GTK_BOX(connect_row),forward,FALSE,FALSE,0);g_signal_connect(t->fastest,"changed",G_CALLBACK(linux_telemetry_fastest_changed_v9),t);}
    GtkWidget*multi_row=gtk_widget_get_parent(base->multihop);t->hop=gtk_label_new("");if(GTK_IS_BOX(multi_row)){gtk_box_pack_start(GTK_BOX(multi_row),t->hop,FALSE,FALSE,0);}
    GtkWidget*settings=linux_telemetry_find_button_v9(base->stack,"Open settings");if(settings!=NULL&&GTK_IS_BOX(gtk_widget_get_parent(settings))){GtkWidget*performance=make_button("Performance",G_CALLBACK(linux_telemetry_performance_v9),t);gtk_box_pack_start(GTK_BOX(gtk_widget_get_parent(settings)),performance,FALSE,FALSE,0);}
    g_object_set_data_full(G_OBJECT(app->window),"linux-telemetry-v9",t,g_free);linux_telemetry_refresh_fastest_v9(t);linux_telemetry_refresh_v9(t);g_timeout_add(3000,linux_telemetry_refresh_v9,t);gtk_widget_show_all(app->window);
}

/* Linux telemetry v9: fastest-node side dropdown, live current-path RTT, live multihop
 * IN/OUT/PATH RTT, Performance panel, Forward shortcut and map latency refresh. */
