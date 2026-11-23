#include "routervpn-ordered-candidates-v1.inc"
#include "routervpn-ordered-latency-v1.inc"

/* The panel observes generation-tagged main-owned jobs. It never owns a CURL
 * handle or lends stack memory to a worker. Main Disconnect remains reachable. */
typedef struct {
    App *app;
    GtkWidget *dialog, *result, *detail, *actions[10];
    guint64 generation;
    guint poll;
    gboolean preflight, closed, hop_result;
    JsonNode *local_source;
    char *ordered_token;
} LinuxPerformanceV17;

static void linux_performance_release_source_v17(LinuxPerformanceV17 *p) {
    g_clear_pointer(&p->local_source, json_node_free);
    g_clear_pointer(&p->ordered_token, g_free);
}
static gboolean linux_performance_local_source_v17(JsonObject *obj, int count, const char *entry, const char *exit) {
    gboolean selected = json_object_has_member(obj, "ordered_original_source");
    if (selected && json_object_has_member(obj, "ordered_local_source")) return FALSE;
    JsonObject *source = linux_ol_object_v1(obj, selected ? "ordered_original_source" : "ordered_local_source");
    const char *winner = linux_ol_string_v1(source, "selected_execution");
    if (selected && ((g_strcmp0(winner, "local") && g_strcmp0(winner, "server")) ||
        g_strcmp0(winner,linux_ol_string_v1(obj,"execution")) || !linux_ol_hex_v1(linux_ol_string_v1(source,"generation_sha256"),64))) return FALSE;
    if (!selected && g_strcmp0(linux_ol_string_v1(obj,"execution"),"local")) return FALSE;
    JsonArray *ids = linux_ol_array_v1(source, "node_ids");
    if (count < 9 || count > 96 || source == NULL || json_object_get_size(source) != (selected ? 5u : 3u) ||
        !linux_ol_hex_v1(linux_ol_string_v1(source, "source_sha256"), 64) ||
        !linux_ol_hex_v1(linux_ol_string_v1(source, "config_sha256"), 64) ||
        ids == NULL || json_array_get_length(ids) != (guint)count) return FALSE;
    GHashTable *seen = g_hash_table_new(g_str_hash, g_str_equal);
    gboolean valid = TRUE;
    for (int i = 0; i < count && valid; i++) {
        JsonNode *n = json_array_get_element(ids, (guint)i);
        const char *id = n != NULL && JSON_NODE_HOLDS_VALUE(n) && json_node_get_value_type(n) == G_TYPE_STRING ? json_node_get_string(n) : NULL;
        valid = linux_ol_text_v1(id, selected ? 64 : 128) &&
            (!selected || strspn(id,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")==strlen(id)) && (i != 0 || !g_strcmp0(id, entry)) &&
            (i != count-1 || !g_strcmp0(id, exit)) && g_hash_table_add(seen, (gpointer)id);
    }
    g_hash_table_unref(seen);
    return valid;
}
static gboolean linux_performance_local_result_v17(LinuxPerformanceV17 *p, JsonObject *obj) {
    gboolean connected = FALSE;
    JsonArray *ids = linux_ol_array_v1(json_node_get_object(p->local_source), "node_ids");
    guint count = json_array_get_length(ids);
    JsonArray *rows = linux_ol_array_v1(obj, "hops");
    gboolean selected = json_object_has_member(json_node_get_object(p->local_source), "selected_execution");
    if (obj == NULL || json_object_has_member(obj, selected ? "ordered_local_source" : "ordered_original_source")) return FALSE;
    const char *winner = selected ? linux_ol_string_v1(json_node_get_object(p->local_source),"selected_execution") : NULL;
    if (selected && g_strcmp0(winner, linux_ol_string_v1(obj,"execution"))) return FALSE;
    JsonNode *source = json_object_get_member(obj, selected ? "ordered_original_source" : "ordered_local_source");
    if (source == NULL || !json_node_equal(p->local_source, source) || rows == NULL || json_array_get_length(rows) != count ||
        !linux_ol_bool_v1(obj, "connected", &connected) || !connected || g_strcmp0(linux_ol_string_v1(obj, "mode"), "multihop") ||
        g_strcmp0(linux_ol_string_v1(obj, "entry_id"), json_array_get_string_element(ids, 0)) ||
        g_strcmp0(linux_ol_string_v1(obj, "exit_id"), json_array_get_string_element(ids, count-1)) ||
        g_strcmp0(linux_ol_string_v1(obj, "ordered_capture"), p->ordered_token) ||
        !linux_ol_number_v1(obj, "ordered_nodes", count, count, TRUE) || !linux_ol_number_v1(obj, "bytes", 8388608, 8388608, TRUE)) return FALSE;
    for (guint i = 0; i < count; i++) {
        JsonNode *n = json_array_get_element(rows, i);
        if (n == NULL || !JSON_NODE_HOLDS_OBJECT(n)) return FALSE;
        JsonObject *row = json_node_get_object(n), *speed = linux_ol_object_v1(row, "speed");
        const char *id = json_array_get_string_element(ids, i), *role = i == 0 ? "entry" : i+1 == count ? "exit" : "intermediate";
        const char *suffix = i > 0 && i+1 < count ? " to the public benchmark" : "";
        char speed_label[128], latency_label[128];
        g_snprintf(speed_label, sizeof(speed_label), "Cumulative%s%s path through node %u of %u%s transfer", selected ? " " : "", selected ? winner : "", i+1, count, suffix);
        g_snprintf(latency_label, sizeof(latency_label), "Cumulative%s%s path through node %u of %u%s HTTP response", selected ? " " : "", selected ? winner : "", i+1, count, suffix);
        if (g_strcmp0(linux_ol_string_v1(row, "role"), role) || g_strcmp0(linux_ol_string_v1(row, "router_id"), id) ||
            g_strcmp0(linux_ol_string_v1(row, "speed_label"), speed_label) || g_strcmp0(linux_ol_string_v1(row, "latency_label"), latency_label) ||
            g_strcmp0(linux_ol_string_v1(linux_ol_object_v1(row, "latency"), "router_id"), id) ||
            g_strcmp0(linux_ol_string_v1(speed, "router_id"), id) || !linux_ol_number_v1(speed, "bytes", 8388608, 8388608, TRUE)) return FALSE;
    }
    return TRUE;
}

static void linux_performance_buttons_v17(LinuxPerformanceV17 *p, gboolean working) {
    for (int id=0; id<10; id++) gtk_widget_set_sensitive(p->actions[id], !working);
    gtk_dialog_set_response_sensitive(GTK_DIALOG(p->dialog), 6, working);
}
static void linux_performance_destroy_v17(GtkWidget *widget, gpointer data) {
    (void)widget;
    LinuxPerformanceV17 *p=data;
    p->closed=TRUE;
    linux_performance_release_source_v17(p);
    if(p->poll!=0){g_source_remove(p->poll);p->poll=0;}
    linux_async_cancel_request_v17(p->app,p->generation);
}
static gboolean linux_performance_poll_v17(gpointer data);
static void linux_performance_begin_v17(LinuxPerformanceV17 *p, const char *path, const char *body, long timeout, gboolean get) {
    p->generation=linux_async_request_v17(p->app,path,body,timeout,"Performance",get);
    if(p->generation==0){gtk_label_set_text(GTK_LABEL(p->result),"Another operation is pending; no test was started.");return;}
    linux_performance_buttons_v17(p,TRUE);
    gtk_label_set_text(GTK_LABEL(p->result),get?"Checking exact active multihop identity…":"Measurement running… Cancel stops this request only.");
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(p->detail)),"",-1);
    if(p->poll==0)p->poll=g_timeout_add(50,linux_performance_poll_v17,p);
}
static gboolean linux_performance_poll_v17(gpointer data) {
    LinuxPerformanceV17 *p=data;
    LinuxAsyncActionsV16 *s=linux_async_state_v16(p->app);
    if(p->closed)return G_SOURCE_REMOVE;
    if(s!=NULL&&!s->closed&&s->generation==p->generation&&s->primary!=NULL)return G_SOURCE_CONTINUE;
    p->poll=0;
    gboolean matching=s!=NULL&&!s->closed&&s->generation==p->generation&&s->finished_generation==p->generation;
    if(matching&&s->last_ok&&p->preflight){
        p->preflight=FALSE;
        JsonNode *root=parse_json(s->last_result);
        JsonObject *obj=root!=NULL&&JSON_NODE_HOLDS_OBJECT(root)?json_node_get_object(root):NULL;
        JsonNode *connected=obj!=NULL?json_object_get_member(obj,"connected"):NULL;
        JsonNode *entry=obj!=NULL?json_object_get_member(obj,"entry_id"):NULL;
        JsonNode *exit=obj!=NULL?json_object_get_member(obj,"exit_id"):NULL;
        gboolean valid=connected&&JSON_NODE_HOLDS_VALUE(connected)&&json_node_get_value_type(connected)==G_TYPE_BOOLEAN&&json_node_get_boolean(connected)&&
            entry&&JSON_NODE_HOLDS_VALUE(entry)&&json_node_get_value_type(entry)==G_TYPE_STRING&&exit&&JSON_NODE_HOLDS_VALUE(exit)&&json_node_get_value_type(exit)==G_TYPE_STRING;
        const char *in=valid?json_node_get_string(entry):"",*out=valid?json_node_get_string(exit):"";
        JsonNode *capture=obj!=NULL?json_object_get_member(obj,"ordered_capture"):NULL;
        JsonNode *count=obj!=NULL?json_object_get_member(obj,"ordered_nodes"):NULL;
        JsonNode *local_source=obj!=NULL?json_object_get_member(obj,"ordered_local_source"):NULL;
        JsonNode *selected_source=obj!=NULL?json_object_get_member(obj,"ordered_original_source"):NULL;
        gboolean ordered=capture!=NULL||count!=NULL||local_source!=NULL||selected_source!=NULL;
        const char *token=capture&&JSON_NODE_HOLDS_VALUE(capture)&&json_node_get_value_type(capture)==G_TYPE_STRING?json_node_get_string(capture):NULL;
        gboolean ordered_valid=!ordered||(token&&strlen(token)==64&&strspn(token,"0123456789abcdef")==64&&count&&JSON_NODE_HOLDS_VALUE(count)&&json_node_get_value_type(count)==G_TYPE_INT64&&json_node_get_int(count)>=2&&json_node_get_int(count)<=96);
        if (ordered && ordered_valid) {
            int total = (int)json_node_get_int(count);
            ordered_valid = total <= 8 ? local_source == NULL && selected_source == NULL :
                linux_performance_local_source_v17(obj, total, in, out);
        }
        if(valid&&ordered_valid&&in[0]&&out[0]&&strcmp(in,out)!=0){
            JsonBuilder *b=json_builder_new();json_builder_begin_object(b);
            json_builder_set_member_name(b,"entry_id");json_builder_add_string_value(b,in);
            json_builder_set_member_name(b,"exit_id");json_builder_add_string_value(b,out);
            json_builder_set_member_name(b,"bytes");json_builder_add_int_value(b,ordered?8388608:4194304);
            if(ordered){json_builder_set_member_name(b,"ordered_capture");json_builder_add_string_value(b,token);}
            json_builder_end_object(b);JsonNode *payload=json_builder_get_root(b);JsonGenerator *g=json_generator_new();json_generator_set_root(g,payload);
            char *body=json_generator_to_data(g,NULL);
            p->hop_result=TRUE;
            if (local_source != NULL || selected_source != NULL) { p->local_source = json_node_copy(selected_source != NULL ? selected_source : local_source); p->ordered_token = g_strdup(token); }
            linux_performance_begin_v17(p,"/api/multihop/speed-test",body,ordered?100000:70000,FALSE);
            g_free(body);g_object_unref(g);json_node_free(payload);g_object_unref(b);json_node_free(root);
            if(p->poll!=0)return G_SOURCE_REMOVE; /* New generation owns the next source. */
        }else{
            if(root!=NULL)json_node_free(root);
            gtk_label_set_text(GTK_LABEL(p->result),"Connect an actual multihop graph with different entry and exit nodes first.");
        }
    }else{
        if (matching && s->last_ok && p->hop_result) {
            JsonNode *result = parse_json(s->last_result);
            JsonObject *obj = result != NULL && JSON_NODE_HOLDS_OBJECT(result) ? json_node_get_object(result) : NULL;
            gboolean bound = p->local_source != NULL ? linux_performance_local_result_v17(p, obj) :
                obj == NULL || (!json_object_has_member(obj, "ordered_local_source") && !json_object_has_member(obj, "ordered_original_source") && !linux_ol_number_v1(obj, "ordered_nodes", 9, G_MAXINT, TRUE));
            if (result != NULL) json_node_free(result);
            if (!bound) matching = FALSE;
        }
        gtk_label_set_text(GTK_LABEL(p->result),matching?(s->last_ok?"Request finished; actual controller result below.":"Request failed or was cancelled; see details."):"Request superseded; stale result discarded.");
        gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(p->detail)),matching&&s->last_result?s->last_result:"No result belongs to this request.",-1);
    }
    linux_performance_release_source_v17(p);
    p->generation=0;p->preflight=FALSE;p->hop_result=FALSE;
    linux_performance_buttons_v17(p,FALSE);
    return G_SOURCE_REMOVE;
}
static void linux_performance_response_v17(GtkDialog *dialog, int response, gpointer data) {
    LinuxPerformanceV17 *p=data;
    if(response==GTK_RESPONSE_CLOSE||response==GTK_RESPONSE_DELETE_EVENT){gtk_widget_destroy(GTK_WIDGET(dialog));return;}
    if(response==6){linux_async_cancel_request_v17(p->app,p->generation);gtk_label_set_text(GTK_LABEL(p->result),"Cancelling request; controller cleanup may still be pending.");return;}
    if(p->generation!=0||linux_async_busy_v16(p->app))return;
    const char *path=NULL,*body="{}";long timeout=12000;char *owned=NULL;
    p->preflight=FALSE;
    if(response==1){path="/api/connection/live-latency";body="{\"samples\":5}";}
    else if(response==2){
        const char *id=active_router_id(p->app);
        if(id==NULL||id[0]=='\0'){gtk_label_set_text(GTK_LABEL(p->result),"Select a real linked node first.");return;}
        JsonBuilder *b=json_builder_new();json_builder_begin_object(b);json_builder_set_member_name(b,"id");json_builder_add_string_value(b,id);json_builder_set_member_name(b,"samples");json_builder_add_int_value(b,50);json_builder_end_object(b);
        JsonNode *n=json_builder_get_root(b);JsonGenerator *g=json_generator_new();json_generator_set_root(g,n);owned=json_generator_to_data(g,NULL);json_node_free(n);g_object_unref(g);g_object_unref(b);
        path="/api/profile/latency";body=owned;timeout=180000;
    }else if(response==3){path="/api/connection/speed-test";body="{\"bytes\":8388608}";timeout=45000;}
    else if(response==4){path="/api/multihop/status";p->preflight=TRUE;timeout=5000;}
    else if(response==5){linux_mtu_dialog_v20(p->app);return;}
    else if(response==7){linux_external_comparison_open(p->app);return;}
    else if(response==8){linux_ordered_candidates_open(p->app);return;}
    else if(response==9){linux_ordered_candidates_open_purpose(p->app,TRUE);return;}
    else if(response==10){linux_ordered_candidates_open_captured(p->app,TRUE,TRUE);return;}
    else if(response==11){linux_ordered_latency_open_v1(p->app);return;}
    if(path!=NULL)linux_performance_begin_v17(p,path,body,timeout,p->preflight);
    g_free(owned);
}
static void linux_performance_action_v17(GtkButton *button, gpointer data) {
    LinuxPerformanceV17 *p=data;
    gtk_dialog_response(GTK_DIALOG(p->dialog),GPOINTER_TO_INT(g_object_get_data(G_OBJECT(button),"performance-response")));
}
static void linux_telemetry_performance_v9(GtkButton *button, gpointer data) {
    (void)button;LinuxTelemetryV9 *t=data;if(t==NULL)return;
    LinuxPerformanceV17 *p=g_new0(LinuxPerformanceV17,1);p->app=t->app;
    p->dialog=gtk_dialog_new_with_buttons("Router VPN Performance",GTK_WINDOW(t->app->window),GTK_DIALOG_DESTROY_WITH_PARENT,
        "Cancel test",6,"Close",GTK_RESPONSE_CLOSE,NULL);
    gtk_window_set_default_size(GTK_WINDOW(p->dialog),760,470);
    gtk_widget_set_size_request(p->dialog,640,400);
    GtkWidget *area=gtk_dialog_get_content_area(GTK_DIALOG(p->dialog));gtk_container_set_border_width(GTK_CONTAINER(area),14);
    GtkWidget *flow=gtk_flow_box_new();gtk_flow_box_set_selection_mode(GTK_FLOW_BOX(flow),GTK_SELECTION_NONE);
    gtk_flow_box_set_min_children_per_line(GTK_FLOW_BOX(flow),1);gtk_flow_box_set_max_children_per_line(GTK_FLOW_BOX(flow),2);
    const char *labels[]={"Live path response","50-sample selected node","Real path speed","Routed hop speeds","Throughput + Auto MTU","Compare external / connect fastest","Candidates through connected prefix","Test saved Local path","Test selected prefix only","50 responses per hop"};
    for(int i=0;i<10;i++){p->actions[i]=gtk_button_new_with_label(labels[i]);g_object_set_data(G_OBJECT(p->actions[i]),"performance-response",GINT_TO_POINTER(i>=5?i+2:i+1));g_signal_connect(p->actions[i],"clicked",G_CALLBACK(linux_performance_action_v17),p);gtk_container_add(GTK_CONTAINER(flow),p->actions[i]);}
    gtk_box_pack_start(GTK_BOX(area),flow,FALSE,FALSE,4);
    p->result=gtk_label_new("Choose a real measurement. Disconnect/Emergency Stop remain available on the map.");gtk_label_set_line_wrap(GTK_LABEL(p->result),TRUE);gtk_label_set_max_width_chars(GTK_LABEL(p->result),56);gtk_box_pack_start(GTK_BOX(area),p->result,FALSE,FALSE,8);
    GtkWidget *scroll=gtk_scrolled_window_new(NULL,NULL);p->detail=gtk_text_view_new();gtk_text_view_set_editable(GTK_TEXT_VIEW(p->detail),FALSE);gtk_text_view_set_monospace(GTK_TEXT_VIEW(p->detail),TRUE);
    gtk_container_add(GTK_CONTAINER(scroll),p->detail);gtk_box_pack_start(GTK_BOX(area),scroll,TRUE,TRUE,0);
    g_object_set_data_full(G_OBJECT(p->dialog),"linux-performance-v17",p,g_free);
    g_signal_connect(p->dialog,"destroy",G_CALLBACK(linux_performance_destroy_v17),p);
    g_signal_connect(p->dialog,"response",G_CALLBACK(linux_performance_response_v17),p);
    linux_performance_buttons_v17(p,FALSE);gtk_widget_show_all(p->dialog);
}
