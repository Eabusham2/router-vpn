typedef struct {
    App *app;
    LinuxUnifiedV8 *base;
    GtkWidget *fastest;
    GtkWidget *live;
    GtkWidget *hop;
    GtkWidget *forward;
    gboolean syncing;
    RVHttpJobV16 *live_job;
    JsonNode *live_capture;
    gint64 live_started, live_deadline;
    guint live_poll, refresh_poll;
    guint64 live_generation;
    char *live_id;
    double live_ms;
} LinuxTelemetryV9;

#include "routervpn-connection-profiles-v11.inc"

static void linux_external_comparison_open(App *app);

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
    if (t == NULL || t->fastest == NULL || linux_async_busy_v16(t->app)) return;
    Buffer out={0}; char *err=NULL;
    if (!api_request("/api/profiles","GET",NULL,4000,&out,&err)) { g_free(err); free(out.data); return; }
    JsonNode *root=parse_json(out.data);
    const char *active_id="fastest";
    t->syncing=TRUE; gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(t->fastest));
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(t->fastest),"fastest","⚡ Fastest Router · 50 TCP samples");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(t->fastest),"external-comparison","External paths · 50 responses…");
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
    if(strcmp(id,"external-comparison")==0){linux_external_comparison_open(t->app);linux_telemetry_refresh_fastest_v9(t);return;}
    if(!routervpn_require_mutation_idle(t->app,"selecting a Router VPN node")){linux_telemetry_refresh_fastest_v9(t);return;}
    char *body = strcmp(id,"fastest")==0 ? g_strdup("{\"samples\":50,\"select\":true}") : json_string_body("id",id);
    guint64 request = linux_async_request_v17(t->app, strcmp(id,"fastest")==0 ? "/api/profile/fastest" : "/api/profile/select", body, strcmp(id,"fastest")==0 ? 185000 : 12000, strcmp(id,"fastest")==0 ? "Fastest: 50 TCP samples per node, ranked by trimmed mean. Cancel stops this round." : "Node selection; Press Connect when ready.", FALSE);
    g_free(body);
    if(request != 0) {gtk_widget_set_sensitive(GTK_WIDGET(combo),FALSE);append_diag(t->app,"Measuring/selecting node; selection is not complete until the controller confirms it. Press Connect when ready.");}

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

/* Performance preserves Live path RTT, 50-sample selected node, Real path speed,
 * Routed hop speeds and Throughput + Auto MTU as separate owned requests.
 * /api/connection/speed-test and /api/multihop/speed-test remain real transfers. */

/* One panel retains one server-issued intent. Every short HTTP worker is joined
 * before reuse/free; closing cancels that intent and observes its final drain. */
typedef struct {
    App *app;
    GtkWidget *dialog, *status, *detail, *compare, *fastest, *cancel;
    RVHttpJobV16 *job;
    guint poll;
    int phase, choice; /* offer=1, start=2, poll=3, cancel=4; choice=-1 previews */
    char request[33], cohort[65];
    gboolean started, finished, cancel_wanted, cancel_accepted, close_wanted, closed, held;
    gint64 next_poll;
} LinuxExternalComparison;

static JsonNode *linux_ec_member(JsonObject *o,const char *name){return o!=NULL&&json_object_has_member(o,name)?json_object_get_member(o,name):NULL;}
static JsonObject *linux_ec_object(JsonObject *o,const char *name){JsonNode*n=linux_ec_member(o,name);return n!=NULL&&JSON_NODE_HOLDS_OBJECT(n)?json_node_get_object(n):NULL;}
static JsonArray *linux_ec_array(JsonObject *o,const char *name){JsonNode*n=linux_ec_member(o,name);return n!=NULL&&JSON_NODE_HOLDS_ARRAY(n)?json_node_get_array(n):NULL;}
static const char *linux_ec_string(JsonObject *o,const char *name){JsonNode*n=linux_ec_member(o,name);return n!=NULL&&JSON_NODE_HOLDS_VALUE(n)&&json_node_get_value_type(n)==G_TYPE_STRING?json_node_get_string(n):"";}
static gboolean linux_ec_bool(JsonObject *o,const char *name){JsonNode*n=linux_ec_member(o,name);return n!=NULL&&JSON_NODE_HOLDS_VALUE(n)&&json_node_get_value_type(n)==G_TYPE_BOOLEAN&&json_node_get_boolean(n);}
static double linux_ec_number(JsonObject *o,const char *name){JsonNode*n=linux_ec_member(o,name);return n!=NULL&&JSON_NODE_HOLDS_VALUE(n)&&(json_node_get_value_type(n)==G_TYPE_DOUBLE||json_node_get_value_type(n)==G_TYPE_INT64)?json_node_get_double(n):NAN;}
static gboolean linux_ec_token(const char *text,size_t length){if(text==NULL||strlen(text)!=length)return FALSE;for(size_t i=0;i<length;i++){if(!((text[i]>='0'&&text[i]<='9')||(text[i]>='a'&&text[i]<='f')))return FALSE;}return TRUE;}
static gboolean linux_ec_matches(JsonObject *o,const char *request,const char *cohort){const char*r=linux_ec_string(o,"request_id"),*c=linux_ec_string(o,"cohort_id");return linux_ec_token(r,32)&&linux_ec_token(c,64)&&strcmp(r,request)==0&&strcmp(c,cohort)==0;}
static double linux_ec_score(JsonObject *o){
    JsonObject*b=linux_ec_object(o,"benchmark"),*d=linux_ec_object(b,"distribution");
    if(strcmp(linux_ec_string(o,"status"),"complete")||linux_ec_number(b,"schema")!=1||strcmp(linux_ec_string(b,"measurement"),"routed-https-response-after-tls")||strcmp(linux_ec_string(b,"endpoint"),"https://speed.cloudflare.com/__down?bytes=1")||linux_ec_number(b,"attempts")!=50||linux_ec_number(b,"failed")!=0||linux_ec_number(d,"samples")!=50)return NAN;
    double ms=linux_ec_number(b,"trimmed_mean_ms");return isfinite(ms)&&ms>0?ms:NAN;
}
static void linux_ec_append_rows(GString *text,JsonArray *rows,gboolean history){
    g_string_append(text,history?"Saved history — these values are not a current winner.\n":"50 routed HTTPS responses · 10% trimmed mean\n");
    for(guint i=0;rows!=NULL&&i<json_array_get_length(rows);i++){
        JsonNode*n=json_array_get_element(rows,i);if(n==NULL||!JSON_NODE_HOLDS_OBJECT(n))continue;JsonObject*r=json_node_get_object(n);
        const char*name=linux_ec_string(r,"name");if(!name[0])name=linux_ec_string(r,"id");const char*entry=linux_ec_string(r,"entry_name");if(!entry[0])entry=linux_ec_string(r,"entry_id");
        g_string_append_printf(text,"%s · %s%s",name,entry[0]?"Via ":"Direct saved path",entry);double ms=linux_ec_score(r);
        if(isfinite(ms))g_string_append_printf(text," · %s · %.2f ms\n",linux_ec_string(r,"execution"),ms);
        else{const char*status=linux_ec_string(r,"failure");if(!status[0])status=linux_ec_string(r,"status");g_string_append_printf(text," · %s\n",status);}
    }
}
static void linux_ec_lease(LinuxExternalComparison *s,gboolean hold){
    LinuxAsyncActionsV16*a=linux_async_state_v16(s->app);
    if(hold&&!s->held){if(a!=NULL)a->auxiliary_jobs++;s->held=TRUE;}
    else if(!hold&&s->held){if(a!=NULL&&a->auxiliary_jobs>0)a->auxiliary_jobs--;s->held=FALSE;}
}
static void linux_ec_controls(LinuxExternalComparison*s){gboolean idle=s->job==NULL&&(!s->started||s->finished);gtk_widget_set_sensitive(s->compare,idle);gtk_widget_set_sensitive(s->fastest,idle);gtk_widget_set_sensitive(s->cancel,s->started&&!s->finished);}
static void linux_ec_send(LinuxExternalComparison*s,int phase,const char*path,const char*body){
    if(s->closed||s->job!=NULL){return;}
    s->phase=phase;s->job=rv_http_start_method_v17(path,body!=NULL?body:"",10000,"External comparison",body==NULL);
    if(s->job==NULL){gtk_label_set_text(GTK_LABEL(s->status),"Could not start this comparison request. Cancellation will be retried if a batch was started.");if(s->started&&!s->finished){s->cancel_wanted=TRUE;s->cancel_accepted=FALSE;}s->next_poll=g_get_monotonic_time()+G_USEC_PER_SEC;}
    linux_ec_controls(s);
}
static char *linux_ec_body(LinuxExternalComparison*s,gboolean include_choice){return include_choice?g_strdup_printf("{\"request_id\":\"%s\",\"cohort_id\":\"%s\",\"connect_fastest\":%s}",s->request,s->cohort,s->choice==1?"true":"false"):g_strdup_printf("{\"request_id\":\"%s\",\"cohort_id\":\"%s\"}",s->request,s->cohort);}
static void linux_ec_receive(LinuxExternalComparison*s,JsonObject*o,int phase){
    if(phase==1){
        const char*r=linux_ec_string(o,"request_id"),*c=linux_ec_string(o,"cohort_id");JsonArray*candidates=linux_ec_array(o,"candidates");
        if(!linux_ec_token(r,32)||!linux_ec_token(c,64)||candidates==NULL||json_array_get_length(candidates)<1||json_array_get_length(candidates)>128){gtk_label_set_text(GTK_LABEL(s->status),"Saved external paths could not be captured. Refresh and try again.");s->choice=-1;return;}
        g_strlcpy(s->request,r,sizeof(s->request));g_strlcpy(s->cohort,c,sizeof(s->cohort));GString*detail=g_string_new("");
        for(guint i=0;i<json_array_get_length(candidates);i++){JsonNode*n=json_array_get_element(candidates,i);if(!JSON_NODE_HOLDS_OBJECT(n))continue;JsonObject*row=json_node_get_object(n);g_string_append_printf(detail,"%s · %s · %s\n",linux_ec_string(row,"name"),linux_ec_bool(row,"has_entry")?linux_ec_string(row,"entry_id"):"Direct",linux_ec_string(row,"protocol"));}
        JsonArray*history=linux_ec_array(linux_ec_object(o,"history"),"rows");if(history!=NULL&&json_array_get_length(history)>0){g_string_append(detail,"\n");linux_ec_append_rows(detail,history,TRUE);}
        gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(s->detail)),detail->str,-1);g_string_free(detail,TRUE);
        char*message=g_strdup_printf("%u saved external paths. Compare, or explicitly compare and connect the winner.\n%s",json_array_get_length(candidates),linux_ec_string(o,"warning"));gtk_label_set_text(GTK_LABEL(s->status),message);g_free(message);
        if(s->choice>=0&&!s->close_wanted){s->started=TRUE;s->finished=FALSE;linux_ec_lease(s,TRUE);char*body=linux_ec_body(s,TRUE);linux_ec_send(s,2,"/api/speed-lab/external-comparison",body);g_free(body);}return;
    }
    if(!linux_ec_matches(o,s->request,s->cohort)){gtk_label_set_text(GTK_LABEL(s->status),"A response belongs to another comparison. Result discarded; cancelling only the captured request.");s->cancel_wanted=TRUE;s->cancel_accepted=FALSE;return;}
    if(phase==4)s->cancel_accepted=TRUE;
    GString*message=g_string_new(linux_ec_string(o,"stage"));const char*progress=linux_ec_string(o,"progress");if(progress[0])g_string_append_printf(message," · %s",progress);
    if(linux_ec_bool(o,"complete")){g_string_append(message,linux_ec_bool(o,"committed")?(strcmp(linux_ec_string(o,"stage"),"connected")==0?"\nThe freshly proved winner is connected and selected.":"\nThe winner selection was saved. Check the current connection status."):linux_ec_bool(o,"restored")?"\nYour original connection state was restored.":"\nRestoration is unresolved; check the main connection status.");if(!linux_ec_bool(o,"drained"))g_string_append(message,"\nCleanup is pending. Retry Cancel.");}
    const char*failure=linux_ec_string(o,"failure"),*warning=linux_ec_string(o,"warning");if(failure[0])g_string_append_printf(message,"\n%s",failure);if(warning[0])g_string_append_printf(message,"\n%s",warning);gtk_label_set_text(GTK_LABEL(s->status),message->str);g_string_free(message,TRUE);
    GString*detail=g_string_new("");linux_ec_append_rows(detail,linux_ec_array(o,"rows"),FALSE);gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(s->detail)),detail->str,-1);g_string_free(detail,TRUE);
    s->finished=linux_ec_bool(o,"complete")&&linux_ec_bool(o,"drained");
    if(s->finished){s->choice=-1;linux_ec_lease(s,FALSE);refresh_all(s->app);}
    else if(linux_ec_bool(o,"complete")){s->cancel_wanted=TRUE;s->cancel_accepted=FALSE;}
}
static gboolean linux_ec_tick(gpointer data){
    LinuxExternalComparison*s=data;if(s->closed)return G_SOURCE_REMOVE;
    if(s->job!=NULL&&rv_http_ready_v16(s->job)){
        RVHttpJobV16*job=s->job;int phase=s->phase;s->job=NULL;gboolean ok=!atomic_load(&job->cancelled)&&job->result==CURLE_OK&&job->status>=200&&job->status<300;JsonNode*root=ok?parse_json(job->response):NULL;
        if(root!=NULL&&JSON_NODE_HOLDS_OBJECT(root)){linux_ec_receive(s,json_node_get_object(root),phase);}
        else{gtk_label_set_text(GTK_LABEL(s->status),"The comparison request failed. A started batch will be cancelled and observed until cleanup is confirmed.");if(s->started&&!s->finished){s->cancel_wanted=TRUE;s->cancel_accepted=FALSE;}else s->choice=-1;}
        if(root!=NULL){json_node_free(root);}
        rv_http_free_v16(job);s->next_poll=g_get_monotonic_time()+650000;
    }
    if(s->close_wanted&&s->job==NULL&&(!s->started||s->finished)){s->poll=0;gtk_widget_destroy(s->dialog);return G_SOURCE_REMOVE;}
    if(s->job==NULL&&s->started&&!s->finished&&g_get_monotonic_time()>=s->next_poll){
        if(s->cancel_wanted&&!s->cancel_accepted){char*body=linux_ec_body(s,FALSE);linux_ec_send(s,4,"/api/speed-lab/external-comparison/cancel",body);g_free(body);}
        else{char*path=g_strdup_printf("/api/speed-lab/external-comparison?request_id=%s",s->request);linux_ec_send(s,3,path,NULL);g_free(path);}
    }
    linux_ec_controls(s);return G_SOURCE_CONTINUE;
}
static void linux_ec_cancel(LinuxExternalComparison*s){s->cancel_wanted=TRUE;s->cancel_accepted=FALSE;gtk_label_set_text(GTK_LABEL(s->status),"Cancelling this comparison; waiting for workers and original-state restoration.");}
static gboolean linux_ec_delete(GtkWidget*widget,GdkEvent*event,gpointer data){(void)widget;(void)event;LinuxExternalComparison*s=data;if(s->job!=NULL||(s->started&&!s->finished)){s->close_wanted=TRUE;linux_ec_cancel(s);if(!s->started)rv_http_cancel_v16(s->job);return TRUE;}return FALSE;}
static void linux_ec_destroy(GtkWidget*widget,gpointer data){
    (void)widget;LinuxExternalComparison*s=data;s->closed=TRUE;if(s->poll!=0){g_source_remove(s->poll);s->poll=0;}rv_http_cancel_v16(s->job);rv_http_free_v16(s->job);s->job=NULL;
    /* A forced parent teardown still sends only the captured cancellation.
     * Controller shutdown owns the remaining native drain; this request owns
     * no UI callback and its bounded worker is joined before the panel frees. */
    if(s->started&&!s->finished&&linux_ec_token(s->request,32)&&linux_ec_token(s->cohort,64)){
        char*body=linux_ec_body(s,FALSE);RVHttpJobV16*cancel=rv_http_start_method_v17("/api/speed-lab/external-comparison/cancel",body,3000,"Cancel external comparison",0);g_free(body);
        if(cancel!=NULL){gint64 deadline=g_get_monotonic_time()+3500000;while(!rv_http_ready_v16(cancel)&&g_get_monotonic_time()<deadline)g_usleep(10000);rv_http_free_v16(cancel);}
    }
    linux_ec_lease(s,FALSE);if(s->app->window!=NULL&&g_object_get_data(G_OBJECT(s->app->window),"linux-external-comparison")==s)g_object_set_data(G_OBJECT(s->app->window),"linux-external-comparison",NULL);
}
static void linux_ec_action(GtkButton*button,gpointer data){
    LinuxExternalComparison*s=data;int action=GPOINTER_TO_INT(g_object_get_data(G_OBJECT(button),"external-comparison-action"));
    if(action==3){linux_ec_cancel(s);return;}if(action==4){gtk_window_close(GTK_WINDOW(s->dialog));return;}
    if(s->job!=NULL||(s->started&&!s->finished)||!routervpn_require_mutation_idle(s->app,"comparing saved external paths"))return;
    s->choice=action==2?1:0;s->started=FALSE;s->finished=TRUE;s->cancel_wanted=FALSE;s->cancel_accepted=FALSE;gtk_label_set_text(GTK_LABEL(s->status),"Capturing the current saved external paths…");linux_ec_send(s,1,"/api/speed-lab/external-comparison",NULL);
}
static void linux_external_comparison_open(App*app){
    if(app==NULL||app->window==NULL){return;}
    LinuxExternalComparison*existing=g_object_get_data(G_OBJECT(app->window),"linux-external-comparison");if(existing!=NULL&&!existing->closed){gtk_window_present(GTK_WINDOW(existing->dialog));return;}
    LinuxExternalComparison*s=g_new0(LinuxExternalComparison,1);s->app=app;s->choice=-1;s->finished=TRUE;s->dialog=gtk_window_new(GTK_WINDOW_TOPLEVEL);gtk_window_set_title(GTK_WINDOW(s->dialog),"Compare external paths");gtk_window_set_transient_for(GTK_WINDOW(s->dialog),GTK_WINDOW(app->window));gtk_window_set_destroy_with_parent(GTK_WINDOW(s->dialog),TRUE);gtk_window_set_default_size(GTK_WINDOW(s->dialog),820,560);
    GtkWidget*box=gtk_box_new(GTK_ORIENTATION_VERTICAL,12);gtk_container_set_border_width(GTK_CONTAINER(box),18);gtk_container_add(GTK_CONTAINER(s->dialog),box);GtkWidget*title=gtk_label_new("Find the fastest saved external path");gtk_box_pack_start(GTK_BOX(box),title,FALSE,FALSE,0);
    GtkWidget*note=gtk_label_new("Each saved path keeps its own entry, DNS and protection. Every valid path sends 50 HTTPS responses through its proved exit to the same Cloudflare endpoint. Timing starts after TLS; lowest 10% trimmed mean wins. Router TCP reachability is separate. Compare restores your original connection between trials; connecting the winner requires the explicit second action.");gtk_label_set_line_wrap(GTK_LABEL(note),TRUE);gtk_label_set_max_width_chars(GTK_LABEL(note),88);gtk_box_pack_start(GTK_BOX(box),note,FALSE,FALSE,0);
    s->status=gtk_label_new("Loading saved external paths…");gtk_label_set_line_wrap(GTK_LABEL(s->status),TRUE);gtk_box_pack_start(GTK_BOX(box),s->status,FALSE,FALSE,0);GtkWidget*scroll=gtk_scrolled_window_new(NULL,NULL);s->detail=gtk_text_view_new();gtk_text_view_set_editable(GTK_TEXT_VIEW(s->detail),FALSE);gtk_text_view_set_monospace(GTK_TEXT_VIEW(s->detail),TRUE);gtk_container_add(GTK_CONTAINER(scroll),s->detail);gtk_box_pack_start(GTK_BOX(box),scroll,TRUE,TRUE,0);
    GtkWidget*buttons=gtk_button_box_new(GTK_ORIENTATION_HORIZONTAL);const char*labels[]={"Compare external paths","Compare + connect fastest","Cancel","Close"};GtkWidget*items[4];for(int i=0;i<4;i++){items[i]=gtk_button_new_with_label(labels[i]);g_object_set_data(G_OBJECT(items[i]),"external-comparison-action",GINT_TO_POINTER(i+1));g_signal_connect(items[i],"clicked",G_CALLBACK(linux_ec_action),s);gtk_container_add(GTK_CONTAINER(buttons),items[i]);}s->compare=items[0];s->fastest=items[1];s->cancel=items[2];gtk_box_pack_start(GTK_BOX(box),buttons,FALSE,FALSE,0);
    g_object_set_data(G_OBJECT(app->window),"linux-external-comparison",s);g_object_set_data_full(G_OBJECT(s->dialog),"external-comparison-state",s,g_free);g_signal_connect(s->dialog,"delete-event",G_CALLBACK(linux_ec_delete),s);g_signal_connect(s->dialog,"destroy",G_CALLBACK(linux_ec_destroy),s);s->poll=g_timeout_add(200,linux_ec_tick,s);linux_ec_send(s,1,"/api/speed-lab/external-comparison",NULL);gtk_widget_show_all(s->dialog);
}

#include "routervpn-performance-v17.inc"

static gboolean linux_live_paused(LinuxTelemetryV9*t){
    if(linux_async_busy_v16(t->app))return TRUE;
    gboolean paused=FALSE;GList*windows=gtk_window_list_toplevels();
    for(GList*i=windows;i!=NULL;i=i->next){GtkWidget*w=i->data;if(gtk_widget_get_visible(w)&&gtk_window_get_transient_for(GTK_WINDOW(w))==GTK_WINDOW(t->app->window)&&(g_object_get_data(G_OBJECT(w),"linux-performance-v17")!=NULL||g_object_get_data(G_OBJECT(w),"linux-speed-lab-v12")!=NULL||g_object_get_data(G_OBJECT(w),"external-comparison-state")!=NULL))paused=TRUE;}
    g_list_free(windows);return paused;
}
static void linux_live_clear(LinuxTelemetryV9*t){t->live_ms=0;t->live_deadline=0;g_clear_pointer(&t->live_id,g_free);gtk_label_set_text(GTK_LABEL(t->live),"-- ms");if(t->app->map!=NULL)gtk_widget_queue_draw(t->app->map);}
static gboolean linux_live_receipt(JsonObject*o,gint64 now_ms,gint64 uptime,gint64 started,double*median,gint64*deadline){
    JsonObject*r=linux_ec_object(o,"response"),*d=linux_ec_object(r,"distribution");
    if(strcmp(linux_ec_string(o,"measurement"),"routed-https-response-after-tls")||!linux_ec_bool(o,"connected")||r==NULL||d==NULL||json_object_get_size(r)!=5||json_object_get_size(d)!=7||linux_ec_number(r,"schema")!=1||linux_ec_number(r,"attempts")!=3||linux_ec_number(d,"samples")!=3||strcmp(linux_ec_string(r,"measurement"),"routed-https-response-after-tls")||strcmp(linux_ec_string(r,"endpoint"),"https://speed.cloudflare.com/__down?bytes=1"))return FALSE;
    const char*keys[]={"profile_id","profile_token","session_id","request_id","source_sha256","config_sha256","network_sha256"};
    for(guint i=0;i<G_N_ELEMENTS(keys);i++){const char*v=linux_ec_string(o,keys[i]);if(!v[0]||(i!=0&&!linux_ec_token(v,(i==2||i==3)?32:64)))return FALSE;}
    const char*forbidden[]={"median_ms","benchmark","idle","download","upload"};for(guint i=0;i<G_N_ELEMENTS(forbidden);i++)if(linux_ec_member(o,forbidden[i])!=NULL)return FALSE;
    double min=linux_ec_number(d,"min_ms"),ms=linux_ec_number(d,"median_ms"),avg=linux_ec_number(d,"average_ms"),p90=linux_ec_number(d,"p90_ms"),max=linux_ec_number(d,"max_ms"),jitter=linux_ec_number(d,"jitter_ms"),at=linux_ec_number(o,"measured_at"),left=linux_ec_number(o,"expires_in_ms");
    double values[]={min,ms,avg,p90,max,jitter,at,left};for(guint i=0;i<G_N_ELEMENTS(values);i++)if(!isfinite(values[i]))return FALSE;
    if(min<=0||min>ms||ms>p90||p90>max||max>10000||avg<min||avg>max||jitter<0||jitter>max-min||left<=0||left>10000||now_ms<at||now_ms-at>=10000||uptime<started)return FALSE;
    double remaining=fmin(left*1000-(uptime-started),(10000-(now_ms-at))*1000);if(remaining<=0)return FALSE;
    *median=ms;*deadline=uptime+(gint64)remaining;return TRUE;
}
static gboolean linux_live_matches(JsonObject*a,JsonObject*b){
    const char*keys[]={"profile_id","profile_token","session_id","request_id","source_sha256","config_sha256","network_sha256"};for(guint i=0;i<G_N_ELEMENTS(keys);i++)if(strcmp(linux_ec_string(a,keys[i]),linux_ec_string(b,keys[i])))return FALSE;
    JsonNode*x=linux_ec_member(a,"response"),*y=linux_ec_member(b,"response");return x!=NULL&&y!=NULL&&json_node_equal(x,y);
}
static double linux_live_map_ms(App*app,const char*id){
    LinuxTelemetryV9*t=app!=NULL&&app->window!=NULL?g_object_get_data(G_OBJECT(app->window),"linux-telemetry-v9"):NULL;
    LinuxAsyncActionsV16*s=app!=NULL?linux_async_state_v16(app):NULL;
    return t!=NULL&&t->live_id!=NULL&&g_strcmp0(t->live_id,id)==0&&g_strcmp0(active_router_id(app),id)==0&&g_get_monotonic_time()<t->live_deadline&&!linux_live_paused(t)&&(s==NULL||s->generation==t->live_generation)?t->live_ms:0;
}
static gboolean linux_live_tick(gpointer data){
    LinuxTelemetryV9*t=data;LinuxAsyncActionsV16*s=linux_async_state_v16(t->app);
    gboolean current=!linux_live_paused(t)&&(s==NULL||s->generation==t->live_generation);
    if(!current||(t->live_id!=NULL&&g_strcmp0(t->live_id,active_router_id(t->app))!=0)||(t->live_deadline>0&&g_get_monotonic_time()>=t->live_deadline))linux_live_clear(t);
    if(!current&&t->live_job!=NULL)rv_http_cancel_v16(t->live_job);
    if(t->live_job==NULL||!rv_http_ready_v16(t->live_job))return G_SOURCE_CONTINUE;
    RVHttpJobV16*job=t->live_job;t->live_job=NULL;
    gboolean ok=current&&!atomic_load(&job->cancelled)&&job->result==CURLE_OK&&job->status>=200&&job->status<300;
    JsonNode*root=ok?parse_json(job->response):NULL;JsonObject*o=root!=NULL&&JSON_NODE_HOLDS_OBJECT(root)?json_node_get_object(root):NULL;
    double ms=0;gint64 deadline=0;gboolean valid=linux_live_receipt(o,g_get_real_time()/1000,g_get_monotonic_time(),t->live_started,&ms,&deadline);
    if(valid&&t->live_capture==NULL){
        t->live_capture=json_node_copy(root);char*path=g_strdup_printf("/api/connection/live-latency?request_id=%s",linux_ec_string(o,"request_id"));t->live_job=rv_http_start_method_v17(path,"",3000,"Validate live HTTPS",1);g_free(path);
    }else if(valid&&linux_live_matches(json_node_get_object(t->live_capture),o)&&g_strcmp0(active_router_id(t->app),linux_ec_string(o,"profile_id"))==0){
        t->live_ms=ms;t->live_deadline=deadline;g_free(t->live_id);t->live_id=g_strdup(linux_ec_string(o,"profile_id"));char*label=g_strdup_printf("%.1f ms HTTPS",ms);gtk_label_set_text(GTK_LABEL(t->live),label);g_free(label);gtk_widget_set_tooltip_text(t->live,"3 HTTPS responses through the current proved VPN path and selected DNS, timed after DNS/TCP/TLS preparation. Expires after 10 seconds; separate from ICMP, private-node RTT and saved50.");
    }else if(o!=NULL&&linux_ec_member(o,"measurement")==NULL&&isfinite(linux_ec_number(o,"median_ms"))&&linux_ec_number(o,"median_ms")>0){linux_live_clear(t);char*label=g_strdup_printf("%.1f ms",linux_ec_number(o,"median_ms"));gtk_label_set_text(GTK_LABEL(t->live),label);g_free(label);gtk_widget_set_tooltip_text(t->live,"HTTP RTT through the current private Router-node path.");}
    else linux_live_clear(t);
    if(root!=NULL)json_node_free(root);
    rv_http_free_v16(job);
    if(t->live_job==NULL&&t->live_capture!=NULL){json_node_free(t->live_capture);t->live_capture=NULL;}
    if(t->app->map!=NULL)gtk_widget_queue_draw(t->app->map);
    return G_SOURCE_CONTINUE;
}
static void linux_live_start(LinuxTelemetryV9*t){
    if(t->live_job!=NULL||linux_live_paused(t))return;
    LinuxAsyncActionsV16*s=linux_async_state_v16(t->app);t->live_generation=s!=NULL?s->generation:0;t->live_started=g_get_monotonic_time();
    t->live_job=rv_http_start_method_v17("/api/connection/live-latency","",3500,"Current path response",1);
}
static void linux_telemetry_free(gpointer data){LinuxTelemetryV9*t=data;if(t->live_poll)g_source_remove(t->live_poll);if(t->refresh_poll)g_source_remove(t->refresh_poll);rv_http_cancel_v16(t->live_job);rv_http_free_v16(t->live_job);if(t->live_capture)json_node_free(t->live_capture);g_free(t->live_id);g_free(t);}

static gboolean linux_telemetry_refresh_v9(gpointer data){
    LinuxTelemetryV9*t=data;if(t==NULL)return G_SOURCE_REMOVE;
    if(linux_async_busy_v16(t->app)){gtk_widget_set_sensitive(t->fastest,FALSE);gtk_label_set_text(GTK_LABEL(t->live),"-- ms");return G_SOURCE_CONTINUE;}
    linux_telemetry_refresh_fastest_v9(t);
    if(t->fastest!=NULL)gtk_widget_set_sensitive(t->fastest,!routervpn_mutation_busy(t->app));
    linux_live_start(t);Buffer out={0};char*err=NULL;
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
    GtkWidget*settings=linux_telemetry_find_button_v9(base->stack,"Open settings");if(settings!=NULL&&GTK_IS_BOX(gtk_widget_get_parent(settings))){GtkWidget*performance=linux_telemetry_button_v9("Performance",G_CALLBACK(linux_telemetry_performance_v9),t);gtk_box_pack_start(GTK_BOX(gtk_widget_get_parent(settings)),performance,FALSE,FALSE,0);}
    linux_install_connection_profiles_v11(app);
    g_object_set_data_full(G_OBJECT(app->window),"linux-telemetry-v9",t,linux_telemetry_free);t->live_poll=g_timeout_add(100,linux_live_tick,t);linux_telemetry_refresh_fastest_v9(t);linux_telemetry_refresh_v9(t);t->refresh_poll=g_timeout_add(3000,linux_telemetry_refresh_v9,t);gtk_widget_show_all(app->window);
}

/* Linux telemetry v9: fastest/specific node selector kept separate from Connect, live current-path RTT, live multihop
 * IN/OUT/PATH RTT, real authenticated path Mbps, real routed entry/exit Mbps when reachable,
 * separate MTU optimizer, Settings-row v11 Profiles manager, Performance panel, real /api/forwarding/master ON/OFF control and map latency refresh. */
