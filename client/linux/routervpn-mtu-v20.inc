/* One modeless view follows one captured controller session and one request.
 * Workers own only bounded HTTP data; the GTK thread adopts completed replies.
 * Cancelling a POST is distinct from confirming the controller's rollback. */
#include <math.h>

enum { LINUX_MTU_RUN_V20, LINUX_MTU_CANCEL_V20, LINUX_MTU_POLL_V20, LINUX_MTU_JOBS_V20 };
typedef struct {
    App *app;
    GtkWidget *dialog, *result, *detail, *retest, *cancel, *parent;
    gulong parent_destroy;
    guint timer;
    guint64 generation, completion, job_generation[LINUX_MTU_JOBS_V20], job_completion[LINUX_MTU_JOBS_V20];
    gboolean job_after_run[LINUX_MTU_JOBS_V20];
    RVHttpJobV16 *jobs[LINUX_MTU_JOBS_V20];
    char *session, *profile, *request, *message, *details, *post_error;
    gboolean seen, own, cancelled, cancel_ack, terminal, retired, closing, detaching, run_done, optimization_allowed;
    gint64 next_poll, deadline;
} LinuxMTUV20;

static gboolean linux_mtu_tick_v20(gpointer data);
static void linux_mtu_dialog_v20(App *app);

static const char *linux_mtu_string_v20(JsonObject *o, const char *key) {
    JsonNode *n=o!=NULL?json_object_get_member(o,key):NULL;
    return n!=NULL&&JSON_NODE_HOLDS_VALUE(n)&&json_node_get_value_type(n)==G_TYPE_STRING?json_node_get_string(n):NULL;
}
static gboolean linux_mtu_bool_v20(JsonObject *o, const char *key, gboolean *out) {
    JsonNode *n=o!=NULL?json_object_get_member(o,key):NULL;
    if(n==NULL||!JSON_NODE_HOLDS_VALUE(n)||json_node_get_value_type(n)!=G_TYPE_BOOLEAN)return FALSE;
    *out=json_node_get_boolean(n);return TRUE;
}
static double linux_mtu_number_v20(JsonObject *o,const char *key) {
    JsonNode *n=o!=NULL?json_object_get_member(o,key):NULL;
    if(n==NULL||!JSON_NODE_HOLDS_VALUE(n))return 0;
    GType type=json_node_get_value_type(n);
    if(type!=G_TYPE_INT64&&type!=G_TYPE_DOUBLE)return 0;
    double value=json_node_get_double(n);return isfinite(value)?value:0;
}
static int linux_mtu_integer_v20(JsonObject *o,const char *key) {
    double value=linux_mtu_number_v20(o,key);return value>=0&&value<=9000&&value==(int)value?(int)value:0;
}
static JsonObject *linux_mtu_object_v20(JsonObject *o,const char *key) {
    JsonNode *n=o!=NULL?json_object_get_member(o,key):NULL;
    return n!=NULL&&JSON_NODE_HOLDS_OBJECT(n)?json_node_get_object(n):NULL;
}
static gboolean linux_mtu_id_v20(const char *id) {
    if(id==NULL||strlen(id)!=32)return FALSE;
    for(guint i=0;i<32;i++)if(!((id[i]>='0'&&id[i]<='9')||(id[i]>='a'&&id[i]<='f')))return FALSE;
    return TRUE;
}
static void linux_mtu_message_v20(LinuxMTUV20 *s,const char *message) {
    g_free(s->message);s->message=g_strndup(message!=NULL?message:"MTU status unavailable",2048);
}
static void linux_mtu_retire_v20(LinuxMTUV20 *s,const char *reason) {
    s->retired=TRUE;s->terminal=TRUE;linux_mtu_message_v20(s,reason);
    rv_http_cancel_v16(s->jobs[LINUX_MTU_RUN_V20]);rv_http_cancel_v16(s->jobs[LINUX_MTU_POLL_V20]);
}
static char *linux_mtu_details_v20(JsonObject *status) {
    GString *text=g_string_new(NULL);
    const char *source=linux_mtu_string_v20(status,"source");
    int original=linux_mtu_integer_v20(status,"original_mtu"),effective=linux_mtu_integer_v20(status,"effective_mtu");
    if(source!=NULL&&g_str_has_prefix(source,"saved-")){
        if(effective>0)g_string_append_printf(text,"Saved MTU: %d (historical; not measured on this path)\n",effective);
    }else{
        if(original>0)g_string_append_printf(text,"Previous interface MTU: %d\n",original);
        if(effective>0)g_string_append_printf(text,"Effective interface MTU: %d\n",effective);
    }
    if(source!=NULL&&source[0])g_string_append_printf(text,"Measurement source: %.256s\n",source);
    JsonNode *node=json_object_get_member(status,"candidates");
    if(node!=NULL&&JSON_NODE_HOLDS_ARRAY(node)){
        JsonArray *a=json_node_get_array(node);guint count=MIN(json_array_get_length(a),64);
        for(guint i=0;i<count;i++){
            JsonNode *item=json_array_get_element(a,i);if(!JSON_NODE_HOLDS_OBJECT(item))continue;
            JsonObject *candidate=json_node_get_object(item);int mtu=linux_mtu_integer_v20(candidate,"mtu");
            if(mtu<576||mtu>9000)continue;
            gboolean working=FALSE;(void)linux_mtu_bool_v20(candidate,"working",&working);
            g_string_append_printf(text,"MTU %d: %s",mtu,working?"working":"not proved");
            const char *kind=linux_mtu_string_v20(candidate,"latency_kind");double latency=linux_mtu_number_v20(candidate,"median_rtt_ms");
            if(kind!=NULL&&kind[0]&&latency>0)g_string_append_printf(text," | %.128s %.1f ms",kind,latency);
            const char *directions[]={"download","upload"};
            for(guint d=0;d<G_N_ELEMENTS(directions);d++){
                double rate=linux_mtu_number_v20(linux_mtu_object_v20(candidate,directions[d]),"mbps");
                if(rate>0)g_string_append_printf(text," | %s %.1f Mbps",directions[d],rate);
            }
            const char *failure=linux_mtu_string_v20(candidate,"failure");if(failure!=NULL&&failure[0])g_string_append_printf(text," | %.256s",failure);
            g_string_append_c(text,'\n');
        }
    }
    return g_string_free(text,FALSE);
}
static gboolean linux_mtu_receive_v20(LinuxMTUV20 *s,JsonObject *reply,gboolean after_run) {
    if(s->detaching||s->retired)return FALSE;
    const char *session=linux_mtu_string_v20(reply,"session_id"),*profile=linux_mtu_string_v20(reply,"profile_id");
    JsonObject *status=linux_mtu_object_v20(reply,"status");const char *id=linux_mtu_string_v20(status,"request_id");
    gboolean waiting,requested,running,complete,measured,restored,optimization_allowed=TRUE;
    if(session==NULL||!session[0]||strlen(session)>128||profile==NULL||!profile[0]||strlen(profile)>256||id==NULL||(id[0]&&!linux_mtu_id_v20(id))||
       !linux_mtu_bool_v20(reply,"waiting_commit",&waiting)||!linux_mtu_bool_v20(reply,"requested",&requested)||
       (json_object_has_member(reply,"optimization_allowed")&&!linux_mtu_bool_v20(reply,"optimization_allowed",&optimization_allowed))||
       !linux_mtu_bool_v20(status,"running",&running)||!linux_mtu_bool_v20(status,"complete",&complete)||
       !linux_mtu_bool_v20(status,"measured",&measured)||!linux_mtu_bool_v20(status,"restored",&restored)){
        linux_mtu_retire_v20(s,"Invalid captured MTU progress. No result was adopted.");return FALSE;
    }
    (void)requested; /* Idle legacy status remains eligible for server-validated Retest. */
    if(s->session!=NULL&&(strcmp(s->session,session)!=0||strcmp(s->profile,profile)!=0)){
        linux_mtu_retire_v20(s,"The connection changed. Reopen MTU for the new connection.");return FALSE;
    }
    if(s->session==NULL){s->session=g_strdup(session);s->profile=g_strdup(profile);}
    if(s->request!=NULL&&strcmp(s->request,id)!=0){linux_mtu_retire_v20(s,"This MTU request was replaced. Its result was discarded.");return FALSE;}
    if(s->request==NULL&&id[0]){s->request=g_strdup(id);s->deadline=g_get_monotonic_time()+180*G_USEC_PER_SEC;}
    if(id[0])s->seen=TRUE;
    s->optimization_allowed=optimization_allowed;
    g_free(s->details);s->details=linux_mtu_details_v20(status);
    gboolean candidate=id[0]&&complete&&!running&&!waiting;
    s->terminal=candidate&&s->jobs[LINUX_MTU_CANCEL_V20]==NULL&&(!s->own||(s->run_done&&after_run));
    const char *failure=linux_mtu_string_v20(status,"failure"),*phase=linux_mtu_string_v20(status,"phase");
    int effective=linux_mtu_integer_v20(status,"effective_mtu");
    if(s->terminal){
        if(restored)linux_mtu_message_v20(s,"Previous MTU restored.");
        else if(measured&&effective>=576&&effective<=9000){char *text=g_strdup_printf("Measured MTU: %d%s",effective,s->cancelled?" (the test finished before cancellation)":"");linux_mtu_message_v20(s,text);g_free(text);}
        else if(failure!=NULL&&failure[0]){char *text=g_strdup_printf("MTU test failed: %.512s",failure);linux_mtu_message_v20(s,text);g_free(text);}
        else linux_mtu_message_v20(s,"The test ended without a new MTU measurement.");
    }else if(candidate){linux_mtu_message_v20(s,"The controller is finishing this test. Waiting for its final captured status.");g_clear_pointer(&s->details,g_free);}
    else if(s->cancelled)linux_mtu_message_v20(s,"Cancelling; waiting for this test to finish its restoration.");
    else if(waiting)linux_mtu_message_v20(s,"Saving the verified MTU...");
    else if(running){char *text=g_strdup_printf("MTU test: %.128s",phase!=NULL&&phase[0]?phase:"measuring the captured path");linux_mtu_message_v20(s,text);g_free(text);}
    else if(!id[0]&&!s->optimization_allowed)linux_mtu_message_v20(s,"This connection keeps its configured MTU. Retest is disabled by its Fixed, Default, or Jumbo policy.");
    else linux_mtu_message_v20(s,id[0]?"Waiting for the captured MTU test...":"No MTU test is running. Retest measures this connected path.");
    return TRUE;
}
static char *linux_mtu_body_v20(LinuxMTUV20 *s,gboolean include_profile) {
    JsonBuilder *b=json_builder_new();json_builder_begin_object(b);
    json_builder_set_member_name(b,"request_id");json_builder_add_string_value(b,s->request);
    json_builder_set_member_name(b,"session_id");json_builder_add_string_value(b,s->session);
    if(include_profile){json_builder_set_member_name(b,"profile_id");json_builder_add_string_value(b,s->profile);}
    json_builder_end_object(b);JsonNode *root=json_builder_get_root(b);JsonGenerator *g=json_generator_new();json_generator_set_root(g,root);
    char *body=json_generator_to_data(g,NULL);g_object_unref(g);json_node_free(root);g_object_unref(b);return body;
}
static gboolean linux_mtu_start_job_v20(LinuxMTUV20 *s,int kind,const char *path,const char *body,long timeout,gboolean get) {
    if(s->detaching||s->jobs[kind]!=NULL)return FALSE;
    s->jobs[kind]=rv_http_start_method_v17(path,body,timeout,"Captured MTU",get);
    s->job_generation[kind]=s->generation;s->job_completion[kind]=s->completion;s->job_after_run[kind]=s->run_done;return s->jobs[kind]!=NULL;
}
static gboolean linux_mtu_start_v20(LinuxMTUV20 *s) {
    if(s->detaching||s->closing||s->retired||!s->optimization_allowed||s->session==NULL||!s->run_done||s->jobs[LINUX_MTU_RUN_V20]!=NULL||s->jobs[LINUX_MTU_CANCEL_V20]!=NULL||(s->request!=NULL&&!s->terminal))return FALSE;
    if(s->app!=NULL&&linux_async_busy_v16(s->app)){linux_mtu_message_v20(s,"Another Router VPN action is running. Wait for it to finish.");return FALSE;}
    rv_http_cancel_v16(s->jobs[LINUX_MTU_POLL_V20]);s->generation++;
    char *uuid=g_uuid_string_random();GString *id=g_string_new(NULL);for(char *p=uuid;*p;p++)if(*p!='-')g_string_append_c(id,*p);g_free(uuid);
    g_free(s->request);s->request=g_string_free(id,FALSE);s->seen=FALSE;s->own=TRUE;s->terminal=FALSE;s->cancelled=FALSE;s->cancel_ack=FALSE;s->run_done=FALSE;
    g_clear_pointer(&s->post_error,g_free);g_clear_pointer(&s->details,g_free);s->next_poll=0;s->deadline=g_get_monotonic_time()+180*G_USEC_PER_SEC;
    linux_mtu_message_v20(s,"Submitting Retest for this connection...");char *body=linux_mtu_body_v20(s,TRUE);
    gboolean ok=linux_mtu_start_job_v20(s,LINUX_MTU_RUN_V20,"/api/mtu/retest",body,150000,FALSE);g_free(body);
    if(!ok){s->run_done=TRUE;linux_mtu_retire_v20(s,"Retest could not start its owned request.");}return ok;
}
static void linux_mtu_cancel_v20(LinuxMTUV20 *s) {
    if(s->detaching||s->retired||s->request==NULL||s->terminal||s->cancel_ack||s->jobs[LINUX_MTU_CANCEL_V20]!=NULL)return;
    s->cancelled=TRUE;linux_mtu_message_v20(s,"Cancelling; waiting for this test to finish its restoration.");
    if(s->own&&!s->seen)rv_http_cancel_v16(s->jobs[LINUX_MTU_RUN_V20]);
    char *body=linux_mtu_body_v20(s,FALSE);
    if(!linux_mtu_start_job_v20(s,LINUX_MTU_CANCEL_V20,"/api/mtu/cancel",body,6000,FALSE)){
        if(s->own)rv_http_cancel_v16(s->jobs[LINUX_MTU_RUN_V20]);
        linux_mtu_message_v20(s,"Cancellation was not confirmed. Waiting for captured status; Cancel can be retried.");
    }
    g_free(body);
}
static void linux_mtu_free_v20(LinuxMTUV20 *s) {
    if(s->parent!=NULL&&s->parent_destroy!=0)g_signal_handler_disconnect(s->parent,s->parent_destroy);
    g_free(s->session);g_free(s->profile);g_free(s->request);g_free(s->message);g_free(s->details);g_free(s->post_error);g_free(s);
}
static void linux_mtu_render_v20(LinuxMTUV20 *s) {
    if(s->dialog==NULL)return;
    gtk_label_set_text(GTK_LABEL(s->result),s->message!=NULL?s->message:"");
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(s->detail)),s->details!=NULL?s->details:"",-1);
    gboolean ready=!s->retired&&!s->closing&&s->optimization_allowed&&s->session!=NULL&&s->run_done&&s->jobs[LINUX_MTU_RUN_V20]==NULL&&s->jobs[LINUX_MTU_CANCEL_V20]==NULL&&(s->request==NULL||s->terminal);
    gtk_widget_set_sensitive(s->retest,ready);
    gtk_widget_set_sensitive(s->cancel,!s->retired&&!s->terminal&&!s->cancel_ack&&s->request!=NULL&&s->jobs[LINUX_MTU_CANCEL_V20]==NULL);
}
static gboolean linux_mtu_tick_v20(gpointer data) {
    LinuxMTUV20 *s=data;
    for(int kind=0;kind<LINUX_MTU_JOBS_V20;kind++){
        RVHttpJobV16 *job=s->jobs[kind];if(job==NULL||!rv_http_ready_v16(job))continue;
        s->jobs[kind]=NULL;
        if(s->job_generation[kind]==s->generation&&!s->detaching){
            JsonNode *root=job->response!=NULL&&job->length<=262144?parse_json(job->response):NULL;
            JsonObject *reply=root!=NULL&&JSON_NODE_HOLDS_OBJECT(root)?json_node_get_object(root):NULL;
            long code=job->result==CURLE_OK?job->status:0;
            if(kind==LINUX_MTU_RUN_V20){
                s->run_done=TRUE;s->completion++;s->terminal=s->retired;g_free(s->post_error);s->post_error=g_strndup(job->response!=NULL?job->response:"Request cancelled or failed",512);s->next_poll=0;
                if(s->jobs[LINUX_MTU_POLL_V20]!=NULL&&!s->job_after_run[LINUX_MTU_POLL_V20])rv_http_cancel_v16(s->jobs[LINUX_MTU_POLL_V20]);
                /* POST errors, including 409 after rollback, never replace a
                 * filtered status receipt with an inferred connection change. */
            }else if(kind==LINUX_MTU_CANCEL_V20){
                s->completion++;s->terminal=s->retired;rv_http_cancel_v16(s->jobs[LINUX_MTU_POLL_V20]);
                const char *id=linux_mtu_string_v20(reply,"request_id"),*phase=linux_mtu_string_v20(reply,"phase");
                if(code==200&&g_strcmp0(id,s->request)==0&&g_strcmp0(phase,"canceling")==0)s->cancel_ack=TRUE;
                else if(code==409)linux_mtu_message_v20(s,"Cancellation raced a completed or changed operation. Checking only the captured request.");
                else if(code!=404||s->seen){if(s->own)rv_http_cancel_v16(s->jobs[LINUX_MTU_RUN_V20]);linux_mtu_message_v20(s,"Cancellation was not confirmed. Waiting for captured status; Cancel can be retried.");}
                s->next_poll=0;
            }else if(!s->retired){
                if(s->job_completion[kind]!=s->completion||(s->own&&s->run_done&&!s->job_after_run[kind])){s->next_poll=0;}
                else if(code==200)(void)linux_mtu_receive_v20(s,reply,s->job_after_run[kind]);
                else if(code==404&&s->own&&!s->seen){
                    if(!s->run_done)linux_mtu_message_v20(s,s->cancelled?"Cancelling the unaccepted Retest request...":"Waiting for the controller to accept this Retest...");
                    else if(s->cancelled){s->terminal=TRUE;linux_mtu_message_v20(s,"Retest cancelled before it was accepted.");}
                    else linux_mtu_retire_v20(s,"Retest was not accepted by the captured connection.");
                }else if(code==404||code==409)linux_mtu_retire_v20(s,"The connection or MTU request changed. Reopen MTU for the current path.");
                else linux_mtu_message_v20(s,"MTU progress could not be confirmed. Retrying the same captured request.");
            }
            if(root!=NULL)json_node_free(root);
        }
        rv_http_free_v16(job); /* ready was acquired; join never waits on network. */
    }
    if(s->detaching){
        for(int k=0;k<LINUX_MTU_JOBS_V20;k++)if(s->jobs[k]!=NULL)return G_SOURCE_CONTINUE;
        s->timer=0;linux_mtu_free_v20(s);return G_SOURCE_REMOVE;
    }
    gint64 now=g_get_monotonic_time();
    if(!s->retired&&!s->terminal&&s->deadline!=0&&now>s->deadline)linux_mtu_retire_v20(s,"MTU status exceeded its deadline. No successful measurement or restoration is claimed.");
    if(!s->retired&&!s->terminal&&s->jobs[LINUX_MTU_POLL_V20]==NULL&&now>=s->next_poll){
        char *escaped=s->session!=NULL?g_uri_escape_string(s->session,NULL,FALSE):NULL;
        char *path=s->request!=NULL?g_strdup_printf("/api/mtu/status?request_id=%s&session_id=%s",s->request,escaped):
            escaped!=NULL?g_strdup_printf("/api/mtu/status?session_id=%s",escaped):g_strdup("/api/mtu/status");
        gboolean started=linux_mtu_start_job_v20(s,LINUX_MTU_POLL_V20,path,"",6000,TRUE);g_free(path);g_free(escaped);
        s->next_poll=now+(started?500:2000)*G_TIME_SPAN_MILLISECOND;
        if(!started)linux_mtu_message_v20(s,"MTU progress could not be requested.");
    }
    linux_mtu_render_v20(s);
    if(s->closing&&(s->terminal||s->retired)&&s->run_done&&s->jobs[LINUX_MTU_RUN_V20]==NULL&&s->jobs[LINUX_MTU_CANCEL_V20]==NULL){gtk_widget_destroy(s->dialog);return G_SOURCE_REMOVE;}
    return G_SOURCE_CONTINUE;
}
static void linux_mtu_destroy_v20(GtkWidget *widget,gpointer data) {
    (void)widget;LinuxMTUV20 *s=data;
    if(s->timer!=0){g_source_remove(s->timer);s->timer=0;}
    if(s->app!=NULL&&g_object_get_data(G_OBJECT(s->app->window),"router-vpn-mtu-v20")==s)g_object_set_data(G_OBJECT(s->app->window),"router-vpn-mtu-v20",NULL);
    s->app=NULL;s->dialog=NULL;s->detaching=TRUE;s->generation++;
    for(int k=0;k<LINUX_MTU_JOBS_V20;k++)rv_http_cancel_v16(s->jobs[k]);
    /* Keep only the small non-UI owner until every bounded worker has drained. */
    s->timer=g_timeout_add(50,linux_mtu_tick_v20,s);
}
static void linux_mtu_parent_destroy_v20(GtkWidget *widget,gpointer data) {
    (void)widget;LinuxMTUV20 *s=data;s->parent=NULL;s->parent_destroy=0;
    if(s->dialog!=NULL)gtk_widget_destroy(s->dialog);
    if(s->timer!=0){g_source_remove(s->timer);s->timer=0;}
    /* The application's next step is curl_global_cleanup. Cancel every owned
     * loopback worker first, then join all of them before leaving destruction.
     * They poll cancellation at 50 ms and never wait for a remote DNS resolver. */
    for(int k=0;k<LINUX_MTU_JOBS_V20;k++)rv_http_cancel_v16(s->jobs[k]);
    for(int k=0;k<LINUX_MTU_JOBS_V20;k++){rv_http_free_v16(s->jobs[k]);s->jobs[k]=NULL;}
    linux_mtu_free_v20(s);
}
static gboolean linux_mtu_close_v20(LinuxMTUV20 *s) {
    if((s->own||s->cancelled)&&!s->retired&&(!s->terminal||!s->run_done||s->jobs[LINUX_MTU_CANCEL_V20]!=NULL)){
        s->closing=TRUE;linux_mtu_cancel_v20(s);linux_mtu_render_v20(s);return FALSE;
    }
    gtk_widget_destroy(s->dialog);return TRUE;
}
static gboolean linux_mtu_delete_v20(GtkWidget *widget,GdkEvent *event,gpointer data) {
    (void)widget;(void)event;(void)linux_mtu_close_v20(data);return TRUE;
}
static void linux_mtu_response_v20(GtkDialog *dialog,int response,gpointer data) {
    (void)dialog;LinuxMTUV20 *s=data;
    if(response==1)(void)linux_mtu_start_v20(s);
    else if(response==2)linux_mtu_cancel_v20(s);
    else if(response==GTK_RESPONSE_CLOSE||response==GTK_RESPONSE_DELETE_EVENT){(void)linux_mtu_close_v20(s);return;}
    linux_mtu_render_v20(s);
}
static void linux_mtu_dialog_v20(App *app) {
    if(app==NULL||app->window==NULL)return;
    LinuxMTUV20 *existing=g_object_get_data(G_OBJECT(app->window),"router-vpn-mtu-v20");
    if(existing!=NULL&&existing->dialog!=NULL){gtk_window_present(GTK_WINDOW(existing->dialog));return;}
    LinuxMTUV20 *s=g_new0(LinuxMTUV20,1);s->app=app;s->parent=app->window;s->generation=1;s->run_done=TRUE;
    linux_mtu_message_v20(s,"Checking MTU on the connected path...");
    s->dialog=gtk_dialog_new_with_buttons("Router VPN MTU",GTK_WINDOW(app->window),GTK_DIALOG_DESTROY_WITH_PARENT,
        "Retest MTU",1,"Cancel test",2,"Close",GTK_RESPONSE_CLOSE,NULL);
    gtk_window_set_default_size(GTK_WINDOW(s->dialog),690,460);gtk_widget_set_size_request(s->dialog,540,330);
    GtkWidget *area=gtk_dialog_get_content_area(GTK_DIALOG(s->dialog));gtk_container_set_border_width(GTK_CONTAINER(area),16);
    GtkWidget *hint=gtk_label_new("A running Auto measurement appears here. Retest measures this connection. Cancel waits for this test to finish or restore the previous MTU.");
    gtk_label_set_line_wrap(GTK_LABEL(hint),TRUE);gtk_label_set_xalign(GTK_LABEL(hint),0);gtk_box_pack_start(GTK_BOX(area),hint,FALSE,FALSE,6);
    s->result=gtk_label_new(s->message);gtk_label_set_line_wrap(GTK_LABEL(s->result),TRUE);gtk_label_set_xalign(GTK_LABEL(s->result),0);gtk_box_pack_start(GTK_BOX(area),s->result,FALSE,FALSE,8);
    GtkWidget *scroll=gtk_scrolled_window_new(NULL,NULL);s->detail=gtk_text_view_new();gtk_text_view_set_editable(GTK_TEXT_VIEW(s->detail),FALSE);gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(s->detail),GTK_WRAP_WORD_CHAR);gtk_text_view_set_monospace(GTK_TEXT_VIEW(s->detail),TRUE);
    gtk_container_add(GTK_CONTAINER(scroll),s->detail);gtk_box_pack_start(GTK_BOX(area),scroll,TRUE,TRUE,0);
    s->retest=gtk_dialog_get_widget_for_response(GTK_DIALOG(s->dialog),1);s->cancel=gtk_dialog_get_widget_for_response(GTK_DIALOG(s->dialog),2);
    g_object_set_data(G_OBJECT(app->window),"router-vpn-mtu-v20",s);
    g_signal_connect(s->dialog,"response",G_CALLBACK(linux_mtu_response_v20),s);
    g_signal_connect(s->dialog,"delete-event",G_CALLBACK(linux_mtu_delete_v20),s);
    g_signal_connect(s->dialog,"destroy",G_CALLBACK(linux_mtu_destroy_v20),s);
    s->parent_destroy=g_signal_connect(s->parent,"destroy",G_CALLBACK(linux_mtu_parent_destroy_v20),s);
    linux_mtu_render_v20(s);gtk_widget_show_all(s->dialog);s->timer=g_timeout_add(50,linux_mtu_tick_v20,s);
}
