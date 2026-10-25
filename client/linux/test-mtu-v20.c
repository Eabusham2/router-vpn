/* Execute the shipping GTK callbacks with controllable completed HTTP jobs.
 * The separate --live build retains the real pthread/libcurl transport. */
#include <gtk/gtk.h>
#include <json-glib/json-glib.h>
#include <string.h>
#include "routervpn-http-job-v16.h"
typedef struct {GtkWidget *window;} App;
static gboolean linux_async_busy_v16(App *app){(void)app;return FALSE;}
static JsonNode *parse_json(const char *text){JsonParser *p=json_parser_new();JsonNode *r=NULL;if(json_parser_load_from_data(p,text,-1,NULL))r=json_node_copy(json_parser_get_root(p));g_object_unref(p);return r;}
static int checks=0;
static void check(gboolean ok,const char *message){if(!ok)g_error("MTU check failed: %s",message);checks++;}

#ifndef ROUTERVPN_MTU_LIVE
typedef struct {RVHttpJobV16 *job;char *path,*body;gboolean get,cancelled,freed;} Record;
static GPtrArray *records;
static gboolean shutdown_join=FALSE;
static Record *find(RVHttpJobV16 *job){for(guint i=0;i<records->len;i++){Record *r=g_ptr_array_index(records,i);if(r->job==job)return r;}g_error("unowned HTTP job");return NULL;}
static RVHttpJobV16 *fake_start(const char *path,const char *body,long timeout,const char *label,int get){
    (void)label;check(timeout>0&&timeout<=150000,"bounded HTTP timeout");
    RVHttpJobV16 *j=g_new0(RVHttpJobV16,1);atomic_init(&j->cancelled,0);atomic_init(&j->ready,0);j->result=CURLE_OK;
    Record *r=g_new0(Record,1);r->job=j;r->path=g_strdup(path);r->body=g_strdup(body);r->get=get;g_ptr_array_add(records,r);return j;
}
static void fake_cancel(RVHttpJobV16 *j){if(j!=NULL){find(j)->cancelled=TRUE;atomic_store(&j->cancelled,1);}}
static void fake_free(RVHttpJobV16 *j){if(j==NULL)return;check(atomic_load(&j->ready)||(shutdown_join&&atomic_load(&j->cancelled)),"worker drained or synchronously joined after cancellation before free");Record *r=find(j);r->freed=TRUE;r->job=NULL;free(j->response);g_free(j);}
#define rv_http_start_method_v17 fake_start
#define rv_http_cancel_v16 fake_cancel
#define rv_http_free_v16 fake_free
#endif
#ifndef ROUTERVPN_MTU_SOURCE
#define ROUTERVPN_MTU_SOURCE "routervpn-mtu-v20.inc"
#endif
#include ROUTERVPN_MTU_SOURCE

static JsonNode *status(const char *id,gboolean running,gboolean complete,gboolean restored){
    char *raw=g_strdup_printf("{\"session_id\":\"captured-session\",\"profile_id\":\"router-a\",\"requested\":false,\"waiting_commit\":false,\"status\":{\"request_id\":\"%s\",\"phase\":\"measuring\",\"running\":%s,\"complete\":%s,\"measured\":false,\"restored\":%s,\"original_mtu\":1420,\"effective_mtu\":1420,\"source\":\"saved-auto-throughput\",\"candidates\":[]}}",id,running?"true":"false",complete?"true":"false",restored?"true":"false");
    JsonNode *n=parse_json(raw);g_free(raw);return n;
}
static void receive(LinuxMTUV20 *s,JsonNode *n){(void)linux_mtu_receive_v20(s,json_node_get_object(n),TRUE);json_node_free(n);}
static LinuxMTUV20 *open_view(App *app){
    linux_mtu_dialog_v20(app);LinuxMTUV20 *s=g_object_get_data(G_OBJECT(app->window),"router-vpn-mtu-v20");
    check(s!=NULL&&s->dialog!=NULL,"actual GTK panel created");check(!gtk_window_get_modal(GTK_WINDOW(s->dialog)),"MTU panel must be modeless");
    check(gtk_widget_is_sensitive(app->window),"main controls remain reachable");return s;
}

#ifndef ROUTERVPN_MTU_LIVE
static void freeze_timer(LinuxMTUV20 *s){if(s->timer){g_source_remove(s->timer);s->timer=0;}}
static Record *last(void){return g_ptr_array_index(records,records->len-1);}
static void reply(Record *r,long code,JsonNode *n){
    check(r->job!=NULL&&!r->freed,"reply still belongs to request");r->job->status=code;
    JsonGenerator *g=json_generator_new();json_generator_set_root(g,n);r->job->response=json_generator_to_data(g,&r->job->length);g_object_unref(g);json_node_free(n);atomic_store(&r->job->ready,1);
}
static void code(Record *r,long code){reply(r,code,parse_json("{\"error\":\"fixture\"}"));}
static void dispose_view(LinuxMTUV20 *s){
    if(s->dialog!=NULL)gtk_widget_destroy(s->dialog);
    freeze_timer(s);
    for(guint i=0;i<records->len;i++){Record *r=g_ptr_array_index(records,i);if(r->job!=NULL){check(r->cancelled,"closing cancels only remaining owned tasks");atomic_store(&r->job->ready,1);}}
    check(linux_mtu_tick_v20(s)==G_SOURCE_REMOVE,"closed owner drains and retires");
}
static void idle(LinuxMTUV20 *s){receive(s,status("",FALSE,FALSE,FALSE));linux_mtu_render_v20(s);check(gtk_widget_is_sensitive(s->retest),"requested false retains eligible Retest");}
static void advance(LinuxMTUV20 *s){s->next_poll=0;(void)linux_mtu_tick_v20(s);}
static void run_state_tests(App *app){
    records=g_ptr_array_new();LinuxMTUV20 *s=open_view(app);freeze_timer(s);idle(s);
    check(strstr(s->details,"historical; not measured")!=NULL&&strstr(s->details,"Effective interface MTU")==NULL,"saved value is not a fresh readback");
    gtk_button_clicked(GTK_BUTTON(s->retest));Record *run=last();char *id=g_strdup(s->request);
    JsonNode *body=parse_json(run->body);JsonObject *b=json_node_get_object(body);
    check(linux_mtu_id_v20(id)&&g_strcmp0(linux_mtu_string_v20(b,"request_id"),id)==0&&g_strcmp0(linux_mtu_string_v20(b,"session_id"),s->session)==0&&g_strcmp0(linux_mtu_string_v20(b,"profile_id"),s->profile)==0,"manual POST captures exact identities");json_node_free(body);
    check(!s->run_done&&!atomic_load(&run->job->ready),"Retest callback remains asynchronous");
    advance(s);Record *poll=last();check(strstr(poll->path,id)!=NULL&&strstr(poll->path,"session_id=captured-session")!=NULL&&poll->get,"poll uses exact request and session");
    code(poll,404);(void)linux_mtu_tick_v20(s);check(!s->retired&&!s->terminal,"pre-acceptance 404 waits only while own POST pending");
    gtk_button_clicked(GTK_BUTTON(s->cancel));Record *cancel=last();check(run->cancelled,"early Cancel aborts its unaccepted POST");
    body=parse_json(cancel->body);b=json_node_get_object(body);check(g_strcmp0(linux_mtu_string_v20(b,"request_id"),id)==0&&g_strcmp0(linux_mtu_string_v20(b,"session_id"),s->session)==0,"Cancel is bound to the captured request");json_node_free(body);
    code(cancel,404);(void)linux_mtu_tick_v20(s);check(!s->terminal,"unaccepted Cancel does not pretend POST drain");
    run->job->result=CURLE_ABORTED_BY_CALLBACK;atomic_store(&run->job->ready,1);(void)linux_mtu_tick_v20(s);
    poll=last();code(poll,404);(void)linux_mtu_tick_v20(s);if(!s->terminal){poll=last();code(poll,404);(void)linux_mtu_tick_v20(s);}check(s->terminal&&s->run_done&&!s->seen,"early Cancel completes only after owned POST drain and exact 404");
    dispose_view(s);g_free(id);

    s=open_view(app);freeze_timer(s);idle(s);gtk_button_clicked(GTK_BUTTON(s->retest));run=last();id=g_strdup(s->request);advance(s);poll=last();reply(poll,200,status(id,TRUE,FALSE,FALSE));(void)linux_mtu_tick_v20(s);check(s->seen,"accepted request is retained");
    gtk_button_clicked(GTK_BUTTON(s->cancel));cancel=last();check(!run->cancelled,"accepted manual request retained through rollback");
    char *ack=g_strdup_printf("{\"request_id\":\"%s\",\"phase\":\"canceling\"}",id);reply(cancel,200,parse_json(ack));g_free(ack);(void)linux_mtu_tick_v20(s);
    check(s->cancel_ack&&!s->terminal&&!gtk_widget_is_sensitive(s->retest),"pending cancel ACK does not complete rollback");
    poll=last();JsonNode *waiting=status(id,FALSE,TRUE,TRUE);json_object_set_boolean_member(json_node_get_object(waiting),"waiting_commit",TRUE);reply(poll,200,waiting);(void)linux_mtu_tick_v20(s);check(!s->terminal,"waiting commit is not terminal");
    advance(s);poll=last();reply(poll,200,status(id,FALSE,TRUE,TRUE));(void)linux_mtu_tick_v20(s);
    check(!s->terminal&&strcmp(s->message,"Previous MTU restored.")!=0&&!gtk_widget_is_sensitive(s->retest),"pre-POST completion GET never attests restoration");
    advance(s);Record *before_drain=last();code(run,409);(void)linux_mtu_tick_v20(s);
    check(s->run_done&&!s->retired&&!s->terminal&&before_drain->cancelled,"POST completion cancels older poll and requires fresh receipt");
    reply(before_drain,200,status(id,FALSE,TRUE,TRUE));(void)linux_mtu_tick_v20(s);check(!s->terminal,"delayed older GET cannot attest final result");
    poll=last();reply(poll,200,status(id,FALSE,TRUE,TRUE));(void)linux_mtu_tick_v20(s);check(s->terminal&&!s->retired&&gtk_widget_is_sensitive(s->retest)&&strcmp(s->message,"Previous MTU restored.")==0,"fresh final GET after POST409 proves rollback");
    gtk_button_clicked(GTK_BUTTON(s->retest));check(strcmp(id,s->request)!=0,"next Retest uses a fresh ID");dispose_view(s);g_free(id);

    s=open_view(app);freeze_timer(s);advance(s);poll=last();reply(poll,200,status("",FALSE,FALSE,FALSE));(void)linux_mtu_tick_v20(s);advance(s);poll=last();
    check(strcmp(poll->path,"/api/mtu/status?session_id=captured-session")==0,"idle Auto observer pins its session");
    id=g_strdup("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");reply(poll,200,status(id,TRUE,FALSE,FALSE));(void)linux_mtu_tick_v20(s);check(s->seen&&!s->own&&strcmp(s->request,id)==0,"Auto observer retains the first request");
    JsonNode *auto_waiting=status(id,FALSE,TRUE,TRUE);json_object_set_boolean_member(json_node_get_object(auto_waiting),"waiting_commit",TRUE);receive(s,auto_waiting);check(!s->terminal,"Auto completion cannot skip durable commit");
    gtk_button_clicked(GTK_BUTTON(s->cancel));cancel=last();code(cancel,409);(void)linux_mtu_tick_v20(s);check(!s->retired,"Cancel409 needs filtered final status");
    poll=last();reply(poll,200,status(id,FALSE,TRUE,TRUE));(void)linux_mtu_tick_v20(s);check(s->terminal&&strcmp(s->message,"Previous MTU restored.")==0,"Cancel conflict preserves terminal restoration");dispose_view(s);g_free(id);

    s=open_view(app);freeze_timer(s);id=g_strdup("abababababababababababababababab");receive(s,status(id,TRUE,FALSE,FALSE));advance(s);poll=last();linux_mtu_cancel_v20(s);cancel=last();
    reply(poll,200,status(id,FALSE,TRUE,TRUE));(void)linux_mtu_tick_v20(s);check(!s->terminal,"pending Cancel cannot adopt earlier completion");
    advance(s);Record *during_cancel=last();ack=g_strdup_printf("{\"request_id\":\"%s\",\"phase\":\"canceling\"}",id);reply(cancel,200,parse_json(ack));g_free(ack);(void)linux_mtu_tick_v20(s);
    check(during_cancel->cancelled&&!s->terminal,"Cancel completion revokes older in-flight poll");reply(during_cancel,200,status(id,FALSE,TRUE,TRUE));(void)linux_mtu_tick_v20(s);check(!s->terminal,"old pre-Cancel GET cannot attest restoration");
    poll=last();reply(poll,200,status(id,FALSE,TRUE,TRUE));(void)linux_mtu_tick_v20(s);check(s->terminal&&strcmp(s->message,"Previous MTU restored.")==0,"fresh post-Cancel GET confirms rollback");dispose_view(s);g_free(id);
    for(long error=404;error<=409;error+=5){s=open_view(app);freeze_timer(s);receive(s,status("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",TRUE,FALSE,FALSE));advance(s);poll=last();code(poll,error);(void)linux_mtu_tick_v20(s);check(s->retired&&strcmp(s->request,"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")==0,"missing observed request retires without replacement adoption");dispose_view(s);}
    const char *fields[]={"session_id","profile_id"};
    for(guint i=0;i<G_N_ELEMENTS(fields);i++){s=open_view(app);freeze_timer(s);idle(s);JsonNode *n=status("",FALSE,FALSE,FALSE);json_object_set_string_member(json_node_get_object(n),fields[i],"replacement");receive(s,n);check(s->retired,"replaced session/profile retires the view");dispose_view(s);}
    s=open_view(app);freeze_timer(s);receive(s,status("cccccccccccccccccccccccccccccccc",TRUE,FALSE,FALSE));receive(s,status("dddddddddddddddddddddddddddddddd",TRUE,FALSE,FALSE));check(s->retired&&strcmp(s->request,"cccccccccccccccccccccccccccccccc")==0,"replacement request never changes owner");dispose_view(s);
    const char *flags[]={"running","complete","measured","restored"};
    for(guint i=0;i<G_N_ELEMENTS(flags);i++){s=open_view(app);freeze_timer(s);JsonNode *n=status("",FALSE,FALSE,FALSE);json_object_set_string_member(linux_mtu_object_v20(json_node_get_object(n),"status"),flags[i],"false");receive(s,n);check(s->retired,"malformed boolean fails closed");dispose_view(s);}
    s=open_view(app);freeze_timer(s);advance(s);Record *old=last();idle(s);gtk_button_clicked(GTK_BUTTON(s->retest));id=g_strdup(s->request);check(old->cancelled,"manual Retest revokes preceding poll");
    JsonNode *foreign=status("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",TRUE,FALSE,FALSE);json_object_set_string_member(json_node_get_object(foreign),"session_id","replacement");reply(old,200,foreign);(void)linux_mtu_tick_v20(s);check(!s->retired&&strcmp(s->request,id)==0&&strcmp(s->session,"captured-session")==0,"stale callback cannot mutate current view");dispose_view(s);g_free(id);
    s=open_view(app);freeze_timer(s);idle(s);gtk_button_clicked(GTK_BUTTON(s->retest));run=last();check(!linux_mtu_close_v20(s),"manual Close waits for its own cancellation and rollback");check(s->closing&&s->cancelled&&run->cancelled,"manual Close cancels its own unaccepted POST");check(!linux_mtu_start_v20(s),"closing view cannot start another test");dispose_view(s);
    s=open_view(app);freeze_timer(s);advance(s);poll=last();guint before=records->len;check(linux_mtu_close_v20(s),"Auto observer closes without cancelling Auto");freeze_timer(s);check(poll->cancelled&&records->len==before&&s->detaching,"closing cancels only owned poll");reply(poll,200,status("ffffffffffffffffffffffffffffffff",TRUE,FALSE,FALSE));check(linux_mtu_tick_v20(s)==G_SOURCE_REMOVE,"late successful response drains without adoption");
    s=open_view(app);freeze_timer(s);advance(s);poll=last();check(!atomic_load(&poll->job->ready),"shutdown fixture owns a pending HTTP worker");shutdown_join=TRUE;gtk_widget_destroy(app->window);app->window=NULL;check(poll->cancelled&&poll->freed,"main shutdown cancels and joins before global CURL cleanup");
    for(guint i=0;i<records->len;i++){Record *r=g_ptr_array_index(records,i);check(r->freed&&r->job==NULL,"all HTTP owners freed exactly after drain");g_free(r->path);g_free(r->body);g_free(r);}g_ptr_array_free(records,TRUE);
}
#else
static void pump(void){while(g_main_context_iteration(NULL,FALSE)){}g_usleep(5000);}
static void live_test(App *app,const char *scenario){
    LinuxMTUV20 *s=open_view(app);gint64 deadline=g_get_monotonic_time()+8*G_USEC_PER_SEC;
    while(s->session==NULL&&!s->retired&&g_get_monotonic_time()<deadline)pump();
    check(s->session!=NULL&&!s->retired,"real loopback initial status accepted");
    gtk_button_clicked(GTK_BUTTON(s->retest));check(s->own&&s->request!=NULL,"actual Retest click returns before its HTTP response");
    guint pulses=0;
    if(strcmp(scenario,"early")==0){gtk_button_clicked(GTK_BUTTON(s->cancel));}
    else{
        while(!s->seen&&!s->retired&&g_get_monotonic_time()<deadline){pump();pulses++;}
        check(s->seen,"native loopback accepted captured request");
        if(strcmp(scenario,"replaced")!=0)gtk_button_clicked(GTK_BUTTON(s->cancel));
    }
    while((!s->terminal||!s->run_done)&&g_get_monotonic_time()<deadline){pump();pulses++;}
    check((strcmp(scenario,"early")==0||pulses>0)&&gtk_widget_is_sensitive(app->window),"GTK main dispatch remains responsive during Retest");
    if(strcmp(scenario,"replaced")==0)check(s->retired&&s->terminal,"real replaced owner retires without adoption");
    else if(strcmp(scenario,"early")==0)check(s->terminal&&s->run_done&&!s->seen,"real unaccepted POST cancellation drains before completion");
    else check(s->terminal&&s->run_done&&!s->retired&&strstr(s->message,"restored")!=NULL,"real Cancel waits for matching rollback and POST409 drain");
    check(linux_mtu_close_v20(s),"completed panel can close");
    for(int i=0;i<40;i++)pump();
}
#endif
int main(int argc,char **argv){
    gtk_init(&argc,&argv);curl_global_init(CURL_GLOBAL_DEFAULT);App app={gtk_window_new(GTK_WINDOW_TOPLEVEL)};gtk_widget_show(app.window);
#ifdef ROUTERVPN_MTU_LIVE
    live_test(&app,argc>1?argv[1]:"accepted");
#else
    run_state_tests(&app);
#endif
    if(app.window!=NULL)gtk_widget_destroy(app.window);
    while(g_main_context_iteration(NULL,FALSE)){}
    curl_global_cleanup();g_print("PASS: %d actual GTK MTU callback/ownership checks\n",checks);return 0;
}
