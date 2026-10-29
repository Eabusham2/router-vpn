#define _GNU_SOURCE
#define main routervpn_core_fixture_main
#include "routervpn-gtk-product.c"
#undef main

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/socket.h>

static unsigned checks;
static pid_t fixture_owned_child;
static int fixture_control_read=-1,fixture_control_write=-1;
static void fixture_cleanup(void) {
    if(fixture_control_write>=0){char quit='q';ssize_t ignored=write(fixture_control_write,&quit,1);(void)ignored;}
    if(fixture_owned_child>0){pid_t joined;do{joined=waitpid(fixture_owned_child,NULL,0);}while(joined<0&&errno==EINTR);fixture_owned_child=0;}
    if(fixture_control_read>=0){close(fixture_control_read);fixture_control_read=-1;}
    if(fixture_control_write>=0){close(fixture_control_write);fixture_control_write=-1;}
    while(waitpid(-1,NULL,WNOHANG)>0){}
}

static void check(gboolean value,const char *message) {
    checks++;
    if(!value){fprintf(stderr,"GTK controller shutdown failure: %s\n",message);exit(1);}
}

static int fixture_send(int fd,const char *data,size_t length) {
    while(length>0){ssize_t n=send(fd,data,length,MSG_NOSIGNAL);if(n<0&&errno==EINTR)continue;if(n<=0)return -1;data+=n;length-=(size_t)n;}return 0;
}

static void fixture_response(int fd,int status,const char *body) {
    char header[256];int n=snprintf(header,sizeof(header),"HTTP/1.1 %d Fixture\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",status,strlen(body));
    (void)fixture_send(fd,header,(size_t)n);(void)fixture_send(fd,body,strlen(body));
}

static char *fixture_header(const char *request,const char *name) {
    char *key=g_strdup_printf("\r\n%s: ",name);const char *value=strcasestr(request,key);g_free(key);
    if(value==NULL)return NULL;
    value=strchr(value+2,':');if(value==NULL)return NULL;value+=2;
    const char *end=strstr(value,"\r\n");return end!=NULL?g_strndup(value,(gsize)(end-value)):NULL;
}

static void fixture_launch_exec(App *app) {
    if(g_strcmp0(getenv("RV_CONTROLLER_TEST_SCENARIO"),"auth-cancel")==0)_exit(126);
    char *controller=g_build_filename(app->package_root,"router-vpn-client",NULL);
    if(setenv("HOMEVPN_ROOT",app->package_root,1)!=0)_exit(126);
    execl(controller,controller,(char*)NULL);_exit(127);
}

static int fixture_controller(void) {
    const char *scenario=getenv("RV_CONTROLLER_TEST_SCENARIO"),*root=getenv("HOMEVPN_ROOT"),*control=getenv("RV_CONTROLLER_TEST_FD");
    if(scenario==NULL||root==NULL||control==NULL)return 91;
    char frame[385];size_t length=0;
    while(length<sizeof(frame)-1){ssize_t n=read(STDIN_FILENO,frame+length,1);if(n<0&&errno==EINTR)continue;if(n!=1)return 90;if(frame[length++]=='\n')break;}
    frame[length]='\0';JsonNode *identity=parse_json(frame);
    if(identity==NULL||!JSON_NODE_HOLDS_OBJECT(identity))return 89;
    JsonObject *launch=json_node_get_object(identity);char owner[33],access[65];
    g_strlcpy(owner,obj_string(launch,"owner_token"),sizeof(owner));g_strlcpy(access,obj_string(launch,"access_token"),sizeof(access));
    json_node_free(identity);memset(frame,0,sizeof(frame));
    if(!controller_owner_token_valid(owner)||!rv_controller_secret_valid(access)||strcmp(owner,getenv("HOMEVPN_CONTROLLER_OWNER"))==0)return 88;
    int control_fd=atoi(control);
    int server=socket(AF_INET,SOCK_STREAM,0);if(server<0)return 92;
    int reuse=1;(void)setsockopt(server,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));
    struct sockaddr_in address;memset(&address,0,sizeof(address));address.sin_family=AF_INET;address.sin_port=htons(8788);address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(bind(server,(struct sockaddr*)&address,sizeof(address))!=0||listen(server,4)!=0){close(server);return 93;}
    int posts=0;
    for(;;){
        fd_set input;FD_ZERO(&input);FD_SET(server,&input);FD_SET(control_fd,&input);FD_SET(STDIN_FILENO,&input);int maximum=server>control_fd?server:control_fd;
        if(select(maximum+1,&input,NULL,NULL,NULL)<0){if(errno==EINTR)continue;return 94;}
        if(FD_ISSET(control_fd,&input)){char command;ssize_t ignored=read(control_fd,&command,1);(void)ignored;close(server);return 0;}
        if(FD_ISSET(STDIN_FILENO,&input)){char extra;ssize_t n=read(STDIN_FILENO,&extra,1);close(server);return n==0?0:87;}
        int client=accept(server,NULL,NULL);if(client<0)continue;
        struct timeval timeout={2,0};(void)setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
        char request[8193];size_t used=0;char *body=NULL;size_t need=0;
        while(used<sizeof(request)-1){
            ssize_t n=recv(client,request+used,sizeof(request)-used-1,0);if(n<0&&errno==EINTR)continue;if(n<=0)break;used+=(size_t)n;request[used]='\0';
            body=strstr(request,"\r\n\r\n");if(body==NULL)continue;body+=4;
            const char *length=strcasestr(request,"\r\nContent-Length:");need=length!=NULL?(size_t)strtoul(length+17,NULL,10):0;
            if(need>4096)break;
            if(used>=(size_t)(body-request)+need)break;
        }
        if(body==NULL||used<(size_t)(body-request)+need){close(client);continue;}
        char *authorization=fixture_header(request,"Authorization");
        if(strncmp(request,"GET /api/controller/identity ",29)==0){
            char *challenge=fixture_header(request,"X-RouterVPN-Challenge");
            if(challenge==NULL||!controller_owner_token_valid(challenge)||authorization==NULL){g_free(challenge);g_free(authorization);close(client);return 86;}
            char *message=g_strdup_printf("routervpn-controller-identity-request\n%s",challenge);
            char *mac=g_compute_hmac_for_string(G_CHECKSUM_SHA256,(const guchar*)access,64,message,-1);
            char *expected_auth=g_strdup_printf("RouterVPN-Identity %s",mac);g_free(message);g_free(mac);
            if(strcmp(authorization,expected_auth)!=0||strstr(request,access)!=NULL){g_free(expected_auth);g_free(authorization);g_free(challenge);close(client);return 85;}
            g_free(expected_auth);g_free(authorization);
            message=g_strdup_printf("routervpn-controller-identity-response\n%ld\n%s",(long)getpid(),challenge);
            mac=g_compute_hmac_for_string(G_CHECKSUM_SHA256,(const guchar*)access,64,message,-1);g_free(message);
            if(strcmp(scenario,"wrong-proof")==0)mac[0]=mac[0]=='a'?'b':'a';
            if(strcmp(scenario,"wrong-challenge")==0)challenge[0]=challenge[0]=='a'?'b':'a';
            char *reply=g_strdup_printf("{\"schema\":1,\"process_id\":%ld,\"challenge\":\"%s\",\"proof\":\"%s\"}",(long)getpid()+(strcmp(scenario,"wrong-pid")==0?1:0),challenge,mac);
            fixture_response(client,200,reply);g_free(reply);g_free(mac);g_free(challenge);close(client);continue;
        }
        char *expected_auth=g_strdup_printf("Bearer %s",access);
        gboolean authorized=authorization!=NULL&&strcmp(authorization,expected_auth)==0;g_free(authorization);g_free(expected_auth);
        if(!authorized){fixture_response(client,403,"{}");close(client);return 84;}
        if(strncmp(request,"GET /api/status ",16)==0){fixture_response(client,200,"{\"connected\":false}");close(client);continue;}
        char *expected=g_strdup_printf("{\"schema\":1,\"process_id\":%ld,\"owner_token\":\"%s\"}",(long)getpid(),owner);
        if(strncmp(request,"POST /api/controller/shutdown ",30)!=0||need!=strlen(expected)||memcmp(body,expected,need)!=0){g_free(expected);fixture_response(client,400,"{}");close(client);close(server);return 95;}
        g_free(expected);posts++;
        char *count_path=g_build_filename(root,"request-count",NULL),*count=g_strdup_printf("%d",posts);(void)g_file_set_contents(count_path,count,-1,NULL);g_free(count_path);g_free(count);
        if(strcmp(scenario,"pending")==0&&posts==1){fixture_response(client,503,"{\"failure\":\"cleanup pending\"}");close(client);continue;}
        char changed[33];g_strlcpy(changed,owner,sizeof(changed));changed[0]=changed[0]=='a'?'b':'a';
        const char *receipt_owner=strcmp(scenario,"wrong-owner")==0?changed:owner;
        char *reply=g_strdup_printf("{\"schema\":1,\"process_id\":%ld,\"owner_token\":\"%s\",\"closed\":true}",(long)getpid(),receipt_owner);
        if(strcmp(scenario,"duplicate")==0){g_free(reply);reply=g_strdup_printf("{\"schema\":1,\"process_id\":%ld,\"owner_token\":\"%s\",\"closed\":true,\"closed\":true}",(long)getpid(),owner);}
        if(strcmp(scenario,"lost-receipt")==0){fixture_response(client,200,"{\"closed\":true}");g_free(reply);close(client);close(server);return 0;}
        if(strcmp(scenario,"exit-during-body")==0){
            size_t half=strlen(reply)/2;char header[256];int n=snprintf(header,sizeof(header),"HTTP/1.1 200 Fixture\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",strlen(reply));
            (void)fixture_send(client,header,(size_t)n);(void)fixture_send(client,reply,half);
            pid_t writer=fork();if(writer<0){g_free(reply);close(client);close(server);return 96;}
            if(writer==0){close(server);close(control_fd);g_usleep(400000);(void)fixture_send(client,reply+half,strlen(reply)-half);g_free(reply);close(client);_exit(0);}
            g_free(reply);close(client);close(server);return 0;
        }
        if(strcmp(scenario,"replace-owner")==0)g_usleep(350000);
        fixture_response(client,200,reply);g_free(reply);close(client);
        if(strcmp(scenario,"wrong-owner")==0||strcmp(scenario,"duplicate")==0||strcmp(scenario,"replace-owner")==0)continue;
        if(strcmp(scenario,"delay-exit")==0)g_usleep(450000);
        close(server);return strcmp(scenario,"abnormal-exit")==0?7:0;
    }
}

typedef struct { App *app; gboolean during_pending; } FixtureHeartbeat;
static gboolean heartbeat(gpointer data){FixtureHeartbeat *beat=data;if(beat->app->controller_shutdown!=NULL)beat->during_pending=TRUE;return G_SOURCE_CONTINUE;}
static void iterate(void){while(g_main_context_iteration(NULL,FALSE)){}g_usleep(1000);}
static void fixture_window(App *app){
    app->window=gtk_window_new(GTK_WINDOW_TOPLEVEL);app->diagnostics=gtk_text_view_new();gtk_container_add(GTK_CONTAINER(app->window),app->diagnostics);
    g_signal_connect(app->window,"delete-event",G_CALLBACK(on_delete),app);g_signal_connect(app->window,"destroy",G_CALLBACK(on_destroy),app);gtk_widget_show_all(app->window);
}

static void receipt_checks(void){
    const char *owner="0123456789abcdef0123456789abcdef";
    char *good=g_strdup_printf("{\"schema\":1,\"process_id\":42,\"owner_token\":\"%s\",\"closed\":true}",owner);
    check(controller_shutdown_receipt(good,strlen(good),42,owner),"exact typed receipt accepted");
    char *reordered=g_strdup_printf("{\"closed\":true,\"owner_token\":\"%s\",\"process_id\":42,\"schema\":1}",owner);
    check(controller_shutdown_receipt(reordered,strlen(reordered),42,owner),"field order does not replace exact identity");g_free(reordered);
    const char *bad[]={"{}","[]","null","{\"closed\":true}","{\"schema\":1,\"process_id\":42,\"owner_token\":\"0123456789abcdef0123456789abcdef\",\"closed\":false}",
        "{\"schema\":1,\"process_id\":42.0,\"owner_token\":\"0123456789abcdef0123456789abcdef\",\"closed\":true}",
        "{\"schema\":1,\"process_id\":42,\"owner_token\":\"0123456789abcdef0123456789abcdef\",\"closed\":true,\"closed\":true}",
        "{\"schema\":1,\"process_id\":42,\"owner_token\":\"0123456789abcdef0123456789abcdef\",\"closed\":true,\"extra\":0}",
        "{\"schema\":1,\"process_id\":42,\"owner_token\":\"0123456789abcdef0123456789abcdef\",\"Closed\":true}",
        "{\"schema\":1,\"process_id\":42,\"owner_token\":\"0123456789abcdef0123456789abcdef\",\"closed\":true}{}",
        "{\"schema\":1,\"process_id\":42,\"owner_token\":\"0123456789abcdef0123456789abcdef\",\"closed\":true,}",
        "{\"schema\":1,\"process_id\":42,\"owner_token\":\"0123456789abcdef0123456789abcdef\",\"closed\":true/*closed*/}",
        "{\"schema\":01,\"process_id\":42,\"owner_token\":\"0123456789abcdef0123456789abcdef\",\"closed\":true}",
        "{\"schema\":1,\"process_id\":18446744073709551658,\"owner_token\":\"0123456789abcdef0123456789abcdef\",\"closed\":true}",
        "{\"schema\":1,\"process_id\":\"42\",\"owner_token\":\"0123456789abcdef0123456789abcdef\",\"closed\":true}",
        "{\"schema\":1,\"process_id\":42,\"owner_token\":\"0123456789abcdef0123456789abcdef\",\"closed\":1}"};
    for(size_t i=0;i<G_N_ELEMENTS(bad);i++){
        char *message=g_strdup_printf("ambiguous or unconfirmed receipt %zu rejected",i);
        check(!controller_shutdown_receipt(bad[i],strlen(bad[i]),42,owner),message);g_free(message);
    }
    check(!controller_shutdown_receipt(good,strlen(good),43,owner),"different child rejected");
    check(!controller_shutdown_receipt(good,strlen(good),42,"1123456789abcdef0123456789abcdef"),"different launch nonce rejected");
    Buffer body={0};char bytes[4097];memset(bytes,'x',sizeof(bytes));
    check(controller_shutdown_write(bytes,1,4096,&body)==4096,"bounded response accepted");
    check(controller_shutdown_write(bytes,1,1,&body)==0&&body.len==4096,"overflow response rejected before allocation");free(body.data);g_free(good);
    char token[33],second[33];check(controller_owner_token_create(token)&&controller_owner_token_create(second)&&controller_owner_token_valid(token)&&strcmp(token,second)!=0,"fresh secure launcher identities");
}

int main(int argc,char **argv){
    char *name=g_path_get_basename(argv[0]);gboolean controller=strcmp(name,"router-vpn-client")==0;g_free(name);
    if(controller)return fixture_controller();
    check(atexit(fixture_cleanup)==0,"fixture child cleanup registered");
    check(argc==3,"fixture scenario and private root supplied");
    const char *scenario=argv[1];
    check(curl_global_init(CURL_GLOBAL_DEFAULT)==CURLE_OK,"real cURL initialized");check(gtk_init_check(&argc,&argv),"real GTK initialized");
    check(prctl(PR_SET_CHILD_SUBREAPER,1)==0,"fixture retains its buffered-response writer child");
    receipt_checks();
    App app={0};app.package_root=g_strdup(argv[2]);fixture_window(&app);
    if(strcmp(scenario,"occupied")==0){
        int listener=socket(AF_INET,SOCK_STREAM,0);check(listener>=0,"foreign listener created");
        int reuse=1;(void)setsockopt(listener,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));
        struct sockaddr_in address;memset(&address,0,sizeof(address));address.sin_family=AF_INET;address.sin_port=htons(8788);address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        check(bind(listener,(struct sockaddr*)&address,sizeof(address))==0&&listen(listener,1)==0,"foreign listener owns local port");
        char *error=NULL;check(!controller_launch_owned(&app,&error,fixture_launch_exec,500)&&!app.owns_controller&&app.controller_pid==0,"occupied port is never adopted or stopped");g_free(error);
        RVControllerAuth capture;rv_controller_auth_capture(&capture);check(capture.process==0&&capture.header[0]=='\0',"foreign listener never receives controller credential");
        close(listener);gtk_widget_destroy(app.window);g_free(app.package_root);curl_global_cleanup();printf("GTK shutdown %s: %u checks PASS\n",scenario,checks);return 0;
    }
    if(strcmp(scenario,"foreign")==0){
        app.controller_pid=getpid();gboolean handled=TRUE;g_signal_emit_by_name(app.window,"delete-event",NULL,&handled);
        check(!handled&&app.controller_shutdown==NULL&&!app.owns_controller,"non-owned controller receives no shutdown request");
        gtk_widget_destroy(app.window);g_free(app.package_root);curl_global_cleanup();printf("GTK shutdown %s: %u checks PASS\n",scenario,checks);return 0;
    }
    int control[2];check(pipe(control)==0,"fixture control pipe created");fixture_control_read=control[0];fixture_control_write=control[1];char descriptor[32];snprintf(descriptor,sizeof(descriptor),"%d",control[0]);
    check(setenv("RV_CONTROLLER_TEST_SCENARIO",scenario,1)==0&&setenv("RV_CONTROLLER_TEST_FD",descriptor,1)==0,"controlled subprocess environment ready");
    check(setenv("HOMEVPN_CONTROLLER_OWNER","ffffffffffffffffffffffffffffffff",1)==0,"foreign inherited owner installed for negative control");
    gboolean reject_launch=strcmp(scenario,"wrong-proof")==0||strcmp(scenario,"wrong-pid")==0||strcmp(scenario,"wrong-challenge")==0||strcmp(scenario,"auth-cancel")==0;
    char *error=NULL;gboolean launched=controller_launch_owned(&app,&error,fixture_launch_exec,reject_launch?700:5000);
    if(reject_launch){
        check(!launched&&!app.owns_controller&&app.controller_pid==0&&app.controller_lifetime_fd==0,"unproved or cancelled child is joined before launch failure");
        RVControllerAuth capture;rv_controller_auth_capture(&capture);check(capture.process==0&&capture.header[0]=='\0'&&app.controller_access[0]=='\0',"failed identity never publishes bearer secret");
        g_free(error);gtk_widget_destroy(app.window);g_free(app.package_root);curl_global_cleanup();printf("GTK shutdown %s: %u checks PASS\n",scenario,checks);return 0;
    }
    check(launched,error!=NULL?error:"actual launcher started controlled child");g_free(error);
    pid_t child=app.controller_pid;fixture_owned_child=app.owns_controller?child:0;char captured[33];g_strlcpy(captured,app.controller_owner,sizeof(captured));
    check(app.owns_controller&&child>0&&child!=getpid()&&controller_child_observe(child)==0,"launcher owns exact unreaped child");
    check(strcmp(captured,"ffffffffffffffffffffffffffffffff")!=0,"launcher replaced inherited nonce");
    Buffer authenticated={0};check(api_request("/api/status","GET",NULL,900,&authenticated,NULL),"ordinary read uses the authenticated captured controller");free(authenticated.data);
    FixtureHeartbeat beat={.app=&app};guint timer=g_timeout_add(10,heartbeat,&beat);
    gboolean handled=FALSE;g_signal_emit_by_name(app.window,"delete-event",NULL,&handled);
    check(handled&&app.controller_shutdown!=NULL&&app.window!=NULL,"delete callback keeps UI while cleanup is pending");
    Buffer paused={0};char *paused_error=NULL;
    check(!api_request("/api/status","GET",NULL,900,&paused,&paused_error)&&paused_error!=NULL&&strstr(paused_error,"checked controller cleanup")!=NULL,"ordinary UI timer requests cannot block terminal cleanup");
    free(paused.data);g_free(paused_error);
    gpointer first=app.controller_shutdown;g_signal_emit_by_name(app.window,"delete-event",NULL,&handled);check(app.controller_shutdown==first,"repeated close retains one owner");
    gboolean saw_receipt_before_exit=FALSE,saw_exit_before_receipt=FALSE,replaced=FALSE;
    gboolean should_close=strcmp(scenario,"pending")==0||strcmp(scenario,"delay-exit")==0||strcmp(scenario,"exit-during-body")==0;
    gint64 deadline=g_get_monotonic_time()+7*G_USEC_PER_SEC;
    while(g_get_monotonic_time()<deadline){
        iterate();RVControllerShutdown *shutdown=app.controller_shutdown;
        if(shutdown!=NULL){
            if(!shutdown->worker_started&&shutdown->receipt&&controller_child_observe(child)==0)saw_receipt_before_exit=TRUE;
            if(shutdown->worker_started&&!atomic_load_explicit(&shutdown->ready,memory_order_acquire)&&controller_child_observe(child)==1)saw_exit_before_receipt=TRUE;
            if(strcmp(scenario,"replace-owner")==0&&shutdown->worker_started&&!replaced){
                app.controller_pid=child+10000;memset(app.controller_owner,'a',32);app.controller_owner[32]='\0';replaced=TRUE;
            }
            if(!should_close&&strcmp(scenario,"replace-owner")!=0&&!shutdown->worker_started&&shutdown->response_status!=0)break;
        }
        if(app.controller_shutdown==NULL)break;
    }
    check(beat.during_pending,"GTK main loop stayed responsive during cleanup");g_source_remove(timer);
    if(should_close){
        check(!app.owns_controller&&app.controller_pid==0&&app.controller_shutdown==NULL&&app.window==NULL,"receipt and normal exit both completed before closing");
        check(waitpid(child,NULL,WNOHANG)==-1&&errno==ECHILD,"exact captured child joined only after receipt");
        if(strcmp(scenario,"delay-exit")==0)check(saw_receipt_before_exit,"valid response alone did not close before process exit");
        if(strcmp(scenario,"exit-during-body")==0)check(saw_exit_before_receipt,"buffered reply survives normal child exit");
        char *path=g_build_filename(app.package_root,"request-count",NULL),*raw=NULL;check(g_file_get_contents(path,&raw,NULL,NULL),"actual captured endpoint was called");
        check(atoi(raw)==(strcmp(scenario,"pending")==0?2:1),"same identity retried only after pending response");g_free(raw);g_free(path);
    }else if(strcmp(scenario,"replace-owner")==0){
        check(replaced&&app.controller_shutdown==NULL&&app.window!=NULL&&app.owns_controller&&app.controller_pid==child+10000&&strcmp(app.controller_owner,captured)!=0,"old completion cannot clear or close replacement owner");
    }else{
        check(app.owns_controller&&app.controller_pid==child&&app.controller_shutdown!=NULL&&app.window!=NULL,"unconfirmed or abnormal exit leaves owned UI intact");
    }
    /* Test-only out-of-band fixture control is independent of the shipping
     * lifecycle. It never signals a process and cannot affect a real VPN. */
    if(!should_close){char quit='q';check(write(control[1],&quit,1)==1,"fixture controller receives explicit teardown");int status=0;pid_t joined;do{joined=waitpid(child,&status,0);}while(joined<0&&errno==EINTR);check(joined==child,"fixture child reaped by its test owner");app.owns_controller=FALSE;app.controller_pid=0;memset(app.controller_owner,0,sizeof(app.controller_owner));
        deadline=g_get_monotonic_time()+2*G_USEC_PER_SEC;while(app.controller_shutdown!=NULL&&g_get_monotonic_time()<deadline)iterate();check(app.controller_shutdown==NULL,"retired worker drains before fixture releases GTK");
        if(app.window!=NULL)gtk_widget_destroy(app.window);
    }
    fixture_owned_child=0;fixture_cleanup();
    g_free(app.package_root);curl_global_cleanup();printf("GTK shutdown %s: %u checks PASS\n",scenario,checks);return 0;
}
