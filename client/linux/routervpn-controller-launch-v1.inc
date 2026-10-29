/* The GUI never runs as root. Its only elevated command is the fixed installed
 * controller through the desktop's ordinary polkit agent. pkexec receives no
 * private token in argv or environment; stdin is the captured lifetime pipe.
 * https://polkit.pages.freedesktop.org/polkit/pkexec.1.html */
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>

#define RV_CONTROLLER_INSTALLED_ROOT "/opt/router-vpn-client"
#define RV_CONTROLLER_INSTALLED_EXEC RV_CONTROLLER_INSTALLED_ROOT "/router-vpn-client"

typedef void (*RVControllerExec)(App *app);

static void controller_private_launch_exec(App *app) {
    (void)app;
    execl("/usr/bin/pkexec","pkexec","--disable-internal-agent",RV_CONTROLLER_INSTALLED_EXEC,"--linux-owned-controller",(char*)NULL);
    _exit(127);
}

static void controller_launch_credentials_close(App *app) {
    rv_controller_auth_clear(app->controller_pid,app->controller_access);
    if(app->controller_lifetime_fd>2)close(app->controller_lifetime_fd);
    app->controller_lifetime_fd=0;
    memset(app->controller_access,0,sizeof(app->controller_access));
}

static gboolean controller_fixed_install(App *app,char **error_out) {
    if(getuid()==0||geteuid()!=getuid()){
        if(error_out!=NULL)*error_out=g_strdup("Open Router VPN from your normal desktop account. The system authentication dialog authorizes its tunnel controller.");
        return FALSE;
    }
    struct stat info;
    if(g_strcmp0(app->package_root,RV_CONTROLLER_INSTALLED_ROOT)!=0||
       lstat(RV_CONTROLLER_INSTALLED_EXEC,&info)!=0||!S_ISREG(info.st_mode)||info.st_uid!=0||info.st_gid!=0||
       (info.st_mode&0022)!=0||info.st_nlink!=1||access(RV_CONTROLLER_INSTALLED_EXEC,X_OK)!=0||access("/usr/bin/pkexec",X_OK)!=0){
        if(error_out!=NULL)*error_out=g_strdup("Install Router VPN with sudo ./install-router-vpn.sh, then open the installed Router VPN desktop entry. Its privileged controller must use the protected installation.");
        return FALSE;
    }
    return TRUE;
}

static gboolean controller_loopback_available(void) {
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);if(fd<0)return FALSE;
    int reuse=1;(void)setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));
    struct sockaddr_in address;memset(&address,0,sizeof(address));address.sin_family=AF_INET;
    address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);address.sin_port=htons(8788);
    gboolean available=bind(fd,(struct sockaddr*)&address,sizeof(address))==0;
    close(fd);return available;
}

static gboolean controller_lifetime_pipe(int pair[2]) {
    int created[2];if(pipe2(created,O_CLOEXEC)!=0)return FALSE;
    pair[0]=fcntl(created[0],F_DUPFD_CLOEXEC,3);
    pair[1]=fcntl(created[1],F_DUPFD_CLOEXEC,3);
    close(created[0]);close(created[1]);
    if(pair[0]<0||pair[1]<0){if(pair[0]>=0)close(pair[0]);if(pair[1]>=0)close(pair[1]);return FALSE;}
    return TRUE;
}

static gboolean controller_identity_proved(App *app) {
    if(!app->owns_controller||controller_child_observe(app->controller_pid)!=0||!rv_controller_secret_valid(app->controller_access))return FALSE;
    char challenge[33];if(!controller_owner_token_create(challenge))return FALSE;
    char *message=g_strdup_printf("routervpn-controller-identity-request\n%s",challenge);
    char *proof=g_compute_hmac_for_string(G_CHECKSUM_SHA256,(const guchar*)app->controller_access,64,message,-1);
    g_free(message);
    char *authorization=g_strdup_printf("Authorization: RouterVPN-Identity %s",proof);
    char *challenge_header=g_strdup_printf("X-RouterVPN-Challenge: %s",challenge);
    g_free(proof);
    CURL *curl=curl_easy_init();Buffer response={0};long status=0;CURLcode code=CURLE_FAILED_INIT;
    if(curl!=NULL){
        struct curl_slist *headers=NULL;headers=curl_slist_append(headers,authorization);headers=curl_slist_append(headers,challenge_header);
        curl_easy_setopt(curl,CURLOPT_URL,ROUTER_VPN_BASE_URL "/api/controller/identity");
        curl_easy_setopt(curl,CURLOPT_PROXY,"");curl_easy_setopt(curl,CURLOPT_NOPROXY,"*");curl_easy_setopt(curl,CURLOPT_NOSIGNAL,1L);
        curl_easy_setopt(curl,CURLOPT_CONNECTTIMEOUT_MS,300L);curl_easy_setopt(curl,CURLOPT_TIMEOUT_MS,500L);
        curl_easy_setopt(curl,CURLOPT_FOLLOWLOCATION,0L);curl_easy_setopt(curl,CURLOPT_HTTPHEADER,headers);
        curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,controller_shutdown_write);curl_easy_setopt(curl,CURLOPT_WRITEDATA,&response);
        code=curl_easy_perform(curl);curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&status);
        curl_slist_free_all(headers);curl_easy_cleanup(curl);
    }
    g_free(authorization);g_free(challenge_header);
    gboolean accepted=FALSE;
    if(code==CURLE_OK&&status==200&&response.len<2048){
        JsonNode *root=parse_json(response.data);
        if(root!=NULL&&JSON_NODE_HOLDS_OBJECT(root)){
            JsonObject *object=json_node_get_object(root);
            JsonNode *schema=json_object_get_member(object,"schema"),*process=json_object_get_member(object,"process_id");
            if(json_object_get_size(object)==4&&schema!=NULL&&process!=NULL&&
               JSON_NODE_HOLDS_VALUE(schema)&&json_node_get_value_type(schema)==G_TYPE_INT64&&json_node_get_int(schema)==1&&
               JSON_NODE_HOLDS_VALUE(process)&&json_node_get_value_type(process)==G_TYPE_INT64&&json_node_get_int(process)==app->controller_pid&&
               strcmp(obj_string(object,"challenge"),challenge)==0){
                message=g_strdup_printf("routervpn-controller-identity-response\n%ld\n%s",(long)app->controller_pid,challenge);
                proof=g_compute_hmac_for_string(G_CHECKSUM_SHA256,(const guchar*)app->controller_access,64,message,-1);
                accepted=proof!=NULL&&strcmp(obj_string(object,"proof"),proof)==0&&controller_child_observe(app->controller_pid)==0;
                g_free(message);g_free(proof);
            }
        }
        if(root!=NULL)json_node_free(root);
    }
    free(response.data);return accepted;
}

static void controller_launch_join_failed(App *app) {
    /* Closing only our write end makes a started controller drain its owned
     * runtimes. An authentication dialog that has not completed can be closed
     * normally; if later approved, its controller receives EOF and rejects it.
     * Retain the unreaped child until it actually exits; never discard a PID or
     * send a bearer secret to an unproved listener merely to request cleanup. */
    if(app->controller_lifetime_fd>2)close(app->controller_lifetime_fd);
    app->controller_lifetime_fd=0;
    GtkWidget *dialog=NULL;
    while(controller_child_observe(app->controller_pid)==0){
        if(dialog==NULL){
            dialog=gtk_message_dialog_new(NULL,0,GTK_MESSAGE_INFO,GTK_BUTTONS_NONE,"Closing Router VPN controller startup");
            gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(dialog),"Waiting for this launch to exit. Close any pending system authentication dialog. Active native work is being cleaned up.");
            g_signal_connect(dialog,"delete-event",G_CALLBACK(controller_shutdown_keep_window),NULL);gtk_widget_show(dialog);
        }
        while(g_main_context_iteration(NULL,FALSE)){}
        g_usleep(20000);
    }
    if(dialog!=NULL)gtk_widget_destroy(dialog);
    int status;pid_t joined;
    do{joined=waitpid(app->controller_pid,&status,0);}while(joined<0&&errno==EINTR);
    if(joined==app->controller_pid){
        controller_launch_credentials_close(app);app->controller_pid=0;app->owns_controller=FALSE;
        memset(app->controller_owner,0,sizeof(app->controller_owner));
    }
}

/* The callable boundary is used by the executable launcher tests with their
 * own child process. The production caller below always supplies fixed pkexec
 * arguments, the fixed installation and the ordinary desktop user. */
static gboolean controller_launch_owned(App *app,char **error_out,RVControllerExec execute,long budget_ms) {
    if(app->owns_controller||app->controller_pid!=0||execute==NULL||budget_ms<1||budget_ms>120000||!controller_loopback_available()){
        if(error_out!=NULL)*error_out=g_strdup("Another Router VPN window or program owns the local controller port. Close that instance before opening this one.");
        return FALSE;
    }
    if(!controller_owner_token_create(app->controller_owner)||!controller_owner_token_create(app->controller_access)||
       !controller_owner_token_create(app->controller_access+32)){
        if(error_out!=NULL)*error_out=g_strdup("Could not create the private controller launch identity.");
        return FALSE;
    }
    int pipefd[2];
    if(!controller_lifetime_pipe(pipefd)){
        memset(app->controller_access,0,sizeof(app->controller_access));
        if(error_out!=NULL)*error_out=g_strdup("Could not create the private controller lifetime channel.");
        return FALSE;
    }
    char *frame=g_strdup_printf("{\"schema\":1,\"access_token\":\"%s\",\"owner_token\":\"%s\"}\n",app->controller_access,app->controller_owner);
    size_t size=strlen(frame),used=0;
    while(used<size){ssize_t n=write(pipefd[1],frame+used,size-used);if(n<0&&errno==EINTR)continue;if(n<=0)break;used+=(size_t)n;}
    memset(frame,0,size);g_free(frame);
    if(used!=size){close(pipefd[0]);close(pipefd[1]);memset(app->controller_access,0,sizeof(app->controller_access));
        if(error_out!=NULL)*error_out=g_strdup("Could not transfer the private controller launch identity.");
        return FALSE;}
    pid_t child=fork();
    if(child==0){
        close(pipefd[1]);if(dup2(pipefd[0],STDIN_FILENO)<0)_exit(126);close(pipefd[0]);
        execute(app);_exit(127);
    }
    close(pipefd[0]);
    if(child<0){close(pipefd[1]);memset(app->controller_access,0,sizeof(app->controller_access));
        if(error_out!=NULL)*error_out=g_strdup("Could not start the authorized tunnel controller.");
        return FALSE;}
    app->controller_lifetime_fd=pipefd[1];app->controller_pid=child;app->owns_controller=TRUE;
    gint64 deadline=g_get_monotonic_time()+budget_ms*1000;
    while(g_get_monotonic_time()<deadline&&controller_child_observe(child)==0){
        if(controller_identity_proved(app)&&rv_controller_auth_publish(child,app->controller_access))return TRUE;
        while(g_main_context_iteration(NULL,FALSE)){}
        g_usleep(100000);
    }
    controller_launch_join_failed(app);
    if(error_out!=NULL)*error_out=g_strdup("Router VPN could not authorize and verify this tunnel controller. The system dialog may have been cancelled, or the installed configuration needs repair.");
    return FALSE;
}

static gboolean ensure_controller(App *app,char **error_out) {
    if(!controller_fixed_install(app,error_out))return FALSE;
    return controller_launch_owned(app,error_out,controller_private_launch_exec,120000);
}
