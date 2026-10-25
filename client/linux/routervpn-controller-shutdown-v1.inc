/* Normal app exit retains the exact launched, unreaped child until both its
 * authenticated cleanup receipt and normal process exit have been observed.
 * HTTP workers carry immutable launch identity and never operate GTK widgets. */
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/random.h>

typedef struct {
    App *app;
    pid_t process;
    char owner[33];
    GtkWidget *dialog;
    guint timer;
    pthread_t worker;
    gboolean worker_started, receipt, retired;
    atomic_bool ready;
    long response_status;
    Buffer response;
    gint64 retry_at;
} RVControllerShutdown;

static gboolean controller_shutdown_tick(gpointer data);

static gboolean controller_owner_token_valid(const char *token) {
    if (token == NULL || strlen(token) != 32) return FALSE;
    for (size_t i=0;i<32;i++) if (!((token[i]>='0'&&token[i]<='9')||(token[i]>='a'&&token[i]<='f'))) return FALSE;
    return TRUE;
}

static gboolean controller_owner_token_create(char token[33]) {
    unsigned char bytes[16];size_t used=0;
    while (used<sizeof(bytes)) {
        ssize_t n=getrandom(bytes+used,sizeof(bytes)-used,0);
        if (n<0&&errno==EINTR) continue;
        if (n<=0) { memset(bytes,0,sizeof(bytes));token[0]='\0';return FALSE; }
        used+=(size_t)n;
    }
    static const char digits[]="0123456789abcdef";
    for(size_t i=0;i<sizeof(bytes);i++){token[2*i]=digits[bytes[i]>>4];token[2*i+1]=digits[bytes[i]&15];}
    token[32]='\0';memset(bytes,0,sizeof(bytes));return TRUE;
}

/* Zero means still alive, one means normal exit, two means abnormal exit.
 * WNOWAIT deliberately prevents PID reuse while a reply is still in flight. */
static int controller_child_observe(pid_t process) {
    if(process<=0)return -1;
    siginfo_t info;memset(&info,0,sizeof(info));
    int result;
    do {result=waitid(P_PID,(id_t)process,&info,WEXITED|WNOHANG|WNOWAIT);}while(result<0&&errno==EINTR);
    if(result<0)return -1;
    if(info.si_pid==0)return 0;
    if(info.si_pid!=process)return -1;
    return info.si_code==CLD_EXITED&&info.si_status==0?1:2;
}

static void controller_shutdown_space(const char **cursor,const char *end) {
    while(*cursor<end&&(**cursor==' '||**cursor=='\t'||**cursor=='\r'||**cursor=='\n'))(*cursor)++;
}

/* The receipt has four fixed ASCII keys and a lowercase hex token. This small
 * decoder deliberately consumes the whole document; JSON-GLib accepts trailing
 * documents, which cannot be accepted as a single cleanup acknowledgement. */
static gboolean controller_shutdown_string(const char **cursor,const char *end,char value[33]) {
    if(*cursor>=end||*(*cursor)++!='"')return FALSE;
    size_t length=0;
    while(*cursor<end&&**cursor!='"'){
        unsigned char ch=(unsigned char)*(*cursor)++;
        if(ch<0x20||ch>=0x7f||ch=='\\'||length>=32)return FALSE;
        value[length++]=(char)ch;
    }
    if(*cursor>=end)return FALSE;
    (*cursor)++;value[length]='\0';return TRUE;
}

static gboolean controller_shutdown_integer(const char **cursor,const char *end,guint64 *value) {
    if(*cursor>=end||**cursor<'0'||**cursor>'9')return FALSE;
    gboolean leading_zero=**cursor=='0';size_t digits=0;*value=0;
    while(*cursor<end&&**cursor>='0'&&**cursor<='9'){
        guint64 digit=(guint64)(*(*cursor)++-'0');
        if(*value>(G_MAXUINT64-digit)/10)return FALSE;
        *value=*value*10+digit;digits++;
    }
    return !leading_zero||digits==1;
}

static gboolean controller_shutdown_receipt(const char *data,size_t length,pid_t process,const char *owner) {
    if(data==NULL||length==0||length>4096||process<=0||!controller_owner_token_valid(owner)||memchr(data,'\0',length)!=NULL)return FALSE;
    const char *cursor=data,*end=data+length;guint seen=0;
    controller_shutdown_space(&cursor,end);
    if(cursor>=end||*cursor++!='{')return FALSE;
    for(;;){
        char key[33],captured_owner[33];guint bit=0;guint64 number=0;
        controller_shutdown_space(&cursor,end);
        if(!controller_shutdown_string(&cursor,end,key))return FALSE;
        if(strcmp(key,"schema")==0)bit=1;else if(strcmp(key,"process_id")==0)bit=2;
        else if(strcmp(key,"owner_token")==0)bit=4;else if(strcmp(key,"closed")==0)bit=8;
        if(bit==0||(seen&bit)!=0)return FALSE;
        seen|=bit;controller_shutdown_space(&cursor,end);
        if(cursor>=end||*cursor++!=':')return FALSE;
        controller_shutdown_space(&cursor,end);
        if(bit==1||bit==2){
            if(!controller_shutdown_integer(&cursor,end,&number)||number!=(bit==1?1:(guint64)process))return FALSE;
        }else if(bit==4){
            if(!controller_shutdown_string(&cursor,end,captured_owner)||!(strcmp(captured_owner,owner)==0))return FALSE;
        }else{
            if(end-cursor<4||memcmp(cursor,"true",4)!=0)return FALSE;
            cursor+=4;
        }
        controller_shutdown_space(&cursor,end);
        if(cursor>=end)return FALSE;
        if(*cursor==','){cursor++;continue;}
        if(*cursor++!='}')return FALSE;
        controller_shutdown_space(&cursor,end);
        return seen==15&&cursor==end;
    }
}

static size_t controller_shutdown_write(void *data,size_t size,size_t count,void *context) {
    Buffer *buffer=context;
    if(size!=0&&count>4096/size)return 0;
    size_t length=size*count;
    if(buffer->len>4096||length>4096-buffer->len)return 0;
    char *next=realloc(buffer->data,buffer->len+length+1);if(next==NULL)return 0;
    buffer->data=next;memcpy(next+buffer->len,data,length);buffer->len+=length;next[buffer->len]='\0';return length;
}

static void *controller_shutdown_worker(void *data) {
    RVControllerShutdown *shutdown=data;
    CURL *curl=curl_easy_init();
    if(curl!=NULL){
        char *body=g_strdup_printf("{\"schema\":1,\"process_id\":%ld,\"owner_token\":\"%s\"}",(long)shutdown->process,shutdown->owner);
        struct curl_slist *headers=NULL;headers=curl_slist_append(headers,"Content-Type: application/json");headers=curl_slist_append(headers,"Accept: application/json");
        curl_easy_setopt(curl,CURLOPT_URL,ROUTER_VPN_BASE_URL "/api/controller/shutdown");
        curl_easy_setopt(curl,CURLOPT_PROXY,"");curl_easy_setopt(curl,CURLOPT_NOPROXY,"*");curl_easy_setopt(curl,CURLOPT_NOSIGNAL,1L);
        curl_easy_setopt(curl,CURLOPT_CONNECTTIMEOUT_MS,2000L);curl_easy_setopt(curl,CURLOPT_TIMEOUT_MS,35000L);
        curl_easy_setopt(curl,CURLOPT_FOLLOWLOCATION,0L);curl_easy_setopt(curl,CURLOPT_HTTPHEADER,headers);
        curl_easy_setopt(curl,CURLOPT_POSTFIELDS,body);curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,controller_shutdown_write);
        curl_easy_setopt(curl,CURLOPT_WRITEDATA,&shutdown->response);
        CURLcode code=curl_easy_perform(curl);curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&shutdown->response_status);
        shutdown->receipt=code==CURLE_OK&&shutdown->response_status==200&&controller_shutdown_receipt(shutdown->response.data,shutdown->response.len,shutdown->process,shutdown->owner);
        curl_slist_free_all(headers);curl_easy_cleanup(curl);g_free(body);
    }
    atomic_store_explicit(&shutdown->ready,TRUE,memory_order_release);return NULL;
}

static gboolean controller_shutdown_current(RVControllerShutdown *shutdown) {
    App *app=shutdown->app;
    return app->controller_shutdown==shutdown&&app->owns_controller&&app->controller_pid==shutdown->process&&strcmp(app->controller_owner,shutdown->owner)==0;
}

static void controller_shutdown_message(RVControllerShutdown *shutdown,const char *message) {
    if(shutdown->dialog!=NULL)gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(shutdown->dialog),"%s",message);
}

static gboolean controller_shutdown_keep_window(GtkWidget *widget,GdkEvent *event,gpointer data) {
    (void)widget;(void)event;(void)data;return TRUE;
}

static void controller_shutdown_release(RVControllerShutdown *shutdown,gboolean completed) {
    App *app=shutdown->app;
    gboolean owned_slot=app->controller_shutdown==shutdown;
    if(owned_slot)app->controller_shutdown=NULL;
    if(shutdown->dialog!=NULL)gtk_widget_destroy(shutdown->dialog);
    free(shutdown->response.data);memset(shutdown->owner,0,sizeof(shutdown->owner));g_free(shutdown);
    if(completed){
        if(app->window!=NULL)gtk_widget_destroy(app->window);
        if(gtk_main_level()>0)gtk_main_quit();
    }else if(owned_slot){
        atomic_store_explicit(&controller_exit_pending,FALSE,memory_order_release);
        if(app->window!=NULL)gtk_widget_set_sensitive(app->window,TRUE);
    }
}

static gboolean controller_shutdown_tick(gpointer data) {
    RVControllerShutdown *shutdown=data;
    if(!controller_shutdown_current(shutdown))shutdown->retired=TRUE;
    if(shutdown->worker_started){
        /* Process death cannot cancel a buffered response. Its complete body
         * is still required, within the original bounded request lifetime. */
        if(!atomic_load_explicit(&shutdown->ready,memory_order_acquire))return G_SOURCE_CONTINUE;
        (void)pthread_join(shutdown->worker,NULL);shutdown->worker_started=FALSE;
        shutdown->retry_at=g_get_monotonic_time()+G_USEC_PER_SEC;
        if(!shutdown->receipt)controller_shutdown_message(shutdown,"Cleanup has not been confirmed. Router VPN is staying open and will retry.");
    }
    if(shutdown->retired){controller_shutdown_release(shutdown,FALSE);return G_SOURCE_REMOVE;}
    int child=controller_child_observe(shutdown->process);
    if(shutdown->receipt&&child==1){
        int status=0;pid_t joined;
        do{joined=waitpid(shutdown->process,&status,WNOHANG);}while(joined<0&&errno==EINTR);
        if(joined==shutdown->process&&WIFEXITED(status)&&WEXITSTATUS(status)==0&&controller_shutdown_current(shutdown)){
            shutdown->app->owns_controller=FALSE;shutdown->app->controller_pid=0;memset(shutdown->app->controller_owner,0,sizeof(shutdown->app->controller_owner));
            controller_shutdown_release(shutdown,TRUE);return G_SOURCE_REMOVE;
        }
        controller_shutdown_message(shutdown,"The controller exit could not be confirmed for this launch. Router VPN remains open.");return G_SOURCE_CONTINUE;
    }
    if(child!=0){
        controller_shutdown_message(shutdown,"The controller stopped without a complete cleanup confirmation. Router VPN remains open.");return G_SOURCE_CONTINUE;
    }
    if(shutdown->receipt){controller_shutdown_message(shutdown,"Cleanup confirmed. Waiting for the controller to exit normally.");return G_SOURCE_CONTINUE;}
    if(g_get_monotonic_time()<shutdown->retry_at)return G_SOURCE_CONTINUE;
    free(shutdown->response.data);memset(&shutdown->response,0,sizeof(shutdown->response));shutdown->response_status=0;
    atomic_store_explicit(&shutdown->ready,FALSE,memory_order_relaxed);
    if(pthread_create(&shutdown->worker,NULL,controller_shutdown_worker,shutdown)==0)shutdown->worker_started=TRUE;
    else{shutdown->retry_at=g_get_monotonic_time()+G_USEC_PER_SEC;controller_shutdown_message(shutdown,"The cleanup request could not start. Router VPN will retry.");}
    return G_SOURCE_CONTINUE;
}

static void shutdown_controller(App *app) {
    if(!app->owns_controller||app->controller_pid<=0||app->controller_shutdown!=NULL)return;
    RVControllerShutdown *shutdown=g_new0(RVControllerShutdown,1);shutdown->app=app;shutdown->process=app->controller_pid;
    g_strlcpy(shutdown->owner,app->controller_owner,sizeof(shutdown->owner));atomic_init(&shutdown->ready,FALSE);
    app->controller_shutdown=shutdown;
    atomic_store_explicit(&controller_exit_pending,TRUE,memory_order_release);
    shutdown->dialog=gtk_message_dialog_new(app->window!=NULL?GTK_WINDOW(app->window):NULL,0,GTK_MESSAGE_INFO,GTK_BUTTONS_NONE,"Closing Router VPN");
    gtk_window_set_title(GTK_WINDOW(shutdown->dialog),"Router VPN");
    g_signal_connect(shutdown->dialog,"delete-event",G_CALLBACK(controller_shutdown_keep_window),NULL);
    controller_shutdown_message(shutdown,"Waiting for the current connection and MTU test to finish cleanup.");
    if(app->window!=NULL)gtk_widget_set_sensitive(app->window,FALSE);
    gtk_widget_show_all(shutdown->dialog);
    if(!controller_owner_token_valid(shutdown->owner)){
        shutdown->retry_at=G_MAXINT64;controller_shutdown_message(shutdown,"This controller has no captured launch identity. Router VPN cannot confirm its cleanup.");
    }
    shutdown->timer=g_timeout_add(100,controller_shutdown_tick,shutdown);
}

static gboolean on_delete(GtkWidget *widget,GdkEvent *event,gpointer data) {
    (void)widget;(void)event;App *app=data;
    if(!app->owns_controller)return FALSE;
    shutdown_controller(app);return TRUE;
}
