#ifndef ROUTERVPN_CONTROLLER_AUTH_V1_H
#define ROUTERVPN_CONTROLLER_AUTH_V1_H
#include <pthread.h>
#include <string.h>
#include <sys/types.h>

/* Workers capture this immutable header when their operation is created.
 * A later launch can never supply its credential to an older HTTP request. */
typedef struct {
    pid_t process;
    char header[96];
} RVControllerAuth;

static pthread_mutex_t rv_controller_auth_lock=PTHREAD_MUTEX_INITIALIZER;
static RVControllerAuth rv_controller_auth_current;

static inline int rv_controller_secret_valid(const char *secret) {
    if(secret==NULL||strlen(secret)!=64)return 0;
    for(size_t i=0;i<64;i++)if(!((secret[i]>='0'&&secret[i]<='9')||(secret[i]>='a'&&secret[i]<='f')))return 0;
    return 1;
}

static inline int rv_controller_auth_from(RVControllerAuth *capture,pid_t process,const char *secret) {
    memset(capture,0,sizeof(*capture));
    if(process<=0||!rv_controller_secret_valid(secret))return 0;
    capture->process=process;
    memcpy(capture->header,"Authorization: Bearer ",22);
    memcpy(capture->header+22,secret,65);
    return 1;
}

static inline void rv_controller_auth_capture(RVControllerAuth *capture) {
    pthread_mutex_lock(&rv_controller_auth_lock);
    *capture=rv_controller_auth_current;
    pthread_mutex_unlock(&rv_controller_auth_lock);
}

static inline int rv_controller_auth_publish(pid_t process,const char *secret) {
    RVControllerAuth capture;
    if(!rv_controller_auth_from(&capture,process,secret))return 0;
    pthread_mutex_lock(&rv_controller_auth_lock);
    int empty=rv_controller_auth_current.process==0;
    if(empty)rv_controller_auth_current=capture;
    pthread_mutex_unlock(&rv_controller_auth_lock);
    memset(&capture,0,sizeof(capture));
    return empty;
}

static inline void rv_controller_auth_clear(pid_t process,const char *secret) {
    RVControllerAuth capture;
    if(!rv_controller_auth_from(&capture,process,secret))return;
    pthread_mutex_lock(&rv_controller_auth_lock);
    if(rv_controller_auth_current.process==process&&strcmp(rv_controller_auth_current.header,capture.header)==0)
        memset(&rv_controller_auth_current,0,sizeof(rv_controller_auth_current));
    pthread_mutex_unlock(&rv_controller_auth_lock);
    memset(&capture,0,sizeof(capture));
}
#endif
