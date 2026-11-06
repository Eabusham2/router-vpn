#include "validator.h"
#include <unbound.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
struct rvdns {
    struct ub_ctx *ctx;
    uint32_t result[8];
    unsigned char packet[65535];
    unsigned anchors, insecure, bytes;
    int started, id;
};
uint32_t rvdns_abi(void) { return 1; }
static int name_ok(const char *s, uint32_t n) {
    if (!s || !n || n > 254 || s[n-1] != '.') return 0;
    if(n == 1) return 1;
    unsigned label = 0;
    for(uint32_t i=0;i<n;i++) {
        unsigned char c = (unsigned char)s[i];
        if(c == '.') { if(!label || label > 63) return 0; label=0; }
        else { if(!((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'||c=='_')) return 0; label++; }
    }
    return 1;
}
struct rvdns *rvdns_create(uint16_t port) {
    if(!port || !OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL)) return NULL;
    struct rvdns *v = calloc(1, sizeof(*v));
    if(!v) return NULL;
    v->result[0]=1;
    v->ctx=ub_ctx_create();
    if(!v->ctx) { free(v); return NULL; }
    const char *opts[][2] = {
        {"local-zone:","localhost. transparent"}, {"local-zone:","test. transparent"},
        {"local-zone:","invalid. transparent"}, {"local-zone:","onion. transparent"},
        {"local-zone:","home.arpa. transparent"}, {"local-zone:","resolver.arpa. transparent"},
        {"local-zone:","service.arpa. transparent"}, {"local-zone:","127.in-addr.arpa. transparent"},
        {"local-zone:","1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa. transparent"},
        {"unblock-lan-zones:","yes"}, {"module-config:","validator iterator"}, {"tcp-upstream:","yes"},
        {"do-udp:","no"}, {"do-ip6:","no"}, {"do-not-query-localhost:","no"},
        {"trust-anchor-signaling:","no"}, {"use-syslog:","no"},
        {"val-permissive-mode:","no"}, {"qname-minimisation:","no"},
        {"harden-dnssec-stripped:","yes"}, {"edns-buffer-size:","1232"},
        {"msg-cache-size:","1m"}, {"rrset-cache-size:","1m"},
        {"key-cache-size:","1m"}, {"neg-cache-size:","1m"},
        {"outgoing-range:","8"}, {"outgoing-num-tcp:","8"},
        {"num-queries-per-thread:","16"}, {"verbosity:","0"}
    };
    for(unsigned i=0;i<sizeof(opts)/sizeof(opts[0]);i++)
        if(ub_ctx_set_option(v->ctx,opts[i][0],opts[i][1])) goto fail;
    char forward[32];
    snprintf(forward,sizeof(forward),"127.0.0.1@%u",port);
    /* Pinned ub_ctx_set_fwd allocates root forward with calloc: first=0.
     * Never pass NULL (which would remove the only forwarder). */
    if(ub_ctx_set_fwd(v->ctx,forward) || ub_ctx_async(v->ctx,1)) goto fail;
    return v;
fail:
    ub_ctx_delete(v->ctx); free(v); return NULL;
}
int rvdns_anchor(struct rvdns *v,const char *s,uint32_t n) {
    if(!v||v->started||!s||!n||n>4096||v->anchors>=32||v->bytes+n>32768) return -1;
    for(uint32_t i=0;i<n;i++) if((s[i]!='\t' && (unsigned char)s[i]<32) || (unsigned char)s[i]>126) return -1;
    char buf[4097]; memcpy(buf,s,n); buf[n]=0;
    if(ub_ctx_add_ta(v->ctx,buf)) return -1;
    v->anchors++; v->bytes+=n; return 0;
}
int rvdns_insecure(struct rvdns *v,const char *s,uint32_t n) {
    if(!v||v->started||v->insecure>=32||!name_ok(s,n)) return -1;
    char buf[255]; memcpy(buf,s,n); buf[n]=0;
    if(ub_ctx_set_option(v->ctx,"domain-insecure:",buf)) return -1;
    v->insecure++; return 0;
}
static void done(void *arg,int error,struct ub_result *r) {
    struct rvdns *v=arg;
    v->result[1]=RVDNS_ERROR; v->result[7]=(uint32_t)error;
    if(!error && r && r->answer_len>=0 && r->answer_len<=65535) {
        v->result[1]=r->bogus?RVDNS_BOGUS:(r->rcode!=0 && r->rcode!=3)?RVDNS_ERROR:r->secure?RVDNS_SECURE:RVDNS_INSECURE;
        v->result[2]=(uint32_t)r->rcode; v->result[3]=(uint32_t)r->havedata;
        v->result[4]=(uint32_t)r->nxdomain; v->result[5]=(uint32_t)r->ttl;
        v->result[6]=(uint32_t)r->answer_len;
        if(r->answer_len) memcpy(v->packet,r->answer_packet,(size_t)r->answer_len);
    }
    ub_resolve_free(r);
}
int rvdns_start(struct rvdns *v,const char *s,uint32_t n,uint16_t type) {
    if(!v||v->started||!name_ok(s,n)||(type!=1&&type!=28&&type!=5)) return -1;
    char name[255]; memcpy(name,s,n); name[n]=0; v->started=1;
    int err=ub_resolve_async(v->ctx,name,type,1,v,done,&v->id);
    if(err) { v->result[1]=RVDNS_ERROR; v->result[7]=(uint32_t)err; return -1; }
    return 0;
}
int rvdns_fd(struct rvdns *v) { return v&&v->ctx&&v->started?ub_fd(v->ctx):-1; }
int rvdns_process(struct rvdns *v) {
    if(!v||!v->ctx||!v->started) return -1;
    return ub_process(v->ctx);
}
int rvdns_cancel(struct rvdns *v) {
    if(!v||!v->ctx) return -1;
    if(v->started && !v->result[1]) (void)ub_cancel(v->ctx,v->id);
    ub_ctx_delete(v->ctx); v->ctx=NULL;
    memset(v->packet,0,sizeof(v->packet)); memset(v->result,0,sizeof(v->result));
    v->result[0]=1; v->result[1]=RVDNS_CANCELLED; v->started=1; return 0;
}
int rvdns_result(struct rvdns *v,uint32_t *header,uint32_t words,unsigned char *packet,uint32_t capacity) {
    if(!v||!header||words!=8||capacity<v->result[6]||(!packet&&v->result[6])) return -1;
    memcpy(header,v->result,sizeof(v->result));
    if(v->result[6]) memcpy(packet,v->packet,v->result[6]);
    return v->result[1]?1:0;
}
void rvdns_destroy(struct rvdns *v) {
    if(!v) return;
    if(v->ctx) ub_ctx_delete(v->ctx);
    memset(v,0,sizeof(*v)); free(v);
}
