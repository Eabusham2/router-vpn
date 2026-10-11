#include <jni.h>
#include <stdlib.h>
#include "routervpn_pq_host.h"
#define FN(name) Java_com_eabusham_routervpn_RouterPQNative_##name
static void fail(JNIEnv *env) {
    if((*env)->ExceptionCheck(env)) return;
    jclass cls=(*env)->FindClass(env,"java/io/IOException");
    if(cls) (*env)->ThrowNew(env,cls,"Native PQ protocol operation failed");
}
static uint8_t *copy(JNIEnv *env,jbyteArray array,size_t required) {
    if(!array || required<32 || required>2u*1024u*1024u || (size_t)(*env)->GetArrayLength(env,array)!=required) return NULL;
    uint8_t *data=malloc(required);if(!data) return NULL;
    (*env)->GetByteArrayRegion(env,array,0,(jsize)required,(jbyte*)data);
    if((*env)->ExceptionCheck(env)) {routervpn_pq_erase(data,required);free(data);return NULL;}
    return data;
}
JNIEXPORT jint JNICALL FN(nativeABI)(JNIEnv *env,jclass cls) {
    (void)env;(void)cls;return (jint)routervpn_rp_abi_version();
}
JNIEXPORT jlong JNICALL FN(nativeOpen)(JNIEnv *env,jclass cls,jbyteArray secret,jbyteArray public_key,jbyteArray peer,jint version) {
    (void)cls;size_t sn=routervpn_rp_secret_size(),pn=routervpn_rp_public_size();
    uint8_t *s=NULL,*p=NULL,*r=NULL;uint64_t handle=0;
    if((version!=2 && version!=3) || routervpn_rp_abi_version()!=1) goto cleanup;
    s=copy(env,secret,sn);if(!s) goto cleanup;
    p=copy(env,public_key,pn);if(!p) goto cleanup;
    r=copy(env,peer,pn);if(!r) goto cleanup;
    if(routervpn_rp_new(s,sn,p,pn,r,pn,(uint32_t)version,&handle)!=0 || handle>INT64_MAX) {
        if(handle) routervpn_rp_close(handle);handle=0;
    }
cleanup:
    if(s){routervpn_pq_erase(s,sn);free(s);}if(p){routervpn_pq_erase(p,pn);free(p);}if(r){routervpn_pq_erase(r,pn);free(r);}
    if(!handle) fail(env);return (jlong)handle;
}
JNIEXPORT jbyteArray JNICALL FN(nativeEvent)(JNIEnv *env,jclass cls,jlong handle,jint kind,jbyteArray input) {
    (void)cls;jbyteArray result=NULL;uint8_t *in=NULL,*out=NULL;size_t n=0,out_n=0;
    if(handle<=0 || kind<0 || kind>2) goto cleanup;
    n=input?(size_t)(*env)->GetArrayLength(env,input):0;
    if(n>65535 || (kind!=1 && n)) goto cleanup;
    if(n){in=malloc(n);if(!in) goto cleanup;(*env)->GetByteArrayRegion(env,input,0,(jsize)n,(jbyte*)in);if((*env)->ExceptionCheck(env)) goto cleanup;}
    out=calloc(ROUTERVPN_PQ_FRAME_CAPACITY,1);if(!out) goto cleanup;
    if(routervpn_pq_event((uint64_t)handle,(uint32_t)kind,in,n,out,ROUTERVPN_PQ_FRAME_CAPACITY,&out_n)!=0) goto cleanup;
    result=(*env)->NewByteArray(env,(jsize)out_n);if(result) (*env)->SetByteArrayRegion(env,result,0,(jsize)out_n,(const jbyte*)out);
cleanup:
    if(in){routervpn_pq_erase(in,n);free(in);}if(out){routervpn_pq_erase(out,ROUTERVPN_PQ_FRAME_CAPACITY);free(out);}
    if(!result) fail(env);return result;
}
JNIEXPORT void JNICALL FN(nativeClose)(JNIEnv *env,jclass cls,jlong handle) {
    (void)cls;if(handle<=0 || routervpn_rp_close((uint64_t)handle)!=0) fail(env);
}
