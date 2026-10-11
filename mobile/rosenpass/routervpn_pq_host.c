#include "routervpn_pq_host.h"
#include <stdlib.h>
#include <string.h>
void routervpn_pq_erase(void *ptr,size_t size) {
    volatile uint8_t *p=(volatile uint8_t*)ptr;
    while(size--) *p++=0;
}
static void le32(uint8_t *p,uint32_t n) {
    p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);p[2]=(uint8_t)(n>>16);p[3]=(uint8_t)(n>>24);
}
int32_t routervpn_pq_event(uint64_t id,uint32_t kind,const uint8_t *input,size_t input_len,
                          uint8_t *output,size_t capacity,size_t *output_len) {
    if(!output_len) return -1;
    *output_len=0;
    if(!output || capacity<ROUTERVPN_PQ_FRAME_HEADER || capacity>ROUTERVPN_PQ_FRAME_CAPACITY) return -1;
    routervpn_pq_erase(output,capacity);
    if(!id || kind>2 || input_len>65535 || (input_len && !input) || (kind!=1 && input_len)) return -1;
    size_t packet_cap=routervpn_rp_packet_size();
    if(routervpn_rp_abi_version()!=1 || !packet_cap || packet_cap>65535 || capacity<packet_cap+ROUTERVPN_PQ_FRAME_HEADER) return -1;
    uint8_t *packet=calloc(packet_cap,1);
    if(!packet) return -1;
    uint8_t key[32]={0};size_t packet_len=0;uint32_t flags=0;uint64_t wait=0;
    int32_t status=routervpn_rp_step(id,kind,input,input_len,packet,packet_cap,&packet_len,key,sizeof(key),&flags,&wait);
    int32_t result=-1;
    if((status==0 || status==-2) && packet_len<=packet_cap && wait<=1000 && !(flags&~3u) && flags!=3 &&
       !(status==-2 && (packet_len || flags))) {
        if(status==-2) wait=1000;
        le32(output,(uint32_t)status);le32(output+4,(uint32_t)wait);le32(output+8,flags);
        if(flags&1u) memcpy(output+12,key,sizeof(key));
        if(packet_len) memcpy(output+ROUTERVPN_PQ_FRAME_HEADER,packet,packet_len);
        *output_len=ROUTERVPN_PQ_FRAME_HEADER+packet_len;result=0;
    }
    routervpn_pq_erase(key,sizeof(key));routervpn_pq_erase(packet,packet_cap);free(packet);
    return result;
}
