#ifndef ROUTERVPN_ROSENPASS_H
#define ROUTERVPN_ROSENPASS_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
uint32_t routervpn_rp_abi_version(void);
size_t routervpn_rp_secret_size(void);
size_t routervpn_rp_public_size(void);
size_t routervpn_rp_packet_size(void);
/* New copies keys; handles are never reused. 0 success, -1 invalid/closed. */
int32_t routervpn_rp_new(const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t,uint32_t,uint64_t*);
/* kind: poll=0, receive=1, initiate=2. flags: key changed=1, expired=2.
 * -2 means rejected datagram. Close joins in-flight key publication.
 * Caller owns nonoverlapping buffers; no pointer is retained. */
int32_t routervpn_rp_step(uint64_t,uint32_t,const uint8_t*,size_t,uint8_t*,size_t,size_t*,uint8_t*,size_t,uint32_t*,uint64_t*);
int32_t routervpn_rp_close(uint64_t);
#ifdef __cplusplus
}
#endif
#endif
