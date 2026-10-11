#ifndef ROUTERVPN_PQ_HOST_H
#define ROUTERVPN_PQ_HOST_H
#include "routervpn_rosenpass.h"
#define ROUTERVPN_PQ_FRAME_HEADER 44u
#define ROUTERVPN_PQ_FRAME_CAPACITY (44u + 65535u)
#ifdef __cplusplus
extern "C" {
#endif
/* Output: little-endian status(i32), wait_ms(u32), flags(u32), key[32], packet.
 * A rejected packet is status -2 with no flags/key/packet. Failures erase output.
 * Own nonoverlapping input/output; no pointer is retained. */
int32_t routervpn_pq_event(uint64_t,uint32_t,const uint8_t*,size_t,uint8_t*,size_t,size_t*);
void routervpn_pq_erase(void*,size_t);
#ifdef __cplusplus
}
#endif
#endif
