#ifndef ROUTERVPN_DNSSEC_VALIDATOR_H
#define ROUTERVPN_DNSSEC_VALIDATOR_H
#include <stdint.h>
/* ABI 1. All calls for one handle must be serialized by its owner. No callbacks
 * enter the caller. Destroy joins the pinned library worker before returning.
 * Cancel destroys/joins that worker before exposing the cancelled state.
 * The caller must impose its original hard process deadline around C calls. */
#define RVDNS_EXPORT __attribute__((visibility("default")))
struct rvdns;
enum { RVDNS_PENDING=0, RVDNS_SECURE=1, RVDNS_INSECURE=2,
       RVDNS_BOGUS=3, RVDNS_ERROR=4, RVDNS_CANCELLED=5 };
RVDNS_EXPORT uint32_t rvdns_abi(void);
RVDNS_EXPORT struct rvdns *rvdns_create(uint16_t loopback_tcp_port);
RVDNS_EXPORT int rvdns_anchor(struct rvdns *, const char *, uint32_t);
RVDNS_EXPORT int rvdns_insecure(struct rvdns *, const char *, uint32_t);
RVDNS_EXPORT int rvdns_start(struct rvdns *, const char *, uint32_t, uint16_t);
RVDNS_EXPORT int rvdns_fd(struct rvdns *);
RVDNS_EXPORT int rvdns_process(struct rvdns *);
RVDNS_EXPORT int rvdns_cancel(struct rvdns *);
/* Copies 8 uint32 words: ABI,state,rcode,havedata,nxdomain,ttl,packetlen,error.
 * Returns -1 for invalid/short buffers, zero pending, one terminal. */
RVDNS_EXPORT int rvdns_result(struct rvdns *, uint32_t *, uint32_t, unsigned char *, uint32_t);
RVDNS_EXPORT void rvdns_destroy(struct rvdns *);
#endif
