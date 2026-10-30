/* Router VPN adapter for the explicitly pinned Apple private userland PF ABI.
 * The upstream files and their complete notices are preserved in pfabi/.
 * This is not a declaration that PF is a stable or public SDK interface. */
#ifndef ROUTERVPN_DARWIN_PFABI_H
#define ROUTERVPN_DARWIN_PFABI_H

/* Resolve public dependencies before enabling the upstream PF header's
 * PRIVATE guard. In particular, do not ask the public SDK's if_var.h to load
 * unrelated kernel/private networking interfaces. No ABI types are replaced. */
#include <stdbool.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <net/if_var.h>

#ifdef KERNEL
#error "Router VPN requires Apple's userland PF declarations"
#endif
#ifndef PRIVATE
#define ROUTERVPN_DEFINED_PRIVATE
#define PRIVATE
#endif
#include "desktop_socket_darwin_pfabi/net/pfvar.h"
#ifdef ROUTERVPN_DEFINED_PRIVATE
#undef PRIVATE
#undef ROUTERVPN_DEFINED_PRIVATE
#endif

#endif
