//go:build darwin && cgo && routervpn_darwin_guardian

package mobiletor

/*
#cgo CFLAGS: -I${SRCDIR}/desktop_socket_darwin_pfabi
#include <errno.h>
#include <fcntl.h>
#include "desktop_socket_darwin_pfabi.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

// The native guardian test uses the pinned Apple private userland PF ABI.
// Source identity, license and version bounds are in pfabi/UPSTREAM.json.
// A single-queue transaction avoids pfctl loaders which can include additional
// rulesets. This probe never flushes PF or changes an unselected ruleset.
static int routervpn_darwin_pf_queue_probe(const char *anchor,
    const unsigned char address[4], int rs_num, int operation, int *stage, int *rollback) {
    struct pfioc_trans_e element;
    struct pfioc_trans transaction;
    struct pfioc_pooladdr pool;
    struct pfioc_rule request;
    int error = 0, begun = 0;
    *stage = 1;
    *rollback = 0;
    int descriptor = open("/dev/pf", O_RDWR | O_CLOEXEC);
    if (descriptor < 0) return errno;
    memset(&element, 0, sizeof(element));
    memset(&transaction, 0, sizeof(transaction));
    element.rs_num = rs_num;
    strlcpy(element.anchor, anchor, sizeof(element.anchor));
    transaction.size = 1;
    transaction.esize = sizeof(element);
    transaction.array = &element;
    *stage = 2;
    if (ioctl(descriptor, DIOCXBEGIN, &transaction) != 0) {
        error = errno;
        goto finish;
    }
    begun = 1;
    if (operation != 0) {
        memset(&pool, 0, sizeof(pool));
        *stage = 3;
        if (ioctl(descriptor, DIOCBEGINADDRS, &pool) != 0) {
            error = errno;
            goto finish;
        }
        memset(&request, 0, sizeof(request));
        strlcpy(request.anchor, anchor, sizeof(request.anchor));
        request.ticket = element.ticket;
        request.pool_ticket = pool.ticket;
        request.rule.action = PF_DROP;
        request.rule.direction = PF_OUT;
        request.rule.af = AF_INET;
        request.rule.src.addr.type = PF_ADDR_ADDRMASK;
        request.rule.dst.addr.type = PF_ADDR_ADDRMASK;
        memcpy(&request.rule.dst.addr.v.a.addr.v4addr, address, 4);
        memset(&request.rule.dst.addr.v.a.mask.v4addr, 0xff, 4);
        strlcpy(request.rule.ifname, "lo0", sizeof(request.rule.ifname));
        strlcpy(request.rule.label, "rvpn-filter-only-probe", sizeof(request.rule.label));
        if (rs_num == PF_RULESET_NAT || rs_num == PF_RULESET_RDR) {
            unsigned char source[4] = {address[0], address[1], address[2], 10};
            request.rule.action = rs_num == PF_RULESET_NAT ? PF_NAT : PF_RDR;
            request.rule.direction = rs_num == PF_RULESET_NAT ? PF_OUT : PF_IN;
            request.rule.proto = IPPROTO_UDP;
            request.rule.rpool.af = AF_INET;
            memcpy(&request.rule.src.addr.v.a.addr.v4addr, source, 4);
            memset(&request.rule.src.addr.v.a.mask.v4addr, 0xff, 4);
            request.rule.dst.xport.range.op = PF_OP_EQ;
            request.rule.dst.xport.range.port[0] = request.rule.dst.xport.range.port[1] = htons(49301);
            strlcpy(request.rule.label, "rvpn-translation-probe", sizeof(request.rule.label));
            pool.af = AF_INET;
            pool.addr.addr.type = PF_ADDR_ADDRMASK;
            memcpy(&pool.addr.addr.v.a.addr.v4addr, rs_num == PF_RULESET_NAT ? address : source, 4);
            memset(&pool.addr.addr.v.a.mask.v4addr, 0xff, 4);
            if (ioctl(descriptor, DIOCADDADDR, &pool) != 0) {
                error = errno;
                goto finish;
            }
        }
        *stage = 4;
        if (ioctl(descriptor, DIOCADDRULE, &request) != 0) {
            error = errno;
            goto finish;
        }
    }
    *stage = operation == 2 ? 5 : 6;
    if (ioctl(descriptor, operation == 2 ? DIOCXROLLBACK : DIOCXCOMMIT,
              &transaction) != 0) {
        error = errno;
        goto finish;
    }
    begun = 0;
finish:
    if (begun && ioctl(descriptor, DIOCXROLLBACK, &transaction) != 0)
        *rollback = errno;
    if (close(descriptor) != 0 && error == 0) {
        *stage = 7;
        error = errno;
    }
    return error;
}
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"syscall"
	"unsafe"
)

var desktopDarwinPFProbeAnchor = regexp.MustCompile(`^com\.apple/zzz\.t-[a-f0-9]{12}$`)

// This function exists only in the explicitly tagged native guardian fixture.
// Neither shipping arguments nor graph data can select its test namespace.
func desktopDarwinPFProbeTransaction(ctx context.Context, anchor string, address netip.Addr, operation int) error {
	return desktopDarwinPFProbeQueue(ctx, anchor, address, "filter", operation)
}

func desktopDarwinPFProbeQueue(ctx context.Context, anchor string, address netip.Addr, kind string, operation int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := desktopDarwinPFCapturedABI(); err != nil {
		return err
	}
	if !desktopDarwinPFProbeAnchor.MatchString(anchor) || !address.Is4() || operation < 0 || operation > 2 {
		return errors.New("Darwin PF probe requires its bounded fixture capture")
	}
	octets := address.As4()
	if octets[0] != 127 || octets[1] != 78 || octets[3] != 11 {
		return errors.New("Darwin PF probe cannot select an address outside its new loopback fixture")
	}
	var ruleset C.int
	switch kind {
	case "filter":
		ruleset = C.PF_RULESET_FILTER
	case "nat":
		ruleset = C.PF_RULESET_NAT
	case "rdr":
		ruleset = C.PF_RULESET_RDR
	default:
		return errors.New("Darwin fixture probe requires a single selected queue")
	}
	path := C.CString(anchor)
	defer C.free(unsafe.Pointer(path))
	var stage, rollback C.int
	code := C.routervpn_darwin_pf_queue_probe(path, (*C.uchar)(unsafe.Pointer(&octets[0])), ruleset, C.int(operation), &stage, &rollback)
	if code != 0 {
		return fmt.Errorf("Darwin fixture %s transaction stage %d: %w (owned rollback errno %d)", kind, int(stage), syscall.Errno(code), int(rollback))
	}
	return ctx.Err()
}
