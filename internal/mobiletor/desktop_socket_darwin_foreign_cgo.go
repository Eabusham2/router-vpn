//go:build darwin && cgo

package mobiletor

/*
#cgo CFLAGS: -I${SRCDIR}/desktop_socket_darwin_pfabi
#include <errno.h>
#include <fcntl.h>
#include "desktop_socket_darwin_pfabi.h"
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

// XNU DIOCGETRULES returns the active queue's count and ticket for the
// action selector. An anchor call is itself a rule. A wildcard query also
// requires an empty child inventory, including unreferenced child anchors.
// A nonempty or changed queue always goes to the independent pfctl reader.
static int routervpn_pf_empty_foreign(const char *anchor, int recursive,
    int translations, int *empty) {
    const u_int8_t filters[] = {PF_SCRUB, PF_PASS, PF_DUMMYNET};
    const u_int8_t nat[] = {PF_NAT, PF_BINAT, PF_RDR};
    const u_int8_t *actions = translations ? nat : filters;
    u_int32_t tickets[3];
    int fd, error = 0;
    *empty = 0;
    fd = open("/dev/pf", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return errno;
    for (int pass = 0; pass < 2; pass++) {
        for (int i = 0; i < 3; i++) {
            struct pfioc_rule queue = {0};
            if (strlcpy(queue.anchor, anchor, sizeof(queue.anchor)) >= sizeof(queue.anchor)) {
                error = ENAMETOOLONG;
                goto finish;
            }
            queue.rule.action = actions[i];
            if (ioctl(fd, DIOCGETRULES, &queue) != 0) {
                error = errno;
                goto finish;
            }
            if (queue.nr != 0 || (pass && queue.ticket != tickets[i])) goto finish;
            tickets[i] = queue.ticket;
        }
        if (recursive) {
            struct pfioc_ruleset children = {0};
            if (strlcpy(children.path, anchor, sizeof(children.path)) >= sizeof(children.path)) {
                error = ENAMETOOLONG;
                goto finish;
            }
            if (ioctl(fd, DIOCGETRULESETS, &children) != 0) {
                error = errno;
                goto finish;
            }
            if (children.nr != 0) goto finish;
        }
    }
    *empty = 1;
finish:
    if (close(fd) != 0 && !error) error = errno;
    return error;
}
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

func desktopDarwinPFEmptyForeign(ctx context.Context, anchor string, translations bool) (bool, error) {
	path := strings.TrimSuffix(anchor, "/*")
	if ctx == nil || !desktopPFInventoryPath(path) {
		return false, errors.New("Darwin foreign PF query requires its original named anchor")
	}
	release, err := desktopPFEnterCommand(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	if _, err := desktopDarwinPFCapturedABI(); err != nil {
		return false, err
	}
	name := C.CString(path)
	defer C.free(unsafe.Pointer(name))
	var recursive, nat, empty C.int
	if path != anchor {
		recursive = 1
	}
	if translations {
		nat = 1
	}
	code := C.routervpn_pf_empty_foreign(name, recursive, nat, &empty)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if syscall.Errno(code) == syscall.EINVAL {
		// Missing ruleset or unsupported selector. Only the full reader may
		// classify this path. EINVAL is never a native proof of emptiness.
		return false, nil
	}
	if code != 0 {
		return false, fmt.Errorf("read Darwin foreign PF queue: %w", syscall.Errno(code))
	}
	return empty == 1, nil
}
