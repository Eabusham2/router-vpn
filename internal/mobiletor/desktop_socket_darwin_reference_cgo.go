//go:build darwin && cgo

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

// The pinned Apple pfioctl_ioc_tokens copies as many complete entries as fit
// and returns copied bytes, not the total required size. A full buffer is
// therefore ambiguous and must never become an absence result. One bounded
// ioctl also avoids a size-query/read race. No foreign token is returned.
static int routervpn_pf_reference(uint64_t token, int *present) {
    const size_t capacity = 1025;
    struct pfioc_tokens request;
    struct pfioc_token *tokens = NULL;
    int descriptor = -1, error = 0, matches = 0;
    *present = 0;
    if (token == 0) return EINVAL;
    tokens = calloc(capacity, sizeof(*tokens));
    if (tokens == NULL) return ENOMEM;
    descriptor = open("/dev/pf", O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) { error = errno; goto finish; }
    memset(&request, 0, sizeof(request));
    request.size = (int)(capacity * sizeof(*tokens));
    request.pgt_buf = (caddr_t)tokens;
    if (ioctl(descriptor, DIOCGETSTARTERS, &request) != 0) {
        // In the pinned kernel source ENOENT means the token list is empty.
        // Other ioctl errors are unknown state, never an absent reference.
        error = errno == ENOENT ? 0 : errno;
        goto finish;
    }
    if (request.size < 0 || (size_t)request.size >= capacity * sizeof(*tokens) ||
        (size_t)request.size % sizeof(*tokens) != 0) {
        error = EOVERFLOW;
        goto finish;
    }
    for (size_t i = 0; i < (size_t)request.size / sizeof(*tokens); i++) {
        if (tokens[i].token_value == 0) { error = EINVAL; goto finish; }
        if (tokens[i].token_value == token) matches++;
    }
    if (matches > 1) { error = EINVAL; goto finish; }
    *present = matches == 1;
finish:
    if (descriptor >= 0 && close(descriptor) != 0 && error == 0) error = errno;
    free(tokens);
    return error;
}
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"syscall"
)

func desktopDarwinPFReferenceExists(ctx context.Context, token uint64) (bool, error) {
	if ctx == nil || token == 0 {
		return false, errors.New("Darwin PF reference inspection lost its captured token")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if _, err := desktopDarwinPFCapturedABI(); err != nil {
		return false, err
	}
	var present C.int
	if code := C.routervpn_pf_reference(C.uint64_t(token), &present); code != 0 {
		return false, fmt.Errorf("inspect exact Darwin PF reference: %w", syscall.Errno(code))
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return present == 1, nil
}
