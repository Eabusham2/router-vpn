//go:build darwin && cgo

package mobiletor

/*
#cgo CFLAGS: -I${SRCDIR}/desktop_socket_darwin_pfabi
#include <errno.h>
#include <fcntl.h>
#include "desktop_socket_darwin_pfabi.h"
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

// This small input type is ours, not a guessed copy of a kernel ABI. Native
// pf_rule/pfioc_trans layouts and ioctl numbers come from the unmodified pinned
// Apple private userland header. The kernel/build gate precedes any ioctl.
struct routervpn_pf_filter_input {
    uint8_t action, direction, quick, family, protocol;
    uint8_t has_uid, keep_state, flags_any, floating, match_not;
    uint32_t uid;
    uint16_t source_port, destination_port;
    unsigned char source[16], source_mask[16], destination[16], destination_mask[16];
    char interface_name[16], tag[64], match_tag[64], label[64], anchor_call[64];
};

_Static_assert(IFNAMSIZ >= 16, "native PF interface field became smaller");
_Static_assert(PF_TAG_NAME_SIZE >= 64, "native PF tag field became smaller");
_Static_assert(PF_RULE_LABEL_SIZE >= 64, "native PF label field became smaller");

static int routervpn_pf_filter_rule(struct pfioc_rule *request,
    const struct routervpn_pf_filter_input *input) {
    if (input->action < 1 || input->action > 3 ||
        (input->direction != 1 && input->direction != 2) || input->quick > 1 ||
        (input->family != 0 && input->family != 4 && input->family != 6) ||
        (input->protocol != 0 && input->protocol != IPPROTO_TCP &&
         input->protocol != IPPROTO_UDP && input->protocol != IPPROTO_ICMPV6) ||
        input->has_uid > 1 || input->keep_state > 1 || input->flags_any > 1 ||
        input->floating > input->keep_state || input->match_not > 1)
        return EINVAL;
    struct pf_rule *rule = &request->rule;
    rule->action = input->action == 2 ? PF_DROP : PF_PASS;
    rule->direction = input->direction == 1 ? PF_IN : PF_OUT;
    rule->quick = input->quick;
    rule->af = input->family == 4 ? AF_INET : input->family == 6 ? AF_INET6 : 0;
    rule->proto = input->protocol;
    rule->src.addr.type = PF_ADDR_ADDRMASK;
    rule->dst.addr.type = PF_ADDR_ADDRMASK;
    memcpy(&rule->src.addr.v.a.addr, input->source, sizeof(input->source));
    memcpy(&rule->src.addr.v.a.mask, input->source_mask, sizeof(input->source_mask));
    memcpy(&rule->dst.addr.v.a.addr, input->destination, sizeof(input->destination));
    memcpy(&rule->dst.addr.v.a.mask, input->destination_mask, sizeof(input->destination_mask));
    if (input->source_port != 0) {
        rule->src.xport.range.port[0] = rule->src.xport.range.port[1] = htons(input->source_port);
        rule->src.xport.range.op = PF_OP_EQ;
    }
    if (input->destination_port != 0) {
        rule->dst.xport.range.port[0] = rule->dst.xport.range.port[1] = htons(input->destination_port);
        rule->dst.xport.range.op = PF_OP_EQ;
    }
    if (input->has_uid) {
        rule->uid.op = PF_OP_EQ;
        rule->uid.uid[0] = rule->uid.uid[1] = input->uid;
    }
    rule->keep_state = input->keep_state ? PF_STATE_NORMAL : 0;
    // This matches PF's explicit stateful default. The owned production
    // filters always say no state; the stateful form is used by the existing
    // native foreign-policy and floating-state rejection fixtures.
    if (input->keep_state && !input->flags_any &&
        (input->protocol == 0 || input->protocol == IPPROTO_TCP)) {
        rule->flags = TH_SYN;
        rule->flagset = TH_SYN | TH_ACK;
    }
    rule->match_tag_not = input->match_not;
    strlcpy(rule->ifname, input->interface_name, sizeof(rule->ifname));
    strlcpy(rule->tagname, input->tag, sizeof(rule->tagname));
    strlcpy(rule->match_tagname, input->match_tag, sizeof(rule->match_tagname));
    strlcpy(rule->label, input->label, sizeof(rule->label));
    if (input->action == 3)
        strlcpy(request->anchor_call, input->anchor_call, sizeof(request->anchor_call));
    return 0;
}

static int routervpn_pf_replace_filters(const char *anchor,
    const struct routervpn_pf_filter_input *rules, size_t count,
    int *stage, size_t *failed_rule, int *rollback) {
    struct pfioc_trans_e element;
    struct pfioc_trans transaction;
    struct pfioc_pooladdr pool;
    struct pfioc_rule request;
    int error = 0, begun = 0;
    *stage = 1;
    *failed_rule = 0;
    *rollback = 0;
    if (count > 1024 || (count != 0 && rules == NULL)) return EINVAL;
    int descriptor = open("/dev/pf", O_RDWR | O_CLOEXEC);
    if (descriptor < 0) return errno;
    memset(&element, 0, sizeof(element));
    memset(&transaction, 0, sizeof(transaction));
    element.rs_num = PF_RULESET_FILTER;
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
    for (size_t index = 0; index < count; index++) {
        *failed_rule = index;
        *stage = 3;
        memset(&request, 0, sizeof(request));
        error = routervpn_pf_filter_rule(&request, &rules[index]);
        if (error != 0) goto finish;
        strlcpy(request.anchor, anchor, sizeof(request.anchor));
        request.ticket = element.ticket;
        memset(&pool, 0, sizeof(pool));
        *stage = 4;
        if (ioctl(descriptor, DIOCBEGINADDRS, &pool) != 0) {
            error = errno;
            goto finish;
        }
        request.pool_ticket = pool.ticket;
        *stage = 5;
        if (ioctl(descriptor, DIOCADDRULE, &request) != 0) {
            error = errno;
            goto finish;
        }
    }
    *stage = 6;
    if (ioctl(descriptor, DIOCXCOMMIT, &transaction) != 0) {
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
	"strings"
	"syscall"
	"unsafe"
)

// Only the guardian's compiled filter records cross this adapter. It changes
// one owned anchor's FILTER queue and uses that exact transaction ticket for
// rollback. Tables, normalization, translation and other anchors are untouched.
func desktopDarwinPFNativeReplace(ctx context.Context, anchor string, rules []desktopPFFilterRule) error {
	if ctx == nil || !desktopPFInventoryPath(anchor) || len(anchor) > desktopDarwinPFAnchorPathLimit || strings.HasPrefix(anchor, "/") || len(rules) > desktopPFFilterLimit {
		return errors.New("Darwin native filter replacement lost its bounded capture")
	}
	owner := desktopDarwinPFNamespace
	// The separately compiled guardian fixture captures two fresh namespaces.
	// Shipping code never assigns a test scope or an alternate namespace.
	if desktopDarwinPFTestScope != "" && strings.HasPrefix(desktopDarwinPFNamespace, "com.apple/000.t-") {
		fixture := strings.Replace(desktopDarwinPFNamespace, "/000.t-", "/zzz.t-", 1)
		if anchor == fixture {
			owner = fixture
		}
	}
	if anchor != owner && !strings.HasPrefix(anchor, owner+"/") {
		return errors.New("Darwin native filter replacement cannot select another anchor owner")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := desktopDarwinPFCapturedABI(); err != nil {
		return err
	}
	var storage unsafe.Pointer
	if len(rules) != 0 {
		storage = C.calloc(C.size_t(len(rules)), C.size_t(C.sizeof_struct_routervpn_pf_filter_input))
		if storage == nil {
			return syscall.ENOMEM
		}
		defer C.free(storage)
	}
	native := unsafe.Slice((*C.struct_routervpn_pf_filter_input)(storage), len(rules))
	for index, rule := range rules {
		input, err := desktopPFNativeProject(rule)
		if err != nil {
			return err
		}
		if input.Action == 3 && !desktopPFNativeDispatch(anchor, owner, input.Anchor) {
			return errors.New("Darwin native filter dispatch cannot reference another anchor owner")
		}
		value := &native[index]
		value.action, value.direction = C.uint8_t(input.Action), C.uint8_t(input.Direction)
		value.quick, value.family, value.protocol = C.uint8_t(input.Quick), C.uint8_t(input.Family), C.uint8_t(input.Protocol)
		value.has_uid, value.uid = C.uint8_t(input.User), C.uint32_t(input.UID)
		value.source_port, value.destination_port = C.uint16_t(input.SourcePort), C.uint16_t(input.DestinationPort)
		value.keep_state, value.flags_any, value.floating = C.uint8_t(input.KeepState), C.uint8_t(input.FlagsAny), C.uint8_t(input.Floating)
		value.match_not = C.uint8_t(input.MatchTagNot)
		copyField := func(first *C.char, size int, text string) error {
			if len(text) >= size || strings.IndexByte(text, 0) >= 0 {
				return errors.New("Darwin native filter field exceeds its pinned private ABI projection")
			}
			copy(unsafe.Slice((*byte)(unsafe.Pointer(first)), size), text)
			return nil
		}
		if err := errors.Join(
			copyField(&value.interface_name[0], len(value.interface_name), input.Interface),
			copyField(&value.tag[0], len(value.tag), input.Tag),
			copyField(&value.match_tag[0], len(value.match_tag), input.MatchTag),
			copyField(&value.label[0], len(value.label), input.Label),
			copyField(&value.anchor_call[0], len(value.anchor_call), input.Anchor)); err != nil {
			return err
		}
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&value.source[0])), len(value.source)), input.Source[:])
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&value.source_mask[0])), len(value.source_mask)), input.SourceMask[:])
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&value.destination[0])), len(value.destination)), input.Destination[:])
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&value.destination_mask[0])), len(value.destination_mask)), input.DestinationMask[:])
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	path := C.CString(anchor)
	defer C.free(unsafe.Pointer(path))
	var stage, rollback C.int
	var failedRule C.size_t
	code := C.routervpn_pf_replace_filters(path, (*C.struct_routervpn_pf_filter_input)(storage), C.size_t(len(rules)), &stage, &failedRule, &rollback)
	if code != 0 {
		return errors.Join(ctx.Err(), fmt.Errorf("Darwin native filter transaction stage %d rule %d: %w (owned rollback errno %d)", int(stage), int(failedRule), syscall.Errno(code), int(rollback)))
	}
	return ctx.Err()
}
