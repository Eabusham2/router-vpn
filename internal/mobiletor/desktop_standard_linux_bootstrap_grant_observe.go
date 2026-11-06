//go:build linux

package mobiletor

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"syscall"
	"time"
)

func (g *desktopLinuxBootstrapGrant) generation() uint32 {
	if g == nil || len(g.requests) != 5 {
		return 0
	}
	fields, err := desktopLinuxBootstrapAttributeMap(g.requests[0][20:], 0)
	if err != nil || len(fields[1]) != 4 {
		return 0
	}
	generation := binary.BigEndian.Uint32(fields[1]) + 1
	if generation == 0 {
		generation = 1
	}
	return generation
}

// Point reads locate the original objects but confer no authority: their
// exact handles and full kernel expressions must equal original mutation
// echoes, inside the baseline's unchanged-generation bracket.
func (n *desktopLinuxBaselineNetlink) observeBootstrapGrant(ctx context.Context, g *desktopLinuxBootstrapGrant) error {
	if n == nil || g == nil || !g.complete() || g.rejected {
		return errors.New("bootstrap readback lacks original commit")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if !g.owns(n) {
		return errors.New("bootstrap observation replaced original endpoint")
	}
	for _, index := range []int{1, 3} {
		seq, err := n.nextSequence()
		if err != nil {
			return err
		}
		kind := uint16(0x0a0a)
		attrs := bootstrapAttrs(bootstrapString(1, g.table), bootstrapString(2, g.set))
		if index == 3 {
			kind = 0x0a07
			attrs = bootstrapAttrs(bootstrapString(1, g.table), bootstrapString(2, "output"), bootstrapU64(3, g.ruleHandle))
		}
		request := desktopLinuxBaselineMessage(kind, syscall.NLM_F_REQUEST, seq, n.port, desktopLinuxNFTInet, 0, attrs)
		reply, _, err := n.exchange(ctx, request, seq)
		if err != nil || reply == nil {
			return errors.Join(err, errors.New("bootstrap object read omitted native receipt"))
		}
		if reply.Header.Type == syscall.NLMSG_ERROR {
			return errors.Join(desktopLinuxBaselineKernelError(reply, request), errors.New("original bootstrap object absent before exact retirement"))
		}
		copy := *g
		copy.committed = false
		copy.ruleHandle = 0
		copy.setHandle = 0
		copy.requests = append([][]byte(nil), g.requests...)
		copy.requests[index] = bytes.Clone(g.requests[index])
		binary.NativeEndian.PutUint32(copy.requests[index][8:12], seq)
		if err = copy.receipt(reply); err != nil {
			return err
		}
		if index == 1 && copy.setHandle != g.setHandle || index == 3 && copy.ruleHandle != g.ruleHandle {
			return errors.New("bootstrap point read found a replacement handle")
		}
	}
	return ctx.Err()
}

// nft JSON renders timer fields in whole seconds. They are permitted to
// decrease or disappear with the expired element, never used as a userspace
// timer proving kernel absence. Linux nf_tables_api.c:nf_tables_dump_setelem
// omits expired/dead elements before backend dump, independently of GC:
// https://github.com/torvalds/linux/blob/v6.12/net/netfilter/nf_tables_api.c
// nftables 1.1.1 src/json.c:set_elem_expr_json renders milliseconds / 1000.
// Native echo/readback proves the actual timeout
// and exact rule; generation bracketing rejects any userspace element update.
func (t *desktopLinuxStandardBootstrap) inventoryGrantSet(b *DesktopLinuxNodeBaseline, set map[string]any) error {
	g := t.grant
	if g == nil || !desktopLinuxProtectionKeys(set, "family", "table", "name", "handle", "type", "flags", "timeout", "elem") || set["family"] != "inet" || set["table"] != b.nft.table() || set["name"] != g.set || desktopLinuxNumber(set["handle"]) != g.setHandle || set["type"] != "mark" || !reflect.DeepEqual(set["flags"], []any{"timeout"}) {
		return errors.New("bootstrap timer set changed original object")
	}
	max := float64(g.duration / time.Second)
	if set["timeout"] != max {
		return errors.New("bootstrap set changed original finite timeout")
	}
	elements, ok := set["elem"]
	if !ok {
		return nil
	}
	list, ok := elements.([]any)
	if !ok || len(list) > 1 {
		return errors.New("bootstrap timer set acquired extra elements")
	}
	if len(list) == 0 {
		return nil
	}
	outer, ok := list[0].(map[string]any)
	if !ok || len(outer) != 1 {
		return errors.New("bootstrap timer element lost its expiry")
	}
	element, ok := outer["elem"].(map[string]any)
	if !ok || !desktopLinuxProtectionKeys(element, "val", "timeout", "expires") || desktopLinuxNumber(element["val"]) != uint64(t.mark) {
		return errors.New("bootstrap timer element changed original socket key")
	}
	for _, key := range []string{"timeout", "expires"} {
		if value, present := element[key]; present {
			seconds, ok := value.(float64)
			if !ok || seconds < 0 || seconds > max {
				return errors.New("bootstrap timer element renewed its original bound")
			}
		}
	}
	t.grantLive = true
	return nil
}
