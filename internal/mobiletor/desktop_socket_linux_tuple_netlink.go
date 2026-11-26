//go:build linux

package mobiletor

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"syscall"
)

const desktopLinuxNFTDeleteSetElement = 0x0a0e

func (n *desktopLinuxNFT) tupleRows(ctx context.Context) ([]map[string]any, uint32, error) {
	rows, generation, err := n.observedRows(ctx)
	if err == nil {
		err = n.verifyRows(rows, true)
	}
	return rows, generation, err
}

func (n *desktopLinuxNFT) observedRows(ctx context.Context) ([]map[string]any, uint32, error) {
	before, err := n.tupleNetlink.generation(ctx)
	if err != nil {
		return nil, 0, err
	}
	rows, err := desktopLinuxNFTReadTable(ctx, n.table())
	if err != nil {
		return nil, 0, err
	}
	after, err := n.tupleNetlink.generation(ctx)
	if err != nil || before != after {
		return nil, 0, errors.Join(err, errors.New("Linux socket policy changed during its original kernel observation"))
	}
	return rows, before, nil
}

func (n *desktopLinuxNFT) observeElement(ctx context.Context, g DesktopSocketGrant) (map[string]any, bool, uint32, error) {
	rows, gen, err := n.tupleRows(ctx)
	if err != nil {
		return nil, false, 0, err
	}
	element, found, err := n.findElement(rows, g)
	return element, found, gen, err
}

// nft concatenations pad each field to a 32-bit register. The physical
// interface index is host-endian; packet addresses and ports are network-endian.
func desktopLinuxTupleKey(g DesktopSocketGrant) []byte {
	key := bootstrapNative32(g.Binding.InterfaceIndex)
	for _, endpoint := range [2]netip.AddrPort{g.Local, g.Remote} {
		key = append(key, endpoint.Addr().AsSlice()...)
		key = binary.BigEndian.AppendUint16(key, endpoint.Port())
		key = append(key, 0, 0)
	}
	return key
}

func (n *desktopLinuxNFT) mutateElement(ctx context.Context, g DesktopSocketGrant, generation uint32, remove bool, seconds int64, comment string) error {
	link := n.tupleNetlink
	if link == nil || generation == 0 || !remove && seconds == 0 || seconds < 0 || seconds > 9 || seconds > 0 && (len(comment) == 0 || len(comment) > 180) {
		return errors.New("Linux physical mutation lost its original tuple or bounded lease")
	}
	link.mu.Lock()
	defer link.mu.Unlock()
	if link.seq > ^uint32(0)-8 {
		return errors.New("Linux physical tuple exhausted its original kernel sequence")
	}
	seq := link.seq + 1
	link.seq += 4
	set := n.Prefix + "_" + n.kind(g)
	key := desktopLinuxTupleKey(g)
	requests := [][]byte{desktopLinuxBaselineMessage(desktopLinuxNFTBatchBegin, syscall.NLM_F_REQUEST, seq, link.port, 0, desktopLinuxNFTSubsystem, bootstrapU32(1, generation))}
	appendElement := func(kind, flags uint16, values ...[]byte) {
		// The first command owns the kernel's commit NEWGEN.
		if len(requests) == 1 {
			flags |= syscall.NLM_F_ECHO
		}
		fields := append([][]byte{bootstrapNest(1, bootstrapAttr(1, key))}, values...)
		attrs := bootstrapAttrs(bootstrapString(1, n.table()), bootstrapString(2, set), bootstrapNest(3, bootstrapNest(1, fields...)))
		requests = append(requests, desktopLinuxBaselineMessage(kind, syscall.NLM_F_REQUEST|flags, seq+uint32(len(requests)), link.port, desktopLinuxNFTInet, 0, attrs))
	}
	if remove {
		appendElement(desktopLinuxNFTDeleteSetElement, 0)
	}
	if seconds > 0 {
		userdata := append([]byte{0, byte(len(comment) + 1)}, []byte(comment)...)
		appendElement(desktopLinuxNFTNewSetElement, syscall.NLM_F_EXCL|syscall.NLM_F_CREATE, bootstrapU64(4, uint64(seconds)*1000), bootstrapAttr(6, append(userdata, 0)))
	}
	requests = append(requests, desktopLinuxBaselineMessage(desktopLinuxNFTBatchEnd, syscall.NLM_F_REQUEST, seq+uint32(len(requests)), link.port, 0, desktopLinuxNFTSubsystem, nil))
	return link.commitSocketPolicy(ctx, generation, requests, func(m *syscall.NetlinkMessage) error {
		bad := errors.New("Linux physical mutation lost its original kernel element notification")
		// nf_tables_setelem_notify emits an element with sequence zero
		// and copies only CREATE/EXCL. The following NEWGEN independently
		// binds this observed exact key to the original request sequence.
		wantFlags := binary.NativeEndian.Uint16(requests[1][6:8]) & (syscall.NLM_F_EXCL | syscall.NLM_F_CREATE)
		if m.Header.Seq != 0 || m.Header.Flags != wantFlags || m.Header.Type != binary.NativeEndian.Uint16(requests[1][4:6]) || m.Data[0] != desktopLinuxNFTInet {
			return bad
		}
		fields, err := desktopLinuxBootstrapAttributeMap(m.Data[4:], 0)
		if err != nil || !bytes.Equal(fields[1], append([]byte(n.table()), 0)) || !bytes.Equal(fields[2], append([]byte(set), 0)) {
			return bad
		}
		list, err := desktopLinuxBootstrapAttributes(fields[3])
		if err != nil || len(list) != 1 || list[0].kind != 1 {
			return bad
		}
		element, err := desktopLinuxBootstrapAttributeMap(list[0].value, 8) // NFTA_SET_ELEM_PAD
		if err != nil {
			return bad
		}
		value, err := desktopLinuxBootstrapAttributeMap(element[1], 0)
		if err != nil || len(value) != 1 || !bytes.Equal(value[1], key) {
			return bad
		}
		return nil
	})
}

// Retire only the handles in the checked inventory, in one generation-bound
// transaction. The first object's unicast echo and NEWGEN witness commit.
func (n *desktopLinuxNFT) retireChildren(ctx context.Context, generation uint32, children []desktopLinuxNFTChild) error {
	link := n.tupleNetlink
	if link == nil || generation == 0 || len(children) == 0 || len(children) > 9 {
		return errors.New("Linux socket cleanup lost its original endpoint or bounded inventory")
	}
	link.mu.Lock()
	defer link.mu.Unlock()
	count := uint32(len(children) + 2)
	if link.seq > ^uint32(0)-count {
		return errors.New("Linux socket cleanup exhausted its original kernel sequence")
	}
	seq := link.seq + 1
	link.seq += count
	requests := [][]byte{desktopLinuxBaselineMessage(desktopLinuxNFTBatchBegin, syscall.NLM_F_REQUEST, seq, link.port, 0, desktopLinuxNFTSubsystem, bootstrapU32(1, generation))}
	for i, child := range children {
		if child.handle == 0 || child.handle > 1<<53-1 {
			return errors.New("Linux socket cleanup lost an original child handle")
		}
		attributes := bootstrapString(1, n.table())
		switch child.kind {
		case desktopLinuxNFTDeleteRule:
			attributes = append(attributes, bootstrapAttrs(bootstrapString(2, "output"), bootstrapU64(3, child.handle))...)
		case desktopLinuxNFTDeleteSet:
			attributes = append(attributes, bootstrapU64(16, child.handle)...)
		default:
			return errors.New("Linux socket cleanup encountered an unknown original object")
		}
		flags := uint16(syscall.NLM_F_REQUEST)
		if i == 0 {
			flags |= syscall.NLM_F_ECHO
		}
		requests = append(requests, desktopLinuxBaselineMessage(child.kind, flags, seq+uint32(i)+1, link.port, desktopLinuxNFTInet, 0, attributes))
	}
	requests = append(requests, desktopLinuxBaselineMessage(desktopLinuxNFTBatchEnd, syscall.NLM_F_REQUEST, link.seq, link.port, 0, desktopLinuxNFTSubsystem, nil))
	first := children[0]
	return link.commitSocketPolicy(ctx, generation, requests, func(m *syscall.NetlinkMessage) error {
		bad := errors.New("Linux socket cleanup lost the original child retirement receipt")
		if m.Header.Seq != seq+1 || m.Header.Flags != 0 || m.Header.Type != first.kind || m.Data[0] != desktopLinuxNFTInet {
			return bad
		}
		pad, handle := uint16(8), uint16(3) // NFTA_RULE_PAD, NFTA_RULE_HANDLE
		if first.kind == desktopLinuxNFTDeleteSet {
			pad, handle = 14, 16 // NFTA_SET_PAD, NFTA_SET_HANDLE
		}
		fields, err := desktopLinuxBootstrapAttributeMap(m.Data[4:], pad)
		if err != nil || string(fields[1]) != n.table()+"\x00" || string(fields[2]) != first.name+"\x00" || len(fields[handle]) != 8 || binary.BigEndian.Uint64(fields[handle]) != first.handle {
			return bad
		}
		return nil
	})
}

// The caller holds the endpoint lock. Only the first object requests an echo.
// A negative is definitive only before that echo and for an original request.
func (link *desktopLinuxBaselineNetlink) commitSocketPolicy(ctx context.Context, generation uint32, requests [][]byte, checkFirst func(*syscall.NetlinkMessage) error) error {
	seq := binary.NativeEndian.Uint32(requests[0][8:12])
	seen, committed := false, false
	_, err := link.exchangeUntil(ctx, bytes.Join(requests, nil), func(data []byte, source syscall.Sockaddr, flags int) (bool, error) {
		kernel, ok := source.(*syscall.SockaddrNetlink)
		if ok && kernel.Groups == 0 {
			if len(data) < syscall.NLMSG_HDRLEN {
				return false, errors.New("Linux socket policy received a truncated kernel acknowledgement")
			}
			ack := binary.NativeEndian.Uint32(data[8:12])
			if ack < seq || ack-seq >= uint32(len(requests)) {
				return false, errors.New("Linux socket policy received an unrelated kernel acknowledgement")
			}
			reply, err := desktopLinuxBaselineReply(data, source, flags, link.port, ack)
			if err != nil {
				return false, err
			}
			err = desktopLinuxBaselineKernelError(reply, requests[ack-seq])
			var rejection syscall.Errno
			if !seen && errors.As(err, &rejection) {
				return true, err
			}
			return false, errors.New("Linux socket policy received a contradictory kernel acknowledgement")
		}
		return desktopLinuxCommitDatagram(data, source, flags, link.port, seq+1, desktopLinuxNextGeneration(generation), &committed, func(m *syscall.NetlinkMessage) error {
			if m.Header.Type == desktopLinuxNFTNewGeneration && seen {
				return nil
			}
			if m.Header.Type == desktopLinuxNFTNewGeneration || seen {
				return errors.New("Linux socket policy lost its ordered kernel commit receipt")
			}
			if err := checkFirst(m); err != nil {
				return err
			}
			seen = true
			return nil
		})
	})
	return err
}
