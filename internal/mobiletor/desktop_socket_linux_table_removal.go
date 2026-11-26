//go:build linux

package mobiletor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"syscall"
)

// nf_tables_commit emits the original DELTABLE and NEWGEN notifications only
// after validation, publication of the next generation, and removal of the
// table. The requesting socket has no multicast subscriptions. Its NLM_F_ECHO
// replies carry NFNLGRP_NFTABLES even when unicast to its original port.
// This works on kernels which do not acknowledge NFNL_MSG_BATCH_END.
type desktopLinuxTableRemoval struct {
	table                            string
	handle                           uint64
	next                             uint32
	objectSeen, tableSeen, committed bool
}

func (p *desktopLinuxTableRemoval) receive(data []byte, source syscall.Sockaddr, flags int, port, sequence uint32) (bool, error) {
	return desktopLinuxCommitDatagram(data, source, flags, port, sequence, p.next, &p.committed, func(m *syscall.NetlinkMessage) error {
		bad := errors.New("Linux baseline deletion lost its original table notification")
		if m.Header.Seq != sequence || m.Header.Flags != 0 {
			return bad
		}
		if m.Header.Type == desktopLinuxNFTNewGeneration {
			if !p.tableSeen {
				return bad
			}
			return nil
		}
		if p.tableSeen || m.Data[0] != desktopLinuxNFTInet {
			return bad
		}
		// Deleting the complete closed table can first echo its contained
		// rule, anonymous set and output-chain removals in the same datagram.
		switch m.Header.Type {
		case desktopLinuxNFTDeleteTable, desktopLinuxNFTDeleteRule, desktopLinuxNFTDeleteSet, 0x0a05:
		default:
			return bad
		}
		attrs, err := desktopLinuxBootstrapAttributes(m.Data[4:])
		if err != nil {
			return bad
		}
		name, handle := false, false
		for _, a := range attrs {
			if a.kind == 1 {
				if name || !bytes.Equal(a.value, append([]byte(p.table), 0)) {
					return bad
				}
				name = true
			}
			if a.kind == 4 && m.Header.Type == desktopLinuxNFTDeleteTable {
				if handle || len(a.value) != 8 || binary.BigEndian.Uint64(a.value) != p.handle {
					return bad
				}
				handle = true
			}
		}
		if !name || m.Header.Type == desktopLinuxNFTDeleteTable && !handle {
			return bad
		}
		p.objectSeen = true
		p.tableSeen = m.Header.Type == desktopLinuxNFTDeleteTable
		return nil
	})
}

// The private netlink socket has zero multicast subscriptions. Linux reports
// its requested unicast commit notifications with NFNLGRP_NFTABLES as source.
func desktopLinuxCommitDatagram(data []byte, source syscall.Sockaddr, flags int, port, sequence, next uint32, committed *bool, accept func(*syscall.NetlinkMessage) error) (bool, error) {
	bad := errors.New("Linux nftables mutation lost its exact kernel commit notification")
	kernel, ok := source.(*syscall.SockaddrNetlink)
	const nftablesGroup = 1 << (7 - 1)
	if !ok || kernel.Family != syscall.AF_NETLINK || kernel.Pid != 0 || kernel.Groups != nftablesGroup || flags != 0 || len(data) == 0 {
		return false, bad
	}
	for len(data) > 0 {
		if len(data) < syscall.NLMSG_HDRLEN {
			return false, bad
		}
		length := int(binary.NativeEndian.Uint32(data))
		if length < syscall.NLMSG_HDRLEN+4 || length > len(data) {
			return false, bad
		}
		aligned := (length + 3) &^ 3
		if aligned > len(data) || !bytes.Equal(data[length:aligned], make([]byte, aligned-length)) {
			return false, bad
		}
		messages, err := syscall.ParseNetlinkMessage(data[:aligned])
		if err != nil || len(messages) != 1 {
			return false, bad
		}
		m := &messages[0]
		if *committed || m.Header.Pid != port || m.Data[1] != 0 || binary.BigEndian.Uint16(m.Data[2:4]) != uint16(next) {
			return false, bad
		}
		data = data[aligned:]
		if err = accept(m); err != nil {
			return false, err
		}
		if m.Header.Type == desktopLinuxNFTNewGeneration {
			generation, err := desktopLinuxBaselineGeneration(m)
			if err != nil || generation != next || m.Header.Seq != sequence || m.Header.Flags != 0 || len(data) != 0 {
				return false, bad
			}
			*committed = true
			return true, nil
		}
	}
	return false, nil
}
