package desktopnetwork

import (
	"fmt"
	"net"
)

// This is the copied read-only IP Helper row identity, not an authority to
// configure an interface. Kept platform independent to execute shape controls
// on every build host; only the Windows table reader supplies native rows.
type desktopWindowsIPInterfaceShape struct {
	Family uint16
	Index  uint32
	LUID   uint64
	MTU    uint32
}

func desktopWindowsLinkMTU(link Link, rows []desktopWindowsIPInterfaceShape) (Link, error) {
	if link.MTU > 0 {
		return link, nil
	}
	bad := func() (Link, error) {
		shape := "bounded-count-only"
		if len(rows) <= 2 {
			shape = fmt.Sprint(rows)
		}
		return Link{}, fmt.Errorf("Windows interface MTU shape is not corroborated (index=%d luid=%d mtu=%d flags=%d rows=%d native_family_index_luid_mtu=%s)", link.Index, link.LUID, link.MTU, link.Flags, len(rows), shape)
	}
	// Go's net.Interfaces deliberately maps the native DWORD 0xffffffff to
	// -1. Keep that exact large loopback value in the physical inventory only
	// when each same-identity IP Helper family row independently confirms it.
	// A native VPN receipt still enforces its ordinary bounded MTU contract.
	if link.MTU != -1 || link.Index == 0 || link.LUID == 0 || link.Flags&uint32(net.FlagLoopback) == 0 || len(rows) == 0 || len(rows) > 2 {
		return bad()
	}
	seen := make(map[uint16]bool)
	for _, row := range rows {
		if row.Index != link.Index || row.LUID != link.LUID || row.Family != 2 && row.Family != 23 ||
			seen[row.Family] || row.MTU != ^uint32(0) {
			return bad()
		}
		seen[row.Family] = true
	}
	link.MTU = int(uint64(^uint32(0)))
	if link.MTU <= 0 {
		return bad()
	}
	return link, nil
}
