//go:build linux

package desktopnetwork

import (
	"context"
	"errors"
	"net"
	"syscall"
)

func interfaceContextNative(ctx context.Context, index int) (*net.Interface, []net.Addr, error) {
	return linuxInterfaceContext(ctx, index, linuxDump)
}

func linuxInterfaceContext(ctx context.Context, index int, dump func(context.Context, int, uint16) ([]syscall.NetlinkMessage, error)) (*net.Interface, []net.Addr, error) {
	readLink := func() (*net.Interface, error) {
		rows, err := dump(ctx, syscall.RTM_GETLINK, syscall.RTM_NEWLINK)
		if err != nil {
			return nil, err
		}
		var current *net.Interface
		for _, row := range rows {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			link, err := linuxLink(row.Data)
			if err != nil {
				return nil, err
			}
			if link.Index != uint32(index) {
				continue
			}
			if current != nil {
				return nil, errors.New("native interface inventory duplicated its index")
			}
			attrs, err := linuxAttributes(row.Data, 16)
			if err != nil {
				return nil, err
			}
			current = &net.Interface{Index: index, Name: link.Name, MTU: link.MTU, HardwareAddr: append(net.HardwareAddr(nil), attrs[1]...)}
			for _, flag := range []struct {
				native    uint32
				projected net.Flags
			}{
				{syscall.IFF_UP, net.FlagUp}, {syscall.IFF_RUNNING, net.FlagRunning}, {syscall.IFF_BROADCAST, net.FlagBroadcast},
				{syscall.IFF_LOOPBACK, net.FlagLoopback}, {syscall.IFF_POINTOPOINT, net.FlagPointToPoint}, {syscall.IFF_MULTICAST, net.FlagMulticast},
			} {
				if link.Flags&flag.native != 0 {
					current.Flags |= flag.projected
				}
			}
		}
		if current == nil {
			return nil, errors.New("original physical interface disappeared")
		}
		return current, ctx.Err()
	}
	current, err := readLink()
	if err != nil {
		return nil, nil, err
	}
	rows, err := dump(ctx, syscall.RTM_GETADDR, syscall.RTM_NEWADDR)
	if err != nil {
		return nil, nil, err
	}
	var addresses []net.Addr
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		address, err := linuxAddress(row.Data)
		if err != nil {
			return nil, nil, err
		}
		if address.Index != uint32(index) {
			continue
		}
		ip, prefix, err := net.ParseCIDR(address.Prefix)
		if err != nil {
			return nil, nil, err
		}
		prefix.IP = ip // Retain the host address, not the masked network prefix.
		addresses = append(addresses, prefix)
	}
	after, err := readLink()
	if err != nil {
		return nil, nil, err
	}
	if !sameInterface(current, after) {
		return nil, nil, errors.New("interface changed while reading its addresses")
	}
	return current, addresses, ctx.Err()
}
