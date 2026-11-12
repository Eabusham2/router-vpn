package mobilemultihop

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"router-vpn/internal/mobilemtu"
)

// Native acquisition is intentionally Linux-only. It sends only kernel route
// queries, never test traffic or credentials to the captured remote endpoint.
// The route MTU is a kernel bound; neither it nor interface MTU proves PMTU.
func NewNodeChainServerCarrierContext(ctx, lifetime context.Context, source string) (*NodeChainServerCarrier, error) {
	if ctx == nil || ctx.Err() != nil || lifetime == nil || lifetime.Err() != nil {
		return nil, nodeChainServerCarrierError
	}
	policy, err := NewNodeChainServerPolicy(source)
	if err != nil {
		return nil, err
	}
	target, err := nodeChainServerCarrierTarget(policy)
	if err != nil {
		return nil, err
	}
	owner, err := newNodeChainServerLinuxCarrier(lifetime, target)
	if err != nil {
		return nil, err
	}
	carrier, err := captureNodeChainServerCarrier(ctx, policy, owner.observe)
	if carrier == nil {
		carrier = &NodeChainServerCarrier{}
	}
	carrier.close = owner.closeContext
	carrier.check = owner.admit
	carrier.retired = owner.done
	owner.authority.Store(carrier)
	if owner.invalid.Load() {
		carrier.invalid.Store(true)
		err = nodeChainServerCarrierError
	}
	if err != nil {
		owner.cancel()
		return carrier, err
	}
	return carrier, nil
}

type nodeChainServerLinuxCarrier struct {
	target                          PhysicalEgress
	namespaceDevice, namespaceInode uint64
	fd                              int
	mu                              sync.Mutex
	active                          sync.WaitGroup
	closing                         bool
	joinOnce                        sync.Once
	joined                          chan struct{}
	invalid                         atomic.Bool
	identity                        atomic.Pointer[nodeChainServerCarrierSnapshot]
	authority                       atomic.Pointer[NodeChainServerCarrier]
	ctx                             context.Context
	cancel                          context.CancelFunc
	done                            chan struct{}
}

func nodeChainServerNamespace() (uint64, uint64, error) {
	info, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil {
		return 0, 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, nodeChainServerCarrierError
	}
	return uint64(stat.Dev), stat.Ino, nil
}
func newNodeChainServerLinuxCarrier(ctx context.Context, target PhysicalEgress) (*nodeChainServerLinuxCarrier, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	dev, ino, err := nodeChainServerNamespace()
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	// Link, both address families, routes and rules. A queued change invalidates
	// the observation even if the original values have already been restored.
	const groups = 0x1 | 0x10 | 0x40 | 0x80 | 0x100 | 0x400 | 0x40000
	if err = syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: groups}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	owned, cancel := context.WithCancel(ctx)
	owner := &nodeChainServerLinuxCarrier{target: target, namespaceDevice: dev, namespaceInode: ino, fd: fd, ctx: owned, cancel: cancel, done: make(chan struct{}), joined: make(chan struct{})}
	go owner.watch()
	return owner, nil
}
func (o *nodeChainServerLinuxCarrier) events(ctx context.Context) error {
	if o.invalid.Load() || o.ctx.Err() != nil {
		return nodeChainServerCarrierError
	}
	if err := mobilemtu.LockContext(ctx, &o.mu); err != nil {
		return err
	}
	defer o.mu.Unlock()
	if o.invalid.Load() || o.ctx.Err() != nil {
		return nodeChainServerCarrierError
	}
	buffer := make([]byte, 65536)
	for batches := 0; batches < 16; batches++ {
		n, _, err := syscall.Recvfrom(o.fd, buffer, syscall.MSG_DONTWAIT)
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			return nil
		}
		if err != nil || n == 0 {
			o.invalidate()
			return nodeChainServerCarrierError
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			o.invalidate()
			return nodeChainServerCarrierError
		}
		for _, message := range messages {
			relevant, err := nodeChainServerCarrierEvent(message, o.target, o.identity.Load())
			if err != nil || relevant {
				o.invalidate()
				return nodeChainServerCarrierError
			}
		}
	}
	o.invalidate()
	return nodeChainServerCarrierError
}
func (o *nodeChainServerLinuxCarrier) invalidate() {
	o.invalid.Store(true)
	if carrier := o.authority.Load(); carrier != nil {
		carrier.invalid.Store(true)
	}
}
func (o *nodeChainServerLinuxCarrier) watch() {
	defer o.invalidate()
	defer o.cancel()
	defer close(o.done)
	defer func() { o.mu.Lock(); _ = syscall.Close(o.fd); o.mu.Unlock() }()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-o.ctx.Done():
			return
		case <-ticker.C:
			if o.events(o.ctx) != nil {
				return
			}
		}
	}
}
func (o *nodeChainServerLinuxCarrier) begin(ctx context.Context) error {
	if err := mobilemtu.LockContext(ctx, &o.mu); err != nil {
		return err
	}
	defer o.mu.Unlock()
	if o.closing || o.invalid.Load() || o.ctx.Err() != nil {
		return nodeChainServerCarrierError
	}
	o.active.Add(1)
	return nil
}
func (o *nodeChainServerLinuxCarrier) closeContext(ctx context.Context) error {
	o.invalidate()
	o.cancel()
	if err := mobilemtu.LockContext(ctx, &o.mu); err != nil {
		return err
	}
	o.closing = true
	if o.joined == nil {
		o.joined = make(chan struct{})
	}
	o.joinOnce.Do(func() { go func() { <-o.done; o.active.Wait(); close(o.joined) }() })
	joined := o.joined
	o.mu.Unlock()
	select {
	case <-joined:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (o *nodeChainServerLinuxCarrier) admit(ctx context.Context) error {
	if ctx == nil {
		return nodeChainServerCarrierError
	}
	if err := o.begin(ctx); err != nil {
		return err
	}
	defer o.active.Done()
	if ctx == nil || ctx.Err() != nil {
		return nodeChainServerCarrierError
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	dev, ino, err := nodeChainServerNamespace()
	if err != nil || dev != o.namespaceDevice || ino != o.namespaceInode {
		return nodeChainServerCarrierError
	}
	return o.events(ctx)
}
func (o *nodeChainServerLinuxCarrier) observe(ctx context.Context) (nodeChainServerCarrierSnapshot, error) {
	var empty nodeChainServerCarrierSnapshot
	if ctx == nil || ctx.Err() != nil {
		return empty, nodeChainServerCarrierError
	}
	if err := o.begin(ctx); err != nil {
		return empty, err
	}
	defer o.active.Done()
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	stop := context.AfterFunc(o.ctx, cancel)
	defer func() { stop(); cancel() }()
	if err := o.events(bounded); err != nil {
		return empty, err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	dev, ino, err := nodeChainServerNamespace()
	if err != nil || dev != o.namespaceDevice || ino != o.namespaceInode {
		return empty, nodeChainServerCarrierError
	}
	route, err := nodeChainServerLinuxRoute(bounded, o.target)
	if err != nil {
		return empty, err
	}
	iface, err := net.InterfaceByIndex(route.index)
	if err != nil || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return empty, nodeChainServerCarrierError
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return empty, err
	}
	foundSource := false
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr().String() == route.source {
			foundSource = true
		}
	}
	if !foundSource {
		return empty, nodeChainServerCarrierError
	}
	snapshot := nodeChainServerCarrierSnapshot{NamespaceDevice: dev, NamespaceInode: ino, InterfaceIndex: iface.Index, InterfaceName: iface.Name, InterfaceAddress: iface.HardwareAddr.String(), InterfaceMTU: iface.MTU, RouteMTU: route.mtu, SourceAddress: route.source, RouteSHA256: route.digest}
	if err := snapshot.validate(o.target); err != nil {
		return empty, err
	}
	o.identity.CompareAndSwap(nil, &snapshot)
	if err := o.events(bounded); err != nil {
		return empty, err
	}
	return snapshot, nil
}

type nodeChainServerLinuxRouteResult struct {
	index, mtu     int
	source, digest string
}

func nodeChainServerRouteAttr(kind uint16, value []byte) []byte {
	size := 4 + len(value)
	raw := make([]byte, (size+3)&^3)
	binary.NativeEndian.PutUint16(raw, uint16(size))
	binary.NativeEndian.PutUint16(raw[2:], kind)
	copy(raw[4:], value)
	return raw
}
func nodeChainServerLinuxRoute(ctx context.Context, target PhysicalEgress) (nodeChainServerLinuxRouteResult, error) {
	var empty nodeChainServerLinuxRouteResult
	if err := nodeChainServerRejectPortRules(ctx, target); err != nil {
		return empty, err
	}
	first, err := nodeChainServerQueryLinuxRoute(ctx, target, nil, false)
	if err != nil {
		return empty, err
	}
	selected, err := nodeChainServerParseLinuxRoute(first, target)
	if err != nil {
		return empty, err
	}
	actual, err := nodeChainServerQueryLinuxRoute(ctx, target, &selected, false)
	if err != nil {
		return empty, err
	}
	bound, err := nodeChainServerParseLinuxRoute(actual, target)
	if err != nil || selected.index != bound.index || selected.source != bound.source {
		return empty, nodeChainServerCarrierError
	}
	fib, err := nodeChainServerQueryLinuxRoute(ctx, target, &bound, true)
	if err != nil {
		return empty, err
	}
	identity, err := nodeChainServerFIBIdentity(fib, target, bound.index)
	if err != nil {
		return empty, err
	}
	bound.digest = externalDigest([]byte(bound.digest + "\x00" + identity))
	return bound, nil
}

func nodeChainServerQueryLinuxRoute(ctx context.Context, target PhysicalEgress, bound *nodeChainServerLinuxRouteResult, fib bool) (syscall.NetlinkMessage, error) {
	var empty syscall.NetlinkMessage
	destination, err := netip.ParseAddr(target.Host)
	if err != nil {
		return empty, err
	}
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, syscall.NETLINK_ROUTE)
	if err != nil {
		return empty, err
	}
	defer syscall.Close(fd)
	if err = syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return empty, err
	}
	request := make([]byte, syscall.NLMSG_HDRLEN+syscall.SizeofRtMsg)
	binary.NativeEndian.PutUint16(request[4:], syscall.RTM_GETROUTE)
	binary.NativeEndian.PutUint16(request[6:], syscall.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(request[8:], 1)
	family, bits := byte(syscall.AF_INET), byte(32)
	if destination.Is6() {
		family, bits = syscall.AF_INET6, 128
	}
	request[syscall.NLMSG_HDRLEN], request[syscall.NLMSG_HDRLEN+1] = family, bits
	request = append(request, nodeChainServerRouteAttr(syscall.RTA_DST, destination.AsSlice())...)
	// Linux RTA_IP_PROTO/DPORT bind policy routing to the original transport.
	request = append(request, nodeChainServerRouteAttr(27, []byte{syscall.IPPROTO_UDP})...)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(target.Port))
	request = append(request, nodeChainServerRouteAttr(29, port)...)
	if bound != nil {
		source := netip.MustParseAddr(bound.source)
		request[syscall.NLMSG_HDRLEN+2] = bits
		request = append(request, nodeChainServerRouteAttr(syscall.RTA_SRC, source.AsSlice())...)
		index := make([]byte, 4)
		binary.NativeEndian.PutUint32(index, uint32(bound.index))
		request = append(request, nodeChainServerRouteAttr(syscall.RTA_OIF, index)...)
	}
	if fib {
		binary.NativeEndian.PutUint32(request[syscall.NLMSG_HDRLEN+8:], 0x2000)
	} // RTM_F_FIB_MATCH
	binary.NativeEndian.PutUint32(request, uint32(len(request)))
	if err = syscall.Sendto(fd, request, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return empty, err
	}
	buffer := make([]byte, 65536)
	for {
		if ctx.Err() != nil {
			return empty, ctx.Err()
		}
		n, from, err := syscall.Recvfrom(fd, buffer, syscall.MSG_DONTWAIT)
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			select {
			case <-ctx.Done():
				return empty, ctx.Err()
			case <-time.After(time.Millisecond):
				continue
			}
		}
		if err != nil {
			return empty, err
		}
		sender, ok := from.(*syscall.SockaddrNetlink)
		if !ok || sender.Pid != 0 {
			return empty, nodeChainServerCarrierError
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil || len(messages) != 1 {
			return empty, nodeChainServerCarrierError
		}
		message := messages[0]
		if message.Header.Seq != 1 || message.Header.Type != syscall.RTM_NEWROUTE {
			return empty, nodeChainServerCarrierError
		}
		return message, nil
	}
}
func nodeChainServerParseLinuxRoute(message syscall.NetlinkMessage, target PhysicalEgress) (nodeChainServerLinuxRouteResult, error) {
	var result nodeChainServerLinuxRouteResult
	if len(message.Data) < syscall.SizeofRtMsg || message.Header.Type != syscall.RTM_NEWROUTE {
		return result, nodeChainServerCarrierError
	}
	destination, err := netip.ParseAddr(target.Host)
	if err != nil {
		return result, err
	}
	family := byte(syscall.AF_INET)
	if destination.Is6() {
		family = syscall.AF_INET6
	}
	if message.Data[0] != family || message.Data[7] != syscall.RTN_UNICAST {
		return result, nodeChainServerCarrierError
	}
	attrs, err := syscall.ParseNetlinkRouteAttr(&message)
	if err != nil {
		return result, err
	}
	stable := append([]byte(nil), message.Data[:syscall.SizeofRtMsg]...)
	seen := map[uint16]bool{}
	for _, attr := range attrs {
		kind := attr.Attr.Type & 0x3fff
		if seen[kind] {
			// IPv6 can emit its selected and explicitly configured preferred source
			// twice. Only the same exact source is redundant, never two authorities.
			source, ok := netip.AddrFromSlice(attr.Value)
			if kind == syscall.RTA_PREFSRC && ok && source.String() == result.source {
				continue
			}
			return result, nodeChainServerCarrierError
		}
		seen[kind] = true
		switch kind {
		case syscall.RTA_DST:
			actual, ok := netip.AddrFromSlice(attr.Value)
			if !ok || actual != destination {
				return result, nodeChainServerCarrierError
			}
		case syscall.RTA_GATEWAY:
			gateway, ok := netip.AddrFromSlice(attr.Value)
			if !ok || gateway.Is6() != destination.Is6() || gateway.IsUnspecified() {
				return result, nodeChainServerCarrierError
			}
		case syscall.RTA_OIF:
			if len(attr.Value) != 4 {
				return result, nodeChainServerCarrierError
			}
			result.index = int(binary.NativeEndian.Uint32(attr.Value))
		case syscall.RTA_PREFSRC, syscall.RTA_SRC:
			source, ok := netip.AddrFromSlice(attr.Value)
			if !ok || source.Is6() != destination.Is6() {
				return result, nodeChainServerCarrierError
			}
			if kind == syscall.RTA_SRC && int(message.Data[2]) != source.BitLen() {
				return result, nodeChainServerCarrierError
			}
			if result.source != "" && result.source != source.String() {
				return result, nodeChainServerCarrierError
			}
			result.source = source.String()
		case syscall.RTA_MULTIPATH, 18, 19, 21, 22, 30: // Multipath or nexthop-object indirection is not a single captured carrier.
			return result, nodeChainServerCarrierError
		case syscall.RTA_METRICS:
			raw := attr.Value
			for len(raw) > 0 {
				if len(raw) < 4 {
					return result, nodeChainServerCarrierError
				}
				size := int(binary.NativeEndian.Uint16(raw))
				kind := binary.NativeEndian.Uint16(raw[2:]) & 0x3fff
				if size < 4 || size > len(raw) || (size+3)&^3 > len(raw) {
					return result, nodeChainServerCarrierError
				}
				if kind == syscall.RTAX_MTU {
					if size != 8 || result.mtu != 0 {
						return result, nodeChainServerCarrierError
					}
					result.mtu = int(binary.NativeEndian.Uint32(raw[4:]))
				}
				raw = raw[(size+3)&^3:]
			}
		}
		// Cache timers/usage are not routing identity. MTU metrics remain included.
		if kind != syscall.RTA_CACHEINFO && kind != 23 {
			stable = append(stable, nodeChainServerRouteAttr(kind, attr.Value)...)
		}
	}
	if result.index <= 0 || result.source == "" || !seen[syscall.RTA_DST] {
		return result, errors.New("kernel route omitted original carrier/source identity")
	}
	result.digest = externalDigest(stable)
	return result, nil
}

func nodeChainServerFIBIdentity(message syscall.NetlinkMessage, target PhysicalEgress, index int) (string, error) {
	if message.Header.Type != syscall.RTM_NEWROUTE || len(message.Data) < syscall.SizeofRtMsg || message.Data[7] != syscall.RTN_UNICAST {
		return "", nodeChainServerCarrierError
	}
	destination := netip.MustParseAddr(target.Host)
	family := byte(syscall.AF_INET)
	bits := 32
	if destination.Is6() {
		family = syscall.AF_INET6
		bits = 128
	}
	if message.Data[0] != family || int(message.Data[1]) > bits {
		return "", nodeChainServerCarrierError
	}
	attrs, err := syscall.ParseNetlinkRouteAttr(&message)
	if err != nil {
		return "", err
	}
	network := netip.IPv4Unspecified()
	if destination.Is6() {
		network = netip.IPv6Unspecified()
	}
	found := false
	stable := append([]byte(nil), message.Data[:syscall.SizeofRtMsg]...)
	seen := map[uint16]bool{}
	for _, attr := range attrs {
		kind := attr.Attr.Type & 0x3fff
		if seen[kind] {
			return "", nodeChainServerCarrierError
		}
		seen[kind] = true
		switch kind {
		case syscall.RTA_MULTIPATH, 18, 19, 21, 22, 30:
			return "", nodeChainServerCarrierError
		case syscall.RTA_OIF:
			if len(attr.Value) != 4 || int(binary.NativeEndian.Uint32(attr.Value)) != index {
				return "", nodeChainServerCarrierError
			}
			found = true
		case syscall.RTA_DST:
			var ok bool
			network, ok = netip.AddrFromSlice(attr.Value)
			if !ok || network.Is6() != destination.Is6() {
				return "", nodeChainServerCarrierError
			}
		}
		if kind != syscall.RTA_CACHEINFO && kind != 23 {
			stable = append(stable, nodeChainServerRouteAttr(kind, attr.Value)...)
		}
	}
	if !found || !netip.PrefixFrom(network, int(message.Data[1])).Contains(destination) {
		return "", nodeChainServerCarrierError
	}
	return externalDigest(stable), nil
}

// The native WG bind chooses its own ephemeral UDP source port. A routing rule
// selected by that port cannot be inferred from a different observation flow.
func nodeChainServerRejectPortRules(ctx context.Context, target PhysicalEgress) error {
	destination := netip.MustParseAddr(target.Host)
	family := byte(syscall.AF_INET)
	if destination.Is6() {
		family = syscall.AF_INET6
	}
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err = syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	request := make([]byte, syscall.NLMSG_HDRLEN+12)
	binary.NativeEndian.PutUint32(request, uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:], syscall.RTM_GETRULE)
	binary.NativeEndian.PutUint16(request[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(request[8:], 1)
	request[syscall.NLMSG_HDRLEN] = family
	if err = syscall.Sendto(fd, request, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	buffer := make([]byte, 65536)
	total := 0
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, from, err := syscall.Recvfrom(fd, buffer, syscall.MSG_DONTWAIT)
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Millisecond):
				continue
			}
		}
		if err != nil {
			return err
		}
		sender, ok := from.(*syscall.SockaddrNetlink)
		if !ok || sender.Pid != 0 {
			return nodeChainServerCarrierError
		}
		total += n
		if n == 0 || total > 1<<20 {
			return nodeChainServerCarrierError
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			return err
		}
		for _, message := range messages {
			if message.Header.Seq != 1 || message.Header.Flags&0x10 != 0 {
				return nodeChainServerCarrierError
			} // NLM_F_DUMP_INTR
			if message.Header.Type == syscall.NLMSG_DONE {
				if len(message.Data) > 0 && (len(message.Data) != 4 || binary.NativeEndian.Uint32(message.Data) != 0) {
					return nodeChainServerCarrierError
				}
				return nil
			}
			if err := nodeChainServerValidateRule(message, family); err != nil {
				return err
			}
		}
	}
}
func nodeChainServerValidateRule(message syscall.NetlinkMessage, family byte) error {
	if message.Header.Type != syscall.RTM_NEWRULE || len(message.Data) < 12 || message.Data[0] != family {
		return nodeChainServerCarrierError
	}
	// fib_rule_hdr and rtmsg are both twelve bytes; only the attribute layout is
	// shared here. No route identity is inferred from a rule message.
	attrs, err := syscall.ParseNetlinkRouteAttr(&syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: syscall.RTM_NEWROUTE}, Data: message.Data})
	if err != nil {
		return err
	}
	for _, attr := range attrs {
		if attr.Attr.Type&0x3fff == 23 {
			return errors.New("ordered Server carrier cannot infer source-port policy routing")
		}
	}
	return nil
}

func nodeChainServerCarrierEvent(message syscall.NetlinkMessage, target PhysicalEgress, original *nodeChainServerCarrierSnapshot) (bool, error) {
	if original == nil {
		return true, nil
	}
	switch message.Header.Type {
	case syscall.RTM_NEWLINK, syscall.RTM_DELLINK:
		if len(message.Data) < syscall.SizeofIfInfomsg {
			return false, nodeChainServerCarrierError
		}
		return int(binary.NativeEndian.Uint32(message.Data[4:])) == original.InterfaceIndex, nil
	case syscall.RTM_NEWADDR, syscall.RTM_DELADDR:
		if len(message.Data) < syscall.SizeofIfAddrmsg {
			return false, nodeChainServerCarrierError
		}
		if int(binary.NativeEndian.Uint32(message.Data[4:])) != original.InterfaceIndex {
			return false, nil
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&message)
		if err != nil {
			return false, err
		}
		for _, attr := range attrs {
			if attr.Attr.Type == syscall.IFA_LOCAL || attr.Attr.Type == syscall.IFA_ADDRESS {
				ip, ok := netip.AddrFromSlice(attr.Value)
				if !ok {
					return false, nodeChainServerCarrierError
				}
				if ip.String() == original.SourceAddress {
					return true, nil
				}
			}
		}
		return false, nil
	case syscall.RTM_NEWROUTE, syscall.RTM_DELROUTE, syscall.RTM_NEWRULE, syscall.RTM_DELRULE:
		if len(message.Data) < syscall.SizeofRtMsg {
			return false, nodeChainServerCarrierError
		}
		destination := netip.MustParseAddr(target.Host)
		family := byte(syscall.AF_INET)
		bits := 32
		network := netip.IPv4Unspecified()
		if destination.Is6() {
			family = syscall.AF_INET6
			bits = 128
			network = netip.IPv6Unspecified()
		}
		if message.Data[0] != family {
			return false, nil
		}
		if message.Header.Type == syscall.RTM_NEWRULE || message.Header.Type == syscall.RTM_DELRULE {
			return true, nil
		}
		if int(message.Data[1]) > bits {
			return false, nodeChainServerCarrierError
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&message)
		if err != nil {
			return false, err
		}
		for _, attr := range attrs {
			if attr.Attr.Type == syscall.RTA_DST {
				var ok bool
				network, ok = netip.AddrFromSlice(attr.Value)
				if !ok || network.Is6() != destination.Is6() {
					return false, nodeChainServerCarrierError
				}
			}
		}
		return netip.PrefixFrom(network, int(message.Data[1])).Contains(destination), nil
	default:
		return false, nodeChainServerCarrierError
	}
}
