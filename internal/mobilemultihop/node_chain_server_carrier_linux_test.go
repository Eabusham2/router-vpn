package mobilemultihop

import (
	"context"
	"encoding/binary"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

func serverCarrierRouteFixture(ipv6 bool) (syscall.NetlinkMessage, PhysicalEgress) {
	target := PhysicalEgress{Host: "198.51.100.10", Port: 51820, Network: "udp"}
	source := "192.0.2.2"
	family := byte(syscall.AF_INET)
	if ipv6 {
		target.Host = "2001:db8:1::10"
		source = "2001:db8::2"
		family = syscall.AF_INET6
	}
	raw := make([]byte, syscall.SizeofRtMsg)
	raw[0], raw[1], raw[4], raw[7] = family, 32, 254, syscall.RTN_UNICAST
	if ipv6 {
		raw[1] = 128
	}
	index := make([]byte, 4)
	binary.NativeEndian.PutUint32(index, 3)
	raw = append(raw, nodeChainServerRouteAttr(syscall.RTA_DST, netip.MustParseAddr(target.Host).AsSlice())...)
	raw = append(raw, nodeChainServerRouteAttr(syscall.RTA_OIF, index)...)
	raw = append(raw, nodeChainServerRouteAttr(syscall.RTA_PREFSRC, netip.MustParseAddr(source).AsSlice())...)
	return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: syscall.RTM_NEWROUTE, Seq: 1}, Data: raw}, target
}
func TestNodeChainServerCarrierLinuxKernelRouteParser(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		message, target := serverCarrierRouteFixture(v6)
		original, err := nodeChainServerParseLinuxRoute(message, target)
		if err != nil || original.index != 3 || original.mtu != 0 || original.source == "" || len(original.digest) != 64 {
			t.Fatal("exact kernel route", err)
		}
		value := make([]byte, 4)
		binary.NativeEndian.PutUint32(value, 1400)
		withMTU := message
		withMTU.Data = append(append([]byte(nil), message.Data...), nodeChainServerRouteAttr(syscall.RTA_METRICS, nodeChainServerRouteAttr(syscall.RTAX_MTU, value))...)
		bounded, err := nodeChainServerParseLinuxRoute(withMTU, target)
		if err != nil || bounded.mtu != 1400 || bounded.digest == original.digest {
			t.Fatal("kernel MTU lost binding", err)
		}
		for _, kind := range []uint16{syscall.RTA_MULTIPATH, 30, syscall.RTA_OIF} {
			changed := message
			changed.Data = append(append([]byte(nil), message.Data...), nodeChainServerRouteAttr(kind, value)...)
			if _, err := nodeChainServerParseLinuxRoute(changed, target); err == nil {
				t.Fatal("ambiguous/duplicate route accepted", kind)
			}
		}
		foreign := target
		foreign.Host = "198.51.100.99"
		if v6 {
			foreign.Host = "2001:db8:1::99"
		}
		if _, err := nodeChainServerParseLinuxRoute(message, foreign); err == nil {
			t.Fatal("wrong endpoint route accepted")
		}
		malformed := message
		malformed.Data = message.Data[:4]
		if _, err := nodeChainServerParseLinuxRoute(malformed, target); err == nil {
			t.Fatal("truncated kernel header accepted")
		}
	}
}
func TestNodeChainServerCarrierLinuxQueuedChangeAndJoinedClose(t *testing.T) {
	sockets, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(sockets[1])
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner := &nodeChainServerLinuxCarrier{fd: sockets[0], ctx: ctx, cancel: cancel, done: make(chan struct{})}
	go owner.watch()
	carrier := &NodeChainServerCarrier{close: owner.closeContext}
	if err := owner.events(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := syscall.Write(sockets[1], []byte("test-owned kernel-event boundary")); err != nil {
		t.Fatal(err)
	}
	if owner.events(ctx) == nil || !owner.invalid.Load() {
		t.Fatal("queued change was not latched")
	}
	if owner.events(ctx) == nil {
		t.Fatal("draining event revived lost owner")
	}
	bounded, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	if err := carrier.CloseContext(bounded); err != nil {
		t.Fatal(err)
	}
	select {
	case <-owner.done:
	default:
		t.Fatal("close acknowledged before watcher joined")
	}
	if err := carrier.CloseContext(context.Background()); err != nil {
		t.Fatal("joined cleanup retry", err)
	}
}

func TestNodeChainServerCarrierLinuxFIBAndPolicyAmbiguityRefused(t *testing.T) {
	message, target := serverCarrierRouteFixture(false)
	if _, err := nodeChainServerFIBIdentity(message, target, 3); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []uint16{syscall.RTA_MULTIPATH, 18, 19, 21, 22, 30} {
		changed := message
		changed.Data = append(append([]byte(nil), message.Data...), nodeChainServerRouteAttr(kind, []byte{1, 0, 0, 0})...)
		if _, err := nodeChainServerFIBIdentity(changed, target, 3); err == nil {
			t.Fatal("selected flow hid ambiguous full FIB route", kind)
		}
	}
	if _, err := nodeChainServerFIBIdentity(message, target, 4); err == nil {
		t.Fatal("FIB route changed bound interface")
	}
	rule := syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: syscall.RTM_NEWRULE}, Data: make([]byte, 12)}
	rule.Data[0] = syscall.AF_INET
	if err := nodeChainServerValidateRule(rule, syscall.AF_INET); err != nil {
		t.Fatal(err)
	}
	rule.Data = append(rule.Data, nodeChainServerRouteAttr(23, []byte{0, 1, 0, 2})...)
	if nodeChainServerValidateRule(rule, syscall.AF_INET) == nil {
		t.Fatal("source-port routing borrowed unrelated flow authority")
	}
}
func TestNodeChainServerCarrierLinuxEventsMatchOriginalOwnership(t *testing.T) {
	snapshot := serverCarrierSnapshotFixture()
	route, target := serverCarrierRouteFixture(false)
	if relevant, err := nodeChainServerCarrierEvent(route, target, &snapshot); err != nil || !relevant {
		t.Fatal("original route change ignored", err)
	}
	foreign, other := serverCarrierRouteFixture(false)
	other.Host = "198.51.100.11"
	if relevant, err := nodeChainServerCarrierEvent(foreign, other, &snapshot); err != nil || relevant {
		t.Fatal("unrelated destination retired owner", err)
	}
	link := syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: syscall.RTM_NEWLINK}, Data: make([]byte, syscall.SizeofIfInfomsg)}
	binary.NativeEndian.PutUint32(link.Data[4:], uint32(snapshot.InterfaceIndex))
	if relevant, err := nodeChainServerCarrierEvent(link, target, &snapshot); err != nil || !relevant {
		t.Fatal("original interface change ignored", err)
	}
	binary.NativeEndian.PutUint32(link.Data[4:], 999)
	if relevant, err := nodeChainServerCarrierEvent(link, target, &snapshot); err != nil || relevant {
		t.Fatal("unrelated interface retired owner", err)
	}
	address := syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: syscall.RTM_NEWADDR}, Data: make([]byte, syscall.SizeofIfAddrmsg)}
	binary.NativeEndian.PutUint32(address.Data[4:], uint32(snapshot.InterfaceIndex))
	address.Data = append(address.Data, nodeChainServerRouteAttr(syscall.IFA_LOCAL, netip.MustParseAddr(snapshot.SourceAddress).AsSlice())...)
	if relevant, err := nodeChainServerCarrierEvent(address, target, &snapshot); err != nil || !relevant {
		t.Fatal("original source address change ignored", err)
	}
	address.Data = address.Data[:syscall.SizeofIfAddrmsg]
	address.Data = append(address.Data, nodeChainServerRouteAttr(syscall.IFA_ADDRESS, netip.MustParseAddr("fe80::1234").AsSlice())...)
	if relevant, err := nodeChainServerCarrierEvent(address, target, &snapshot); err != nil || relevant {
		t.Fatal("unrelated IPv6 DAD changed IPv4 carrier", err)
	}
}

func TestNodeChainServerCarrierLinuxCloseRetainsAdmittedQuery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	close(done)
	owner := &nodeChainServerLinuxCarrier{ctx: ctx, cancel: cancel, done: done, fd: -1}
	if err := owner.begin(context.Background()); err != nil {
		t.Fatal(err)
	}
	closeCtx, finish := context.WithTimeout(context.Background(), 10*time.Millisecond)
	if err := owner.closeContext(closeCtx); err == nil {
		t.Fatal("close acknowledged while original admitted query remained")
	}
	finish()
	if owner.begin(context.Background()) == nil {
		t.Fatal("retired collector admitted new native query")
	}
	owner.active.Done()
	bounded, finish := context.WithTimeout(context.Background(), time.Second)
	defer finish()
	if err := owner.closeContext(bounded); err != nil {
		t.Fatal("same original observer did not join on retry", err)
	}
	select {
	case <-owner.joined:
	default:
		t.Fatal("cleanup acknowledgement lacked original query join")
	}
}

func TestNodeChainServerCarrierLinuxExplicitSourceReply(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		message, target := serverCarrierRouteFixture(v6)
		selected, err := nodeChainServerParseLinuxRoute(message, target)
		if err != nil {
			t.Fatal(err)
		}
		attributes, err := syscall.ParseNetlinkRouteAttr(&message)
		if err != nil {
			t.Fatal(err)
		}
		explicit := message
		explicit.Data = append([]byte(nil), message.Data[:syscall.SizeofRtMsg]...)
		explicit.Data[2] = message.Data[1]
		for _, attr := range attributes {
			kind := attr.Attr.Type
			if kind == syscall.RTA_PREFSRC {
				kind = syscall.RTA_SRC
			}
			explicit.Data = append(explicit.Data, nodeChainServerRouteAttr(kind, attr.Value)...)
		}
		actual, err := nodeChainServerParseLinuxRoute(explicit, target)
		if err != nil || actual.source != selected.source {
			t.Fatal("kernel explicit source reply lost original binding", err)
		}
		source := netip.MustParseAddr(selected.source)
		same := message
		same.Data = append(append([]byte(nil), message.Data...), nodeChainServerRouteAttr(syscall.RTA_PREFSRC, source.AsSlice())...)
		if _, err := nodeChainServerParseLinuxRoute(same, target); err != nil {
			t.Fatal("identical IPv6 selected/preferred source rejected", err)
		}
		foreign := netip.MustParseAddr("192.0.2.99")
		if v6 {
			foreign = netip.MustParseAddr("2001:db8::99")
		}
		mismatch := explicit
		mismatch.Data = append(append([]byte(nil), explicit.Data...), nodeChainServerRouteAttr(syscall.RTA_PREFSRC, foreign.AsSlice())...)
		if _, err := nodeChainServerParseLinuxRoute(mismatch, target); err == nil {
			t.Fatal("contradictory kernel source authorities accepted")
		}
	}
}
