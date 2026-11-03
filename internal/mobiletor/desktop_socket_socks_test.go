package mobiletor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Only OS admission is modeled. Broker control/relay ownership, actual bound
// TCP/UDP descriptors, bytes, renewal, and joined cleanup execute unchanged.
type desktopSOCKSPrivateFixture struct {
	*desktopSocketPolicyFixture
	control netip.AddrPort
	fault   string
}
type desktopSOCKSPrivateScope struct {
	*desktopSocketPolicyFixture
	parent  *desktopSOCKSPrivateFixture
	control DesktopSocketGrant
	remote  netip.AddrPort
	id      string
}

func (p *desktopSOCKSPrivateFixture) Select(ctx context.Context, c DesktopSocketCapture, n string, r netip.AddrPort) (DesktopSocketBinding, error) {
	if n != "tcp" || r != p.control {
		return DesktopSocketBinding{}, errors.New("ordinary private UDP is not captured")
	}
	return p.desktopSocketPolicyFixture.Select(ctx, c, n, r)
}
func (p *desktopSOCKSPrivateFixture) privateSOCKSRelayPolicy(c DesktopSocketGrant, r netip.AddrPort, id string) (DesktopSocketPolicy, error) {
	if !desktopSocketPrivateSOCKSRelay(c, r) || c.Remote != p.control || !desktopSocketHex(id, 32) || id == c.SocketID {
		return nil, errors.New("foreign modeled association")
	}
	return &desktopSOCKSPrivateScope{p.desktopSocketPolicyFixture, p, c, r, id}, nil
}
func (p *desktopSOCKSPrivateScope) currentControl() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	actual, ok := p.grants[desktopSocketFixtureKey(p.control)]
	return ok && desktopSocketSOCKSControlMatches(actual, p.control)
}
func (p *desktopSOCKSPrivateScope) Select(ctx context.Context, c DesktopSocketCapture, n string, r netip.AddrPort) (DesktopSocketBinding, error) {
	if p.parent.fault == "select" || !p.currentControl() || c != p.control.Capture || n != "udp" || r != p.remote {
		return DesktopSocketBinding{}, errors.New("private association selection refused")
	}
	return p.desktopSocketPolicyFixture.Select(ctx, c, n, r)
}
func (p *desktopSOCKSPrivateScope) Bind(ctx context.Context, c DesktopSocketCapture, b DesktopSocketBinding, n string, raw syscall.RawConn) error {
	if p.parent.fault == "bind" || !p.currentControl() || c != p.control.Capture || b != p.control.Binding {
		return errors.New("private association bind refused")
	}
	return p.desktopSocketPolicyFixture.Bind(ctx, c, b, n, raw)
}
func (p *desktopSOCKSPrivateScope) Grant(ctx context.Context, q DesktopSocketGrant) (DesktopSocketReceipt, error) {
	if p.parent.fault == "grant" || p.parent.fault == "renew" && q.Sequence > 1 || !p.currentControl() || q.SocketID != p.id || q.Capture != p.control.Capture || q.Binding != p.control.Binding || q.Network != "udp" || q.Remote != p.remote {
		return DesktopSocketReceipt{}, errors.New("private association grant refused")
	}
	r, err := p.desktopSocketPolicyFixture.Grant(ctx, q)
	if p.parent.fault == "renew" {
		r.ExpiresAt = time.Now().Add(600 * time.Millisecond).UnixMilli()
	}
	return r, err
}

func desktopSOCKSPrivateFixtureNew(t *testing.T, fault string) (*DesktopSocketBroker, *desktopSOCKSPrivateFixture, *net.TCPListener, net.PacketConn) {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var selected net.Interface
	var address netip.Addr
	for _, i := range interfaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, _ := i.Addrs()
		for _, raw := range addresses {
			p, e := netip.ParsePrefix(raw.String())
			if e == nil && p.Addr().Is4() && p.Addr().IsPrivate() {
				selected, address = i, p.Addr()
				break
			}
		}
		if address.IsValid() {
			break
		}
	}
	if !address.IsValid() {
		t.Fatal("private SOCKS broker fixture requires an actual private physical address")
	}
	listener, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(netip.AddrPortFrom(address, 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	packet, err := net.ListenPacket("udp4", netip.AddrPortFrom(address, 0).String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packet.Close() })
	p := &desktopSOCKSPrivateFixture{desktopSocketPolicyFixture: desktopSocketFixturePolicy(), control: listener.Addr().(*net.TCPAddr).AddrPort(), fault: fault}
	p.selectHook = func(b *DesktopSocketBinding) {
		b.InterfaceIndex = uint32(selected.Index)
		b.InterfaceName = selected.Name
		b.LocalAddress = address
	}
	b, err := NewDesktopSocketBroker(context.Background(), desktopSocketFixtureCapture(), p, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := b.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return b, p, listener, packet
}
func desktopSOCKSPrivateControl(t *testing.T, b *DesktopSocketBroker, l *net.TCPListener) net.Conn {
	t.Helper()
	accepted := make(chan *net.TCPConn, 1)
	go func() { c, _ := l.AcceptTCP(); accepted <- c }()
	control, err := b.DialContext(context.Background(), "tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer := desktopSocketAwait(t, accepted)
	if peer == nil {
		t.Fatal("actual private control was not accepted")
	}
	t.Cleanup(func() { _ = peer.Close() })
	return control
}
func desktopSOCKSPrivateExchange(t *testing.T, c net.Conn, p net.PacketConn) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	_ = p.SetDeadline(time.Now().Add(time.Second))
	if n, err := c.Write([]byte("owned-private-payload")); err != nil || n != 21 {
		t.Fatal("private relay write", n, err)
	}
	var body [128]byte
	n, remote, err := p.ReadFrom(body[:])
	if err != nil || string(body[:n]) != "owned-private-payload" || remote.String() != c.LocalAddr().String() {
		t.Fatal("private relay changed actual bound bytes", err)
	}
	if _, err := p.WriteTo(body[:n], remote); err != nil {
		t.Fatal(err)
	}
	n, err = c.Read(body[:])
	if err != nil || string(body[:n]) != "owned-private-payload" {
		t.Fatal("private relay lost its exact return tuple", err)
	}
}

type desktopSOCKSWrappedControl struct{ net.Conn }

func TestDesktopPrivateSOCKSRelayRequiresOriginalControlAndExactTuple(t *testing.T) {
	b, p, l, packet := desktopSOCKSPrivateFixtureNew(t, "")
	control := desktopSOCKSPrivateControl(t, b, l)
	defer control.Close()
	remote := packet.LocalAddr().String()
	if c, err := b.DialContext(context.Background(), "udp", remote); err == nil || c != nil {
		t.Fatal("ordinary private UDP gained association authority")
	}
	other := netip.MustParseAddr("10.254.253.252")
	if other == p.control.Addr() {
		other = netip.MustParseAddr("172.31.254.253")
	}
	for _, fault := range []string{"wrapped", "nil", "other-private", "public", "domain", "zero", "cancelled"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			candidate := control
			address := remote
			switch fault {
			case "wrapped":
				candidate = &desktopSOCKSWrappedControl{control}
			case "nil":
				candidate = nil
			case "other-private":
				address = netip.AddrPortFrom(other, 5353).String()
			case "public":
				address = "198.51.100.8:5353"
			case "domain":
				address = "unowned.invalid:5353"
			case "zero":
				address = netip.AddrPortFrom(p.control.Addr(), 0).String()
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if c, err := b.DialPrivateSOCKSRelay(ctx, candidate, address); err == nil || c != nil {
				t.Fatal("foreign association acquired private authority", fault)
			}
		})
	}
	foreign, _, foreignListener, _ := desktopSOCKSPrivateFixtureNew(t, "")
	foreignControl := desktopSOCKSPrivateControl(t, foreign, foreignListener)
	defer foreignControl.Close()
	if c, err := b.DialPrivateSOCKSRelay(context.Background(), foreignControl, remote); err == nil || c != nil {
		t.Fatal("another broker supplied private control authority")
	}
	relay, err := b.DialPrivateSOCKSRelay(context.Background(), control, remote)
	if err != nil {
		t.Fatal(err)
	}
	desktopSOCKSPrivateExchange(t, relay, packet)
	if c, err := b.DialPrivateSOCKSRelay(context.Background(), control, remote); err == nil || c != nil {
		t.Fatal("one authenticated control was reused for another relay socket")
	}
	if c, err := b.DialContext(context.Background(), "udp", remote); err == nil || c != nil {
		t.Fatal("per-socket private authority changed shared policy")
	}
	if err := relay.Close(); err != nil {
		t.Fatal(err)
	}
	if !control.(*desktopSocketConn).socket.allowed(p.control) || p.count() != 1 {
		t.Fatal("relay close changed original TCP authority")
	}
	if c, err := b.DialPrivateSOCKSRelay(context.Background(), control, remote); err == nil || c != nil {
		t.Fatal("retired association capability was reused")
	}
}

func TestDesktopPrivateSOCKSControlCloseJoinsRelayBeforeTCPAndKeepsSibling(t *testing.T) {
	b, p, l, packet := desktopSOCKSPrivateFixtureNew(t, "")
	a := desktopSOCKSPrivateControl(t, b, l)
	bControl := desktopSOCKSPrivateControl(t, b, l)
	defer bControl.Close()
	first, err := b.DialPrivateSOCKSRelay(context.Background(), a, packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.DialPrivateSOCKSRelay(context.Background(), bControl, packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	firstSocket := first.(*desktopConnectedPacket).packet.socket
	parent := a.(*desktopSocketConn).socket
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	p.revoke = func(ctx context.Context, q DesktopSocketGrant) error {
		if q.SocketID == firstSocket.id {
			select {
			case <-entered:
			default:
				close(entered)
			}
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- a.Close() }()
	desktopSocketAwait(t, entered)
	select {
	case <-done:
		t.Fatal("TCP control close returned before its relay revocation joined")
	default:
	}
	p.mu.Lock()
	tcpPresent := false
	for _, g := range p.grants {
		if g.SocketID == parent.id {
			tcpPresent = true
		}
	}
	p.mu.Unlock()
	if !tcpPresent {
		t.Fatal("original TCP authority retired before its child")
	}
	desktopSocketAssertReserved(t, "udp", firstSocket.local)
	desktopSOCKSPrivateExchange(t, second, packet)
	if _, err := first.Write([]byte("retired")); !errors.Is(err, net.ErrClosed) {
		t.Fatal("retired private control retained UDP bytes", err)
	}
	once.Do(func() { close(release) })
	if err := desktopSocketAwait(t, done); err != nil {
		t.Fatal(err)
	}
	if p.count() != 2 {
		t.Fatal("private control retirement changed sibling grant count", p.count())
	}
	desktopSOCKSPrivateExchange(t, second, packet)
}

func TestDesktopPrivateSOCKSStagesAndRenewalFailClosedWithoutFallback(t *testing.T) {
	for _, stage := range []string{"select", "bind", "grant", "renew"} {
		t.Run(stage, func(t *testing.T) {
			b, p, l, packet := desktopSOCKSPrivateFixtureNew(t, stage)
			control := desktopSOCKSPrivateControl(t, b, l)
			defer control.Close()
			relay, err := b.DialPrivateSOCKSRelay(context.Background(), control, packet.LocalAddr().String())
			if stage != "renew" {
				if err == nil || relay != nil {
					t.Fatal("private phase failure fell back to ordinary UDP", stage)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				socket := relay.(*desktopConnectedPacket).packet.socket
				socket.refresh()
				desktopSocketAwait(t, socket.done)
				if _, err := relay.Write([]byte("expired")); !errors.Is(err, net.ErrClosed) {
					t.Fatal("failed independent renewal retained data authority", err)
				}
			}
			parent := control.(*desktopSocketConn).socket
			parent.mu.Lock()
			children := make([]*desktopSocket, 0, len(parent.children))
			for c := range parent.children {
				children = append(children, c)
			}
			parent.mu.Unlock()
			for _, c := range children {
				desktopSocketAwait(t, c.done)
			}
			if p.count() != 1 || !parent.allowed(p.control) {
				t.Fatal("private failure discarded its unrelated original control")
			}
		})
	}
}

func TestDesktopPrivateSOCKSControlRenewalRefreshesBlockedRelayRead(t *testing.T) {
	b, _, listener, packet := desktopSOCKSPrivateFixtureNew(t, "")
	control := desktopSOCKSPrivateControl(t, b, listener)
	defer control.Close()
	relay, err := b.DialPrivateSOCKSRelay(context.Background(), control, packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	parent := control.(*desktopSocketConn).socket
	parent.mu.Lock()
	peer := parent.peers[parent.remote]
	parent.mu.Unlock()
	peer.mu.Lock()
	// Hold only modeled policy completion; real kernel read/deadline updates
	// run unchanged. The control renews before its original short lease ends.
	peer.applying = true
	peer.receipt.ExpiresAt = time.Now().Add(300 * time.Millisecond).UnixMilli()
	peer.mu.Unlock()
	parent.updateDeadlines()
	// Establish the original short deadline on the actual child independently
	// so this test fails if renewal propagation from the parent is removed.
	relay.(*desktopConnectedPacket).packet.socket.updateDeadlines()
	read := make(chan error, 1)
	go func() {
		var body [64]byte
		n, err := relay.Read(body[:])
		if err == nil && string(body[:n]) != "renewed-control" {
			err = errors.New("private relay changed renewed-control bytes")
		}
		read <- err
	}()
	time.Sleep(50 * time.Millisecond)
	peer.mu.Lock()
	peer.receipt.ExpiresAt = time.Now().Add(2 * time.Second).UnixMilli()
	peer.mu.Unlock()
	parent.updateDeadlines()
	select {
	case err := <-read:
		t.Fatal("pending relay read retained the retired control deadline", err)
	case <-time.After(350 * time.Millisecond):
	}
	if _, err := packet.WriteTo([]byte("renewed-control"), relay.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if err := desktopSocketAwait(t, read); err != nil {
		t.Fatal("renewed original control lost an actual blocked UDP read", err)
	}
}

func TestDesktopPrivateSOCKSAuthorityMetadataRejectsForeignFields(t *testing.T) {
	control := DesktopSocketGrant{Capture: desktopSocketFixtureCapture(), Binding: DesktopSocketBinding{Owner: desktopSocketFixturePolicy().owner, InterfaceName: "owned", InterfaceIndex: 2, LocalAddress: netip.MustParseAddr("10.0.0.2")}, SocketID: strings.Repeat("a", 32), Network: "tcp", Local: netip.MustParseAddrPort("10.0.0.2:40000"), Remote: netip.MustParseAddrPort("10.0.0.1:1080"), Sequence: 1}
	remote := netip.MustParseAddrPort("10.0.0.1:54000")
	if !desktopSocketPrivateSOCKSRelay(control, remote) {
		t.Fatal("valid exact private control metadata rejected")
	}
	renewed := control
	renewed.Sequence++
	if !desktopSocketSOCKSControlMatches(renewed, control) || !desktopSocketSOCKSControlMatches(control, control) || desktopSocketSOCKSControlMatches(control, renewed) {
		t.Fatal("control receipt confused a genuine renewal with a fabricated future sequence")
	}
	for _, fault := range []string{"capture", "owner", "socket", "network", "sequence", "local", "public", "loopback", "link-local", "other-private", "zero"} {
		t.Run(fault, func(t *testing.T) {
			c, r := control, remote
			switch fault {
			case "capture":
				c.Capture.SessionID = ""
			case "owner":
				c.Binding.Owner.IdentitySHA256 = ""
			case "socket":
				c.SocketID = ""
			case "network":
				c.Network = "udp"
			case "sequence":
				c.Sequence = 0
			case "local":
				c.Local = netip.MustParseAddrPort("10.0.0.3:40000")
			case "public":
				c.Remote = netip.MustParseAddrPort("198.51.100.1:1080")
				r = netip.MustParseAddrPort("198.51.100.1:54000")
			case "loopback":
				c.Remote = netip.MustParseAddrPort("127.0.0.1:1080")
				r = netip.MustParseAddrPort("127.0.0.1:54000")
			case "link-local":
				c.Remote = netip.MustParseAddrPort("169.254.10.1:1080")
				r = netip.MustParseAddrPort("169.254.10.1:54000")
			case "other-private":
				r = netip.MustParseAddrPort("10.0.0.9:54000")
			case "zero":
				r = netip.MustParseAddrPort("10.0.0.1:0")
			}
			if desktopSocketPrivateSOCKSRelay(c, r) {
				t.Fatal("private control metadata accepted replacement", fault)
			}
		})
	}
}
