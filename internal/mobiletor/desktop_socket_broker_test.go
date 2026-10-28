package mobiletor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The OS permission boundary is deliberately doubled. Every TCP/UDP socket,
// retained source port, kernel close and byte exchange below is real loopback;
// this suite does not claim a host firewall or isolated identity was installed.
type desktopSocketPolicyFixture struct {
	mu         sync.Mutex
	owner      DesktopSocketKernelOwner
	live       atomic.Bool
	grants     map[string]DesktopSocketGrant
	requests   chan DesktopSocketGrant
	removed    chan DesktopSocketGrant
	grant      func(context.Context, DesktopSocketGrant, DesktopSocketReceipt) (DesktopSocketReceipt, error)
	revoke     func(context.Context, DesktopSocketGrant) error
	selectHook func(*DesktopSocketBinding)
	bindCount  atomic.Int32
}

func desktopSocketFixtureCapture() DesktopSocketCapture {
	return DesktopSocketCapture{SessionID: strings.Repeat("1", 32), SourceSHA256: strings.Repeat("2", 64), NetworkID: strings.Repeat("3", 32)}
}

func desktopSocketFixturePolicy() *desktopSocketPolicyFixture {
	p := &desktopSocketPolicyFixture{owner: DesktopSocketKernelOwner{Kind: "unix-isolated-uid", IdentitySHA256: strings.Repeat("4", 64), Generation: 1, ProcessID: uint32(os.Getpid())}, grants: make(map[string]DesktopSocketGrant), requests: make(chan DesktopSocketGrant, 512), removed: make(chan DesktopSocketGrant, 512)}
	p.live.Store(true)
	return p
}

func (p *desktopSocketPolicyFixture) Owner() (DesktopSocketKernelOwner, error) { return p.owner, nil }
func (p *desktopSocketPolicyFixture) Current(DesktopSocketCapture, DesktopSocketKernelOwner) bool {
	return p.live.Load()
}
func (p *desktopSocketPolicyFixture) Select(_ context.Context, _ DesktopSocketCapture, _ string, hint netip.AddrPort) (DesktopSocketBinding, error) {
	address := netip.MustParseAddr("127.0.0.1")
	if !hint.Addr().Is4() {
		address = netip.IPv6Loopback()
	}
	b := DesktopSocketBinding{Owner: p.owner, InterfaceName: "fixture-loopback", InterfaceIndex: 1, LocalAddress: address}
	if p.selectHook != nil {
		p.selectHook(&b)
	}
	return b, nil
}
func (p *desktopSocketPolicyFixture) Bind(ctx context.Context, _ DesktopSocketCapture, _ DesktopSocketBinding, _ string, raw syscall.RawConn) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := raw.Control(func(uintptr) {}); err != nil {
		return err
	}
	p.bindCount.Add(1)
	return nil
}
func desktopSocketFixtureKey(q DesktopSocketGrant) string {
	return q.Capture.SessionID + "|" + q.Capture.NetworkID + "|" + q.SocketID + "|" + q.Remote.String()
}
func (p *desktopSocketPolicyFixture) Grant(ctx context.Context, q DesktopSocketGrant) (DesktopSocketReceipt, error) {
	p.mu.Lock()
	p.grants[desktopSocketFixtureKey(q)] = q
	p.mu.Unlock()
	p.requests <- q
	now := time.Now()
	receipt := DesktopSocketReceipt{Grant: q, ObservedAt: now.UnixMilli(), ExpiresAt: now.Add(DesktopSocketGrantMaxAge).UnixMilli()}
	if p.grant != nil {
		return p.grant(ctx, q, receipt)
	}
	return receipt, nil
}
func (p *desktopSocketPolicyFixture) Revoke(ctx context.Context, q DesktopSocketGrant) error {
	if p.revoke != nil {
		if err := p.revoke(ctx, q); err != nil {
			return err
		}
	}
	p.mu.Lock()
	delete(p.grants, desktopSocketFixtureKey(q))
	p.mu.Unlock()
	p.removed <- q
	return nil
}
func (p *desktopSocketPolicyFixture) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.grants)
}

func newDesktopSocketFixture(t *testing.T, p *desktopSocketPolicyFixture) (*DesktopSocketBroker, *atomic.Bool) {
	t.Helper()
	current := &atomic.Bool{}
	current.Store(true)
	b, err := NewDesktopSocketBroker(context.Background(), desktopSocketFixtureCapture(), p, current.Load)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := b.Close(ctx); err != nil {
			t.Error("retained broker did not drain", err)
		}
	})
	return b, current
}

func desktopSocketAwait[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("owned socket fixture did not reach its deterministic boundary")
		var zero T
		return zero
	}
}

func desktopSocketListener(t *testing.T) *net.TCPListener {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	return listener
}

func desktopSocketAssertReserved(t *testing.T, network string, address netip.AddrPort) {
	t.Helper()
	if network == "tcp" {
		listener, err := net.Listen("tcp", address.String())
		if err == nil {
			listener.Close()
			t.Fatal("live/unremoved socket released its exclusive source port")
		}
	} else {
		packet, err := net.ListenPacket("udp", address.String())
		if err == nil {
			packet.Close()
			t.Fatal("live/unremoved UDP socket released its exclusive source port")
		}
	}
}

func TestDesktopSocketBoundTCPBytesAndRemovalBeforeRelease(t *testing.T) {
	p := desktopSocketFixturePolicy()
	b, _ := newDesktopSocketFixture(t, p)
	listener := desktopSocketListener(t)
	accepted := make(chan *net.TCPConn, 1)
	go func() { conn, _ := listener.AcceptTCP(); accepted <- conn }()
	connection, err := b.DialContext(context.Background(), "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer := desktopSocketAwait(t, accepted)
	if peer == nil {
		t.Fatal("real peer did not accept")
	}
	defer peer.Close()
	request := desktopSocketAwait(t, p.requests)
	if request.Local.String() != connection.LocalAddr().String() || request.Remote.String() != listener.Addr().String() || request.Capture != b.Capture() || request.Binding.Owner != p.owner || request.Sequence != 1 {
		t.Fatal("permit was not captured from the actual complete socket")
	}
	const payload = "actual captured relay TCP bytes"
	done := make(chan error, 1)
	go func() {
		data := make([]byte, len(payload))
		_, err := io.ReadFull(peer, data)
		if err == nil && string(data) != payload {
			err = errors.New("wrong real bytes")
		}
		done <- err
	}()
	if _, err := connection.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := desktopSocketAwait(t, done); err != nil {
		t.Fatal(err)
	}
	p.revoke = func(_ context.Context, q DesktopSocketGrant) error {
		desktopSocketAssertReserved(t, "tcp", q.Local)
		return nil
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	removed := desktopSocketAwait(t, p.removed)
	if removed.SocketID != request.SocketID || p.count() != 0 {
		t.Fatal("exact permit was not removed before close")
	}
}

func TestDesktopSocketUnknownGrantAndFailedRemovalRetainKernelPort(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			p := desktopSocketFixturePolicy()
			issued := make(chan struct{})
			grantRelease := make(chan struct{})
			removeEntered := make(chan DesktopSocketGrant, 1)
			removeRelease := make(chan struct{})
			var grantOnce, removeOnce sync.Once
			p.grant = func(_ context.Context, _ DesktopSocketGrant, r DesktopSocketReceipt) (DesktopSocketReceipt, error) {
				grantOnce.Do(func() { close(issued) })
				<-grantRelease
				return r, nil
			}
			p.revoke = func(_ context.Context, q DesktopSocketGrant) error {
				removeOnce.Do(func() { removeEntered <- q })
				<-removeRelease
				return nil
			}
			b, _ := newDesktopSocketFixture(t, p)
			caller, cancel := context.WithCancel(context.Background())
			defer cancel()
			listener := desktopSocketListener(t)
			target := listener.Addr().String()
			result := make(chan error, 1)
			go func() {
				c, err := b.DialContext(caller, network, target)
				if c != nil {
					_ = c.Close()
				}
				result <- err
			}()
			desktopSocketAwait(t, issued)
			request := desktopSocketAwait(t, p.requests)
			desktopSocketAssertReserved(t, network, request.Local)
			if network == "tcp" {
				_ = listener.SetDeadline(time.Now().Add(50 * time.Millisecond))
				incoming, err := listener.AcceptTCP()
				if incoming != nil {
					incoming.Close()
				}
				if err == nil {
					t.Fatal("TCP connected before actual permit acknowledgment")
				}
			}
			cancel()
			wait, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
			err := b.Close(wait)
			stop()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("unknown permit falsely drained", err)
			}
			desktopSocketAssertReserved(t, network, request.Local)
			close(grantRelease)
			if err := desktopSocketAwait(t, result); err == nil {
				t.Fatal("canceled late permit was accepted")
			}
			removed := desktopSocketAwait(t, removeEntered)
			if removed.SocketID != request.SocketID {
				t.Fatal("wrong cleanup owner")
			}
			desktopSocketAssertReserved(t, network, request.Local)
			wait, stop = context.WithTimeout(context.Background(), 30*time.Millisecond)
			err = b.Close(wait)
			stop()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("pending removal falsely drained", err)
			}
			close(removeRelease)
			wait, stop = context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if err := b.Close(wait); err != nil {
				t.Fatal(err)
			}
			if p.count() != 0 {
				t.Fatal("unknown grant survived joined cleanup")
			}
		})
	}
}

func TestDesktopSocketRejectsEveryForeignReadbackField(t *testing.T) {
	cases := map[string]func(*DesktopSocketReceipt){
		"session":            func(r *DesktopSocketReceipt) { r.Grant.Capture.SessionID = strings.Repeat("5", 32) },
		"source":             func(r *DesktopSocketReceipt) { r.Grant.Capture.SourceSHA256 = strings.Repeat("5", 64) },
		"network-generation": func(r *DesktopSocketReceipt) { r.Grant.Capture.NetworkID = strings.Repeat("5", 32) },
		"kernel-kind":        func(r *DesktopSocketReceipt) { r.Grant.Binding.Owner.Kind = "shared-process-path" },
		"kernel-identity":    func(r *DesktopSocketReceipt) { r.Grant.Binding.Owner.IdentitySHA256 = strings.Repeat("5", 64) },
		"kernel-generation":  func(r *DesktopSocketReceipt) { r.Grant.Binding.Owner.Generation++ },
		"kernel-process":     func(r *DesktopSocketReceipt) { r.Grant.Binding.Owner.ProcessID++ },
		"interface":          func(r *DesktopSocketReceipt) { r.Grant.Binding.InterfaceName = "foreign" },
		"interface-index":    func(r *DesktopSocketReceipt) { r.Grant.Binding.InterfaceIndex++ },
		"bound-address":      func(r *DesktopSocketReceipt) { r.Grant.Binding.LocalAddress = netip.MustParseAddr("127.0.0.2") },
		"socket":             func(r *DesktopSocketReceipt) { r.Grant.SocketID = strings.Repeat("5", 32) },
		"transport":          func(r *DesktopSocketReceipt) { r.Grant.Network = "udp" },
		"local-port":         func(r *DesktopSocketReceipt) { r.Grant.Local = netip.AddrPortFrom(r.Grant.Local.Addr(), 1) },
		"remote":             func(r *DesktopSocketReceipt) { r.Grant.Remote = netip.MustParseAddrPort("127.0.0.2:443") },
		"sequence":           func(r *DesktopSocketReceipt) { r.Grant.Sequence++ },
		"future":             func(r *DesktopSocketReceipt) { r.ObservedAt = time.Now().Add(time.Second).UnixMilli() },
		"stale":              func(r *DesktopSocketReceipt) { r.ObservedAt = time.Now().Add(-6 * time.Second).UnixMilli() },
		"expired":            func(r *DesktopSocketReceipt) { r.ExpiresAt = time.Now().Add(-time.Second).UnixMilli() },
		"unbounded": func(r *DesktopSocketReceipt) {
			r.ExpiresAt = r.ObservedAt + DesktopSocketGrantMaxAge.Milliseconds() + 1
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := desktopSocketFixturePolicy()
			p.grant = func(_ context.Context, _ DesktopSocketGrant, r DesktopSocketReceipt) (DesktopSocketReceipt, error) {
				mutate(&r)
				return r, nil
			}
			b, _ := newDesktopSocketFixture(t, p)
			listener := desktopSocketListener(t)
			connection, err := b.DialContext(context.Background(), "tcp", listener.Addr().String())
			if connection != nil {
				connection.Close()
			}
			if err == nil {
				t.Fatal("foreign/unproved permit was accepted")
			}
			wait, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := b.Close(wait); err != nil {
				t.Fatal(err)
			}
			if p.count() != 0 {
				t.Fatal("rejected permit was not removed")
			}
		})
	}
}

func TestDesktopSocketUDPActualPeersAndNoImplicitDNS(t *testing.T) {
	p := desktopSocketFixturePolicy()
	b, _ := newDesktopSocketFixture(t, p)
	packet, err := b.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	remote, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	ungranted, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ungranted.Close()
	if p.count() != 0 {
		t.Fatal("merely binding UDP created a broad peer grant")
	}
	if _, err := packet.WriteTo([]byte("STUN-like real datagram"), remote.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	request := desktopSocketAwait(t, p.requests)
	if request.Network != "udp" || request.Local.String() != packet.LocalAddr().String() || request.Remote.String() != remote.LocalAddr().String() {
		t.Fatal("UDP grant was not its actual complete tuple")
	}
	buffer := make([]byte, 128)
	_ = remote.SetReadDeadline(time.Now().Add(time.Second))
	n, from, err := remote.ReadFrom(buffer)
	if err != nil || string(buffer[:n]) != "STUN-like real datagram" || from.String() != packet.LocalAddr().String() {
		t.Fatal("actual UDP payload lost", n, from, err)
	}
	_, _ = ungranted.WriteTo([]byte("foreign-UDP"), packet.LocalAddr())
	_, _ = remote.WriteTo([]byte("permitted-UDP"), packet.LocalAddr())
	_ = packet.SetReadDeadline(time.Now().Add(time.Second))
	n, from, err = packet.ReadFrom(buffer)
	if err != nil || string(buffer[:n]) != "permitted-UDP" || from.String() != remote.LocalAddr().String() {
		t.Fatal("ungranted datagram was accepted or permitted data lost", string(buffer[:n]), from, err)
	}
	for _, network := range []string{"tcp", "udp"} {
		if c, err := b.DialContext(context.Background(), network, "must-not-resolve.invalid:443"); err == nil || c != nil {
			t.Fatal("broker attempted host resolver fallback")
		}
	}
	for len(packet.(*desktopSocketPacket).socket.peers) < DesktopSocketPeerLimit {
		controlled, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer controlled.Close()
		if _, err := packet.WriteTo([]byte{1}, controlled.LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := packet.WriteTo([]byte{1}, ungranted.LocalAddr()); err == nil {
		t.Fatal("unbounded Snowflake UDP peers were accepted")
	}
	if len(packet.(*desktopSocketPacket).socket.peers) != DesktopSocketPeerLimit {
		t.Fatal("UDP peer bound is not exact")
	}
}

func TestDesktopSocketUDPRemovalReadbackKeepsBoundKernelPort(t *testing.T) {
	p := desktopSocketFixturePolicy()
	b, _ := newDesktopSocketFixture(t, p)
	packet, err := b.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	remote, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	if _, err := packet.WriteTo([]byte("owned"), remote.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	p.revoke = func(_ context.Context, q DesktopSocketGrant) error {
		probe, err := net.ListenPacket("udp4", q.Local.String())
		if err == nil {
			probe.Close()
			t.Error("UDP source port released before the absent policy readback")
		}
		return nil
	}
	if err := packet.Close(); err != nil || p.count() != 0 {
		t.Fatal("UDP policy did not join its exact kernel port", err)
	}
}

func TestDesktopSocketCancellationAndReplacementOwnership(t *testing.T) {
	for _, change := range []string{"native-source", "kernel-owner", "cancel"} {
		t.Run(change, func(t *testing.T) {
			p := desktopSocketFixturePolicy()
			b, current := newDesktopSocketFixture(t, p)
			replacementPolicy := desktopSocketFixturePolicy()
			replacement, _ := newDesktopSocketFixture(t, replacementPolicy)
			packet, err := b.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			fresh, err := replacement.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer fresh.Close()
			controlled, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer controlled.Close()
			switch change {
			case "native-source":
				current.Store(false)
			case "kernel-owner":
				p.live.Store(false)
			case "cancel":
				b.Cancel()
			}
			if _, err := packet.WriteTo([]byte{1}, controlled.LocalAddr()); err == nil {
				t.Fatal("retired owner sent a UDP packet")
			}
			wait, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := b.Close(wait); err != nil {
				t.Fatal(err)
			}
			if !replacement.Current() {
				t.Fatal("old owner retired replacement broker")
			}
			if _, err := fresh.WriteTo([]byte{1}, controlled.LocalAddr()); err != nil {
				t.Fatal("replacement lost independent permission", err)
			}
		})
	}
}

type desktopSocketHeldIO struct {
	net.Conn
	entered, release chan struct{}
	once             sync.Once
	write            bool
}

func (c *desktopSocketHeldIO) Read(p []byte) (int, error) {
	if !c.write {
		c.once.Do(func() { close(c.entered) })
		<-c.release
	}
	return c.Conn.Read(p)
}
func (c *desktopSocketHeldIO) Write(p []byte) (int, error) {
	if c.write {
		c.once.Do(func() { close(c.entered) })
		<-c.release
	}
	return c.Conn.Write(p)
}

func TestDesktopSocketRetainsEnteredIOThroughFailedRemoval(t *testing.T) {
	for _, write := range []bool{false, true} {
		t.Run(fmt.Sprint("write-", write), func(t *testing.T) {
			p := desktopSocketFixturePolicy()
			b, _ := newDesktopSocketFixture(t, p)
			listener := desktopSocketListener(t)
			accepted := make(chan *net.TCPConn, 1)
			go func() { c, _ := listener.AcceptTCP(); accepted <- c }()
			connection, err := b.DialContext(context.Background(), "tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			peer := desktopSocketAwait(t, accepted)
			defer peer.Close()
			request := desktopSocketAwait(t, p.requests)
			raw := connection.(*desktopSocketConn).socket
			held := &desktopSocketHeldIO{Conn: raw.conn, entered: make(chan struct{}), release: make(chan struct{}), write: write}
			raw.mu.Lock()
			raw.conn = held
			raw.mu.Unlock()
			result := make(chan error, 1)
			go func() {
				var err error
				if write {
					_, err = connection.Write([]byte("must not outlive owner"))
				} else {
					_, err = connection.Read(make([]byte, 1))
				}
				result <- err
			}()
			desktopSocketAwait(t, held.entered)
			b.Cancel()
			wait, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			err = b.Close(wait)
			cancel()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("socket closed before entered I/O joined", err)
			}
			desktopSocketAssertReserved(t, "tcp", request.Local)
			if p.count() != 1 {
				t.Fatal("fixture did not retain exact pending socket permit")
			}
			var refuse atomic.Bool
			refuse.Store(true)
			removeTried := make(chan struct{}, 1)
			p.revoke = func(context.Context, DesktopSocketGrant) error {
				if refuse.Load() {
					select {
					case removeTried <- struct{}{}:
					default:
					}
					return errors.New("held independent absent readback")
				}
				return nil
			}
			close(held.release)
			if err := desktopSocketAwait(t, result); err == nil {
				t.Fatal("entered I/O reported success after cancellation")
			}
			desktopSocketAwait(t, removeTried)
			desktopSocketAssertReserved(t, "tcp", request.Local)
			wait, cancel = context.WithTimeout(context.Background(), 30*time.Millisecond)
			err = b.Close(wait)
			cancel()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("failed removal falsely drained", err)
			}
			refuse.Store(false)
			wait, cancel = context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := b.Close(wait); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDesktopSocketExpiryInterruptsDataWhileRenewalIsHeld(t *testing.T) {
	p := desktopSocketFixturePolicy()
	pending := make(chan struct{})
	release := make(chan struct{})
	retired := make(chan struct{})
	var once sync.Once
	p.grant = func(ctx context.Context, q DesktopSocketGrant, r DesktopSocketReceipt) (DesktopSocketReceipt, error) {
		if q.Sequence == 1 {
			r.ExpiresAt = time.Now().Add(400 * time.Millisecond).UnixMilli()
			return r, nil
		}
		once.Do(func() { close(pending) })
		<-ctx.Done()
		close(retired)
		<-release
		return r, nil
	}
	b, _ := newDesktopSocketFixture(t, p)
	listener := desktopSocketListener(t)
	accepted := make(chan *net.TCPConn, 1)
	go func() { c, _ := listener.AcceptTCP(); accepted <- c }()
	connection, err := b.DialContext(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer := desktopSocketAwait(t, accepted)
	defer peer.Close()
	request := desktopSocketAwait(t, p.requests)
	connection.(*desktopSocketConn).socket.refresh()
	desktopSocketAwait(t, pending)
	read := make(chan error, 1)
	go func() { _, err := connection.Read(make([]byte, 1)); read <- err }()
	if err := desktopSocketAwait(t, read); err == nil {
		t.Fatal("expired permit retained successful data I/O")
	}
	if _, err := connection.Write([]byte("expired")); err == nil {
		t.Fatal("held renewal permitted data after receipt expiry")
	}
	desktopSocketAwait(t, retired)
	desktopSocketAssertReserved(t, "tcp", request.Local)
	wait, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	err = b.Close(wait)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("pending renewal was not retained", err)
	}
	close(release)
	wait, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := b.Close(wait); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopSocketFreshReadbackKeepsTheSameLiveStream(t *testing.T) {
	p := desktopSocketFixturePolicy()
	firstExpiry := make(chan time.Time, 1)
	renewed := make(chan DesktopSocketGrant, 1)
	var renewedOnce sync.Once
	p.grant = func(_ context.Context, q DesktopSocketGrant, r DesktopSocketReceipt) (DesktopSocketReceipt, error) {
		if q.Sequence == 1 {
			until := time.Now().Add(400 * time.Millisecond)
			r.ExpiresAt = until.UnixMilli()
			firstExpiry <- until
		} else {
			renewedOnce.Do(func() { renewed <- q })
		}
		return r, nil
	}
	b, _ := newDesktopSocketFixture(t, p)
	listener := desktopSocketListener(t)
	accepted := make(chan *net.TCPConn, 1)
	go func() { c, _ := listener.AcceptTCP(); accepted <- c }()
	connection, err := b.DialContext(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	peer := desktopSocketAwait(t, accepted)
	defer peer.Close()
	initial := desktopSocketAwait(t, p.requests)
	until := desktopSocketAwait(t, firstExpiry)
	connection.(*desktopSocketConn).socket.refresh()
	refresh := desktopSocketAwait(t, renewed)
	if refresh.Sequence != 2 || refresh.SocketID != initial.SocketID || refresh.Local != initial.Local || refresh.Remote != initial.Remote {
		t.Fatal("refresh replaced the captured socket or tuple")
	}
	// A real read spans the first receipt expiry. The peer sends only after
	// that point; a stale deadline or an incorrectly substituted owner fails.
	_ = peer.SetDeadline(until.Add(2 * time.Second))
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		timer := time.NewTimer(time.Until(until.Add(100 * time.Millisecond)))
		defer timer.Stop()
		<-timer.C
		_, _ = peer.Write([]byte("retained"))
	}()
	data := make([]byte, len("retained"))
	if _, err := io.ReadFull(connection, data); err != nil || string(data) != "retained" {
		t.Fatal("fresh readback killed a healthy retained stream", string(data), err)
	}
	desktopSocketAwait(t, sent)
	if !connection.(*desktopSocketConn).socket.allowed(initial.Remote) || p.count() != 1 {
		t.Fatal("renewal lost the original socket owner")
	}
}

func TestDesktopSocketUDPKeepsCurrentGrantWhileControlRenewalIsHeld(t *testing.T) {
	p := desktopSocketFixturePolicy()
	pending, release, retired := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var pendingOnce sync.Once
	p.grant = func(ctx context.Context, q DesktopSocketGrant, r DesktopSocketReceipt) (DesktopSocketReceipt, error) {
		if q.Sequence == 1 {
			r.ExpiresAt = time.Now().Add(600 * time.Millisecond).UnixMilli()
			return r, nil
		}
		pendingOnce.Do(func() { close(pending) })
		<-ctx.Done()
		close(retired)
		<-release
		return r, nil
	}
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	b, _ := newDesktopSocketFixture(t, p)
	remote, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	packet, err := b.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := packet.WriteTo([]byte("first"), remote.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	request := desktopSocketAwait(t, p.requests)
	packet.(*desktopSocketPacket).socket.refresh()
	desktopSocketAwait(t, pending)
	result := make(chan error, 1)
	go func() { _, err := packet.WriteTo([]byte("current"), remote.LocalAddr()); result <- err }()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal("pending renewal rejected the still-current native grant", err)
		}
	case <-time.After(250 * time.Millisecond):
		b.Cancel()
		releaseOnce.Do(func() { close(release) })
		desktopSocketAwait(t, result)
		t.Fatal("pending renewal serialized healthy UDP data behind control I/O")
	}
	_ = remote.SetReadDeadline(time.Now().Add(time.Second))
	for _, expected := range []string{"first", "current"} {
		data := make([]byte, 32)
		n, from, err := remote.ReadFrom(data)
		if err != nil || string(data[:n]) != expected || from.String() != request.Local.String() {
			t.Fatal("real UDP grant did not retain its exact data socket", string(data[:n]), from, err)
		}
	}
	desktopSocketAwait(t, retired)
	if _, err := packet.WriteTo([]byte("expired"), remote.LocalAddr()); err == nil {
		t.Fatal("expired UDP grant was reused while renewal remained blocked")
	}
	desktopSocketAssertReserved(t, "udp", request.Local)
	releaseOnce.Do(func() { close(release) })
	wait, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := b.Close(wait); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopSocketCapabilityAndBindingFailuresOpenNoPermit(t *testing.T) {
	for _, kind := range []string{"", "tuple-only", "process-path", "shared-uid"} {
		p := desktopSocketFixturePolicy()
		p.owner.Kind = kind
		if b, err := NewDesktopSocketBroker(context.Background(), desktopSocketFixtureCapture(), p, func() bool { return true }); err == nil || b != nil {
			t.Fatal("unisolated kernel capability accepted", kind)
		}
	}
	for _, mutate := range []func(*DesktopSocketBinding){func(b *DesktopSocketBinding) { b.Owner.Generation++ }, func(b *DesktopSocketBinding) { b.InterfaceIndex = 0 }, func(b *DesktopSocketBinding) { b.InterfaceName = "interface\x00foreign" }, func(b *DesktopSocketBinding) { b.LocalAddress = netip.IPv4Unspecified() }} {
		p := desktopSocketFixturePolicy()
		p.selectHook = mutate
		b, _ := newDesktopSocketFixture(t, p)
		listener := desktopSocketListener(t)
		if c, err := b.DialContext(context.Background(), "tcp", listener.Addr().String()); err == nil || c != nil {
			t.Fatal("invalid physical binding was accepted")
		}
		if p.count() != 0 || p.bindCount.Load() != 0 {
			t.Fatal("invalid binding reached a kernel permit")
		}
	}
}
