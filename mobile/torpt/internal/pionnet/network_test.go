package pionnet

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/transport/v4"
	"router-vpn/internal/mobiletor"
)

func fixtureInterfaces() []*transport.Interface {
	iface := transport.NewInterface(net.Interface{Index: 7, Name: "captured-fixture", Flags: net.FlagUp})
	iface.AddAddress(&net.IPNet{IP: net.IPv4(192, 0, 2, 12), Mask: net.CIDRMask(24, 32)})
	return []*transport.Interface{iface}
}
func fixtureOwner(t *testing.T, resolve Resolve) *Network {
	t.Helper()
	lower, err := mobiletor.NewNetwork(context.Background(), func(context.Context, string, string) (net.Conn, error) { return nil, ErrUnsupported }, func(context.Context, string, string) (net.PacketConn, error) { return nil, ErrUnsupported })
	if err != nil {
		t.Fatal(err)
	}
	n, err := New(context.Background(), lower, resolve, fixtureInterfaces())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close(context.Background()); lower.Close(context.Background()) })
	return n
}

func TestCallerCanceledDNSCannotPublishLateAnswer(t *testing.T) {
	entered, release := make(chan context.Context, 1), make(chan struct{})
	n := fixtureOwner(t, func(ctx context.Context, family, host string) ([]netip.Addr, error) {
		if family != "ip4" || host != "captured.invalid" {
			t.Error("captured DNS options changed")
		}
		entered <- ctx
		<-release
		return []netip.Addr{netip.MustParseAddr("192.0.2.31")}, nil
	})
	caller, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		address, err := n.ResolveUDPAddrContext(caller, "udp4", "captured.invalid:3478")
		if address != nil {
			result <- errors.New("late DNS answer was published")
		} else {
			result <- err
		}
	}()
	lowerCtx := <-entered
	cancel()
	select {
	case <-lowerCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("caller DNS cancellation was not forwarded")
	}
	if n.ctx.Err() != nil {
		t.Fatal("canceling one DNS request closed the whole VPN owner")
	}
	select {
	case err := <-result:
		close(release)
		t.Fatalf("DNS operation was released before its actual callback returned: %v", err)
	default:
	}
	close(release)
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("late DNS callback did not drain")
	}
	if _, err := n.ResolveIPAddr("ip4", "192.0.2.40"); err != nil {
		t.Fatal("active owner could not resolve its next literal", err)
	}
}

func TestSessionCloseRetainsUncooperativeDNS(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	n := fixtureOwner(t, func(context.Context, string, string) ([]netip.Addr, error) {
		close(entered)
		<-release
		return []netip.Addr{netip.MustParseAddr("192.0.2.99")}, nil
	})
	result := make(chan error, 1)
	go func() {
		address, err := n.ResolveUDPAddr("udp4", "captured.invalid:3478")
		if address != nil {
			result <- errors.New("closed session adopted a DNS result")
		} else {
			result <- err
		}
	}()
	<-entered
	bounded, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := n.Close(bounded); !errors.Is(err, context.DeadlineExceeded) {
		close(release)
		t.Fatal("DNS owner was released before callback drain", err)
	}
	select {
	case <-n.done:
		close(release)
		t.Fatal("DNS owner falsely marked shutdown complete")
	default:
	}
	close(release)
	if err := <-result; !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if err := n.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := n.ResolveUDPAddr("udp4", "after-close.invalid:3478"); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

func TestInterfaceSnapshotAndNoFallbackConfiguration(t *testing.T) {
	n := fixtureOwner(t, func(context.Context, string, string) ([]netip.Addr, error) {
		t.Error("unexpected DNS operation")
		return nil, ErrUnsupported
	})
	first, err := n.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	first[0].Name = "changed"
	addresses, _ := first[0].Addrs()
	addresses[0].(*net.IPNet).IP[0] = 0
	again, err := n.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	addresses, _ = again[0].Addrs()
	if again[0].Name != "captured-fixture" || !addresses[0].(*net.IPNet).IP.Equal(net.IPv4(192, 0, 2, 12)) {
		t.Fatal("caller mutated captured interface snapshot")
	}
	if _, err := n.Dial("unix", "/tmp/unowned"); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := n.ListenTCP("tcp", nil); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := n.CreateDialer(&net.Dialer{Resolver: &net.Resolver{}}).Dial("tcp", "192.0.2.1:443"); !errors.Is(err, ErrUnsupported) {
		t.Fatal("custom resolver escaped network capture", err)
	}
	if _, err := n.CreateListenConfig(&net.ListenConfig{KeepAlive: time.Second}).ListenPacket(context.Background(), "udp4", "0.0.0.0:0"); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := n.ListenUDP("udp4", &net.UDPAddr{Port: 1234}); !errors.Is(err, ErrUnsupported) {
		t.Fatal("source port binding was invented", err)
	}
}

func TestRealCapturedUDPAndTCPUseOnlySuppliedDNS(t *testing.T) {
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udpDone, tcpDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(udpDone)
		var b [256]byte
		count, addr, err := udp.ReadFrom(b[:])
		if err == nil {
			_, _ = udp.WriteTo(b[:count], addr)
		}
	}()
	go func() {
		defer close(tcpDone)
		conn, err := tcp.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
	var queries, dials, listens atomic.Int32
	lower, err := mobiletor.NewNetwork(context.Background(), func(ctx context.Context, kind, address string) (net.Conn, error) {
		dials.Add(1)
		if strings.Contains(address, "captured.invalid") {
			return nil, errors.New("unresolved captured destination")
		}
		return (&net.Dialer{}).DialContext(ctx, kind, address)
	}, func(ctx context.Context, kind, address string) (net.PacketConn, error) {
		listens.Add(1)
		return (&net.ListenConfig{}).ListenPacket(ctx, kind, address)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lower.Close(context.Background())
	n, err := New(context.Background(), lower, func(ctx context.Context, family, host string) ([]netip.Addr, error) {
		queries.Add(1)
		if host != "captured.invalid" {
			return nil, ErrUnsupported
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}, fixtureInterfaces())
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close(context.Background())
	_, port, _ := net.SplitHostPort(udp.LocalAddr().String())
	remote, err := n.ResolveUDPAddr("udp4", "captured.invalid:"+port)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := n.DialUDP("udp4", nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	packet.SetDeadline(time.Now().Add(time.Second))
	if _, err = packet.Write([]byte("captured UDP")); err != nil {
		t.Fatal(err)
	}
	var data [64]byte
	count, err := packet.Read(data[:])
	if err != nil || string(data[:count]) != "captured UDP" {
		t.Fatal("captured UDP payload failed", err)
	}
	packet.Close()
	<-udpDone
	_, port, _ = net.SplitHostPort(tcp.Addr().String())
	connection, err := n.DialContext(context.Background(), "tcp4", "captured.invalid:"+port)
	if err != nil {
		t.Fatal(err)
	}
	connection.SetDeadline(time.Now().Add(time.Second))
	if _, err = connection.Write([]byte("captured TCP")); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(connection, data[:12]); err != nil || string(data[:12]) != "captured TCP" {
		t.Fatal("captured TCP payload failed", err)
	}
	connection.Close()
	<-tcpDone
	if queries.Load() != 2 || dials.Load() != 1 || listens.Load() != 1 {
		t.Fatal("traffic bypassed captured DNS/TCP/UDP callbacks")
	}
}
