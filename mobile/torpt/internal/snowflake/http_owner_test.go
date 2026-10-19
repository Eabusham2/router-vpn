package snowflake_client

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/transport/v4"
	"router-vpn/internal/mobiletor"
	"router-vpn/mobile/torpt/internal/pionnet"
)

type brokerOwnerFixture struct {
	readEntered, writeEntered, closeEntered chan struct{}
	readRelease, writeRelease, closeRelease chan struct{}
	readOnce, writeOnce, closeOnce          sync.Once
	reads, writes, closes, deadlines        atomic.Int32
	active                                  atomic.Int32
	closeErr                                error
}

func newBrokerOwnerFixture() *brokerOwnerFixture {
	return &brokerOwnerFixture{readEntered: make(chan struct{}), writeEntered: make(chan struct{}),
		closeEntered: make(chan struct{}), readRelease: make(chan struct{})}
}
func (c *brokerOwnerFixture) Read([]byte) (int, error) {
	c.reads.Add(1)
	c.active.Add(1)
	defer c.active.Add(-1)
	c.readOnce.Do(func() { close(c.readEntered) })
	<-c.readRelease
	return 0, net.ErrClosed
}
func (c *brokerOwnerFixture) Write(b []byte) (int, error) {
	c.writes.Add(1)
	c.active.Add(1)
	defer c.active.Add(-1)
	c.writeOnce.Do(func() { close(c.writeEntered) })
	if c.writeRelease != nil {
		<-c.writeRelease
		return 0, net.ErrClosed
	}
	return len(b), nil
}
func (c *brokerOwnerFixture) Close() error {
	c.closes.Add(1)
	c.closeOnce.Do(func() { close(c.closeEntered) })
	if c.closeRelease != nil {
		<-c.closeRelease
	}
	return c.closeErr
}
func (*brokerOwnerFixture) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10101}
}
func (*brokerOwnerFixture) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}
}
func (c *brokerOwnerFixture) SetDeadline(time.Time) error      { c.deadlines.Add(1); return nil }
func (c *brokerOwnerFixture) SetReadDeadline(time.Time) error  { c.deadlines.Add(1); return nil }
func (c *brokerOwnerFixture) SetWriteDeadline(time.Time) error { c.deadlines.Add(1); return nil }

func brokerAwait(t *testing.T, signal <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal(label)
	}
}
func brokerPending(t *testing.T, result <-chan error, label string) {
	t.Helper()
	select {
	case err := <-result:
		t.Fatalf("%s: %v", label, err)
	case <-time.After(30 * time.Millisecond):
	}
}

// This is the independent review's original failure: net/http can return on
// cancellation while its asynchronous TLS read still runs. Both lower network
// close barriers may finish, but the exchange and broker close must retain it.
func TestBrokerDefaultTLSCloseJoinsHandshake(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	raw := newBrokerOwnerFixture()
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(raw.readRelease) })
	lower, err := mobiletor.NewNetwork(ctx,
		func(context.Context, string, string) (net.Conn, error) { return raw, nil },
		func(context.Context, string, string) (net.PacketConn, error) {
			return nil, errors.New("no fixture UDP")
		})
	if err != nil {
		t.Fatal(err)
	}
	owned, err := pionnet.New(ctx, lower, func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	}, []*transport.Interface{})
	if err != nil {
		t.Fatal(err)
	}
	broker, err := newHTTPRendezvous("https://broker.example/", []string{"front.example"}, "", owned.DialContext)
	if err != nil {
		t.Fatal(err)
	}
	exchange := make(chan error, 1)
	go func() { _, err := broker.Exchange(ctx, []byte("fixture")); exchange <- err }()
	brokerAwait(t, raw.readEntered, "TLS read did not begin")
	cancel()
	brokerAwait(t, raw.closeEntered, "cancellation did not close TLS socket")
	brokerPending(t, exchange, "broker released its actual TLS handshake reader")
	closed := make(chan error, 1)
	go func() { broker.Close(); closed <- nil }()
	brokerPending(t, closed, "broker Close released its actual TLS handshake reader")
	releaseOnce.Do(func() { close(raw.readRelease) })
	if err := <-exchange; err == nil {
		t.Fatal("canceled broker exchange succeeded")
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if err := owned.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lower.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if raw.active.Load() != 0 || raw.closes.Load() != 1 {
		t.Fatal("TLS read or socket was not retired exactly once")
	}
}
