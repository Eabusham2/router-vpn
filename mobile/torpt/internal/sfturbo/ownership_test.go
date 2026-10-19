package turbotunnel

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var fixtureAddr = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}

func await(t *testing.T, signal <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal(what)
	}
}

// This same test also runs against the unchanged source from the verified
// upstream module ZIP. It must expose the original uncanceled pending dial.
func TestCloseCancelsPendingDialAndJoins(t *testing.T) {
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer close(release)
	conn := NewRedialPacketConn(fixtureAddr, fixtureAddr, func(ctx context.Context) (net.PacketConn, error) {
		close(entered)
		select {
		case <-ctx.Done():
			close(canceled)
			return nil, ctx.Err()
		case <-release:
			return nil, errors.New("test cleanup")
		}
	})
	await(t, entered, "dial did not begin")
	done := make(chan struct{})
	go func() { _ = conn.Close(); close(done) }()
	select {
	case <-canceled:
	case <-time.After(150 * time.Millisecond):
		t.Fatal("Snowflake Close left the pending dial context active")
	}
	await(t, done, "Close did not join canceled dial")
}

type ownedFixturePacket struct {
	closed       chan struct{}
	once         sync.Once
	closes       atomic.Int32
	readEntered  chan struct{}
	writeEntered chan struct{}
	writeRelease chan struct{}
	active       atomic.Int32
}

func newFixturePacket() *ownedFixturePacket {
	return &ownedFixturePacket{closed: make(chan struct{}), readEntered: make(chan struct{}),
		writeEntered: make(chan struct{}), writeRelease: make(chan struct{})}
}
func (p *ownedFixturePacket) Close() error {
	p.once.Do(func() { p.closes.Add(1); close(p.closed) })
	return nil
}
func (p *ownedFixturePacket) ReadFrom([]byte) (int, net.Addr, error) {
	p.active.Add(1)
	defer p.active.Add(-1)
	close(p.readEntered)
	<-p.closed
	return 0, nil, net.ErrClosed
}
func (p *ownedFixturePacket) WriteTo([]byte, net.Addr) (int, error) {
	p.active.Add(1)
	defer p.active.Add(-1)
	close(p.writeEntered)
	<-p.writeRelease // Model a real lower operation that is slow to stop.
	return 0, net.ErrClosed
}
func (p *ownedFixturePacket) LocalAddr() net.Addr              { return fixtureAddr }
func (p *ownedFixturePacket) SetDeadline(time.Time) error      { return nil }
func (p *ownedFixturePacket) SetReadDeadline(time.Time) error  { return nil }
func (p *ownedFixturePacket) SetWriteDeadline(time.Time) error { return nil }

func TestCloseRetainsLateDialSuccess(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	packet := newFixturePacket()
	conn := NewRedialPacketConn(fixtureAddr, fixtureAddr, func(context.Context) (net.PacketConn, error) {
		close(entered)
		<-release
		return packet, nil
	})
	await(t, entered, "dial did not begin")
	done := make(chan struct{})
	go func() { _ = conn.Close(); close(done) }()
	select {
	case <-done:
		close(release)
		t.Fatal("Snowflake Close released a pending dial before its late socket drained")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	await(t, done, "late success was not joined")
	if packet.closes.Load() != 1 || packet.active.Load() != 0 {
		t.Fatal("late packet connection was published or not closed exactly once")
	}
}

func TestCloseJoinsBothPacketPumps(t *testing.T) {
	packet := newFixturePacket()
	conn := NewRedialPacketConn(fixtureAddr, fixtureAddr, func(context.Context) (net.PacketConn, error) { return packet, nil })
	await(t, packet.readEntered, "packet read did not begin")
	if _, err := conn.WriteTo([]byte("payload"), fixtureAddr); err != nil {
		t.Fatal(err)
	}
	await(t, packet.writeEntered, "packet write did not begin")
	done := make(chan struct{})
	go func() { _ = conn.Close(); close(done) }()
	select {
	case <-done:
		close(packet.writeRelease)
		t.Fatal("Snowflake Close released an active packet pump")
	case <-time.After(30 * time.Millisecond):
	}
	close(packet.writeRelease)
	await(t, done, "packet pumps did not drain")
	if packet.active.Load() != 0 || packet.closes.Load() != 1 {
		t.Fatal("packet pumps remain active")
	}
	if _, err := conn.WriteTo([]byte("after-close"), fixtureAddr); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}
