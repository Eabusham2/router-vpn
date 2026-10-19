package mobiletor

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCapturedNetworkClosesTCPAndCannotReopenAfterRelease(t *testing.T) {
	var calls atomic.Int32
	var peers []net.Conn
	network, err := NewNetwork(context.Background(), func(ctx context.Context, kind, address string) (net.Conn, error) {
		calls.Add(1)
		if kind != "tcp" || address != "bridge.example:443" {
			t.Error("captured dial arguments changed")
		}
		client, peer := net.Pipe()
		peers = append(peers, peer)
		return client, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := network.DialContext(context.Background(), "tcp", "bridge.example:443"); err != nil {
			t.Fatal(err)
		}
	}
	var closers sync.WaitGroup
	for i := 0; i < 8; i++ {
		closers.Add(1)
		go func() {
			defer closers.Done()
			if err := network.Close(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	closers.Wait()
	for _, peer := range peers {
		var b [1]byte
		if _, err := peer.Read(b[:]); err != io.EOF {
			t.Error("owned peer remained open", err)
		}
		peer.Close()
	}
	if _, err := network.DialContext(context.Background(), "tcp", "bridge.example:443"); !errors.Is(err, net.ErrClosed) {
		t.Fatal("released network reused", err)
	}
	if calls.Load() != 8 {
		t.Fatal("released owner called a fresh dialer")
	}
}

func TestLateProtectedDialStaysOwnedUntilItsSocketCloses(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	client, peer := net.Pipe()
	defer peer.Close()
	network, _ := NewNetwork(context.Background(), func(context.Context, string, string) (net.Conn, error) {
		close(entered)
		<-release
		return client, nil // Deliberately ignores cancellation to exercise the owner boundary.
	}, nil)
	result := make(chan error, 1)
	go func() {
		_, err := network.DialContext(context.Background(), "tcp", "bridge.example:443")
		result <- err
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := network.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("unfinished dial was declared drained", err)
	}
	close(release)
	if err := <-result; !errors.Is(err, net.ErrClosed) {
		t.Fatal("late socket escaped to a new session", err)
	}
	if err := network.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := peer.Read(b[:]); err != io.EOF {
		t.Fatal("late socket remained open", err)
	}
}

func TestNetworkCancellationInterruptsPendingDialAndOpenPackets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pending := make(chan struct{})
	packet := &packetFixture{closed: make(chan struct{})}
	network, _ := NewNetwork(ctx, func(ctx context.Context, kind, address string) (net.Conn, error) {
		close(pending)
		<-ctx.Done()
		return nil, ctx.Err()
	}, func(context.Context, string, string) (net.PacketConn, error) { return packet, nil })
	if !network.HasPackets() {
		t.Fatal("captured UDP capability disappeared")
	}
	if _, err := network.ListenPacket(context.Background(), "udp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	dialDone := make(chan error, 1)
	go func() {
		_, err := network.DialContext(context.Background(), "tcp", "bridge.example:443")
		dialDone <- err
	}()
	<-pending
	cancel()
	if err := network.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-dialDone; !errors.Is(err, context.Canceled) {
		t.Fatal("pending dial ignored session cancellation", err)
	}
	select {
	case <-packet.closed:
	default:
		t.Fatal("packet ownership survived session cancellation")
	}
}

func TestCallerCancellationRejectsLateTCPWithoutClosingSession(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	client, peer := net.Pipe()
	defer peer.Close()
	fresh, freshPeer := net.Pipe()
	defer freshPeer.Close()
	var calls atomic.Int32
	network, _ := NewNetwork(context.Background(), func(context.Context, string, string) (net.Conn, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release // Lower owner intentionally ignores only this caller's cancellation.
			return client, nil
		}
		return fresh, nil
	}, nil)
	defer network.Close(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		connection, err := network.DialContext(ctx, "tcp", "bridge.example:443")
		if connection != nil {
			connection.Close()
			err = errors.New("canceled call delivered its late TCP socket")
		}
		done <- err
	}()
	<-entered
	cancel()
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("caller cancellation was lost", err)
	}
	var b [1]byte
	if _, err := peer.Read(b[:]); err != io.EOF {
		t.Fatal("canceled caller's TCP socket remained open", err)
	}
	connection, err := network.DialContext(context.Background(), "tcp", "bridge.example:443")
	if err != nil {
		t.Fatal("canceling one caller closed the active session", err)
	}
	connection.Close()
}

func TestCallerCancellationRejectsLatePacketsWithoutClosingSession(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	packet := &packetFixture{closed: make(chan struct{})}
	fresh := &packetFixture{closed: make(chan struct{})}
	var calls atomic.Int32
	network, _ := NewNetwork(context.Background(), func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("TCP is not used in this packet boundary test")
	}, func(context.Context, string, string) (net.PacketConn, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
			return packet, nil
		}
		return fresh, nil
	})
	defer network.Close(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		connection, err := network.ListenPacket(ctx, "udp", "127.0.0.1:0")
		if connection != nil {
			connection.Close()
			err = errors.New("canceled call delivered its late packet socket")
		}
		done <- err
	}()
	<-entered
	cancel()
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("packet caller cancellation was lost", err)
	}
	select {
	case <-packet.closed:
	default:
		t.Fatal("canceled caller's packet socket remained open")
	}
	connection, err := network.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("canceling one packet caller closed the active session", err)
	}
	connection.Close()
}

func TestNativeNetworkNeverUsesDefaultHostDialer(t *testing.T) {
	if _, err := NewNetwork(context.Background(), nil, nil); err == nil {
		t.Fatal("missing protected network accepted")
	}
	network, _ := NewNetwork(context.Background(), func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("captured rejection") }, nil)
	defer network.Close(context.Background())
	if _, err := network.DialContext(context.Background(), "tcp", "bridge.example:443"); err == nil {
		t.Fatal("captured failure was replaced by another route")
	}
	if _, err := network.DialContext(context.Background(), "unix", "/tmp/private"); err == nil {
		t.Fatal("non-network socket entered Tor protected owner")
	}
	if _, err := network.ListenPacket(context.Background(), "udp", "127.0.0.1:0"); err == nil {
		t.Fatal("missing packet owner replaced by host network")
	}
}

// Explicit lifecycle fixture; no network protocol or Tor traffic is simulated.
type packetFixture struct {
	closed chan struct{}
	once   sync.Once
}

func (p *packetFixture) Close() error { p.once.Do(func() { close(p.closed) }); return nil }
func (p *packetFixture) ReadFrom([]byte) (int, net.Addr, error) {
	<-p.closed
	return 0, nil, net.ErrClosed
}
func (p *packetFixture) WriteTo([]byte, net.Addr) (int, error) { return 0, net.ErrClosed }
func (p *packetFixture) LocalAddr() net.Addr                   { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (p *packetFixture) SetDeadline(time.Time) error           { return nil }
func (p *packetFixture) SetReadDeadline(time.Time) error       { return nil }
func (p *packetFixture) SetWriteDeadline(time.Time) error      { return nil }
