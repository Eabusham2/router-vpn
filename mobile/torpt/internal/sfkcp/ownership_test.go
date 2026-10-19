package kcp

import (
	"net"
	"sync"
	"testing"
	"time"
)

type heldPacket struct {
	entered chan struct{}
	closed  chan struct{}
	release chan struct{}
	exited  chan struct{}
	once    sync.Once
}

func (p *heldPacket) ReadFrom([]byte) (int, net.Addr, error) {
	close(p.entered)
	<-p.closed
	<-p.release
	close(p.exited)
	return 0, nil, net.ErrClosed
}
func (p *heldPacket) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (p *heldPacket) Close() error                              { p.once.Do(func() { close(p.closed) }); return nil }
func (p *heldPacket) LocalAddr() net.Addr                       { return &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443} }
func (p *heldPacket) SetDeadline(time.Time) error               { return nil }
func (p *heldPacket) SetReadDeadline(time.Time) error           { return nil }
func (p *heldPacket) SetWriteDeadline(time.Time) error          { return nil }

// The unchanged upstream fixture uses the same test; its ordinary Close has
// no join hook and therefore returns while the actual packet reader is alive.
func TestKCPShutdownRetainsActualPacketReader(t *testing.T) {
	p := &heldPacket{entered: make(chan struct{}), closed: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
	session, err := NewConn2(p.LocalAddr(), nil, 0, 0, p)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.entered:
	case <-time.After(time.Second):
		t.Fatal("KCP reader did not begin")
	}
	done := make(chan struct{})
	go func() {
		session.Close()
		p.Close()
		if joiner, ok := any(session).(interface{ WaitClosed() }); ok {
			joiner.WaitClosed()
		}
		close(done)
	}()
	select {
	case <-done:
		close(p.release)
		t.Fatal("KCP shutdown released its still-running packet reader")
	case <-time.After(30 * time.Millisecond):
	}
	close(p.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("KCP packet reader did not drain")
	}
	select {
	case <-p.exited:
	default:
		t.Fatal("KCP reader exit was not joined")
	}
}
