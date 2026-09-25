package applexray

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakePacketIO struct {
	read    chan packet
	writes  chan packet
	done    chan struct{}
	unblock chan struct{}
	entered chan struct{}
	once    sync.Once
	block   bool
	closes  atomic.Int32
}

func fakePackets(block bool) *fakePacketIO {
	return &fakePacketIO{read: make(chan packet, 16), writes: make(chan packet, 16), done: make(chan struct{}), unblock: make(chan struct{}), entered: make(chan struct{}, 1), block: block}
}
func (f *fakePacketIO) ReadPacket() ([]byte, net.Addr, error) {
	select {
	case <-f.done:
		return nil, nil, net.ErrClosed
	case v := <-f.read:
		return v.data, v.addr, v.err
	}
}
func (f *fakePacketIO) WritePacket(b []byte, a net.Addr) error {
	select {
	case f.entered <- struct{}{}:
	default:
	}
	if f.block {
		select {
		case <-f.unblock:
		case <-f.done:
			return net.ErrClosed
		}
	}
	select {
	case <-f.done:
		return net.ErrClosed
	case f.writes <- packet{data: append([]byte(nil), b...), addr: a}:
		return nil
	}
}
func (f *fakePacketIO) Close() error {
	f.once.Do(func() { f.closes.Add(1); close(f.done) })
	return nil
}
func wait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("operation did not complete")
	}
}
func TestPacketDeadlineAndCancellation(t *testing.T) {
	f := fakePackets(false)
	ctx, cancel := context.WithCancel(context.Background())
	p := NewPacketConn(ctx, f)
	defer p.Close()
	if err := p.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.ReadFrom(make([]byte, 64)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("read deadline ineffective", err)
	}
	if err := p.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	f.read <- packet{data: []byte("after deadline"), addr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}}
	b := make([]byte, 100)
	n, _, err := p.ReadFrom(b)
	if err != nil || string(b[:n]) != "after deadline" {
		t.Fatal("deadline reset failed")
	}
	blocked := make(chan struct{})
	go func() { defer close(blocked); _, _, _ = p.ReadFrom(b) }()
	cancel()
	wait(t, blocked)
	wait(t, f.done)
	if _, err := p.WriteTo([]byte("late"), &net.UDPAddr{}); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed write accepted")
	}
	if err := p.SetDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed setter accepted")
	}
}
func TestPacketSupportsJumboAndPreservesDestinations(t *testing.T) {
	f := fakePackets(false)
	p := NewPacketConn(context.Background(), f)
	defer p.Close()
	for _, size := range []int{0, 64, 8192, 9000, 65535} {
		b := bytes.Repeat([]byte{byte(size)}, size)
		addr := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}
		if n, err := p.WriteTo(b, addr); err != nil || n != size {
			t.Fatal("packet truncated", size, n, err)
		}
		v := <-f.writes
		if !bytes.Equal(v.data, b) || v.addr.String() != addr.String() {
			t.Fatal("packet or destination changed")
		}
		f.read <- v
		out := make([]byte, size)
		if n, a, err := p.ReadFrom(out); err != nil || n != size || a.String() != addr.String() || !bytes.Equal(out, b) {
			t.Fatal("packet receive changed", size, err)
		}
	}
	if _, err := p.WriteTo(make([]byte, 65536), &net.UDPAddr{}); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatal("oversized UDP accepted")
	}
}
func TestPacketWriteTimeoutClosesExactRay(t *testing.T) {
	f := fakePackets(true)
	p := NewPacketConn(context.Background(), f)
	defer p.Close()
	_ = p.SetWriteDeadline(time.Now().Add(15 * time.Millisecond))
	if _, err := p.WriteTo([]byte("must-not-reappear"), &net.UDPAddr{Port: 53}); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("timeout missing", err)
	}
	wait(t, f.done)
	close(f.unblock)
	select {
	case <-f.writes:
		t.Fatal("expired queued write survived teardown")
	case <-time.After(10 * time.Millisecond):
	}
	if f.closes.Load() != 1 {
		t.Fatal("ray closed more than once")
	}
}
func TestPacketChangingDeadlineUnblocksPendingRead(t *testing.T) {
	f := fakePackets(false)
	p := NewPacketConn(context.Background(), f)
	defer p.Close()
	done := make(chan struct{})
	go func() { defer close(done); _, _, _ = p.ReadFrom(make([]byte, 10)) }()
	_ = p.SetReadDeadline(time.Now().Add(-time.Second))
	wait(t, done)
}
func TestPacketEOFDoesNotHangSecondRead(t *testing.T) {
	f := fakePackets(false)
	p := NewPacketConn(context.Background(), f)
	defer p.Close()
	f.read <- packet{err: io.EOF}
	for i := 0; i < 2; i++ {
		_ = p.SetReadDeadline(time.Now().Add(time.Second))
		if _, _, err := p.ReadFrom(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatal("EOF not retained", err)
		}
	}
}
func TestPacketConcurrentDeadlinesAndClose(t *testing.T) {
	f := fakePackets(false)
	p := NewPacketConn(context.Background(), f)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = p.SetDeadline(time.Now().Add(time.Second))
				_ = p.SetReadDeadline(time.Time{})
			}
		}()
	}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = p.Close() }()
	}
	wg.Wait()
	if f.closes.Load() != 1 {
		t.Fatal("multiple backend closes")
	}
}
