package startwhitening

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Mimics lazy cipher state publication AFTER socket I/O finishes, as in the
// pinned SS2022 implementation. Close must not inspect it until I/O drains.
type lazyStream struct {
	net.Conn
	reading        chan struct{}
	writing        chan struct{}
	publishedRead  int
	publishedWrite int
	closes         atomic.Int64
	closedSawRead  int
	closedSawWrite int
}

func (c *lazyStream) Read(p []byte) (int, error) {
	close(c.reading)
	n, e := c.Conn.Read(p)
	c.publishedRead = 1
	return n, e
}
func (c *lazyStream) Write(p []byte) (int, error) {
	close(c.writing)
	n, e := c.Conn.Write(p)
	c.publishedWrite = 1
	return n, e
}
func (c *lazyStream) Close() error {
	c.closes.Add(1)
	c.closedSawRead = c.publishedRead
	c.closedSawWrite = c.publishedWrite
	return c.Conn.Close()
}
func (c *lazyStream) NeedHandshake() bool { return c.publishedWrite == 0 }
func waitStream(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("owned stream did not settle")
	}
}
func TestStreamGuardInterruptsBothDirectionsBeforeCipherRelease(t *testing.T) {
	for trial := 0; trial < 20; trial++ {
		a, b := net.Pipe()
		cipher := &lazyStream{Conn: a, reading: make(chan struct{}), writing: make(chan struct{})}
		g := GuardAuthenticatedStream(a, cipher)
		if !g.NeedHandshake() {
			t.Fatal("lazy handshake capability lost")
		}
		readDone, writeDone := make(chan struct{}), make(chan struct{})
		go func() { defer close(readDone); _, _ = g.Read(make([]byte, 8)) }()
		go func() { defer close(writeDone); _, _ = g.Write([]byte("blocked")) }()
		waitStream(t, cipher.reading)
		waitStream(t, cipher.writing)
		var callers sync.WaitGroup
		for i := 0; i < 32; i++ {
			callers.Add(1)
			go func() { defer callers.Done(); _ = g.Close() }()
		}
		finished := make(chan struct{})
		go func() { callers.Wait(); close(finished) }()
		waitStream(t, finished)
		waitStream(t, readDone)
		waitStream(t, writeDone)
		b.Close()
		if cipher.closes.Load() != 1 || cipher.closedSawRead != 1 || cipher.closedSawWrite != 1 {
			t.Fatal("cipher state released during active I/O")
		}
		if _, e := g.Write([]byte("after")); !errors.Is(e, net.ErrClosed) {
			t.Fatal("closed writer reopened")
		}
		if _, e := g.Read(make([]byte, 1)); !errors.Is(e, net.ErrClosed) {
			t.Fatal("closed reader reopened")
		}
		if g.NeedHandshake() {
			t.Fatal("closed stream requests a handshake")
		}
	}
}
func TestStreamGuardKeepsDeadlinesBytesAndAddresses(t *testing.T) {
	a, b := net.Pipe()
	g := GuardAuthenticatedStream(a, a)
	defer g.Close()
	defer b.Close()
	if g.LocalAddr() != a.LocalAddr() || g.RemoteAddr() != a.RemoteAddr() {
		t.Fatal("address changed")
	}
	if e := g.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); e != nil {
		t.Fatal(e)
	}
	if _, e := g.Read(make([]byte, 1)); e == nil {
		t.Fatal("read deadline ignored")
	}
	if e := g.SetDeadline(time.Time{}); e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = b.Write([]byte("auth-bytes")) }()
	received := make([]byte, 10)
	if _, e := io.ReadFull(g, received); e != nil || string(received) != "auth-bytes" {
		t.Fatal("payload changed", e)
	}
	waitStream(t, done)
	if e := g.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); e != nil {
		t.Fatal(e)
	}
	if _, e := g.Write([]byte("blocked")); e == nil {
		t.Fatal("write deadline ignored")
	}
	if _, ok := any(g).(interface{ Upstream() any }); ok {
		t.Fatal("unsafe cipher bypass exposed")
	}
}
