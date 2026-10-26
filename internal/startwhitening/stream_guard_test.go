package startwhitening

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

func TestStreamDialCompletesRequestBeforeConcurrentDuplexPublication(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		conn, err := DialAuthenticatedStream(ctx, raw, func(owned net.Conn) (net.Conn, error) {
			if owned != raw {
				return nil, errors.New("constructor substituted the captured socket")
			}
			if _, err := owned.Write([]byte("request-header")); err != nil {
				return nil, err
			}
			close(entered)
			<-release
			return owned, nil
		})
		done <- result{conn, err}
	}()
	header := make([]byte, len("request-header"))
	if _, err := io.ReadFull(peer, header); err != nil || string(header) != "request-header" {
		t.Fatal("initial request not written", err)
	}
	waitStream(t, entered)
	select {
	case value := <-done:
		if value.conn != nil {
			value.conn.Close()
		}
		t.Fatal("duplex stream exposed before authenticated request publication")
	default:
	}
	releaseOnce.Do(func() { close(release) })
	value := <-done
	if value.err != nil || value.conn == nil {
		t.Fatal(value.err)
	}
	defer value.conn.Close()
	readDone, writeDone := make(chan error, 1), make(chan error, 1)
	go func() {
		var response [1]byte
		_, err := value.conn.Read(response[:])
		if err == nil && response[0] != 'R' {
			err = errors.New("response changed")
		}
		readDone <- err
	}()
	go func() { _, err := value.conn.Write([]byte("data")); writeDone <- err }()
	peerWrite := make(chan error, 1)
	go func() { _, err := peer.Write([]byte("R")); peerWrite <- err }()
	payload := make([]byte, 4)
	if _, err := io.ReadFull(peer, payload); err != nil || string(payload) != "data" {
		t.Fatal("duplex payload changed", err)
	}
	for _, result := range []<-chan error{readDone, writeDone, peerWrite} {
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	}
}

type streamDelayedClose struct {
	net.Conn
	entered, release chan struct{}
	once             sync.Once
}

func (c *streamDelayedClose) Close() error {
	var err error
	c.once.Do(func() { err = c.Conn.Close(); close(c.entered); <-c.release })
	return err
}
func TestStreamDialCancellationJoinsActualConstructionAndClose(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	closeEntered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	raw := &streamDelayedClose{Conn: a, entered: closeEntered, release: release}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handshakeEntered := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		conn, err := DialAuthenticatedStream(ctx, raw, func(owned net.Conn) (net.Conn, error) {
			close(handshakeEntered)
			_, err := owned.Write([]byte("blocked initial request"))
			return owned, err
		})
		if conn != nil {
			conn.Close()
			done <- errors.New("cancelled constructor published a stream")
			return
		}
		done <- err
	}()
	waitStream(t, handshakeEntered)
	cancel()
	waitStream(t, closeEntered)
	select {
	case err := <-done:
		t.Fatal("constructor acknowledged a still-blocked captured close", err)
	default:
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled constructor lost its owner", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("constructor failed to join after actual close")
	}
}

type streamDeadlineCapture struct {
	net.Conn
	deadlines []time.Time
	failClear bool
}

func (c *streamDeadlineCapture) SetDeadline(value time.Time) error {
	c.deadlines = append(c.deadlines, value)
	if value.IsZero() && c.failClear {
		return errors.New("deadline clear failed")
	}
	return c.Conn.SetDeadline(value)
}
func TestStreamDialRetainsBoundedDeadlineAndFailureCleanup(t *testing.T) {
	for _, kind := range []string{"caller-deadline", "default-bound", "cancelled", "handshake-failed", "missing-stream", "clear-failed"} {
		t.Run(kind, func(t *testing.T) {
			a, b := net.Pipe()
			defer b.Close()
			raw := &streamDeadlineCapture{Conn: a, failClear: kind == "clear-failed"}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "caller-deadline" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, time.Second)
				defer stop()
			}
			if kind == "cancelled" {
				cancel()
			}
			called := false
			before := time.Now()
			conn, err := DialAuthenticatedStream(ctx, raw, func(owned net.Conn) (net.Conn, error) {
				called = true
				if kind == "handshake-failed" {
					return owned, errors.New("handshake failed")
				}
				if kind == "missing-stream" {
					return nil, nil
				}
				return owned, nil
			})
			valid := kind == "caller-deadline" || kind == "default-bound"
			if !valid {
				if err == nil || conn != nil {
					if conn != nil {
						conn.Close()
					}
					t.Fatal("failed authenticated construction published stream")
				}
				if kind == "cancelled" && called {
					t.Fatal("retired context began handshake")
				}
				if _, err := b.Write([]byte("closed")); !errors.Is(err, io.ErrClosedPipe) {
					t.Fatal("construction failure retained its raw socket", err)
				}
				return
			}
			if err != nil || conn == nil {
				t.Fatal(err)
			}
			defer conn.Close()
			bound := before.Add(11 * time.Second)
			if kind == "caller-deadline" {
				bound = before.Add(2 * time.Second)
			}
			if !called || len(raw.deadlines) != 2 || raw.deadlines[0].IsZero() || raw.deadlines[0].After(bound) || !raw.deadlines[1].IsZero() {
				t.Fatal("initial request deadline was absent, widened or retained", raw.deadlines)
			}
		})
	}
}
