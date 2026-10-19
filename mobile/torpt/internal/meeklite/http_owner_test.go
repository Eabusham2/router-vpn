package meeklite

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
)

// Like the protocol-worker regressions, the lower Read remains active briefly
// after Close. A socket count reaching zero must not release that real work.
type heldTLSConn struct {
	entered, release chan struct{}
	once             sync.Once
	active, closes   atomic.Int32
}

func (c *heldTLSConn) Read([]byte) (int, error) {
	c.active.Add(1)
	defer c.active.Add(-1)
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return 0, net.ErrClosed
}
func (c *heldTLSConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *heldTLSConn) Close() error                { c.closes.Add(1); return nil }
func (*heldTLSConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10101}
}
func (*heldTLSConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}
}
func (*heldTLSConn) SetDeadline(time.Time) error      { return nil }
func (*heldTLSConn) SetReadDeadline(time.Time) error  { return nil }
func (*heldTLSConn) SetWriteDeadline(time.Time) error { return nil }

// This source also runs unchanged against pinned Lyrebird. Its ordinary Close
// returns while a physical TLS operation remains active, which must fail.
func TestMeekCloseRetainsActualTLSRead(t *testing.T) {
	for _, hello := range []string{"", "hellochrome_auto"} {
		t.Run(hello, func(t *testing.T) {
			lower := &heldTLSConn{entered: make(chan struct{}), release: make(chan struct{})}
			var released sync.Once
			release := func() { released.Do(func() { close(lower.release) }) }
			args := pt.Args{"url": []string{"https://bridge.example/owned-fixture"}, "front": []string{"front.example"}}
			if hello != "" {
				args["utls"] = []string{hello}
			}
			parsed, err := newClientArgs(&args)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := newMeekConn("tcp", "192.0.2.1:443", func(string, string) (net.Conn, error) { return lower, nil }, parsed)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { release(); _ = conn.Close() }()
			_, _ = conn.Write([]byte("start the owned TLS request"))
			select {
			case <-lower.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("meek TLS read did not begin")
			}
			done := make(chan error, 1)
			go func() { done <- conn.Close() }()
			select {
			case <-done:
				t.Fatal("meek Close released an active physical TLS read")
			case <-time.After(30 * time.Millisecond):
			}
			release()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("meek physical TLS read was not joined after returning")
			}
			if lower.active.Load() != 0 || lower.closes.Load() != 1 {
				t.Fatal("meek released a live lower operation or repeated its native close")
			}
		})
	}
}
