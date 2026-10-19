package smux

import (
	"io"
	"sync"
	"testing"
	"time"
)

type heldStream struct {
	entered, closed, release, exited chan struct{}
	once                             sync.Once
}

func (c *heldStream) Read([]byte) (int, error) {
	close(c.entered)
	<-c.closed
	<-c.release
	close(c.exited)
	return 0, io.ErrClosedPipe
}
func (c *heldStream) Write(p []byte) (int, error) { return len(p), nil }
func (c *heldStream) Close() error                { c.once.Do(func() { close(c.closed) }); return nil }

func TestSmuxShutdownRetainsActualStreamReader(t *testing.T) {
	conn := &heldStream{entered: make(chan struct{}), closed: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
	cfg := DefaultConfig()
	cfg.Version = 2
	session, err := Client(conn, cfg)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-conn.entered:
	case <-time.After(time.Second):
		t.Fatal("smux reader did not begin")
	}
	done := make(chan struct{})
	go func() {
		session.Close()
		if joiner, ok := any(session).(interface{ WaitClosed() }); ok {
			joiner.WaitClosed()
		}
		close(done)
	}()
	select {
	case <-done:
		close(conn.release)
		t.Fatal("smux shutdown released its still-running stream reader")
	case <-time.After(30 * time.Millisecond):
	}
	close(conn.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("smux stream reader did not drain")
	}
	select {
	case <-conn.exited:
	default:
		t.Fatal("smux reader exit was not joined")
	}
}
