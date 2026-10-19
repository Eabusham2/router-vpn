package meeklite

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
)

// This test also runs unchanged against the exact upstream package as a
// negative control: upstream Close leaves the blocked Write asleep forever.
func TestMeekCloseDrainsBackpressuredReaderAndWriter(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		requests.Add(1)
		w.Write([]byte("buffered peer data"))
	}))
	defer server.Close()
	args := pt.Args{"url": []string{"http://bridge.example/owned-meek-fixture"}, "front": []string{"front.example"}}
	parsed, err := newClientArgs(&args)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := newMeekConn("tcp", "192.0.2.20:80", func(network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(context.Background(), "tcp", server.Listener.Addr().String())
	}, parsed)
	if err != nil {
		t.Fatal(err)
	}
	c := connection.(*meekConn)
	defer connection.Close()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for requests.Load() <= maxChanBacklog || len(c.workerRdChan) < maxChanBacklog {
		select {
		case <-deadline.C:
			t.Fatal("real HTTP worker did not fill the unread data queue")
		case <-time.After(time.Millisecond):
		}
	}
	written := make(chan struct{})
	go func() {
		defer close(written)
		for i := 0; i < maxChanBacklog*2; i++ {
			if _, err := connection.Write([]byte("queued application bytes")); err != nil {
				return
			}
		}
	}()
	for len(c.workerWrChan) < maxChanBacklog {
		select {
		case <-deadline.C:
			t.Fatal("backpressured HTTP worker did not fill the write queue")
		case <-time.After(time.Millisecond):
		}
	}
	closed := make(chan struct{})
	go func() { connection.Close(); close(closed) }()
	closeDeadline := time.NewTimer(time.Second)
	defer closeDeadline.Stop()
	select {
	case <-closed:
	case <-closeDeadline.C:
		t.Error("meek Close did not join the backpressured worker")
	}
	select {
	case <-written:
	case <-time.After(250 * time.Millisecond):
		t.Error("meek Close left a backpressured application Write blocked")
		// Release the intentionally broken upstream negative control after
		// recording its failure, so the fixture itself does not leak workers.
		for {
			select {
			case <-written:
				return
			case <-c.workerRdChan:
			case <-time.After(time.Second):
				return
			}
		}
	}
}
