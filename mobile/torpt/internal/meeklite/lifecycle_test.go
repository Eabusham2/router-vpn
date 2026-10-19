package meeklite

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
)

func TestMeekCloseCancelsRealHTTPRequestAndJoinsWorker(t *testing.T) {
	entered, exited := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "bridge.example" || r.URL.Path != "/private-meek-fixture" || r.Header.Get("X-Session-Id") == "" {
			t.Error("meek fronting or per-connection session identity changed")
		}
		io.Copy(io.Discard, r.Body)
		close(entered)
		<-r.Context().Done()
		close(exited)
	}))
	defer server.Close()
	args := pt.Args{"url": []string{"http://bridge.example/private-meek-fixture"}, "front": []string{"front.example"}}
	parsed, err := newClientArgs(&args)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := newMeekConn("tcp", "192.0.2.20:80", func(network, address string) (net.Conn, error) {
		if network != "tcp" || address != "front.example:80" {
			t.Error("meek HTTP did not use the captured front dial")
		}
		return (&net.Dialer{}).DialContext(context.Background(), "tcp", server.Listener.Addr().String())
	}, parsed)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	connection.Write([]byte("actual meek POST body"))
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("real meek request did not reach the test front")
	}
	var closers sync.WaitGroup
	closers.Add(8)
	for i := 0; i < 8; i++ {
		go func() { defer closers.Done(); connection.Close() }()
	}
	joined := make(chan struct{})
	go func() { closers.Wait(); close(joined) }()
	select {
	case <-joined:
	case <-time.After(2 * time.Second):
		server.CloseClientConnections()
		t.Fatal("meek request did not cancel on concurrent Close")
	}
	select {
	case <-connection.(*meekConn).workerDoneChan:
	default:
		t.Fatal("meek Close returned while its worker still ran")
	}
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP front still owned the canceled request")
	}
}
