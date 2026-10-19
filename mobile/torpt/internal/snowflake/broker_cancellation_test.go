package snowflake_client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/mobile/torpt/internal/httpowner"
)

// Real TLS and HTTP use this actual TCP socket. Header cases delay a Read
// interrupted by native Close; body cases hold an admitted response Read at the
// socket boundary. Both gates are independent of the HTTP transport and prove
// cancellation retains admitted physical IO through actual completion.
type brokerLaggingRead struct {
	net.Conn
	release      <-chan struct{}
	stalled      chan struct{}
	once         sync.Once
	active       atomic.Int32
	closes       atomic.Int32
	closeErr     error
	afterHeaders *atomic.Bool
}

func (c *brokerLaggingRead) Read(b []byte) (int, error) {
	c.active.Add(1)
	defer c.active.Add(-1)
	if c.afterHeaders != nil && c.afterHeaders.Load() {
		c.once.Do(func() { close(c.stalled) })
		<-c.release
	}
	n, err := c.Conn.Read(b)
	if err != nil || (c.afterHeaders != nil && c.afterHeaders.Load()) {
		c.once.Do(func() { close(c.stalled) })
		<-c.release
	}
	return n, err
}
func (c *brokerLaggingRead) Close() error {
	c.closes.Add(1)
	err := c.Conn.Close()
	if c.closeErr != nil {
		return c.closeErr
	}
	return err
}

func TestBrokerCancellationRetainsActualTLSIO(t *testing.T) {
	for _, hello := range []string{"", "hellochrome_auto"} {
		for _, http2 := range []bool{false, true} {
			for _, phase := range []string{"headers", "body"} {
				name := "default"
				if hello != "" {
					name = "utls"
				}
				if http2 {
					name += "/h2/"
				} else {
					name += "/h1/"
				}
				t.Run(name+phase, func(t *testing.T) {
					testBrokerCancellation(t, hello, http2, phase)
				})
			}
		}
	}
}

func testBrokerCancellation(t *testing.T, hello string, http2 bool, phase string) {
	ctx, cancel := context.WithCancel(context.Background())
	releaseServer, releaseRead := make(chan struct{}), make(chan struct{})
	var serverOnce, readOnce sync.Once
	var receivedHeaders, serverReceived atomic.Bool
	firstByte := make(chan struct{})
	var firstByteOnce sync.Once
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotFirstResponseByte: func() {
		receivedHeaders.Store(true)
		firstByteOnce.Do(func() { close(firstByte) })
	}})
	served := make(chan struct{})
	serverErrors := make(chan string, 4)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.ServerName != "front.example" || r.Host != "broker.example" || r.URL.RequestURI() != "/client?token=fixture" {
			serverErrors <- "captured broker SNI, Host or authenticated path changed"
		}
		if (r.ProtoMajor == 2) != http2 {
			serverErrors <- "broker ALPN did not exercise the expected HTTP version"
		}
		if phase == "body" {
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("partial"))
			w.(http.Flusher).Flush()
		}
		serverReceived.Store(true)
		close(served)
		if phase == "body" {
			select {
			case <-firstByte:
				_, _ = w.Write([]byte("more"))
				w.(http.Flusher).Flush()
			case <-releaseServer:
				return
			}
		}
		<-releaseServer
	}))
	server.EnableHTTP2 = http2
	server.TLS = &tls.Config{Certificates: []tls.Certificate{fixtureCertificate(t, "front.example")}}
	server.StartTLS()
	t.Cleanup(func() {
		cancel()
		readOnce.Do(func() { close(releaseRead) })
		serverOnce.Do(func() { close(releaseServer) })
		server.Close()
	})
	dialed := make(chan *brokerLaggingRead, 1)
	broker, err := newHTTPRendezvous("https://broker.example/?token=fixture", []string{"front.example"}, hello,
		func(call context.Context, kind, address string) (net.Conn, error) {
			if kind != "tcp" || address != "front.example:443" {
				return nil, errors.New("uncaptured fixture broker dial")
			}
			conn, err := (&net.Dialer{}).DialContext(call, "tcp4", server.Listener.Addr().String())
			if err != nil {
				return nil, err
			}
			owned := &brokerLaggingRead{Conn: conn, release: releaseRead, stalled: make(chan struct{})}
			if phase == "body" {
				owned.closeErr = errors.New("private-token=must-not-be-returned")
				owned.afterHeaders = &receivedHeaders
			} else {
				// HTTP/2 may finish a SETTINGS read between the active counter
				// observation and cancellation. Hold the admitted read on either
				// side of the actual TCP call after request receipt, so that race
				// cannot turn an already-finished operation into a false failure.
				owned.afterHeaders = &serverReceived
			}
			dialed <- owned
			return owned, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	exchange := make(chan error, 1)
	go func() { _, err := broker.Exchange(ctx, []byte("actual TLS broker cancellation")); exchange <- err }()
	brokerAwait(t, served, "actual TLS broker did not receive the authenticated request")
	raw := <-dialed
	if phase == "body" {
		brokerAwait(t, firstByte, "broker did not receive the actual TLS response headers")
		brokerAwait(t, raw.stalled, "broker did not enter its owned response body read")
	}
	// After request receipt (and body flush where applicable), let the real
	// client enter its next blocking TCP read before canceling the exchange.
	ticker, deadline := time.NewTicker(time.Millisecond), time.NewTimer(3*time.Second)
	defer ticker.Stop()
	defer deadline.Stop()
	for raw.active.Load() == 0 {
		select {
		case <-ticker.C:
		case err := <-exchange:
			t.Fatal("broker completed before cancellation", err)
		case <-deadline.C:
			t.Fatal("actual broker TLS socket never entered its response read")
		}
	}
	cancel()
	brokerAwait(t, raw.stalled, "broker cancellation did not interrupt the actual TCP read")
	brokerPending(t, exchange, "broker exchange released an actual TLS response reader")
	closed := make(chan error, 1)
	go func() { broker.Close(); closed <- nil }()
	brokerPending(t, closed, "broker Close released an actual TLS response reader")
	readOnce.Do(func() { close(releaseRead) })
	var exchangeErr error
	select {
	case exchangeErr = <-exchange:
	case <-time.After(3 * time.Second):
		t.Fatal("broker did not finish after its actual TLS IO drained")
	}
	if exchangeErr == nil {
		t.Fatal("canceled broker exchange succeeded")
	}
	if phase == "body" && (!errors.Is(exchangeErr, httpowner.ErrClose) || strings.Contains(exchangeErr.Error(), "token")) {
		t.Fatal("broker lost its sticky credential-free close error", exchangeErr)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if raw.active.Load() != 0 || raw.closes.Load() != 1 {
		t.Fatal("actual broker socket IO remained active or native close was repeated")
	}
	if _, err := broker.Exchange(context.Background(), []byte("after-close")); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed broker admitted another exchange", err)
	}
	select {
	case problem := <-serverErrors:
		t.Fatal(problem)
	default:
	}
}
