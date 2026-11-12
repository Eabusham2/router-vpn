package startwhitening

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type carrierCloseWitness struct {
	net.Conn
	calls atomic.Int32
	err   error
}

func (c *carrierCloseWitness) Close() error {
	c.calls.Add(1)
	if c.Conn != nil {
		c.err = c.Conn.Close()
	}
	return c.err
}

// The existing lower owner closes its original descriptor exactly once. TLS
// still owns its alert state, so a later TLS Close observes the retired writer.
type carrierCloseOnce struct {
	net.Conn
	once sync.Once
	err  error
}

func (c *carrierCloseOnce) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close() })
	return c.err
}

func TestCancelledOwnerJoinsAlreadyRetiredTLSCarrier(t *testing.T) {
	const payload = "original TLS carrier"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, payload)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	physical, err := (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	lower := &carrierCloseOnce{Conn: physical}
	defer lower.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	secure := tls.Client(lower, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
	deadline, _ := ctx.Deadline()
	if err := secure.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := secure.HandshakeContext(ctx); err != nil {
		t.Fatal("actual captured TLS carrier handshake", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Write(secure); err != nil {
		t.Fatal("original TLS request", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(secure), request)
	if err != nil {
		t.Fatal("original TLS response", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1024))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || string(body) != payload {
		t.Fatal("original TLS carrier did not exchange its actual payload", readErr, closeErr)
	}
	witness := &carrierCloseWitness{Conn: secure}
	owner := NewOwner(ctx)
	defer owner.Close()
	raw, err := owner.Open(ctx, [32]byte{9}, false, func(context.Context) (net.Conn, error) { return witness, nil })
	if err != nil {
		t.Fatal(err)
	}
	cipher := &statefulCipher{Conn: raw}
	authenticated, err := OwnAuthenticatedStream(raw, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if err := lower.Close(); err != nil {
		t.Fatal("original lower owner did not retire its descriptor", err)
	}
	cancel()
	for range 2 {
		if err := owner.Close(); err != nil {
			t.Fatal("joined TLS carrier reported only its already-closed writer as a teardown failure", err)
		}
	}
	if !errors.Is(witness.err, net.ErrClosed) || !strings.Contains(witness.err.Error(), "closeNotify") {
		t.Fatal("real TLS did not exercise its alert after lower-owner retirement", witness.err)
	}
	if witness.calls.Load() != 1 || cipher.closed.Load() != 1 || len(owner.conns) != 0 || raw.key != [32]byte{} {
		t.Fatal("cancelled carrier repeated cleanup or retained cipher/key ownership")
	}
	if n, err := authenticated.Write([]byte("retired")); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatal("joined carrier accepted another authenticated write", n, err)
	}
	t.Log("actual TLS close cause retained by witness:", witness.err)
}

type carrierUnusualJoin struct{ children []error }

func (*carrierUnusualJoin) Error() string     { return "unusual carrier close" }
func (e *carrierUnusualJoin) Unwrap() []error { return e.children }

type carrierUnwrapCycle struct{}

func (*carrierUnwrapCycle) Error() string   { return "cyclic carrier close" }
func (e *carrierUnwrapCycle) Unwrap() error { return e }

func TestCarrierCloseRetainsEveryNonClosedCause(t *testing.T) {
	failure := errors.New("physical carrier release failed")
	wrapped := fmt.Errorf("TLS close alert: %w", net.ErrClosed)
	deep := error(net.ErrClosed)
	for range 33 {
		deep = fmt.Errorf("layer: %w", deep)
	}
	for _, test := range []struct {
		name   string
		err    error
		closed bool
	}{
		{"nil", nil, true}, {"closed", net.ErrClosed, true}, {"wrapped", wrapped, true},
		{"joined-closed", errors.Join(net.ErrClosed, wrapped), true},
		{"mixed", errors.Join(wrapped, failure), false}, {"real", failure, false},
		{"timeout", os.ErrDeadlineExceeded, false},
		{"closed-and-timeout", errors.Join(net.ErrClosed, os.ErrDeadlineExceeded), false},
		{"nil-wrapper", &carrierUnusualJoin{[]error{nil}}, false},
		{"nil-and-closed", &carrierUnusualJoin{[]error{nil, net.ErrClosed}}, false},
		{"empty-wrapper", &carrierUnusualJoin{}, false},
		{"text", errors.New(net.ErrClosed.Error()), false}, {"deep", deep, false},
		{"cycle", &carrierUnwrapCycle{}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := NewOwner(context.Background())
			defer owner.Close()
			witness := &carrierCloseWitness{err: test.err}
			raw, err := owner.Open(context.Background(), [32]byte{9}, false, func(context.Context) (net.Conn, error) { return witness, nil })
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				err := owner.Close()
				if (err == nil) != test.closed || !test.closed && raw.closeErr != test.err {
					t.Fatal("carrier close discarded an actual or unclassified failure", test.name, err)
				}
			}
			if witness.calls.Load() != 1 || len(owner.conns) != 0 || raw.key != [32]byte{} {
				t.Fatal("carrier result bypassed the joined original cleanup")
			}
		})
	}
}

// Expire the actual socket writer at the closeNotify write boundary. This
// deterministically schedules a cancellation deadline before the alert write;
// the wrapper never synthesizes a timeout or bypasses the original TCP socket.
func TestCancelledOwnerJoinsExpiredTLSWriter(t *testing.T) {
	for _, scenario := range []string{"direct-tls", "opaque-wrapper", "lower-close-failure", "lower-close-timeout"} {
		t.Run(scenario, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "original expired-writer carrier")
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			physical, err := (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer physical.Close()
			lower := &tlsCloseResultCarrier{Conn: physical}
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			secure := tls.Client(lower, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
			deadline, _ := ctx.Deadline()
			if err := secure.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if err := secure.HandshakeContext(ctx); err != nil {
				t.Fatal(err)
			}
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := request.Write(secure); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(secure), request)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
			if err != nil {
				t.Fatal(err)
			}
			if err := response.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusOK || string(body) != "original expired-writer carrier" {
				t.Fatal("original TLS exchange failed")
			}
			lower.expire.Store(true)
			var captured net.Conn = secure
			if scenario == "opaque-wrapper" {
				captured = &carrierCloseWitness{Conn: secure}
			}
			failure := errors.New("original lower close failed")
			if scenario == "lower-close-timeout" {
				failure = os.ErrDeadlineExceeded
			}
			if strings.HasPrefix(scenario, "lower-close-") {
				lower.failure = failure
			}
			owner := NewOwner(ctx)
			defer owner.Close()
			raw, err := owner.Open(ctx, [32]byte{9}, false, func(context.Context) (net.Conn, error) { return captured, nil })
			if err != nil {
				t.Fatal(err)
			}
			cipher := &statefulCipher{Conn: raw}
			authenticated, err := OwnAuthenticatedStream(raw, cipher)
			if err != nil {
				t.Fatal(err)
			}
			cancel()
			for range 2 {
				err := owner.Close()
				switch scenario {
				case "direct-tls":
					if err != nil {
						t.Fatal("closed original TLS carrier retained its alert writer timeout", err)
					}
				case "opaque-wrapper":
					if !errors.Is(err, os.ErrDeadlineExceeded) || !strings.Contains(err.Error(), "closeNotify") {
						t.Fatal("opaque TLS timeout was discarded", err)
					}
				case "lower-close-failure", "lower-close-timeout":
					if !errors.Is(err, failure) {
						t.Fatal("original lower close failure was discarded", err)
					}
				}
			}
			if lower.writes.Load() != 1 {
				t.Fatal("missing actual TLS close alert write")
			}
			if scenario == "opaque-wrapper" && !errors.Is(lower.writeErr, os.ErrDeadlineExceeded) {
				t.Fatal("real alert writer did not expire", lower.writeErr)
			}
			if lower.failure != nil {
				// The original close refused without retiring its descriptor. The
				// owner must preserve that failure, not certify terminal cleanup.
				if err := physical.SetWriteDeadline(time.Time{}); err != nil {
					t.Fatal("failed-close control unexpectedly retired the socket", err)
				}
				if err := physical.Close(); err != nil {
					t.Fatal("fixture could not retire its failed-close control", err)
				}
			}
			if n, err := physical.Write([]byte("retired")); n != 0 || !errors.Is(err, net.ErrClosed) {
				t.Fatal("physical TLS socket was not retired", n, err)
			}
			if cipher.closed.Load() != 1 || len(owner.conns) != 0 || raw.key != [32]byte{} {
				t.Fatal("TLS teardown retained cipher/key ownership")
			}
			if n, err := authenticated.Write([]byte("retired")); n != 0 || !errors.Is(err, net.ErrClosed) {
				t.Fatal("authenticated write survived teardown", n, err)
			}
		})
	}
}

type tlsCloseResultCarrier struct {
	net.Conn
	failure  error
	expire   atomic.Bool
	writes   atomic.Int32
	writeErr error
}

func (c *tlsCloseResultCarrier) Close() error {
	if c.failure != nil {
		return c.failure
	}
	return c.Conn.Close()
}

func (c *tlsCloseResultCarrier) Write(p []byte) (int, error) {
	if !c.expire.Load() {
		return c.Conn.Write(p)
	}
	c.writes.Add(1)
	_ = c.Conn.SetWriteDeadline(time.Now().Add(-time.Second))
	n, err := c.Conn.Write(p)
	c.writeErr = err
	return n, err
}
