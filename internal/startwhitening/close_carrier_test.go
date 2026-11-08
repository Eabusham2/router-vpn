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
