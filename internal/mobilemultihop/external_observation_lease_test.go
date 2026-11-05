package mobilemultihop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/multihoprelay"
)

type observedLeaseRequestKey struct{}

type observedLeaseExecution struct {
	*observedExecution
	response *httptest.Server
	body     chan struct{}
	cancel   context.CancelFunc
}

func (e *observedLeaseExecution) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	if ctx.Value(observedLeaseRequestKey{}) != e {
		return e.externalExecutionEngine.Dial(ctx, tag, address)
	}
	if tag != e.policy.capture.EntryTag || address != "10.77.0.1:8787" {
		return nil, errors.New("observer selected another lease route")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", e.response.Listener.Addr().String())
	if err != nil {
		return nil, err
	}
	return &observedLeaseBodyConn{Conn: conn, body: e.body, cancel: e.cancel}, nil
}

type observedLeaseBodyConn struct {
	net.Conn
	header     []byte
	headerRead bool
	release    sync.Once
	body       chan struct{}
	cancel     context.CancelFunc
}

func (c *observedLeaseBodyConn) Read(p []byte) (int, error) {
	afterHeader := c.headerRead
	if afterHeader {
		c.release.Do(func() { close(c.body) })
	}
	n, err := c.Conn.Read(p)
	if afterHeader && n > 0 {
		// Headers have already reached the real http.Client. Cancel only while
		// its actual response body is being consumed, so HTTP status and expiry
		// are both observed by the original lease operation.
		c.cancel()
	} else if !c.headerRead {
		c.header = append(c.header, p[:n]...)
		c.headerRead = bytes.Contains(c.header, []byte("\r\n\r\n"))
	}
	return n, err
}

func TestOpenVPNLeaseObservationKeepsGenuineFailureAlongsideCancellation(t *testing.T) {
	mappedOpenVPNTargets(t)
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			source, capture := externalOpenVPNMappedExecutionFixture(t)
			request, engine := externalExecutionCapturedRequest(t, source, capture, "server")
			owned := &observedLeaseExecution{observedExecution: &observedExecution{engine}, body: make(chan struct{})}
			ready := make(chan struct{})
			var expected multihoprelay.Request
			owned.response = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				<-ready
				var actual multihoprelay.Request
				if r.Method != "POST" || r.URL.Path != "/api/multihop/lease" || json.NewDecoder(r.Body).Decode(&actual) != nil || actual != expected {
					t.Error("lease observation changed its original proposal")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Length", "1024")
				w.WriteHeader(status)
				w.(http.Flusher).Flush()
				select {
				case <-owned.body:
				case <-r.Context().Done():
					return
				}
				_, _ = w.Write([]byte("partial lease body"))
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}))
			defer owned.response.Close()
			request.engine, request.execution.engine = owned, owned
			if _, err := request.Run(); err != nil {
				t.Fatal(err)
			}
			request.execution.leaseMu.Lock()
			expected = request.execution.proposal
			request.execution.leaseMu.Unlock()
			close(ready)
			original := request.execution.openvpnActive.Load()
			ctx, cancel := context.WithCancel(context.WithValue(t.Context(), observedLeaseRequestKey{}, owned))
			defer cancel()
			owned.cancel = cancel
			err := request.VerifyCurrentPathContext(ctx)
			if err == nil || ctx.Err() != context.Canceled {
				t.Fatal("controlled body did not cancel its original observer", err, ctx.Err())
			}
			if request.execution.openvpnActive.Load() != original {
				t.Fatal("failed observation adopted or refreshed its remote receipt")
			}
			if status == http.StatusOK {
				if !errors.Is(err, context.Canceled) || !common.ObservationContextExpired(ctx, err) || !request.succeeded.Load() || request.ctx.Err() != nil || request.execution.generation.Load() != 1 {
					t.Fatal("pure body observer expiry retired the healthy captured owner", err)
				}
				if err := request.HealthyContext(context.Background()); err != nil {
					t.Fatal("pure observer expiry damaged retained proof", err)
				}
			} else {
				var failure controlError
				if !errors.As(err, &failure) || failure.status != status || common.ObservationContextExpired(ctx, err) || request.succeeded.Load() || request.ctx.Err() == nil || request.execution.generation.Load() == 1 {
					t.Fatal("real lease rejection was laundered into healthy observer cancellation", err)
				}
			}
		})
	}
}
