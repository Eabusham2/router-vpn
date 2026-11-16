//go:build go1.25

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"router-vpn/internal/multihoprelay"
	"strings"
	"testing"
	"time"
)

func TestNodeChainCandidateHTTPAuthenticatedUnavailableBoundary(t *testing.T) {
	runner := &chainHTTPRunner{}
	s, mux, lease := chainHTTPFixture(t, runner)
	defer s.relay.Close(context.Background())
	if w := chainHTTPCall(mux, http.MethodPut, "10.77.0.2:9000", "private-agent-token", chainHTTPBody(t, lease, "")); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	runner.mu.Lock()
	worker := runner.workers[0]
	runner.mu.Unlock()
	close(worker.release)
	c := worker.capture
	digest, _ := c.Digest()
	q := multihoprelay.NodeChainCandidateRequest{Schema: 1, Lease: lease, OwnerID: c.OwnerID, CaptureSHA256: digest, Operation: strings.Repeat("a", 64), ExecutionSHA256: strings.Repeat("b", 64), Trial: strings.Repeat("c", 32), SelectionEpoch: 1, InventorySHA256: strings.Repeat("d", 64), Position: 1, CandidateID: "candidate", CandidateSourceSHA256: strings.Repeat("e", 64), Address: "192.168.1.9:443", DeadlineAt: time.Now().Add(time.Minute).UnixMilli(), Password: strings.Repeat("9", 64)}
	raw, _ := json.Marshal(q)
	call := func(method, peer, token, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, multihopNodeChainCandidatePath, strings.NewReader(body))
		request.RemoteAddr = peer
		request.Header.Set("Authorization", "Bearer "+token)
		out := httptest.NewRecorder()
		mux.ServeHTTP(out, request)
		return out
	}
	for _, test := range []struct {
		name, method, peer, token, body string
		want                            int
	}{
		{"unauthenticated", http.MethodPut, "10.77.0.2:9000", "wrong", string(raw), http.StatusForbidden},
		{"public-peer", http.MethodPut, "203.0.113.1:9000", "private-agent-token", string(raw), http.StatusForbidden},
		{"unknown-tag", http.MethodPut, "10.77.0.2:9000", "private-agent-token", strings.TrimSuffix(string(raw), "}") + `,"tag":"final"}`, http.StatusBadRequest},
		{"oversize", http.MethodPut, "10.77.0.2:9000", "private-agent-token", strings.Repeat(" ", multihoprelay.NodeChainCandidateMaximumBytes+1), http.StatusBadRequest},
		{"no-discovery", http.MethodGet, "10.77.0.2:9000", "private-agent-token", "", http.StatusMethodNotAllowed},
	} {
		t.Run(test.name, func(t *testing.T) {
			w := call(test.method, test.peer, test.token, test.body)
			if w.Code != test.want {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
	// The real old worker interface remains unsupported, not an unknown command
	// sent over its pipe and not a fabricated candidate success receipt.
	w := call(http.MethodPut, "10.77.0.2:9000", "private-agent-token", string(raw))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatal(w.Code, w.Body.String())
	}
	if !worker.Alive() {
		t.Fatal("unsupported candidate request killed original lease")
	}
	if strings.Contains(w.Body.String(), q.Password) {
		t.Fatal("private grant escaped in error")
	}
}
