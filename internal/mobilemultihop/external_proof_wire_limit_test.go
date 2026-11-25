package mobilemultihop

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestExternalMeasuredProofRequiresCompleteCloseDelimitedResponse(t *testing.T) {
	for _, tc := range []struct {
		name     string
		header   int
		complete bool
	}{
		{"complete", 4096, true}, {"wire-budget-exhausted", 13000, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const expected = "203.0.113.52"
			body := "ip=" + expected + "\nmetadata=" + strings.Repeat("v", 4096) + "\n"
			peer, trust := externalMTUTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("X-Trace-Metadata", strings.Repeat("h", tc.header))
				// The peer's EOF terminates this HTTP/1.1 response.
				w.Header().Set("Transfer-Encoding", "identity")
				w.(http.Flusher).Flush()
				fmt.Fprint(w, body)
			}))
			dial := func(ctx context.Context, tag, addr string) (net.Conn, error) {
				if tag != "original-prefix" || addr != "1.1.1.1:443" {
					return nil, fmt.Errorf("unexpected original route")
				}
				return new(net.Dialer).DialContext(ctx, "tcp", peer.Listener.Addr().String())
			}
			began, verified := false, false
			got, err := externalProofHTTPMeasured(t.Context(), dial, "original-prefix", "https://1.1.1.1/cdn-cgi/trace", "", "", trust, func() error { began = true; return nil }, func(data []byte) error {
				verified = true
				return externalTraceAddress(data, expected)
			})
			if !began || (err == nil) != tc.complete || verified != tc.complete {
				t.Fatalf("timed=%t verified=%t complete=%t error=%v", began, verified, tc.complete, err)
			}
			if tc.complete && string(got) != body || !tc.complete && got != nil {
				t.Fatal("published incomplete response bytes")
			}
		})
	}
}
