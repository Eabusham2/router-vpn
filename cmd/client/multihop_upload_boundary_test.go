package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// A valid JSON prefix followed by excess whitespace used to bypass the body
// limit: LimitReader truncated it to valid JSON, which looked like a full ack.
func TestMultihopUploadAcknowledgementSizeBoundary(t *testing.T) {
	for _, size := range []int{64 << 10, (64 << 10) + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			_, p, _ := asyncPathFixture(t, "http://10.77.0.1:8787")
			ack := `{"bytes":1048576,"server_receive_ms":1}`
			ack += strings.Repeat(" ", size-len(ack))
			asyncExitLaneServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer exit-test-token" {
					http.Error(w, "wrong token", http.StatusForbidden)
					return
				}
				switch r.URL.Path {
				case "/health":
					fmt.Fprintf(w, `{"ok":true,"node_id":%q,"proof":%q}`, p.NodeProofID, desktopNodeProofKind)
				case "/api/benchmark/download":
					io.WriteString(w, strings.Repeat("x", 1<<20))
				case "/api/benchmark/upload":
					io.Copy(io.Discard, r.Body)
					io.WriteString(w, ack)
				default:
					http.NotFound(w, r)
				}
			}))
			result, err := measureRoutedProfileSpeedViaProxyContext(context.Background(), p, 1<<20, multihopProofProxy)
			if size == 64<<10 {
				if err != nil || result.Bytes != 1<<20 {
					t.Fatalf("bounded ack rejected: result=%+v err=%v", result, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "oversized") || result.Bytes != 0 {
				t.Fatalf("oversized ack accepted as measured throughput: result=%+v err=%v", result, err)
			}
		})
	}
}
