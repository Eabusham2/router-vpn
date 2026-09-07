package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMultihopConnectProofResponseBoundaries(t *testing.T) {
	for _, scenario := range []string{"valid", "exact-limit", "oversized", "redirect", "wrong-node", "bad-status", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			a, exit, _ := asyncPathFixture(t, "http://10.77.0.1:8787")
			exit.PathProbeURL = exit.RouterAPI + "/health"
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			a.connectionContext = ctx
			proof := fmt.Sprintf(`{"ok":true,"node_id":%q,"proof":%q}`, exit.NodeProofID, desktopNodeProofKind)
			var calls, redirected atomic.Int32
			asyncExitLaneServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path == "/redirected" {
					redirected.Add(1)
					io.WriteString(w, proof)
					return
				}
				if scenario != "valid" && scenario != "exact-limit" {
					// Stop the readiness retry window quickly, without making a
					// bad response acceptable or requiring a real VPN/network.
					time.AfterFunc(80*time.Millisecond, cancel)
				}
				switch scenario {
				case "exact-limit":
					io.WriteString(w, proof+strings.Repeat(" ", 4096-len(proof)))
				case "oversized":
					io.WriteString(w, proof+strings.Repeat(" ", 4097-len(proof)))
				case "redirect":
					http.Redirect(w, r, "http://10.77.0.1:8787/redirected", http.StatusFound)
				case "wrong-node":
					io.WriteString(w, `{"ok":true,"node_id":"wrong-node","proof":"wrong-proof"}`)
				case "bad-status":
					w.WriteHeader(http.StatusBadGateway)
					io.WriteString(w, proof)
				default:
					io.WriteString(w, proof)
				}
			}))
			if scenario == "cancelled" {
				cancel()
			}
			err := a.proveMultihopExit(exit)
			valid := scenario == "valid" || scenario == "exact-limit"
			if (err == nil) != valid {
				t.Fatalf("proof accepted=%t want=%t, err=%v", err == nil, valid, err)
			}
			if redirected.Load() != 0 {
				t.Fatal("multihop connection proof followed a redirect")
			}
			if scenario == "cancelled" && calls.Load() != 0 {
				t.Fatal("cancelled connection issued a proof request")
			}
		})
	}
}
