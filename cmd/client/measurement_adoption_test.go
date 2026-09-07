package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestLiveMeasurementsCannotPersistAcrossAnotherTransaction(t *testing.T) {
	for _, endpoint := range []string{"public-ip", "dns", "home-exit"} {
		t.Run(endpoint, func(t *testing.T) {
			a, profile, _ := asyncPathFixture(t, "http://10.77.0.1:8787")
			t.Cleanup(func() { homeExitProofs.Delete(a) })
			if err := a.persistProfiles(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(a.cfg.ProfilesFile)
			if err != nil {
				t.Fatal(err)
			}
			started, respond := make(chan struct{}, 1), make(chan struct{})
			server := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health" {
					fmt.Fprintf(w, `{"ok":true,"node_id":%q,"proof":%q}`, profile.NodeProofID, desktopNodeProofKind)
					return
				}
				started <- struct{}{}
				select {
				case <-respond:
				case <-r.Context().Done():
					return
				}
				if endpoint == "dns" {
					io.WriteString(w, `{"winner":{"address":"1.1.1.1","latency_ms":1},"results":[]}`)
				} else {
					io.WriteString(w, "203.0.113.12")
				}
			})
			handler, method := a.publicIP, http.MethodGet
			if endpoint == "dns" {
				asyncExitLaneServer(t, server)
				handler, method = a.retestDNS, http.MethodPost
			} else {
				installPublicExitTestTransport(t, true, server)
				if endpoint == "home-exit" {
					handler, method = a.proveHomeExit, http.MethodPost
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				w := httptest.NewRecorder()
				handler(w, httptest.NewRequest(method, "/measurement", nil).WithContext(ctx))
				done <- w
			}()
			select {
			case <-started:
			case w := <-done:
				t.Fatalf("request did not reach HTTP: %d %s", w.Code, w.Body.String())
			case <-ctx.Done():
				t.Fatal("request did not start")
			}
			if !a.operationMu.TryLock() {
				t.Fatal("measurement held the mutation lock across network I/O")
			}
			defer a.operationMu.Unlock()
			close(respond)
			select {
			case w := <-done:
				if w.Code != http.StatusConflict {
					t.Fatalf("measurement adopted during another transaction: %d %s", w.Code, w.Body.String())
				}
			case <-time.After(time.Second):
				t.Fatal("adoption should fail closed rather than wait behind a transaction")
			}
			after, err := os.ReadFile(a.cfg.ProfilesFile)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("rejected measurement changed durable profiles")
			}
			if a.profiles.Profiles[1].PublicIP != "" || a.profiles.Profiles[1].FastestDNSHost != "old-result" {
				t.Fatal("rejected measurement changed in-memory results")
			}
		})
	}
}

func TestAsyncMeasurementAdoptionBindsOwnerSessionBothHopsAndEpoch(t *testing.T) {
	for _, change := range []string{"none", "owner", "unbound", "cancel", "session", "entry", "graph", "transient-recheck", "transient-graph"} {
		t.Run(change, func(t *testing.T) {
			a, profile, session := asyncPathFixture(t, "http://10.77.0.1:8787")
			ctx, stop, _, err := asyncMeasurementPathContext(context.Background(), a, profile, a.state, session, asyncMeasurementProfileToken(profile))
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			target := a
			switch change {
			case "owner":
				target = &app{}
			case "unbound":
				ctx = context.Background()
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "session":
				tracker := sessionTrackerFor(a)
				tracker.mu.Lock()
				tracker.session.ID = "new-session"
				tracker.mu.Unlock()
			case "entry":
				a.mu.Lock()
				a.profiles.Profiles[0].APIToken = "rotated-secret"
				a.mu.Unlock()
			case "graph":
				graph, _ := getActiveMultihopGraph(a)
				graph.Started = graph.Started.Add(time.Second)
				activeMultihopGraphs.Store(a, graph)
			case "transient-recheck":
				tracker := sessionTrackerFor(a)
				tracker.mu.Lock()
				tracker.session.DNSProof.Status = "passed"
				tracker.mu.Unlock()
				old := tracker.capture()
				checking := old
				checking.Connected, checking.Phase = false, "checking"
				tracker.observe(checking)
				tracker.observe(old)
			case "transient-graph":
				graph, _ := getActiveMultihopGraph(a)
				clearActiveMultihopGraph(a)
				activeMultihopGraphs.Store(a, graph)
			}
			release, err := target.beginAsyncMeasurementAdoption(ctx)
			if release != nil {
				release()
			}
			if (err == nil) != (change == "none") {
				t.Fatalf("change=%s adoption err=%v", change, err)
			}
			// Failed adoption must release every lock, without changing the VPN.
			if !target.operationMu.TryLock() {
				t.Fatal("adoption leaked operation lock")
			}
			target.operationMu.Unlock()
			if !target.mu.TryLock() {
				t.Fatal("adoption leaked app lock")
			}
			target.mu.Unlock()
			tracker := sessionTrackerFor(a)
			if !tracker.mu.TryLock() {
				t.Fatal("adoption leaked session lock")
			}
			tracker.mu.Unlock()
			if !a.state.Connected {
				t.Fatal("adoption disconnected the VPN")
			}
		})
	}
}
