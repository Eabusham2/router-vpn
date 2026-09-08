package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func readSessionStatusForExitTest(t *testing.T, a *app) connectionSession {
	t.Helper()
	w := httptest.NewRecorder()
	a.sessionStatus(w, httptest.NewRequest(http.MethodGet, "/api/session", nil))
	var got connectionSession
	if w.Code != http.StatusOK {
		t.Fatalf("session status=%d: %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("live session response can be cached")
	}
	return got
}

func TestSessionStatusDoesNotPresentCachedExitAsLiveProof(t *testing.T) {
	a, _, _ := asyncPathFixture(t, "http://10.77.0.1:8787")
	a.profiles.Profiles[1].PublicIP = "203.0.113.99"
	tracker := sessionTrackerFor(a)
	tracker.dnsProofRunning = true // No unrelated network probes in this test.
	tracker.observe(tracker.capture())
	if tracker.snapshot(0).ExitIP != "" {
		t.Error("observation copied historical PublicIP into the live session")
	}
	got := readSessionStatusForExitTest(t, a)
	if got.ExitIP != "" {
		t.Fatalf("cached address advertised as a current-session exit: %+v", got)
	}
	if !got.Connected || got.RouterID != "exit" {
		t.Fatal("omitting unproved IP changed the working session")
	}
}

func TestSessionStatusExitRequiresCurrentBoundProof(t *testing.T) {
	for _, change := range []string{"unchanged", "display", "graph", "credentials", "policy", "session", "checking", "disconnect", "lifecycle", "private-proof", "missing-time"} {
		t.Run(change, func(t *testing.T) {
			a := provedHomeExitFixture(t)
			tracker := sessionTrackerFor(a)
			// Metadata and even an older session field must never substitute for proof.
			a.profiles.Profiles[1].PublicIP = "203.0.113.99"
			tracker.mu.Lock()
			tracker.session.ExitIP = "203.0.113.98"
			tracker.mu.Unlock()
			switch change {
			case "display":
				a.profiles.Profiles[1].Name = "renamed"
				a.profiles.Profiles[1].LatencyMedianMs = 9
			case "graph":
				g, _ := getActiveMultihopGraph(a)
				g.Started = g.Started.Add(time.Second)
				activeMultihopGraphs.Store(a, g)
			case "credentials":
				a.profiles.Profiles[0].APIToken = "new-entry-token"
			case "policy":
				a.profiles.Profiles[1].DNSHost = "8.8.8.8"
			case "session":
				tracker.session.ID = "new-session"
			case "checking":
				a.state.Phase = "checking"
			case "disconnect":
				a.state.Connected = false
			case "lifecycle":
				homeExitProofs.Delete(a)
			case "private-proof", "missing-time":
				raw, _ := homeExitProofs.Load(a)
				p := *raw.(*homeExitProof)
				if change == "private-proof" {
					p.IP = "192.168.50.1"
				} else {
					p.At = time.Time{}
				}
				homeExitProofs.Store(a, &p)
			}
			got := readSessionStatusForExitTest(t, a)
			want := ""
			if change == "unchanged" || change == "display" {
				want = "203.0.113.12"
			}
			if got.ExitIP != want {
				t.Fatalf("session exit=%q want=%q after %s", got.ExitIP, want, change)
			}
			if a.profiles.Profiles[1].PublicIP != "203.0.113.99" {
				t.Fatal("read-only session status rewrote durable metadata")
			}
			if a.profiles.SelectedID != "entry" {
				t.Fatal("session status changed node selection")
			}
			if strings.Contains(got.ExitIP, "98") || strings.Contains(got.ExitIP, "99") {
				t.Fatal("stale cached exit escaped")
			}
		})
	}
}
